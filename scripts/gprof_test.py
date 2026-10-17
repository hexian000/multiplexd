#!/usr/bin/env python3
"""Regression tests for profiling configuration, credentials and report units.

Run from the project root: python3 scripts/gprof_test.py
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import gprof
from smoke_test import BUILTIN_CERT_PEM, BUILTIN_KEY_PEM


class ConfigureTests(unittest.TestCase):
    def test_preserves_backend_threads_and_dependency_inputs(self):
        for backend in ("openssl", "mbedtls", "none"):
            with self.subTest(backend=backend):
                cache = {
                    "USE_TLS_LIBRARY": backend,
                    "ENABLE_THREADS": "ON",
                    "FORCE_POSIX": "ON",
                    "LINK_STATIC_LIBS": "ON",
                    "CMAKE_C_COMPILER": "/custom/bin/gcc",
                    "CMAKE_PREFIX_PATH": "/deps/one;/deps/two",
                    "MbedTLS_DIR": "/deps/mbedtls/cmake",
                    "OPENSSL_ROOT_DIR": "/deps/openssl",
                    "LIBEV_INCLUDE_DIR": "/deps/ev/include",
                    "LIBEV_LIBRARY": "/deps/ev/lib/libev.a",
                }
                command = gprof.build_configure_command(
                    "cmake", cache, Path("build/gprof"), "RelWithDebInfo")
                for key, value in cache.items():
                    self.assertIn("-D%s=%s" % (key, value), command)

    def test_overrides_incompatible_flags_and_ignores_probe_results(self):
        cache = {
            "ENABLE_THREADS": "OFF",
            "CMAKE_PREFIX_PATH": "",
            "ENABLE_SANITIZERS": "ON",
            "BUILD_TESTING": "ON",
            "BUILD_PIE": "ON",
            "CMAKE_POSITION_INDEPENDENT_CODE": "ON",
            "CMAKE_INTERPROCEDURAL_OPTIMIZATION": "ON",
            "CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE": "ON",
            "CMAKE_C_FLAGS": "-fsanitize=address",
            "CMAKE_EXE_LINKER_FLAGS": "-pie",
            "multiplexd_BINARY_DIR": "/old/build",
            "HAVE_C11_THREADS": "1",
        }
        command = gprof.build_configure_command(
            "cmake", cache, Path("build/gprof"), "Release")
        settings = dict(part[2:].split("=", 1)
                        for part in command if part.startswith("-D"))
        for key in ("ENABLE_SANITIZERS", "BUILD_TESTING", "BUILD_PIE",
                    "CMAKE_POSITION_INDEPENDENT_CODE",
                    "CMAKE_INTERPROCEDURAL_OPTIMIZATION",
                    "CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE"):
            self.assertEqual(settings[key], "OFF")
        self.assertEqual(settings["ENABLE_THREADS"], "OFF")
        self.assertEqual(settings["CMAKE_PREFIX_PATH"], "")
        self.assertEqual(settings["CMAKE_C_FLAGS"], "-pg -fno-pie")
        self.assertEqual(settings["CMAKE_EXE_LINKER_FLAGS"], "-pg -no-pie")
        self.assertNotIn("multiplexd_BINARY_DIR", settings)
        self.assertNotIn("HAVE_C11_THREADS", settings)

    def test_empty_base_cache_uses_project_defaults(self):
        command = gprof.build_configure_command(
            "cmake", {}, Path("build/gprof"), "Debug")
        self.assertNotIn("-DENABLE_THREADS=", " ".join(command))
        self.assertIn("-DCMAKE_BUILD_TYPE=Debug", command)


class CredentialTests(unittest.TestCase):
    def setUp(self):
        scratch = Path("build/tmp")
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        self.binary = self.runtime / "non-openssl-binary"

    def assert_complete_fixture(self):
        for role in ("server", "client"):
            self.assertEqual((self.runtime / (role + "-cert.pem")).read_text(),
                             BUILTIN_CERT_PEM)
            self.assertEqual((self.runtime / (role + "-key.pem")).read_text(),
                             BUILTIN_KEY_PEM)

    def test_missing_private_key_regenerates_complete_set(self):
        for missing_role in ("server", "client"):
            with self.subTest(missing_role=missing_role):
                for role in ("server", "client"):
                    for kind in ("cert", "key"):
                        path = self.runtime / ("%s-%s.pem" % (role, kind))
                        path.write_text("old " + kind)
                (self.runtime / (missing_role + "-key.pem")).unlink()
                with mock.patch.object(gprof, "run_command") as command:
                    gprof.ensure_certificates(self.binary, self.runtime)
                    command.assert_not_called()
                self.assert_complete_fixture()

    def test_fresh_tls_assets_do_not_require_backend_generator(self):
        with mock.patch.object(gprof, "run_command") as command:
            server, client = gprof.prepare_runtime_assets(
                self.binary, self.runtime, use_tls=True)
            command.assert_not_called()
        self.assert_complete_fixture()
        for config in (server, client):
            tls = json.loads(config.read_text())["tls"]
            for asset in (tls["cert"], tls["key"], *tls["authcerts"]):
                self.assertTrue((self.runtime / asset[1:]).is_file())

    def test_complete_existing_set_is_preserved(self):
        for role in ("server", "client"):
            for kind in ("cert", "key"):
                (self.runtime / ("%s-%s.pem" % (role, kind))).write_text("custom")
        gprof.ensure_certificates(self.binary, self.runtime)
        for path in self.runtime.glob("*.pem"):
            self.assertEqual(path.read_text(), "custom")

    def test_plain_assets_need_no_certificates(self):
        with mock.patch.object(gprof, "ensure_certificates") as certificates:
            server, client = gprof.prepare_runtime_assets(
                self.binary, self.runtime, use_tls=False)
            certificates.assert_not_called()
        self.assertEqual(list(self.runtime.glob("*.pem")), [])
        for config in (server, client):
            self.assertNotIn("tls", json.loads(config.read_text()))


class FlatProfileTests(unittest.TestCase):
    @staticmethod
    def profile(unit="ms", total_unit=None):
        return ("Flat profile:\n\nEach sample counts as 0.01 seconds.\n"
                "  %%   cumulative   self              self     total\n"
                " time   seconds   seconds    calls  %s/call  %s/call  name\n"
                "100.00      1.00     1.00      100    10.00    20.00  work\n"
                "  0.00      1.00     0.00                            uncounted\n"
                "\nCall graph\n" % (unit, total_unit or unit))

    def test_millisecond_values_are_normalized_to_microseconds(self):
        rows = gprof.parse_flat_profile(self.profile())
        self.assertEqual(rows[0].self_us_per_call, 10000)
        self.assertEqual(rows[0].total_us_per_call, 20000)
        self.assertEqual(rows[0].self_seconds, 1)
        self.assertEqual(rows[0].calls, 100)
        self.assertEqual(rows[1].name, "uncounted")
        self.assertIsNone(rows[1].calls)
        self.assertIsNone(rows[1].self_us_per_call)

    def test_microsecond_values_are_preserved(self):
        row = gprof.parse_flat_profile(self.profile("us"))[0]
        self.assertEqual(row.self_us_per_call, 10)
        self.assertEqual(row.total_us_per_call, 20)

    def test_seconds_nanoseconds_and_independent_column_units(self):
        for unit, factor in (("s", 1e6), ("ns", 1e-3)):
            with self.subTest(unit=unit):
                row = gprof.parse_flat_profile(self.profile(unit, "us"))[0]
                self.assertEqual(row.self_us_per_call, 10 * factor)
                self.assertEqual(row.total_us_per_call, 20)

    def test_missing_or_unknown_units_are_rejected(self):
        with self.assertRaisesRegex(SystemExit, "unsupported gprof"):
            gprof.parse_flat_profile(self.profile("unknown"))
        text = self.profile().replace(
            " time   seconds   seconds    calls  ms/call  ms/call  name\n", "")
        with self.assertRaisesRegex(SystemExit, "no per-call unit header"):
            gprof.parse_flat_profile(text)

    def test_report_labels_and_values_use_same_unit(self):
        profile_dir = gprof.ROOT / "build/gprof"
        report = gprof.render_markdown_report(
            output_path=gprof.ROOT / "build/gprof.md",
            profile_build_dir=profile_dir,
            binary_path=profile_dir / "bin/multiplexd",
            profile_files=[], benchmark_command_text="iperf3",
            benchmark_output="", gprof_text_path=profile_dir / "gprof.txt",
            gprof_output=self.profile(), use_tls=False,
            command_timeout_seconds=30,
            shutdown_budget=gprof.ProcessShutdownBudget(5, 2))
        self.assertIn("Self us/call | Total us/call", report)
        self.assertIn("| work | 100.00 | 1.00 | 1.00 | 100 | 10000.00 | 20000.00 |", report)
        self.assertIn("| work | 100.00 | 1.00 | 100 | 20000.00 |", report)


if __name__ == "__main__":
    unittest.main()
