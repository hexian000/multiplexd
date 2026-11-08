#!/usr/bin/env python3
"""Regression tests for profiling configuration, credentials and report units.

Run from the project root: python3 scripts/gprof_test.py
"""

from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import signal
import subprocess
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


class MainTests(unittest.TestCase):
    def setUp(self):
        scratch = Path("build/tmp")
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name).resolve()
        self.binary = self.runtime / "bin/multiplexd"
        self.binary.parent.mkdir()
        self.binary.touch()
        self.profile = self.runtime / "gmon.out"
        self.profile.touch()
        self.output = self.runtime / "report.md"
        self.args = ["--build-dir", str(self.runtime),
                     "--profile-build-dir", str(self.runtime),
                     "--output", str(self.output)]
        self.skip_all = ["--skip-configure", "--skip-build", "--skip-benchmark"]

    def test_offline_report_needs_only_gprof(self):
        result = subprocess.CompletedProcess(
            [], 0, stdout=FlatProfileTests.profile())
        with mock.patch.object(gprof.shutil, "which", side_effect=lambda name:
                               "/tools/gprof" if name == "gprof" else None) as which:
            with mock.patch.object(gprof, "run_command", return_value=result) as run:
                self.assertEqual(gprof.main(self.args + self.skip_all), 0)
        which.assert_called_once_with("gprof")
        run.assert_called_once_with(
            ["/tools/gprof", str(self.binary), str(self.profile)],
            cwd=gprof.ROOT, capture_output=True)
        self.assertIn("| work |", self.output.read_text())
        self.assertTrue((self.runtime / "gprof.txt").is_file())

    def test_offline_report_preserves_runtime_evidence(self):
        for saved_tls in (False, True):
            with self.subTest(saved_tls=saved_tls):
                evidence = {
                    self.runtime / "server.json": json.dumps(
                        gprof.build_server_config(saved_tls)).encode(),
                    self.runtime / "client.json": json.dumps(
                        gprof.build_client_config(saved_tls)).encode(),
                    self.runtime / "server-cert.pem": b"saved certificate",
                    self.runtime / "server-key.pem": b"saved key",
                    self.profile: b"saved profile",
                }
                for path, content in evidence.items():
                    path.write_bytes(content)
                result = subprocess.CompletedProcess(
                    [], 0, stdout=FlatProfileTests.profile())
                cli_tls = [] if saved_tls else ["--tls"]
                with mock.patch.object(gprof.shutil, "which", return_value="gprof"):
                    with mock.patch.object(gprof, "run_command", return_value=result):
                        self.assertEqual(gprof.main(
                            self.args + self.skip_all + cli_tls), 0)
                for path, content in evidence.items():
                    self.assertEqual(path.read_bytes(), content)
                report = self.output.read_text()
                for field in ("TLS", "Benchmark timeout", "Shutdown grace"):
                    self.assertIn("| %s | unknown |" % field, report)
                self.assertIn("unknown (reused profile data)", report)
                self.assertNotIn("--bidir", report)

    def test_offline_report_does_not_create_runtime_assets(self):
        result = subprocess.CompletedProcess(
            [], 0, stdout=FlatProfileTests.profile())
        (self.runtime / "iperf3-parallel.stdout").write_text("saved traffic\n")
        with mock.patch.object(gprof.shutil, "which", return_value="gprof"):
            with mock.patch.object(gprof, "run_command", return_value=result):
                self.assertEqual(gprof.main(
                    self.args + self.skip_all + ["--tls"]), 0)
        for name in ("server.json", "client.json", "server-cert.pem",
                     "client-cert.pem", "server-key.pem", "client-key.pem"):
            self.assertFalse((self.runtime / name).exists())
        report = self.output.read_text()
        self.assertIn("saved traffic", report)
        self.assertIn("reused existing benchmark log", report)
        self.assertIn("| TLS | unknown |", report)

    def benchmark_collaborators(self, stack, processes, benchmark, *, port_lines=None):
        stack.enter_context(mock.patch.object(
            gprof.shutil, "which", side_effect=lambda name: "/tools/" + name))
        if port_lines is None:
            stack.enter_context(mock.patch.object(
                gprof, "check_port_available", return_value=True))
        else:
            stack.enter_context(mock.patch.object(
                gprof, "_ss_listen_lines", side_effect=lambda: list(port_lines)))
        stack.enter_context(mock.patch.object(gprof.time, "sleep"))
        spawn = stack.enter_context(mock.patch.object(
            gprof.subprocess, "Popen", side_effect=processes))
        run = stack.enter_context(mock.patch.object(
            gprof, "run_benchmark", side_effect=benchmark))
        command = stack.enter_context(mock.patch.object(
            gprof, "run_command", return_value=subprocess.CompletedProcess(
                [], 0, stdout=FlatProfileTests.profile())))
        terminate = stack.enter_context(mock.patch.object(
            gprof, "terminate_process"))
        return spawn, run, command, terminate

    def test_collision_cleanup_respects_executable_ownership(self):
        for owned in (False, True):
            with self.subTest(owned=owned):
                rows = [PortOwnershipTests.row("[::]:8443", 42001)]
                processes = [mock.Mock(pid=100 + i) for i in range(3)]
                for proc in processes:
                    proc.poll.return_value = None
                with ExitStack() as stack:
                    spawn, run, command, _ = self.benchmark_collaborators(
                        stack, processes, lambda *a, **k: "traffic", port_lines=rows)
                    stack.enter_context(mock.patch.object(
                        gprof, "_proc_exe", return_value=str(
                            self.binary if owned else self.runtime / "unrelated")))
                    killed = stack.enter_context(mock.patch.object(
                        gprof.os, "kill", side_effect=lambda *args: rows.clear()))
                    args = self.args + [
                        "--skip-configure", "--skip-build", "--keep-profile-data"]
                    if owned:
                        self.assertEqual(gprof.main(args), 0)
                    else:
                        with self.assertRaisesRegex(SystemExit, "ports still in use"):
                            gprof.main(args)
                if owned:
                    killed.assert_called_once_with(42001, signal.SIGTERM)
                    self.assertEqual(spawn.call_count, 3)
                    run.assert_called_once()
                    command.assert_called_once()
                else:
                    killed.assert_not_called()
                    spawn.assert_not_called()
                    run.assert_not_called()
                    command.assert_not_called()

    def test_benchmark_refuses_service_exits_before_teardown(self):
        names = ("iperf3 server", "multiplexd server", "multiplexd client")
        for when in ("before", "during"):
            for failed, name in enumerate(names):
                for status in (0, -11):
                    with self.subTest(when=when, name=name, status=status):
                        processes = [mock.Mock(pid=100 + i) for i in range(3)]
                        for proc in processes:
                            proc.poll.return_value = None
                        if when == "before":
                            processes[failed].poll.side_effect = [None, status]

                        def benchmark(*args, **kwargs):
                            if when == "during":
                                processes[failed].poll.return_value = status
                            return "successful traffic"

                        self.output.write_text("previous report\n")
                        with ExitStack() as stack:
                            spawn, run, command, terminate = self.benchmark_collaborators(
                                stack, processes, benchmark)
                            with self.assertRaisesRegex(
                                    SystemExit, "%s exited early \\(status %d\\)" % (name, status)):
                                gprof.main(self.args + [
                                    "--skip-configure", "--skip-build", "--keep-profile-data"])
                        self.assertEqual(run.call_count, when == "during")
                        command.assert_not_called()
                        self.assertEqual(self.output.read_text(), "previous report\n")
                        self.assertEqual(terminate.call_count, 3)
                        self.assertTrue(all(call.kwargs["stdout"].closed
                                            for call in spawn.call_args_list))

    def test_benchmark_publishes_when_every_service_stays_alive(self):
        processes = [mock.Mock(pid=100 + i) for i in range(3)]
        for proc in processes:
            proc.poll.return_value = None
        with ExitStack() as stack:
            _, run, command, terminate = self.benchmark_collaborators(
                stack, processes, lambda *args, **kwargs: "successful traffic")
            self.assertEqual(gprof.main(self.args + [
                "--skip-configure", "--skip-build", "--keep-profile-data", "--tls"]), 0)
        run.assert_called_once()
        command.assert_called_once()
        self.assertEqual(terminate.call_count, 3)
        self.assertTrue(all(proc.poll.call_count == 3 for proc in processes))
        report = self.output.read_text()
        self.assertIn("| TLS | on |", report)
        self.assertNotIn("unknown", report)
        self.assertIn("successful traffic", report)

    def test_cleanup_failure_still_stops_every_child_and_closes_logs(self):
        for primary in (None, RuntimeError("benchmark failed")):
            for cleanup_error in (subprocess.TimeoutExpired("client", 2),
                                  OSError("cannot signal client")):
                with self.subTest(primary=primary, cleanup=cleanup_error):
                    processes = [mock.Mock(pid=100 + i) for i in range(3)]
                    for proc in processes:
                        proc.poll.return_value = None
                    self.output.write_text("previous report\n")
                    expected = primary if primary is not None else cleanup_error
                    with ExitStack() as stack:
                        spawn, run, command, terminate = self.benchmark_collaborators(
                            stack, processes, lambda *args, **kwargs: "traffic")
                        if primary is not None:
                            run.side_effect = primary
                        terminate.side_effect = [cleanup_error, None, None]
                        logged = stack.enter_context(mock.patch.object(gprof, "log"))
                        with self.assertRaises(type(expected)) as caught:
                            gprof.main(self.args + [
                                "--skip-configure", "--skip-build", "--keep-profile-data"])
                    handles = [call.kwargs["stdout"] for call in spawn.call_args_list]
                    for handle in handles:
                        self.addCleanup(handle.close)
                    self.assertIs(caught.exception, expected)
                    self.assertEqual([call.args[0] for call in terminate.call_args_list],
                                     list(reversed(processes)))
                    self.assertTrue(all(handle.closed for handle in handles))
                    self.assertTrue(any("cleanup failed for multiplexd client" in call.args[0]
                                        for call in logged.call_args_list))
                    command.assert_not_called()
                    self.assertEqual(self.output.read_text(), "previous report\n")

    def test_each_enabled_cmake_stage_requires_cmake(self):
        for skipped in ("--skip-configure", "--skip-build"):
            with self.subTest(skipped=skipped):
                with mock.patch.object(gprof.shutil, "which", return_value=None):
                    with self.assertRaisesRegex(SystemExit, "required tool not found: cmake"):
                        gprof.main(self.args + [skipped, "--skip-benchmark"])

    def test_enabled_benchmark_requires_iperf3(self):
        with mock.patch.object(gprof.shutil, "which", side_effect=lambda name:
                               "/tools/gprof" if name == "gprof" else None):
            with self.assertRaisesRegex(SystemExit, "required tool not found: iperf3"):
                gprof.main(self.args + ["--skip-configure", "--skip-build"])

    def test_offline_report_still_requires_gprof(self):
        with mock.patch.object(gprof.shutil, "which", return_value=None):
            with self.assertRaisesRegex(SystemExit, "required tool not found: gprof"):
                gprof.main(self.args + self.skip_all)

    def test_offline_report_still_validates_binary_and_profile(self):
        with mock.patch.object(gprof.shutil, "which", return_value="/tools/gprof"):
            self.binary.unlink()
            with self.assertRaisesRegex(SystemExit, "expected binary not found"):
                gprof.main(self.args + self.skip_all)
            self.binary.touch()
            self.profile.unlink()
            with self.assertRaisesRegex(SystemExit, "no gprof data files found"):
                gprof.main(self.args + self.skip_all)


class PortOwnershipTests(unittest.TestCase):
    @staticmethod
    def row(local, pid, peer="*:0"):
        return 'LISTEN 0 128 %s %s users:(("service",pid=%d,fd=3))' % (
            local, peer, pid)

    def test_local_port_parsing_handles_wildcards_and_ignores_peer(self):
        for local in ("*:8443", "0.0.0.0:8443", "[::]:8443", "127.0.0.1:8443"):
            with self.subTest(local=local):
                row = self.row(local, 42001, "127.0.0.1:9081")
                self.assertEqual(gprof._line_listen_port(row), 8443)
                with mock.patch.object(gprof, "_ss_listen_lines", return_value=[row]):
                    self.assertFalse(gprof.check_port_available(8443))
                    self.assertTrue(gprof.check_port_available(9081))
                    self.assertEqual(gprof._parse_listening_pids(8443), [42001])
                    self.assertEqual(gprof._parse_listening_pids(9081), [])
        for row in ("", "State Recv-Q Send-Q Local Address:Port Peer Address:Port",
                    "LISTEN 0 128 *:https *:0", "LISTEN 0 128 malformed *:0"):
            with self.subTest(row=row):
                self.assertIsNone(gprof._line_listen_port(row))

    def test_only_owned_listeners_are_signalled_once(self):
        binary = (gprof.ROOT / "build/multiplexd").resolve()
        iperf = (gprof.ROOT / "build/iperf3").resolve()
        rows = [self.row("*:8443", 42001), self.row("[::]:8443", 42001),
                self.row("*:9081", 42001), self.row("0.0.0.0:5201", 42002),
                self.row("*:8443", 42003), self.row("*:8443", 42004),
                self.row("*:8443", 42005), self.row("*:9999", 42006)]
        exes = {42001: str(binary), 42002: str(iperf),
                42003: str(gprof.ROOT / "build/unrelated"), 42004: None}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(gprof, "_ss_listen_lines", return_value=rows))
            stack.enter_context(mock.patch.object(gprof.os, "getpid", return_value=42005))
            exe = stack.enter_context(mock.patch.object(gprof, "_proc_exe", side_effect=exes.get))
            kill = stack.enter_context(mock.patch.object(gprof.os, "kill"))
            stack.enter_context(mock.patch.object(gprof.time, "sleep"))
            self.assertEqual(gprof.kill_leftover_on_ports(
                [(8443, "mux"), (9081, "api"), (5201, "iperf")], [binary, iperf]), 2)
        self.assertEqual(kill.call_args_list, [mock.call(42001, signal.SIGTERM),
                                              mock.call(42002, signal.SIGTERM)])
        self.assertNotIn(mock.call(42005), exe.call_args_list)
        self.assertNotIn(mock.call(42006), exe.call_args_list)


class BenchmarkProcessTests(unittest.TestCase):
    def setUp(self):
        scratch = Path("build/tmp")
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        self.budget = gprof.ProcessShutdownBudget(0.1, 0.1)

    def run_client(self, proc):
        with mock.patch.object(gprof.subprocess, "Popen", return_value=proc) as spawn:
            try:
                return gprof.run_benchmark(
                    [["iperf3", "-c", "127.0.0.1"]], cwd=self.runtime,
                    stdout_log_path=self.runtime / "stdout.log",
                    stderr_log_path=self.runtime / "stderr.log",
                    timeout_seconds=1, shutdown_budget=self.budget)
            finally:
                if spawn.called:
                    self.assertTrue(spawn.call_args.kwargs["stdout"].closed)
                    self.assertTrue(spawn.call_args.kwargs["stderr"].closed)

    @staticmethod
    def process(outcomes):
        proc = mock.Mock(pid=42001, returncode=None)
        proc.poll.side_effect = lambda: proc.returncode
        results = iter(outcomes)

        def wait(**kwargs):
            outcome = next(results)
            if isinstance(outcome, BaseException):
                raise outcome
            proc.returncode = outcome
            return outcome

        proc.wait.side_effect = wait
        return proc

    def test_cancellation_and_wait_errors_reap_client_and_close_logs(self):
        for error in (KeyboardInterrupt(), RuntimeError("wait failed")):
            with self.subTest(error=type(error).__name__):
                proc = self.process([error, -signal.SIGINT])
                with self.assertRaises(type(error)) as caught:
                    self.run_client(proc)
                self.assertIs(caught.exception, error)
                proc.send_signal.assert_called_once_with(signal.SIGINT)
                self.assertIsNotNone(proc.returncode)
                self.assertEqual(proc.wait.call_count, 2)

    def test_timeout_escalates_to_kill_and_preserves_timeout_diagnostic(self):
        timeout = subprocess.TimeoutExpired("iperf3", 1)
        proc = self.process([timeout, timeout, timeout, -signal.SIGKILL])
        with self.assertRaisesRegex(SystemExit, "timed out after 1.0 seconds"):
            self.run_client(proc)
        proc.send_signal.assert_called_once_with(signal.SIGINT)
        proc.terminate.assert_called_once_with()
        proc.kill.assert_called_once_with()
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        self.assertEqual(proc.wait.call_count, 4)

    def test_cleanup_errors_still_force_reap_and_preserve_cancellation(self):
        for stage in ("send_signal", "terminate", "wait", "kill"):
            with self.subTest(stage=stage):
                primary = KeyboardInterrupt()
                failure = OSError("graceful cleanup failed")
                timeout = subprocess.TimeoutExpired("iperf3", 1)
                outcomes = [primary]
                if stage == "terminate":
                    outcomes.append(timeout)
                elif stage == "kill":
                    outcomes.extend([timeout, timeout])
                elif stage == "wait":
                    outcomes.append(failure)
                outcomes.append(-signal.SIGKILL)
                proc = self.process(outcomes)
                if stage != "wait":
                    getattr(proc, stage).side_effect = failure
                with mock.patch.object(gprof, "log") as logged:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.run_client(proc)
                self.assertIs(caught.exception, primary)
                proc.kill.assert_called_once_with()
                self.assertEqual(proc.returncode, -signal.SIGKILL)
                self.assertTrue(any("cleanup failed for benchmark client" in call.args[0]
                                    for call in logged.call_args_list))

    def test_successful_client_is_not_signalled(self):
        proc = self.process([0])
        self.assertIn("$ iperf3", self.run_client(proc))
        proc.send_signal.assert_not_called()
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()


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

    def test_gnu_large_and_small_units_are_normalized_in_each_column(self):
        for unit, factor in (("Ts", 1e18), ("Gs", 1e15), ("Ms", 1e12),
                             ("Ks", 1e9), ("ps", 1e-6), ("fs", 1e-9), ("as", 1e-12)):
            with self.subTest(unit=unit):
                row = gprof.parse_flat_profile(self.profile(unit, "us"))[0]
                self.assertEqual(row.self_us_per_call, 10 * factor)
                self.assertEqual(row.total_us_per_call, 20)
                row = gprof.parse_flat_profile(self.profile("us", unit))[0]
                self.assertEqual(row.self_us_per_call, 10)
                self.assertEqual(row.total_us_per_call, 20 * factor)

    def test_zero_sample_terasecond_profile_preserves_zero_and_call_counts(self):
        text = ("Flat profile:\n\nEach sample counts as 0.01 seconds.\n"
                " no time accumulated\n"
                "  %   cumulative   self              self     total\n"
                " time   seconds   seconds    calls  Ts/call  Ts/call  name\n"
                "  0.00      0.00     0.00        3     0.00     0.00  work\n"
                "  0.00      0.00     0.00                            uncounted\n\n")
        rows = gprof.parse_flat_profile(text)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].calls, 3)
        self.assertEqual(rows[0].percent, 0)
        self.assertEqual(rows[0].cumulative_seconds, 0)
        self.assertEqual(rows[0].self_seconds, 0)
        self.assertEqual(rows[0].self_us_per_call, 0)
        self.assertEqual(rows[0].total_us_per_call, 0)
        self.assertEqual(rows[1].name, "uncounted")
        self.assertIsNone(rows[1].calls)
        self.assertIsNone(rows[1].self_us_per_call)
        self.assertIsNone(rows[1].total_us_per_call)

    def test_seconds_nanoseconds_and_independent_column_units(self):
        for unit, factor in (("s", 1e6), ("ns", 1e-3)):
            with self.subTest(unit=unit):
                row = gprof.parse_flat_profile(self.profile(unit, "us"))[0]
                self.assertEqual(row.self_us_per_call, 10 * factor)
                self.assertEqual(row.total_us_per_call, 20)

    def test_missing_or_unknown_units_are_rejected(self):
        for unit in ("unknown", "ks"):
            with self.subTest(unit=unit):
                with self.assertRaisesRegex(SystemExit, "unsupported gprof"):
                    gprof.parse_flat_profile(self.profile(unit))
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
