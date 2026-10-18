#!/usr/bin/env python3
"""Regression tests for the linearity benchmark setup, teardown and report."""

from __future__ import annotations

import argparse
import contextlib
import errno
import http.server
import io
import json
import pathlib
import subprocess
import tempfile
import threading
import unittest
from contextlib import ExitStack
from typing import List, Optional, Sequence, Set
from unittest import mock

import linearity_test
from smoke_test import BUILTIN_CERT_PEM, BUILTIN_KEY_PEM

# Anchored to this file, not the CWD: ctest runs from the build directory.
SCRATCH = pathlib.Path(__file__).resolve().parent.parent / "build" / "tmp"

# Ports each spawned process listens on once it is up, keyed by the last argv
# element (the daemons' config file) or the program name (iperf3).
_PROCESS_PORTS = {
    "iperf3": [linearity_test.IPERF3_PORT],
    "server.json": [linearity_test.MUX_PORT, linearity_test.SERVER_LISTEN],
    "client.json": [linearity_test.MUX_LISTEN],
}


class _HealthHandler(http.server.BaseHTTPRequestHandler):
    # Status of each successive GET; the last one repeats.
    statuses: List[int] = [200]

    def do_GET(self) -> None:
        status = self.statuses[0]
        if len(self.statuses) > 1:
            _HealthHandler.statuses = self.statuses[1:]
        self.send_response(status)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class _FakeProcess:
    _next_pid = 1000

    def __init__(self, argv: Sequence[str]) -> None:
        self.argv = list(argv)
        self.pid = _FakeProcess._next_pid
        _FakeProcess._next_pid += 1
        self.returncode: Optional[int] = None
        self.terminated = False

    def poll(self) -> Optional[int]:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        if self.returncode is None:
            self.returncode = -15

    def kill(self) -> None:
        self.terminate()

    def wait(self, timeout: float = 0) -> int:
        return self.returncode if self.returncode is not None else 0


class _FakeSystem:
    """Stands in for the subprocess module: spawning a process opens its
    ports, and `ss` reports whatever is open."""

    DEVNULL = subprocess.DEVNULL
    PIPE = subprocess.PIPE
    TimeoutExpired = subprocess.TimeoutExpired
    CompletedProcess = subprocess.CompletedProcess

    def __init__(self) -> None:
        self.procs: List[_FakeProcess] = []
        self.listening: Set[int] = set()
        # Spawn index whose Popen raises instead of starting a process.
        self.fail_spawn: Optional[int] = None
        self.spawn_error: BaseException = OSError(
            errno.ENOEXEC, "Exec format error")
        # Raised by `ss` once a process has been spawned.
        self.ss_error: Optional[BaseException] = None
        # Processes (by _PROCESS_PORTS key) that exit as soon as spawned.
        self.exit_on_spawn: Set[str] = set()

    def Popen(self, argv: Sequence[str], **kwargs: object) -> _FakeProcess:
        if self.fail_spawn == len(self.procs):
            raise self.spawn_error
        proc = _FakeProcess(argv)
        self.procs.append(proc)
        key = "iperf3" if argv[0] == "iperf3" else argv[-1]
        if key in self.exit_on_spawn:
            proc.returncode = 1
        else:
            self.listening.update(_PROCESS_PORTS.get(key, []))
        return proc

    def run(self, cmd: Sequence[str], **kwargs: object):
        if cmd[0] == "ss":
            if self.ss_error is not None and self.procs:
                raise self.ss_error
            out = "".join(
                f"LISTEN 0 4096 127.0.0.1:{port} 0.0.0.0:*\n"
                for port in sorted(self.listening))
            return subprocess.CompletedProcess(list(cmd), 0, out, "")
        return subprocess.run(cmd, **kwargs)


class LinearityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        _HealthHandler.statuses = [200]
        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _HealthHandler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05})
        self.thread.start()

        self.old_api_port = linearity_test.API_PORT
        linearity_test.API_PORT = self.server.server_port

        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.build_dir = pathlib.Path(self.temp_dir.name)
        (self.build_dir / "bin").mkdir()
        self.fake = _FakeSystem()
        self.test = self._make_test()

    def _make_test(self) -> linearity_test.LinearityTest:
        args = argparse.Namespace(
            build_dir=str(self.build_dir),
            output=str(self.build_dir / "report.md"),
            duration=1,
            bw_list="0",
        )
        test = linearity_test.LinearityTest(args)
        test.binary.touch()
        # A partial certificate set, as an interrupted earlier run leaves.
        (test.work_dir / "server-cert.pem").touch()
        return test

    def tearDown(self) -> None:
        self.test.teardown()
        self.temp_dir.cleanup()
        linearity_test.API_PORT = self.old_api_port
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def _patched(self) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(mock.patch.object(
            linearity_test, "subprocess", self.fake))
        stack.enter_context(mock.patch.object(
            linearity_test, "listening_conflicts", return_value={}))
        stack.enter_context(mock.patch.object(linearity_test.time, "sleep"))
        return stack

    def _setup(self) -> None:
        with self._patched():
            self.test.setup()

    def _reset(self) -> None:
        """Start a subtest from a fresh runner and a fresh fake system."""
        self.test.teardown()
        self.test = self._make_test()
        self.fake = _FakeSystem()


class LinearitySetupTests(LinearityTestCase):
    def test_setup_accepts_http_ok(self) -> None:
        self._setup()
        self.assertIsNotNone(self.test._srv_pid)
        self.assertIsNotNone(self.test._cli_pid)

    def test_setup_rejects_http_error(self) -> None:
        _HealthHandler.statuses = [503]
        self.test.ready_timeout = 0.5
        with self.assertRaises(SystemExit):
            self._setup()

    def test_setup_polls_until_tunnel_is_healthy(self) -> None:
        # The tunnel comes up some time after the client starts: /healthy
        # answers 503 until then.
        _HealthHandler.statuses = [503, 503, 200]
        self._setup()
        self.assertIsNotNone(self.test._cli_pid)

    def test_setup_detects_daemon_exit(self) -> None:
        for config in ("server.json", "client.json"):
            with self.subTest(config=config):
                self._reset()
                self.fake.exit_on_spawn = {config}
                self.test.ready_timeout = 60.0
                with self.assertRaises(SystemExit) as cm:
                    self._setup()
                self.assertIn("exited with status 1", str(cm.exception))

    def test_setup_writes_complete_builtin_certs(self) -> None:
        self._setup()
        work = self.test.work_dir
        for role in ("server", "client"):
            self.assertEqual(
                (work / f"{role}-cert.pem").read_text(encoding="utf-8"),
                BUILTIN_CERT_PEM)
            self.assertEqual(
                (work / f"{role}-key.pem").read_text(encoding="utf-8"),
                BUILTIN_KEY_PEM)

    def test_setup_omits_tls_on_build_without_tls(self) -> None:
        (self.build_dir / "src").mkdir()
        (self.build_dir / "src" / "config.h").write_text(
            "#define WITH_TLS 0\n", encoding="utf-8")
        self.test = self._make_test()
        self._setup()
        for name in ("server.json", "client.json"):
            cfg = json.loads(
                (self.test.work_dir / name).read_text(encoding="utf-8"))
            self.assertNotIn("tls", cfg, name)


class LinearityTeardownTests(LinearityTestCase):
    def _run_expecting_teardown(self) -> None:
        stderr = io.StringIO()
        with self._patched(), contextlib.redirect_stderr(stderr):
            try:
                rc = self.test.run()
            except (KeyboardInterrupt, OSError, subprocess.SubprocessError):
                rc = None
        self.assertTrue(self.fake.procs, "nothing was spawned")
        for proc in self.fake.procs:
            self.assertTrue(proc.terminated,
                            f"{proc.argv[0]} left running after setup failed")
        if rc is not None:
            self.assertEqual(rc, 1)

    def test_run_tears_down_when_spawn_fails(self) -> None:
        # iperf3 is up when exec of the multiplexd server fails.
        self.fake.fail_spawn = 1
        self._run_expecting_teardown()

    def test_run_tears_down_when_probe_tool_fails(self) -> None:
        for error in (FileNotFoundError(errno.ENOENT, "No such file", "ss"),
                      subprocess.TimeoutExpired(["ss"], 10)):
            with self.subTest(error=type(error).__name__):
                self._reset()
                self.fake.ss_error = error
                self._run_expecting_teardown()

    def test_run_tears_down_on_interrupt(self) -> None:
        self.fake.fail_spawn = 1
        self.fake.spawn_error = KeyboardInterrupt()
        self._run_expecting_teardown()


class LinearityReportTests(LinearityTestCase):
    def test_analysis_handles_zero_efficiency(self) -> None:
        for first_eff, last_eff, conclusion in (
                (0.0, 0.0, "CPU/Mbps shows no increase"),
                (0.0, 0.1, "CPU/Mbps increased from a zero baseline"),
                (0.1, 0.0, "CPU/Mbps is roughly constant")):
            with self.subTest(first=first_eff, last=last_eff):
                rows = [
                    {"bw": bw, "thr_mbps": 1.0, "srv_dur_pct": 0.0,
                     "cli_dur_pct": 0.0, "srv_aft_pct": 0.0,
                     "cli_aft_pct": 0.0, "net_cpu_pct": 0.0,
                     "cpu_per_mbps": eff}
                    for bw, eff in (("10M", first_eff), ("0", last_eff))]
                report = self.test.render_report(rows, 0.0, 0.0, 0.0, 0.0)
                self.assertIn(conclusion, report)
                self.assertNotIn("super-linearly", report)
                self.assertNotIn("ratio=inf", report)
                if first_eff == 0:
                    self.assertIn("growth ratio is undefined", report)
                else:
                    self.assertIn("ratio=0.00", report)

    def test_analysis_describes_throughput_not_stream_count(self) -> None:
        # Every step runs a single stream (-P 1) at a different -b, so the
        # verdict may only speak of throughput, never of streams.
        for last_eff in (0.15, 0.3, 1.0):
            with self.subTest(ratio=last_eff / 0.1):
                rows = [
                    {"bw": bw, "thr_mbps": 1.0, "srv_dur_pct": 0.0,
                     "cli_dur_pct": 0.0, "srv_aft_pct": 0.0,
                     "cli_aft_pct": 0.0, "net_cpu_pct": 0.0,
                     "cpu_per_mbps": eff}
                    for bw, eff in (("10M", 0.1), ("0", last_eff))]
                report = self.test.render_report(rows, 0.0, 0.0, 0.0, 0.0)
                analysis = report.split("## Analysis", 1)[1]
                self.assertIn("throughput", analysis)
                self.assertNotIn("stream", analysis)


if __name__ == "__main__":
    unittest.main()
