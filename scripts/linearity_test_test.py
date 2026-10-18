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


def _bidir_report():
    return {"end": {"streams": [
        {"sender": {"socket": 5, "sender": True,
                    "bits_per_second": 1_250_000},
         "receiver": {"socket": 5, "sender": True,
                      "bits_per_second": 1_200_000}},
        {"sender": {"socket": 7, "sender": False,
                    "bits_per_second": 2_600_000},
         "receiver": {"socket": 7, "sender": False,
                      "bits_per_second": 2_500_000}},
        {"sender": {"socket": 9, "sender": True,
                    "bits_per_second": 3_750_000.0},
         "receiver": {"socket": 9, "sender": True,
                      "bits_per_second": 3_700_000.0}},
        {"sender": {"socket": 11, "sender": False,
                    "bits_per_second": 5_100_000.0},
         "receiver": {"socket": 11, "sender": False,
                      "bits_per_second": 5_000_000.0}},
    ]}}


class LinearityThroughputTests(unittest.TestCase):
    def test_summary_bits_accepts_numbers_and_defaults_invalid_values(self) -> None:
        for value in (0, 1_250_000, 2_500_000.5):
            with self.subTest(value=value):
                self.assertEqual(linearity_test.parse_summary_bits(
                    {"bits_per_second": value}), float(value))
        for summary in (None, [], "invalid", {}, {"bits_per_second": None},
                        {"bits_per_second": "1250000"},
                        {"bits_per_second": []}):
            with self.subTest(summary=summary):
                self.assertEqual(linearity_test.parse_summary_bits(summary), 0.0)

    def test_bidir_selects_each_direction_once_and_scales_to_mbps(self) -> None:
        streams = _bidir_report()["end"]["streams"]
        for stream, expected in zip(streams, (1.25, 2.5, 3.75, 5.0)):
            with self.subTest(socket=stream["sender"]["socket"]):
                self.assertEqual(linearity_test.extract_bidir_throughput_mbps(
                    {"end": {"streams": [stream]}}), expected)
        self.assertEqual(linearity_test.extract_bidir_throughput_mbps(
            _bidir_report()), 12.5)

    def test_bidir_requires_end_and_streams_containers(self) -> None:
        for report in ({}, {"end": None}, {"end": []}):
            with self.subTest(report=report), self.assertRaisesRegex(
                    SystemExit, "missing end summary"):
                linearity_test.extract_bidir_throughput_mbps(report)
        for end in ({}, {"streams": None}, {"streams": {}}):
            with self.subTest(end=end), self.assertRaisesRegex(
                    SystemExit, "missing end.streams"):
                linearity_test.extract_bidir_throughput_mbps({"end": end})
        self.assertEqual(linearity_test.extract_bidir_throughput_mbps(
            {"end": {"streams": []}}), 0.0)

    def test_bidir_skips_malformed_entries_without_losing_valid_streams(self) -> None:
        report = _bidir_report()
        report["end"]["streams"] += [
            None, [], "invalid", {}, {"sender": None, "receiver": []},
            {"sender": {"sender": True, "bits_per_second": "1000000"},
             "receiver": {"sender": False}},
        ]
        for flag in (None, 0, 1, "true", "false"):
            report["end"]["streams"].append({
                "sender": {"sender": flag, "bits_per_second": 100_000_000},
                "receiver": {"sender": flag, "bits_per_second": 100_000_000},
            })
        self.assertEqual(linearity_test.extract_bidir_throughput_mbps(report), 12.5)


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


class LinearityMeasurementTests(LinearityTestCase):
    def test_nonempty_iperf_report_reaches_throughput_and_cpu_efficiency(self) -> None:
        self._setup()
        with self._patched(), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(linearity_test, "_read_ticks", return_value=0), \
                mock.patch.object(linearity_test.TickSnap, "cpu_since",
                                  side_effect=[7.25, 0.0, 4.0, 0.0]), \
                mock.patch.object(linearity_test, "run_iperf_json",
                                  return_value=_bidir_report()):
            rows = self.test.sweep(1.0, 1.0)
        self.assertEqual(rows[0]["thr_mbps"], 12.5)
        self.assertEqual(rows[0]["cpu_per_mbps"], 0.5)
        report = self.test.render_report(rows, 1.0, 1.0, 0.0, 0.0)
        self.assertIn("| unlimited | 12.5 |", report)
        self.assertIn("| 0.500 |", report)

    def _run_measurement(self, *, sleep=None, iperf=None, render=None,
                         ticks=None) -> str:
        output = io.StringIO()
        report = {"end": {"streams": []}}
        with self._patched(), contextlib.redirect_stderr(output), \
                contextlib.redirect_stdout(output), \
                mock.patch.object(linearity_test, "_read_ticks", side_effect=ticks,
                                  return_value=0), \
                mock.patch.object(linearity_test.time, "sleep", side_effect=sleep), \
                mock.patch.object(linearity_test, "run_iperf_json",
                                  side_effect=iperf, return_value=report):
            if render is not None:
                with mock.patch.object(self.test, "render_report", side_effect=render):
                    rc = self.test.run()
            else:
                rc = self.test.run()
        self.assertEqual(rc, 1, output.getvalue())
        self.assertFalse(self.test.output.exists())
        self.assertNotIn("Final CPU returned", output.getvalue())
        self.assertTrue(all(p.terminated for p in self.fake.procs))
        return output.getvalue()

    def test_run_rejects_exit_during_each_measurement_interval(self) -> None:
        # Idle settle, idle sampling, post-traffic settle, tombstone settle,
        # final sampling. Keep ticks readable: even an exited zombie can
        # retain /proc stats, so missing-sample detection alone is insufficient.
        for proc_index in range(3):
            for interval in range(5):
                with self.subTest(process=proc_index, interval=interval):
                    self._reset()
                    sleeps = []

                    def exit_during_interval(seconds):
                        sleeps.append(seconds)
                        if len(sleeps) == interval + 1:
                            self.fake.procs[proc_index].returncode = 1

                    output = self._run_measurement(sleep=exit_during_interval)
                    self.assertIn("exited with status 1", output)

    def test_run_rejects_exit_during_traffic(self) -> None:
        def exit_during_traffic(*args, **kwargs):
            self.test._srv.returncode = 1
            return {"end": {"streams": []}}

        self.assertIn("exited with status 1",
                      self._run_measurement(iperf=exit_during_traffic))

    def test_run_rejects_exit_while_sampling(self) -> None:
        def exit_during_sample(pid):
            self.test._cli.returncode = 1
            return 0

        self.assertIn("exited with status 1",
                      self._run_measurement(ticks=exit_during_sample))

    def test_run_rechecks_liveness_before_publishing(self) -> None:
        def exit_before_publish(*args):
            self.test._cli.returncode = 1
            return "Final CPU returned"

        self.assertIn("before publishing report",
                      self._run_measurement(render=exit_before_publish))

    def test_live_run_can_report_zero_cpu(self) -> None:
        with self._patched(), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(linearity_test, "_read_ticks", return_value=0), \
                mock.patch.object(linearity_test, "run_iperf_json",
                                  return_value={"end": {"streams": []}}):
            self.assertEqual(self.test.run(), 0)
        self.assertIn("Final CPU after cleanup", self.test.output.read_text())


class LinearitySampleTests(unittest.TestCase):
    def test_unavailable_ticks_are_errors(self) -> None:
        for error in (FileNotFoundError(), PermissionError(), OSError("read failed")):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(pathlib.Path, "read_text", side_effect=error):
                with self.assertRaisesRegex(RuntimeError, "cannot read CPU ticks"):
                    linearity_test._read_ticks(123)

    def test_malformed_ticks_are_errors(self) -> None:
        for raw in ("bad stat", "123 (name) S", "123 (name) " + "x " * 13):
            with self.subTest(raw=raw), \
                    mock.patch.object(pathlib.Path, "read_text", return_value=raw):
                with self.assertRaises(RuntimeError):
                    linearity_test._read_ticks(123)

    def test_valid_ticks_allow_spaces_and_parentheses_in_name(self) -> None:
        raw = "123 (name (with spaces)) S " + "0 " * 10 + "12 34"
        with mock.patch.object(pathlib.Path, "read_text", return_value=raw):
            self.assertEqual(linearity_test._read_ticks(123), 46)

    def test_invalid_cpu_intervals_are_errors(self) -> None:
        for values in ((1.0, 10, 2.0, 0), (1.0, 10, 1.0, 10), (2.0, 10, 1.0, 10)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                linearity_test.cpu_pct_interval(*values)
        self.assertEqual(linearity_test.cpu_pct_interval(1.0, 0, 2.0, 0), 0)
        self.assertEqual(linearity_test.cpu_pct_interval(
            1.0, 0, 2.0, linearity_test._CLK_TCK), 100)


class LinearityProbeTests(unittest.TestCase):
    def test_listening_probes_configure_subprocess_timeouts(self) -> None:
        for probe in (lambda: linearity_test.listening_conflicts([5201]),
                      lambda: linearity_test.port_listening(5201)):
            with self.subTest(probe=probe):
                def unresponsive_ss(command, **kwargs):
                    if kwargs.get("timeout") is None:
                        self.fail("ss would wait indefinitely without timeout")
                    self.assertGreater(kwargs["timeout"], 0)
                    self.assertLessEqual(kwargs["timeout"], 1.0)
                    self.assertTrue(kwargs["check"])
                    raise subprocess.TimeoutExpired(command, kwargs["timeout"])

                with mock.patch.object(linearity_test.subprocess, "run",
                                       side_effect=unresponsive_ss):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        probe()

    def test_readiness_passes_remaining_deadline_to_probe(self) -> None:
        probe = mock.Mock(return_value=False)
        with mock.patch.object(linearity_test.time, "monotonic",
                               side_effect=[10.0, 10.75, 11.0]):
            with self.assertRaises(SystemExit):
                linearity_test.wait_ready("listener", probe, {}, 1.0)
        probe.assert_called_once_with(0.25)

    def test_readiness_rejects_late_success(self) -> None:
        with mock.patch.object(linearity_test.time, "monotonic",
                               side_effect=[10.0, 10.0, 12.0]):
            with self.assertRaises(SystemExit):
                linearity_test.wait_ready("listener", lambda timeout: True, {}, 1.0)


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
