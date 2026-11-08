#!/usr/bin/env python3
"""Regression tests for benchmark readiness and measurement aggregation.

Run from the project root: python3 scripts/bench_test.py
"""

from __future__ import annotations

import contextlib
import http.server
import io
import math
import os
import pathlib
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from typing import Dict, List, Optional, Sequence, Set, Tuple
from unittest import mock

import bench
import gprof

# Seconds a fake iperf3 run takes on the fake clock.
SCENARIO_SECONDS = 1.0


class BoundedFileReadTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = bench.ROOT / "build/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "input"

    def test_log_tails_preserve_splitlines_and_replacement_decoding(self) -> None:
        text = ("head " + "x" * 65530 + "\r\n" +
                "\n\v\f\x1c\x1d\x1e\x85\u2028\u2029".join(
                    "  line %d \t" % index for index in range(200)))
        data = text.encode() + b"\ninvalid \xff  \n \t\nunterminated"
        self.path.write_bytes(data)
        decoded = data.decode("utf-8", errors="replace")
        lines = [line.rstrip() for line in decoded.splitlines() if line.strip()]
        # Reject the old whole-file read while exercising both public diagnostics.
        with mock.patch.object(pathlib.Path, "read_text",
                               side_effect=AssertionError("whole log read")):
            for count in (1, 20, 300, 0, -2):
                self.assertEqual(bench._log_tail(self.path, count),
                                 "\n".join(lines[-count:]))
            proc = mock.Mock()
            proc.poll.return_value = 7
            with self.assertRaises(SystemExit) as caught:
                gprof.verify_process_running(proc, "fixture", log_path=self.path,
                                             wait_seconds=0)
            self.assertEqual(str(caught.exception),
                             "fixture exited early (status 7). Last log lines:\n" +
                             "\n".join(lines[-20:]))

    def test_log_tail_fallbacks(self) -> None:
        self.assertEqual(bench._log_tail(None), "(no log)")
        self.assertEqual(bench._log_tail(self.path), "(no log)")
        self.path.write_text(" \t\n\v")
        self.assertEqual(bench._log_tail(self.path), "(log empty)")
        self.assertEqual(bench._log_tail(self.path.parent), "(log unreadable)")
        for path in (None, self.path, self.path.parent):
            with self.subTest(path=path):
                proc = mock.Mock()
                proc.poll.return_value = 1
                with self.assertRaises(SystemExit) as caught:
                    gprof.verify_process_running(proc, "fixture", log_path=path,
                                                 wait_seconds=0)
                self.assertTrue(str(caught.exception).endswith("(no log available)"))

    def test_file_digest_reads_bounded_chunks_and_preserves_errors(self) -> None:
        import hashlib
        for data in (b"", b"small", bytes(range(256)) * 1025):
            with self.subTest(length=len(data)):
                self.path.write_bytes(data)
                stream = io.BytesIO(data)
                read = stream.read
                sizes = []
                def bounded_read(size=-1):
                    self.assertGreater(size, 0)
                    self.assertLessEqual(size, 65536)
                    sizes.append(size)
                    return read(size)
                with mock.patch.object(stream, "read", side_effect=bounded_read), \
                     mock.patch.object(pathlib.Path, "open", return_value=stream), \
                     mock.patch.object(pathlib.Path, "read_bytes",
                                       side_effect=AssertionError("whole file read")):
                    self.assertEqual(bench.file_sha256(self.path),
                                     hashlib.sha256(data).hexdigest())
                self.assertTrue(sizes)
                self.assertTrue(stream.closed)
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            bench.file_sha256(self.path)
        with self.assertRaises(IsADirectoryError):
            bench.file_sha256(self.path.parent)


class _FakeClock:
    """Stands in for bench's time module: sleeping advances the clock."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _FakeProcess:
    _next_pid = 1 << 22

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.pid = _FakeProcess._next_pid
        _FakeProcess._next_pid += 1
        self.returncode: Optional[int] = None

    def poll(self) -> Optional[int]:
        return self.returncode

    def send_signal(self, _signum: int) -> None:
        self.returncode = 0

    def wait(self, timeout: Optional[float] = None) -> int:
        return 0 if self.returncode is None else self.returncode


class _NullSampler:
    def __init__(self, procs: Sequence[Tuple[str, int]]) -> None:
        self._procs = list(procs)

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def results(self) -> List[bench.ResourceUsage]:
        return []


class _StatsHandler(http.server.BaseHTTPRequestHandler):
    body = ""

    def do_GET(self) -> None:
        payload = self.body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


def _config_ports(value: object) -> Set[int]:
    """Collect every port a generated daemon config names."""
    if isinstance(value, dict):
        return set().union(*(_config_ports(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_config_ports(item) for item in value))
    if isinstance(value, str) and value.startswith("127.0.0.1:"):
        return {int(value.rpartition(":")[2])}
    return set()


SERVER_CONFIG = bench.build_server_config(use_tls=False)
CLIENT_CONFIG = bench.build_client_config(use_tls=False)
# Every fixed port the benchmark's daemons and iperf3 server bind or dial.
BENCH_PORTS = _config_ports(SERVER_CONFIG) | _config_ports(CLIENT_CONFIG)
CLIENT_API_PORT = int(str(CLIENT_CONFIG.get("api_listen", ":0"))
                      .rpartition(":")[2])


def _iperf_report() -> Dict[str, object]:
    summary = {"bits_per_second": 1.0, "seconds": SCENARIO_SECONDS}
    return {
        "end": {"sum_sent": summary, "sum_received": summary, "streams": []},
        "intervals": [],
    }


def _forward_report() -> Dict[str, object]:
    return {
        "end": {
            "sum_sent": {"bits_per_second": 120_000_000, "seconds": 3.5},
            "sum_received": {"bits_per_second": 100_000_000, "seconds": 2.5},
        },
        "intervals": [
            {"sum": {"bits_per_second": bps}}
            for bps in (100_000_000, 120_000_000, 140_000_000)
        ],
    }


def _reverse_report() -> Dict[str, object]:
    return {
        "end": {
            "sum_sent": {"bits_per_second": 80_000_000, "seconds": 3.0},
            "sum_received": {"bits_per_second": 90_000_000, "seconds": 4.25},
        },
        "intervals": [
            {"sum": {"bits_per_second": bps}}
            for bps in (70_000_000, 90_000_000, 110_000_000)
        ],
    }


def _bidir_report() -> Dict[str, object]:
    # Forward streams have sender=True at both endpoints, reverse streams
    # sender=False. Only the client's forward sender and reverse receiver
    # contribute; the peer measurements deliberately differ.
    return {
        "end": {
            "streams": [
                {"sender": {"sender": True, "bits_per_second": 100_000_000,
                            "seconds": 4.0},
                 "receiver": {"sender": True, "bits_per_second": 90_000_000,
                              "seconds": 90.0}},
                {"sender": {"sender": True, "bits_per_second": 200_000_000,
                            "seconds": 5.0},
                 "receiver": {"sender": True, "bits_per_second": 180_000_000,
                              "seconds": 90.0}},
                {"sender": {"sender": False, "bits_per_second": 350_000_000,
                            "seconds": 90.0},
                 "receiver": {"sender": False, "bits_per_second": 300_000_000,
                              "seconds": 6.0}},
                {"sender": {"sender": False, "bits_per_second": 440_000_000,
                            "seconds": 90.0},
                 "receiver": {"sender": False, "bits_per_second": 400_000_000,
                              "seconds": 6.25}},
            ],
        },
        "intervals": [
            {"streams": [{"bits_per_second": 200_000_000},
                         {"bits_per_second": 600_000_000}],
             "sum": {"bits_per_second": 200_000_000}},
            {"streams": [{"bits_per_second": 300_000_000},
                         {"bits_per_second": 700_000_000}],
             "sum": {"bits_per_second": 300_000_000}},
            {"streams": [{"bits_per_second": 400_000_000},
                         {"bits_per_second": 800_000_000}],
             "sum": {"bits_per_second": 400_000_000}},
        ],
    }


class BenchMeasurementTests(unittest.TestCase):
    def test_bidir_uses_client_senders_and_receivers(self) -> None:
        report = _bidir_report()
        self.assertEqual(bench.extract_bidir_throughput(report["end"]),
                         (300_000_000.0, 700_000_000.0, 6.25))
        for scenario in bench.SCENARIOS[2:]:
            with self.subTest(scenario=scenario.name):
                self.assertEqual(
                    bench.extract_total_throughput(report, scenario),
                    (1_000_000_000.0, 300_000_000.0, 700_000_000.0, 6.25))
                self.assertEqual(
                    bench.combine_throughput([report, report], scenario),
                    (2_000_000_000.0, 600_000_000.0, 1_400_000_000.0, 6.25))

    def test_forward_reverse_summaries_and_combined_duration(self) -> None:
        forward = _forward_report()
        reverse = _reverse_report()
        self.assertEqual(
            bench.extract_total_throughput(forward, bench.SCENARIOS[0]),
            (120_000_000.0, 120_000_000.0, 100_000_000.0, 2.5))
        self.assertEqual(
            bench.extract_total_throughput(reverse, bench.SCENARIOS[1]),
            (90_000_000.0, 80_000_000.0, 90_000_000.0, 4.25))
        self.assertEqual(
            bench.combine_throughput([forward, reverse], bench.SCENARIOS[0]),
            (210_000_000.0, 200_000_000.0, 190_000_000.0, 4.25))

    def test_summary_duration_falls_back_to_sender(self) -> None:
        report = {"end": {
            "sum_sent": {"bits_per_second": 12.5, "seconds": 3.75},
            "sum_received": {"bits_per_second": 10.0, "seconds": "missing"},
        }}
        self.assertEqual(
            bench.extract_total_throughput(report, bench.SCENARIOS[0]),
            (12.5, 12.5, 10.0, 3.75))

    def test_empty_summaries_and_reports_are_zero(self) -> None:
        for scenario in bench.SCENARIOS:
            with self.subTest(scenario=scenario.name):
                self.assertEqual(bench.combine_throughput([], scenario),
                                 (0.0, 0.0, 0.0, 0.0))
                self.assertEqual(bench.extract_total_throughput(
                    {"end": {"streams": []}}, scenario),
                    (0.0, 0.0, 0.0, 0.0))

    def test_missing_end_or_bidir_streams_is_an_error(self) -> None:
        for end in (None, []):
            with self.subTest(end=end), self.assertRaisesRegex(
                    SystemExit, "missing end summary"):
                bench.extract_total_throughput({"end": end}, bench.SCENARIOS[0])
        for streams in (None, {}):
            with self.subTest(streams=streams), self.assertRaisesRegex(
                    SystemExit, "missing end.streams"):
                bench.extract_bidir_throughput({"streams": streams})

    def test_interval_stream_totals_override_directional_sum(self) -> None:
        self.assertEqual(bench.extract_interval_throughputs(_bidir_report()),
                         [800_000_000.0, 1_000_000_000.0, 1_200_000_000.0])
        # A real zero-valued stream breakdown must not fall back to sum.
        self.assertEqual(bench.extract_interval_throughputs({"intervals": [
            {"streams": [{"bits_per_second": 0}],
             "sum": {"bits_per_second": 500}},
        ]}), [0.0])

    def test_intervals_fall_back_to_sum_without_streams(self) -> None:
        self.assertEqual(bench.extract_interval_throughputs({"intervals": [
            {"sum": {"bits_per_second": 10}},
            {"streams": [], "sum": {"bits_per_second": 12.5}},
            {"streams": None, "sum": {"bits_per_second": 0}},
        ]}), [10.0, 12.5, 0.0])

    def test_missing_or_invalid_interval_values(self) -> None:
        for intervals in (None, {}, []):
            with self.subTest(intervals=intervals):
                self.assertEqual(bench.extract_interval_throughputs(
                    {"intervals": intervals}), [])
        self.assertEqual(bench.extract_interval_throughputs({}), [])
        self.assertEqual(bench.extract_interval_throughputs({"intervals": [
            None, {}, {"sum": {"bits_per_second": "bad"}},
            {"streams": [None, {}, {"bits_per_second": "bad"},
                         {"bits_per_second": 15}]},
        ]}), [0.0, 0.0, 15.0])

    def test_sample_standard_deviation(self) -> None:
        # Mean=4 and squared deviations=18; sample variance=18/(3-1).
        self.assertEqual(bench.compute_stddev([1.0, 4.0, 7.0]), 3.0)
        self.assertAlmostEqual(bench.compute_stddev([0.0, 2.0]), math.sqrt(2))
        for values in ([], [12.5], [0.0, 0.0], [12.5, 12.5, 12.5]):
            with self.subTest(values=values):
                self.assertEqual(bench.compute_stddev(values), 0.0)

    def test_combined_stddev_pools_intervals_across_reports(self) -> None:
        reports = [
            {"intervals": [{"sum": {"bits_per_second": 1}}]},
            {"intervals": []},
            {"intervals": [{"streams": [{"bits_per_second": 1},
                                        {"bits_per_second": 3}]},
                           {"sum": {"bits_per_second": 7}}]},
        ]
        self.assertEqual(bench.collect_interval_throughputs(reports),
                         [1.0, 4.0, 7.0])
        self.assertEqual(bench.compute_combined_stddev(reports), 3.0)
        self.assertEqual(bench.compute_combined_stddev([]), 0.0)
        self.assertEqual(bench.compute_combined_stddev([{"intervals": []}]), 0.0)
        self.assertEqual(bench.compute_combined_stddev(reports[:1]), 0.0)


class CleanupServicesTests(unittest.TestCase):
    def test_all_cleanup_errors_are_reported_after_every_resource_is_attempted(self) -> None:
        for module in (bench, gprof):
            for preserve_error in (False, True):
                with self.subTest(module=module.__name__, preserve_error=preserve_error):
                    processes = [mock.Mock(), mock.Mock()]
                    handles = [mock.Mock(), mock.Mock()]
                    first = OSError("child cleanup failed")
                    second = OSError("log cleanup failed")
                    handles[0].close.side_effect = second
                    order = mock.Mock()
                    order.attach_mock(handles[0].close, "first_log")
                    order.attach_mock(handles[1].close, "second_log")
                    with mock.patch.object(module, "terminate_process",
                                           side_effect=[first, None]) as terminate, \
                            mock.patch.object(module, "log") as logged:
                        order.attach_mock(terminate, "terminate")
                        order.attach_mock(logged, "log")
                        def cleanup():
                            module.cleanup_services(
                                ((processes[0], "client"), (None, "absent"),
                                 (processes[1], "server")),
                                (handles[0], None, handles[1]),
                                shutdown_budget=module.ProcessShutdownBudget(1, 1),
                                preserve_error=preserve_error)
                        if preserve_error:
                            cleanup()
                        else:
                            with self.assertRaises(OSError) as caught:
                                cleanup()
                            self.assertIs(caught.exception, first)
                    self.assertEqual([call[0] for call in order.mock_calls],
                                     ["terminate", "terminate", "first_log", "second_log",
                                      "log", "log"])
                    self.assertIn("child cleanup failed", logged.call_args_list[0].args[0])
                    self.assertIn("log cleanup failed", logged.call_args_list[1].args[0])

    def test_log_failure_is_raised_after_other_handles_close(self) -> None:
        for module in (bench, gprof):
            with self.subTest(module=module.__name__):
                handles = [mock.Mock(), mock.Mock()]
                error = OSError("log close failed")
                handles[0].close.side_effect = error
                with mock.patch.object(module, "log"):
                    with self.assertRaises(OSError) as caught:
                        module.cleanup_services(
                            (), handles,
                            shutdown_budget=module.ProcessShutdownBudget(1, 1),
                            preserve_error=False)
                self.assertIs(caught.exception, error)
                handles[1].close.assert_called_once_with()


    def test_real_children_and_logs_are_released_after_first_cleanup_error(self) -> None:
        scratch = pathlib.Path("build/tmp")
        scratch.mkdir(parents=True, exist_ok=True)
        for module in (bench, gprof):
            with self.subTest(module=module.__name__), \
                    tempfile.TemporaryDirectory(dir=scratch) as temp:
                handles = []
                processes = []
                error = OSError("injected failure after first child shutdown")
                stop = module.terminate_process
                try:
                    for i in range(3):
                        handle = (pathlib.Path(temp) / ("child-%d.log" % i)).open("w")
                        handles.append(handle)
                        processes.append(subprocess.Popen(
                            [sys.executable, "-c", "import signal; signal.pause()"],
                            stdout=handle, stderr=subprocess.STDOUT))

                    def stop_then_fail(proc, name, *, shutdown_budget):
                        stop(proc, name, shutdown_budget=shutdown_budget)
                        if proc is processes[0]:
                            raise error

                    with mock.patch.object(module, "terminate_process", side_effect=stop_then_fail), \
                            mock.patch.object(module, "log"):
                        with self.assertRaises(OSError) as caught:
                            module.cleanup_services(
                                tuple((proc, "child %d" % i)
                                      for i, proc in enumerate(processes)),
                                handles, shutdown_budget=module.ProcessShutdownBudget(.5, .5),
                                preserve_error=False)
                    self.assertIs(caught.exception, error)
                    self.assertTrue(all(proc.poll() is not None for proc in processes))
                    self.assertTrue(all(handle.closed for handle in handles))
                finally:
                    for proc in processes:
                        if proc.poll() is None:
                            proc.kill()
                        proc.wait(timeout=2)
                    for handle in handles:
                        handle.close()


class BenchReadinessTests(unittest.TestCase):
    """Drive main() with the daemons faked out and the client's established
    session count scripted on a fake clock."""

    def setUp(self) -> None:
        scratch = pathlib.Path("build/tmp")
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=scratch)
        self.build_dir = pathlib.Path(self.temp_dir.name)
        (self.build_dir / "bin").mkdir()
        (self.build_dir / "bin" / "multiplexd").touch()
        self.clock = _FakeClock()
        # (from time, established sessions) steps, in time order.
        self.session_steps: List[Tuple[float, int]] = [(0.0, 0)]
        # Ports the fake daemons hold; a pid missing here holds none.
        self.held_ports: Dict[int, Set[int]] = {}
        self.processes: List[_FakeProcess] = []
        self.sessions_at_scenario_start: List[int] = []
        self.sessions_queries = 0

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _sessions_now(self) -> int:
        count = 0
        for start, value in self.session_steps:
            if self.clock.now >= start:
                count = value
        return count

    def _established_sessions(self, _api_port: int, *,
                              deadline: Optional[float] = None) -> Optional[int]:
        self.sessions_queries += 1
        return self._sessions_now()

    def _listening_ports(self, pid: int) -> Set[int]:
        return self.held_ports.get(pid, set())

    def _popen(self, *args: object, **kwargs: object) -> _FakeProcess:
        proc = _FakeProcess()
        self.held_ports[proc.pid] = set(BENCH_PORTS)
        self.processes.append(proc)
        return proc

    def _run_json_command(self, *args: object,
                          **kwargs: object) -> Dict[str, object]:
        self.sessions_at_scenario_start.append(self._sessions_now())
        self.clock.now += SCENARIO_SECONDS
        return _iperf_report()

    def _main(self, *extra: str) -> int:
        argv = [
            "--build-dir", str(self.build_dir),
            "--output", str(self.build_dir / "bench.md"),
            "--no-tls",
            "--iperf3", sys.executable,
            "-t", "1",
            "--tunnels", "2",
            *extra,
        ]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(bench, "time", self.clock))
            stack.enter_context(mock.patch.object(
                bench.subprocess, "Popen", side_effect=self._popen))
            stack.enter_context(mock.patch.object(
                bench, "ProcSampler", _NullSampler))
            stack.enter_context(mock.patch.object(
                bench, "run_json_command", side_effect=self._run_json_command))
            stack.enter_context(mock.patch.object(
                bench, "listening_ports", create=True,
                side_effect=self._listening_ports))
            stack.enter_context(mock.patch.object(
                bench, "established_sessions", create=True,
                side_effect=self._established_sessions))
            stack.enter_context(mock.patch.object(bench, "log"))
            return bench.main(argv)

    def test_first_scenario_waits_for_a_tunnel_on_the_backoff_rung(
            self) -> None:
        # The second tunnel's first dials were refused, so it comes up on
        # the 2.0 s reconnect rung, well after any fixed startup sleep.
        self.session_steps = [(0.0, 0), (0.3, 1), (2.6, 2)]
        self.assertEqual(self._main(), 0)
        self.assertEqual(len(self.sessions_at_scenario_start),
                         len(bench.SCENARIOS))
        self.assertEqual(min(self.sessions_at_scenario_start), 2)

    def test_scenario_after_a_dropped_tunnel_waits_for_its_return(
            self) -> None:
        self.session_steps = [(0.0, 2), (0.5, 1), (4.0, 2)]
        self.assertEqual(self._main(), 0)
        self.assertEqual(min(self.sessions_at_scenario_start), 2)
        self.assertGreaterEqual(self.clock.now, 4.0)

    def test_tunnel_that_never_establishes_fails_before_measuring(
            self) -> None:
        self.session_steps = [(0.0, 1)]
        with self.assertRaises(SystemExit) as caught:
            self._main()
        self.assertIn("1 of 2 tunnel sessions", str(caught.exception))
        self.assertEqual(self.sessions_at_scenario_start, [])
        self.assertFalse((self.build_dir / "bench.md").exists())

    def test_stats_are_not_trusted_until_the_client_owns_the_api_port(
            self) -> None:
        # A stale daemon answers on the client's API port with a full
        # session count, while the client under test never bound it.
        self.session_steps = [(0.0, 2)]
        popen = self._popen

        def popen_without_api(*args: object, **kwargs: object) -> _FakeProcess:
            proc = popen(*args, **kwargs)
            if "client.json" in " ".join(str(part) for part in args[0]):
                self.held_ports[proc.pid].discard(CLIENT_API_PORT)
            return proc

        self._popen = popen_without_api  # type: ignore[method-assign]
        with self.assertRaises(SystemExit) as caught:
            self._main("--ready-timeout", "1")
        self.assertIn("multiplexd client is not listening on port %d"
                      % CLIENT_API_PORT, str(caught.exception))
        self.assertEqual(self.sessions_queries, 0)
        self.assertEqual(self.sessions_at_scenario_start, [])

    def test_successful_probe_after_deadline_refuses_measurement(self) -> None:
        def late_sessions(_api_port: int, **_kwargs: object) -> int:
            self.clock.now += 1.1
            return 2

        with mock.patch.object(self, "_established_sessions",
                               side_effect=late_sessions):
            with self.assertRaisesRegex(SystemExit, "readiness deadline expired"):
                self._main("--ready-timeout", "1")
        self.assertEqual(self.sessions_at_scenario_start, [])
        self.assertFalse((self.build_dir / "bench.md").exists())

    def test_retry_wait_is_capped_to_remaining_budget(self) -> None:
        self.session_steps = [(0.0, 1)]
        budget = bench.READY_POLL_INTERVAL / 2
        with self.assertRaises(SystemExit):
            self._main("--ready-timeout", str(budget))
        self.assertEqual(self.clock.now, budget)
        self.assertEqual(self.sessions_queries, 1)
        self.assertEqual(self.sessions_at_scenario_start, [])

    def test_listener_probe_exhausting_budget_skips_stats_request(self) -> None:
        def late_listeners(pid: int) -> Set[int]:
            self.clock.now += 1.1
            return self.held_ports.get(pid, set())

        with mock.patch.object(self, "_listening_ports", side_effect=late_listeners), \
                mock.patch.object(self, "_established_sessions",
                                  side_effect=bench.established_sessions), \
                mock.patch.object(bench, "api_request", return_value=(
                    200, "Sessions: 0 / 0 (+0)")) as request:
            with self.assertRaises(SystemExit):
                self._main("--ready-timeout", "1")
        request.assert_not_called()
        self.assertEqual(self.sessions_at_scenario_start, [])

    def test_ready_timeout_and_tunnels_must_be_positive(self) -> None:
        for argv in (["--ready-timeout", "0"], ["--tunnels", "0"]):
            with self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                bench.parse_args(argv)

    def test_daemon_exit_during_measurement_refuses_the_report(self) -> None:
        self.session_steps = [(0.0, 2)]
        run_command = self._run_json_command
        names = ("iperf3 server", "multiplexd server", "multiplexd client")
        for scenario_count in (1, len(bench.SCENARIOS)):
            for index, name in enumerate(names):
                for status in (0, 1):
                    with self.subTest(scenario_count=scenario_count,
                                      daemon=name, status=status):
                        self.processes.clear()
                        self.sessions_at_scenario_start.clear()

                        def exit_during_command(*args: object,
                                                **kwargs: object
                                                ) -> Dict[str, object]:
                            report = run_command(*args, **kwargs)
                            if (len(self.sessions_at_scenario_start)
                                    == scenario_count):
                                self.processes[index].returncode = status
                            return report

                        with mock.patch.object(self, "_run_json_command",
                                               side_effect=exit_during_command), \
                                mock.patch.object(_NullSampler, "results",
                                                  return_value=[]) as samples:
                            with self.assertRaises(SystemExit) as caught:
                                self._main()
                        self.assertEqual(samples.call_count, scenario_count - 1)
                        self.assertIn(
                            "%s exited early (status %d)" % (name, status),
                            str(caught.exception))
                        self.assertEqual(len(self.sessions_at_scenario_start),
                                         scenario_count)
                        self.assertFalse((self.build_dir / "bench.md").exists())
                        self.assertTrue(all(proc.poll() is not None
                                            for proc in self.processes))

    def test_daemon_exit_while_assembling_final_result_refuses_report(
            self) -> None:
        self.session_steps = [(0.0, 2)]
        collect_intervals = bench.collect_interval_throughputs

        def exit_during_collection(
                reports: Sequence[Dict[str, object]]) -> List[float]:
            intervals = collect_intervals(reports)
            if len(self.sessions_at_scenario_start) == len(bench.SCENARIOS):
                self.processes[-1].returncode = 1
            return intervals

        with mock.patch.object(bench, "collect_interval_throughputs",
                               side_effect=exit_during_collection):
            with self.assertRaises(SystemExit) as caught:
                self._main()
        self.assertIn("multiplexd client exited early (status 1)",
                      str(caught.exception))
        self.assertEqual(len(self.sessions_at_scenario_start),
                         len(bench.SCENARIOS))
        self.assertFalse((self.build_dir / "bench.md").exists())
        self.assertTrue(all(proc.poll() is not None for proc in self.processes))

    def test_cleanup_failure_still_stops_every_child_and_closes_logs(self) -> None:
        self.session_steps = [(0.0, 2)]
        for primary in (None, RuntimeError("benchmark failed")):
            for cleanup_error in (subprocess.TimeoutExpired("client", 2),
                                  OSError("cannot signal client")):
                with self.subTest(primary=primary, cleanup=cleanup_error):
                    self.processes.clear()
                    self.sessions_at_scenario_start.clear()
                    output = self.build_dir / "bench.md"
                    output.write_text("previous report\n")
                    expected = primary if primary is not None else cleanup_error
                    handles = []
                    open_log = bench.open_log

                    def record_log(path: pathlib.Path):
                        handle = open_log(path)
                        handles.append(handle)
                        self.addCleanup(handle.close)
                        return handle

                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            bench, "open_log", side_effect=record_log))
                        terminate = stack.enter_context(mock.patch.object(
                            bench, "terminate_process", side_effect=[cleanup_error, None, None]))
                        if primary is not None:
                            stack.enter_context(mock.patch.object(
                                self, "_run_json_command", side_effect=primary))
                        with self.assertRaises(type(expected)) as caught:
                            self._main()
                    self.assertIs(caught.exception, expected)
                    self.assertEqual([call.args[0] for call in terminate.call_args_list],
                                     list(reversed(self.processes)))
                    self.assertEqual(len(handles), 3)
                    self.assertTrue(all(handle.closed for handle in handles))
                    self.assertEqual(output.read_text(), "previous report\n")

    def test_nonempty_measurements_reach_the_markdown_report(self) -> None:
        self.session_steps = [(0.0, 2)]
        with mock.patch.object(self, "_run_json_command",
                               side_effect=[_forward_report(), _reverse_report(),
                                            _bidir_report(), _bidir_report()]):
            self.assertEqual(self._main(), 0)
        report = (self.build_dir / "bench.md").read_text(encoding="utf-8")
        self.assertIn(
            "| Uplink | 120.00 Mbit/s | 120.00 Mbit/s | 100.00 Mbit/s | "
            "20.00 Mbit/s | 2.50 s |", report)
        self.assertIn(
            "| Downlink | 90.00 Mbit/s | 80.00 Mbit/s | 90.00 Mbit/s | "
            "20.00 Mbit/s | 4.25 s |", report)
        for label in ("Bidirectional", "Parallel Bidirectional"):
            self.assertIn(
                "| %s | 1.00 Gbit/s | 300.00 Mbit/s | 700.00 Mbit/s | "
                "200.00 Mbit/s | 6.25 s |" % label, report)
        self.assertIn("| 1 | 100.00 Mbit/s |", report)
        self.assertIn("| 2 | 120.00 Mbit/s |", report)
        self.assertIn("| 3 | 140.00 Mbit/s |", report)
        self.assertIn("| 1 | 70.00 Mbit/s |", report)
        self.assertIn("| 2 | 90.00 Mbit/s |", report)
        self.assertIn("| 3 | 110.00 Mbit/s |", report)
        self.assertEqual(report.count("| 1 | 800.00 Mbit/s |"), 2)
        self.assertEqual(report.count("| 2 | 1.00 Gbit/s |"), 2)
        self.assertEqual(report.count("| 3 | 1.20 Gbit/s |"), 2)


class BenchProbeTests(unittest.TestCase):
    """The readiness probes against real sockets and a real HTTP server."""

    def test_listening_ports_reports_only_own_listeners(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, \
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bound:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            bound.bind(("127.0.0.1", 0))
            ports = bench.listening_ports(os.getpid())
            self.assertIn(listener.getsockname()[1], ports)
            self.assertNotIn(bound.getsockname()[1], ports)

    def test_listening_ports_of_a_missing_pid_is_empty(self) -> None:
        self.assertEqual(bench.listening_ports(1 << 30), set())

    def test_established_sessions_parses_stats(self) -> None:
        _StatsHandler.body = (
            "multiplexd 1.0\n  https://example.invalid\n\n"
            "Server Time         : 2026-09-28T00:00:00+00:00\n"
            "Sessions            : 3 / 4 (+1)\n"
            "Streams             : 0 (+0)\n")
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _StatsHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            self.assertEqual(
                bench.established_sessions(server.server_port), 3)
            _StatsHandler.body = "Streams             : 0 (+0)\n"
            self.assertIsNone(
                bench.established_sessions(server.server_port))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_stats_request_uses_remaining_readiness_budget(self) -> None:
        clock = _FakeClock()
        clock.now = 10.0
        with mock.patch.object(bench, "time", clock), \
                mock.patch.object(bench, "api_request", return_value=(
                    200, "Sessions: 2 / 2 (+0)")) as request:
            self.assertEqual(bench.established_sessions(1234, deadline=10.25), 2)
            request.assert_called_once_with(1234, "/stats", timeout=0.25)
            request.reset_mock()
            self.assertIsNone(bench.established_sessions(1234, deadline=10.0))
            request.assert_not_called()

    def test_established_sessions_of_a_closed_port_is_none(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.assertIsNone(bench.established_sessions(port))


class CompareProcessIsolationTests(unittest.TestCase):
    """Exercise owned benchmark processes beside an existing same-binary service."""

    def setUp(self) -> None:
        scratch = bench.ROOT / "build" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    @staticmethod
    def cleanup_process(proc: subprocess.Popen) -> None:
        try:
            try:
                proc.stdin.close()
            finally:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        finally:
            proc.stdout.close()

    def test_common_sampler_excludes_existing_same_executable(self) -> None:
        binary = self.root / "tlswrapper"
        binary.symlink_to(sys.executable)
        service_code = (
            "import os,time; start=time.process_time()\n"
            "while time.process_time()-start < 0.6: pass\n"
            "os.write(1,b'ready\\n'); os.read(0,1)\n")
        child_code = (
            "import os,time; os.read(0,1); start=time.process_time()\n"
            "while time.process_time()-start < 0.15: pass\n"
            "os.write(1,b'done\\n'); os.read(0,1)\n")
        children = []
        service = subprocess.Popen([str(binary), "-c", service_code],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.addCleanup(self.cleanup_process, service)
        self.assertTrue(select.select([service.stdout], [], [], 5)[0])
        self.assertEqual(service.stdout.readline(), b"ready\n")
        prior = sum(bench.read_proc_cpu_ticks(service.pid)) / bench.CLK_TCK
        for _ in range(2):
            child = subprocess.Popen([str(binary), "-c", child_code],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self.addCleanup(self.cleanup_process, child)
            children.append(child)
        sampler = bench.ProcSampler([("h2mux %d" % i, proc.pid)
                                     for i, proc in enumerate(children)])
        sampler.start()
        try:
            for proc in children:
                proc.stdin.write(b"x")
                proc.stdin.flush()
            for proc in children:
                self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
                self.assertEqual(proc.stdout.readline(), b"done\n")
        finally:
            sampler.stop()
        cpu = sum(p.user_seconds + p.sys_seconds for p in sampler.results())
        self.assertGreater(cpu, 0)
        self.assertLess(cpu, prior, "pre-existing service CPU entered this run")
        self.assertIsNone(service.poll(), "existing service was signalled")

    def test_occupied_port_is_not_contacted_or_reclaimed(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            with mock.patch.object(bench.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(SystemExit, "unavailable"):
                    bench.run_owned_benchmark(
                        ["must-not-start"], self.root,
                        ports=(listener.getsockname()[1],))
            launch.assert_not_called()
            self.assertEqual(listener.getsockopt(socket.SOL_SOCKET,
                                                socket.SO_ACCEPTCONN), 1)
            self.assertFalse(select.select([listener], [], [], 0)[0])

    def test_active_binary_is_not_rebuilt(self) -> None:
        with mock.patch.object(bench, "check_benchmark_ports") as ports:
            with self.assertRaisesRegex(SystemExit, "binary is in use"):
                bench.check_benchmark_environment([pathlib.Path(sys.executable)])
        ports.assert_not_called()

    def test_timeout_cleans_only_the_owned_session(self) -> None:
        service = subprocess.Popen(
            [sys.executable, "-c", "import os; os.read(0,1)"],
            stdin=subprocess.PIPE)
        launched = []
        real_popen = subprocess.Popen

        def launch(*args: object, **kwargs: object) -> subprocess.Popen:
            proc = real_popen(*args, **kwargs)
            launched.append(proc)
            return proc

        try:
            with mock.patch.object(bench.subprocess, "Popen", side_effect=launch):
                result = bench.run_owned_benchmark(
                    [sys.executable, "-c", "import signal; signal.pause()"],
                    self.root, timeout_seconds=0.1, ports=())
            self.assertEqual(result, 124)
            self.assertIsNotNone(launched[0].poll())
            self.assertIsNone(service.poll())
        finally:
            service.stdin.close()
            service.wait(timeout=5)

    def test_failed_attempt_removes_stale_cpu_result(self) -> None:
        cpu = self.root / "cpu.txt"
        cpu.write_text("99999\n")
        result = bench.run_owned_benchmark(
            [sys.executable, "-c", "raise SystemExit(7)"], self.root,
            cpu_output=cpu, daemon_binary=pathlib.Path(sys.executable), ports=())
        self.assertEqual(result, 7)
        self.assertFalse(cpu.exists())

    def test_sampler_keeps_lifetimes_and_excludes_other_sessions_and_helpers(self) -> None:
        procfs = self.root / "proc"
        procfs.mkdir()
        binary = pathlib.Path(sys.executable).resolve()

        def process(pid: int, start: int, session: int, cpu: int,
                    args: bytes = b"tlswrapper\0-c\0config\0") -> None:
            entry = procfs / str(pid)
            entry.mkdir(exist_ok=True)
            fields = ["0"] * 20
            fields[0], fields[3] = "S", str(session)
            fields[11], fields[19] = str(cpu), str(start)
            (entry / "stat").write_text(
                "%d (name with ) parentheses) %s" % (pid, " ".join(fields)))
            (entry / "cmdline").write_bytes(args)
            if not (entry / "exe").exists():
                (entry / "exe").symlink_to(binary)

        process(10, 100, 1, 7)
        process(11, 200, 1, 9)
        process(12, 300, 2, 9999)
        process(13, 400, 1, 9999, b"tlswrapper\0--gencerts\0")
        ticks = {}
        with mock.patch.object(bench, "Path", return_value=procfs):
            bench.sample_session_cpu(1, binary, ticks)
            self.assertEqual(ticks, {(10, 100): 7, (11, 200): 9})
            (procfs / "11" / "stat").unlink()
            process(10, 500, 1, 3)  # A reused PID is a different lifetime.
            bench.sample_session_cpu(1, binary, ticks)
            self.assertEqual(ticks, {(10, 100): 7, (11, 200): 9, (10, 500): 3})

    def test_interrupt_reaps_owned_process_and_preserves_existing_service(self) -> None:
        service = subprocess.Popen(
            [sys.executable, "-c", "import os; os.read(0,1)"],
            stdin=subprocess.PIPE)
        command = (
            "import pathlib,sys\n"
            "sys.path.insert(0, %r)\n"
            "from bench import run_owned_benchmark\n"
            "child=[sys.executable,'-c',"
            "'import os; print(os.getpid(),flush=True); os.read(0,1)']\n"
            "raise SystemExit(run_owned_benchmark(child,pathlib.Path.cwd(),ports=()))\n"
            % str(bench.ROOT / "scripts"))
        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(signal=signum):
                    supervisor = subprocess.Popen(
                        [sys.executable, "-c", command], cwd=bench.ROOT,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    try:
                        self.assertTrue(select.select([supervisor.stdout], [], [], 5)[0])
                        child_pid = int(supervisor.stdout.readline())
                        supervisor.send_signal(signum)
                        self.assertEqual(supervisor.wait(timeout=5), 128 + signum)
                        self.assertFalse(pathlib.Path("/proc", str(child_pid)).exists())
                        self.assertIsNone(service.poll())
                    finally:
                        supervisor.stdin.close()
                        supervisor.stdout.close()
                        if supervisor.poll() is None:
                            supervisor.terminate()
                            supervisor.wait(timeout=5)
        finally:
            service.stdin.close()
            service.wait(timeout=5)


class SamplerCleanupTests(unittest.TestCase):
    @staticmethod
    def process(pid: int):
        proc = mock.Mock(pid=pid)
        proc.wait.return_value = 0
        proc.stdout.readline.return_value = b"ready\n"
        return proc

    def test_failed_readiness_reaps_timed_out_service_and_closes_pipes(self) -> None:
        proc = self.process(42001)
        proc.wait.side_effect = [subprocess.TimeoutExpired("fixture", 5), 0]
        fixture = CompareProcessIsolationTests(
            "test_common_sampler_excludes_existing_same_executable")
        result = unittest.TestResult()
        with mock.patch.object(subprocess, "Popen", return_value=proc), \
             mock.patch.object(select, "select", return_value=([], [], [])):
            fixture.run(result)
        self.assertEqual(len(result.failures), 1)  # The readiness failure survives.
        self.assertEqual(result.errors, [])
        proc.kill.assert_called_once_with()
        self.assertEqual(proc.wait.call_args_list,
                         [mock.call(timeout=5), mock.call(timeout=5)])
        proc.stdin.close.assert_called_once_with()
        proc.stdout.close.assert_called_once_with()

    def test_one_cleanup_error_does_not_abandon_other_children(self) -> None:
        for stage in (None, "stdin", "reap", "stdout"):
            with self.subTest(stage=stage):
                service, first, last = [self.process(42001 + i) for i in range(3)]
                failure = OSError("cleanup failure")
                last.wait.side_effect = [subprocess.TimeoutExpired("fixture", 5),
                                         failure if stage == "reap" else 0]
                if stage == "stdin":
                    last.stdin.close.side_effect = failure
                elif stage == "stdout":
                    last.stdout.close.side_effect = failure
                sampler = mock.Mock()
                sampler.start.side_effect = RuntimeError("sampler setup failed")
                fixture = CompareProcessIsolationTests(
                    "test_common_sampler_excludes_existing_same_executable")
                result = unittest.TestResult()
                with mock.patch.object(subprocess, "Popen",
                                       side_effect=[service, first, last]), \
                     mock.patch.object(select, "select",
                                       return_value=([service.stdout], [], [])), \
                     mock.patch.object(bench, "read_proc_cpu_ticks", return_value=(100, 0)), \
                     mock.patch.object(bench, "ProcSampler", return_value=sampler):
                    fixture.run(result)
                self.assertEqual(result.failures, [])
                self.assertEqual(len(result.errors), 1 if stage is None else 2)
                self.assertIn("sampler setup failed", result.errors[0][1])
                if stage is not None:
                    self.assertIn("cleanup failure", result.errors[1][1])
                for proc in (service, first, last):
                    proc.stdin.close.assert_called_once_with()
                    proc.stdout.close.assert_called_once_with()
                last.kill.assert_called_once_with()
                self.assertEqual(last.wait.call_args_list,
                                 [mock.call(timeout=5), mock.call(timeout=5)])
                for proc in (service, first):
                    proc.wait.assert_called_once_with(timeout=5)
                    proc.kill.assert_not_called()


class RepeatedMeasurementTests(unittest.TestCase):
    @staticmethod
    def trial(rate: float, *, deviation: float = 1.0, duration: int = 20) -> Dict[str, object]:
        return {
            "total_bits_per_second": rate,
            "stddev_bits_per_second": deviation,
            "interval_throughputs": [rate] * duration,
            "sent_bits_per_second": rate,
            "received_bits_per_second": rate,
            "transferred_bytes": rate * duration / 8,
            "resource_usage": [{"user_seconds": duration / 8, "sys_seconds": duration / 8,
                                "real_seconds": duration, "runnable_wait_seconds": 0.1}
                               for _ in range(2)],
        }

    def analyze(self, reference: Sequence[float], candidate: Sequence[float], **kwargs: object) -> Dict[str, object]:
        options = dict(max_cv=0.05, max_interval_cv=0.10, duration=20, warmup=3)
        options.update(kwargs)
        return bench.analyze_pair([self.trial(rate) for rate in reference],
                                  [self.trial(rate) for rate in candidate], **options)

    def test_stable_pairs_report_observed_ratio_range(self) -> None:
        result = self.analyze([100, 101, 99, 100], [90, 90.9, 89.1, 90])
        self.assertEqual(result["status"], "stable")
        self.assertAlmostEqual(result["ratio_median"], 0.9)
        self.assertAlmostEqual(result["ratio_min"], 0.9)
        self.assertAlmostEqual(result["ratio_max"], 0.9)

    def test_common_drift_is_unstable_even_when_ratio_looks_perfect(self) -> None:
        result = self.analyze([100, 60, 100, 60], [200, 120, 200, 120])
        self.assertEqual(result["status"], "unstable")
        self.assertEqual(result["ratio_cv"], 0)
        self.assertTrue(any("reference repeat CV" in reason for reason in result["reasons"]))

    def test_pairing_does_not_hide_opposing_drift(self) -> None:
        result = self.analyze([100, 101, 99, 100], [80, 100, 120, 140])
        self.assertEqual(result["status"], "unstable")
        self.assertGreater(result["ratio_cv"], 0.05)

    def test_single_run_instability_is_not_hidden_by_repeat_medians(self) -> None:
        reference = [self.trial(100) for _ in range(4)]
        candidate = [self.trial(100, deviation=30) for _ in range(4)]
        result = bench.analyze_pair(reference, candidate, max_cv=0.05,
                                    max_interval_cv=0.10, duration=20, warmup=3)
        self.assertEqual(result["status"], "unstable")
        self.assertTrue(any("interval CV" in reason for reason in result["reasons"]))

    def test_short_or_cold_runs_never_qualify_as_indicators(self) -> None:
        for change in [dict(duration=1), dict(warmup=0)]:
            result = self.analyze([100] * 4, [100] * 4, **change)
            self.assertEqual(result["status"], "unstable")
        self.assertEqual(self.analyze([100] * 2, [100] * 2)["status"], "unstable")

    def test_invalid_values_and_incomplete_pairs_are_rejected(self) -> None:
        for values in [([], []), ([100], []), ([float("nan")], [100]), ([0], [100])]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.analyze(*values)

    def test_cpu_efficiency_has_no_inverse_duration_bias(self) -> None:
        a = bench.summarize_trials([self.trial(1e9, duration=20)])
        b = bench.summarize_trials([self.trial(1e9, duration=40)])
        self.assertEqual(a["gbit_per_daemon_cpu_second"], 2)
        self.assertEqual(a["gbit_per_daemon_cpu_second"], b["gbit_per_daemon_cpu_second"])

    def test_omitted_warmup_does_not_inflate_measured_interval_variance(self) -> None:
        report = {"intervals": [
            {"sum": {"omitted": True}, "streams": [{"bits_per_second": 9999, "omitted": True}]},
            {"sum": {"omitted": False}, "streams": [{"bits_per_second": 10}]},
            {"sum": {"omitted": False}, "streams": [{"bits_per_second": 30}]},
        ]}
        self.assertEqual(bench.extract_interval_throughputs(report), [10, 30])
        self.assertAlmostEqual(bench.compute_combined_stddev([report]), math.sqrt(200))

    def test_iperf_runs_continuously_without_the_omit_reset_race(self) -> None:
        for scenario in bench.SCENARIOS:
            command = bench.build_scenario_commands("iperf3", scenario, 20, 10, 3)[0]
            self.assertNotIn("--omit", command)
            self.assertEqual(command[command.index("-t") + 1], "23")

    def test_warmup_view_uses_measured_bytes_and_actual_elapsed_time(self) -> None:
        report = {"intervals": [
            {"sum": {"start": start, "end": start + 1, "seconds": 1},
             "streams": [{"bytes": count, "bits_per_second": count * 8, "sender": True}]}
            for start, count in [(0, 9999), (1, 9999), (2, 9999), (3, 10), (4, 20)]
        ]}
        remote = {"intervals": [{"sum": dict(interval["sum"]), "streams": [dict(stream, sender=False)
                  for stream in interval["streams"]]} for interval in report["intervals"]]}
        report["server_output_json"] = remote
        view = bench.measurement_view(report, bench.SCENARIOS[0], 3)
        self.assertEqual(bench.extract_total_throughput(view, bench.SCENARIOS[0]), (120, 120, 0, 2))
        self.assertEqual(len(report["intervals"]), 5, "raw observations were mutated")
        self.assertEqual(len(view["intervals"]), 2)

    def test_iperf316_omit_reset_corruption_is_not_guessed_away(self) -> None:
        corrupt = {"intervals": [{"sum": {"start": 1.000021, "end": 1.001069,
                                          "seconds": 2.0010900497}, "streams": []}]}
        with self.assertRaisesRegex(ValueError, "inconsistent iperf"):
            bench.measurement_view(corrupt, bench.SCENARIOS[0], 3)

    def test_short_tail_does_not_get_a_whole_second_of_statistical_weight(self) -> None:
        def interval(start: float, seconds: float, rate: float) -> Dict[str, object]:
            return {"sum": {"start": start, "end": start + seconds, "seconds": seconds},
                    "streams": [{"bytes": rate * seconds / 8, "bits_per_second": rate, "sender": True}]}
        report = {"intervals": [interval(3, 1, 100), interval(4, 1, 100), interval(5, .001, 0)]}
        remote = {"intervals": [{"sum": dict(interval["sum"]), "streams": [dict(stream, sender=False)
                  for stream in interval["streams"]]} for interval in report["intervals"]]}
        report["server_output_json"] = remote
        view = bench.measurement_view(report, bench.SCENARIOS[0], 3)
        self.assertLess(bench.compute_combined_stddev([view]), 5)

    def test_sender_buffering_does_not_count_as_delivered_throughput(self) -> None:
        local = {"sum": {"start": 3, "end": 4, "seconds": 1},
                 "streams": [{"bytes": 999999, "sender": True, "bits_per_second": 7999992}]}
        remote = {"sum": dict(local["sum"]),
                  "streams": [{"bytes": 100, "sender": False, "bits_per_second": 800}]}
        report = {"intervals": [local], "server_output_json": {"intervals": [remote]}}
        view = bench.measurement_view(report, bench.SCENARIOS[0], 3)
        self.assertEqual(bench.extract_total_throughput(view, bench.SCENARIOS[0])[0], 800)
        self.assertEqual(bench.received_bytes(report), 100)

    def test_bidirectional_goodput_aligns_receiver_windows_and_ignores_tx_queues(self) -> None:
        def endpoint(start: float) -> Dict[str, object]:
            return {"intervals": [{"sum": {"start": start, "end": start + 1, "seconds": 1},
                                   "streams": [{"bytes": 100, "sender": False},
                                               {"bytes": 999999, "sender": True}]}]}
        report = endpoint(3)
        report["server_output_json"] = endpoint(3.2)
        view = bench.measurement_view(report, bench.SCENARIOS[2], 3)
        total, sent, received, seconds = bench.extract_total_throughput(view, bench.SCENARIOS[2])
        self.assertAlmostEqual(total, 1600)
        self.assertAlmostEqual(sent, 800)
        self.assertAlmostEqual(received, 800)
        self.assertAlmostEqual(seconds, .8)
        self.assertEqual(bench.received_bytes(report), 200)

    def test_preflight_covers_every_port_the_common_configs_use(self) -> None:
        ports = _config_ports(bench.build_server_config(use_tls=False))
        ports |= _config_ports(bench.build_client_config(use_tls=False))
        self.assertEqual(ports, set(bench.BENCH_PORTS))

    def test_aes_matching_requires_every_visible_cpu_to_support_gcm(self) -> None:
        self.assertTrue(bench.aes_gcm_host("flags : aes pclmulqdq sse4_1 ssse3", "x86_64"))
        self.assertFalse(bench.aes_gcm_host("flags : aes pclmulqdq sse4_1 ssse3\nflags : aes", "x86_64"))
        self.assertTrue(bench.aes_gcm_host("Features : aes pmull", "aarch64"))
        self.assertFalse(bench.aes_gcm_host("Features : aes", "aarch64"))

    def test_cpu_layout_rejects_smt_siblings_and_disallowed_cpus(self) -> None:
        with mock.patch.object(bench.os, "sched_getaffinity", return_value=set(range(8))), \
             mock.patch.object(bench, "cpu_core", side_effect=lambda cpu: (0, cpu // 2)):
            for value in ["0,1,4,6", "0,2,4,8", "0,2,4,4"]:
                with self.subTest(value=value), self.assertRaises(SystemExit):
                    bench.parse_cpu_set(value)
            self.assertEqual(bench.parse_cpu_set("0,2,4,6"), (0, 2, 4, 6))

    def test_quiet_core_selection_is_done_before_measurement(self) -> None:
        before = {cpu: (100, 50) for cpu in range(10)}
        after = {cpu: (200, 50 if cpu < 2 else 150) for cpu in range(10)}
        with mock.patch.object(bench.os, "sched_getaffinity", return_value=set(range(10))), \
             mock.patch.object(bench, "cpu_core", side_effect=lambda cpu: (0, cpu // 2)), \
             mock.patch.object(bench, "cpu_snapshot", side_effect=[before, after]), \
             mock.patch.object(bench.time, "sleep"):
            self.assertEqual(bench.select_cpus(), (2, 4, 6, 8))

    def test_coordinator_avoids_both_smt_threads_of_test_cores(self) -> None:
        with mock.patch.object(bench.os, "sched_getaffinity", return_value=set(range(12))), \
             mock.patch.object(bench, "cpu_core", side_effect=lambda cpu: (0, cpu // 2)), \
             mock.patch.object(bench.os, "sched_setaffinity") as set_affinity:
            bench.isolate_coordinator((0, 2, 4, 6))
            set_affinity.assert_called_once_with(0, {8, 9, 10, 11})


class ComparisonDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = bench.ROOT / "build/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.build = self.root / "build"
        (self.build / "bin").mkdir(parents=True)
        self.mux = self.build / "bin/multiplexd"
        self.h2 = self.root / "tlswrapper"
        for path in (self.mux, self.h2):
            path.write_bytes(b"unchanging test executable")
        self.output = self.root / "comparison.md"
        self.order = []
        self.fail_at = None
        self.noisy = False

    def run_comparison(self) -> int:
        import hashlib
        metadata = {"role_cpus": [0, 2, 4, 6],
                    "harness_sha256": hashlib.sha256(pathlib.Path(bench.__file__).read_bytes()).hexdigest(),
                    "binaries": {str(path): {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                 for path in (self.mux, self.h2)}}
        def measure(command: Sequence[str], _cwd: pathlib.Path, **kwargs: object) -> int:
            h2mux = "--h2mux-binary" in command
            self.order.append(h2mux)
            if self.fail_at == len(self.order):
                return 7
            rate = 1e9 if not h2mux else (0.5e9 if self.noisy and len(self.order) == 2 else 1.1e9)
            result = RepeatedMeasurementTests.trial(rate)
            result["scenario"] = {"name": "uplink", "label": "Uplink"}
            binary = self.h2 if h2mux else self.mux
            report = pathlib.Path(command[command.index("--report-json") + 1])
            report.write_text(bench.json.dumps({"binary": str(binary),
                "binary_sha256": metadata["binaries"][str(binary)]["sha256"], "results": [result]}))
            return 0
        with mock.patch.object(bench, "select_cpus", return_value=(0, 2, 4, 6)), \
             mock.patch.object(bench, "check_benchmark_environment"), \
             mock.patch.object(bench, "benchmark_metadata", return_value=metadata), \
             mock.patch.object(bench, "run_owned_benchmark", side_effect=measure), \
             contextlib.redirect_stdout(io.StringIO()):
            return bench.compare_main(["--build-dir", str(self.build), "--h2mux-binary", str(self.h2),
                "--freestanding", "--scenarios", "uplink", "--duration", "20", "--warmup", "3",
                "--rounds", "4", "--output", str(self.output)])

    def test_real_driver_alternates_adjacent_pairs_and_preserves_every_trial(self) -> None:
        self.assertEqual(self.run_comparison(), 0)
        self.assertEqual(self.order, [False, True, True, False, False, True, True, False])
        result = bench.json.loads(self.output.with_suffix(".json").read_text())
        self.assertEqual(len(result["trials"]), 8)
        reports = [trial["report"] for trial in result["trials"]]
        self.assertEqual(len(set(reports)), 8)
        self.assertTrue(all(pathlib.Path(path).exists() for path in reports))

    def test_noisy_observations_are_not_trimmed_or_retried_to_get_green(self) -> None:
        self.noisy = True
        self.assertEqual(self.run_comparison(), 2)
        result = bench.json.loads(self.output.with_suffix(".json").read_text())
        self.assertEqual(len(self.order), 8)
        self.assertEqual(len(result["trials"]), 8)
        self.assertEqual(result["status"], "unstable")
        self.assertIn("do not infer a winner", self.output.read_text())

    def test_failed_trial_replaces_stale_success_and_retains_partial_evidence(self) -> None:
        self.output.write_text("OLD SUCCESS, 999 Gbit/s")
        self.output.with_suffix(".json").write_text('{"status":"stable"}')
        self.fail_at = 4
        self.assertEqual(self.run_comparison(), 1)
        result = bench.json.loads(self.output.with_suffix(".json").read_text())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["trials"]), 3)
        self.assertNotIn("OLD SUCCESS", self.output.read_text())


if __name__ == "__main__":
    unittest.main()
