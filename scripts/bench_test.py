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
import socket
import sys
import tempfile
import threading
import unittest
from typing import Dict, List, Optional, Sequence, Set, Tuple
from unittest import mock

import bench

# Seconds a fake iperf3 run takes on the fake clock.
SCENARIO_SECONDS = 1.0


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

    def _established_sessions(self, _api_port: int) -> Optional[int]:
        self.sessions_queries += 1
        return self._sessions_now()

    def _listening_ports(self, pid: int) -> Set[int]:
        return self.held_ports.get(pid, set())

    def _popen(self, *args: object, **kwargs: object) -> _FakeProcess:
        proc = _FakeProcess()
        self.held_ports[proc.pid] = set(BENCH_PORTS)
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

    def test_ready_timeout_and_tunnels_must_be_positive(self) -> None:
        for argv in (["--ready-timeout", "0"], ["--tunnels", "0"]):
            with self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                bench.parse_args(argv)

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

    def test_established_sessions_of_a_closed_port_is_none(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.assertIsNone(bench.established_sessions(port))


if __name__ == "__main__":
    unittest.main()
