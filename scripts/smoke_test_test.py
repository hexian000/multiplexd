#!/usr/bin/env python3
"""Regression tests for smoke scenario isolation, load verification and start-up.

The daemons, echo servers and relay are replaced with fakes, so these run
without a build and without binding any port.
"""

from __future__ import annotations

import argparse
import subprocess
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple
from unittest import mock

import smoke_test


class _FakeDaemons:
    """Stands in for smoke_test.Daemons; records which pairs were started."""

    start_ok = True
    started: List[str] = []

    def __init__(self, binary: Path, log_dir: Path, *, tag: str,
                 **_kwargs: object) -> None:
        self.tag = tag
        self.server: Optional[object] = None
        self.client: Optional[object] = None

    def start(self) -> bool:
        _FakeDaemons.started.append(self.tag)
        return _FakeDaemons.start_ok

    def spawn(self) -> None:
        _FakeDaemons.started.append(self.tag)

    def shutdown(self) -> Tuple[Optional[int], Optional[int]]:
        return 0, 0

    def kill(self) -> None:
        pass


class _FakeListener:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


class _FakeGenerator:
    """Stands in for running multiplexd --gencerts / --genpsk.

    Like the real tool it refuses to overwrite an existing output file, and it
    writes every diagnostic to stdout, leaving stderr empty.
    """

    def __init__(self) -> None:
        self.error: Optional[str] = None

    def __call__(self, cmd: Sequence[str], *, cwd: str, stdout: int,
                 stderr: int, **_kwargs: object
                 ) -> "subprocess.CompletedProcess[bytes]":
        assert stdout == subprocess.PIPE
        name = "server-cert.pem" if "--gencerts" in cmd else "smoke~psk.psk"
        error = self.error
        if error is None:
            try:
                (Path(cwd) / name).touch(exist_ok=False)
            except FileExistsError:
                error = "failed to open %s: (17) File exists" % name
        out = b"" if error is None else ("E %s\n" % error).encode()
        err = None if stderr == subprocess.STDOUT else b""
        return subprocess.CompletedProcess(
            list(cmd), 0 if error is None else 1, out, err)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        _FakeDaemons.start_ok = True
        _FakeDaemons.started = []
        scratch = smoke_test.ROOT / "build" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=scratch)
        self.log_dir = Path(self.temp_dir.name)
        # Present, so the PSK topology does not run --genpsk.
        (self.log_dir / "smoke~psk.psk").touch()
        self.sizes = smoke_test.make_sizes(
            argparse.Namespace(quick=True, duration=1.0))
        self.stack = ExitStack()
        self.stack.enter_context(
            mock.patch.object(smoke_test, "Daemons", _FakeDaemons))
        for name in ("EchoServer", "UdpEchoServer", "MuxRelay"):
            self.stack.enter_context(
                mock.patch.object(smoke_test, name, _FakeListener))
        self.stack.enter_context(mock.patch.object(smoke_test, "log"))

    def tearDown(self) -> None:
        self.stack.close()
        self.temp_dir.cleanup()

    def run_all_topologies(self, suite: smoke_test.Suite) -> None:
        binary = self.log_dir / "multiplexd"
        rng = smoke_test.random.Random(1)
        for runner in (smoke_test.run_load_topology,
                       smoke_test.run_parallel_topology,
                       smoke_test.run_identity_verify_topology,
                       smoke_test.run_udp_topology,
                       smoke_test.run_resumption_topology):
            runner(binary, self.log_dir, suite, rng, self.sizes,
                   window=None, loglevel=0)
        smoke_test.run_psk_topology(binary, self.log_dir, suite, rng,
                                    self.sizes, loglevel=0)


class OnlyScopingTests(_Base):
    def test_unselected_topologies_are_not_started(self) -> None:
        # A start-up failure in a topology --only left out must neither run
        # its daemons nor gate the run.
        _FakeDaemons.start_ok = False
        suite = smoke_test.Suite(only={"dump_config"})
        self.run_all_topologies(suite)
        self.assertEqual(_FakeDaemons.started, [])
        self.assertEqual(
            [(r.name, r.status) for r in suite.results], [])

    def test_start_failure_names_the_selected_scenario(self) -> None:
        # The owning topology fails to start: the failure must be reported
        # against the selected scenario, and the name must still be known.
        _FakeDaemons.start_ok = False
        suite = smoke_test.Suite(only={"forward_integrity"})
        self.run_all_topologies(suite)
        self.assertIn("forward_integrity", suite.known)
        failed = [r for r in suite.results if r.status == "FAIL"]
        self.assertEqual(len(failed), 1, [r.name for r in failed])
        self.assertIn("forward_integrity", failed[0].detail)
        self.assertEqual(_FakeDaemons.started, ["load"])

    def test_only_rejects_an_unknown_name_up_front(self) -> None:
        with self.assertRaises(SystemExit):
            smoke_test.parse_only("forward_integrity,no_such_scenario")
        self.assertEqual(smoke_test.parse_only("parallel_tunnels"),
                         {"parallel_tunnels"})
        self.assertIsNone(smoke_test.parse_only(None))


class UdpIsolationTests(_Base):
    def run_udp(self, only: set) -> smoke_test.Suite:
        suite = smoke_test.Suite(only=only)
        smoke_test.run_udp_topology(
            self.log_dir / "multiplexd", self.log_dir, suite,
            smoke_test.random.Random(1), self.sizes, window=None, loglevel=0)
        return suite

    def test_only_starts_the_selected_udp_pair(self) -> None:
        with mock.patch.object(smoke_test, "udp_echo", return_value=True):
            for name, tag in (("udp_forward", "udp"),
                              ("udp_reverse", "udp"),
                              ("udp_identity", "udp-identity")):
                with self.subTest(name=name):
                    _FakeDaemons.started = []
                    suite = self.run_udp({name})
                    self.assertEqual(_FakeDaemons.started, [tag])
                    self.assertEqual([(r.name, r.status) for r in suite.results],
                                     [(name, "PASS")])

    def test_udp_start_failure_names_only_its_selected_scenarios(self) -> None:
        _FakeDaemons.start_ok = False
        suite = self.run_udp({"udp_identity"})
        self.assertEqual(_FakeDaemons.started, ["udp-identity"])
        self.assertEqual(len(suite.results), 1)
        self.assertEqual(suite.results[0].status, "FAIL")
        self.assertIn("udp_identity", suite.results[0].detail)
        self.assertNotIn("udp_forward", suite.results[0].detail)

    def test_failed_identity_pair_does_not_gate_plain_scenario(self) -> None:
        def start(pair: _FakeDaemons) -> bool:
            _FakeDaemons.started.append(pair.tag)
            return pair.tag == "udp"

        with mock.patch.object(_FakeDaemons, "start", start), \
                mock.patch.object(smoke_test, "udp_echo", return_value=True):
            suite = self.run_udp({"udp_forward", "udp_identity"})
        self.assertEqual([(r.name, r.status) for r in suite.results],
                         [("udp-identity_topology_start", "FAIL"),
                          ("udp_forward", "PASS")])
        self.assertNotIn("udp_forward", suite.results[0].detail)

    def test_shutdown_selects_both_udp_pairs(self) -> None:
        suite = self.run_udp({"udp_shutdown"})
        self.assertEqual(_FakeDaemons.started, ["udp", "udp-identity"])
        self.assertEqual([(r.name, r.status) for r in suite.results],
                         [("udp_shutdown", "PASS")])

    def test_stats_alone_generates_its_own_traffic(self) -> None:
        traffic = []

        def echo(port: int, payload: bytes) -> bool:
            traffic.append((port, payload))
            return True

        def stats(_port: int, path: str) -> Tuple[int, str]:
            self.assertEqual(path, "/stats")
            return 200, ("Datagrams : Rx %d (12), Tx %d (12), "
                         "Dropped 0, Flows 1\n" % (len(traffic), len(traffic)))

        with mock.patch.object(smoke_test, "udp_echo", echo), \
                mock.patch.object(smoke_test, "api_request", stats):
            suite = self.run_udp({"udp_stats"})
        self.assertEqual(len(traffic), 1)
        self.assertEqual(_FakeDaemons.started, ["udp"])
        self.assertEqual([(r.name, r.status) for r in suite.results],
                         [("udp_stats", "PASS")])

    def test_stats_requires_new_traffic_not_old_positive_counters(self) -> None:
        before = "Datagrams : Rx 5 (12), Tx 5 (12), Dropped 0, Flows 1"
        for rx, tx in ((5, 5), (6, 5), (5, 6)):
            after = "Datagrams : Rx %d (12), Tx %d (12)" % (rx, tx)
            with self.subTest(rx=rx, tx=tx), \
                    mock.patch.object(smoke_test, "udp_echo", return_value=True), \
                    mock.patch.object(smoke_test, "api_request",
                                      side_effect=[(200, before), (200, after)]):
                ok, detail = smoke_test.scen_udp_stats(1, 2)
            self.assertFalse(ok)
            self.assertIn("did not advance", detail)

    def test_stats_reports_probe_and_api_failures(self) -> None:
        valid = "Datagrams : Rx 0 (0), Tx 0 (0), Dropped 0, Flows 0"
        for status, text, echo_ok, want in (
                (500, valid, True, "HTTP 500"),
                (200, "Sessions : 1", True, "no Datagrams"),
                (200, "Datagrams : Rx bad, Tx 1", True, "unparsable"),
                (200, valid, False, "no echo")):
            with self.subTest(want=want), \
                    mock.patch.object(smoke_test, "api_request",
                                      return_value=(status, text)), \
                    mock.patch.object(smoke_test, "udp_echo",
                                      return_value=echo_ok):
                ok, detail = smoke_test.scen_udp_stats(1, 2)
                self.assertFalse(ok)
                self.assertIn(want, detail)


class CoexistenceTests(unittest.TestCase):
    def run_scenario(self, exchange: Callable[..., Tuple[bool, str]], *,
                     worker_runs: bool = True
                     ) -> Tuple[bool, str]:
        finished = threading.Event()

        def bulk(*args: object, **kwargs: object) -> Tuple[bool, str]:
            try:
                return exchange(*args, **kwargs)
            finally:
                finished.set()

        def sleep(seconds: float) -> None:
            if worker_runs and seconds == 0.5:
                self.assertTrue(finished.wait(timeout=2))

        ping = mock.Mock()
        with mock.patch.object(smoke_test, "bulk_exchange", bulk), \
                mock.patch.object(smoke_test, "connect", return_value=ping), \
                mock.patch.object(smoke_test, "recv_exact", return_value=b"p" * 64), \
                mock.patch.object(smoke_test, "make_payload",
                                  side_effect=lambda _rng, n: b"p" * n), \
                mock.patch.object(smoke_test.time, "sleep", sleep):
            return smoke_test.scen_coexistence(
                1, smoke_test.random.Random(1), bulk_count=1,
                bulk_size=128, pings=1)

    def test_empty_bulk_load_cannot_pass(self) -> None:
        for count, size in ((0, 128), (1, 0)):
            with self.subTest(count=count, size=size):
                ok, detail = smoke_test.scen_coexistence(
                    1, smoke_test.random.Random(1), bulk_count=count,
                    bulk_size=size, pings=1)
                self.assertFalse(ok)
                self.assertIn("nonempty", detail)

    def test_bulk_exception_fails_successful_pings(self) -> None:
        ok, detail = self.run_scenario(mock.Mock(side_effect=ConnectionError(
            "cannot connect")))
        self.assertFalse(ok)
        self.assertIn("bulk 0", detail)
        self.assertIn("cannot connect", detail)

    def test_bulk_verification_failure_fails_successful_pings(self) -> None:
        ok, detail = self.run_scenario(mock.Mock(return_value=(False, "mismatch")))
        self.assertFalse(ok)
        self.assertIn("mismatch", detail)

    def test_no_bulk_completion_cannot_pass(self) -> None:
        # A worker that exits without a result cannot establish bulk load.
        with mock.patch.object(smoke_test.threading, "Thread") as thread:
            thread.return_value.is_alive.return_value = False
            ok, detail = self.run_scenario(
                mock.Mock(return_value=(True, "ok")), worker_runs=False)
        self.assertFalse(ok)
        self.assertIn("verified transfer", detail)

    def test_unfinished_bulk_cannot_pass(self) -> None:
        with mock.patch.object(smoke_test.threading, "Thread") as thread:
            thread.return_value.is_alive.return_value = True
            ok, detail = self.run_scenario(
                mock.Mock(return_value=(True, "ok")), worker_runs=False)
        self.assertFalse(ok)
        self.assertIn("did not finish", detail)

    def test_verified_bulk_and_pings_pass(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        def exchange(*_args: object, **_kwargs: object) -> Tuple[bool, str]:
            entered.set()
            if not release.wait(timeout=2):
                return False, "test did not release transfer"
            return True, "verified"

        def sleep(seconds: float) -> None:
            if seconds == 0.5:
                self.assertTrue(entered.wait(timeout=2))
            else:
                release.set()

        ping = mock.Mock()
        with mock.patch.object(smoke_test, "bulk_exchange", exchange), \
                mock.patch.object(smoke_test, "connect", return_value=ping), \
                mock.patch.object(smoke_test, "recv_exact", return_value=b"p" * 64), \
                mock.patch.object(smoke_test, "make_payload",
                                  side_effect=lambda _rng, n: b"p" * n), \
                mock.patch.object(smoke_test.time, "sleep", sleep):
            ok, detail = smoke_test.scen_coexistence(
                1, smoke_test.random.Random(1), bulk_count=1,
                bulk_size=128, pings=1)
        self.assertTrue(ok, detail)


class ParallelSessionsTests(_Base):
    def test_waits_for_trailing_tunnels(self) -> None:
        # /healthy is 200 with one tunnel up; the others arrive on a later
        # backoff step, after the first /stats read.
        stats_reads = []

        def api_request(_port: int, path: str,
                        **_kwargs: object) -> Tuple[int, str]:
            self.assertEqual(path, "/stats")
            stats_reads.append(path)
            up = 1 if len(stats_reads) < 3 else self.sizes.tunnels
            return 200, "Sessions            : %d / %d (+0)\n" % (up, up)

        passed: Tuple[bool, str] = (True, "ok")
        self.stack.enter_context(
            mock.patch.object(smoke_test, "api_request", api_request))
        self.stack.enter_context(mock.patch.object(
            smoke_test, "scen_concurrent_streams", return_value=passed))
        self.stack.enter_context(mock.patch.object(
            smoke_test, "scen_integrity", return_value=passed))
        self.stack.enter_context(mock.patch.object(smoke_test.time, "sleep"))

        suite = smoke_test.Suite()
        smoke_test.run_parallel_topology(
            self.log_dir / "multiplexd", self.log_dir, suite,
            smoke_test.random.Random(1), self.sizes, window=None, loglevel=0)
        statuses = {r.name: (r.status, r.detail) for r in suite.results}
        self.assertEqual(statuses["parallel_tunnels"][0], "PASS",
                         statuses["parallel_tunnels"][1])

    def test_gives_up_at_the_deadline(self) -> None:
        self.stack.enter_context(mock.patch.object(
            smoke_test, "api_request",
            return_value=(200, "Sessions            : 1 / 1 (+0)\n")))
        ok, sessions_field = smoke_test.wait_sessions(0, 2, timeout=0.3)
        self.assertFalse(ok)
        self.assertEqual(sessions_field, "1 / 1 (+0)")


class GeneratorTests(_Base):
    """The start-up work main() does before any topology."""

    def setUp(self) -> None:
        super().setUp()
        self.generator = _FakeGenerator()
        self.stack.enter_context(
            mock.patch.object(smoke_test.subprocess, "run", self.generator))
        self.stack.enter_context(
            mock.patch.object(smoke_test, "build_has_tls", return_value=True))
        self.stack.enter_context(mock.patch.object(
            smoke_test, "binary_supports_gencerts", return_value=True))
        self.stack.enter_context(mock.patch.object(
            smoke_test, "scen_dump_config", return_value=(True, "ok")))
        self.build_dir = self.log_dir / "build"
        (self.build_dir / "bin").mkdir(parents=True)
        (self.build_dir / "bin" / "multiplexd").touch()

    def run_main(self, *extra: str) -> int:
        return smoke_test.main(["--build-dir", str(self.build_dir), "--quick",
                                "--only", "dump_config", *extra])

    def test_same_second_runs_get_separate_log_dirs(self) -> None:
        # The default log dir is named by the second the run started in; two
        # runs in that second must still not share one, or the second run's
        # --gencerts collides with the first run's certificates.
        self.stack.enter_context(mock.patch.object(
            smoke_test.time, "strftime", return_value="20260101_000000"))
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.run_main(), 0)
        log_dirs = sorted(p.name for p in self.build_dir.glob("smoke_*"))
        self.assertEqual(log_dirs, ["smoke_20260101_000000",
                                    "smoke_20260101_000000_1"])

    def test_gencerts_failure_reports_the_cause(self) -> None:
        # An explicit --log-dir may be reused; the certificates already there
        # make --gencerts fail, and its stdout is where the reason is.
        log_dir = self.log_dir / "reused"
        log_dir.mkdir()
        (log_dir / "server-cert.pem").touch()
        with self.assertRaises(SystemExit) as caught:
            self.run_main("--log-dir", str(log_dir))
        self.assertIn("server-cert.pem: (17) File exists",
                      str(caught.exception))

    def test_genpsk_failure_reports_the_cause(self) -> None:
        (self.log_dir / "smoke~psk.psk").unlink()
        self.generator.error = "failed to open smoke~psk.psk: (28) No space"
        suite = smoke_test.Suite(only={"psk_match"})
        smoke_test.run_psk_topology(
            self.log_dir / "multiplexd", self.log_dir, suite,
            smoke_test.random.Random(1), self.sizes, loglevel=0)
        self.assertEqual([(r.name, r.status) for r in suite.results],
                         [("psk_genkey", "FAIL")])
        self.assertIn("(28) No space", suite.results[0].detail)


if __name__ == "__main__":
    unittest.main()
