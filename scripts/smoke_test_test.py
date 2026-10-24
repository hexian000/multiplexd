#!/usr/bin/env python3
"""Regression tests for smoke scenario isolation, load verification and start-up.

Most scenarios use fakes without a build. Relay regressions use real loopback
TCP sockets to verify transport cancellation and half-close behavior.
"""

from __future__ import annotations

import argparse
import select
import socket
import subprocess
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple
from unittest import mock

import smoke_test


_REAL_DAEMONS = smoke_test.Daemons


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


class GracefulShutdownTests(_Base):
    def run_load(self, only: set) -> smoke_test.Suite:
        suite = smoke_test.Suite(only=only)
        smoke_test.run_load_topology(
            self.log_dir / "multiplexd", self.log_dir, suite,
            smoke_test.random.Random(1), self.sizes, window=None, loglevel=0)
        return suite

    def test_shutdown_follows_three_verified_open_streams(self) -> None:
        for with_fuzz in (False, True):
            with self.subTest(with_fuzz=with_fuzz):
                sockets = [mock.Mock() for _ in range(3)]
                leftovers = ([mock.Mock() for _ in range(3)]
                             if with_fuzz else [])
                prefix = b"active-stream-prefix"
                received = []

                def echo(sock: object, n: int, *, deadline: float) -> bytes:
                    self.assertGreater(deadline, smoke_test.time.monotonic())
                    self.assertEqual(n, len(prefix))
                    sock.sendall.assert_called_once_with(prefix)
                    sock.close.assert_not_called()
                    received.append(sock)
                    return prefix

                def shutdown() -> Tuple[int, int]:
                    if not sockets[0].close.called:
                        self.assertEqual(received, sockets)
                        for sock in sockets + leftovers:
                            sock.close.assert_not_called()
                    return 0, 0

                with ExitStack() as stack:
                    patch = stack.enter_context
                    patch(mock.patch.object(smoke_test, "free_ports",
                                            return_value=list(range(7))))
                    patch(mock.patch.object(smoke_test.socket, "socket",
                                            side_effect=sockets))
                    patch(mock.patch.object(smoke_test, "make_payload",
                                            return_value=prefix))
                    patch(mock.patch.object(smoke_test, "recv_exact",
                                            side_effect=echo))
                    patch(mock.patch.object(
                        smoke_test, "scen_random_fuzz",
                        return_value=(True, "fuzzed", leftovers)))
                    stop = patch(mock.patch.object(
                        _FakeDaemons, "shutdown", side_effect=shutdown))
                    only = {"graceful_shutdown"}
                    if with_fuzz:
                        only.add("random_fuzz")
                    suite = self.run_load(only)
                self.assertTrue(all(r.status == "PASS" for r in suite.results))
                self.assertIn("3 verified active", suite.results[-1].detail)
                self.assertEqual(stop.call_count, 2)
                for sock in sockets + leftovers:
                    sock.close.assert_called_once_with()

    def test_setup_failure_refuses_shutdown_and_closes_sockets(self) -> None:
        for failure in ("connect", "send", "receive", "mismatch"):
            with self.subTest(failure=failure):
                sock = mock.Mock()
                if failure == "connect":
                    sock.connect.side_effect = OSError("connect failed")
                if failure == "send":
                    sock.sendall.side_effect = OSError("send failed")
                with ExitStack() as stack:
                    patch = stack.enter_context
                    patch(mock.patch.object(smoke_test, "free_ports",
                                            return_value=list(range(7))))
                    patch(mock.patch.object(smoke_test.socket, "socket",
                                            return_value=sock))
                    patch(mock.patch.object(smoke_test, "make_payload",
                                            return_value=b"prefix"))
                    patch(mock.patch.object(
                        smoke_test, "recv_exact", return_value=b"wrong",
                        side_effect=(TimeoutError("no echo")
                                     if failure == "receive" else None)))
                    stop = patch(mock.patch.object(
                        _FakeDaemons, "shutdown", return_value=(0, 0)))
                    suite = self.run_load({"graceful_shutdown"})
                self.assertEqual([(r.name, r.status) for r in suite.results],
                                 [("graceful_shutdown", "FAIL")])
                stop.assert_called_once_with()
                sock.close.assert_called_once_with()


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


class TeardownTests(_Base):
    def test_traffic_only_scenarios_gate_on_abnormal_exit(self) -> None:
        for name, tag in (("psk_match", "psk-ok"),
                          ("identity_verify_match", "idverify-ok"),
                          ("forward_integrity", "load"),
                          ("parallel_tunnels", "parallel"),
                          ("udp_forward", "udp"),
                          ("session_resumption", "resume")):
            for codes in ((0, 1), (-9, 0), (None, 0)):
                with self.subTest(name=name, codes=codes), ExitStack() as stack:
                    for scenario in ("scen_integrity", "scen_concurrent_streams",
                                     "scen_resumption"):
                        stack.enter_context(mock.patch.object(
                            smoke_test, scenario, return_value=(True, "traffic ok")))
                    stack.enter_context(mock.patch.object(
                        smoke_test, "wait_sessions", return_value=(True, "2")))
                    stack.enter_context(mock.patch.object(
                        smoke_test, "udp_echo", return_value=True))
                    stack.enter_context(mock.patch.object(
                        _FakeDaemons, "shutdown", return_value=codes))
                    suite = smoke_test.Suite(only={name})
                    self.run_all_topologies(suite)
                    self.assertEqual(suite.results[0].status, "PASS")
                    failed = [r for r in suite.results if r.gating_failure]
                    self.assertEqual([r.name for r in failed], [tag + "_teardown"])
                    self.assertIn("client rc=%s server rc=%s" % codes,
                                  failed[0].detail)

    def test_teardown_observes_real_process_exit_statuses(self) -> None:
        for client_rc, server_rc in ((0, 0), (0, 1), (-9, 0), (None, 0)):
            with self.subTest(client_rc=client_rc, server_rc=server_rc):
                pair = _REAL_DAEMONS(
                    self.log_dir / "multiplexd", self.log_dir, server_cfg={},
                    client_cfg={}, server_api=1, client_api=2, tag="probe")
                pair.client = mock.Mock(pid=123, returncode=client_rc)
                pair.client.poll.return_value = client_rc
                if client_rc is None:
                    pair.client.wait.side_effect = subprocess.TimeoutExpired("probe", 1)
                pair.server = mock.Mock(pid=456, returncode=server_rc)
                pair.server.poll.return_value = server_rc
                suite = smoke_test.Suite(only={"psk_match"})
                suite.teardown(pair)
                self.assertEqual(any(r.gating_failure for r in suite.results),
                                 client_rc != 0 or server_rc != 0)
                self.assertEqual(pair.client is not None, client_rc is None)
                self.assertIsNone(pair.server)

    def test_teardown_exception_gates_the_suite(self) -> None:
        pair = _FakeDaemons(self.log_dir, self.log_dir, tag="probe")
        with mock.patch.object(pair, "shutdown", side_effect=OSError("cannot stop")):
            suite = smoke_test.Suite(only={"psk_match"})
            suite.teardown(pair)
        self.assertTrue(suite.results[0].gating_failure)
        self.assertIn("cannot stop", suite.results[0].detail)

    def test_rejected_authentication_still_passes(self) -> None:
        def spawn(pair: _FakeDaemons) -> None:
            pair.server = mock.Mock()
            pair.server.poll.return_value = None
            pair.client = mock.Mock()
            pair.client.poll.return_value = None

        (self.log_dir / "psk-bad-server.log").write_text("authenticated with the key of")
        (self.log_dir / "idverify-bad-server.log").write_text("does not name it")
        with mock.patch.object(_FakeDaemons, "spawn", spawn), \
                mock.patch.object(smoke_test, "api_request", return_value=(503, "")):
            suite = smoke_test.Suite(only={"psk_mismatch", "identity_verify_mismatch"})
            self.run_all_topologies(suite)
        self.assertEqual([(r.name, r.status) for r in suite.results],
                         [("identity_verify_mismatch", "PASS"),
                          ("psk_mismatch", "PASS")])


class CoexistenceTests(unittest.TestCase):
    def run_scenario(self, exchange: Callable[..., Tuple[bool, str]], *,
                     worker_runs: bool = True) -> Tuple[bool, str]:
        ping = mock.MagicMock()
        with ExitStack() as stack:
            patch = stack.enter_context
            patch(mock.patch.object(smoke_test, "bulk_exchange", exchange))
            patch(mock.patch.object(smoke_test, "connect", return_value=ping))
            patch(mock.patch.object(smoke_test, "recv_exact", return_value=b"p" * 64))
            patch(mock.patch.object(smoke_test, "make_payload",
                                    side_effect=lambda _rng, n: b"p" * n))
            patch(mock.patch.object(smoke_test.time, "sleep"))
            if not worker_runs:
                patch(mock.patch.object(threading.Condition, "wait_for",
                                        return_value=False))
            return smoke_test.scen_coexistence(
                1, smoke_test.random.Random(1), bulk_count=1,
                bulk_size=128, pings=2)

    def test_empty_bulk_load_cannot_pass(self) -> None:
        for count, size in ((0, 128), (1, 0)):
            with self.subTest(count=count, size=size):
                ok, detail = smoke_test.scen_coexistence(
                    1, smoke_test.random.Random(1), bulk_count=count,
                    bulk_size=size, pings=1)
                self.assertFalse(ok)
                self.assertIn("nonempty", detail)

    def test_empty_ping_phase_cannot_pass(self) -> None:
        ok, detail = smoke_test.scen_coexistence(
            1, smoke_test.random.Random(1), bulk_count=1,
            bulk_size=128, pings=0)
        self.assertFalse(ok)
        self.assertIn("no ping", detail)

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
        first_ping = threading.Event()
        progressed = threading.Event()
        transfers = []
        observed = []

        def exchange(*_args: object, **_kwargs: object) -> Tuple[bool, str]:
            if transfers:
                if not first_ping.wait(timeout=2):
                    return False, "test did not send first ping"
                progressed.set()
            transfers.append(True)
            return True, "verified"

        def echo(*_args: object, **_kwargs: object) -> bytes:
            observed.append(len(transfers))
            return b"p" * 64

        def sleep(_seconds: float) -> None:
            first_ping.set()
            self.assertTrue(progressed.wait(timeout=2))

        with mock.patch.object(smoke_test, "bulk_exchange", exchange), \
                mock.patch.object(smoke_test, "connect", return_value=mock.MagicMock()), \
                mock.patch.object(smoke_test, "recv_exact", side_effect=echo), \
                mock.patch.object(smoke_test, "make_payload",
                                  side_effect=lambda _rng, n: b"p" * n), \
                mock.patch.object(smoke_test.time, "sleep", sleep):
            ok, detail = smoke_test.scen_coexistence(
                1, smoke_test.random.Random(1), bulk_count=1,
                bulk_size=128, pings=1)
        self.assertTrue(ok, detail)
        self.assertEqual(len(observed), 2)
        self.assertGreater(observed[-1], observed[0])

    def test_bulk_completing_only_during_join_cannot_pass(self) -> None:
        release = threading.Event()
        entered = threading.Event()
        completed = threading.Event()
        real_thread = threading.Thread
        observed = []
        case = self

        class JoinReleasedThread:
            def __init__(self, **kwargs: object) -> None:
                self.worker = real_thread(**kwargs)

            def start(self) -> None:
                self.worker.start()
                case.assertTrue(entered.wait(timeout=2))

            def join(self, **kwargs: object) -> None:
                release.set()
                self.worker.join(**kwargs)

            def is_alive(self) -> bool:
                return self.worker.is_alive()

        def exchange(*_args: object, **_kwargs: object) -> Tuple[bool, str]:
            entered.set()
            if not release.wait(timeout=2):
                return False, "test did not join worker"
            completed.set()
            return True, "verified after pings"

        def echo(*_args: object, **_kwargs: object) -> bytes:
            observed.append(completed.is_set())
            return b"p" * 64

        with mock.patch.object(smoke_test.threading, "Thread", JoinReleasedThread), \
                mock.patch.object(threading.Condition, "wait_for", return_value=False), \
                mock.patch.object(smoke_test, "bulk_exchange", exchange), \
                mock.patch.object(smoke_test, "connect", return_value=mock.MagicMock()), \
                mock.patch.object(smoke_test, "recv_exact", side_effect=echo), \
                mock.patch.object(smoke_test, "make_payload",
                                  side_effect=lambda _rng, n: b"p" * n), \
                mock.patch.object(smoke_test.time, "sleep"):
            ok, detail = smoke_test.scen_coexistence(
                1, smoke_test.random.Random(1), bulk_count=1,
                bulk_size=128, pings=3)
        self.assertFalse(ok, detail)
        self.assertIn("verified transfer", detail)
        self.assertFalse(any(observed))

    def test_bulk_must_advance_after_first_ping(self) -> None:
        calls = []

        def wait_for(predicate: Callable[[], bool], *, timeout: float) -> bool:
            calls.append(True)
            # Initial verified load is present, but no worker advances during
            # the measurement phase. No real deadline wait is needed.
            return len(calls) == 1

        with mock.patch.object(threading.Condition, "wait_for", side_effect=wait_for), \
                mock.patch.object(smoke_test.threading, "Thread") as thread:
            thread.return_value.is_alive.return_value = False
            ok, detail = self.run_scenario(mock.Mock(return_value=(True, "ok")))
        self.assertFalse(ok, detail)
        self.assertIn("during pings", detail)


class _DeferredThread:
    """Expose a fault fired before a transfer/receiver worker gets scheduled."""

    def __init__(self, *, target: Callable[[], None], **_kwargs: object) -> None:
        self.target = target

    def start(self) -> None:
        pass

    def join(self, **_kwargs: object) -> None:
        self.target()

    def is_alive(self) -> bool:
        return False


class _EchoSocket:
    def __init__(self) -> None:
        self.pending = bytearray()
        self.sent = bytearray()
        self.received = 0
        self.closed = False
        self.corrupt = False
        self.read_error: Optional[OSError] = None

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        assert not self.closed
        self.sent.extend(data)
        self.pending.extend(data)

    def recv(self, n: int) -> bytes:
        if self.read_error is not None:
            raise self.read_error
        n = min(n, len(self.pending), 8191)
        data = bytes(self.pending[:n])
        del self.pending[:n]
        self.received += n
        return bytes(byte ^ 1 for byte in data) if self.corrupt else data

    def close(self) -> None:
        self.closed = True


class ActiveFaultTests(unittest.TestCase):
    def hot_reload(self, sock: _EchoSocket, *, require_prefix: bool = True
                   ) -> Tuple[Tuple[bool, str], mock.Mock]:
        applied = False
        payload = bytes(range(256)) * 1024
        client = mock.Mock()
        client.poll.return_value = None

        def request(_port: int, _path: str, *, method: str = "GET",
                    **_kwargs: object) -> Tuple[int, str]:
            nonlocal applied
            if method == "PUT":
                if require_prefix:
                    self.assertGreater(sock.received, 0,
                                       "reload preceded verified transfer")
                    self.assertLess(len(sock.sent), len(payload))
                    self.assertFalse(sock.closed)
                applied = True
                return 204, ""
            return 200, '{"loglevel": %d}' % (5 if applied else 4)

        with mock.patch.object(smoke_test, "api_request", side_effect=request) as api, \
                mock.patch.object(smoke_test, "connect", return_value=sock), \
                mock.patch.object(smoke_test, "make_payload", return_value=payload), \
                mock.patch.object(smoke_test.threading, "Thread", _DeferredThread), \
                mock.patch.object(smoke_test, "wait_forward_ready", return_value=True), \
                mock.patch.object(smoke_test, "bulk_exchange", return_value=(True, "ok")):
            result = smoke_test.scen_hot_reload(
                client, 1, 2, smoke_test.random.Random(1), {"loglevel": 4})
        return result, api

    def test_hot_reload_waits_for_verified_prefix(self) -> None:
        sock = _EchoSocket()
        (ok, detail), _api = self.hot_reload(sock)
        self.assertTrue(ok, detail)
        self.assertEqual(sock.received, len(sock.sent))
        self.assertEqual(len(sock.sent), 256 * 1024)
        self.assertTrue(sock.closed)

    def test_hot_reload_rejects_unverified_prefix_without_put(self) -> None:
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                sock = _EchoSocket()
                sock.corrupt = corrupt
                if not corrupt:
                    sock.read_error = ConnectionError("stream not established")
                (ok, _detail), api = self.hot_reload(sock, require_prefix=False)
                self.assertFalse(ok)
                self.assertFalse(any(call.kwargs.get("method") == "PUT"
                                     for call in api.call_args_list))
                self.assertTrue(sock.closed)

    def resume(self, sock: _EchoSocket, *, drops: int = 2, size: int = 257,
               active_pair: bool = True
               ) -> Tuple[Tuple[bool, str], mock.Mock]:
        payload = bytes(i % 251 for i in range(size))
        relay = mock.Mock(drops=0)

        def drop() -> int:
            self.assertGreater(sock.received, 0,
                               "drop preceded verified transfer")
            self.assertGreater(len(sock.sent), sock.received,
                               "drop had no pending echo")
            self.assertLess(len(sock.sent), len(payload),
                            "drop came after the whole payload was sent")
            self.assertFalse(sock.closed)
            if active_pair:
                relay.drops += 1
            return int(active_pair)

        relay.drop_all.side_effect = drop
        with mock.patch.object(smoke_test, "connect", return_value=sock), \
                mock.patch.object(smoke_test, "make_payload", return_value=payload), \
                mock.patch.object(smoke_test.threading, "Thread", _DeferredThread), \
                mock.patch.object(smoke_test, "bulk_exchange", return_value=(True, "ok")), \
                mock.patch.object(smoke_test, "stat_reconnects", side_effect=[0, 1]), \
                mock.patch.object(smoke_test.time, "sleep"), \
                mock.patch.object(smoke_test, "log"):
            result = smoke_test.scen_resumption(
                1, 2, relay, smoke_test.random.Random(1), size=size,
                target_seconds=3.0, drops=drops)
        return result, relay

    def test_resumption_faults_overlap_verified_active_stream(self) -> None:
        for drops, size in ((1, 3), (2, 257), (3, 2 * smoke_test._CHUNK + 3)):
            with self.subTest(drops=drops, size=size):
                sock = _EchoSocket()
                (ok, detail), relay = self.resume(sock, drops=drops, size=size)
                self.assertTrue(ok, detail)
                self.assertEqual(relay.drop_all.call_count, drops)
                self.assertEqual(sock.received, size)
                self.assertEqual(len(sock.sent), size)
                self.assertTrue(sock.closed)

    def test_resumption_requires_an_actual_transport_drop(self) -> None:
        sock = _EchoSocket()
        (ok, detail), relay = self.resume(sock, active_pair=False)
        self.assertFalse(ok)
        self.assertIn("no active mux transport", detail)
        self.assertEqual(relay.drop_all.call_count, 1)
        self.assertTrue(sock.closed)

    def test_resumption_rejects_unverified_prefix_before_dropping(self) -> None:
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                sock = _EchoSocket()
                sock.corrupt = corrupt
                if not corrupt:
                    sock.read_error = ConnectionError("echo never became ready")
                (ok, detail), relay = self.resume(sock)
                self.assertFalse(ok)
                self.assertIn("integrity broken", detail)
                relay.drop_all.assert_not_called()
                self.assertTrue(sock.closed)

    def test_resumption_rejects_missing_overlap_budget(self) -> None:
        for drops, size in ((0, 10), (2, 0), (2, 3)):
            with self.subTest(drops=drops, size=size):
                ok, _detail = smoke_test.scen_resumption(
                    1, 2, mock.Mock(), smoke_test.random.Random(1),
                    size=size, target_seconds=1.0, drops=drops)
                self.assertFalse(ok)


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


class RelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.waiting = {}
        self.condition = threading.Condition()
        self.write_wait = threading.Event()
        original_socket = socket.socket
        original_select = select.select
        test = self

        class ObservedSocket(original_socket):
            def recv(self, *args: object, **kwargs: object) -> bytes:
                if threading.current_thread().name == "relay-pump":
                    ready, _, _ = original_select([self], [], [], 0)
                    if not ready:
                        test.mark_wait(self, True)
                data = super().recv(*args, **kwargs)
                if threading.current_thread().name == "relay-pump" and data:
                    test.mark_wait(self, False)
                return data

        def observed_select(readers, writers, errors, timeout=None):
            if (threading.current_thread().name == "relay-pump"
                    and len(readers) == 2 and not writers):
                ready, _, _ = original_select([readers[0]], [], [], 0)
                if not ready:
                    self.mark_wait(readers[0], True)
            if threading.current_thread().name == "relay-pump" and writers:
                _, ready, _ = original_select([], writers, [], 0)
                if not ready:
                    self.write_wait.set()
            return original_select(readers, writers, errors, timeout)

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(socket, "socket",
                                                   ObservedSocket))
        self.stack.enter_context(mock.patch.object(select, "select",
                                                   observed_select))
        self.listener = socket.socket()
        self.stack.callback(self.listener.close)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(2.0)
        self.relay = smoke_test.MuxRelay(0, self.listener.getsockname()[1])
        self.relay.start()
        self.stack.callback(self.relay.stop)
        self.port = self.relay._listen.getsockname()[1]

    def mark_wait(self, sock: socket.socket, waiting: bool) -> None:
        with self.condition:
            self.waiting[sock] = waiting
            self.condition.notify_all()

    def connect_pair(self):
        front = socket.create_connection(("127.0.0.1", self.port), timeout=2.0)
        self.stack.callback(front.close)
        back, _ = self.listener.accept()
        self.stack.callback(back.close)
        back.settimeout(2.0)
        front.sendall(b"forward")
        self.assertEqual(back.recv(7), b"forward")
        back.sendall(b"reverse")
        self.assertEqual(front.recv(7), b"reverse")
        # Every successful recv clears the observation. Both pumps must have
        # returned to an empty read before the control thread injects a fault.
        with self.condition:
            self.assertTrue(self.condition.wait_for(
                lambda: sum(self.waiting.values()) >= 2, timeout=2.0))
        return front, back

    def assert_reset(self, sock: socket.socket) -> None:
        sock.settimeout(0.3)
        with self.assertRaises(ConnectionResetError):
            sock.recv(1)

    def test_drop_completes_with_both_pumps_waiting_and_allows_reconnect(self):
        for expected_drops in (1, 2):
            front, back = self.connect_pair()
            with self.condition:
                pumps = list(self.waiting)
            self.assertEqual(self.relay.drop_all(), 1)
            self.assertEqual(self.relay.drops, expected_drops)
            self.assert_reset(front)
            self.assert_reset(back)
            self.assertTrue(all(sock.fileno() == -1 for sock in pumps))
            self.waiting.clear()
        self.assertEqual(self.relay.drop_all(), 0)
        self.assertEqual(self.relay.drops, 2)

    def test_stop_completes_with_both_pumps_waiting(self):
        front, back = self.connect_pair()
        self.relay.stop()
        self.assertFalse(self.relay._thread.is_alive())
        self.assert_reset(front)
        self.assert_reset(back)
        self.relay.stop()
        self.assertEqual(self.relay.drops, 1)

    def test_drop_cancels_a_pump_waiting_for_a_backpressured_peer(self):
        front, back = self.connect_pair()
        with self.relay._lock:
            pair = self.relay._pairs[0]
        pair.back.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        back.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)

        send_errors = []

        def send() -> None:
            try:
                front.sendall(b"x" * (8 * 1024 * 1024))
            except OSError as exc:
                send_errors.append(exc)

        writer = threading.Thread(target=send, name="relay-test-writer")
        writer.start()

        def finish_writer() -> None:
            front.close()
            writer.join(timeout=3.0)
            self.assertFalse(writer.is_alive())

        self.stack.callback(finish_writer)
        self.assertTrue(self.write_wait.wait(timeout=2.0))
        self.assertEqual(self.relay.drop_all(), 1)
        writer.join(timeout=2.0)
        self.assertFalse(writer.is_alive())
        self.assertTrue(all(not pump.is_alive() for pump in pair.pumps))
        self.assertEqual(len(send_errors), 1)
        self.assertIsInstance(send_errors[0],
                              (ConnectionResetError, BrokenPipeError))

    def test_stop_does_not_publish_a_connection_still_being_created(self):
        entered = threading.Event()
        release = threading.Event()
        create_connection = socket.create_connection

        def delayed_connection(*args, **kwargs):
            sock = create_connection(*args, **kwargs)
            if threading.current_thread().name == "mux-relay":
                entered.set()
                release.wait(timeout=3.0)
            return sock

        with mock.patch.object(socket, "create_connection", delayed_connection):
            front = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=2.0)
            self.stack.callback(front.close)
            back, _ = self.listener.accept()
            self.stack.callback(back.close)
            self.assertTrue(entered.wait(timeout=2.0))
            stopper = threading.Thread(target=self.relay.stop,
                                       name="relay-test-stopper")
            stopper.start()
            try:
                self.assertTrue(self.relay._stop.wait(timeout=2.0))
            finally:
                release.set()
                stopper.join(timeout=3.0)
            self.assertFalse(stopper.is_alive())
        self.assertFalse(self.relay._thread.is_alive())
        self.assertEqual(self.relay._pairs, [])
        self.assertEqual(front.recv(1), b"")

    def test_half_close_preserves_the_other_direction(self):
        front, back = self.connect_pair()
        front.shutdown(socket.SHUT_WR)
        self.assertEqual(back.recv(1), b"")
        back.sendall(b"after EOF")
        self.assertEqual(front.recv(9), b"after EOF")
        back.shutdown(socket.SHUT_WR)
        self.assertEqual(front.recv(1), b"")


if __name__ == "__main__":
    unittest.main()
