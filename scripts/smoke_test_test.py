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
    created: List["_FakeDaemons"] = []

    def __init__(self, binary: Path, log_dir: Path, *, tag: str,
                 **_kwargs: object) -> None:
        self.tag = tag
        self.server_cfg = _kwargs.get("server_cfg")
        self.client_cfg = _kwargs.get("client_cfg")
        self.extra_clients = _kwargs.get("extra_clients", [])
        _FakeDaemons.created.append(self)
        self.server: Optional[object] = None
        self.client: Optional[object] = None
        self.premature_exits: List[str] = []

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
        _FakeDaemons.created = []
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
                       smoke_test.run_multi_peer_topology,
                       smoke_test.run_udp_negotiation_topology,
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


class PluginTopologyTests(_Base):
    def run_plugin(self, name: str) -> smoke_test.Suite:
        suite = smoke_test.Suite(only={name})
        with ExitStack() as stack:
            for helper in ("scen_identity_routes", "scen_udp_multiflow",
                           "scen_udp_tcp_coexistence", "scen_udp_unnegotiated",
                           "scen_integrity"):
                stack.enter_context(mock.patch.object(
                    smoke_test, helper, return_value=(True, "verified")))
            self.run_all_topologies(suite)
        return suite

    def test_udp_topologies_reserve_ports_for_both_protocols(self) -> None:
        for scenario, expected in (
                ("udp_multiflow", (12, (0, 1, 5, 6, 10, 11))),
                ("udp_multi_peer", (11, tuple(range(4, 11)))),
                ("identity_multi_peer", (11, ())),
                ("udp_negotiation", (7, (0, 1, 5, 6)))):
            with self.subTest(scenario=scenario), mock.patch.object(
                    smoke_test, "free_ports", wraps=smoke_test.free_ports) as reserve:
                self.run_plugin(scenario)
                self.assertTrue(reserve.called)
                for call in reserve.call_args_list:
                    self.assertEqual(call.args, (expected[0],))
                    self.assertEqual(tuple(call.kwargs.get("udp", ())), expected[1])

    def test_each_plugin_scenario_starts_only_its_topology(self) -> None:
        for name, tags in (
                ("identity_multi_peer", ["multi-peer"]),
                ("udp_multi_peer", ["multi-peer"]),
                ("udp_negotiation", ["udp-only-server", "udp-only-client"]),
                ("udp_multiflow", ["udp"]),
                ("udp_tcp_coexistence", ["udp"])):
            with self.subTest(name=name):
                _FakeDaemons.started = []
                suite = self.run_plugin(name)
                self.assertEqual(_FakeDaemons.started, tags)
                self.assertEqual([(r.name, r.status) for r in suite.results],
                                 [(name, "PASS")])

    def test_start_failure_reports_only_the_selected_scenario(self) -> None:
        _FakeDaemons.start_ok = False
        for name in ("identity_multi_peer", "udp_multi_peer", "udp_negotiation",
                     "udp_multiflow", "udp_tcp_coexistence"):
            with self.subTest(name=name):
                suite = self.run_plugin(name)
                self.assertEqual(len(suite.results), 1)
                self.assertTrue(suite.results[0].gating_failure)
                self.assertIn(name, suite.results[0].name + suite.results[0].detail)

    def test_multi_peer_configs_keep_distinct_routes(self) -> None:
        for scenario in ("identity_multi_peer", "udp_multi_peer"):
            with self.subTest(scenario=scenario):
                self.run_plugin(scenario)
                pair = _FakeDaemons.created[-1]
                hub = pair.server_cfg
                a = pair.client_cfg
                b, _api = pair.extra_clients[0]
                self.assertEqual(set(hub["identity"]["listen"]),
                                 {"spoke-a", "spoke-b"})
                self.assertEqual(a["identity"]["claim"], "spoke-a")
                self.assertEqual(b["identity"]["claim"], "spoke-b")
                for cfg in (a, b):
                    self.assertEqual(set(cfg["identity"]["listen"]), {"hub"})
                    self.assertEqual(cfg["identity"]["mux_connect"],
                                     [hub["mux_listen"]])
                for cfg in (hub, a, b):
                    self.assertEqual("lossymux" in cfg["mux"],
                                     scenario == "udp_multi_peer")
                    self.assertFalse(cfg["identity"].get("verify", False))

    def test_negotiation_exercises_both_unilateral_offers(self) -> None:
        self.run_plugin("udp_negotiation")
        for pair in _FakeDaemons.created:
            self.assertEqual("lossymux" in pair.server_cfg["mux"],
                             pair.tag == "udp-only-server")
            self.assertEqual("lossymux" in pair.client_cfg["mux"],
                             pair.tag == "udp-only-client")

    def test_new_scenarios_gate_on_abnormal_exit(self) -> None:
        for name in ("identity_multi_peer", "udp_multi_peer", "udp_negotiation",
                     "udp_multiflow", "udp_tcp_coexistence"):
            with self.subTest(name=name), mock.patch.object(
                    _FakeDaemons, "shutdown", return_value=(1, 0)):
                suite = self.run_plugin(name)
                self.assertTrue(any(r.gating_failure for r in suite.results))

    def test_all_clients_spawn_before_health_checks(self) -> None:
        pair = _REAL_DAEMONS(
            self.log_dir, self.log_dir, server_cfg={}, client_cfg={},
            server_api=1, client_api=2, tag="multi",
            extra_clients=[({}, 3)])
        procs = [mock.Mock() for _ in range(3)]
        with mock.patch.object(pair, "_spawn", side_effect=procs) as spawn:
            def healthy(api: int, _label: str, *, proc: object) -> bool:
                self.assertEqual(spawn.call_count, 3)
                self.assertIs(proc, procs[api - 1])
                return api != 3

            with mock.patch.object(smoke_test, "wait_healthy", healthy):
                self.assertFalse(pair.start())
        self.assertEqual([call.args[1] for call in spawn.call_args_list],
                         ["server", "client", "client-2"])

    def test_extra_client_exit_gates_and_retains_unreaped_handle(self) -> None:
        for rc in (0, 1, None):
            with self.subTest(rc=rc):
                pair = _REAL_DAEMONS(
                    self.log_dir, self.log_dir, server_cfg={}, client_cfg={},
                    server_api=1, client_api=2, tag="multi")
                extra = mock.Mock()
                pair._extra_procs = [(extra, 3, "client-2")]
                with mock.patch.object(smoke_test, "terminate_process", return_value=rc):
                    suite = smoke_test.Suite()
                    suite.teardown(pair)
                self.assertEqual(bool(suite.results), rc != 0)
                self.assertEqual(bool(pair._extra_procs), rc is None)


class PluginPayloadTests(unittest.TestCase):
    def test_tcp_routes_reject_the_wrong_backend_or_corrupt_payload(self) -> None:
        for greeting, echoed, error in ((b"wrong---", b"", "reached"),
                                        (b"right---", b"bad", "corrupt")):
            with self.subTest(greeting=greeting):
                sock = mock.MagicMock()
                with mock.patch.object(smoke_test, "connect", return_value=sock), \
                        mock.patch.object(smoke_test, "recv_exact",
                                          side_effect=(greeting, echoed)):
                    with self.assertRaisesRegex(ValueError, error):
                        smoke_test.scen_identity_routes([(1, b"right---")],
                                                       smoke_test.random.Random(1), 16)
                if greeting != b"right---":
                    sock.__enter__.return_value.sendall.assert_not_called()

    def test_udp_multiflow_rejects_cross_socket_replies(self) -> None:
        sockets = [mock.MagicMock(), mock.MagicMock()]
        sockets[0].recv.side_effect = lambda _size: sockets[1].send.call_args.args[0]
        with mock.patch.object(smoke_test.socket, "socket", side_effect=sockets), \
                mock.patch.object(smoke_test.select, "select",
                                  return_value=([sockets[0]], [], [])):
            ok, detail = smoke_test.scen_udp_multiflow(
                [(1, b"")], smoke_test.random.Random(1), 2)
        self.assertFalse(ok)
        self.assertIn("wrong flow", detail)
        for sock in sockets:
            sock.close.assert_called_once()

    def test_udp_multiflow_rejects_wrong_backend_and_missing_replies(self) -> None:
        for wrong_backend in (True, False):
            with self.subTest(wrong_backend=wrong_backend):
                sock = mock.Mock()
                sock.recv.return_value = b"wrong---payload"
                readable = [sock] if wrong_backend else []
                with mock.patch.object(smoke_test.socket, "socket", return_value=sock), \
                        mock.patch.object(smoke_test.select, "select",
                                          return_value=(readable, [], [])), \
                        mock.patch.object(smoke_test.time, "monotonic",
                                          side_effect=range(100)):
                    ok, _detail = smoke_test.scen_udp_multiflow(
                        [(1, b"right---")], smoke_test.random.Random(1), 1)
                self.assertFalse(ok)
                sock.close.assert_called_once()

    def test_udp_multiflow_accepts_only_own_replies_across_all_rounds(self) -> None:
        sockets = [mock.Mock(), mock.Mock()]
        for sock in sockets:
            sock.recv.side_effect = lambda _size, s=sock: b"backend-" + s.send.call_args.args[0]
        rounds = []
        with mock.patch.object(smoke_test.socket, "socket", side_effect=sockets), \
                mock.patch.object(smoke_test.select, "select",
                                  return_value=(sockets, [], [])):
            ok, _detail = smoke_test.scen_udp_multiflow(
                [(1, b"backend-")], smoke_test.random.Random(1), 2,
                after_round=rounds.append)
        self.assertTrue(ok)
        self.assertEqual(rounds, [0, 1, 2])
        self.assertTrue(all(sock.send.call_count == 3 for sock in sockets))

    def test_udp_multiflow_retries_missing_and_ignores_own_duplicates(self) -> None:
        sock = mock.Mock()
        replies = []
        sent = []

        def send(data: bytes) -> None:
            sent.append(data)
            if len(sent) > 1:
                if len(sent) > 2:
                    replies.append(sent[-2])
                replies.append(data)

        sock.send.side_effect = send
        sock.recv.side_effect = lambda _size: replies.pop(0)
        with mock.patch.object(smoke_test.socket, "socket", return_value=sock), \
                mock.patch.object(smoke_test.select, "select",
                                  side_effect=lambda *_args: ([sock] if replies else [], [], [])):
            ok, _detail = smoke_test.scen_udp_multiflow(
                [(1, b"")], smoke_test.random.Random(1), 1)
        self.assertTrue(ok)
        self.assertEqual(len(sent), 4)
        self.assertEqual(sent[0], sent[1])
        self.assertNotEqual(sent[1], sent[2])
        sock.close.assert_called_once()

    def test_unnegotiated_udp_refuses_unavailable_or_malformed_stats(self) -> None:
        for status, text in ((503, "unavailable"), (200, "Datagrams: missing")):
            with self.subTest(status=status), \
                    mock.patch.object(smoke_test, "api_request", return_value=(status, text)):
                with self.assertRaises(ValueError):
                    smoke_test.scen_udp_unnegotiated(1, 2)

    def test_unnegotiated_udp_requires_new_drops_and_no_reply(self) -> None:
        for counters, reply, expected in (((3, 4), False, True),
                                          ((3, 3), False, False),
                                          ((3, 4), True, False)):
            with self.subTest(counters=counters, reply=reply):
                sock = mock.MagicMock()
                sock.__enter__.return_value = sock
                if not reply:
                    sock.recv.side_effect = socket.timeout
                stats = [(200, "Datagrams: Rx 0, Tx 0, Dropped %d, Flows 0" % n)
                         for n in counters]
                with mock.patch.object(smoke_test.socket, "socket", return_value=sock), \
                        mock.patch.object(smoke_test, "api_request", side_effect=stats), \
                        mock.patch.object(smoke_test.time, "monotonic",
                                          side_effect=(0, 0, 2)):
                    ok, _detail = smoke_test.scen_udp_unnegotiated(1, 2)
                self.assertEqual(ok, expected)
                sock.send.assert_called_once()

    def test_coexistence_requires_tcp_progress_between_udp_rounds(self) -> None:
        class EchoSocket:
            def __init__(self) -> None:
                self.pending = b""
                self.sent = []

            def sendall(self, data: bytes) -> None:
                self.pending += data
                self.sent.append(data)

            def recv(self, n: int) -> bytes:
                data, self.pending = self.pending[:n], self.pending[n:]
                return data

            def gettimeout(self) -> float:
                return 5.0

            def settimeout(self, _timeout: Optional[float]) -> None:
                pass

            def close(self) -> None:
                pass

        for progress in (True, False):
            with self.subTest(progress=progress):
                sock = EchoSocket()

                def udp(*_args: object, **kwargs: object) -> Tuple[bool, str]:
                    self.assertEqual(sock.sent, [b"tcp-warmup"])
                    if progress:
                        for round_no in range(3):
                            kwargs["after_round"](round_no)
                        self.assertEqual(len(sock.sent), 2)
                    return True, "UDP ok"

                with mock.patch.object(smoke_test, "connect", return_value=sock), \
                        mock.patch.object(smoke_test, "scen_udp_multiflow", udp):
                    ok, _detail = smoke_test.scen_udp_tcp_coexistence(
                        [1], smoke_test.random.Random(1), 16)
                self.assertEqual(ok, progress)
                self.assertEqual(sock.sent[-1], b"tcp-final")


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
                        smoke_test, "stream_open_counts", side_effect=[
                            {"1": 0, "2": 0}, {"1": 1, "2": 1},
                            {"1": 0, "2": 0}, {"1": 1, "2": 1}]))
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
                pair.client.poll.side_effect = [None, client_rc]
                if client_rc is None:
                    pair.client.poll.side_effect = None
                    pair.client.poll.return_value = None
                    pair.client.wait.side_effect = subprocess.TimeoutExpired("probe", 1)
                pair.server = mock.Mock(pid=456, returncode=server_rc)
                pair.server.poll.side_effect = [None, server_rc]
                suite = smoke_test.Suite(only={"psk_match"})
                suite.teardown(pair)
                self.assertEqual(any(r.gating_failure for r in suite.results),
                                 client_rc != 0 or server_rc != 0)
                self.assertEqual(pair.client is not None, client_rc is None)
                self.assertIsNone(pair.server)

    def test_zero_exit_before_shutdown_fails_for_every_owned_role(self) -> None:
        for role in ("client", "server", "extra"):
            with self.subTest(role=role):
                pair = _REAL_DAEMONS(
                    self.log_dir, self.log_dir, server_cfg={}, client_cfg={},
                    server_api=1, client_api=2, tag="probe")
                proc = mock.Mock(pid=123)
                proc.poll.return_value = 0
                if role == "extra":
                    pair._extra_procs = [(proc, 3, "client-2")]
                else:
                    setattr(pair, role, proc)
                suite = smoke_test.Suite(only={"forward_integrity"})
                suite.teardown(pair)
                self.assertEqual(len(suite.results), 1)
                self.assertTrue(suite.results[0].gating_failure)
                self.assertIn("exited before shutdown", suite.results[0].detail)
                self.assertIn("code 0", suite.results[0].detail)
                proc.send_signal.assert_not_called()
                self.assertIsNone(pair.client)
                self.assertIsNone(pair.server)
                self.assertEqual(pair._extra_procs, [])

    def test_intentionally_stopped_process_is_not_checked_again(self) -> None:
        pair = _REAL_DAEMONS(
            self.log_dir, self.log_dir, server_cfg={}, client_cfg={},
            server_api=1, client_api=2, tag="probe")
        proc = mock.Mock(pid=123)
        proc.poll.side_effect = [None, 0]
        pair.client = proc
        self.assertEqual(pair.shutdown(), (0, 0))
        suite = smoke_test.Suite()
        suite.teardown(pair)
        self.assertEqual(suite.results, [])
        self.assertEqual(proc.poll.call_count, 2)

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


class SocketBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 10.0
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(
            smoke_test.time, "monotonic", side_effect=lambda: self.now))
        self.sleep = self.stack.enter_context(mock.patch.object(
            smoke_test.time, "sleep", side_effect=self.advance))

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def test_recv_caps_each_read_and_restores_timeout(self) -> None:
        for original in (None, 30.0, 0.25):
            with self.subTest(original=original):
                self.now = 10.0
                sock = mock.Mock()
                sock.gettimeout.return_value = original

                def recv(_size: int) -> bytes:
                    self.advance(0.5)
                    return b"x"

                sock.recv.side_effect = recv
                self.assertEqual(smoke_test.recv_exact(sock, 2, deadline=12.0), b"xx")
                cap = 2.0 if original is None else min(2.0, original)
                next_cap = 1.5 if original is None else min(1.5, original)
                self.assertEqual(sock.settimeout.call_args_list,
                                 [mock.call(cap), mock.call(next_cap), mock.call(original)])

    def test_recv_rejects_late_complete_payload_and_closes_budget_on_timeout(self) -> None:
        for timed_out in (False, True):
            with self.subTest(timed_out=timed_out):
                self.now = 10.0
                sock = mock.Mock()
                sock.gettimeout.return_value = 30.0

                def recv(_size: int) -> bytes:
                    self.advance(2.0)
                    if timed_out:
                        raise socket.timeout()
                    return b"complete"

                sock.recv.side_effect = recv
                with self.assertRaises(TimeoutError):
                    smoke_test.recv_exact(sock, 8, deadline=11.0)
                sock.recv.assert_called_once()
                self.assertEqual(sock.settimeout.call_args_list,
                                 [mock.call(1.0), mock.call(30.0)])

    def test_recv_does_not_start_after_deadline_and_restores_after_eof(self) -> None:
        sock = mock.Mock()
        sock.gettimeout.return_value = None
        with self.assertRaises(TimeoutError):
            smoke_test.recv_exact(sock, 1, deadline=10.0)
        sock.recv.assert_not_called()
        sock.recv.return_value = b""
        with self.assertRaises(ConnectionError):
            smoke_test.recv_exact(sock, 1, deadline=11.0)
        sock.settimeout.assert_called_with(None)

    def test_connect_caps_operation_and_retry_delay(self) -> None:
        sock = mock.Mock()

        def refuse(_address: object) -> None:
            self.advance(0.95)
            raise ConnectionRefusedError()

        sock.connect.side_effect = refuse
        with mock.patch.object(smoke_test.socket, "socket", return_value=sock) as factory:
            with self.assertRaises(TimeoutError):
                smoke_test.connect(1, deadline=11.0)
        sock.settimeout.assert_called_once_with(1.0)
        sock.close.assert_called_once()
        self.assertEqual(factory.call_count, 1)
        self.assertAlmostEqual(self.sleep.call_args.args[0], 0.05)
        self.assertEqual(self.now, 11.0)

    def test_connect_rejects_a_late_success(self) -> None:
        sock = mock.Mock()
        sock.connect.side_effect = lambda _address: self.advance(2.0)
        with mock.patch.object(smoke_test.socket, "socket", return_value=sock):
            with self.assertRaises(TimeoutError):
                smoke_test.connect(1, deadline=11.0)
        sock.close.assert_called_once()
        self.sleep.assert_not_called()

    def test_recovery_passes_budget_through_send_and_receive(self) -> None:
        sock = mock.Mock()
        sock.gettimeout.return_value = 4.0
        payload = b"p" * 64

        def connected(_port: int, *, timeout: float, deadline: float) -> object:
            self.assertEqual(deadline, 15.0)
            self.advance(1.0)
            return sock

        sock.sendall.side_effect = lambda _data: self.advance(1.0)
        sock.recv.side_effect = lambda _size: payload
        with mock.patch.object(smoke_test, "connect", side_effect=connected), \
                mock.patch.object(smoke_test, "make_payload", return_value=payload):
            self.assertTrue(smoke_test.wait_forward_ready(1, mock.Mock(), timeout=5.0))
        self.assertEqual(sock.settimeout.call_args_list,
                         [mock.call(4.0), mock.call(3.0), mock.call(4.0)])
        sock.close.assert_called_once()

    def test_recovery_closes_failed_probe_and_caps_retry_sleep(self) -> None:
        sock = mock.Mock()

        def send(_data: bytes) -> None:
            self.advance(0.9)
            raise socket.timeout()

        sock.sendall.side_effect = send
        with mock.patch.object(smoke_test, "connect", return_value=sock):
            self.assertFalse(smoke_test.wait_forward_ready(1, mock.Mock(), timeout=1.0))
        sock.close.assert_called_once()
        self.assertAlmostEqual(self.sleep.call_args.args[0], 0.1)
        self.assertEqual(self.now, 11.0)


class BulkExchangeTests(unittest.TestCase):
    def test_verifies_echo_and_preserves_send_pacing(self) -> None:
        for payload, received, expected in (
            (b"", b"", (True, "0 bytes verified")),
            (b"echo", b"echo", (True, "4 bytes verified")),
            (b"echo", b"ech", (False, "length mismatch: got 3 want 4")),
            (b"echo", b"xxxx", (False, "payload mismatch (4 bytes)")),
        ):
            with self.subTest(payload=payload, received=received):
                sock = mock.Mock()
                with mock.patch.object(smoke_test, "connect", return_value=sock), \
                        mock.patch.object(smoke_test, "recv_exact", return_value=received) as recv, \
                        mock.patch.object(smoke_test.time, "monotonic", return_value=10.0), \
                        mock.patch.object(smoke_test.time, "sleep") as pace, \
                        mock.patch.object(smoke_test, "_CHUNK", 2):
                    self.assertEqual(smoke_test.bulk_exchange(
                        1234, payload, timeout=3.0, pace_seconds=0.1), expected)
                recv.assert_called_once_with(sock, len(payload), deadline=13.0)
                self.assertEqual(sock.sendall.call_args_list,
                                 [mock.call(payload[i:i + 2])
                                  for i in range(0, len(payload), 2)])
                self.assertEqual(pace.call_count, (len(payload) + 1) // 2)
                sock.settimeout.assert_called_once_with(3.0)
                sock.close.assert_called_once()

    def test_collects_sender_and_receiver_errors_before_comparing(self) -> None:
        sock = mock.Mock()
        sock.sendall.side_effect = OSError("send failed")
        with mock.patch.object(smoke_test, "connect", return_value=sock), \
                mock.patch.object(smoke_test, "recv_exact", side_effect=TimeoutError("late")):
            ok, detail = smoke_test.bulk_exchange(1234, b"echo", timeout=3.0)
        self.assertFalse(ok)
        self.assertIn("receiver: TimeoutError('late')", detail)
        self.assertIn("sender: OSError('send failed')", detail)
        sock.close.assert_called_once()

    def test_unfinished_receiver_reports_timeout_after_closing_socket(self) -> None:
        sock = mock.Mock()
        rx = mock.Mock()
        rx.is_alive.return_value = True
        with mock.patch.object(smoke_test, "connect", return_value=sock), \
                mock.patch.object(smoke_test.threading, "Thread", return_value=rx):
            self.assertEqual(smoke_test.bulk_exchange(1234, b"echo", timeout=3.0),
                             (False, "transfer did not complete within 3.0 s"))
        rx.start.assert_called_once()
        rx.join.assert_called_once_with(timeout=3.0)
        sock.close.assert_called_once()


class PortReservationTests(unittest.TestCase):
    def test_udp_only_occupation_rejects_a_tcp_candidate(self) -> None:
        real_socket = socket.socket
        with real_socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            port = occupied.getsockname()[1]
            candidates = []

            class CandidateSocket(real_socket):
                def bind(self, address: Tuple[str, int]) -> None:
                    if self.type == socket.SOCK_STREAM:
                        candidates.append(self)
                        if len(candidates) == 1:
                            address = (address[0], port)
                    super().bind(address)

            with mock.patch.object(smoke_test.socket, "socket", CandidateSocket):
                ports = smoke_test.free_ports(2, udp=(0, 1))
            self.assertNotIn(port, ports)
            self.assertEqual(len(set(ports)), 2)
            self.assertEqual(len(candidates), 3)
            self.assertTrue(all(sock.fileno() == -1 for sock in candidates))
            for selected in ports:
                with real_socket() as tcp, real_socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    tcp.bind(("127.0.0.1", selected))
                    udp.bind(("127.0.0.1", selected))

    def test_reservations_are_closed_when_a_later_bind_fails(self) -> None:
        sockets = [mock.Mock(), mock.Mock(), mock.Mock()]
        sockets[0].getsockname.return_value = ("127.0.0.1", 1234)
        sockets[2].bind.side_effect = PermissionError(13, "denied")
        with mock.patch.object(smoke_test.socket, "socket", side_effect=sockets):
            with self.assertRaises(PermissionError):
                smoke_test.free_ports(2, udp=(0,))
        for sock in sockets:
            sock.close.assert_called_once()


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

    def gettimeout(self) -> float:
        return 30.0

    def settimeout(self, _timeout: Optional[float]) -> None:
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


class ReadinessBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 10.0
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(
            smoke_test.time, "monotonic", side_effect=lambda: self.now))
        self.sleep = self.stack.enter_context(mock.patch.object(
            smoke_test.time, "sleep", side_effect=self.advance))
        self.stack.enter_context(mock.patch.object(smoke_test, "log"))
        self.stats = (200, "Sessions: 2 / 2\n")
        self.api = self.stack.enter_context(mock.patch.object(
            smoke_test, "api_request", return_value=self.stats))
        self.response = mock.MagicMock()
        self.response.__enter__.return_value.status = 200
        self.opener = self.stack.enter_context(mock.patch.object(
            smoke_test._OPENER, "open", return_value=self.response))
        self.proc = mock.Mock()
        self.proc.poll.return_value = None

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def wait(self, kind: str, timeout: float) -> bool:
        if kind == "sessions":
            return smoke_test.wait_sessions(1, 2, timeout=timeout)[0]
        return smoke_test.wait_healthy(1, "test", proc=self.proc, timeout=timeout)

    def probe(self, kind: str) -> mock.Mock:
        return self.api if kind == "sessions" else self.opener

    def result(self, kind: str) -> object:
        return self.stats if kind == "sessions" else self.response

    def test_no_probe_after_expired_budget(self) -> None:
        for kind in ("sessions", "healthy"):
            for timeout in (0.0, -1.0):
                with self.subTest(kind=kind, timeout=timeout):
                    self.assertFalse(self.wait(kind, timeout))
                    self.probe(kind).assert_not_called()
                    self.sleep.assert_not_called()

    def test_success_at_or_after_deadline_is_rejected(self) -> None:
        for kind in ("sessions", "healthy"):
            for elapsed in (1.0, 1.5):
                with self.subTest(kind=kind, elapsed=elapsed):
                    self.now = 10.0
                    probe = self.probe(kind)
                    probe.reset_mock()

                    def late(*_args: object, **_kwargs: object) -> object:
                        self.advance(elapsed)
                        return self.result(kind)

                    probe.side_effect = late
                    self.assertFalse(self.wait(kind, 1.0))
                    self.assertEqual(probe.call_count, 1)
                    self.assertEqual(probe.call_args.kwargs["timeout"], 1.0)
                    self.sleep.assert_not_called()

    def test_probe_and_retry_sleep_fit_remaining_budget(self) -> None:
        for kind in ("sessions", "healthy"):
            with self.subTest(kind=kind):
                self.now = 10.0
                self.sleep.reset_mock()
                probe = self.probe(kind)
                probe.reset_mock()

                def unavailable(*_args: object, **_kwargs: object) -> object:
                    self.advance(0.03)
                    raise OSError("not ready")

                probe.side_effect = unavailable
                self.assertFalse(self.wait(kind, 0.05))
                self.assertEqual(probe.call_count, 1)
                self.assertAlmostEqual(probe.call_args.kwargs["timeout"], 0.05)
                self.sleep.assert_called_once()
                self.assertAlmostEqual(self.sleep.call_args.args[0], 0.02)
                self.assertAlmostEqual(self.now, 10.05)

    def test_retry_can_succeed_before_deadline(self) -> None:
        for kind, pause in (("sessions", 0.1), ("healthy", 0.2)):
            with self.subTest(kind=kind):
                self.now = 10.0
                self.sleep.reset_mock()
                probe = self.probe(kind)
                probe.reset_mock()

                def retry(*_args: object, **_kwargs: object) -> object:
                    self.advance(0.05)
                    if probe.call_count == 1:
                        raise OSError("not ready")
                    return self.result(kind)

                probe.side_effect = retry
                self.assertTrue(self.wait(kind, 0.5))
                self.assertEqual(probe.call_count, 2)
                self.assertAlmostEqual(probe.call_args_list[0].kwargs["timeout"], 0.5)
                self.assertAlmostEqual(probe.call_args_list[1].kwargs["timeout"],
                                       0.45 - pause)
                self.sleep.assert_called_once_with(pause)
                self.assertLess(self.now, 10.5)

    def test_probe_timeout_retains_normal_cap(self) -> None:
        for kind, cap in (("sessions", 5.0), ("healthy", 1.0)):
            with self.subTest(kind=kind):
                self.assertTrue(self.wait(kind, 10.0))
                self.assertEqual(self.probe(kind).call_args.kwargs["timeout"], cap)

    def test_process_exit_prevents_health_probe(self) -> None:
        self.proc.poll.return_value = 7
        self.proc.returncode = 7
        self.assertFalse(self.wait("healthy", 1.0))
        self.opener.assert_not_called()
        self.sleep.assert_not_called()


class ParallelSessionsTests(_Base):
    @staticmethod
    def metrics(identity: str, counts: dict) -> str:
        return "".join(
            'multiplexd_session_stream_open_total{identity="%s",tunnel="%s"} %d\n'
            % (identity, tunnel, count) for tunnel, count in counts.items())

    def run_parallel(self, snapshots: list) -> smoke_test.ScenarioResult:
        def api_request(_port: int, path: str,
                        **_kwargs: object) -> Tuple[int, str]:
            self.assertEqual(path, "/metrics")
            return 200, snapshots.pop(0)

        self.stack.enter_context(mock.patch.object(
            smoke_test, "wait_sessions", return_value=(True, "2 / 2")))
        self.stack.enter_context(mock.patch.object(
            smoke_test, "api_request", side_effect=api_request))
        self.traffic = self.stack.enter_context(mock.patch.object(
            smoke_test, "scen_concurrent_streams", return_value=(True, "traffic ok")))
        self.integrity = self.stack.enter_context(mock.patch.object(
            smoke_test, "scen_integrity", return_value=(True, "reverse ok")))
        suite = smoke_test.Suite(only={"parallel_tunnels"})
        smoke_test.run_parallel_topology(
            self.log_dir / "multiplexd", self.log_dir, suite,
            smoke_test.random.Random(1), self.sizes, window=None, loglevel=0)
        return suite.results[0]

    def test_requires_each_tunnel_to_carry_new_streams_in_both_directions(self) -> None:
        for forward, reverse, expected in (
                ({"1": 4, "2": 3}, {"7": 5, "8": 6}, "PASS"),
                ({"1": 8, "2": 2}, {"7": 5, "8": 6}, "FAIL"),
                ({"1": 4, "2": 3}, {"7": 9, "8": 4}, "FAIL")):
            with self.subTest(forward=forward, reverse=reverse):
                result = self.run_parallel([
                    self.metrics("server", {"1": 2, "2": 2}),
                    self.metrics("server", forward),
                    self.metrics("client", {"7": 4, "8": 4}),
                    self.metrics("client", reverse)])
                self.assertEqual(result.status, expected, result.detail)
                if expected == "FAIL":
                    self.assertIn("did not use every tunnel", result.detail)
                else:
                    self.assertEqual(self.traffic.call_count, 2)
                    self.integrity.assert_called_once()

    def test_rejects_missing_replaced_and_reset_tunnel_counters(self) -> None:
        for before, after, message in (
                ({"1": 0}, {"1": 2}, "expected 2 tunnel counters"),
                ({"1": 0, "2": 0}, {"1": 2, "3": 2}, "tunnel set changed"),
                ({"1": 5, "2": 5}, {"1": 1, "2": 6}, "did not use every tunnel")):
            with self.subTest(before=before, after=after):
                result = self.run_parallel([
                    self.metrics("server", before), self.metrics("server", after)])
                self.assertEqual(result.status, "FAIL")
                self.assertIn(message, result.detail)

    def test_stream_counter_parser_filters_peer_and_rejects_bad_responses(self) -> None:
        valid = self.metrics("server", {"1": 23, "2": 29})
        other = self.metrics("client", {"1": 99})
        with mock.patch.object(smoke_test, "api_request", return_value=(200, valid + other)):
            self.assertEqual(smoke_test.stream_open_counts(1, "server"),
                             {"1": 23, "2": 29})
        for response in ((503, valid), (200, valid + valid)):
            with self.subTest(response=response), mock.patch.object(
                    smoke_test, "api_request", return_value=response):
                with self.assertRaises(ValueError):
                    smoke_test.stream_open_counts(1, "server")

    def test_waits_for_trailing_tunnels(self) -> None:
        # /healthy is 200 with one tunnel up; the others arrive on a later
        # backoff step, after the first /stats read.
        stats_reads = []
        metric_reads = []

        def api_request(_port: int, path: str,
                        **_kwargs: object) -> Tuple[int, str]:
            if path == "/metrics":
                metric_reads.append(path)
                identity = "server" if len(metric_reads) <= 2 else "client"
                count = len(metric_reads) % 2 == 0
                return 200, self.metrics(identity, {"1": int(count), "2": int(count)})
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
        now = 10.0

        def advance(seconds: float) -> None:
            nonlocal now
            now += seconds

        self.stack.enter_context(mock.patch.object(
            smoke_test.time, "monotonic", side_effect=lambda: now))
        self.stack.enter_context(mock.patch.object(
            smoke_test.time, "sleep", side_effect=advance))
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
    recv_limit: Optional[int] = None

    def setUp(self) -> None:
        self.waiting = {}
        self.condition = threading.Condition()
        self.write_wait = threading.Event()
        original_socket = socket.socket
        original_select = select.select
        test = self

        class ObservedSocket(original_socket):
            def recv(self, size: int, flags: int = 0) -> bytes:
                if (threading.current_thread().name != "relay-pump"
                        and test.recv_limit is not None):
                    size = min(size, test.recv_limit)
                if threading.current_thread().name == "relay-pump":
                    ready, _, _ = original_select([self], [], [], 0)
                    if not ready:
                        test.mark_wait(self, True)
                data = super().recv(size, flags)
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
        self.assertEqual(smoke_test.recv_exact(
            back, 7, deadline=smoke_test.time.monotonic() + 2.0), b"forward")
        back.sendall(b"reverse")
        self.assertEqual(smoke_test.recv_exact(
            front, 7, deadline=smoke_test.time.monotonic() + 2.0), b"reverse")
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
        self.assertEqual(
            smoke_test.recv_exact(
                front, 9, deadline=smoke_test.time.monotonic() + 2.0),
            b"after EOF")
        back.shutdown(socket.SHUT_WR)
        self.assertEqual(front.recv(1), b"")


class FragmentedRelayTests(RelayTests):
    """Run the relay regressions with legal one-byte application reads."""

    recv_limit = 1


if __name__ == "__main__":
    unittest.main()
