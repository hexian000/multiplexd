#!/usr/bin/env python3

"""End-to-end smoke test for multiplexd.

Generates TLS certificates, starts server and client instances with full trace
logging (loglevel 8), runs a configurable duration of randomised TCP behavior
(connect, send, recv, graceful-close, abrupt-close) against the live pair, then
sends SIGTERM **while connections are still open** and verifies that both
processes shut down cleanly (exit code 0).

Usage::

    python3 scripts/smoke_test.py [options]

    --build-dir DIR   CMake build directory (default: build)
    --log-dir   DIR   Log and work directory (default: build/smoke_<timestamp>)
    --seed      INT   Random seed for reproducibility
    --duration  FLOAT Duration of the random test phase in seconds (default: 10)
"""

from __future__ import annotations

import argparse
import json
import random
import shlex
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD_DIR = ROOT / "build"

# SO_LINGER value that triggers an RST on close instead of a graceful FIN.
_LINGER_RST = struct.pack("ii", 1, 0)

_ACTIONS = ["connect", "send_small", "send_large",
            "recv", "close_graceful", "close_abrupt"]
_WEIGHTS = [4,          3,            2,            5,     2,               1]


# ---------------------------------------------------------------------------
# Utilities (style consistent with scripts/bench.py)
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    print(message, file=sys.stderr)


def quote_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def ensure_project_root(root: Path) -> None:
    if not (root / "CMakeLists.txt").exists():
        raise SystemExit(
            "working directory does not look like the project root: %s" % root
        )


def resolve_path(base: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def parse_cmake_cache(cache_path: Path) -> Dict[str, str]:
    cache: Dict[str, str] = {}
    if not cache_path.exists():
        return cache
    with cache_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            key_type, sep, value = line.partition("=")
            if not sep:
                continue
            key, _, _type = key_type.partition(":")
            if key:
                cache[key] = value
    return cache


def write_config(path: Path, payload: Dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


def free_ports(count: int) -> List[int]:
    """Return *count* distinct available localhost TCP port numbers.

    All sockets are held open simultaneously so the OS cannot reassign a port
    before we have collected the full set.
    """
    socks: List[socket.socket] = []
    ports: List[int] = []
    try:
        for _ in range(count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
            ports.append(s.getsockname()[1])
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
    return ports


# ---------------------------------------------------------------------------
# In-process TCP echo server
# ---------------------------------------------------------------------------

class EchoServer:
    """Thread-backed TCP echo server used as the forwarding target.

    Accepts connections on a fixed port and echoes every received byte back to
    the sender.  Fully self-contained; no external tools required.
    """

    def __init__(self, port: int) -> None:
        self._port = port
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self._port))
        self._sock.listen(128)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="echo-server"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(
                target=EchoServer._handle, args=(conn,), daemon=True
            ).start()

    @staticmethod
    def _handle(conn: socket.socket) -> None:
        conn.settimeout(2.0)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                conn.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Process lifecycle helpers
# ---------------------------------------------------------------------------

def terminate_process(
    proc: "subprocess.Popen[bytes]",
    name: str,
    *,
    sigterm_timeout: float = 8.0,
    sigkill_timeout: float = 3.0,
) -> int:
    """Send SIGTERM and wait.  Escalate to SIGKILL on timeout.

    Returns the exit code, or ``-SIGKILL`` if a kill was necessary.
    """
    rc = proc.poll()
    if rc is not None:
        log("  %s already exited (code %d)" % (name, rc))
        return rc
    log("stopping %s [pid:%d]" % (name, proc.pid))
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=sigterm_timeout)
    except subprocess.TimeoutExpired:
        log("  %s did not exit within %.1f s — sending SIGKILL" %
            (name, sigterm_timeout))
        proc.kill()
        try:
            proc.wait(timeout=sigkill_timeout)
        except subprocess.TimeoutExpired:
            pass
    rc = proc.poll()
    if rc is None:
        rc = -int(signal.SIGKILL)
    log("  %s exited with code %d" % (name, rc))
    return rc


def wait_healthy(
    api_port: int,
    label: str,
    *,
    proc: "subprocess.Popen[bytes]",
    timeout: float = 15.0,
) -> bool:
    """Poll /healthy until 200 OK, process death, or timeout."""
    url = "http://127.0.0.1:%d/healthy" % api_port
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log("[FAIL] %s exited prematurely (code %s)" %
                (label, proc.returncode))
            return False
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    log("  %s healthy (api_port=%d)" % (label, api_port))
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    log("[FAIL] %s did not become healthy within %.1f s" % (label, timeout))
    return False


# ---------------------------------------------------------------------------
# Config builders
# ---------------------------------------------------------------------------

def build_server_config(
    *,
    mux_port: int,
    echo_port: int,
    api_port: int,
) -> Dict[str, object]:
    return {
        "mux_listen": "127.0.0.1:%d" % mux_port,
        "connect": "127.0.0.1:%d" % echo_port,
        "api_listen": "127.0.0.1:%d" % api_port,
        "tls": {
            "cert": "@server-cert.pem",
            "key": "@server-key.pem",
            "authcerts": ["@client-cert.pem"],
        },
        "mux": {
            "ping_timeout": 15,
            "keepalive": 30,
            "max_streams": 200,
        },
        "loglevel": 8,
    }


def build_client_config(
    *,
    mux_port: int,
    listen_port: int,
    api_port: int,
) -> Dict[str, object]:
    return {
        "mux_connect": "127.0.0.1:%d" % mux_port,
        "listen": "127.0.0.1:%d" % listen_port,
        "api_listen": "127.0.0.1:%d" % api_port,
        "tls": {
            "cert": "@client-cert.pem",
            "key": "@client-key.pem",
            "authcerts": ["@server-cert.pem"],
        },
        "mux": {
            "ping_timeout": 15,
            "keepalive": 30,
        },
        "loglevel": 8,
    }


# ---------------------------------------------------------------------------
# Random behavior test
# ---------------------------------------------------------------------------

def _close_conn(conns: List[socket.socket], s: socket.socket, *, rst: bool) -> None:
    conns.remove(s)
    try:
        if rst:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_RST)
        s.close()
    except OSError:
        pass


def run_random_test(
    *,
    listen_port: int,
    duration: float,
    rng: random.Random,
    log_path: Path,
    seed: Optional[int],
) -> Tuple[int, int, int, List[socket.socket]]:
    """Run random TCP activity for *duration* seconds against *listen_port*.

    Returns *(n_connects, n_sent_bytes, n_recv_bytes, open_conns)* where
    *open_conns* holds the sockets that were not closed during the test,
    intentionally preserved for the subsequent graceful-shutdown phase.
    """
    conns: List[socket.socket] = []
    n_connects = 0
    n_sent = 0
    n_recv = 0
    start = time.monotonic()

    with log_path.open("w", encoding="utf-8") as logf:

        def tlog(msg: str) -> None:
            elapsed = time.monotonic() - start
            line = "[%7.3f] %s" % (elapsed, msg)
            logf.write(line + "\n")
            logf.flush()
            log(line)

        tlog(
            "random test started: listen_port=%d duration=%.1f seed=%s"
            % (listen_port, duration, seed)
        )

        deadline = start + duration
        while time.monotonic() < deadline:
            # Force a connect when there are no open connections.
            action = "connect" if not conns else rng.choices(
                _ACTIONS, weights=_WEIGHTS, k=1)[0]

            if action == "connect":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.settimeout(2.0)
                    s.connect(("127.0.0.1", listen_port))
                    s.setblocking(False)
                    conns.append(s)
                    n_connects += 1
                    tlog("CONNECT     fd=%-5d total=%d" %
                         (s.fileno(), len(conns)))
                except OSError as exc:
                    tlog("CONNECT     failed: %s" % exc)
                    try:
                        s.close()
                    except OSError:
                        pass

            elif action == "send_small":
                s = rng.choice(conns)
                data = rng.randbytes(rng.randint(1, 256))
                try:
                    n = s.send(data)
                    n_sent += n
                    tlog("SEND_SMALL  fd=%-5d bytes=%d" % (s.fileno(), n))
                except BlockingIOError:
                    pass
                except OSError as exc:
                    tlog("SEND_SMALL  fd=%-5d error: %s" % (s.fileno(), exc))
                    _close_conn(conns, s, rst=False)

            elif action == "send_large":
                s = rng.choice(conns)
                data = rng.randbytes(rng.randint(1024, 8192))
                try:
                    n = s.send(data)
                    n_sent += n
                    tlog("SEND_LARGE  fd=%-5d bytes=%d" % (s.fileno(), n))
                except BlockingIOError:
                    pass
                except OSError as exc:
                    tlog("SEND_LARGE  fd=%-5d error: %s" % (s.fileno(), exc))
                    _close_conn(conns, s, rst=False)

            elif action == "recv":
                s = rng.choice(conns)
                try:
                    chunk = s.recv(4096)
                    if chunk:
                        n_recv += len(chunk)
                        tlog("RECV        fd=%-5d bytes=%d" %
                             (s.fileno(), len(chunk)))
                    else:
                        tlog("RECV        fd=%-5d EOF" % s.fileno())
                        _close_conn(conns, s, rst=False)
                except BlockingIOError:
                    pass
                except OSError as exc:
                    tlog("RECV        fd=%-5d error: %s" % (s.fileno(), exc))
                    _close_conn(conns, s, rst=False)

            elif action == "close_graceful":
                s = rng.choice(conns)
                tlog("CLOSE_FIN   fd=%d" % s.fileno())
                _close_conn(conns, s, rst=False)

            elif action == "close_abrupt":
                s = rng.choice(conns)
                tlog("CLOSE_RST   fd=%d" % s.fileno())
                _close_conn(conns, s, rst=True)

            time.sleep(rng.uniform(0.003, 0.015))

        tlog(
            "test loop ended: n_connects=%d sent=%d recv=%d open=%d"
            % (n_connects, n_sent, n_recv, len(conns))
        )

    return n_connects, n_sent, n_recv, conns


# ---------------------------------------------------------------------------
# Main test orchestration
# ---------------------------------------------------------------------------

def smoke_test(
    *,
    binary: Path,
    log_dir: Path,
    rng: random.Random,
    duration: float,
    seed: Optional[int],
) -> bool:
    """Orchestrate the full smoke test.  Returns True on pass."""
    # Port allocation: keep all sockets open at once to guarantee uniqueness.
    echo_port, mux_port, server_api_port, client_listen_port, client_api_port = (
        free_ports(5)
    )
    log(
        "ports: echo=%d  mux=%d  server_api=%d  client_listen=%d  client_api=%d"
        % (echo_port, mux_port, server_api_port, client_listen_port, client_api_port)
    )

    echo = EchoServer(echo_port)
    echo.start()
    log("echo server started on port %d" % echo_port)

    server_proc: Optional["subprocess.Popen[bytes]"] = None
    client_proc: Optional["subprocess.Popen[bytes]"] = None
    server_log_fh = None
    client_log_fh = None
    open_conns: List[socket.socket] = []
    passed = False

    try:
        # --- 1/6  Generate certificates ------------------------------------
        log("")
        log("[1/6] generating certificates")
        cmd = [
            str(binary),
            "--gencerts", "server,client",
            "--sni", "smoke.test.local",
            "--keytype", "ed25519",
        ]
        log("+ %s" % quote_command(cmd))
        result = subprocess.run(
            cmd,
            cwd=str(log_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30.0,
        )
        if result.returncode != 0:
            raise SystemExit(
                "gencerts failed (code %d):\n%s"
                % (result.returncode, result.stderr.decode(errors="replace"))
            )

        # --- 2/6  Write configs --------------------------------------------
        log("[2/6] writing configs")
        server_cfg = log_dir / "server.json"
        client_cfg = log_dir / "client.json"
        write_config(
            server_cfg,
            build_server_config(
                mux_port=mux_port, echo_port=echo_port, api_port=server_api_port
            ),
        )
        write_config(
            client_cfg,
            build_client_config(
                mux_port=mux_port,
                listen_port=client_listen_port,
                api_port=client_api_port,
            ),
        )

        # --- 3/6  Start server ---------------------------------------------
        log("[3/6] starting server")
        server_log_fh = (log_dir / "server.log").open("wb")
        cmd = [str(binary), "-c", str(server_cfg)]
        log("+ %s" % quote_command(cmd))
        server_proc = subprocess.Popen(
            cmd,
            cwd=str(log_dir),
            stdout=server_log_fh,
            stderr=subprocess.STDOUT,
        )

        # --- 4/6  Start client ---------------------------------------------
        log("[4/6] starting client")
        client_log_fh = (log_dir / "client.log").open("wb")
        cmd = [str(binary), "-c", str(client_cfg)]
        log("+ %s" % quote_command(cmd))
        client_proc = subprocess.Popen(
            cmd,
            cwd=str(log_dir),
            stdout=client_log_fh,
            stderr=subprocess.STDOUT,
        )

        # --- 5/6  Wait for readiness ---------------------------------------
        log("[5/6] waiting for readiness")
        if not wait_healthy(server_api_port, "server", proc=server_proc):
            return False
        if not wait_healthy(client_api_port, "client", proc=client_proc):
            return False
        log("  both processes healthy")

        # --- 6/6  Random behavior test -------------------------------------
        log("")
        log("[6/6] random behavior test (%.1f s)" % duration)
        n_connects, n_sent, n_recv, open_conns = run_random_test(
            listen_port=client_listen_port,
            duration=duration,
            rng=rng,
            log_path=log_dir / "test.log",
            seed=seed,
        )

        # Guarantee at least two connections are alive for the shutdown test
        # in case the random loop happened to close all of them.
        for _ in range(max(0, 2 - len(open_conns))):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(("127.0.0.1", client_listen_port))
                s.setblocking(False)
                open_conns.append(s)
                log("  extra conn fd=%d (graceful-shutdown bait)" % s.fileno())
            except OSError as exc:
                log("  extra conn failed: %s" % exc)

        log("")
        log(
            "random test done: n_connects=%d  sent=%d  recv=%d  open_for_shutdown=%d"
            % (n_connects, n_sent, n_recv, len(open_conns))
        )

        # --- Graceful shutdown with active connections ----------------------
        log("")
        log(
            "graceful shutdown test (%d connection(s) still open)"
            % len(open_conns)
        )
        # Stop client first so it stops accepting on its local listen port,
        # then stop the server.
        client_rc = terminate_process(client_proc, "client")
        client_proc = None
        server_rc = terminate_process(server_proc, "server")
        server_proc = None

        # Close the surviving test sockets now that both processes are gone.
        for s in open_conns:
            try:
                s.close()
            except OSError:
                pass
        open_conns.clear()

        # --- Verdict -------------------------------------------------------
        log("")
        log("=== results ===")
        log("  connections opened : %d" % n_connects)
        log("  bytes sent         : %d" % n_sent)
        log("  bytes received     : %d" % n_recv)
        log("  client exit code   : %d" % client_rc)
        log("  server exit code   : %d" % server_rc)

        failures: List[str] = []
        if n_connects < 1:
            failures.append("no connections were established")
        if n_sent == 0:
            failures.append("no bytes were sent")
        if client_rc != 0:
            failures.append(
                "client exited with code %d (expected 0)" % client_rc)
        if server_rc != 0:
            failures.append(
                "server exited with code %d (expected 0)" % server_rc)

        if failures:
            for msg in failures:
                log("  FAIL: %s" % msg)
        else:
            passed = True

        return passed

    finally:
        # Ensure all surviving test sockets are closed.
        for s in open_conns:
            try:
                s.close()
            except OSError:
                pass

        # Ensure both processes are stopped regardless of how we got here.
        if client_proc is not None:
            terminate_process(client_proc, "client")
        if server_proc is not None:
            terminate_process(server_proc, "server")

        for fh in (client_log_fh, server_log_fh):
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass

        echo.stop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "End-to-end smoke test for multiplexd. "
            "Generates TLS certs, starts server+client at loglevel 8, "
            "runs randomised TCP activity, then sends SIGTERM with connections "
            "still open to verify graceful shutdown."
        )
    )
    parser.add_argument(
        "--build-dir",
        default="build",
        help="CMake build directory (default: build)",
    )
    parser.add_argument(
        "--log-dir",
        help="directory for logs and work files (default: build/smoke_<timestamp>)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="random seed for reproducibility",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="random test duration in seconds (default: 10)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_project_root(ROOT)

    build_dir = resolve_path(ROOT, args.build_dir)
    binary = build_dir / "bin" / "multiplexd"
    if not binary.exists():
        raise SystemExit("multiplexd not found: %s" % binary)

    cmake_cache = parse_cmake_cache(build_dir / "CMakeCache.txt")
    if cmake_cache.get("USE_TLS_LIBRARY") == "none":
        raise SystemExit(
            "TLS not available in this build (USE_TLS_LIBRARY=none); "
            "smoke test requires TLS and --gencerts"
        )

    if args.log_dir:
        log_dir = resolve_path(ROOT, args.log_dir)
    else:
        ts = time.strftime("%Y%m%d_%H%M%S")
        log_dir = build_dir / ("smoke_%s" % ts)
    log_dir.mkdir(parents=True, exist_ok=True)

    log("multiplexd : %s" % binary)
    log("log dir    : %s" % log_dir)
    log("seed       : %s" % args.seed)
    log("duration   : %.1f s" % args.duration)

    rng = random.Random(args.seed)
    result = smoke_test(
        binary=binary,
        log_dir=log_dir,
        rng=rng,
        duration=args.duration,
        seed=args.seed,
    )

    log("")
    if result:
        log("[PASS] smoke test passed")
        log("logs: %s" % log_dir)
        return 0

    log("[FAIL] smoke test failed")
    log("logs: %s" % log_dir)
    return 1


if __name__ == "__main__":
    sys.exit(main())
