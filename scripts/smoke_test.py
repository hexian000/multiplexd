#!/usr/bin/env python3

"""End-to-end smoke test for multiplexd.

This is a multi-scenario suite that exercises the daemon the way real
deployments do, rather than a single happy-path run.  It builds three live
server/client topologies and runs a battery of scenarios against each:

Load topology (plain bidirectional, single tunnel, API enabled)
  * forward_integrity   - bulk forward transfer, byte-exact verification
  * reverse_integrity   - bulk reverse transfer, byte-exact verification
  * concurrent_streams  - many simultaneous request/response streams
  * half_close          - FIN-based half-close preserved end to end
  * coexistence         - bulk transfers must not starve interactive pings (DRR)
  * random_fuzz         - randomised connect/send/recv/close/RST churn
  * observability       - GET/POST /stats, /metrics, /config, /healthy
  * hot_reload          - PUT /config drains and reloads with streams active
  * graceful_shutdown   - SIGTERM with connections still open exits 0

Parallel topology (identity routing, N mux tunnels)
  * parallel_tunnels    - concurrent streams spread across N sessions, both
                          directions, byte-exact verification

Resumption topology (single tunnel through a kill-able TCP relay)
  * session_resumption  - transport is RST mid-transfer; the client reconnects
                          and replays unacked frames; the byte stream survives
                          intact and the Reconnects counter advances

Each scenario passes or fails independently; the suite prints a summary table
and exits non-zero if any scenario failed.

Usage::

    python3 scripts/smoke_test.py [options]

    --build-dir DIR   CMake build directory (default: build)
    --log-dir   DIR   Log and work directory (default: build/smoke_<timestamp>)
    --seed      INT   Random seed for reproducibility
    --duration  FLOAT Time budget (s) for time-based scenarios (default: 8)
    --quick           Smaller sizes/counts for a fast run
    --only      LIST  Comma-separated scenario names to run (default: all)
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
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD_DIR = ROOT / "build"

# The management API is loopback-only; never route its requests through an
# ambient http_proxy/https_proxy (which would 403 or fail to reach 127.0.0.1).
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# SO_LINGER value that triggers an RST on close instead of a graceful FIN.
_LINGER_RST = struct.pack("ii", 1, 0)

_CHUNK = 65536

_ACTIONS = ["connect", "send_small", "send_large",
            "recv", "close_graceful", "close_abrupt"]
_WEIGHTS = [4,          3,            2,            5,     2,               1]

# Builtin self-signed RSA-4096 certificate (CN/subjectAltName=DNS:test.example)
# and its key, used when the build under test lacks the OpenSSL-only --gencerts
# tool.  Kept identical to src/tlsutil_test.c's test_cert_pem/test_key_pem so
# the same backend-agnostic pair authenticates both peers via mutual pinning.
BUILTIN_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIFKjCCAxKgAwIBAgIUM70vOlOUSVk9dQ7tbW/ih/8sKCwwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCAXDTI2MDYwOTAyNDQ0NVoYDzIx
MjYwNTE2MDI0NDQ1WjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQC+SzjGbGTgjqsKQCEGYS3hFnO1hBoy1VQ8
zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uceOaVYLXIe3f96+TucfBJw
Wh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXkaxOOVaayRJx79cPxqqLFr
rDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW9tNYRrZWVoTe21m2apl6
/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGmRNzcAnguhIIe3z8qbwDH
1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVpmL6QLpMolNS0cznJgVo2
eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV08tZNLeNoN3ezRXsEYE2
/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baozaQwoGNzDO/QXffAADp/W
F2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus2IBTNFZp+mW8mCliYWop
zfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi0omuKHTR326KPLkG7IpW
agolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6Rn0bwaeCR6t0or8ru7Dxs
dq/TW93U5wIDAQABo2wwajAdBgNVHQ4EFgQU3hgHVZAn/Lh/xbRhabVaEGQbxc8w
HwYDVR0jBBgwFoAU3hgHVZAn/Lh/xbRhabVaEGQbxc8wDwYDVR0TAQH/BAUwAwEB
/zAXBgNVHREEEDAOggx0ZXN0LmV4YW1wbGUwDQYJKoZIhvcNAQELBQADggIBAIWF
in4MUtRj4R6GYGtjjnWt1m9aN4I/w22kdD183G07uTJZ+i545DdFNglt8ZIO1f2F
eQ67wQfxIeFeZrr4x6wA7B+RVwX/mRuj3aby5QXhNDVkjAp2su9GRPyIe3jXPDv/
/quE4Oufa0kE8HuvqPIOSO6UYWkNAP81LDoyDhyoadB5+mIuxpM3+NyKh6AK2g8n
Ran7GYKtMUrL7ryRoJyPcpFk/QyrWAMCbmO3p2Rxx5sj3RtL+6HNYTqNij5qsB+S
zmdmX8XyAW5Bgog3hrnrTn1j1AaxNgEczsjdDmaGQiYKscyLwMe38DI8NP/rPP4X
rMH8B/TLl+uRwY1THRtkyHI6y4ZnGzmdEBf001J/KUfBFnLxHZBrJwMYbgqLWjba
nVXS5GXAtt7Mmz2tKQo7gCHUjgByWcnun3qMGcEoCkkTaqi0pxf2844BYyy73VRT
XdPJnfOOHDhuwkkeOfVJbPnfYFAAd8qMpmzBQvz4Clz2q4plB7odyWPSGwvLbFYs
sdwuTXnyLqCrB3K0uMBlKr7xeWiVHUfe5oGCwgp7TjV/2AmKUxNzdg41d3Fn7TPK
CncDeSmMy1elKbutfBvWvl8d7C0A9viO49Vy0CVR41uQnF09bzdFTYoaOrX8c+w4
VtiUoGP5D91X1vhTixpq4BqoHRkKVQpZ0Z/9386J
-----END CERTIFICATE-----
"""

BUILTIN_KEY_PEM = """\
-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQC+SzjGbGTgjqsK
QCEGYS3hFnO1hBoy1VQ8zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uce
OaVYLXIe3f96+TucfBJwWh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXka
xOOVaayRJx79cPxqqLFrrDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW
9tNYRrZWVoTe21m2apl6/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGm
RNzcAnguhIIe3z8qbwDH1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVp
mL6QLpMolNS0cznJgVo2eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV
08tZNLeNoN3ezRXsEYE2/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baoz
aQwoGNzDO/QXffAADp/WF2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus
2IBTNFZp+mW8mCliYWopzfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi
0omuKHTR326KPLkG7IpWagolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6R
n0bwaeCR6t0or8ru7Dxsdq/TW93U5wIDAQABAoICAAorHteLh0BwnzcnAhzDKJ50
gq5aZsP8nkm5kDqWre2s3IMqSJlVtKQg+GddTv/SyY5nzWt7tWjC0qLM1ccGdqir
mDFMDCFqh9m1FwgPjEG+8lDWFpK8bc+fHluVbGDx21+UyOsI6c6WB+ikSLz9Lpl7
C67jULmqVgC47NwoLpHpAoedu+/Pb89CDbzKqdfziAlT/NZmS3TaIA2KFvUKokeu
y97UvdB/lb/617jVneXEMXr92ZfuCqqq0Wi0Dt8Egrdx29NoUhUwwcDuwRaIkz95
GTLpHwj3cYU8G9BRheNkW6ddSzfvVy+E48mR0jJJItu7zOABucekSmaAIP63Xmmf
ISujhU7P1LVLClj/T9c1AJ5EPCdZIbnooe3I1nEppGsKQZ6HP7YOPiWolDjJm2Z2
nDQ/y/Ez3z44rywiY3slmypMDmbg96OBStHvfeBedDm18yRZu973QIJJ3kjrMBh9
MitVVc/8q6WuTIgPnSfMLVYkSQv5AMrOntXcYMzxyiWHui3+lbT0JrL9knJVrNoi
iT1NfSsbWaTxpOZgH0n07na9IDDvsENDy1uoE3wHVBGdHOKb+0bdauIHg4L2Vuaq
9fEXHYnIfmXoPs2pAu+ijP2ZwAwBZpCQrs9wd5p5RAuCPnuQCnKhGZ2087/XZqGR
e1sYrreurkSaZci1DbMxAoIBAQDjNLoiq/ckjuC4eBLr5ubgliKmQxGdXdwJJG/j
udJfRWYY7yaRSSUWomin0jj35Ilmt5idzawSouDZVZz5LP7zPUvt78DtQSVFLazV
vYyaKbPhRcVnt/y1nwbMIOCWPrNEE6smvQyjrANS9mAfPFUteDG7jH9qRxEOB6HT
B3u0JinhbhP0sHyuju1bqzNLCS+Hqyv1re9eYATRMzsy+0vCnIZglojm9/Nfbu6F
VNOaOmmpYn5+gfp3xepfa3CqRO/SdVWAwbgpYi000lWLQK1KarDad/UERwWjE96/
cFStLkwK2IAGJ4K7hXFIcw5oWBanybyVg0SZp6d2X3ZHp6/lAoIBAQDWaPMZqLLY
hDLTAi2FihBnva9zYd7BBkaGDiDas/HzTPfhSW2skCfFJbOf65NPq67YJTAbrVlN
WLNsBFvaKgxAqJtmrgpcCrAW7L5x6hEPKNp4dBGaNOEVzDHZQjZMAobh5fCwl0uK
2et6wda1BNat9ckYtSdYOZNoKSK2FCKzj2xGoboez8ndpq3sbQkYSsG62igMAXkd
TRVlTdvIo5Tgjl6tFPPmppUi5hEJx0K6sD3v+vKK+kCoHU40blL+2t2sulXYSIfH
YiyGBBAljA6AE2KKuz9YoRQ2+Erla2tPQMkC+LgJujEaCZaTP7jWzrvgB4mh+BrL
yU73qOGfgyzbAoIBAESC98XQuRuLAfReMMZ1wBTk8NnVy4/6Z4lSNXMj623TDXBj
XOvedJKYspo4Z/lILq6MmjareEG+X7LpgAYbLV3HlAfRjgl85XIwzbc+CxHJlXZO
hbI65rcVlwUivNZRXdkfXTK3OwJ3siDoLh/9H2ownj6BpUI0382tO3zY+tJd168k
dFwKg+5XJvfHbhYoVO7CDOVuZ4m7xngWzLkY0cWDUXn6qpmLFxYl60LFS3FsP8RV
8PLQ2ugXBA915GlTlEWQIBJNV+0Sr7MH4ce13wtblKysE3QQvoBoU3jCtKXsGf4D
PsecTm2hVYGVQDjypxI9YOJszNjQl0y4iIAe7okCggEBALhVkmtE9j3fqjJvdOOS
R3hpRCZWxkP9OTSXgPeGLUWXrqUpk/kAFrEQMNYUmpmsaK27ixjAeD5fPCJpvO5b
qB0O2Ev25UEsjyemcjVNn00BOpLEdz20qK8s1s6KdlPy+DPOlJe9+1xs7l6juAv5
FPiKj1GGrUTUez7Z3tXbidoGPHidIn7K9ipx2qWhOGiCHPygAj4QJihi1To7LfHZ
cW19+TelA+wQ27cdRRi7D0uhqh5gCZYigOQIDexVzVT+pgaSTKud794jMVQmuhsN
xommINpVEakJE3APF5UWPTPt5uN/Ifp68SwJgkMmTaugITYCRPnTbHY3pISX1SJm
jHECggEBAI7oDbmegf1H4KFbAn2ZCRJuMQg2SgtXb4gKbvrnvd/SAQoFkIth0VZ2
9IccGPbgaEYxLXGDhY4oiibtRX5cCwB0uOYbb495SUuJRyA0bMJVHqtcRo3zX5df
PNM+lny+hwzm3VziNfgGqNjAbOK5ukXrtaDMP1J2KyIbfC8A0eP+lUYnd/oJTRQN
rJvfapSR/TGwsz0A4BtKCRJ5zlMvNm87soACzZBV9Es0ROf3683v/e1kMhffcvbS
MKCbHGB5/oKk/I0aaRsNvyU0+TPSXEBu3HzAmmCns1p7MJYfghjg2H3f9nhE5smE
NL+YLwobqSZhkl4iZWt2wGODitzp/aQ=
-----END PRIVATE KEY-----
"""


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


def build_has_tls(build_dir: Path) -> Optional[bool]:
    """Return whether the build in *build_dir* has TLS compiled in.

    Read from ``#define WITH_TLS 0|1`` in the generated src/config.h, which
    records the *effective* backend even when USE_TLS_LIBRARY was left at its
    "auto" default — CMake resolves "auto" into a local and never writes the
    result back to CMakeCache.txt, so the cache is not a reliable source.
    Returns None when it cannot be determined (config.h absent or malformed).
    """
    config_h = build_dir / "src" / "config.h"
    try:
        text = config_h.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for raw in text.splitlines():
        fields = raw.split()
        if (len(fields) >= 3 and fields[0] == "#define"
                and fields[1] == "WITH_TLS"):
            return fields[2] != "0"
    return None


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


def connect(port: int, *, timeout: float = 5.0,
            attempts: int = 20) -> socket.socket:
    """Open a blocking TCP connection to a localhost *port*, with retries.

    The local listener is up by the time the daemon reports healthy, but a
    freshly reloaded listener may briefly refuse; a short retry loop absorbs
    that without flaking.
    """
    last: Optional[OSError] = None
    for _ in range(attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            return s
        except OSError as exc:
            last = exc
            try:
                s.close()
            except OSError:
                pass
            time.sleep(0.1)
    raise ConnectionError(
        "could not connect to 127.0.0.1:%d: %s" % (port, last))


def recv_exact(sock: socket.socket, n: int, *, deadline: float) -> bytes:
    """Read exactly *n* bytes from *sock* or raise before *deadline*."""
    buf = bytearray()
    while len(buf) < n:
        if time.monotonic() > deadline:
            raise TimeoutError(
                "timed out after %d/%d bytes" % (len(buf), n))
        try:
            chunk = sock.recv(min(_CHUNK, n - len(buf)))
        except socket.timeout:
            continue
        if not chunk:
            raise ConnectionError("EOF after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return bytes(buf)


# ---------------------------------------------------------------------------
# In-process TCP echo server (the forwarding target)
# ---------------------------------------------------------------------------

class EchoServer:
    """Thread-backed TCP echo server used as the forwarding target.

    Echoes every received byte back to the sender.  Handler sockets block
    indefinitely on recv so a quiet stream (e.g. during a simulated transport
    outage) is never torn down by a target-side timeout; connections end only
    on EOF or peer close.
    """

    def __init__(self, port: int, name: str = "echo") -> None:
        self._port = port
        self._name = name
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
        self._sock.listen(256)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name=self._name
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
            except socket.timeout:
                continue  # idle tick; keep accepting
            except OSError:
                break  # listener closed by stop()
            threading.Thread(
                target=EchoServer._handle, args=(conn,), daemon=True
            ).start()

    @staticmethod
    def _handle(conn: socket.socket) -> None:
        conn.settimeout(None)
        try:
            while True:
                chunk = conn.recv(_CHUNK)
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
# Kill-able TCP relay for session-resumption testing
# ---------------------------------------------------------------------------

class MuxRelay:
    """TCP relay: listens on *front_port*, forwards to *back_port*.

    :meth:`drop_all` forcibly RSTs every live connection pair but keeps the
    listener up, simulating a transient transport failure that the client must
    recover from via session resumption.  The relay never originates data, so
    dropping it leaves the application byte stream entirely to the daemon's
    unacked-frame replay.
    """

    def __init__(self, front_port: int, back_port: int) -> None:
        self._front = front_port
        self._back = back_port
        self._listen: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._pairs: List[Tuple[socket.socket, socket.socket]] = []
        self.drops = 0

    @property
    def front_port(self) -> int:
        return self._front

    def start(self) -> None:
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen.bind(("127.0.0.1", self._front))
        self._listen.listen(64)
        self._listen.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="mux-relay")
        self._thread.start()

    def _serve(self) -> None:
        assert self._listen is not None
        while not self._stop.is_set():
            try:
                front, _addr = self._listen.accept()
            except socket.timeout:
                continue  # idle tick; keep accepting so reconnects land
            except OSError:
                break  # listener closed by stop()
            try:
                back = socket.create_connection(
                    ("127.0.0.1", self._back), timeout=5.0)
            except OSError:
                try:
                    front.close()
                except OSError:
                    pass
                continue
            front.settimeout(None)
            back.settimeout(None)
            with self._lock:
                self._pairs.append((front, back))
            self._pump(front, back)
            self._pump(back, front)

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        def run() -> None:
            try:
                while True:
                    data = src.recv(_CHUNK)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        threading.Thread(target=run, daemon=True, name="relay-pump").start()

    def drop_all(self) -> int:
        """RST every live pair; keep listening.  Returns pairs dropped."""
        with self._lock:
            pairs = self._pairs
            self._pairs = []
        for a, b in pairs:
            for s in (a, b):
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 _LINGER_RST)
                    s.close()
                except OSError:
                    pass
        if pairs:
            self.drops += 1
        return len(pairs)

    def stop(self) -> None:
        self._stop.set()
        if self._listen is not None:
            try:
                self._listen.close()
            except OSError:
                pass
        self.drop_all()
        if self._thread is not None:
            self._thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# HTTP management API helpers
# ---------------------------------------------------------------------------

def api_request(
    api_port: int,
    path: str,
    *,
    method: str = "GET",
    body: Optional[bytes] = None,
    timeout: float = 5.0,
) -> Tuple[int, str]:
    url = "http://127.0.0.1:%d%s" % (api_port, path)
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def parse_stats(text: str) -> Dict[str, str]:
    """Parse the plain-text /stats body into a label -> value mapping."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        label, sep, value = line.partition(":")
        if sep:
            out[label.strip()] = value.strip()
    return out


def stat_reconnects(api_port: int) -> int:
    _status, text = api_request(api_port, "/stats")
    return int(parse_stats(text).get("Reconnects", "0"))


def wait_forward_ready(port: int, rng: random.Random,
                       timeout: float = 20.0) -> bool:
    """Poll a forward listener with a tiny echo round-trip until it succeeds.

    After a reload the session drains and reconnects; new app connections are
    briefly accepted but reset until the fresh session is established.  This
    rides out that window instead of racing it.
    """
    probe = make_payload(rng, 64)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = connect(port, timeout=5.0)
            s.settimeout(5.0)
            s.sendall(probe)
            got = recv_exact(s, 64, deadline=time.monotonic() + 5.0)
            s.close()
            if got == probe:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------
# Process lifecycle helpers
# ---------------------------------------------------------------------------

def terminate_process(
    proc: "subprocess.Popen[bytes]",
    name: str,
    *,
    sigterm_timeout: float = 10.0,
    sigkill_timeout: float = 3.0,
) -> Optional[int]:
    """Send SIGTERM and wait.  Escalate to SIGKILL on timeout.

    Returns the exit code (``-SIGKILL`` if a kill was necessary), or ``None``
    when even SIGKILL did not reap the process -- e.g. it is wedged in an
    uninterruptible kernel wait.  A ``None`` return means the process is still
    alive: the caller must keep its handle so the live PID is not forgotten,
    not treat it as successfully stopped.
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
        # The process outlived SIGKILL: do not fabricate an exit status or
        # claim it was reaped.  Report the still-live PID and let the caller
        # keep its handle for retry/reporting.
        log("  %s [pid:%d] STILL ALIVE after SIGKILL" % (name, proc.pid))
        return None
    log("  %s exited with code %d" % (name, rc))
    return rc


def binary_supports_gencerts(binary: Path) -> bool:
    """True if the build provides the OpenSSL-only ``--gencerts`` tool.

    The usage text lists ``--gencerts`` only when compiled ``WITH_OPENSSL``; the
    mbedTLS and no-TLS builds omit it, so probing ``--help`` reliably tells us
    whether to generate certs or fall back to the builtin pair.
    """
    try:
        result = subprocess.run(
            [str(binary), "--help"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=10.0)
    except (OSError, subprocess.SubprocessError):
        return False
    return b"--gencerts" in result.stdout


def wait_healthy(
    api_port: int,
    label: str,
    *,
    proc: "subprocess.Popen[bytes]",
    timeout: float = 20.0,
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
            with _OPENER.open(url, timeout=1.0) as resp:
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

def _tls(role: str, peer: str) -> Dict[str, object]:
    return {
        "cert": "@%s-cert.pem" % role,
        "key": "@%s-key.pem" % role,
        "authcerts": ["@%s-cert.pem" % peer],
    }


def _mux(window: Optional[int]) -> Dict[str, object]:
    mux: Dict[str, object] = {
        "keepalive": 30,
        "max_streams": 1000,
    }
    if window is not None:
        mux["stream_window"] = window
        mux["session_window"] = window
    return mux


def build_plain_server(
    *, mux_port: int, echo_port: int, reverse_listen: int, api_port: int,
    window: Optional[int], loglevel: int,
) -> Dict[str, object]:
    return {
        "mux_listen": "127.0.0.1:%d" % mux_port,
        "connect": "127.0.0.1:%d" % echo_port,
        "listen": "127.0.0.1:%d" % reverse_listen,
        "api_listen": "127.0.0.1:%d" % api_port,
        "tls": _tls("server", "client"),
        "mux": _mux(window),
        "loglevel": loglevel,
    }


def build_plain_client(
    *, mux_port: int, echo_port: int, forward_listen: int, api_port: int,
    window: Optional[int], loglevel: int,
) -> Dict[str, object]:
    return {
        "mux_connect": "127.0.0.1:%d" % mux_port,
        "connect": "127.0.0.1:%d" % echo_port,
        "listen": "127.0.0.1:%d" % forward_listen,
        "api_listen": "127.0.0.1:%d" % api_port,
        "tls": _tls("client", "server"),
        "mux": _mux(window),
        "loglevel": loglevel,
    }


def _psk(peer: str, key_file: str) -> Dict[str, object]:
    return {"psk": {peer: "@%s" % key_file}}


def build_psk_server(
    *, mux_port: int, echo_port: int, reverse_listen: int, api_port: int,
    key_file: str, loglevel: int,
) -> Dict[str, object]:
    return {
        "mux_listen": "127.0.0.1:%d" % mux_port,
        "connect": "127.0.0.1:%d" % echo_port,
        "api_listen": "127.0.0.1:%d" % api_port,
        "identity": {
            "claim": "psk-hub",
            "listen": {"psk-spoke": "127.0.0.1:%d" % reverse_listen},
        },
        "tls": _psk("psk-spoke", key_file),
        "mux": _mux(None),
        "loglevel": loglevel,
    }


def build_psk_client(
    *, mux_port: int, echo_port: int, forward_listen: int, api_port: int,
    key_file: str, claim: str, loglevel: int,
) -> Dict[str, object]:
    return {
        "connect": "127.0.0.1:%d" % echo_port,
        "api_listen": "127.0.0.1:%d" % api_port,
        "identity": {
            "claim": claim,
            "mux_connect": ["127.0.0.1:%d" % mux_port],
            "listen": {"psk-hub": "127.0.0.1:%d" % forward_listen},
        },
        "tls": _psk("psk-hub", key_file),
        "mux": _mux(None),
        "loglevel": loglevel,
    }


def build_identity_server(
    *, mux_port: int, echo_port: int, reverse_listen: int, api_port: int,
    window: Optional[int], loglevel: int, verify: bool = False,
) -> Dict[str, object]:
    identity: Dict[str, object] = {
        "claim": "server",
        "listen": {"client": "127.0.0.1:%d" % reverse_listen},
    }
    if verify:
        identity["verify"] = True
    return {
        "mux_listen": "127.0.0.1:%d" % mux_port,
        "connect": "127.0.0.1:%d" % echo_port,
        "api_listen": "127.0.0.1:%d" % api_port,
        "identity": identity,
        "tls": _tls("server", "client"),
        "mux": _mux(window),
        "loglevel": loglevel,
    }


def build_identity_client(
    *, mux_port: int, echo_port: int, forward_listen: int, api_port: int,
    tunnels: int, window: Optional[int], loglevel: int,
    verify: bool = False, claim: str = "client",
) -> Dict[str, object]:
    identity: Dict[str, object] = {
        "claim": claim,
        "mux_connect": ["127.0.0.1:%d" % mux_port] * tunnels,
        "listen": {"server": "127.0.0.1:%d" % forward_listen},
    }
    if verify:
        identity["verify"] = True
    return {
        "connect": "127.0.0.1:%d" % echo_port,
        "api_listen": "127.0.0.1:%d" % api_port,
        "identity": identity,
        "tls": _tls("client", "server"),
        "mux": _mux(window),
        "loglevel": loglevel,
    }


# ---------------------------------------------------------------------------
# Daemon pair lifecycle
# ---------------------------------------------------------------------------

class Daemons:
    """A running server+client pair with their log handles and API ports."""

    def __init__(
        self, binary: Path, log_dir: Path, *,
        server_cfg: Dict[str, object], client_cfg: Dict[str, object],
        server_api: int, client_api: int, tag: str,
    ) -> None:
        self.binary = binary
        self.log_dir = log_dir
        self.server_api = server_api
        self.client_api = client_api
        self.tag = tag
        self._server_cfg = server_cfg
        self._client_cfg = client_cfg
        self.server: Optional["subprocess.Popen[bytes]"] = None
        self.client: Optional["subprocess.Popen[bytes]"] = None
        self._fhs: List[object] = []

    def _spawn(self, cfg: Dict[str, object], role: str) -> "subprocess.Popen[bytes]":
        cfg_path = self.log_dir / ("%s-%s.json" % (self.tag, role))
        write_config(cfg_path, cfg)
        fh = (self.log_dir / ("%s-%s.log" % (self.tag, role))).open("wb")
        self._fhs.append(fh)
        cmd = [str(self.binary), "-c", str(cfg_path)]
        log("+ %s" % quote_command(cmd))
        return subprocess.Popen(
            cmd, cwd=str(self.log_dir), stdout=fh, stderr=subprocess.STDOUT)

    def spawn(self) -> None:
        """Start both processes without waiting for either to become healthy.

        For scenarios where one peer is expected to stay offline, so start()'s
        health gate would report the intended outcome as a failure.
        """
        self.server = self._spawn(self._server_cfg, "server")
        self.client = self._spawn(self._client_cfg, "client")

    def start(self) -> bool:
        self.server = self._spawn(self._server_cfg, "server")
        self.client = self._spawn(self._client_cfg, "client")
        if not wait_healthy(self.server_api, "%s server" % self.tag,
                            proc=self.server):
            return False
        if not wait_healthy(self.client_api, "%s client" % self.tag,
                            proc=self.client):
            return False
        # Give the client a moment to dial and establish its mux session(s).
        time.sleep(0.5)
        return True

    def shutdown(self) -> Tuple[Optional[int], Optional[int]]:
        """Stop client then server; return (client_rc, server_rc).

        A daemon that could not be reaped keeps its handle -- so the live PID
        is not forgotten -- and yields a ``None`` rc, which the caller's
        ``rc != 0`` check reports as a failure rather than a clean exit.
        """
        client_rc: Optional[int] = 0
        server_rc: Optional[int] = 0
        if self.client is not None:
            client_rc = terminate_process(self.client, "%s client" % self.tag)
            if client_rc is not None:
                self.client = None
        if self.server is not None:
            server_rc = terminate_process(self.server, "%s server" % self.tag)
            if server_rc is not None:
                self.server = None
        for fh in self._fhs:
            try:
                fh.close()  # type: ignore[attr-defined]
            except OSError:
                pass
        self._fhs = []
        return client_rc, server_rc

    def kill(self) -> None:
        # Best-effort teardown: keep the handle of any process that outlived
        # SIGKILL (terminate_process returns None) so it is not forgotten.
        if self.client is not None:
            rc = terminate_process(self.client, "%s client" % self.tag)
            if rc is not None:
                self.client = None
        if self.server is not None:
            rc = terminate_process(self.server, "%s server" % self.tag)
            if rc is not None:
                self.server = None
        for fh in self._fhs:
            try:
                fh.close()  # type: ignore[attr-defined]
            except OSError:
                pass
        self._fhs = []


# ---------------------------------------------------------------------------
# Scenario result + runner
# ---------------------------------------------------------------------------

# Scenarios known to fail because of an in-progress daemon bug, not a test
# defect.  They still run and report their real result, but an expected failure
# (XFAIL) does not fail the suite; an unexpected pass (XPASS) is flagged so the
# entry can be removed once the daemon is fixed.  Empty when the daemon is
# healthy; populate it (with a why + a removal condition) to quarantine a known
# regression without masking the rest of the suite.
KNOWN_FAILING: set = set()


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    detail: str = ""
    seconds: float = 0.0
    status: str = "PASS"  # PASS | FAIL | XFAIL | XPASS | SKIP

    @property
    def gating_failure(self) -> bool:
        """True only for failures that should make the suite exit non-zero."""
        return self.status == "FAIL"


@dataclass
class Suite:
    only: Optional[set] = None
    results: List[ScenarioResult] = field(default_factory=list)
    # Every scenario name run() has been offered, whether or not --only ran it.
    # main() validates --only against this so a typo can't silently skip all.
    known: set = field(default_factory=set)

    def run(self, name: str, fn: Callable[[], Tuple[bool, str]]) -> ScenarioResult:
        self.known.add(name)
        if self.only is not None and name not in self.only:
            return ScenarioResult(name, True, "skipped", 0.0, "SKIP")
        log("")
        log("--- scenario: %s ---" % name)
        start = time.monotonic()
        try:
            passed, detail = fn()
        except Exception as exc:  # noqa: BLE001 - report any failure as a result
            passed, detail = False, "exception: %r" % exc
        elapsed = time.monotonic() - start
        if name in KNOWN_FAILING:
            status = "XPASS" if passed else "XFAIL"
        else:
            status = "PASS" if passed else "FAIL"
        result = ScenarioResult(name, passed, detail, elapsed, status)
        self.results.append(result)
        log("  [%s] %s (%.2f s) %s" % (status, name, elapsed, detail))
        return result


# ---------------------------------------------------------------------------
# Payload + transfer helpers
# ---------------------------------------------------------------------------

def make_payload(rng: random.Random, n: int) -> bytes:
    return rng.randbytes(n)


def bulk_exchange(
    port: int, payload: bytes, *,
    timeout: float, pace_seconds: float = 0.0,
) -> Tuple[bool, str]:
    """Send *payload* over a stream and verify the echo is byte-identical.

    A receiver thread drains the echo concurrently with the (optionally paced)
    sender so full-duplex transfers larger than the socket buffers cannot
    deadlock.
    """
    sock = connect(port, timeout=timeout)
    sock.settimeout(timeout)
    received = bytearray()
    errors: List[str] = []
    deadline = time.monotonic() + timeout

    def receiver() -> None:
        try:
            received.extend(recv_exact(sock, len(payload), deadline=deadline))
        except Exception as exc:  # noqa: BLE001
            errors.append("receiver: %r" % exc)

    rx = threading.Thread(target=receiver, daemon=True, name="bulk-rx")
    rx.start()
    try:
        view = memoryview(payload)
        for off in range(0, len(payload), _CHUNK):
            sock.sendall(view[off:off + _CHUNK])
            if pace_seconds:
                time.sleep(pace_seconds)
    except Exception as exc:  # noqa: BLE001
        errors.append("sender: %r" % exc)
    rx.join(timeout=timeout)
    try:
        sock.close()
    except OSError:
        pass

    if rx.is_alive():
        return False, "transfer did not complete within %.1f s" % timeout
    if errors:
        return False, "; ".join(errors)
    if len(received) != len(payload):
        return False, "length mismatch: got %d want %d" % (
            len(received), len(payload))
    if bytes(received) != payload:
        return False, "payload mismatch (%d bytes)" % len(payload)
    return True, "%d bytes verified" % len(payload)


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scen_integrity(port: int, rng: random.Random, size: int,
                   label: str) -> Tuple[bool, str]:
    payload = make_payload(rng, size)
    timeout = max(30.0, size / (1 << 20) * 8.0)
    ok, detail = bulk_exchange(port, payload, timeout=timeout)
    return ok, "%s %s" % (label, detail)


def scen_concurrent_streams(port: int, rng: random.Random, count: int,
                            msg_size: int) -> Tuple[bool, str]:
    """Open *count* simultaneous streams, each a request/response echo."""
    payloads = [make_payload(rng, msg_size) for _ in range(count)]
    results: List[Optional[str]] = [None] * count
    barrier = threading.Barrier(count, timeout=30.0)

    def worker(i: int) -> None:
        try:
            sock = connect(port, timeout=15.0)
            sock.settimeout(20.0)
        except Exception as exc:  # noqa: BLE001
            results[i] = "connect: %r" % exc
            return
        try:
            try:
                barrier.wait()  # maximise concurrency overlap
            except threading.BrokenBarrierError:
                pass
            deadline = time.monotonic() + 20.0
            sock.sendall(payloads[i])
            got = recv_exact(sock, msg_size, deadline=deadline)
            if got != payloads[i]:
                results[i] = "stream %d payload mismatch" % i
        except Exception as exc:  # noqa: BLE001
            results[i] = "stream %d: %r" % (i, exc)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=40.0)

    failures = [r for r in results if r is not None]
    alive = sum(1 for t in threads if t.is_alive())
    if alive:
        return False, "%d/%d streams did not finish" % (alive, count)
    if failures:
        return False, "%d/%d failed: %s" % (
            len(failures), count, failures[0])
    return True, "%d concurrent streams verified" % count


def scen_half_close(port: int, rng: random.Random,
                    size: int) -> Tuple[bool, str]:
    """Verify FIN-based half-close: shutdown(WR), drain echo, then read EOF."""
    payload = make_payload(rng, size)
    sock = connect(port, timeout=10.0)
    sock.settimeout(20.0)
    deadline = time.monotonic() + 20.0
    try:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)  # half-close the write direction
        got = recv_exact(sock, size, deadline=deadline)
        # After the echo of all bytes, the target sees EOF and closes; the FIN
        # must propagate back so our next read returns EOF, not data.
        tail = sock.recv(1)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if got != payload:
        return False, "echo mismatch after half-close"
    if tail != b"":
        return False, "expected EOF after echo, got %d byte(s)" % len(tail)
    return True, "half-close preserved end to end (%d bytes)" % size


def scen_coexistence(port: int, rng: random.Random, *,
                     bulk_count: int, bulk_size: int,
                     pings: int) -> Tuple[bool, str]:
    """Bulk transfers must not starve small interactive request/responses.

    Saturating bulk streams run in the background while we time round-trips of
    tiny messages on separate streams; the DRR scheduler should keep the
    interactive streams responsive rather than letting bulk monopolise the
    link.
    """
    stop = threading.Event()
    bulk_errors: List[str] = []
    bulk_payloads = [make_payload(rng, bulk_size) for _ in range(bulk_count)]

    def bulk(i: int) -> None:
        # Loop the transfer so bulk pressure persists for the ping phase.
        while not stop.is_set():
            ok, detail = bulk_exchange(
                port, bulk_payloads[i], timeout=max(30.0, bulk_size / (1 << 20) * 8))
            if not ok:
                bulk_errors.append("bulk %d: %s" % (i, detail))
                return

    workers = [threading.Thread(target=bulk, args=(i,), daemon=True)
               for i in range(bulk_count)]
    for t in workers:
        t.start()

    time.sleep(0.5)  # let bulk ramp up and fill windows

    ping = make_payload(rng, 64)
    rtts: List[float] = []
    ping_errors: List[str] = []
    for _ in range(pings):
        try:
            s = connect(port, timeout=10.0)
            s.settimeout(10.0)
            t0 = time.monotonic()
            s.sendall(ping)
            echo = recv_exact(s, len(ping), deadline=time.monotonic() + 10.0)
            rtts.append(time.monotonic() - t0)
            if echo != ping:
                ping_errors.append("ping payload mismatch")
            s.close()
        except Exception as exc:  # noqa: BLE001
            ping_errors.append("%r" % exc)
        time.sleep(0.02)

    stop.set()
    for t in workers:
        t.join(timeout=60.0)

    if ping_errors:
        return False, "%d/%d pings failed: %s" % (
            len(ping_errors), pings, ping_errors[0])
    if bulk_errors:
        return False, bulk_errors[0]
    if not rtts:
        return False, "no ping samples collected"
    rtts.sort()
    p50 = rtts[len(rtts) // 2]
    p90 = rtts[min(len(rtts) - 1, int(len(rtts) * 0.9))]
    worst = rtts[-1]
    # Generous bound: this is a no-starvation/no-deadlock check, not a tight
    # latency SLA (loopback under sanitizers is slow and bursty).
    if worst > 5.0:
        return False, "interactive ping starved: max=%.3fs p90=%.3fs" % (
            worst, p90)
    return True, "%d pings under bulk load: p50=%.1fms p90=%.1fms max=%.1fms" % (
        pings, p50 * 1e3, p90 * 1e3, worst * 1e3)


def scen_random_fuzz(
    port: int, *, duration: float, rng: random.Random, log_path: Path,
) -> Tuple[bool, str, List[socket.socket]]:
    """Randomised connect/send/recv/close/RST churn for *duration* seconds.

    Returns ``(passed, detail, open_conns)``; the surviving sockets are handed
    back so the caller can use them for the graceful-shutdown check.
    """
    conns: List[socket.socket] = []
    n_connects = n_sent = n_recv = 0
    start = time.monotonic()

    def _close(s: socket.socket, *, rst: bool) -> None:
        conns.remove(s)
        try:
            if rst:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_RST)
            s.close()
        except OSError:
            pass

    with log_path.open("w", encoding="utf-8") as logf:
        deadline = start + duration
        while time.monotonic() < deadline:
            action = "connect" if not conns else rng.choices(
                _ACTIONS, weights=_WEIGHTS, k=1)[0]
            if action == "connect":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.settimeout(2.0)
                    s.connect(("127.0.0.1", port))
                    s.setblocking(False)
                    conns.append(s)
                    n_connects += 1
                except OSError:
                    try:
                        s.close()
                    except OSError:
                        pass
            elif action in ("send_small", "send_large"):
                s = rng.choice(conns)
                lo, hi = (1, 256) if action == "send_small" else (1024, 8192)
                try:
                    n_sent += s.send(rng.randbytes(rng.randint(lo, hi)))
                except BlockingIOError:
                    pass
                except OSError:
                    _close(s, rst=False)
            elif action == "recv":
                s = rng.choice(conns)
                try:
                    chunk = s.recv(4096)
                    if chunk:
                        n_recv += len(chunk)
                    else:
                        _close(s, rst=False)
                except BlockingIOError:
                    pass
                except OSError:
                    _close(s, rst=False)
            elif action == "close_graceful":
                _close(rng.choice(conns), rst=False)
            elif action == "close_abrupt":
                _close(rng.choice(conns), rst=True)
            time.sleep(rng.uniform(0.002, 0.010))
        logf.write("connects=%d sent=%d recv=%d open=%d\n" %
                   (n_connects, n_sent, n_recv, len(conns)))

    if n_connects < 1:
        return False, "no connections established", conns
    if n_sent == 0:
        return False, "no bytes sent", conns
    return True, "connects=%d sent=%d recv=%d open=%d" % (
        n_connects, n_sent, n_recv, len(conns)), conns


def scen_observability(server_api: int, client_api: int) -> Tuple[bool, str]:
    checks: List[str] = []

    def fail(msg: str) -> Tuple[bool, str]:
        return False, msg

    for label, api in (("server", server_api), ("client", client_api)):
        status, _ = api_request(api, "/healthy")
        if status != 200:
            return fail("%s /healthy returned %d" % (label, status))

        status, text = api_request(api, "/stats")
        if status != 200 or "Sessions" not in text:
            return fail("%s GET /stats malformed (status %d)" % (label, status))
        stats = parse_stats(text)
        for key in ("Sessions", "Streams", "Stream Opens", "Reconnects"):
            if key not in stats:
                return fail("%s /stats missing %r" % (label, key))

        status, text = api_request(api, "/stats", method="POST")
        if status != 200:
            return fail("%s POST /stats returned %d" % (label, status))

        status, text = api_request(api, "/metrics")
        if status != 200 or "multiplexd_" not in text:
            return fail("%s /metrics malformed (status %d)" % (label, status))
        for metric in ("multiplexd_uptime_seconds", "multiplexd_streams"):
            if metric not in text:
                return fail("%s /metrics missing %s" % (label, metric))

        status, text = api_request(api, "/config")
        if status != 200:
            return fail("%s GET /config returned %d" % (label, status))
        try:
            cfg = json.loads(text)
        except json.JSONDecodeError as exc:
            return fail("%s /config not valid JSON: %s" % (label, exc))
        if "mux" not in cfg:
            return fail("%s /config missing mux block" % label)
        checks.append("%s ok" % label)

    return True, "; ".join(checks)


def scen_hot_reload(client_proc: "subprocess.Popen[bytes]", client_api: int,
                    forward_port: int, rng: random.Random,
                    base_cfg: Dict[str, object]) -> Tuple[bool, str]:
    """Reload via PUT /config with a stream in flight; verify drain + apply.

    Checks the reload guarantees that a hot reload must honour:
      * PUT /config parses and applies the new config (returns 204);
      * an already-established stream completes byte-exact despite the
        reload-triggered session drain;
      * the change is observable via GET /config;
      * the daemon stays up and serves brand-new connections after the
        post-drain reconnect.

    GET /config redacts TLS key material (returns empty cert/key strings), so a
    GET-then-PUT round trip cannot reload a TLS config; we PUT a config we build
    ourselves, keeping the ``@path`` certificate references the daemon resolves
    from its working directory.
    """
    status, text = api_request(client_api, "/config")
    if status != 200:
        return False, "GET /config returned %d" % status
    old_level = int(json.loads(text).get("loglevel", 4))
    new_level = 5 if old_level != 5 else 6

    # Open a stream and leave a verification in flight across the reload.
    payload = make_payload(rng, 256 * 1024)
    sock = connect(forward_port, timeout=10.0)
    sock.settimeout(30.0)
    received = bytearray()
    deadline = time.monotonic() + 40.0

    def receiver() -> None:
        try:
            received.extend(recv_exact(sock, len(payload), deadline=deadline))
        except Exception:  # noqa: BLE001
            pass

    rx = threading.Thread(target=receiver, daemon=True)
    rx.start()
    sock.sendall(payload[:len(payload) // 2])

    new_cfg = dict(base_cfg)
    new_cfg["loglevel"] = new_level
    status, _ = api_request(
        client_api, "/config", method="PUT",
        body=json.dumps(new_cfg).encode("utf-8"))
    if status not in (200, 204):
        sock.close()
        return False, "PUT /config returned %d" % status

    # Active stream must finish despite the reload-triggered session drain.
    sock.sendall(payload[len(payload) // 2:])
    rx.join(timeout=40.0)
    try:
        sock.close()
    except OSError:
        pass
    if bytes(received) != payload:
        return False, "active stream corrupted across reload (%d/%d bytes)" % (
            len(received), len(payload))

    # The reloaded config must be observable.
    status, text = api_request(client_api, "/config")
    if status != 200 or int(json.loads(text).get("loglevel", -1)) != new_level:
        return False, "reloaded loglevel not reflected in /config"

    # The daemon must survive the reload.
    if client_proc.poll() is not None:
        return False, "client exited (code %s) after reload" % (
            client_proc.returncode)

    # A brand-new connection must work once the session has reconnected.
    if not wait_forward_ready(forward_port, rng, timeout=20.0):
        return False, "forward path did not recover after reload"
    ok, detail = bulk_exchange(forward_port, make_payload(rng, 256 * 1024),
                               timeout=30.0)
    if not ok:
        return False, "post-reload transfer failed: %s" % detail
    return True, ("reload loglevel %d->%d applied; active stream survived "
                  "drain; new connections served" % (old_level, new_level))


def scen_resumption(
    forward_port: int, client_api: int, relay: MuxRelay, rng: random.Random,
    *, size: int, target_seconds: float, drops: int,
) -> Tuple[bool, str]:
    """Drop the mux transport mid-transfer; the byte stream must survive."""
    before = stat_reconnects(client_api)
    payload = make_payload(rng, size)
    num_chunks = max(1, len(payload) // _CHUNK)
    pace = target_seconds / num_chunks
    # Generous enough for a healthy paced transfer plus resume recovery, while
    # bounding how long a stalled (currently-failing) resume blocks the suite.
    timeout = target_seconds + 30.0

    outcome: List[Tuple[bool, str]] = []

    def transfer() -> None:
        outcome.append(bulk_exchange(
            forward_port, payload, timeout=timeout, pace_seconds=pace))

    worker = threading.Thread(target=transfer, daemon=True, name="resume-xfer")
    worker.start()

    # Space the drops evenly through the transfer window. Each sleep is a delay
    # relative to the previous drop, so a constant interval places drop k at an
    # absolute k * target_seconds / (drops + 1); scaling by (i + 1) instead made
    # the offsets accumulate, landing the last drop at or past the window end.
    for i in range(drops):
        time.sleep(target_seconds / (drops + 1))
        dropped = relay.drop_all()
        log("  relay drop #%d: RST %d connection pair(s)" % (i + 1, dropped))

    worker.join(timeout=timeout + 10.0)
    if worker.is_alive():
        return False, "transfer hung after %d transport drop(s)" % drops
    if not outcome:
        return False, "transfer produced no result"
    ok, detail = outcome[0]
    if not ok:
        return False, "integrity broken across resumption: %s" % detail

    # Allow the reconnect bookkeeping to settle, then confirm it happened.
    time.sleep(0.5)
    after = stat_reconnects(client_api)
    if after <= before:
        return False, "Reconnects did not advance (%d -> %d) after %d drop(s)" % (
            before, after, relay.drops)
    return True, "%s; Reconnects %d->%d across %d drop(s)" % (
        detail, before, after, relay.drops)


# ---------------------------------------------------------------------------
# Topology runners
# ---------------------------------------------------------------------------

@dataclass
class Sizes:
    bulk: int
    streams: int
    stream_msg: int
    coexist_bulk: int
    coexist_count: int
    pings: int
    tunnels: int
    fuzz_duration: float
    resume_size: int
    resume_seconds: float
    drops: int


def run_load_topology(binary: Path, log_dir: Path, suite: Suite,
                      rng: random.Random, sizes: Sizes, *,
                      window: Optional[int], loglevel: int) -> None:
    (echo_f, echo_r, mux, srv_api, cli_api, fwd_listen,
     rev_listen) = free_ports(7)
    log("load topology ports: echoF=%d echoR=%d mux=%d srv_api=%d cli_api=%d "
        "fwd=%d rev=%d" % (echo_f, echo_r, mux, srv_api, cli_api,
                           fwd_listen, rev_listen))
    ef, er = EchoServer(echo_f, "echo-fwd"), EchoServer(echo_r, "echo-rev")
    ef.start()
    er.start()
    client_cfg = build_plain_client(
        mux_port=mux, echo_port=echo_r, forward_listen=fwd_listen,
        api_port=cli_api, window=window, loglevel=loglevel)
    daemons = Daemons(
        binary, log_dir,
        server_cfg=build_plain_server(
            mux_port=mux, echo_port=echo_f, reverse_listen=rev_listen,
            api_port=srv_api, window=window, loglevel=loglevel),
        client_cfg=client_cfg,
        server_api=srv_api, client_api=cli_api, tag="load")
    try:
        if not daemons.start():
            suite.results.append(ScenarioResult(
                "load_topology_start", False,
                "daemons did not become healthy", 0.0, "FAIL"))
            return

        suite.run("forward_integrity", lambda: scen_integrity(
            fwd_listen, rng, sizes.bulk, "forward"))
        suite.run("reverse_integrity", lambda: scen_integrity(
            rev_listen, rng, sizes.bulk, "reverse"))
        suite.run("concurrent_streams", lambda: scen_concurrent_streams(
            fwd_listen, rng, sizes.streams, sizes.stream_msg))
        suite.run("half_close", lambda: scen_half_close(
            fwd_listen, rng, sizes.stream_msg))
        suite.run("coexistence", lambda: scen_coexistence(
            fwd_listen, rng, bulk_count=sizes.coexist_count,
            bulk_size=sizes.coexist_bulk, pings=sizes.pings))
        suite.run("observability", lambda: scen_observability(srv_api, cli_api))

        # hot_reload drains the session, which waits for all active streams to
        # finish, so run it while no other scenario is holding streams open
        # (before random_fuzz, whose leftover connections would block the
        # drain indefinitely).
        suite.run("hot_reload", lambda: scen_hot_reload(
            daemons.client, cli_api, fwd_listen, rng, client_cfg))

        # Random fuzz last so its leftover connections feed the shutdown test.
        open_conns: List[socket.socket] = []

        def fuzz() -> Tuple[bool, str]:
            ok, detail, conns = scen_random_fuzz(
                fwd_listen, duration=sizes.fuzz_duration, rng=rng,
                log_path=log_dir / "fuzz.log")
            open_conns.extend(conns)
            return ok, detail

        suite.run("random_fuzz", fuzz)

        # Graceful shutdown with connections still open.
        for _ in range(max(0, 3 - len(open_conns))):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(("127.0.0.1", fwd_listen))
                open_conns.append(s)
            except OSError:
                pass

        def shutdown() -> Tuple[bool, str]:
            client_rc, server_rc = daemons.shutdown()
            for s in open_conns:
                try:
                    s.close()
                except OSError:
                    pass
            if client_rc != 0 or server_rc != 0:
                return False, "client rc=%s server rc=%s (expected 0)" % (
                    client_rc, server_rc)
            return True, "clean exit with %d open connection(s)" % len(open_conns)

        suite.run("graceful_shutdown", shutdown)
    finally:
        daemons.kill()
        ef.stop()
        er.stop()


def run_psk_topology(binary: Path, log_dir: Path, suite: Suite,
                     rng: random.Random, sizes: Sizes, *,
                     loglevel: int) -> None:
    """External-PSK mode: no certificate is sent in either direction.

    Unlike the certificate scenarios this runs on every TLS backend, because
    --genpsk needs only randomness and the label derivation.
    """
    key_file = "smoke~psk.psk"
    if not (log_dir / key_file).exists():
        cmd = [str(binary), "--genpsk", "smoke~psk"]
        log("+ %s" % quote_command(cmd))
        r = subprocess.run(cmd, cwd=str(log_dir), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30.0)
        if r.returncode != 0:
            suite.results.append(ScenarioResult(
                "psk_genkey", False, r.stderr.decode(errors="replace")[:200],
                0.0, "FAIL"))
            return

    # --- honest pair -------------------------------------------------------
    (echo_f, echo_r, mux, srv_api, cli_api, fwd, rev) = free_ports(7)
    ef, er = EchoServer(echo_f, "k-echo-fwd"), EchoServer(echo_r, "k-echo-rev")
    ef.start()
    er.start()
    daemons = Daemons(
        binary, log_dir,
        server_cfg=build_psk_server(
            mux_port=mux, echo_port=echo_f, reverse_listen=rev,
            api_port=srv_api, key_file=key_file, loglevel=loglevel),
        client_cfg=build_psk_client(
            mux_port=mux, echo_port=echo_r, forward_listen=fwd,
            api_port=cli_api, key_file=key_file, claim="psk-spoke",
            loglevel=loglevel),
        server_api=srv_api, client_api=cli_api, tag="psk-ok")
    try:
        if not daemons.start():
            suite.results.append(ScenarioResult(
                "psk_match", False, "daemons not healthy", 0.0, "FAIL"))
        else:
            suite.run("psk_match", lambda: scen_integrity(
                fwd, rng, sizes.stream_msg, "forward"))
    finally:
        daemons.shutdown()
        ef.stop()
        er.stop()

    # --- impostor: same key, a claim it does not own -----------------------
    (echo_f2, echo_r2, mux2, srv_api2, cli_api2, fwd2, rev2) = free_ports(7)
    ef2 = EchoServer(echo_f2, "k-echo-fwd2")
    er2 = EchoServer(echo_r2, "k-echo-rev2")
    ef2.start()
    er2.start()
    bad = Daemons(
        binary, log_dir,
        server_cfg=build_psk_server(
            mux_port=mux2, echo_port=echo_f2, reverse_listen=rev2,
            api_port=srv_api2, key_file=key_file, loglevel=loglevel),
        client_cfg=build_psk_client(
            mux_port=mux2, echo_port=echo_r2, forward_listen=fwd2,
            api_port=cli_api2, key_file=key_file, claim="impostor",
            loglevel=loglevel),
        server_api=srv_api2, client_api=cli_api2, tag="psk-bad")

    def mismatch() -> Tuple[bool, str]:
        # Both peers own a forwarding listener, so with the impostor refused
        # neither reports healthy; observe the steady state instead of gating
        # on wait_healthy.
        bad.spawn()
        assert bad.server is not None and bad.client is not None
        deadline = time.monotonic() + 15.0
        server_log = log_dir / "psk-bad-server.log"
        rejected = False
        while time.monotonic() < deadline and not rejected:
            if bad.server.poll() is not None:
                return False, "server exited (%s)" % bad.server.returncode
            if bad.client.poll() is not None:
                return False, "client exited (%s)" % bad.client.returncode
            try:
                rejected = "authenticated with the key of" in \
                    server_log.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            if not rejected:
                time.sleep(0.2)
        if not rejected:
            return False, "server never rejected the mismatched claim"
        status, _body = api_request(cli_api2, "/healthy")
        if status == 200:
            return False, "impostor established a tunnel anyway"
        return True, ("claim refused despite a valid key; client "
                      "/healthy=%d" % status)

    try:
        suite.run("psk_mismatch", mismatch)
    finally:
        bad.kill()
        ef2.stop()
        er2.stop()


def run_identity_verify_topology(binary: Path, log_dir: Path, suite: Suite,
                                 rng: random.Random, sizes: Sizes, *,
                                 window: Optional[int], loglevel: int) -> None:
    """identity.verify end to end: the claim must be named by the certificate.

    Relies on the caller's --identity server,client pairing, which is exactly
    what the identity topology claims, so the honest pair needs no extra
    certificates.  The caller only invokes this when --gencerts produced the
    certificate set.
    """
    # --- honest peer: claim matches the certificate, traffic flows ----------
    (echo_f, echo_r, mux, srv_api, cli_api, fwd_listen,
     rev_listen) = free_ports(7)
    log("identity-verify topology ports: echoF=%d echoR=%d mux=%d" % (
        echo_f, echo_r, mux))
    ef, er = EchoServer(echo_f, "v-echo-fwd"), EchoServer(echo_r, "v-echo-rev")
    ef.start()
    er.start()
    daemons = Daemons(
        binary, log_dir,
        server_cfg=build_identity_server(
            mux_port=mux, echo_port=echo_f, reverse_listen=rev_listen,
            api_port=srv_api, window=window, loglevel=loglevel, verify=True),
        client_cfg=build_identity_client(
            mux_port=mux, echo_port=echo_r, forward_listen=fwd_listen,
            api_port=cli_api, tunnels=1, window=window, loglevel=loglevel,
            verify=True),
        server_api=srv_api, client_api=cli_api, tag="idverify-ok")
    try:
        if not daemons.start():
            suite.results.append(ScenarioResult(
                "identity_verify_match", False,
                "daemons not healthy with a matching identity", 0.0, "FAIL"))
        else:
            suite.run("identity_verify_match", lambda: scen_integrity(
                fwd_listen, rng, sizes.stream_msg, "forward"))
    finally:
        daemons.shutdown()
        ef.stop()
        er.stop()

    # --- impostor: same certificate, a claim it does not name ---------------
    # The certificate still chains to authcerts, so the TLS handshake succeeds
    # and only the post-handshake identity check rejects it.  That is the whole
    # point: without identity.verify this peer would be routed as "server".
    (echo_f2, echo_r2, mux2, srv_api2, cli_api2, fwd_listen2,
     rev_listen2) = free_ports(7)
    ef2 = EchoServer(echo_f2, "v-echo-fwd2")
    er2 = EchoServer(echo_r2, "v-echo-rev2")
    ef2.start()
    er2.start()
    bad = Daemons(
        binary, log_dir,
        server_cfg=build_identity_server(
            mux_port=mux2, echo_port=echo_f2, reverse_listen=rev_listen2,
            api_port=srv_api2, window=window, loglevel=loglevel, verify=True),
        client_cfg=build_identity_client(
            mux_port=mux2, echo_port=echo_r2, forward_listen=fwd_listen2,
            api_port=cli_api2, tunnels=1, window=window, loglevel=loglevel,
            verify=True, claim="impostor"),
        server_api=srv_api2, client_api=cli_api2, tag="idverify-bad")

    def mismatch() -> Tuple[bool, str]:
        # Neither peer can report healthy here: both sides own a forwarding
        # listener, and with the impostor rejected no tunnel is established
        # for either.  That 503 is the expected outcome, so the usual
        # wait_healthy() gate would report success as failure -- spawn both
        # and observe the steady state instead.
        bad.spawn()
        assert bad.server is not None and bad.client is not None
        deadline = time.monotonic() + 15.0
        server_log_path = log_dir / "idverify-bad-server.log"
        rejected = False
        while time.monotonic() < deadline and not rejected:
            if bad.server.poll() is not None:
                return False, "server exited (code %s)" % bad.server.returncode
            if bad.client.poll() is not None:
                return False, "client exited (code %s)" % bad.client.returncode
            try:
                rejected = "does not name it" in server_log_path.read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                pass
            if not rejected:
                time.sleep(0.2)
        if not rejected:
            return False, "server never logged an identity rejection"
        status, _body = api_request(cli_api2, "/healthy")
        if status == 200:
            return False, ("server rejected the claim yet the client reports "
                           "healthy, so a tunnel was established anyway")
        return True, ("mismatched claim rejected before any stream; "
                      "client /healthy=%d" % status)

    try:
        suite.run("identity_verify_mismatch", mismatch)
    finally:
        bad.kill()
        ef2.stop()
        er2.stop()


def run_parallel_topology(binary: Path, log_dir: Path, suite: Suite,
                          rng: random.Random, sizes: Sizes, *,
                          window: Optional[int], loglevel: int) -> None:
    (echo_f, echo_r, mux, srv_api, cli_api, fwd_listen,
     rev_listen) = free_ports(7)
    log("parallel topology ports: echoF=%d echoR=%d mux=%d tunnels=%d" % (
        echo_f, echo_r, mux, sizes.tunnels))
    ef, er = EchoServer(echo_f, "p-echo-fwd"), EchoServer(echo_r, "p-echo-rev")
    ef.start()
    er.start()
    daemons = Daemons(
        binary, log_dir,
        server_cfg=build_identity_server(
            mux_port=mux, echo_port=echo_f, reverse_listen=rev_listen,
            api_port=srv_api, window=window, loglevel=loglevel),
        client_cfg=build_identity_client(
            mux_port=mux, echo_port=echo_r, forward_listen=fwd_listen,
            api_port=cli_api, tunnels=sizes.tunnels, window=window,
            loglevel=loglevel),
        server_api=srv_api, client_api=cli_api, tag="parallel")
    try:
        if not daemons.start():
            suite.results.append(ScenarioResult(
                "parallel_topology_start", False, "daemons not healthy",
                0.0, "FAIL"))
            return

        def parallel() -> Tuple[bool, str]:
            # The client should hold one session per configured tunnel.
            _status, text = api_request(cli_api, "/stats")
            sessions_field = parse_stats(text).get("Sessions", "0")
            current = sessions_field.split("/")[0].strip()
            if int(current) < sizes.tunnels:
                return False, "expected %d sessions, /stats shows %r" % (
                    sizes.tunnels, sessions_field)
            ok, detail = scen_concurrent_streams(
                fwd_listen, rng, sizes.streams, sizes.stream_msg)
            if not ok:
                return False, "forward: %s" % detail
            # Reverse direction over identity routing too.
            ok, rdetail = scen_integrity(rev_listen, rng, sizes.stream_msg,
                                         "reverse")
            if not ok:
                return False, rdetail
            return True, "%d tunnels, %s, reverse ok" % (sizes.tunnels, detail)

        suite.run("parallel_tunnels", parallel)

        def shutdown() -> Tuple[bool, str]:
            client_rc, server_rc = daemons.shutdown()
            if client_rc != 0 or server_rc != 0:
                return False, "client rc=%s server rc=%s" % (
                    client_rc, server_rc)
            return True, "clean exit"

        suite.run("parallel_shutdown", shutdown)
    finally:
        daemons.kill()
        ef.stop()
        er.stop()


def run_resumption_topology(binary: Path, log_dir: Path, suite: Suite,
                            rng: random.Random, sizes: Sizes, *,
                            window: Optional[int], loglevel: int) -> None:
    (echo_f, echo_r, mux_real, relay_front, srv_api, cli_api, fwd_listen,
     rev_listen) = free_ports(8)
    log("resumption topology: relay %d -> server mux %d" %
        (relay_front, mux_real))
    ef, er = EchoServer(echo_f, "r-echo-fwd"), EchoServer(echo_r, "r-echo-rev")
    ef.start()
    er.start()
    relay = MuxRelay(relay_front, mux_real)
    relay.start()
    daemons = Daemons(
        binary, log_dir,
        server_cfg=build_plain_server(
            mux_port=mux_real, echo_port=echo_f, reverse_listen=rev_listen,
            api_port=srv_api, window=window, loglevel=loglevel),
        # The client dials the relay, not the server directly.
        client_cfg=build_plain_client(
            mux_port=relay_front, echo_port=echo_r, forward_listen=fwd_listen,
            api_port=cli_api, window=window, loglevel=loglevel),
        server_api=srv_api, client_api=cli_api, tag="resume")
    try:
        if not daemons.start():
            suite.results.append(ScenarioResult(
                "resumption_topology_start", False, "daemons not healthy",
                0.0, "FAIL"))
            return

        suite.run("session_resumption", lambda: scen_resumption(
            fwd_listen, cli_api, relay, rng,
            size=sizes.resume_size, target_seconds=sizes.resume_seconds,
            drops=sizes.drops))

        def shutdown() -> Tuple[bool, str]:
            client_rc, server_rc = daemons.shutdown()
            if client_rc != 0 or server_rc != 0:
                return False, "client rc=%s server rc=%s" % (
                    client_rc, server_rc)
            return True, "clean exit"

        suite.run("resumption_shutdown", shutdown)
    finally:
        daemons.kill()
        relay.stop()
        ef.stop()
        er.stop()


# A minimal config that parses cleanly but leaves the transport plaintext, so
# conf_check emits its plaintext-mode warning while --dump-config runs. Shared
# by the two scenarios below; each writes its own copy of it.
PLAINTEXT_PROBE_CONFIG = {
    "mux_listen": "127.0.0.1:1",
    "connect": "127.0.0.1:1",
}


def scen_dump_config(binary: Path, log_dir: Path) -> Tuple[bool, str]:
    """--dump-config must put machine-readable JSON on stdout, and nothing else.

    The config is deliberately plaintext so conf_check warns while parsing it:
    that diagnostic has to reach stderr, because on stdout it would prepend a
    `W ...` line to the JSON and break every caller that pipes the output into
    a parser.
    """
    cfg = log_dir / "dump_config.json"
    write_config(cfg, PLAINTEXT_PROBE_CONFIG)
    cmd = [str(binary), "-c", str(cfg), "--dump-config"]
    log("+ %s" % quote_command(cmd))
    result = subprocess.run(cmd, cwd=str(log_dir), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30.0)
    if result.returncode != 0:
        return False, "exit %d: %s" % (
            result.returncode, result.stderr.decode(errors="replace").strip())
    try:
        dumped = json.loads(result.stdout.decode("utf-8"))
    except ValueError as exc:
        return False, "stdout is not JSON (%s): %r" % (
            exc, result.stdout[:160])
    if not isinstance(dumped, dict) or "mux_listen" not in dumped:
        return False, "dumped config lacks mux_listen: %r" % (dumped,)
    # Without a diagnostic actually being emitted, the check above would pass
    # even if the sink were still pointed at stdout.
    stderr_text = result.stderr.decode(errors="replace")
    if "plaintext" not in stderr_text:
        return False, ("expected the plaintext-mode warning on stderr, "
                       "got %r" % stderr_text[:160])
    return True, "stdout parsed as JSON, warning on stderr"


def scen_loglevel_range(binary: Path, log_dir: Path) -> Tuple[bool, str]:
    """--loglevel must accept exactly the 0-8 the usage text documents.

    The rejection calls exit(), so it is only observable from outside the
    process; main_test.c covers the accepted bounds but cannot reach this.
    """
    cfg = log_dir / "loglevel_range.json"
    write_config(cfg, PLAINTEXT_PROBE_CONFIG)
    for level, want_ok in ((0, True), (8, True), (9, False), (99, False)):
        cmd = [str(binary), "-c", str(cfg), "--loglevel", str(level),
               "--dump-config"]
        log("+ %s" % quote_command(cmd))
        result = subprocess.run(cmd, cwd=str(log_dir), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30.0)
        if not want_ok:
            if result.returncode == 0:
                return False, ("--loglevel %d accepted, but the usage text "
                               "documents 0-8" % level)
            continue
        if result.returncode != 0:
            return False, "--loglevel %d rejected: exit %d: %s" % (
                level, result.returncode,
                result.stderr.decode(errors="replace").strip())
        # An accepted level must not disturb the JSON on stdout: level 8 routes
        # every debug line the boot path emits through the sink, so this is what
        # pins those lines to stderr rather than ahead of the dump.
        try:
            json.loads(result.stdout.decode("utf-8"))
        except ValueError as exc:
            return False, "--loglevel %d: stdout is not JSON (%s): %r" % (
                level, exc, result.stdout[:160])
    return True, "0/8 accepted with JSON intact, 9/99 rejected"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Multi-scenario end-to-end smoke test for multiplexd. Builds live "
            "server/client topologies and exercises bidirectional integrity, "
            "concurrency, half-close, DRR fairness, observability, hot reload, "
            "parallel tunnels, session resumption, and graceful shutdown."
        )
    )
    parser.add_argument("--build-dir", default="build",
                        help="CMake build directory (default: build)")
    parser.add_argument("--log-dir",
                        help="logs/work dir (default: build/smoke_<timestamp>)")
    parser.add_argument("--seed", type=int,
                        help="random seed for reproducibility")
    parser.add_argument("--duration", type=float, default=8.0,
                        help="time budget (s) for time-based scenarios")
    parser.add_argument("--quick", action="store_true",
                        help="smaller sizes/counts for a fast run")
    parser.add_argument("--loglevel", type=int, default=6,
                        help="daemon loglevel 0-8 (default: 6)")
    parser.add_argument("--window", type=int,
                        help="set both stream_window and session_window")
    parser.add_argument("--only",
                        help="comma-separated scenario names to run")
    return parser.parse_args(argv)


def make_sizes(args: argparse.Namespace) -> Sizes:
    if args.quick:
        return Sizes(
            bulk=2 << 20, streams=16, stream_msg=32 << 10, coexist_bulk=2 << 20,
            coexist_count=2, pings=12, tunnels=2,
            fuzz_duration=min(args.duration, 3.0), resume_size=1 << 20,
            resume_seconds=min(args.duration, 3.0), drops=2)
    return Sizes(
        bulk=8 << 20, streams=64, stream_msg=64 << 10, coexist_bulk=4 << 20,
        coexist_count=4, pings=30, tunnels=3,
        fuzz_duration=args.duration, resume_size=4 << 20,
        resume_seconds=max(4.0, args.duration), drops=2)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_project_root(ROOT)

    build_dir = resolve_path(ROOT, args.build_dir)
    binary = build_dir / "bin" / "multiplexd"
    if not binary.exists():
        raise SystemExit("multiplexd not found: %s" % binary)

    has_tls = build_has_tls(build_dir)
    if has_tls is None:
        # config.h unreadable; fall back to the (less reliable) cache value.
        cmake_cache = parse_cmake_cache(build_dir / "CMakeCache.txt")
        has_tls = cmake_cache.get("USE_TLS_LIBRARY") != "none"
    if not has_tls:
        raise SystemExit(
            "TLS not available in this build (WITH_TLS=0); "
            "smoke test requires TLS and --gencerts")

    if args.log_dir:
        log_dir = resolve_path(ROOT, args.log_dir)
    else:
        log_dir = build_dir / ("smoke_%s" % time.strftime("%Y%m%d_%H%M%S"))
    log_dir.mkdir(parents=True, exist_ok=True)

    sizes = make_sizes(args)
    rng = random.Random(args.seed)
    only = set(s.strip() for s in args.only.split(",")) if args.only else None

    log("multiplexd : %s" % binary)
    log("log dir    : %s" % log_dir)
    log("seed       : %s" % args.seed)
    log("mode       : %s" % ("quick" if args.quick else "full"))

    # Provide the shared certificate set for all topologies.  Cert generation
    # (--gencerts) is an OpenSSL-only tool, absent from the mbedTLS and no-TLS
    # builds; when the build under test does not provide it, fall back to the
    # builtin self-signed RSA-4096 cert/key (works with every TLS backend) used
    # for both peers, exactly as the unit tests do.
    # identity.verify needs certificates carrying an identity URI
    # subjectAltName; only --gencerts produces those, so the builtin-cert
    # fallback below cannot exercise it.  --identity is spelled out because
    # certificates carry no identity unless asked; the values match what the
    # identity topology claims.
    have_identity_certs = binary_supports_gencerts(binary)
    if have_identity_certs:
        log("")
        log("generating certificates (ed25519)")
        cmd = [str(binary), "--gencerts", "server,client",
               "--identity", "server,client",
               "--sni", "smoke.test.local", "--keytype", "ed25519"]
        log("+ %s" % quote_command(cmd))
        result = subprocess.run(cmd, cwd=str(log_dir), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30.0)
        if result.returncode != 0:
            raise SystemExit("gencerts failed (code %d):\n%s" % (
                result.returncode, result.stderr.decode(errors="replace")))
    else:
        log("")
        log("build has no --gencerts (non-OpenSSL backend); "
            "using builtin RSA-4096 certificate")
        for role in ("server", "client"):
            (log_dir / ("%s-cert.pem" % role)).write_text(
                BUILTIN_CERT_PEM, encoding="utf-8")
            (log_dir / ("%s-key.pem" % role)).write_text(
                BUILTIN_KEY_PEM, encoding="utf-8")

    suite = Suite(only=only)
    suite.run("dump_config", lambda: scen_dump_config(binary, log_dir))
    suite.run("loglevel_range", lambda: scen_loglevel_range(binary, log_dir))
    run_load_topology(binary, log_dir, suite, rng, sizes,
                      window=args.window, loglevel=args.loglevel)
    run_parallel_topology(binary, log_dir, suite, rng, sizes,
                          window=args.window, loglevel=args.loglevel)
    if build_has_tls(build_dir) is not False:
        run_psk_topology(binary, log_dir, suite, rng, sizes,
                         loglevel=args.loglevel)
    if have_identity_certs:
        run_identity_verify_topology(binary, log_dir, suite, rng, sizes,
                                     window=args.window,
                                     loglevel=args.loglevel)
    else:
        log("")
        log("skipping identity-verify topology: the builtin certificate "
            "carries no identity subjectAltName")
    run_resumption_topology(binary, log_dir, suite, rng, sizes,
                            window=args.window, loglevel=args.loglevel)

    # --- Summary -----------------------------------------------------------
    log("")
    log("=== summary ===")
    width = max((len(r.name) for r in suite.results), default=4)
    gating_failures = 0
    xfail = 0
    xpass = 0
    for r in suite.results:
        if r.gating_failure:
            gating_failures += 1
        elif r.status == "XFAIL":
            xfail += 1
        elif r.status == "XPASS":
            xpass += 1
        log("  %-5s  %-*s  %6.2fs  %s" %
            (r.status, width, r.name, r.seconds, r.detail))

    for r in suite.results:
        if r.status == "XPASS":
            log("")
            log("note: %s now passes — remove it from KNOWN_FAILING so it "
                "gates again" % r.name)

    log("")
    log("logs: %s" % log_dir)
    total = len(suite.results)
    extras = []
    if xfail:
        extras.append("%d known-failing (xfail)" % xfail)
    if xpass:
        extras.append("%d unexpectedly passing (xpass)" % xpass)
    suffix = (" [%s]" % ", ".join(extras)) if extras else ""
    # A mistyped --only name would otherwise skip every scenario and still
    # report [PASS]; reject any name that matched no registered scenario.
    if suite.only is not None:
        unknown = suite.only - suite.known
        if unknown:
            raise SystemExit(
                "--only names no known scenario: %s\nknown scenarios: %s"
                % (", ".join(sorted(unknown)),
                   ", ".join(sorted(suite.known))))
    if gating_failures:
        log("[FAIL] %d/%d scenario(s) failed%s" %
            (gating_failures, total, suffix))
        return 1
    log("[PASS] all gating scenario(s) passed%s" % suffix)
    return 0


if __name__ == "__main__":
    sys.exit(main())
