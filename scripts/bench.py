#!/usr/bin/env python3

"""Run the multiplexd iperf3 benchmark suite and write a Markdown summary."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import os
import platform
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, TextIO, Tuple, Union

# Sibling script, same scripts/ directory (Python puts a script's own directory
# on sys.path[0]): reuse its builtin RSA-4096 pair instead of a third copy of
# the same PEM data (the first two are smoke_test.py's own BUILTIN_CERT_PEM/
# KEY_PEM doc comment and src/tlsutil_test.c's embedded fixture).
from smoke_test import (BUILTIN_CERT_PEM, BUILTIN_KEY_PEM, api_request,
                        build_has_tls, parse_stats)

ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "bench.md"
BENCH_NETNS_ENV = "BENCH_NETNS"
MUX_TLS_PORT = 8443
IPERF_PORT = 5201
FORWARD_PORT = 5202
SERVER_API_PORT = 9081
CLIENT_API_PORT = 9082
READY_POLL_INTERVAL = 0.05
TCP_LISTEN_STATE = "0A"
CLK_TCK = float(os.sysconf("SC_CLK_TCK"))
PAGE_SIZE = int(os.sysconf("SC_PAGE_SIZE"))
RESOURCE_SAMPLE_INTERVAL = 0.1
BENCH_PORTS = (MUX_TLS_PORT, IPERF_PORT, FORWARD_PORT,
               SERVER_API_PORT, CLIENT_API_PORT)


def parse_cpu_set(value: str) -> tuple[int, ...]:
    try:
        cpus = tuple(int(item) for item in value.split(","))
    except ValueError as exc:
        raise SystemExit("--cpus requires four comma-separated CPU numbers") from exc
    if len(cpus) != 4 or len(set(cpus)) != 4 or min(cpus) < 0:
        raise SystemExit("--cpus requires four distinct nonnegative CPU numbers")
    if not set(cpus) <= os.sched_getaffinity(0):
        raise SystemExit("--cpus names CPUs outside this process's allowed affinity")
    try:
        if len({cpu_core(cpu) for cpu in cpus}) != 4:
            raise SystemExit("--cpus must use four distinct physical cores, not SMT siblings")
    except (OSError, ValueError):
        pass  # Explicit placement remains usable when topology is unavailable.
    return cpus


def cpu_core(cpu: int) -> tuple[int, int]:
    base = Path("/sys/devices/system/cpu/cpu%d/topology" % cpu)
    return (int((base / "physical_package_id").read_text()),
            int((base / "core_id").read_text()))


def cpu_snapshot() -> Dict[int, tuple[int, int]]:
    values = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if fields and fields[0].startswith("cpu") and fields[0][3:].isdigit():
            counters = [int(value) for value in fields[1:9]]
            values[int(fields[0][3:])] = (sum(counters), counters[3] + counters[4])
    return values


def select_cpus() -> tuple[int, ...]:
    """Choose quiet distinct guest cores once; never move roles between trials."""
    allowed = sorted(os.sched_getaffinity(0))
    cores: Dict[tuple[int, int], List[int]] = {}
    try:
        for cpu in allowed:
            cores.setdefault(cpu_core(cpu), []).append(cpu)
    except (OSError, ValueError) as exc:
        raise SystemExit("CPU topology unavailable; supply --cpus explicitly") from exc
    if len(cores) < 4:
        raise SystemExit("comparison needs four allowed physical cores; cannot isolate roles")
    before = cpu_snapshot()
    time.sleep(1)
    after = cpu_snapshot()
    busy = {cpu: 1 - (after[cpu][1] - before[cpu][1]) /
            max(1, after[cpu][0] - before[cpu][0]) for cpu in allowed}
    ordered = sorted(cores.values(), key=lambda group: (
        sum(busy[cpu] for cpu in group) / len(group), min(group)))
    return tuple(min(group, key=lambda cpu: (busy[cpu], cpu)) for group in ordered[:4])


def isolate_coordinator(cpus: Sequence[int]) -> None:
    """Keep monitoring off the workload's cores where spare cores exist."""
    allowed = os.sched_getaffinity(0)
    try:
        used = {cpu_core(cpu) for cpu in cpus}
        spare = {cpu for cpu in allowed if cpu_core(cpu) not in used}
    except (OSError, ValueError):
        spare = allowed - set(cpus)
    if spare:
        os.sched_setaffinity(0, spare)


def pin_command(command: Sequence[str], cpu: Optional[int]) -> List[str]:
    if cpu is None:
        return list(command)
    return [ensure_tool("taskset"), "-c", str(cpu), *command]


def read_pressure() -> Dict[str, int]:
    """Cumulative stall microseconds; compare deltas over this trial, not avg10."""
    totals = {}
    for resource in ("cpu", "memory", "io"):
        try:
            lines = (Path("/proc/pressure") / resource).read_text().splitlines()
            for line in lines:
                fields = line.split()
                for value in fields[1:]:
                    if value.startswith("total="):
                        totals[resource + "." + fields[0]] = int(value[6:])
        except (OSError, ValueError):
            continue
    return totals


def read_sched_wait(pid: int) -> Optional[int]:
    """Sum per-thread runnable wait nanoseconds (Linux schedstat field 2)."""
    try:
        tasks = list((Path("/proc") / str(pid) / "task").iterdir())
        values = []
        for task in tasks:
            try:
                values.append(int((task / "schedstat").read_text().split()[1]))
            except (OSError, ValueError, IndexError):
                continue
        return sum(values) if values else None
    except OSError:
        return None


def check_benchmark_environment(binaries: Sequence[Path] = ()) -> None:
    """Refuse occupied benchmark ports or rebuilding an in-use benchmark binary."""
    targets = {path.resolve() for path in binaries}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            executable = Path(os.readlink(entry / "exe")
                              .removesuffix(" (deleted)")).resolve()
        except OSError:
            continue
        if executable in targets:
            raise SystemExit(
                "benchmark binary is in use by PID %s: %s; leave the service "
                "running and choose a separate build/runtime directory"
                % (entry.name, executable))
    check_benchmark_ports()


def check_benchmark_ports(ports: Sequence[int] = BENCH_PORTS) -> None:
    """Probe by binding only: never connect to or terminate an existing service."""
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise SystemExit(
                    "benchmark port 127.0.0.1:%d is unavailable: %s; "
                    "leave its owner running and retry when the port is free"
                    % (port, exc)) from exc


def sample_session_cpu(session: int, binary: Path,
                       ticks: Dict[Tuple[int, int], int]) -> None:
    """Track this session's daemon lifetimes, including an exited peer's last sample."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal() or int(entry.name) == session:
            continue
        try:
            fields = (entry / "stat").read_text(
                encoding="ascii", errors="replace").rsplit(")", 1)[1].split()
            if int(fields[3]) != session:  # stat field 6: session ID
                continue
            if (entry / "exe").resolve(strict=True) != binary:
                continue
            if b"-c" not in (entry / "cmdline").read_bytes().split(b"\0"):
                continue
            identity = (int(entry.name), int(fields[19]))  # starttime
            ticks[identity] = max(ticks.get(identity, 0),
                                  int(fields[11]) + int(fields[12]))
        except (OSError, ValueError, IndexError):
            continue  # The process may exit between procfs reads.


def run_owned_benchmark(command: Sequence[str], cwd: Path, *,
                        cpu_output: Optional[Path] = None,
                        daemon_binary: Optional[Path] = None,
                        timeout_seconds: float = 900,
                        ports: Sequence[int] = BENCH_PORTS,
                        log_output: Optional[Path] = None) -> int:
    """Run one harness in a new session; sample and clean up only that session."""
    if cpu_output is not None:
        cpu_output.unlink(missing_ok=True)
    check_benchmark_ports(ports)
    ticks: Dict[Tuple[int, int], int] = {}
    binary = daemon_binary.resolve() if daemon_binary else None
    previous_handlers = {}
    waiter = threading.Event()

    def exit_status(pid: int) -> Optional[os.waitid_result]:
        # Keep the leader waitable until the final group signal: its PID then
        # cannot be reused as an unrelated service's process-group ID.
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def interrupted(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, interrupted)
    proc: Optional[subprocess.Popen[bytes]] = None
    log_handle = None
    try:
        launch = {"cwd": cwd, "start_new_session": True}
        if log_output is not None:
            log_handle = log_output.open("w", encoding="utf-8")
            launch.update(stdout=log_handle, stderr=subprocess.STDOUT)
        proc = subprocess.Popen(command, **launch)
        deadline = time.monotonic() + timeout_seconds
        while True:
            if binary is not None:
                sample_session_cpu(proc.pid, binary, ticks)
            status = exit_status(proc.pid)
            if status is not None:
                result = (status.si_status if status.si_code == os.CLD_EXITED
                          else -status.si_status)
                if cpu_output is not None and result == 0:
                    cpu_output.write_text("%.2f\n" % (sum(ticks.values()) / CLK_TCK),
                                          encoding="ascii")
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 124
            waiter.wait(min(RESOURCE_SAMPLE_INTERVAL, remaining))
    except KeyboardInterrupt as exc:
        return 128 + int(exc.args[0])
    finally:
        try:
            for signum in previous_handlers:
                signal.signal(signum, signal.SIG_IGN)
            if proc is not None:
                # The session/process group was created by this Popen. No
                # process-name or port-owner lookup is used for signalling.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                grace_deadline = time.monotonic() + 3
                while exit_status(proc.pid) is None:
                    remaining = grace_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    waiter.wait(min(RESOURCE_SAMPLE_INTERVAL, remaining))
                # The harness may have exited before a child; bound teardown
                # still removes any remaining members of its process group.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=3)
        finally:
            if log_handle is not None:
                log_handle.close()
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str


@dataclass(frozen=True)
class ResourceUsage:
    name: str
    cpu_percent: float
    real_seconds: float
    user_seconds: float
    sys_seconds: float
    peak_rss_bytes: int
    runnable_wait_seconds: Optional[float] = None


@dataclass
class ScenarioResult:
    scenario: Scenario
    command_texts: List[str]
    log_paths: List[Path]
    stderr_paths: List[Path]
    total_bits_per_second: float
    sent_bits_per_second: float
    received_bits_per_second: float
    stddev_bits_per_second: float
    interval_throughputs: List[float]
    duration_seconds: float
    resource_usage: List[ResourceUsage]
    transferred_bytes: int = 0


@dataclass(frozen=True)
class Service:
    proc: subprocess.Popen[str]
    name: str
    log_path: Path
    listen_ports: tuple[int, ...]


@dataclass(frozen=True)
class ProcessShutdownBudget:
    sigint_wait_seconds: float
    terminate_wait_seconds: float


SCENARIOS = (
    Scenario("uplink", "Uplink"),
    Scenario("downlink", "Downlink"),
    Scenario("bidir", "Bidirectional"),
    Scenario("parallel", "Parallel Bidirectional"),
)


def log(message: str) -> None:
    print(message, file=sys.stderr)


def quote_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def output_text(value: Optional[Union[str, bytes]]) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def read_proc_cpu_ticks(pid: int) -> Optional[tuple[int, int]]:
    """Return cumulative (utime, stime) in clock ticks for all threads of pid."""
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="ascii") as handle:
            data = handle.read()
    except OSError:
        return None
    # The comm field (field 2) is parenthesised and may contain spaces, so
    # split after the final ')'. fields[0] is then field 3 (state).
    rparen = data.rfind(")")
    if rparen < 0:
        return None
    fields = data[rparen + 1:].split()
    try:
        utime = int(fields[11])  # field 14
        stime = int(fields[12])  # field 15
    except (IndexError, ValueError):
        return None
    return utime, stime


def read_proc_rss_bytes(pid: int) -> Optional[int]:
    """Return the resident set size in bytes for pid."""
    try:
        with open("/proc/%d/statm" % pid, "r", encoding="ascii") as handle:
            parts = handle.read().split()
    except OSError:
        return None
    if len(parts) < 2:
        return None
    try:
        resident_pages = int(parts[1])
    except ValueError:
        return None
    return resident_pages * PAGE_SIZE


class ProcSampler:
    """Sample CPU time and peak RSS of processes from /proc during a scenario.

    CPU time is read once at start and once at stop (it is cumulative), while
    RSS is polled on a background thread to capture the peak.
    """

    def __init__(
            self,
            procs: Sequence[tuple[str, int]],
            *,
            interval: float = RESOURCE_SAMPLE_INTERVAL,
    ) -> None:
        self._procs = list(procs)
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._peak_rss: Dict[str, int] = {name: 0 for name, _ in self._procs}
        self._start_ticks: Dict[str, Optional[tuple[int, int]]] = {}
        self._end_ticks: Dict[str, Optional[tuple[int, int]]] = {}
        self._start_wait: Dict[str, Optional[int]] = {}
        self._end_wait: Dict[str, Optional[int]] = {}
        self._start_time = 0.0
        self._end_time = 0.0

    def _sample_rss(self) -> None:
        for name, pid in self._procs:
            rss = read_proc_rss_bytes(pid)
            if rss is not None and rss > self._peak_rss[name]:
                self._peak_rss[name] = rss

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval):
            self._sample_rss()

    def start(self) -> None:
        self._start_time = time.monotonic()
        for name, pid in self._procs:
            self._start_ticks[name] = read_proc_cpu_ticks(pid)
            self._start_wait[name] = read_sched_wait(pid)
        self._sample_rss()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        self._end_time = time.monotonic()
        for name, pid in self._procs:
            self._end_ticks[name] = read_proc_cpu_ticks(pid)
            self._end_wait[name] = read_sched_wait(pid)
        self._sample_rss()

    def results(self) -> List[ResourceUsage]:
        wall = max(1e-6, self._end_time - self._start_time)
        usage: List[ResourceUsage] = []
        for name, _ in self._procs:
            start = self._start_ticks.get(name)
            end = self._end_ticks.get(name)
            if start is None or end is None:
                user_seconds = sys_seconds = cpu_percent = 0.0
            else:
                user_seconds = (end[0] - start[0]) / CLK_TCK
                sys_seconds = (end[1] - start[1]) / CLK_TCK
                cpu_percent = (user_seconds + sys_seconds) / wall * 100.0
            usage.append(
                ResourceUsage(
                    name=name,
                    cpu_percent=cpu_percent,
                    real_seconds=wall,
                    user_seconds=user_seconds,
                    sys_seconds=sys_seconds,
                    peak_rss_bytes=self._peak_rss[name],
                    runnable_wait_seconds=(
                        max(0, self._end_wait[name] - self._start_wait[name]) / 1e9
                        if self._start_wait.get(name) is not None
                        and self._end_wait.get(name) is not None else None),
                )
            )
        return usage


def ensure_project_root(root: Path) -> None:
    if not (root / "CMakeLists.txt").exists():
        raise SystemExit(
            "working directory does not look like the project root: %s" % root
        )


def ensure_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit("required tool not found: %s" % name)
    return path


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


def relative_path(path: Path) -> str:
    return os.path.relpath(path, start=ROOT).replace(os.sep, "/")


def run_command(
        command: Sequence[str],
        *,
        cwd: Optional[Path] = None,
        timeout: Optional[float] = None,
) -> None:
    log("+ %s" % quote_command(command))
    try:
        subprocess.run(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            check=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("command timed out: %s" % quote_command(command))


def find_iperf_warning_line(text: str) -> Optional[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.upper().startswith("WARNING:"):
            return line
    return None


def compute_command_timeout_seconds(
        duration_seconds: int,
        startup_wait_seconds: float,
) -> float:
    extra_seconds = max(
        30.0,
        min(120.0, float(duration_seconds) * 0.25),
        startup_wait_seconds * 4.0,
    )
    return float(duration_seconds) + extra_seconds


def compute_process_shutdown_budget(
        duration_seconds: int,
        startup_wait_seconds: float,
        *,
        scenario_count: int,
) -> ProcessShutdownBudget:
    sigint_wait_seconds = max(
        5.0,
        min(
            60.0,
            startup_wait_seconds * 2.0
            + float(duration_seconds) * 0.25
            + float(scenario_count),
        ),
    )
    terminate_wait_seconds = max(
        2.0,
        min(15.0, sigint_wait_seconds / 2.0),
    )
    return ProcessShutdownBudget(
        sigint_wait_seconds=sigint_wait_seconds,
        terminate_wait_seconds=terminate_wait_seconds,
    )


def apply_tls_options(
        tls: Dict[str, object],
        ciphersuites: Optional[str],
        socket_offload: Optional[bool],
        kernel_offload: Optional[bool],
) -> None:
    """Add optional tls.* knobs to a config dict, omitting any left as None."""
    if ciphersuites is not None:
        tls["ciphersuites"] = ciphersuites
    if socket_offload is not None:
        tls["socket_offload"] = socket_offload
    if kernel_offload is not None:
        tls["kernel_offload"] = kernel_offload


def build_server_config(*, use_tls: bool, window: Optional[int] = None, max_frame_size: Optional[int] = None, ciphersuites: Optional[str] = None, socket_offload: Optional[bool] = None, kernel_offload: Optional[bool] = None) -> Dict[str, object]:
    mux: Dict[str, object] = {
        "tcp": {
            "notsent_lowat": 0,
        }
    }
    if window is not None:
        mux["stream_window"] = window
        mux["session_window"] = window
    if max_frame_size is not None:
        mux["max_frame_size"] = max_frame_size
    config: Dict[str, object] = {
        "api_listen": "127.0.0.1:%d" % SERVER_API_PORT,
        "mux_listen": "127.0.0.1:%d" % MUX_TLS_PORT,
        "connect": "127.0.0.1:%d" % IPERF_PORT,
        "identity": {
            "claim": "server",
        },
        "mux": mux,
        "loglevel": 4,
    }
    if use_tls:
        tls: Dict[str, object] = {
            "cert": "@server-cert.pem",
            "key": "@server-key.pem",
            "authcerts": ["@client-cert.pem"],
        }
        apply_tls_options(tls, ciphersuites, socket_offload, kernel_offload)
        config["tls"] = tls
    return config


def build_client_config(*, use_tls: bool, tunnels: int = 1, window: Optional[int] = None, max_frame_size: Optional[int] = None, ciphersuites: Optional[str] = None, socket_offload: Optional[bool] = None, kernel_offload: Optional[bool] = None) -> Dict[str, object]:
    mux: Dict[str, object] = {
        "tcp": {
            "notsent_lowat": 0,
        }
    }
    if window is not None:
        mux["stream_window"] = window
        mux["session_window"] = window
    if max_frame_size is not None:
        mux["max_frame_size"] = max_frame_size
    config: Dict[str, object] = {
        "api_listen": "127.0.0.1:%d" % CLIENT_API_PORT,
        "connect": "127.0.0.1:%d" % IPERF_PORT,
        "identity": {
            "claim": "client",
            "mux_connect": ["127.0.0.1:%d" % MUX_TLS_PORT] * tunnels,
            "listen": {"server": "127.0.0.1:%d" % FORWARD_PORT},
        },
        "mux": mux,
        "loglevel": 4,
    }
    if use_tls:
        tls: Dict[str, object] = {
            "cert": "@client-cert.pem",
            "key": "@client-key.pem",
            "authcerts": ["@server-cert.pem"],
        }
        apply_tls_options(tls, ciphersuites, socket_offload, kernel_offload)
        config["tls"] = tls
    return config


def write_config(path: Path, payload: Dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


def ensure_certificates(runtime_dir: Path) -> None:
    # Always the same builtin RSA-4096 pair ctest's tlsutil_test.c fixture
    # uses, for both peers via mutual pinning: --gencerts would both spawn the
    # binary just to key-generate on every fresh runtime_dir, and is
    # OpenSSL-only (GENCERTS_SOURCES is empty for mbedTLS/no-TLS builds), so a
    # backend-agnostic benchmark needs a backend-agnostic certificate anyway.
    # Skip only a complete set: a key left missing by an interrupted write
    # would otherwise never be regenerated.
    if all((runtime_dir / ("%s-%s.pem" % (role, kind))).exists()
           for role in ("server", "client") for kind in ("cert", "key")):
        return
    for role in ("server", "client"):
        (runtime_dir / ("%s-cert.pem" % role)).write_text(
            BUILTIN_CERT_PEM, encoding="utf-8")
        (runtime_dir / ("%s-key.pem" % role)).write_text(
            BUILTIN_KEY_PEM, encoding="utf-8")


def prepare_runtime_assets(
        runtime_dir: Path,
        *,
        use_tls: bool,
        tunnels: int = 1,
        window: Optional[int] = None,
        max_frame_size: Optional[int] = None,
        ciphersuites: Optional[str] = None,
        socket_offload: Optional[bool] = None,
        kernel_offload: Optional[bool] = None,
    h2mux: bool = False,
) -> tuple[Path, Path]:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    if use_tls:
        ensure_certificates(runtime_dir)
    server_config_path = runtime_dir / "server.json"
    client_config_path = runtime_dir / "client.json"
    write_config(server_config_path, build_server_config(use_tls=use_tls, window=window, max_frame_size=max_frame_size,
                 ciphersuites=ciphersuites, socket_offload=socket_offload, kernel_offload=kernel_offload))
    write_config(client_config_path, build_client_config(use_tls=use_tls, tunnels=tunnels, window=window,
                 max_frame_size=max_frame_size, ciphersuites=ciphersuites, socket_offload=socket_offload, kernel_offload=kernel_offload))
    if h2mux:
        for path in (server_config_path, client_config_path):
            config = json.loads(path.read_text())
            config["type"] = "application/x-tlswrapper-config; version=4"
            config["mux_protocol"] = "h2mux"
            if "tls" in config:
                config["tls"]["sni"] = "test.example"
            # h2mux's Go TLS 1.3 negotiates AES-128-GCM on this AES-capable host;
            # OpenSSL ciphersuite/record-offload names are not Go config fields.
            config["mux"].pop("tcp", None)
            for key in ("ciphersuites", "socket_offload", "kernel_offload"):
                config.get("tls", {}).pop(key, None)
            write_config(path, config)
    return server_config_path, client_config_path


def terminate_process(
        proc: subprocess.Popen[str],
        name: str,
        *,
        shutdown_budget: ProcessShutdownBudget,
) -> None:
    if proc.poll() is not None:
        return
    log("stopping %s [pid:%d]" % (name, proc.pid))
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=shutdown_budget.sigint_wait_seconds)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=shutdown_budget.terminate_wait_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=max(2.0, shutdown_budget.terminate_wait_seconds))


def cleanup_services(
        services: Sequence[tuple[Optional[subprocess.Popen[str]], str]],
        handles: Sequence[Optional[TextIO]],
        *,
        shutdown_budget: ProcessShutdownBudget,
        preserve_error: bool,
) -> None:
    errors: List[tuple[str, Exception]] = []
    for proc, name in services:
        if proc is not None:
            try:
                terminate_process(proc, name, shutdown_budget=shutdown_budget)
            except Exception as error:
                errors.append((name, error))
    for handle in handles:
        if handle is not None:
            try:
                handle.close()
            except Exception as error:
                errors.append(("log handle", error))
    for name, error in errors:
        log("cleanup failed for %s: %s" % (name, error))
    if errors and not preserve_error:
        raise errors[0][1]


def _log_lines(stream: TextIO) -> Iterator[str]:
    """Stream splitlines-compatible lines, retaining only an incomplete line."""
    parts: List[str] = []
    # TextIO normalizes CR and CRLF; splitlines also recognizes these separators.
    endings = "\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"
    for chunk in iter(lambda: stream.read(65536), ""):
        for line in chunk.splitlines(keepends=True):
            parts.append(line)
            if line[-1] in endings:
                yield "".join(parts)
                parts.clear()
    if parts:
        yield "".join(parts)


def _log_tail(log_path: Optional[Path], n: int = 20) -> str:
    if log_path is None or not log_path.exists():
        return "(no log)"
    try:
        with log_path.open(encoding="utf-8", errors="replace") as stream:
            lines = deque((line.rstrip() for line in _log_lines(stream)
                           if line.strip()), maxlen=n if n > 0 else None)
    except OSError:
        return "(log unreadable)"
    return "\n".join(lines if n >= 0 else list(lines)[-n:]) or "(log empty)"


def ensure_process_alive(
        proc: subprocess.Popen[str], name: str,
        log_path: Optional[Path] = None) -> None:
    """Raise SystemExit if *proc* has already exited. Without this a leftover
    listener holding a port makes the new daemon bind-fail and exit while
    iperf3 connects to the stale process, so the report measures a different
    binary -- betrayed only by a 0% CPU / 0 B RSS sample of the dead pid."""
    ret = proc.poll()
    if ret is None:
        return
    raise SystemExit(
        "%s exited early (status %d); refusing to record a benchmark that may "
        "be measuring a different process. Last log lines:\n%s"
        % (name, ret, _log_tail(log_path)))


def socket_inodes(pid: int) -> Set[str]:
    """Return the inode numbers of the sockets pid holds open."""
    fd_dir = "/proc/%d/fd" % pid
    try:
        names = os.listdir(fd_dir)
    except OSError:
        return set()
    inodes: Set[str] = set()
    for name in names:
        try:
            target = os.readlink(os.path.join(fd_dir, name))
        except OSError:
            continue  # closed between listdir and readlink
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[len("socket:["):-1])
    return inodes


def listening_ports(pid: int) -> Set[int]:
    """Return the TCP ports pid itself holds in LISTEN state, IPv4 and IPv6.

    Matching the listener's socket inode against pid's own descriptors, rather
    than probing the port, is what tells our daemon apart from a stale one
    left holding the same fixed port."""
    inodes = socket_inodes(pid)
    ports: Set[int] = set()
    if not inodes:
        return ports
    for table in ("tcp", "tcp6"):
        try:
            with open("/proc/%d/net/%s" % (pid, table), "r",
                      encoding="ascii") as handle:
                rows = handle.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            # sl local_address rem_address st ... uid timeout inode
            if len(fields) < 10 or fields[3] != TCP_LISTEN_STATE:
                continue
            if fields[9] not in inodes:
                continue
            _addr, _sep, port_hex = fields[1].rpartition(":")
            try:
                ports.add(int(port_hex, 16))
            except ValueError:
                continue
    return ports


def established_sessions(api_port: int, *,
                         deadline: Optional[float] = None) -> Optional[int]:
    """Return the established mux session count /stats reports, or None while
    the API does not answer with one."""
    timeout = 1.0
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            return None
    try:
        status, text = api_request(api_port, "/stats", timeout=timeout)
    except (OSError, http.client.HTTPException):
        return None
    if status != 200:
        return None
    # "Sessions: <established> / <active> (+<half-open>)"
    field = parse_stats(text).get("Sessions", "")
    try:
        return int(field.split("/", 1)[0])
    except ValueError:
        return None


def readiness_gaps(
        services: Sequence[Service],
        *,
        sessions_from: Service,
        api_port: int,
        tunnels: int,
        deadline: Optional[float] = None,
) -> List[str]:
    """Return what still keeps the services from being benchmarked, or an
    empty list once every listener is up and every tunnel is established."""
    for service in services:
        ensure_process_alive(service.proc, service.name, service.log_path)
    gaps: List[str] = []
    for service in services:
        held = listening_ports(service.proc.pid)
        missing = [port for port in service.listen_ports if port not in held]
        if missing:
            gaps.append("%s is not listening on port %s" % (
                service.name, ", ".join(str(port) for port in missing)))
    if gaps:
        # Until the client owns api_port, /stats may be a stale daemon's.
        return gaps
    sessions = established_sessions(api_port, deadline=deadline)
    if sessions is None:
        gaps.append("%s /stats reports no session count" %
                    sessions_from.name)
    elif sessions < tunnels:
        gaps.append("%s has %d of %d tunnel sessions established" % (
            sessions_from.name, sessions, tunnels))
    return gaps


def wait_until_ready(
        services: Sequence[Service],
        *,
        sessions_from: Service,
        api_port: int,
        tunnels: int,
        timeout_seconds: float,
) -> None:
    """Poll until every service listens and every tunnel is established.

    The client spreads iperf3's connections over the sessions it has
    established, so a tunnel still on a reconnect backoff rung would silently
    shrink the tunnel count the report states. Raise SystemExit on a daemon
    exit or once timeout_seconds pass without readiness."""
    deadline = time.monotonic() + timeout_seconds
    gaps: List[str] = []
    while time.monotonic() < deadline:
        gaps = readiness_gaps(services, sessions_from=sessions_from,
                              api_port=api_port, tunnels=tunnels,
                              deadline=deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if not gaps:
            return
        time.sleep(min(READY_POLL_INTERVAL, remaining))
    raise SystemExit(
        "services not ready after %.1f s: %s; refusing to record a "
        "benchmark over fewer tunnels than requested. Last %s log "
        "lines:\n%s" % (timeout_seconds,
                        "; ".join(gaps) or "readiness deadline expired",
                        sessions_from.name,
                        _log_tail(sessions_from.log_path)))


def open_log(path: Path) -> TextIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def build_scenario_commands(
        iperf3: str,
        scenario: Scenario,
        duration: int,
        parallel: int,
        warmup: int = 0,
) -> List[List[str]]:
    base_command = [
        iperf3,
        "-c",
        "127.0.0.1",
        "-p",
        str(FORWARD_PORT),
        "-t",
        str(duration + warmup),
        "--json",
    ]
    if warmup:
        base_command.append("--get-server-output")
    if scenario.name == "uplink":
        return [base_command]
    if scenario.name == "downlink":
        return [base_command + ["-R"]]
    if scenario.name == "bidir":
        return [base_command + ["--bidir"]]
    if scenario.name == "parallel":
        return [base_command + ["--bidir", "-P", str(parallel)]]
    raise SystemExit("unsupported scenario: %s" % scenario.name)


def run_json_command(
        command: Sequence[str],
        *,
        cwd: Path,
        log_path: Path,
        stderr_path: Path,
        timeout_seconds: float,
) -> Dict[str, object]:
    log("+ %s" % quote_command(command))
    try:
        proc = subprocess.run(
            list(command),
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
        output = output_text(proc.stdout)
        stderr_output = output_text(proc.stderr)
    except subprocess.TimeoutExpired as exc:
        output = output_text(exc.stdout)
        stderr_output = output_text(exc.stderr)
        log_path.write_text(output, encoding="utf-8")
        stderr_path.write_text(stderr_output, encoding="utf-8")
        raise SystemExit(
            "benchmark command timed out after %.1f seconds: %s"
            % (timeout_seconds, quote_command(command))
        )
    log_path.write_text(output, encoding="utf-8")
    stderr_path.write_text(stderr_output, encoding="utf-8")
    warning_line = find_iperf_warning_line(output)
    if warning_line is None:
        warning_line = find_iperf_warning_line(stderr_output)
    if warning_line is not None:
        raise SystemExit(
            "benchmark command emitted iperf3 warning in %s: %s"
            % (log_path, warning_line)
        )
    stderr_lines = [line.strip() for line in stderr_output.splitlines()
                    if line.strip()]
    if stderr_lines:
        raise SystemExit(
            "benchmark command emitted stderr in %s: %s"
            % (stderr_path, stderr_lines[0])
        )
    if proc.returncode != 0:
        raise SystemExit(
            "benchmark command failed with status %d: %s"
            % (proc.returncode, quote_command(command))
        )
    json_start = output.find("{")
    if json_start < 0:
        raise SystemExit("invalid iperf3 JSON output in %s: missing JSON object"
                         % log_path)
    prefix = output[:json_start].strip()
    if prefix:
        raise SystemExit(
            "invalid iperf3 JSON output in %s: unexpected text before JSON: %s"
            % (log_path, prefix.splitlines()[0])
        )
    try:
        report, end = json.JSONDecoder().raw_decode(output[json_start:])
    except json.JSONDecodeError as exc:
        raise SystemExit("invalid iperf3 JSON output in %s: %s" %
                         (log_path, exc))
    suffix = output[json_start + end:].strip()
    if suffix:
        raise SystemExit(
            "invalid iperf3 JSON output in %s: unexpected text after JSON: %s"
            % (log_path, suffix.splitlines()[0])
        )
    return report


def parse_summary_bits(summary: object) -> float:
    if not isinstance(summary, dict):
        return 0.0
    value = summary.get("bits_per_second")
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def parse_summary_seconds(summary: object) -> float:
    if not isinstance(summary, dict):
        return 0.0
    value = summary.get("seconds")
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def extract_bidir_throughput(end: Dict[str, object]) -> tuple[float, float, float]:
    streams = end.get("streams")
    if not isinstance(streams, list):
        raise SystemExit("iperf3 bidirectional report missing end.streams")

    sent = 0.0
    received = 0.0
    seconds = 0.0
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        sender = stream.get("sender")
        if isinstance(sender, dict):
            if sender.get("sender") is True:
                sent += parse_summary_bits(sender)
                seconds = max(seconds, parse_summary_seconds(sender))
        receiver = stream.get("receiver")
        if isinstance(receiver, dict):
            if receiver.get("sender") is False:
                received += parse_summary_bits(receiver)
                seconds = max(seconds, parse_summary_seconds(receiver))
    return sent, received, seconds


def receiver_series(report: Dict[str, object], warmup: int) -> List[tuple[float, float, float]]:
    """Receiver goodput intervals, with the deterministic warmup boundary removed."""
    values = []
    for interval in report.get("intervals", []):
        summary = interval.get("sum", {})
        start, end = float(summary["start"]), float(summary["end"])
        seconds = float(summary["seconds"])
        if not all(math.isfinite(value) for value in (start, end, seconds)) or seconds <= 0:
            raise ValueError("invalid iperf interval timestamp")
        if abs((end - start) - seconds) > 0.01:
            raise ValueError("inconsistent iperf interval timing; cannot reconstruct measurement")
        if start < warmup - 0.01:
            continue
        streams = [stream for stream in interval.get("streams", []) if stream.get("sender") is False]
        if streams:
            count = sum(int(stream["bytes"]) for stream in streams)
            values.append((start, end, count * 8 / seconds))
    return values


def received_bytes(report: Dict[str, object]) -> int:
    """Whole-command receiver bytes, including warmup, matching CPU accounting."""
    remote = report.get("server_output_json")
    endpoints = [report, remote] if isinstance(remote, dict) else [report]
    return sum(int(stream.get("bytes", 0)) for endpoint in endpoints
               for interval in endpoint.get("intervals", [])
               for stream in interval.get("streams", [])
               if isinstance(stream, dict) and (remote is None or stream.get("sender") is False))


def measurement_view(report: Dict[str, object], scenario: Scenario, warmup: int) -> Dict[str, object]:
    """Delivered traffic, not sender buffering, over a common measured window.

    iperf runs continuously: using --omit can corrupt reset-boundary intervals
    on 3.16. Full raw client/server JSON is retained. Receiver one-second series
    are aligned by relative test time; fractional common-window edges use the
    recorded interval's mean rate. No throughput-based observation is removed.
    """
    if not warmup:
        return report  # Preserve the standalone legacy end-summary mode.
    local = receiver_series(report, warmup)
    remote_report = report.get("server_output_json")
    if not isinstance(remote_report, dict):
        raise ValueError("iperf server receiver intervals are missing")
    remote = receiver_series(remote_report, warmup)
    sources = ([remote] if scenario.name == "uplink" else [local] if scenario.name == "downlink"
               else [remote, local])
    if any(not source for source in sources):
        raise ValueError("no complete receiver measurement after warmup")
    start = max(source[0][0] for source in sources)
    end = min(source[-1][1] for source in sources)
    if end <= start:
        raise ValueError("receiver measurement windows do not overlap")

    def integral(source: Sequence[tuple[float, float, float]], left: float, right: float) -> float:
        covered = sum(max(0, min(b, right) - max(a, left)) for a, b, _ in source)
        if covered < right - left - 0.01:
            raise ValueError("receiver intervals contain an uncovered time gap")
        return sum(rate * max(0, min(b, right) - max(a, left)) for a, b, rate in source)

    selected, weights = [], []
    cursor = start
    while cursor < end - 1e-9:
        stop = min(cursor + 1, end)
        seconds = stop - cursor
        bits = sum(integral(source, cursor, stop) for source in sources)
        selected.append({"sum": {"start": cursor, "end": stop, "seconds": seconds},
                         "streams": [{"bits_per_second": bits / seconds}]})
        weights.append(seconds)
        cursor = stop
    seconds = end - start
    sent = integral(remote, start, end) / seconds if remote else 0
    received = integral(local, start, end) / seconds if local else 0
    result = dict(report)
    result["intervals"] = selected
    result["_interval_weights"] = weights
    result["_measurement_totals"] = (sent + received, sent, received, seconds)
    return result


def extract_total_throughput(report: Dict[str, object], scenario: Scenario) -> tuple[float, float, float, float]:
    if "_measurement_totals" in report:
        return tuple(report["_measurement_totals"])
    end = report.get("end")
    if not isinstance(end, dict):
        raise SystemExit(
            "iperf3 report missing end summary for %s" % scenario.name)
    if scenario.name in {"bidir", "parallel"}:
        sent, received, seconds = extract_bidir_throughput(end)
        return sent + received, sent, received, seconds

    sent = parse_summary_bits(end.get("sum_sent"))
    received = parse_summary_bits(end.get("sum_received"))
    seconds = 0.0
    for candidate in (end.get("sum_received"), end.get("sum_sent")):
        if isinstance(candidate, dict):
            value = candidate.get("seconds")
            if isinstance(value, (int, float)):
                seconds = float(value)
                break
    total = max(sent, received)
    return total, sent, received, seconds


def combine_throughput(
        reports: Sequence[Dict[str, object]], scenario: Scenario
) -> tuple[float, float, float, float]:
    total = 0.0
    sent = 0.0
    received = 0.0
    seconds = 0.0
    for report in reports:
        report_total, report_sent, report_received, report_seconds = extract_total_throughput(
            report, scenario
        )
        total += report_total
        sent += report_sent
        received += report_received
        seconds = max(seconds, report_seconds)
    return total, sent, received, seconds


def extract_interval_throughputs(report: Dict[str, object]) -> List[float]:
    """Return per-interval total bits_per_second values from an iperf3 JSON report."""
    intervals = report.get("intervals", [])
    if not isinstance(intervals, list):
        return []
    values: List[float] = []
    for interval in intervals:
        if not isinstance(interval, dict):
            continue
        if interval.get("sum", {}).get("omitted") is True:
            continue
        total = 0.0
        # Sum the per-stream values, which for --bidir/-P cover both
        # directions. iperf3's interval["sum"] covers only one direction, so
        # preferring it (and summing streams only when it was zero) understated
        # bidir/parallel throughput ~8x versus the Total Throughput column and
        # made the StdDev / Per-Second Throughput table measure a different
        # quantity. sum is a fallback only when no per-stream breakdown exists.
        streams = interval.get("streams")
        if isinstance(streams, list) and streams:
            for stream in streams:
                if isinstance(stream, dict) and not stream.get("omitted", False):
                    bps = stream.get("bits_per_second")
                    if isinstance(bps, (int, float)):
                        total += float(bps)
        else:
            sum_obj = interval.get("sum")
            if isinstance(sum_obj, dict):
                bps = sum_obj.get("bits_per_second")
                if isinstance(bps, (int, float)):
                    total = float(bps)
        values.append(total)
    return values


def compute_stddev(values: Sequence[float]) -> float:
    """Return sample standard deviation of the given values."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def compute_combined_stddev(
        reports: Sequence[Dict[str, object]],
) -> float:
    """Compute stddev of per-interval throughput across all reports."""
    all_intervals = collect_interval_throughputs(reports)
    if reports and all("_interval_weights" in report for report in reports):
        weights = [weight for report in reports for weight in report["_interval_weights"]]
        total = sum(weights)
        if len(weights) != len(all_intervals):
            raise ValueError("interval weights do not match measured samples")
        denominator = total - sum(weight * weight for weight in weights) / total
        if denominator <= 0:
            return 0.0
        mean = sum(value * weight for value, weight in zip(all_intervals, weights)) / total
        return math.sqrt(sum(weight * (value - mean) ** 2 for value, weight in zip(all_intervals, weights)) / denominator)
    return compute_stddev(all_intervals)


def collect_interval_throughputs(
        reports: Sequence[Dict[str, object]],
) -> List[float]:
    """Gather per-interval throughput values across all reports."""
    all_intervals: List[float] = []
    for report in reports:
        all_intervals.extend(extract_interval_throughputs(report))
    return all_intervals


def format_bits_per_second(bits_per_second: float) -> str:
    units = (
            ("bit/s", 1.0),
            ("Kbit/s", 1_000.0),
            ("Mbit/s", 1_000_000.0),
            ("Gbit/s", 1_000_000_000.0),
    )
    for index in range(len(units) - 1, -1, -1):
        unit, scale = units[index]
        if bits_per_second >= scale or scale == 1.0:
            return "%.2f %s" % (bits_per_second / scale, unit)
    return "0.00 bit/s"


def format_bytes(num_bytes: int) -> str:
    units = (
            ("B", 1.0),
            ("KiB", 1024.0),
            ("MiB", 1024.0 ** 2),
            ("GiB", 1024.0 ** 3),
    )
    for index in range(len(units) - 1, -1, -1):
        unit, scale = units[index]
        if num_bytes >= scale or scale == 1.0:
            return "%.2f %s" % (num_bytes / scale, unit)
    return "0.00 B"


def maybe_reexec_in_netns(netem_delay: Optional[str]) -> None:
    if not netem_delay or os.environ.get(BENCH_NETNS_ENV) == "1":
        return
    command = [
        "unshare",
        "--user",
        "--net",
        "--map-root-user",
        "--",
        "env",
        "%s=1" % BENCH_NETNS_ENV,
        *sys.argv,
    ]
    os.execvp(command[0], command)


def configure_netem(netem_delay: Optional[str]) -> None:
    if not netem_delay:
        return
    run_command(["ip", "link", "set", "lo", "up"], cwd=ROOT)
    run_command(
        [
            "tc",
            "qdisc",
            "add",
            "dev",
            "lo",
            "root",
            "handle",
            "1:",
            "prio",
            "bands",
            "2",
            "priomap",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
        ],
        cwd=ROOT,
    )
    run_command(
        [
            "tc",
            "qdisc",
            "add",
            "dev",
            "lo",
            "parent",
            "1:1",
            "handle",
            "10:",
            "netem",
            "delay",
            netem_delay,
        ],
        cwd=ROOT,
    )
    for field, port in (("dport", str(MUX_TLS_PORT)), ("sport", str(MUX_TLS_PORT))):
        run_command(
            [
                "tc",
                "filter",
                "add",
                "dev",
                "lo",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                "1",
                "u32",
                "match",
                "ip",
                "protocol",
                "6",
                "0xff",
                "match",
                "ip",
                field,
                port,
                "0xffff",
                "flowid",
                "1:1",
            ],
            cwd=ROOT,
        )


def render_markdown_report(
        results: Sequence[ScenarioResult],
        *,
        output_path: Path,
        binary_path: Path,
        duration: int,
        parallel: int,
        netem_delay: Optional[str],
    use_tls: bool,
    tunnels: int,
    window: Optional[int],
    max_frame_size: Optional[int],
    command_timeout_seconds: float,
    shutdown_budget: ProcessShutdownBudget,
    ready_timeout_seconds: float,
    ciphersuites: Optional[str] = None,
    socket_offload: Optional[bool] = None,
    kernel_offload: Optional[bool] = None,
) -> str:
    output_dir = output_path.parent
    lines = [
        "# Benchmark Summary",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Project root | %s |" % relative_path(ROOT),
        "| Binary | %s |" % relative_path(binary_path),
        "| Duration per run | %d s |" % duration,
        "| Parallel streams | %d |" % parallel,
        "| TLS | %s |" % ("on" if use_tls else "off"),
        "| TLS ciphersuites | %s |" % (ciphersuites or "default"),
        "| TLS socket_offload | %s |"
        % ("default" if socket_offload is None else ("on" if socket_offload else "off")),
        "| TLS kernel_offload | %s |"
        % ("default" if kernel_offload is None else ("on" if kernel_offload else "off")),
        "| Tunnels | %d |" % tunnels,
        "| Readiness gate | every tunnel established before each scenario, "
        "timeout %.1f s |" % ready_timeout_seconds,
        "| Stream/session window | %s |" % (str(window)
                                            if window is not None else "default"),
        "| Max frame size | %s |" % (
            str(max_frame_size) if max_frame_size is not None else "default"),
        "| Netem delay | %s |" % (netem_delay or "off"),
        "| Benchmark timeout | %.1f s per scenario |" % command_timeout_seconds,
        "| Shutdown grace | SIGINT %.1f s, terminate %.1f s |"
        % (
            shutdown_budget.sigint_wait_seconds,
            shutdown_budget.terminate_wait_seconds,
        ),
        "| Bidirectional method | iperf3 --bidir single run |",
        "",
        "## Throughput",
        "",
        "| Scenario | Total Throughput | Sent | Received | StdDev | Duration | Logs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for result in results:
        log_parts: List[str] = []
        for path in result.log_paths:
            log_parts.append(
                "[json:%s](%s)"
                % (
                    relative_path(path),
                    os.path.relpath(path, start=output_dir).replace(
                        os.sep, "/"
                    ),
                )
            )
        for path in result.stderr_paths:
            log_parts.append(
                "[stderr:%s](%s)"
                % (
                    relative_path(path),
                    os.path.relpath(path, start=output_dir).replace(
                        os.sep, "/"
                    ),
                )
            )
        log_text = ", ".join(log_parts)
        lines.append(
            "| %s | %s | %s | %s | %s | %.2f s | %s |"
            % (
                result.scenario.label,
                format_bits_per_second(result.total_bits_per_second),
                format_bits_per_second(result.sent_bits_per_second),
                format_bits_per_second(result.received_bits_per_second),
                format_bits_per_second(result.stddev_bits_per_second),
                result.duration_seconds,
                log_text,
            )
        )
    lines.extend(["", "## Commands", ""])
    for result in results:
        lines.append("- %s: `%s`" %
                     (result.scenario.label, " ; ".join(result.command_texts)))

    lines.extend(["", "## Resource Usage", ""])
    lines.append(
        "CPU is average utilisation over the scenario "
        "(100%% = one core); Real is the scenario wall-clock, User/Sys the "
        "process CPU time (utime/stime from /proc/<pid>/stat, all threads); "
        "RSS is the peak resident set size sampled every %.0f ms from /proc."
        % (RESOURCE_SAMPLE_INTERVAL * 1000.0)
    )
    lines.append("")
    lines.append("| Scenario | Process | CPU | Real | User | Sys | Peak RSS |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for result in results:
        for usage in result.resource_usage:
            lines.append(
                "| %s | %s | %.1f%% | %.2f s | %.2f s | %.2f s | %s |"
                % (
                    result.scenario.label,
                    usage.name,
                    usage.cpu_percent,
                    usage.real_seconds,
                    usage.user_seconds,
                    usage.sys_seconds,
                    format_bytes(usage.peak_rss_bytes),
                )
            )

    lines.extend(["", "## Per-Second Throughput", ""])
    for result in results:
        lines.append("### %s" % result.scenario.label)
        lines.append("")
        if not result.interval_throughputs:
            lines.append("*(no interval data)*")
        else:
            lines.append("| Second | Throughput |")
            lines.append("| ---: | ---: |")
            for index, bps in enumerate(result.interval_throughputs, start=1):
                lines.append("| %d | %s |" %
                             (index, format_bits_per_second(bps)))
        lines.append("")
    return "\n".join(lines) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the multiplexd benchmark suite and write build/bench.md."
    )
    parser.add_argument(
        "--build-dir",
        default="build",
        help="build directory containing bin/multiplexd (default: build)",
    )
    parser.add_argument(
        "--output",
        help="Markdown output path (default: build/bench.md)",
    )
    parser.add_argument(
        "-t",
        "--duration",
        type=int,
        default=10,
        help="iperf3 test duration in seconds (default: 10)",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=10,
        help="parallel stream count for the parallel scenario (default: 10)",
    )
    parser.add_argument(
        "--ready-timeout",
        type=float,
        default=30.0,
        help="seconds to wait for the services to listen and every tunnel to "
             "establish, before the first scenario and again before each "
             "one (default: 30)",
    )
    parser.add_argument(
        "--startup-wait",
        type=float,
        default=0.0,
        help="extra seconds to wait once the services are ready, before the "
             "first scenario (default: 0)",
    )
    parser.add_argument(
        "--no-tls",
        action="store_false",
        default=True,
        dest="tls",
        help="disable TLS for the mux transport (default: on)",
    )
    parser.add_argument(
        "--tunnels",
        type=int,
        default=1,
        help="number of parallel mux tunnels (default: 1)",
    )
    parser.add_argument(
        "--ciphersuites",
        help="pin tls.ciphersuites, for example TLS_AES_128_GCM_SHA256 "
             "(default: omit from config; OpenSSL negotiates AES-256-GCM)",
    )
    parser.add_argument(
        "--socket-offload",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="set tls.socket_offload; pass --socket-offload to let the TLS "
             "library own the socket (default: omit from config, daemon default "
             "is off -> in-memory record batching)",
    )
    parser.add_argument(
        "--kernel-offload",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="set tls.kernel_offload / KTLS (default: omit from config; "
             "daemon default is on once socket_offload is also on, off "
             "otherwise -- pass --no-kernel-offload to force it off)",
    )
    parser.add_argument(
        "-w",
        "--window",
        type=int,
        help="set both stream_window and session_window (default: omit from config)",
    )
    parser.add_argument(
        "--max-frame-size",
        type=int,
        help="set mux.max_frame_size in bytes, including the 8-byte header "
             "(default: omit from config, daemon uses 16 KiB frames)",
    )
    parser.add_argument(
        "--netem-delay",
        help="optional tc netem delay applied to the mux transport, for example 100ms",
    )
    parser.add_argument("--iperf3", default="iperf3",
                        help="iperf3 executable name")
    parser.add_argument("--runtime-dir", help="separate configs, logs and reports from the build")
    parser.add_argument("--h2mux-binary", help="measure h2mux through the same harness")
    parser.add_argument("--scenario", choices=[s.name for s in SCENARIOS])
    parser.add_argument("--warmup", type=int, default=0, help="initial seconds excluded by the harness without resetting iperf counters")
    parser.add_argument("--cpus", help="daemon server,daemon client,iperf server,iperf client CPUs")
    parser.add_argument("--report-json", help="machine-readable measurement and diagnostic data")
    args = parser.parse_args(argv)
    if args.duration <= 0 or args.warmup < 0:
        parser.error("duration must be positive and warmup nonnegative")
    if args.h2mux_binary and (args.socket_offload is not None or args.kernel_offload is not None
                             or args.max_frame_size is not None):
        parser.error("OpenSSL offload and custom frame controls cannot be applied to h2mux")
    if args.h2mux_binary and args.ciphersuites not in (None, "TLS_AES_128_GCM_SHA256"):
        parser.error("h2mux comparison supports only its default TLS 1.3 AES-128-GCM suite")
    args.cpu_set = parse_cpu_set(args.cpus) if args.cpus else None
    if args.tunnels < 1:
        parser.error("--tunnels must be at least 1")
    if not args.ready_timeout > 0:
        parser.error("--ready-timeout must be positive")
    if not args.startup_wait >= 0:
        parser.error("--startup-wait must not be negative")
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_project_root(ROOT)
    maybe_reexec_in_netns(args.netem_delay)
    iperf3 = ensure_tool(args.iperf3)
    build_dir = resolve_path(ROOT, args.build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    binary_path = (resolve_path(ROOT, args.h2mux_binary) if args.h2mux_binary
                   else build_dir / "bin" / "multiplexd")
    runtime_dir = resolve_path(ROOT, args.runtime_dir) if args.runtime_dir else build_dir
    runtime_dir.mkdir(parents=True, exist_ok=True)
    implementation = "h2mux" if args.h2mux_binary else "multiplexd"
    selected_scenarios = [s for s in SCENARIOS if not args.scenario or s.name == args.scenario]
    if args.h2mux_binary:
        os.environ["GOMAXPROCS"] = "1"
    if args.cpu_set:
        isolate_coordinator(args.cpu_set)
    def pinned(command: Sequence[str], role: int) -> List[str]:
        return pin_command(command, args.cpu_set[role] if args.cpu_set else None)

    if not binary_path.exists():
        raise SystemExit("expected binary not found: %s" % binary_path)
    if args.tls and not args.h2mux_binary:
        has_tls = build_has_tls(build_dir)
        if has_tls is None:
            # config.h unreadable; fall back to the (less reliable) cache value.
            build_cache = parse_cmake_cache(build_dir / "CMakeCache.txt")
            has_tls = build_cache.get("USE_TLS_LIBRARY") != "none"
        if not has_tls:
            raise SystemExit(
                "TLS requested, but %s was configured without TLS "
                "support (WITH_TLS=0)" % build_dir
            )
    server_config_path, client_config_path = prepare_runtime_assets(
        runtime_dir,
        use_tls=args.tls,
        tunnels=args.tunnels,
        window=args.window,
        max_frame_size=args.max_frame_size,
        ciphersuites=args.ciphersuites,
        socket_offload=args.socket_offload,
        kernel_offload=args.kernel_offload,
        h2mux=bool(args.h2mux_binary),
    )
    configure_netem(args.netem_delay)
    command_timeout_seconds = compute_command_timeout_seconds(
        args.duration + args.warmup,
        args.startup_wait,
    )
    shutdown_budget = compute_process_shutdown_budget(
        args.duration + args.warmup,
        args.startup_wait,
        scenario_count=len(selected_scenarios),
    )

    output_path = resolve_path(
        ROOT, args.output) if args.output else DEFAULT_OUTPUT

    results: List[ScenarioResult] = []
    server_proc: Optional[subprocess.Popen[str]] = None
    client_proc: Optional[subprocess.Popen[str]] = None
    iperf_server_proc: Optional[subprocess.Popen[str]] = None
    server_log: Optional[TextIO] = None
    client_log: Optional[TextIO] = None
    iperf_server_log: Optional[TextIO] = None

    pressure_start = read_pressure()
    measurement_started = time.monotonic()
    transport_diagnostics = None
    work_finished = False
    try:
        server_log = open_log(runtime_dir / "multiplexd-server.log")
        client_log = open_log(runtime_dir / "multiplexd-client.log")
        iperf_server_log = open_log(runtime_dir / "iperf3-server.log")

        iperf_server_command = [iperf3, "-s", "-p", str(IPERF_PORT)]
        if args.warmup:
            iperf_server_command.append("--json")
        log("+ %s" % quote_command(iperf_server_command))
        iperf_server_proc = subprocess.Popen(
            pinned(iperf_server_command, 2),
            cwd=str(runtime_dir),
            stdout=iperf_server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        log("+ %s" %
            quote_command([str(binary_path), "-c", str(server_config_path)]))
        server_proc = subprocess.Popen(
            pinned([str(binary_path), "-c", str(server_config_path)], 0),
            cwd=str(runtime_dir),
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        log("+ %s" %
            quote_command([str(binary_path), "-c", str(client_config_path)]))
        client_proc = subprocess.Popen(
            pinned([str(binary_path), "-c", str(client_config_path)], 1),
            cwd=str(runtime_dir),
            stdout=client_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        client = Service(client_proc, implementation + " client",
                         runtime_dir / "multiplexd-client.log",
                         (FORWARD_PORT, CLIENT_API_PORT))
        services = (
            Service(iperf_server_proc, "iperf3 server",
                    runtime_dir / "iperf3-server.log", (IPERF_PORT,)),
            Service(server_proc, implementation + " server",
                    runtime_dir / "multiplexd-server.log",
                    (MUX_TLS_PORT, SERVER_API_PORT)),
            client,
        )

        def ready() -> None:
            wait_until_ready(services, sessions_from=client,
                             api_port=CLIENT_API_PORT, tunnels=args.tunnels,
                             timeout_seconds=args.ready_timeout)

        ready()
        if args.startup_wait > 0:
            time.sleep(args.startup_wait)

        for scenario in selected_scenarios:
            # Re-check before recording: a daemon that crashed mid-run would
            # otherwise be sampled as a dead pid (0% CPU / 0 B RSS), and a
            # tunnel that dropped would carry this scenario on fewer sessions.
            ready()
            commands = build_scenario_commands(
                iperf3, scenario, args.duration, args.parallel, args.warmup)
            commands = [pinned(command, 3) for command in commands]
            log_paths = [
                runtime_dir / ("iperf3-%s-%02d.json" % (scenario.name, index))
                for index in range(1, len(commands) + 1)
            ]
            stderr_paths = [
                runtime_dir / ("iperf3-%s-%02d.stderr" % (scenario.name, index))
                for index in range(1, len(commands) + 1)
            ]
            sampler = ProcSampler(
                [
                    (implementation + " server", server_proc.pid),
                    (implementation + " client", client_proc.pid),
                ]
            )
            sampler.start()
            try:
                if len(commands) == 1:
                    reports = [
                        run_json_command(
                            commands[0],
                            cwd=ROOT,
                            log_path=log_paths[0],
                            stderr_path=stderr_paths[0],
                            timeout_seconds=command_timeout_seconds,
                        )
                    ]
                else:
                    reports = [
                        run_json_command(
                            command,
                            cwd=ROOT,
                            log_path=log_path,
                            stderr_path=stderr_path,
                            timeout_seconds=command_timeout_seconds,
                        )
                        for command, log_path, stderr_path in zip(
                            commands, log_paths, stderr_paths
                        )
                    ]
            finally:
                sampler.stop()
            for service in services:
                ensure_process_alive(service.proc, service.name,
                                     service.log_path)
            resource_usage = sampler.results()
            transferred_bytes = sum(received_bytes(report) for report in reports)
            reports = [measurement_view(report, scenario, args.warmup) for report in reports]
            total, sent, received, seconds = combine_throughput(
                reports, scenario)
            stddev = compute_combined_stddev(reports)
            intervals = collect_interval_throughputs(reports)
            results.append(
                ScenarioResult(
                    scenario=scenario,
                    command_texts=[quote_command(command)
                                   for command in commands],
                    log_paths=log_paths,
                    stderr_paths=stderr_paths,
                    total_bits_per_second=total,
                    sent_bits_per_second=sent,
                    received_bits_per_second=received,
                    stddev_bits_per_second=stddev,
                    interval_throughputs=intervals,
                    duration_seconds=seconds,
                    resource_usage=resource_usage,
                    transferred_bytes=transferred_bytes,
                )
            )
        # Check once more before intentional shutdown and report publication:
        # a daemon may have exited while the final result was assembled.
        for service in services:
            ensure_process_alive(service.proc, service.name, service.log_path)
        if args.report_json and shutil.which("ss"):
            transport_diagnostics = subprocess.run(
                ["ss", "-tin", "( sport = :8443 or dport = :8443 )"],
                capture_output=True, text=True, timeout=5).stdout
        work_finished = True
    finally:
        cleanup_services(
            ((client_proc, implementation + " client"),
             (server_proc, implementation + " server"),
             (iperf_server_proc, "iperf3 server")),
            (iperf_server_log, client_log, server_log),
            shutdown_budget=shutdown_budget,
            preserve_error=not work_finished,
        )

    report = render_markdown_report(
        results,
        output_path=output_path,
        binary_path=binary_path,
        duration=args.duration,
        parallel=args.parallel,
        netem_delay=args.netem_delay,
        use_tls=args.tls,
        tunnels=args.tunnels,
        window=args.window,
        max_frame_size=args.max_frame_size,
        command_timeout_seconds=command_timeout_seconds,
        shutdown_budget=shutdown_budget,
        ready_timeout_seconds=args.ready_timeout,
        ciphersuites=args.ciphersuites,
        socket_offload=args.socket_offload,
        kernel_offload=args.kernel_offload,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if args.warmup:
        report += "\nThroughput is receiver goodput; sent/received name client-to-server/server-to-client directions.\n"
    report += "\nWarmup: %d omitted seconds per scenario. CPU measurements include warmup.\n" % args.warmup
    report += "CPU layout (server,client,iperf server,iperf client): %s.\n" % (args.cpus or "unpinned")
    output_path.write_text(report, encoding="utf-8")
    if args.report_json:
        pressure_end = read_pressure()
        elapsed = time.monotonic() - measurement_started
        payload = {
            "implementation": implementation, "binary": str(binary_path),
            "binary_sha256": file_sha256(binary_path),
            "duration": args.duration, "warmup": args.warmup,
            "cpus": args.cpu_set, "coordinator_cpus": sorted(os.sched_getaffinity(0)), "host": platform.node(), "kernel": platform.release(),
            "elapsed": elapsed,
            "transport": transport_diagnostics,
            "pressure_percent": {key: max(0, pressure_end[key] - value) / (elapsed * 1e4)
                                 for key, value in pressure_start.items() if key in pressure_end},
            "results": [asdict(result) for result in results],
        }
        # Paths need strings for portable, archival JSON; raw iperf files remain
        # adjacent and are never overwritten by another trial.
        resolve_path(ROOT, args.report_json).write_text(json.dumps(payload, default=str, indent=2) + "\n")
    log("wrote %s" % output_path)
    return 0


def variation(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values) / statistics.mean(values)


def summarize_trials(trials: Sequence[Dict[str, object]]) -> Dict[str, object]:
    rates = [float(t["total_bits_per_second"]) for t in trials]
    if not rates or any(not math.isfinite(rate) or rate <= 0 for rate in rates):
        raise ValueError("a measurement has missing, nonfinite or nonpositive throughput")
    efficiencies = []
    waits = []
    for trial in trials:
        deviation = trial["stddev_bits_per_second"]
        if not math.isfinite(deviation) or deviation < 0:
            raise ValueError("invalid interval standard deviation")
        usage = trial["resource_usage"]
        cpu = sum(p["user_seconds"] + p["sys_seconds"] for p in usage)
        if len(usage) == 2 and cpu > 0 and trial["transferred_bytes"] > 0:
            efficiencies.append(trial["transferred_bytes"] * 8 / 1e9 / cpu)
        for process in usage:
            if process.get("runnable_wait_seconds") is not None:
                waits.append(process["runnable_wait_seconds"] / process["real_seconds"])
    return {
        "median_bps": statistics.median(rates), "min_bps": min(rates), "max_bps": max(rates),
        "cv": variation(rates),
        "max_interval_cv": max(t["stddev_bits_per_second"] / t["total_bits_per_second"] for t in trials),
        "gbit_per_daemon_cpu_second": statistics.median(efficiencies) if efficiencies else None,
        # Sum of thread wait: can exceed wall time for multithreaded daemons.
        "max_thread_sum_wait_per_wall": max(waits) if waits else None,
    }


def analyze_pair(reference: Sequence[Dict[str, object]], candidate: Sequence[Dict[str, object]],
                 *, max_cv: float, max_interval_cv: float, duration: int,
                 warmup: int) -> Dict[str, object]:
    if not reference or len(reference) != len(candidate):
        raise ValueError("a comparison requires complete, equally sized pairs")
    ref, cand = summarize_trials(reference), summarize_trials(candidate)
    ratios = [c["total_bits_per_second"] / r["total_bits_per_second"]
              for r, c in zip(reference, candidate)]
    reasons = []
    if any(t.get("duration_seconds", duration) + 0.01 < 10 for t in [*reference, *candidate]):
        reasons.append("less than ten seconds of retained measurement")
    if any(len(t["interval_throughputs"]) < 2 for t in [*reference, *candidate]):
        reasons.append("missing measured interval samples")
    if len(ratios) < 4 or duration < 10 or warmup < 3:
        reasons.append("insufficient sampling (need >=4 pairs, >=10 s, >=3 s warmup)")
    for name, summary in (("reference", ref), ("candidate", cand)):
        if summary["cv"] > max_cv:
            reasons.append("%s repeat CV %.1f%% exceeds %.1f%%" % (name, summary["cv"] * 100, max_cv * 100))
        if summary["max_interval_cv"] > max_interval_cv:
            reasons.append("%s interval CV %.1f%% exceeds %.1f%%" % (name, summary["max_interval_cv"] * 100, max_interval_cv * 100))
    ratio_cv = variation(ratios)
    if ratio_cv > max_cv:
        reasons.append("paired-ratio CV %.1f%% exceeds %.1f%%" % (ratio_cv * 100, max_cv * 100))
    return {"reference": ref, "candidate": cand, "paired_ratios": ratios,
            "ratio_median": statistics.median(ratios), "ratio_min": min(ratios),
            "ratio_max": max(ratios), "ratio_cv": ratio_cv,
            "status": "unstable" if reasons else "stable", "reasons": reasons}


def aes_gcm_host(cpu_info: str, machine: str) -> bool:
    flags = [set(line.split(":", 1)[1].split()) for line in cpu_info.splitlines()
             if ":" in line and line.split(":", 1)[0].strip() in ("flags", "Features")]
    common = set.intersection(*flags) if flags else set()
    if machine in ("x86_64", "amd64"):
        return {"aes", "pclmulqdq", "sse4_1", "ssse3"} <= common
    if machine in ("aarch64", "arm64"):
        return {"aes", "pmull"} <= common
    return False  # Do not infer an unverified Go TLS default on another ISA.


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def benchmark_metadata(cpus: Sequence[int], binaries: Sequence[Path]) -> Dict[str, object]:
    def version(command: Sequence[str]) -> str:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            return (result.stdout + result.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            return str(exc)
    def libraries(binary: Path) -> Dict[str, str]:
        digests = {}
        for line in version(["ldd", str(binary)]).splitlines():
            if "=> /" in line:
                path = Path(line.split("=>", 1)[1].strip().split()[0])
                try:
                    digests[str(path)] = file_sha256(path)
                except OSError:
                    pass
        return digests
    cpu_info = Path("/proc/cpuinfo").read_text()
    if not aes_gcm_host(cpu_info, platform.machine()):
        raise SystemExit("cannot verify h2mux AES-GCM hardware preference on this host")
    debug = os.environ.get("GODEBUG", "")
    if any(value in debug.split(",") for value in (
            "cpu.all=off", "cpu.aes=off", "cpu.pclmulqdq=off", "cpu.sse41=off",
            "cpu.ssse3=off", "cpu.pmull=off")):
        raise SystemExit("GODEBUG disables required AES-GCM hardware; matched comparison unavailable")
    model = next((line.split(":", 1)[1].strip() for line in cpu_info.splitlines()
                  if line.startswith("model name")), platform.machine())
    return {
        "host": platform.node(), "kernel": platform.release(), "machine": platform.machine(),
        "method": "paired-receiver-goodput-v1", "GODEBUG": debug,
        "harness_sha256": file_sha256(Path(__file__)),
        "cpu_model": model, "allowed_cpus": sorted(os.sched_getaffinity(0)), "role_cpus": list(cpus),
        "topology": {str(cpu): cpu_core(cpu) for cpu in cpus},
        "go_binaries": {str(path): version(["go", "version", "-m", str(path)])
                        for path in binaries if path.name != "multiplexd"},
        "compiler": version(["cc", "--version"]), "iperf3": version(["iperf3", "--version"]),
        "source_head": version(["git", "rev-parse", "HEAD"]),
        "source_diff_sha256": hashlib.sha256(version(["git", "diff", "--binary", "HEAD"]).encode()).hexdigest(),
        "build_options": {str(path): {key: value for key, value in
            parse_cmake_cache(path.parent.parent / "CMakeCache.txt").items()
            if key.startswith(("CMAKE_C_FLAGS", "CMAKE_EXE_LINKER_FLAGS")) or key in ("CMAKE_C_COMPILER", "CMAKE_BUILD_TYPE", "ENABLE_THREADS", "CMAKE_INTERPROCEDURAL_OPTIMIZATION",
                       "BUILD_PIE", "USE_TLS_LIBRARY", "OPENSSL_SSL_LIBRARY", "MbedTLS_DIR")}
            for path in binaries if path.name == "multiplexd"},
        "binaries": {str(path): {"sha256": file_sha256(path),
                                 "ldd": version(["ldd", str(path)]),
                                 "library_sha256": libraries(path)} for path in binaries},
    }


def compare_report(payload: Dict[str, object]) -> str:
    options = payload["options"]
    lines = ["# Repeated paired throughput comparison", "",
             "Status: **%s**. All observations are retained; no throughput-based retries or trimming."
             % payload["status"], "",
             "%d s measured + %d s omitted warmup; %d pairs per scenario; 16 KiB default frames; "
             "window %d bytes; matched AES-128-GCM; one pinned CPU per daemon / GOMAXPROCS=1."
             % (options["duration"], options["warmup"], options["rounds"], options["window"]), "",
             "CPU roles (daemon server/client, iperf server/client): `%s`. "
             "Topology is the guest's view; affinity does not reserve host CPUs." % payload["metadata"]["role_cpus"], "",
             "Throughput counts delivered receiver bytes in both directions, aligned at iperf interval resolution. "
             "Each pair uses fresh daemons for one scenario, in alternating AB/BA order. "
             "References are adjacent to their candidate, rather than an old global baseline.", "",
             "Stable requires reference, candidate and paired-ratio repeat CV <= %.1f%%, "
             "and every measured interval CV <= %.1f%%. Ranges are observed min/max, not confidence intervals."
             % (options["max_cv"] * 100, options["max_interval_cv"] * 100), "",
             "**Unstable cells are diagnostic observations; do not infer a winner or a regression.** "
             "Only compare history with matched host/kernel, CPU layout, build/library provenance and parameters.", "",
             "| Candidate / reference | Scenario | Reference Gbit/s | Candidate Gbit/s | Paired ratio median [range] | CV ref / cand / ratio | Max interval CV | Gbit / daemon CPU-s ref / cand | Quality |",
             "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    notes = []
    for pair in payload["comparisons"]:
        for name, result in pair["scenarios"].items():
            ref, cand = result["reference"], result["candidate"]
            def eff(summary: Dict[str, object]) -> str:
                value = summary["gbit_per_daemon_cpu_second"]
                return "%.2f" % value if value is not None else "n/a"
            lines.append("| %s / %s | %s | %.2f | %.2f | %.3fx [%.3f, %.3f] | %.1f / %.1f / %.1f%% | %.1f%% | %s / %s | %s |" % (
                pair["candidate"], pair["reference"], name, ref["median_bps"] / 1e9, cand["median_bps"] / 1e9,
                result["ratio_median"], result["ratio_min"], result["ratio_max"],
                ref["cv"] * 100, cand["cv"] * 100, result["ratio_cv"] * 100,
                max(ref["max_interval_cv"], cand["max_interval_cv"]) * 100,
                eff(ref), eff(cand), result["status"]))
            notes.extend("- %s / %s, %s: %s" % (pair["candidate"], pair["reference"], name, reason)
                         for reason in result["reasons"])
    lines += ["", *notes, "", "CPU efficiency uses **all application bytes including omitted warmup** divided by "
              "the corresponding server+client daemon CPU seconds. It is independent of run duration. "
              "It excludes iperf/harness CPU. Native per-trial reports also retain wall/user/sys.", "",
              "Per-trial JSON retains PID-scoped CPU and thread-summed runnable wait, PSI stall deltas, "
              "transport TCP diagnostics, binary SHA-256 and raw iperf paths. Host PSI includes this workload "
              "and other jobs; it is diagnostic, not attribution to a specific service.", "",
              "Artifacts: `%s`." % payload["run_dir"], ""]
    if payload.get("error"):
        lines += ["Failure: " + payload["error"], ""]
    return "\n".join(lines)


def compare_main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Repeated, CPU-pinned, adjacent benchmark pairs")
    parser.add_argument("--build-dir", default="build/st")
    parser.add_argument("--mbed-build-dir", default="build/st-mbedtls")
    parser.add_argument("--h2mux-binary", required=True)
    parser.add_argument("--freestanding", action="store_true")
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--window", type=int, default=16777216)
    parser.add_argument("--cpus", help="four explicit role CPUs; default: quiet distinct cores")
    parser.add_argument("--max-cv", type=float, default=0.05)
    parser.add_argument("--max-interval-cv", type=float, default=0.10)
    parser.add_argument("--scenarios", default="uplink,downlink,bidir,parallel")
    parser.add_argument("--output", help="latest summary; per-trial artifacts always use a new directory")
    args = parser.parse_args(argv)
    if args.duration < 1 or args.warmup < 0 or args.rounds < 2 or args.rounds % 2 or args.window < 1:
        parser.error("positive duration/window, nonnegative warmup and even >=2 rounds required")
    if not (0 < args.max_cv <= 1 and 0 < args.max_interval_cv <= 1):
        parser.error("CV limits must be fractions in (0,1]")
    scenarios = args.scenarios.split(",")
    if len(set(scenarios)) != len(scenarios) or not set(scenarios) <= {s.name for s in SCENARIOS}:
        parser.error("--scenarios must name distinct known scenarios")
    cpus = parse_cpu_set(args.cpus) if args.cpus else select_cpus()
    cpu_text = ",".join(map(str, cpus))
    build = resolve_path(ROOT, args.build_dir)
    h2 = resolve_path(ROOT, args.h2mux_binary)
    mbed = resolve_path(ROOT, args.mbed_build_dir)
    output = resolve_path(ROOT, args.output) if args.output else build / "comparison.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    output.with_suffix(".json").unlink(missing_ok=True)
    run_dir = output.parent / ("compare-%s-%d" % (time.strftime("%Y%m%d-%H%M%S"), time.time_ns() % 1000000000))
    run_dir.mkdir()
    # A variant is its build directory, optional h2mux binary, and native knobs.
    variants = {"openssl": (build, None, []), "h2mux TLS": (build, h2, [])}
    pairs = [("openssl", "h2mux TLS")]
    if not args.freestanding:
        variants.update({"openssl socket_offload": (build, None, ["--socket-offload"]),
                         "openssl socket_offload no_ktls": (build, None, ["--socket-offload", "--no-kernel-offload"]),
                         "mbedtls": (mbed, None, ["--ciphersuites", "TLS1-3-AES-128-GCM-SHA256"]),
                         "mbedtls socket_offload": (mbed, None, ["--socket-offload", "--ciphersuites", "TLS1-3-AES-128-GCM-SHA256"]),
                         "multiplexd no-TLS": (build, None, ["--no-tls"]),
                         "h2mux no-TLS": (build, h2, ["--no-tls"])})
        pairs = [("openssl", name) for name in ("openssl socket_offload", "openssl socket_offload no_ktls",
                 "mbedtls", "mbedtls socket_offload", "h2mux TLS")]
        pairs.append(("multiplexd no-TLS", "h2mux no-TLS"))
    binaries = list(dict.fromkeys(binary if binary else directory / "bin/multiplexd"
                                  for directory, binary, _ in variants.values()))
    for binary in binaries:
        if not binary.is_file():
            parser.error("binary is missing: %s" % binary)
    check_benchmark_environment(binaries)
    metadata = benchmark_metadata(cpus, binaries)
    payload = {"status": "running", "options": vars(args), "metadata": metadata,
               "run_dir": str(run_dir), "comparisons": [], "trials": []}

    def measure(name: str, scenario: str, label: str) -> Dict[str, object]:
        if file_sha256(Path(__file__)) != metadata["harness_sha256"]:
            raise RuntimeError("benchmark harness changed during the comparison")
        directory, binary, knobs = variants[name]
        trial_dir = run_dir / label
        trial_dir.mkdir()
        report_path = trial_dir / "measurement.json"
        command = [sys.executable, str(ROOT / "scripts/bench.py"), "--build-dir", str(directory),
                   "--runtime-dir", str(trial_dir), "--scenario", scenario, "--warmup", str(args.warmup),
                   "-t", str(args.duration), "-w", str(args.window), "--cpus", cpu_text,
                   "--ciphersuites", "TLS_AES_128_GCM_SHA256", "--output", str(trial_dir / "measurement.md"),
                   "--report-json", str(report_path), *knobs]
        if binary:
            command += ["--h2mux-binary", str(binary)]
        print("MEASURE %s %s -> %s" % (name, scenario, label), flush=True)
        rc = run_owned_benchmark(command, ROOT, timeout_seconds=args.duration + args.warmup + 65,
                                 log_output=trial_dir / "harness.log")
        if rc:
            raise RuntimeError("%s failed (exit %d); see %s" % (label, rc, trial_dir / "harness.log"))
        measurement = json.loads(report_path.read_text())
        expected = metadata["binaries"][measurement["binary"]]["sha256"]
        if measurement["binary_sha256"] != expected:
            raise RuntimeError("benchmark binary changed during the comparison")
        payload["trials"].append({"variant": name, "scenario": scenario, "label": label,
                                   "report": str(report_path), "data": measurement})
        if len(measurement["results"]) != 1 or measurement["results"][0]["scenario"]["name"] != scenario:
            raise RuntimeError("trial contains the wrong scenario")
        result = measurement["results"][0]
        if scenario in ("bidir", "parallel") and min(result["sent_bits_per_second"], result["received_bits_per_second"]) <= 0:
            raise RuntimeError("bidirectional measurement is missing a traffic direction")
        return result

    try:
        for pair_index, (ref_name, cand_name) in enumerate(pairs):
            pair = {"reference": ref_name, "candidate": cand_name, "scenarios": {}}
            payload["comparisons"].append(pair)
            for scenario in scenarios:
                observations = {"reference": [], "candidate": []}
                for round_index in range(args.rounds):
                    # ABBA / ABBA: both roles occupy the early and late slot.
                    order = ("reference", "candidate") if round_index % 2 == 0 else ("candidate", "reference")
                    for role in order:
                        label = "%02d-%s-%02d-%s" % (pair_index, scenario, round_index, role)
                        observations[role].append(measure(ref_name if role == "reference" else cand_name,
                                                          scenario, label))
                pair["scenarios"][scenario] = analyze_pair(
                    observations["reference"], observations["candidate"], max_cv=args.max_cv,
                    max_interval_cv=args.max_interval_cv, duration=args.duration, warmup=args.warmup)
        payload["status"] = ("stable" if all(result["status"] == "stable"
            for pair in payload["comparisons"] for result in pair["scenarios"].values()) else "unstable")
    except (RuntimeError, ValueError, OSError, KeyboardInterrupt) as exc:
        payload["status"] = "failed"
        payload["error"] = str(exc) or "interrupted"
    finally:
        output.with_suffix(".json").write_text(json.dumps(payload, indent=2) + "\n")
        output.write_text(compare_report(payload))
        print("Comparison %s: %s" % (payload["status"], output), flush=True)
    return 0 if payload["status"] == "stable" else 2 if payload["status"] == "unstable" else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "compare":
        raise SystemExit(compare_main(sys.argv[2:]))
    raise SystemExit(main())
