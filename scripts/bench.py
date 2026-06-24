#!/usr/bin/env python3

"""Run the multiplexd iperf3 benchmark suite and write a Markdown summary."""

from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, TextIO


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "bench.md"
BENCH_NETNS_ENV = "BENCH_NETNS"
MUX_TLS_PORT = 8443
CLK_TCK = float(os.sysconf("SC_CLK_TCK"))
PAGE_SIZE = int(os.sysconf("SC_PAGE_SIZE"))
RESOURCE_SAMPLE_INTERVAL = 0.1


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str


@dataclass(frozen=True)
class ResourceUsage:
    name: str
    cpu_percent: float
    peak_rss_bytes: int


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


def read_proc_cpu_ticks(pid: int) -> Optional[int]:
    """Return cumulative utime+stime (clock ticks) for all threads of pid."""
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
    return utime + stime


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
        self._start_ticks: Dict[str, Optional[int]] = {}
        self._end_ticks: Dict[str, Optional[int]] = {}
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
        self._sample_rss()

    def results(self) -> List[ResourceUsage]:
        wall = max(1e-6, self._end_time - self._start_time)
        usage: List[ResourceUsage] = []
        for name, _ in self._procs:
            start = self._start_ticks.get(name)
            end = self._end_ticks.get(name)
            if start is None or end is None:
                cpu_percent = 0.0
            else:
                cpu_percent = (end - start) / CLK_TCK / wall * 100.0
            usage.append(
                ResourceUsage(
                    name=name,
                    cpu_percent=cpu_percent,
                    peak_rss_bytes=self._peak_rss[name],
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


def build_server_config(*, use_tls: bool, window: Optional[int] = None, max_frame_size: Optional[int] = None, tls_buffered: bool = False) -> Dict[str, object]:
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
        "api_listen": "127.0.0.1:9081",
        "mux_listen": "127.0.0.1:8443",
        "connect": "127.0.0.1:5201",
        "identity": {
            "claim": "server",
            "listen": {"client": "127.0.0.1:5203"},
        },
        "mux": mux,
        "loglevel": 4,
    }
    if use_tls:
        config["tls"] = {
            "cert": "@server-cert.pem",
            "key": "@server-key.pem",
            "authcerts": ["@client-cert.pem"],
            "buffered": tls_buffered,
        }
    return config


def build_client_config(*, use_tls: bool, tunnels: int = 1, window: Optional[int] = None, max_frame_size: Optional[int] = None, tls_buffered: bool = False) -> Dict[str, object]:
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
        "connect": "127.0.0.1:5201",
        "identity": {
            "claim": "client",
            "mux_connect": ["127.0.0.1:8443"] * tunnels,
            "listen": {"server": "127.0.0.1:5202"},
        },
        "mux": mux,
        "loglevel": 4,
    }
    if use_tls:
        config["tls"] = {
            "cert": "@client-cert.pem",
            "key": "@client-key.pem",
            "authcerts": ["@server-cert.pem"],
            "buffered": tls_buffered,
        }
    return config


def write_config(path: Path, payload: Dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


def ensure_certificates(binary_path: Path, runtime_dir: Path) -> None:
    server_cert = runtime_dir / "server-cert.pem"
    client_cert = runtime_dir / "client-cert.pem"
    if server_cert.exists() and client_cert.exists():
        return
    run_command(
        [str(binary_path), "--gencerts", "client,server"],
        cwd=runtime_dir,
        timeout=30.0,
    )


def prepare_runtime_assets(
        binary_path: Path,
        runtime_dir: Path,
        *,
        use_tls: bool,
        tunnels: int = 1,
        window: Optional[int] = None,
        max_frame_size: Optional[int] = None,
        tls_buffered: bool = False,
) -> tuple[Path, Path]:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    if use_tls:
        ensure_certificates(binary_path, runtime_dir)
    server_config_path = runtime_dir / "server.json"
    client_config_path = runtime_dir / "client.json"
    write_config(server_config_path, build_server_config(use_tls=use_tls, window=window, max_frame_size=max_frame_size, tls_buffered=tls_buffered))
    write_config(client_config_path, build_client_config(use_tls=use_tls, tunnels=tunnels, window=window, max_frame_size=max_frame_size, tls_buffered=tls_buffered))
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


def open_log(path: Path) -> TextIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def build_scenario_commands(
        iperf3: str,
        scenario: Scenario,
        duration: int,
        parallel: int,
) -> List[List[str]]:
    base_command = [
        iperf3,
        "-c",
        "127.0.0.1",
        "-p",
        "5202",
        "-t",
        str(duration),
        "--json",
    ]
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
        output = proc.stdout or ""
        stderr_output = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        stderr_output = exc.stderr or ""
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


def extract_total_throughput(report: Dict[str, object], scenario: Scenario) -> tuple[float, float, float, float]:
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
        total = 0.0
        sum_obj = interval.get("sum")
        if isinstance(sum_obj, dict):
            bps = sum_obj.get("bits_per_second")
            if isinstance(bps, (int, float)):
                total = float(bps)
        if total == 0.0:
            streams = interval.get("streams")
            if isinstance(streams, list):
                for stream in streams:
                    if isinstance(stream, dict):
                        bps = stream.get("bits_per_second")
                        if isinstance(bps, (int, float)):
                            total += float(bps)
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
    tls_buffered: bool = False,
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
        "| TLS buffered | %s |" % ("on" if tls_buffered else "off"),
        "| Tunnels | %d |" % tunnels,
        "| Stream/session window | %s |" % (str(window) if window is not None else "default"),
        "| Max frame size | %s |" % (str(max_frame_size) if max_frame_size is not None else "default"),
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
        "(100%% = one core); RSS is the peak resident set size sampled "
        "every %.0f ms from /proc." % (RESOURCE_SAMPLE_INTERVAL * 1000.0)
    )
    lines.append("")
    lines.append("| Scenario | Process | CPU | Peak RSS |")
    lines.append("| --- | --- | ---: | ---: |")
    for result in results:
        for usage in result.resource_usage:
            lines.append(
                "| %s | %s | %.1f%% | %s |"
                % (
                    result.scenario.label,
                    usage.name,
                    usage.cpu_percent,
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
                lines.append("| %d | %s |" % (index, format_bits_per_second(bps)))
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
        "--startup-wait",
        type=float,
        default=1.0,
        help="seconds to wait after starting services before running iperf3",
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
        "--tls-buffered",
        action="store_true",
        default=False,
        help="enable tls.buffered (memory-transport) mode (default: off)",
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
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_project_root(ROOT)
    maybe_reexec_in_netns(args.netem_delay)
    iperf3 = ensure_tool(args.iperf3)
    build_dir = resolve_path(ROOT, args.build_dir)
    build_cache = parse_cmake_cache(build_dir / "CMakeCache.txt")
    build_dir.mkdir(parents=True, exist_ok=True)
    binary_path = build_dir / "bin" / "multiplexd"
    if not binary_path.exists():
        raise SystemExit("expected binary not found: %s" % binary_path)
    if args.tls and build_cache.get("USE_TLS_LIBRARY") == "none":
        raise SystemExit(
            "TLS requested, but %s was configured with USE_TLS_LIBRARY=none"
            % build_dir
        )
    server_config_path, client_config_path = prepare_runtime_assets(
        binary_path,
        build_dir,
        use_tls=args.tls,
        tunnels=args.tunnels,
        window=args.window,
        max_frame_size=args.max_frame_size,
        tls_buffered=args.tls_buffered,
    )
    configure_netem(args.netem_delay)
    command_timeout_seconds = compute_command_timeout_seconds(
        args.duration,
        args.startup_wait,
    )
    shutdown_budget = compute_process_shutdown_budget(
        args.duration,
        args.startup_wait,
        scenario_count=len(SCENARIOS),
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

    try:
        server_log = open_log(build_dir / "multiplexd-server.log")
        client_log = open_log(build_dir / "multiplexd-client.log")
        iperf_server_log = open_log(build_dir / "iperf3-server.log")

        log("+ %s" % quote_command([iperf3, "-s", "-p", "5201"]))
        iperf_server_proc = subprocess.Popen(
            [iperf3, "-s", "-p", "5201"],
            cwd=str(build_dir),
            stdout=iperf_server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        log("+ %s" %
            quote_command([str(binary_path), "-c", str(server_config_path)]))
        server_proc = subprocess.Popen(
            [str(binary_path), "-c", str(server_config_path)],
            cwd=str(build_dir),
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        log("+ %s" %
            quote_command([str(binary_path), "-c", str(client_config_path)]))
        client_proc = subprocess.Popen(
            [str(binary_path), "-c", str(client_config_path)],
            cwd=str(build_dir),
            stdout=client_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        time.sleep(args.startup_wait)

        for scenario in SCENARIOS:
            commands = build_scenario_commands(
                iperf3, scenario, args.duration, args.parallel)
            log_paths = [
                build_dir / ("iperf3-%s-%02d.json" % (scenario.name, index))
                for index in range(1, len(commands) + 1)
            ]
            stderr_paths = [
                build_dir / ("iperf3-%s-%02d.stderr" % (scenario.name, index))
                for index in range(1, len(commands) + 1)
            ]
            sampler = ProcSampler(
                [
                    ("multiplexd server", server_proc.pid),
                    ("multiplexd client", client_proc.pid),
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
            resource_usage = sampler.results()
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
                )
            )
    finally:
        if client_proc is not None:
            terminate_process(
                client_proc,
                "multiplexd client",
                shutdown_budget=shutdown_budget,
            )
        if server_proc is not None:
            terminate_process(
                server_proc,
                "multiplexd server",
                shutdown_budget=shutdown_budget,
            )
        if iperf_server_proc is not None:
            terminate_process(
                iperf_server_proc,
                "iperf3 server",
                shutdown_budget=shutdown_budget,
            )
        for handle in (iperf_server_log, client_log, server_log):
            if handle is not None:
                handle.close()

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
        tls_buffered=args.tls_buffered,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    log("wrote %s" % output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
