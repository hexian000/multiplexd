#!/usr/bin/env python3
"""multiplexd throughput / CPU linearity benchmark.

Generates TLS certificates, starts a server and client pair, then runs
iperf3 bidirectional (``--bidir``) with a single stream (``-P 1``) at
increasing bandwidth limits.  For each step the script records:

* achieved throughput (Mbps, sum of both directions)
* multiplexd CPU usage during the test
* multiplexd CPU usage after the test (to detect post-traffic busy-loops)

A Markdown report is written to **build/linearity_report.md** (default) and
also printed to stdout.

Usage::

    python3 scripts/linearity_test.py [options]

    --build-dir DIR    CMake build directory (default: build)
    --output FILE      Markdown report path (default: build/linearity_report.md)
    --duration SEC     iperf3 test duration per step (default: 8)
    --bw-list M,M,...  comma-separated bandwidth limits (default: 10M,20M,50M,100M,200M,500M,1000M,2000M,3000M,0)
                       0 = unlimited
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_REPORT = DEFAULT_BUILD_DIR / "linearity_report.md"
IPERF3_PORT = 5201
MUX_LISTEN = 5202
MUX_PORT = 8443
API_PORT = 9081


# ---------------------------------------------------------------------------
# utilities
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def quote_cmd(cmd: Sequence[str]) -> str:
    return " ".join(shlex.quote(p) for p in cmd)


def run(cmd: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    log(f"+ {quote_cmd(cmd)}")
    return subprocess.run(list(cmd), **kwargs)


def killall(*names: str) -> None:
    for n in names:
        subprocess.run(["pkill", "-9", "-f", n],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def wait_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
        if f":{port} " in r.stdout:
            return True
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------
# CPU measurement via /proc/<pid>/stat tick delta
#
# utime + stime are monotonic clock ticks.  Taking two snapshots separated
# by a known wall-time interval gives the **average CPU utilisation** over
# that interval:
#
#     cpu% = 100 × (ticks2 − ticks1) / ((t2 − t1) × CLK_TCK)
# ---------------------------------------------------------------------------

_CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])


def _read_ticks(pid: int) -> int:
    """Return utime+stime in clock ticks for *pid*, or 0 if gone.

    Parses /proc/<pid>/stat.  The comm field (field 2) is enclosed in
    parentheses and may contain spaces, so we cannot naively split().
    The kernel places utime at 1-indexed field 14 and stime at field 15
    of the space-delimited suffix that follows the closing ')'.  We find
    that suffix by locating the last ')' in the line and splitting the
    remainder — which always starts with the single-character state field —
    then picking elements [11] and [12] (0-indexed within the suffix).
    """
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text()
    except (FileNotFoundError, PermissionError):
        return 0
    rp = raw.rfind(")")
    if rp < 0:
        return 0
    suffix = raw[rp + 1:].split()
    # suffix[0]=state, [1]=ppid, ..., [11]=utime, [12]=stime
    if len(suffix) < 13:
        return 0
    return int(suffix[11]) + int(suffix[12])


def _total_ticks(*pids: int) -> int:
    return sum(_read_ticks(p) for p in pids)


def cpu_pct_interval(t_start: float, ticks_start: int,
                     t_end: float, ticks_end: int) -> float:
    """Average CPU% over [t_start, t_end] from two tick snapshots."""
    if t_end <= t_start:
        return 0.0
    dt = t_end - t_start
    dticks = ticks_end - ticks_start
    if dticks < 0:          # pid restarted / counter wrapped
        return 0.0
    return dticks / (dt * _CLK_TCK) * 100.0


class TickSnap:
    """A pair of (time.monotonic(), total_ticks)."""
    __slots__ = ("t", "ticks")

    def __init__(self, *pids: int) -> None:
        self.t = time.monotonic()
        self.ticks = _total_ticks(*pids)

    def cpu_since(self, prev: "TickSnap") -> float:
        return cpu_pct_interval(prev.t, prev.ticks, self.t, self.ticks)


def parse_summary_bits(summary: object) -> float:
    """Return bits_per_second from an iperf3 JSON summary dict, or 0."""
    if not isinstance(summary, dict):
        return 0.0
    value = summary.get("bits_per_second")
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def extract_bidir_throughput_mbps(report: Dict[str, object]) -> float:
    """Return total throughput (Mbps) for a --bidir iperf3 JSON report.

    For ``--bidir`` output each stream entry carries both a ``sender`` and
    ``receiver`` sub-object.  The ``sender`` boolean distinguishes the
    client-to-server direction (True) from the server-to-client direction
    (False).  We sum only ``sender.sender == True`` (what the client sent)
    and ``receiver.sender == False`` (what the client received) so that
    the two directions are counted once each.
    """
    end = report.get("end")
    if not isinstance(end, dict):
        raise SystemExit("iperf3 JSON report missing end summary")
    streams = end.get("streams")
    if not isinstance(streams, list):
        raise SystemExit("iperf3 JSON report missing end.streams")
    total_bps = 0.0
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        sender = stream.get("sender")
        if isinstance(sender, dict) and sender.get("sender") is True:
            total_bps += parse_summary_bits(sender)
        receiver = stream.get("receiver")
        if isinstance(receiver, dict) and receiver.get("sender") is False:
            total_bps += parse_summary_bits(receiver)
    return total_bps / 1_000_000.0


def run_iperf_json(
        command: Sequence[str],
        *,
        log_path: Path,
        timeout_seconds: float,
) -> Dict[str, object]:
    """Run iperf3 with --json, write output to *log_path*, return parsed dict.

    Raises SystemExit on timeout, non-zero exit, malformed JSON, or stderr
    output from iperf3.
    """
    log(f"+ {quote_cmd(command)}")
    try:
        proc = subprocess.run(
            list(command),
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
        raise SystemExit(
            f"iperf3 timed out after {timeout_seconds:.0f}s: "
            f"{quote_cmd(command)}"
        )
    log_path.write_text(output, encoding="utf-8")
    stderr_lines = [line.strip() for line in stderr_output.splitlines()
                    if line.strip()]
    if stderr_lines:
        log(f"iperf3 stderr: {stderr_lines[0]}")
    if proc.returncode != 0:
        raise SystemExit(
            f"iperf3 failed with status {proc.returncode}: "
            f"{quote_cmd(command)}"
        )
    json_start = output.find("{")
    if json_start < 0:
        raise SystemExit("iperf3 output missing JSON object")
    prefix = output[:json_start].strip()
    if prefix:
        log(f"iperf3 pre-JSON text: {prefix.splitlines()[0]}")
    try:
        report, end = json.JSONDecoder().raw_decode(output[json_start:])
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid iperf3 JSON output: {exc}")
    suffix = output[json_start + end:].strip()
    if suffix:
        log(f"iperf3 post-JSON text: {suffix.splitlines()[0]}")
    return report


# ---------------------------------------------------------------------------
# config builders
# ---------------------------------------------------------------------------

SERVER_CONF = {
    "api_listen":      f"127.0.0.1:{API_PORT}",
    "mux_listen":      f"127.0.0.1:{MUX_PORT}",
    "listen":          f"127.0.0.1:5203",
    "connect":         f"127.0.0.1:{IPERF3_PORT}",
    "loglevel":        4,
    "mux": {
        "stream_window":  1048576,
        "session_window": 4194304,
    },
    "tls": {
        "cert":         "@server-cert.pem",
        "key":          "@server-key.pem",
        "authcerts":    ["@client-cert.pem"],
        "ciphersuites": "TLS_CHACHA20_POLY1305_SHA256",
    },
}

CLIENT_CONF = {
    "mux_connect":     f"127.0.0.1:{MUX_PORT}",
    "listen":          f"127.0.0.1:{MUX_LISTEN}",
    "connect":         f"127.0.0.1:{IPERF3_PORT}",
    "loglevel":        4,
    "mux": {
        "stream_window":  1048576,
        "session_window": 4194304,
    },
    "tls": {
        "cert":         "@client-cert.pem",
        "key":          "@client-key.pem",
        "authcerts":    ["@server-cert.pem"],
        "ciphersuites": "TLS_CHACHA20_POLY1305_SHA256",
    },
}


# ---------------------------------------------------------------------------
# test runner
# ---------------------------------------------------------------------------

class LinearityTest:
    def __init__(self, args: argparse.Namespace) -> None:
        self.build_dir = Path(args.build_dir).resolve()
        self.binary = self.build_dir / "bin" / "multiplexd"
        self.output = Path(args.output).resolve()
        self.duration = int(args.duration)
        self.bw_list = [b.strip()
                        for b in args.bw_list.split(",") if b.strip()]

        self.work_dir = self.build_dir / "linearity_work"
        self.work_dir.mkdir(parents=True, exist_ok=True)

        self._srv: Optional[subprocess.Popen] = None
        self._cli: Optional[subprocess.Popen] = None
        self._iperf: Optional[subprocess.Popen] = None

    # -- setup / teardown ---------------------------------------------------

    def setup(self) -> None:
        killall("iperf3", "multiplexd")
        time.sleep(1)

        if not self.binary.exists():
            raise SystemExit(f"multiplexd not found: {self.binary}")

        # write configs
        for name, cfg in [("server.json", SERVER_CONF),
                          ("client.json", CLIENT_CONF)]:
            (self.work_dir / name).write_text(
                json.dumps(cfg, indent=4) + "\n", encoding="utf-8")

        # generate certs (idempotent)
        cert_dir = self.work_dir
        if not (cert_dir / "server-cert.pem").exists():
            run([str(self.binary), "--gencerts", "client,server"],
                cwd=str(cert_dir), timeout=30)

        # iperf3 server (foreground, not daemon)
        self._iperf = subprocess.Popen(
            ["iperf3", "-s", "-p", str(IPERF3_PORT)],
            cwd=str(self.work_dir),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not wait_port(IPERF3_PORT):
            raise SystemExit("iperf3 server did not start")

        # multiplexd server
        self._srv = subprocess.Popen(
            [str(self.binary), "-c", "server.json"],
            cwd=str(self.work_dir),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        # multiplexd client
        self._cli = subprocess.Popen(
            [str(self.binary), "-c", "client.json"],
            cwd=str(self.work_dir),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)

        # health check
        r = subprocess.run(
            ["curl", "-s", f"http://127.0.0.1:{API_PORT}/healthy"],
            capture_output=True,
        )
        if r.returncode != 0:
            raise SystemExit("multiplexd not healthy")

        self._srv_pid = self._srv.pid
        self._cli_pid = self._cli.pid
        log(f"multiplexd ready  srv={self._srv_pid}  cli={self._cli_pid}")

    def teardown(self) -> None:
        for p in [self._cli, self._srv, self._iperf]:
            if p is not None:
                try:
                    p.terminate()
                except OSError:
                    pass
        time.sleep(1)
        for p in [self._cli, self._srv, self._iperf]:
            if p is not None:
                try:
                    p.kill()
                except OSError:
                    pass
        killall("iperf3", "multiplexd")

    # -- single test step ---------------------------------------------------

    def run_one(self, bw: str) -> Dict[str, float]:
        """Run iperf3 bidirectional.  Returns dict with throughput and
        per-process CPU percentages averaged over the iperf3 interval
        and the post-test settle interval."""
        label = bw if bw != "0" else "unlimited"
        logfile = self.work_dir / f"iperf_bw{label}.log"
        timeout = float(self.duration) + 30.0

        # --- snapshots just before iperf3 starts --------------------------
        snap0_srv = TickSnap(self._srv_pid)
        snap0_cli = TickSnap(self._cli_pid)

        cmd = ["iperf3", "-c", "127.0.0.1", "-p", str(MUX_LISTEN),
               "-t", str(self.duration), "-P", "1", "--bidir", "--json"]
        if bw != "0":
            cmd += ["-b", bw]
        report = run_iperf_json(cmd, log_path=logfile, timeout_seconds=timeout)

        # --- snapshots right after iperf3 exits, then after settle --------
        snap1_srv = TickSnap(self._srv_pid)
        snap1_cli = TickSnap(self._cli_pid)
        time.sleep(2.0)
        snap2_srv = TickSnap(self._srv_pid)
        snap2_cli = TickSnap(self._cli_pid)

        srv_dur = snap1_srv.cpu_since(snap0_srv)
        srv_aft = snap2_srv.cpu_since(snap1_srv)
        cli_dur = snap1_cli.cpu_since(snap0_cli)
        cli_aft = snap2_cli.cpu_since(snap1_cli)

        thr = extract_bidir_throughput_mbps(report)
        return {
            "thr": thr,
            "srv_dur": srv_dur,
            "srv_aft": srv_aft,
            "cli_dur": cli_dur,
            "cli_aft": cli_aft,
        }

    # -- main sweep ---------------------------------------------------------

    def sweep(self, idle_srv: float, idle_cli: float) -> List[Dict]:
        rows: List[Dict] = []

        for bw in self.bw_list:
            label = bw if bw != "0" else "unlimited"
            log(f"testing bw={label} ...")
            d = self.run_one(bw)
            thr = d["thr"]
            srv_net = max(0.0, d["srv_dur"] - idle_srv)
            cli_net = max(0.0, d["cli_dur"] - idle_cli)
            max_net = max(srv_net, cli_net)
            eff = f"{max_net / thr:.3f}" if thr > 0 else "N/A"

            row = {
                "bw": label,
                "thr_mbps": round(thr, 1),
                "srv_dur_pct": round(d["srv_dur"], 1),
                "cli_dur_pct": round(d["cli_dur"], 1),
                "srv_aft_pct": round(d["srv_aft"], 1),
                "cli_aft_pct": round(d["cli_aft"], 1),
                "net_cpu_pct": round(max_net, 1),
                "cpu_per_mbps": eff,
            }
            rows.append(row)

            log(f"  thr={thr:.0f} Mbps  srv_cpu={d['srv_dur']:.1f}%  "
                f"cli_cpu={d['cli_dur']:.1f}%  cpu/Mbps={eff}")

            max_aft = max(d["srv_aft"], d["cli_aft"])
            if max_aft > 30:
                log(f"  WARNING: post-test CPU srv={d['srv_aft']:.1f}% "
                    f"cli={d['cli_aft']:.1f}% — possible busy-loop")

        return rows

    # -- report -------------------------------------------------------------

    def render_report(self, rows: List[Dict], idle_srv: float,
                      idle_cli: float, final_srv: float,
                      final_cli: float) -> str:
        lines: List[str] = []

        lines.append("# Multiplexd Throughput / CPU Linearity Report")
        lines.append("")
        lines.append(f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Binary**: `{self.binary}`")
        lines.append(f"**iperf3 duration per step**: {self.duration} s")
        lines.append(
            f"**Idle CPU (srv / cli)**: {idle_srv:.1f} % / {idle_cli:.1f} %")
        lines.append(
            f"**Final CPU after cleanup (srv / cli)**: "
            f"{final_srv:.1f} % / {final_cli:.1f} %")
        lines.append("")

        # summary table
        lines.append("## Results")
        lines.append("")
        header = ("| BW limit | Thr (Mbps) | CPU srv (%) | CPU cli (%) | "
                  "CPU aft srv (%) | CPU aft cli (%) | "
                  "Net CPU (%) | CPU / Mbps |")
        sep = ("|----------|------------|------------|------------|"
               "----------------|----------------|"
               "------------|------------|")
        lines.append(header)
        lines.append(sep)

        for r in rows:
            lines.append(
                f"| {r['bw']} | {r['thr_mbps']:.1f} | "
                f"{r['srv_dur_pct']:.1f} | {r['cli_dur_pct']:.1f} | "
                f"{r['srv_aft_pct']:.1f} | {r['cli_aft_pct']:.1f} | "
                f"{r['net_cpu_pct']:.1f} | {r['cpu_per_mbps']} |"
            )

        lines.append("")

        # analysis
        valid = [r for r in rows if isinstance(r['cpu_per_mbps'], float)]
        if len(valid) >= 2:
            first_eff = valid[0]["cpu_per_mbps"]
            last_eff = valid[-1]["cpu_per_mbps"]
            ratio = last_eff / first_eff if first_eff > 0 else float("inf")
            lines.append("## Analysis")
            lines.append("")
            if ratio < 2.0:
                lines.append(
                    f"**CPU/Mbps is roughly constant** "
                    f"(first={first_eff:.3f}, last={last_eff:.3f}, "
                    f"ratio={ratio:.2f}×).  "
                    f"The per-stream scheduling overhead is low and the "
                    f"multiplexer scales linearly with throughput."
                )
            elif ratio < 5.0:
                lines.append(
                    f"**CPU/Mbps shows moderate growth** "
                    f"(first={first_eff:.3f}, last={last_eff:.3f}, "
                    f"ratio={ratio:.2f}×).  "
                    f"Per-stream overhead increases at higher stream counts "
                    f"but remains within acceptable bounds."
                )
            else:
                lines.append(
                    f"**CPU/Mbps grows super-linearly** "
                    f"(first={first_eff:.3f}, last={last_eff:.3f}, "
                    f"ratio={ratio:.2f}×).  "
                    f"This indicates significant per-stream scheduling "
                    f"overhead that may need investigation."
                )

            # check for post-test CPU anomaly
            high_after = [r for r in rows
                          if r["srv_aft_pct"] > 15 or r["cli_aft_pct"] > 15]
            if high_after:
                lines.append("")
                lines.append(
                    "**⚠  Post-test CPU remains elevated** for some steps, "
                    "which may indicate a busy-loop in the stream cleanup "
                    "path (EV_IDLE / tombstone handling)."
                )

            max_final = max(final_srv, final_cli)
            if max_final > 15:
                lines.append("")
                lines.append(
                    f"**⚠  Final CPU after cleanup is "
                    f"srv={final_srv:.1f}% / cli={final_cli:.1f}%** "
                    f"(expected near-idle).  A persistent busy-loop may "
                    f"still be present."
                )
            else:
                lines.append("")
                lines.append(
                    f"**✓  Final CPU returned to "
                    f"srv={final_srv:.1f}% / cli={final_cli:.1f}%** "
                    f"after all tombstones expired."
                )

        lines.append("")
        return "\n".join(lines)

    # -- main ---------------------------------------------------------------

    def run(self) -> int:
        try:
            self.setup()
        except SystemExit as e:
            log(f"setup failed: {e}")
            self.teardown()
            return 1

        try:
            # idle baseline: single 2 s interval after settling
            time.sleep(2)
            idle0_srv = TickSnap(self._srv_pid)
            idle0_cli = TickSnap(self._cli_pid)
            time.sleep(2.0)
            idle1_srv = TickSnap(self._srv_pid)
            idle1_cli = TickSnap(self._cli_pid)
            idle_srv = idle1_srv.cpu_since(idle0_srv)
            idle_cli = idle1_cli.cpu_since(idle0_cli)
            log(f"idle CPU: srv={idle_srv:.1f}%  cli={idle_cli:.1f}%")

            rows = self.sweep(idle_srv, idle_cli)

            # final CPU after tombstone cleanup (12 s interval)
            time.sleep(12)
            final0_srv = TickSnap(self._srv_pid)
            final0_cli = TickSnap(self._cli_pid)
            time.sleep(2.0)
            final1_srv = TickSnap(self._srv_pid)
            final1_cli = TickSnap(self._cli_pid)
            final_srv = final1_srv.cpu_since(final0_srv)
            final_cli = final1_cli.cpu_since(final0_cli)
            log(f"final CPU after cleanup: srv={final_srv:.1f}%  "
                f"cli={final_cli:.1f}%")

            report = self.render_report(rows, idle_srv, idle_cli,
                                        final_srv, final_cli)
            self.output.write_text(report, encoding="utf-8")
            print(report)
            log(f"report written to {self.output}")
            return 0
        except Exception as e:
            log(f"error: {e}")
            import traceback
            traceback.print_exc()
            return 1
        finally:
            self.teardown()


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="multiplexd throughput / CPU linearity benchmark")
    p.add_argument("--build-dir", default=str(DEFAULT_BUILD_DIR),
                   help="CMake build directory")
    p.add_argument("--output", default=str(DEFAULT_REPORT),
                   help="Markdown report path")
    p.add_argument("--duration", type=int, default=8,
                   help="iperf3 test duration per step (seconds)")
    p.add_argument("--bw-list", default="10M,20M,50M,100M,200M,500M,1000M,2000M,3000M,0",
                   help="comma-separated bandwidth limits (0=unlimited)")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    test = LinearityTest(args)
    return test.run()


if __name__ == "__main__":
    sys.exit(main())
