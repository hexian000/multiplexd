# multiplexd - TCP Stream Multiplexer

[![MIT License](https://img.shields.io/github/license/hexian000/multiplexd)](https://github.com/hexian000/multiplexd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/multiplexd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/multiplexd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/multiplexd/total.svg)](https://github.com/hexian000/multiplexd/releases)
[![Release](https://img.shields.io/github/release/hexian000/multiplexd.svg?style=flat)](https://github.com/hexian000/multiplexd/releases)

multiplexd is a TCP stream multiplexer that tunnels many concurrent connections through a single transport session.

**Table of Contents**
- [Features](#features)
- [Architecture](#architecture)
  - [Port Forwarding](#port-forwarding)
  - [Protocol](#protocol)
  - [Implementation](#implementation)
- [Generating Certificates](#generating-certificates)
  - [Generate Self-Signed Certificates](#generate-self-signed-certificates)
  - [Generate CA-Signed Certificates](#generate-ca-signed-certificates)
  - [Certificate Options](#certificate-options)
- [Configuration](#configuration)
  - [Server (server.json)](#server-serverjson)
  - [Client (client.json)](#client-clientjson)
  - [Multi-Peer Routing (`identity` block)](#multi-peer-routing-identity-block)
  - [Parallel Tunnels](#parallel-tunnels)
- [Observability](#observability)
  - [Endpoints](#endpoints)
    - [`GET /healthy`](#get-healthy)
    - [`GET /stats`](#get-stats)
    - [`POST /stats`](#post-stats)
    - [`GET /metrics`](#get-metrics)
- [Usage](#usage)
- [Building](#building)
  - [Dependencies](#dependencies)
  - [Build Instructions](#build-instructions)
  - [Running Tests](#running-tests)
  - [Convenience Builds](#convenience-builds)
  - [Build Options](#build-options)
  - [Developer Scripts](#developer-scripts)
- [Deployment Notes](#deployment-notes)
  - [TLS Security Model](#tls-security-model)
  - [Connection Backoff](#connection-backoff)
  - [API Server](#api-server)
  - [Configuration Reload](#configuration-reload)
- [Credits](#credits)

## Features

- **Stream Multiplexing**: A single transport session can carry up to 65535 concurrent TCP streams (32768 client-initiated, 32767 server-initiated), with a configurable per-session limit via `max_streams`.
- **High Throughput, Low Latency Impact**: Bulk transfers continue efficiently while latency-sensitive streams remain responsive. Stream fastopen combines the SYN with the first data payload in one flight, saving a round-trip on new streams.
- **mTLS Security**: Protocol confidentiality, integrity, and peer authentication rely on TLS 1.3 mutual authentication with an explicit trust set, without relying on the system CA store. On trusted networks, TLS can be disabled to reduce overhead.
- **Session Resumption**: On transport loss both sides suspend; the client reconnects and replays all unacknowledged frames in order over the new transport, so in-flight streams survive a brief disconnect transparently. Reconnect starts with an immediate attempt and falls back to exponential backoff.
- **Bidirectional Forwarding**: Forward and reverse port forwarding can run simultaneously over the same session with no separate control channel.
- **Thread Offloading**: Each session runs on a dedicated thread when `ENABLE_THREADS=ON`. Multiple parallel tunnels to the same peer spread load across CPU cores.
- **Hot Configuration Reload**: The configuration file can be reloaded at runtime without restarting the process. TLS certificates, keys, and trust roots are rotated for newly accepted sessions and future outbound reconnects immediately.
- **Built-in Observability**: Health checks, text stats, and Prometheus-compatible metrics expose runtime status and traffic counters.
- **Fair Bandwidth Sharing**: A deficit round-robin (DRR) scheduler distributes outbound bandwidth fairly across active streams at byte granularity, so no single stream can starve the rest.
- **Two-Level Flow Control**: A per-stream sliding receive window limits in-flight data per stream; a session-wide unacked-frame cap halts new payload scheduling while retransmits and control frames still pass through, so a slow peer cannot deadlock the session.
- **Memory Throttling**: Receive window grants are linearly throttled as aggregate buffer occupancy rises between `mem_pressure.lo` and `mem_pressure.hi`, limiting buffer growth under load.
- **Automatic Window Tuning**: A two-phase BDP estimator learns bandwidth and RTT from payload-driven PING/PONG cycles with no extra traffic. `STARTUP` grows the window aggressively until it is no longer the bottleneck; `TRACK` maintains it and re-enters `STARTUP` only when path capacity appears to have grown. Windows grow monotonically and granted credit is never clawed back.
- **TCP Half-Close Support**: FIN-based half-close behavior is preserved end to end across the tunnel.
- **Standards-compliant**: Built for ISO C11 and POSIX.1-2008, with additional features available on supported platforms.

## Architecture

### Port Forwarding

multiplexd supports simultaneous forward and reverse forwarding over a single mux session:

```
+---------+    +------------+    +------------+    +---------+
| Local   |    |            |    |            |    | Forward |
| Apps    |-n->|            |    |            |-n->| Target  |
+---------+    | multiplexd |-1->| multiplexd |    +---------+
+---------+    |  (client)  |    |  (server)  |    +---------+
| Reverse |<-n-|            |    |            |<-n-| Remote  |
| Target  |    |            |    |            |    | Apps    |
+---------+    +------------+    +------------+    +---------+
```

**Forward forwarding**: local apps connect to the client's `listen` address; the server forwards each mux stream to its `connect` target.

**Reverse forwarding**: remote apps connect to the server's `listen` address; the client forwards each mux stream to its `connect` target. The server can push connections to targets reachable only by the client.

### Protocol

multiplexd streams are ordered byte sequences with no framing, methods, or headers above the mux layer. The wire format is a fixed 8-byte frame header followed by an optional payload; a small set of control frames and a single hello exchange are the only shared session state. Compared to existing multiplexing protocols:

- **vs. HTTP/2 ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) / gRPC**: HTTP/2 and gRPC operate on requests and responses with mandatory HPACK-compressed headers; each stream carries exactly one HTTP transaction or RPC call with method routing and per-call metadata. multiplexd operates on raw octets with no request semantics, headers, or framing above the mux layer.
- **vs. SSH connection protocol ([RFC 4254](https://www.rfc-editor.org/rfc/rfc4254))**: SSH requires a `channel-open` request per stream that names the service and destination, adding a round-trip before any payload can flow and imposing per-stream framing overhead; multiplexd has no channel requests, no per-stream negotiation, and no service-layer framing — the target is fixed at session configuration time.

See [doc/spec.md](doc/spec.md) for the full wire protocol and state-machine specification.

### Implementation

The design prioritises transparent TCP semantics (full half-close support, session resumption invisible to applications), inter-stream fairness (DRR scheduling), and coexistence of bulk and interactive streams without latency inflation.

| Feature                    | multiplexd                                                                       | grpc-go streaming                                                                                         | OpenSSH port forwarding                                                    |
| -------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Stream model**           | Raw byte sequences; fixed 8-byte header                                          | One RPC call per stream; HPACK headers                                                                    | Named channel; `SSH_MSG_CHANNEL_DATA` frames                               |
| **New stream setup**       | SYN + first data in one flight; no per-stream round-trip                         | HEADERS frame; no per-stream round-trip                                                                   | `channel-open` + `channel-open-confirmation`; one RTT before first payload |
| **TCP half-close**         | FIN end-to-end transparent                                                       | END_STREAM bound to RPC lifecycle; no general TCP half-close semantics                                    | Channel EOF maps to TCP FIN; half-close preserved                          |
| **Session resumption**     | Transparent; unacknowledged frames replayed                                      | None                                                                                                      | None                                                                       |
| **Inter-stream fairness**  | Deficit round-robin scheduler; byte-granularity fairness                         | Round-robin scheduler; frame-granularity fairness                                                         | No inter-stream scheduling; systematically skewed under load               |
| **Flow control**           | Per-stream byte window + session-wide unacked-frame cap; cap blocks payload only | Per-stream byte window + connection-level byte window (both byte-based)                                   | Per-channel byte window only                                               |
| **Adaptive window tuning** | Two-phase BDP estimator (`STARTUP` / `TRACK`)                                    | Monotonic BDP estimator                                                                                   | Fixed; manual tuning                                                       |
| **Memory back-pressure**   | Linear throttle via `mem_pressure.lo` / `mem_pressure.hi`                        | None                                                                                                      | None                                                                       |
| **Config reload**          | Drains existing sessions in-process                                              | None built-in                                                                                             | Re-execs master; existing child processes drains naturally                 |
| **Observability**          | Health, stats, Prometheus metrics (built-in; no code changes)                    | channelz (internal introspection); OpenTelemetry / Prometheus via interceptors (requires instrumentation) | None                                                                       |

See [doc/impl.md](doc/impl.md) for runtime topology, send/receive paths, and maintainer-facing invariants.

## Generating Certificates

multiplexd includes a built-in certificate generator for creating self-signed or CA-signed certificates. This feature requires building with OpenSSL (`USE_TLS_LIBRARY=openssl`).

### Generate Self-Signed Certificates

```bash
# Generate client and server certificates with default RSA 4096 keys
multiplexd --gencerts client,server

# Specify a different server name
multiplexd --gencerts client,server --sni example.com

# Use ECDSA P-256 instead of RSA
multiplexd --gencerts client,server --keytype ecdsa --keysize 256

# Use Ed25519
multiplexd --gencerts mycert --keytype ed25519
```

### Generate CA-Signed Certificates

```bash
# First, generate a CA certificate
multiplexd --gencerts ca

# Then generate certificates signed by the CA, so only the CA certificate needs to be listed in authcerts for verification
multiplexd --gencerts client1,client2,client3 --sign ca
```

### Certificate Options

| Option       | Values              | Description                                                 |
| ------------ | ------------------- | ----------------------------------------------------------- |
| `--gencerts` | name[,name...]      | Comma-separated list of certificate names to generate       |
| `--sni`      | hostname            | Server name for certificates (default: example.com)         |
| `--sign`     | name                | Sign certificates with existing name-cert.pem, name-key.pem |
| `--keytype`  | rsa, ecdsa, ed25519 | Key algorithm (default: rsa)                                |
| `--keysize`  | bits                | Key size: RSA 4096 (default); ECDSA 224/256/384/521         |

Generated files: `<name>-cert.pem` and `<name>-key.pem`.

## Configuration

Configuration files are JSON objects. At least one of `mux_listen`, `mux_connect`, or `identity.mux_connect` must be present. The optional `type` field, when present, must be `application/x-multiplexd-config; version=1`. See [`conf_schema.json`](conf_schema.json) for the complete reference, including options, types, defaults, and fixed validation ranges.

Because JSON has no comments, multiplexd ignores any key whose name begins with `-`. The sample [`client.json`](client.json) and [`server.json`](server.json) files use this to carry template-only tuning notes such as `-mux`; these keys are skipped at load time and do not affect the running configuration.

### Server (server.json)

```json
{
    "mux_listen": "0.0.0.0:8443",
    "connect": "127.0.0.1:1080",
    "tls": {
        "cert": "@server-cert.pem",
        "key": "@server-key.pem",
        "authcerts": ["@client-cert.pem"]
    }
}
```

### Client (client.json)

```json
{
    "mux_connect": "server.example.com:8443",
    "listen": "127.0.0.1:1080",
    "tls": {
        "cert": "@client-cert.pem",
        "key": "@client-key.pem",
        "authcerts": ["@server-cert.pem"]
    }
}
```

Omit the `tls` object entirely only on trusted networks where lower overhead is worth giving up protocol confidentiality, integrity, and peer authentication.

**TLS**: `cert`, `key`, and `authcerts` must all be present or all absent. The `@path` prefix loads a PEM file at startup; bare strings are treated as inline PEM. Mutual authentication (mTLS) is always enforced — the system CA store is never consulted.

### Multi-Peer Routing (`identity` block)

The `identity` block lets a node advertise its own identity and maintain simultaneous sessions with multiple named peers.

- `identity.claim` is this node's identity string, sent in every mux hello.
- `identity.mux_connect` is a list of mux endpoint addresses to dial. One outbound session is created per address, and the peer's identity is learned from the `ServerHello`.
- `identity.listen` maps peer identities to local TCP listen addresses. Each listener routes accepted connections over the session whose peer announced that identity.
- All inbound mux streams, regardless of peer identity, are forwarded to the root `connect` target.
- If `identity.mux_connect` or `identity.listen` is configured, `identity.claim` is required.

**Hub node** — accepts inbound mux sessions from multiple clients and exposes each remote peer as a dedicated local listener:

```json
{
    "mux_listen": "0.0.0.0:8443",
    "connect": "127.0.0.1:1080",
    "identity": {
        "claim": "hub-east",
        "listen": {
            "client-a": "127.0.1.1:8022",
            "client-b": "127.0.1.2:8022"
        }
    },
    "tls": {
        "cert": "@hub-east-cert.pem",
        "key": "@hub-east-key.pem",
        "authcerts": ["@ca-cert.pem"]
    }
}
```

**Spoke node** — dials out to multiple hub peers and exposes each as a local listener:

```json
{
    "connect": "127.0.0.1:22",
    "identity": {
        "claim": "client-a",
        "mux_connect": [
            "east.example.com:8443",
            "west.example.com:8443"
        ],
        "listen": {
            "hub-east": "127.0.0.2:1080",
            "hub-west": "127.0.0.3:1080"
        }
    },
    "tls": {
        "cert": "@client-a-cert.pem",
        "key": "@client-a-key.pem",
        "authcerts": ["@ca-cert.pem"]
    }
}
```

Traffic arriving on `127.0.1.1:8022` is sent over the session whose peer claimed `client-a`; traffic on `127.0.1.2:8022` goes to `client-b`. On the spoke, traffic arriving on `127.0.0.2:1080` is multiplexed over the session whose peer claimed `hub-east` and is forwarded to the remote node's root `connect` target; traffic on `127.0.0.3:1080` goes via `hub-west`.

### Parallel Tunnels

When `ENABLE_THREADS=ON`, each entry in `identity.mux_connect` runs on a dedicated thread. Repeating the same address opens multiple independent tunnels to that peer; new connections arriving on the matching `identity.listen` address are distributed across them round-robin.

```json
{
    "connect": "127.0.0.1:22",
    "identity": {
        "claim": "client-a",
        "mux_connect": [
            "east.example.com:8443",
            "east.example.com:8443",
            "east.example.com:8443"
        ],
        "listen": {
            "hub-east": "127.0.0.2:1080"
        }
    },
    "tls": {
        "cert": "@client-a-cert.pem",
        "key": "@client-a-key.pem",
        "authcerts": ["@ca-cert.pem"]
    }
}
```

This configuration opens three parallel tunnels to `east.example.com:8443`. Each tunnel saturates one CPU core independently, so aggregate throughput scales with the number of tunnels.

## Observability

multiplexd exposes a minimal HTTP API for health checks and runtime statistics. Enable it by setting `api_listen` in the configuration file:

```json
{
  "api_listen": "127.0.0.1:9090"
}
```

### Endpoints

#### `GET /healthy`

Returns `200 OK` with an empty body when the process is running. Suitable for load-balancer or container health probes.

```bash
curl http://127.0.0.1:9090/healthy
```

#### `GET /stats`

Returns a plain-text snapshot of runtime counters (no rate calculation).

#### `POST /stats`

Same as `GET /stats`, plus per-interval bandwidth rates and server CPU load derived from the time elapsed since the previous `POST /stats` call. Intended for periodic polling (e.g. every 10 s).

#### `GET /metrics`

Returns metrics in Prometheus exposition format, including cumulative counters and gauges for current session/stream counts and server load.

## Usage

```bash
# Run as server
./multiplexd -c server.json

# Run as client
./multiplexd -c client.json

# Run with colorful and very verbose output
./multiplexd -c config.json -C --loglevel 8

# Run in background and log to syslog, dropping privileges
./multiplexd -c config.json -u nobody: -d

# Dump resolved config with inlined PEM certificates to stdout
./multiplexd -c config.json --dump-config
```

## Building

### Dependencies

Required:
- libev (>= 4.31)
- json-c (>= 0.15)

Recommended (can be disabled by `USE_TLS_LIBRARY=none`); one of:
- OpenSSL >= 3.0
- mbedTLS >= 3.6

### Build Instructions

```bash
mkdir build && cd build
cmake ..
make
```

### Running Tests

```bash
cmake --build . --target check

# or rerun the registered tests directly
ctest --output-on-failure
```

For targeted reruns during development, pass a regex to `ctest -R`, for example `ctest --output-on-failure -R server_test`.

To build without TLS support:

```bash
cmake -DUSE_TLS_LIBRARY=none ..
```

### Convenience Builds

For common in-tree workflows, [`m.sh`](m.sh) wraps configure/build/test steps from the repository root:

- `./m.sh d` builds a debug configuration with sanitizers and threads enabled, then runs `ctest`
- `./m.sh r` rebuilds a release configuration with threads enabled
- `./m.sh posix` rebuilds with `FORCE_POSIX=ON`
- `./m.sh c` removes generated build artifacts

See the script for the full preset list, including clang, cross, min-size, and profiling builds.

### Build Options

| Option              | Default | Description                                                      |
| ------------------- | ------- | ---------------------------------------------------------------- |
| `USE_TLS_LIBRARY`   | auto    | TLS library to use (`auto`, `openssl`, `mbedtls`, `none`)        |
| `BUILD_STATIC`      | OFF     | Build a static executable (incompatible with sanitizers/systemd) |
| `BUILD_PIE`         | OFF     | Build a position-independent executable                          |
| `LINK_STATIC_LIBS`  | OFF     | Link against static libraries                                    |
| `ENABLE_SANITIZERS` | OFF     | Enable address/leak/undefined sanitizers (`BUILD_STATIC=OFF`)    |
| `ENABLE_SYSTEMD`    | OFF     | Enable systemd state notify (`BUILD_STATIC=OFF`)                 |
| `ENABLE_THREADS`    | OFF     | Enable multithread offloading                                    |
| `FORCE_POSIX`       | OFF     | Use POSIX.1 APIs only                                            |

### Developer Scripts

Run these helper scripts from the repository root:

- [`scripts/bench.py`](scripts/bench.py) runs the iperf3 benchmark suite and writes a Markdown summary to `build/bench.md`
- [`scripts/gcov.py`](scripts/gcov.py) configures a gcov coverage build, runs the test suite, and writes `build/gcov.md`
- [`scripts/gprof.py`](scripts/gprof.py) runs a focused gprof benchmark build and writes `build/gprof.md`

## Deployment Notes

### TLS Security Model

With TLS enabled, multiplexd uses TLS 1.3 with mutual certificate authentication and a closed trust store defined solely by `authcerts`. Each peer must present a certificate and matching private key, and a peer is accepted only if its certificate chains to a certificate explicitly configured in `authcerts`. Tunnel confidentiality, integrity, and peer authentication therefore depend on your provisioned certificate set, not on the system CA store, DNS names, or the public Web PKI.

Operational requirements:

- `authcerts` should contain only a private CA certificate or explicitly trusted peer certificates.
- A CA certificate in `authcerts` authorizes every peer certificate issued by that CA; a leaf certificate entry authorizes only that specific peer.
- Compromise of a trusted CA key or an endpoint private key compromises peer authentication.
- `*-key.pem` files and `--dump-config` output contain private key material and must be protected accordingly.

### Connection Backoff

The `max_startups` option (`start:rate:full` format) applies connection backoff on the mux listener to smooth bursts of incoming session attempts.

### API Server

`api_listen` exposes unauthenticated runtime statistics. **Bind it to the loopback address** (`127.0.0.1` or `::1`) or a Unix socket; never expose it to untrusted networks. A warning is logged at startup if a non-local address is configured.

### Configuration Reload

Sending SIGHUP reloads the configuration file and drains all existing sessions: each session stops accepting new inbound streams, completes its current streams gracefully, then reconnects with the updated configuration. Settings that can be changed with a SIGHUP include:

- `loglevel` — applied immediately.
- Live mux behavior applied to sessions before they drain: timeouts, keepalive, stream and session windows, `max_streams`, `max_halfopen`, `nodelay`, and `mem_pressure` thresholds.
- Admission controls: `max_sessions` and `max_startups`.
- Listener bind addresses (`listen`, `mux_listen`, `api_listen`): the listener is stopped and restarted on the new address.
- Forward target (`connect`) and outbound addresses (`mux_connect`, `identity.mux_connect`): reconnects after drain use the new address.
- TLS certificates, keys, trust roots, and TLS 1.3 cipher suites: applied to newly accepted sessions and future outbound reconnects.

## Credits

Thanks to:
- [libev](http://software.schmorp.de/pkg/libev.html)
- [json-c](https://github.com/json-c/json-c)
- [OpenSSL](https://www.openssl.org/)
- [mbedTLS](https://github.com/Mbed-TLS/mbedtls)
