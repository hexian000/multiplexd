# multiplexd - TCP Stream Multiplexer

[![MIT License](https://img.shields.io/github/license/hexian000/multiplexd)](https://github.com/hexian000/multiplexd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/multiplexd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/multiplexd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/multiplexd/total.svg)](https://github.com/hexian000/multiplexd/releases)
[![Release](https://img.shields.io/github/release/hexian000/multiplexd.svg?style=flat)](https://github.com/hexian000/multiplexd/releases)

multiplexd is a TCP stream multiplexer with 0-RTT stream open, fair bandwidth sharing, flow-control with BDP estimation, transparent session resumption, and TLS 1.3 mutual authentication against a private trust store.

**Table of Contents**
- [Features](#features)
  - [Protocol Efficiency](#protocol-efficiency)
  - [Reliability](#reliability)
  - [Performance and Fairness](#performance-and-fairness)
  - [Security and Operations](#security-and-operations)
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
    - [`GET /config`](#get-config)
    - [`PUT /config`](#put-config)
- [Usage](#usage)
- [Pre-built Binaries](#pre-built-binaries)
  - [Binary Variants](#binary-variants)
  - [Runtime Dependencies](#runtime-dependencies)
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

### Protocol Efficiency

- **Low frame overhead**: Fixed 8-byte frame header.
- **Zero-RTT stream open**: First data payload rides the open frame; no setup round-trip.
- **No per-stream negotiation**: Forward target fixed at session configuration time.
- **Up to 65535 concurrent streams per session**: 32768 client-opened plus 32767 server-opened, with a configurable `max_streams` limit. Scale further by adding sessions (additively via multiple parallel sessions, or multiplicatively via nested sessions).

### Reliability

- **Transparent session resumption**: Reconnect replays unacknowledged frames; active streams survive transport loss.
- **TCP half-close**: FIN semantics preserved end to end.
- **Bidirectional forwarding**: Forward and reverse forwarding over one session.

### Performance and Fairness

- **Deficit round-robin (DRR) scheduler**: Fair byte-granular bandwidth sharing across active streams.
- **BDP estimator**: Bidirectional, two-phase estimation sizes the send and receive windows independently, accommodating asymmetric links (uplink ≠ downlink).
- **Two-level flow control**: Per-stream receive window plus a session-wide unacknowledged-byte cap.
- **Memory back-pressure**: Receive grants throttle between `mem_pressure.lo` and `mem_pressure.hi`.
- **Multi-threaded offloading**: Per-session threads distribute load across CPU cores (`ENABLE_THREADS=ON`).

### Security and Operations

- **mTLS with private trust store**: TLS 1.3 mutual authentication; omittable on trusted networks.
- **Hot configuration reload**: `SIGHUP` reloads config and gracefully drains existing sessions.
- **Multi-peer routing**: The `identity` block maintains simultaneous sessions with multiple named peers.
- **Built-in observability**: Health check, plain-text stats, and Prometheus metrics endpoints.
- **Standards-compliant**: ISO C11 and POSIX.1-2008.

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

**Forward** — local apps connect to the client's `listen` address; the server forwards each mux stream to its `connect` target.

**Reverse** — remote apps connect to the server's `listen` address; the client forwards each mux stream to its `connect` target. The server can push connections to targets reachable only by the client.

### Protocol

The wire format is a fixed 8-byte frame header followed by an optional payload; a small set of control frames and a single hello exchange are the only shared session state. Compared to existing multiplexing protocols:

- **vs. HTTP/2 ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) / gRPC**: HTTP/2 and gRPC operate on requests and responses with mandatory HPACK-compressed headers; each stream carries exactly one HTTP transaction or RPC call with method routing and per-call metadata. multiplexd operates on raw octets with no request semantics, headers, or framing above the mux layer.
- **vs. SSH connection protocol ([RFC 4254](https://www.rfc-editor.org/rfc/rfc4254))**: SSH requires a `channel-open` request per stream that names the service and destination, adding a round-trip before any payload can flow and imposing per-stream framing overhead; multiplexd has no channel requests, no per-stream negotiation, and no service-layer framing — the target is fixed at session configuration time.

| Feature                    | multiplexd                                                                       | grpc-go streaming                                                              | OpenSSH port forwarding                                                    |
| -------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| **Stream model**           | Raw byte sequences; fixed 8-byte header                                          | One RPC call per stream; HPACK headers                                         | Named channel; `SSH_MSG_CHANNEL_DATA` frames                               |
| **New stream setup**       | SYN + first data in one flight; no per-stream round-trip                         | HEADERS frame; no per-stream round-trip                                        | `channel-open` + `channel-open-confirmation`; one RTT before first payload |
| **TCP half-close**         | FIN end-to-end transparent                                                       | END_STREAM bound to RPC lifecycle; no general TCP half-close semantics         | Channel EOF maps to TCP FIN; half-close preserved                          |
| **Session resumption**     | Transparent; unacknowledged frames replayed                                      | None                                                                           | None                                                                       |
| **Inter-stream fairness**  | Deficit round-robin scheduler; byte-granularity fairness                         | Round-robin scheduler; frame-granularity fairness                              | No inter-stream scheduler; fairness not guaranteed                         |
| **Flow control**           | Per-stream byte window + session-wide unacked-frame cap; cap blocks payload only | Per-stream byte window + connection-level byte window (both byte-based)        | Per-channel byte window only                                               |
| **Adaptive window tuning** | Per-direction 2-phase BDP estimator                                              | Monotonic BDP estimator                                                        | Fixed; manual tuning                                                       |
| **Memory back-pressure**   | Linear throttle via `mem_pressure.lo` / `mem_pressure.hi`                        | None                                                                           | None                                                                       |
| **Config reload**          | Drains existing sessions in-process                                              | None built-in                                                                  | Re-execs the master process; existing child processes drain naturally      |
| **Observability**          | Health check, plain-text stats, Prometheus metrics                               | channelz (internal introspection); OpenTelemetry / Prometheus via interceptors | Logging only                                                               |

See [doc/spec.md](doc/spec.md) for the full wire protocol and state-machine specification.

### Implementation

The design prioritizes transparent TCP semantics (full half-close support, session resumption invisible to applications), inter-stream fairness (DRR scheduling), and coexistence of bulk and interactive streams without latency inflation.

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

| Option       | Values              | Description                                                                                           |
| ------------ | ------------------- | ----------------------------------------------------------------------------------------------------- |
| `--gencerts` | name[,name...]      | Comma-separated list of certificate names to generate                                                 |
| `--sni`      | hostname            | Server name for certificates (default: example.com)                                                   |
| `--sign`     | name                | Sign generated certificates with the named signer (uses `<name>-cert.pem` and `<name>-key.pem`)       |
| `--keytype`  | rsa, ecdsa, ed25519 | Key algorithm (default: rsa)                                                                          |
| `--keysize`  | bits                | Key size in bits: RSA 4096 (default, range 2048-16384); ECDSA NIST P-224/256/384/521. Ignored when `--keytype ed25519`. |

Generated files: `<name>-cert.pem` and `<name>-key.pem`.

## Configuration

Configuration files are JSON objects. At least one of `mux_listen`, `mux_connect`, or `identity.mux_connect` must be present. The optional `type` field, when present, must be `application/x-multiplexd-config; version=1`. See [`conf_schema.json`](src/conf_schema.json) for the complete reference, including options, types, defaults, and fixed validation ranges.

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

Omit the `tls` object on trusted networks if the lower overhead outweighs the loss of protocol confidentiality, integrity, and peer authentication.

**TLS**: `cert`, `key`, and `authcerts` must all be present or all absent. The `@path` prefix loads a PEM file at startup; bare strings are treated as inline PEM. Mutual authentication (mTLS) is always enforced — the system CA store is never consulted.

### Multi-Peer Routing (`identity` block)

The `identity` block lets a node advertise its own identity and maintain simultaneous sessions with multiple named peers.

- `identity.claim` is this node's identity string, sent in every mux hello. Limited to 255 octets (UTF-8, NUL excluded), the wire limit of the hello's identity extension; a longer value is rejected at config load or reload time.
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

Returns `200 OK` with an empty body when every forwarding listener has a tunnel to forward over (or when none are configured). Returns `503 Service Unavailable` with a `text/plain` body listing the offline listeners (one `offline: <identity-or-listen-address>` line each) when any forwarding listener has no established tunnel — for example, a client tunnel whose peer is unreachable. Suitable for load-balancer or container health probes.

On-demand client tunnels (`idle_timeout > 0`) disconnect when idle by design, so they are never reported offline. Because a persistent tunnel is briefly down during initial connect and reconnect, configure probes with a `failureThreshold` to ride out transient blips.

```bash
curl http://127.0.0.1:9090/healthy
```

#### `GET /stats`

Returns a plain-text snapshot of runtime counters (no rate calculation).

#### `POST /stats`

Same as `GET /stats`, plus per-interval bandwidth rates and server CPU load derived from the time elapsed since the previous `POST /stats` call. Intended for periodic polling (e.g. every 10 s).

#### `GET /metrics`

Returns metrics in Prometheus exposition format, including cumulative counters and gauges for current session/stream counts and server load.

#### `GET /config`

Returns the currently active configuration as JSON. TLS private key material is **not** included: `tls.cert`, `tls.key`, and `tls.authcerts` are erased from memory once loaded into the TLS context, whether that happened at startup or at the most recent config reload, so they come back as empty strings over the API. (This differs from `--dump-config`, which runs before that erase and does inline the PEM.) Consequently the body of a `GET /config` cannot be fed straight back to `PUT /config` for a TLS-enabled config — supply the certificate references (`@path`) or PEM yourself.

#### `PUT /config`

Replaces the active configuration with the JSON body of the request and performs a hot reload, identical in effect to `SIGHUP` with a new config file. The body must carry the full configuration, including TLS credentials (as `@path` references or inline PEM), and is capped at the same 65535-byte maximum as a config file loaded from disk. Returns `204 No Content` on success or `400 Bad Request` if the body fails to parse.

## Usage

```bash
# Run as server
./multiplexd -c server.json

# Run as client
./multiplexd -c client.json

# Run with very verbose output
./multiplexd -c config.json --loglevel 8

# Run in background and log to syslog, dropping privileges
./multiplexd -c config.json -u nobody: -d

# Dump resolved config with inlined PEM certificates to stdout
./multiplexd -c config.json --dump-config
```

## Pre-built Binaries

Pre-built binaries are available on the [Releases](https://github.com/hexian000/multiplexd/releases) page. The naming convention is `multiplexd[-static].<arch>[-<vendor>]-<os>-<abi>`.

### Binary Variants

| Variant              | Linkage | Runtime Dependencies           |
| -------------------- | ------- | ------------------------------ |
| `-static`            | Static  | None — self-contained          |
| `-android`, `-win32` | Dynamic | System-provided libraries only |
| All others           | Dynamic | See table below                |

### Runtime Dependencies

Non-static builds require the following runtime libraries.

| Platform        | TLS Library | Install Command                 |
| --------------- | ----------- | ------------------------------- |
| Debian / Ubuntu | OpenSSL     | `apt install libev4 libssl3`    |
| Alpine Linux    | OpenSSL     | `apk add libev libssl3`         |
| OpenWrt         | mbedTLS     | `apk add libev libmbedtls`      |
| OpenWrt (opkg)  | mbedTLS     | `opkg install libev libmbedtls` |

## Building

### Dependencies

Required:
- libev (>= 4.31)

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

- `./m.sh gen` regenerates the C sources derived from JSON schemas (`*.gen.c` / `*.gen.h`). The generated files are committed to the repository, so builds without Python 3 are unaffected unless the schemas change.
- `./m.sh d` rebuilds a debug configuration with sanitizers enabled, then runs `ctest`
- `./m.sh r` rebuilds a release configuration
- `./m.sh posix` rebuilds with `FORCE_POSIX=ON`
- `./m.sh c` removes generated build artifacts
- `./m.sh` builds the existing configuration

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
| `ENABLE_THREADS`    | OFF     | Enable multi-threaded offloading                                 |
| `FORCE_POSIX`       | OFF     | Use POSIX.1 APIs only                                            |

### Developer Scripts

Run these helper scripts from the repository root:

- [`scripts/bench.py`](scripts/bench.py) runs the iperf3 benchmark suite and writes a Markdown summary to `build/bench.md`
- [`scripts/codesize.py`](scripts/codesize.py) builds a release configuration and writes a per-file object size report to `build/codesize.md`
- [`scripts/gcov.py`](scripts/gcov.py) configures a gcov coverage build, runs the test suite, and writes `build/gcov.md`
- [`scripts/gen_schema.py`](scripts/gen_schema.py) generates C structs, marshal/unmarshal functions, and perfect-hash key dispatchers from JSON Schema files (also invoked by `./m.sh gen`)
- [`scripts/gprof.py`](scripts/gprof.py) runs a focused gprof benchmark build and writes `build/gprof.md`
- [`scripts/linearity_test.py`](scripts/linearity_test.py) runs a bidirectional throughput/CPU linearity benchmark across increasing bandwidth limits and writes `build/linearity_report.md`
- [`scripts/lint.py`](scripts/lint.py) runs clang-tidy on production sources and writes `build/lint.md`
- [`scripts/smoke_test.py`](scripts/smoke_test.py) runs a multi-scenario end-to-end smoke test against live server/client topologies: byte-exact bidirectional transfers, high stream concurrency, TCP half-close, bulk/interactive (DRR) coexistence, the observability API, hot config reload, identity routing with parallel tunnels, randomised TCP fuzzing, session resumption across transport loss, and graceful shutdown under load (`--quick` for a fast run)

## Deployment Notes

### TLS Security Model

With TLS enabled, multiplexd uses TLS 1.3 with mutual certificate authentication and a private trust store defined solely by `authcerts`. Each peer must present a certificate and matching private key, and a peer is accepted only if its certificate chains to a certificate explicitly configured in `authcerts`. Tunnel confidentiality, integrity, and peer authentication therefore depend on your provisioned certificate set, not on the system CA store, DNS names, or the public Web PKI.

Operational requirements:

- `authcerts` should contain only a private CA certificate or explicitly trusted peer certificates.
- A CA certificate in `authcerts` authorizes every peer certificate issued by that CA; a leaf certificate entry authorizes only that specific peer.
- Compromise of a trusted CA key or an endpoint private key compromises peer authentication.
- `*-key.pem` files and `--dump-config` output contain private key material and must be protected accordingly.
- The `identity` extension (`identity.claim`) is a self-declared routing key, not cryptographically bound to the presenting certificate. If `authcerts` is a shared CA, any peer holding a certificate issued by that CA can claim any identity string; use per-peer leaf certificates in `authcerts` instead of a shared CA where distinct peers must not be able to impersonate each other's identity.

### Connection Backoff

The `max_startups` option (`start:rate:full` format, where `rate` is a percentage from 0 to 100) rate-limits incoming session attempts: the first `start` are accepted freely; beyond that, each new attempt is rejected with probability `rate%` until `full` is reached.

### API Server

`api_listen` exposes unauthenticated runtime statistics. **Bind it to the loopback address** (`127.0.0.1` or `::1`); never expose it to untrusted networks. A warning is logged if a non-local address is configured, both at startup and whenever a config reload changes `api_listen` to a new address.

### Configuration Reload

There are two ways to trigger a reload: send `SIGHUP` to the process, or issue a `PUT /config` request to the API server. Both are equivalent in effect. `PUT /config` accepts the new configuration as a JSON body instead of reading from the config file, which makes it scriptable without touching the filesystem.

On reload, all existing sessions drain: each session stops accepting new inbound streams, completes its current streams gracefully, then reconnects with the updated configuration. There is no timeout on the drain phase — a session with long-lived streams may remain open indefinitely. Settings that can be changed at runtime include:

- `loglevel` — applied immediately.
- Live mux behavior applied to sessions before they drain: timeouts, keepalive, stream and session windows, `max_streams`, `max_halfopen`, `nodelay`, and `mem_pressure` thresholds.
- Admission controls: `max_sessions` and `max_startups`.
- Listener bind addresses (`listen`, `mux_listen`, `api_listen`): the listener is stopped and restarted on the new address.
- Forward target (`connect`) and outbound addresses (`mux_connect`, `identity.mux_connect`): reconnects after drain use the new address.
- TLS certificates, keys, trust roots, and TLS 1.3 cipher suites: applied to newly accepted sessions and future outbound reconnects.

## Credits

Thanks to:
- [libev](http://software.schmorp.de/pkg/libev.html)
- [OpenSSL](https://www.openssl.org/)
- [mbedTLS](https://github.com/Mbed-TLS/mbedtls)
