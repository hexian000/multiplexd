# multiplexd - TCP Stream Multiplexer

[![MIT License](https://img.shields.io/github/license/hexian000/multiplexd)](https://github.com/hexian000/multiplexd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/multiplexd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/multiplexd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/multiplexd/total.svg)](https://github.com/hexian000/multiplexd/releases)
[![Release](https://img.shields.io/github/release/hexian000/multiplexd.svg?style=flat)](https://github.com/hexian000/multiplexd/releases)

multiplexd is a TCP stream multiplexer that solves most of the problems of tunneling TCP over TCP. By relaying application streams over a single, flow-controlled transport, it sidesteps the "TCP meltdown" of naive tunnels — and adds 0-RTT stream open, fair bandwidth sharing, flow-control with BDP estimation, transparent session resumption, and TLS 1.3 mutual authentication against a private trust store.

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
  - [Generate Self-Signed Certificate Chains](#generate-self-signed-certificate-chains)
  - [Certificate Options](#certificate-options)
- [Configuration](#configuration)
  - [Server (server.json)](#server-serverjson)
  - [Client (client.json)](#client-clientjson)
  - [Parallel Tunnels](#parallel-tunnels)
  - [Multi-Peer Routing (`identity` extension)](#multi-peer-routing-identity-extension)
  - [UDP Relay (`lossymux` extension)](#udp-relay-lossymux-extension)
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
  - [Power-Constrained Deployment](#power-constrained-deployment)
  - [Memory-Constrained Deployment](#memory-constrained-deployment)
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
- **Best-effort UDP relay**: With `mux.lossymux`, UDP datagrams share the session. Under congestion they are dropped, never queued behind TCP.

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
- **Portability**: ISO C11 and POSIX.1-2008 compliant.

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
| **Config reload**          | Updates live settings; normally drains existing sessions in-process               | None built-in                                                                  | Re-execs the master process; existing child processes drain naturally      |
| **Observability**          | Health check, plain-text stats, Prometheus metrics                               | channelz (internal introspection); OpenTelemetry / Prometheus via interceptors | Logging only                                                               |

See [doc/spec.md](doc/spec.md) for the full wire protocol and state-machine specification.

### Implementation

The design prioritizes transparent TCP semantics (full half-close support, session resumption invisible to applications), inter-stream fairness (DRR scheduling), and coexistence of bulk and interactive streams without latency inflation.

See [doc/impl.md](doc/impl.md) for runtime topology, send/receive paths, and maintainer-facing invariants.

## Generating Certificates

multiplexd includes a built-in certificate generator for creating self-signed certificates and certificate chains rooted in a self-signed private CA. This feature requires building with OpenSSL (`USE_TLS_LIBRARY=openssl`).

### Generate Self-Signed Certificates

```bash
# Generate client and server certificates with default RSA 4096 keys
multiplexd --gencerts client,server

# Specify a different server name
multiplexd --gencerts client,server --sni example.com

# Use ECDSA P-256 instead of RSA
multiplexd --gencerts client,server --keytype ecdsa --keysize 256

# Use Ed25519 (OpenSSL peers only; mbedTLS cannot load such a certificate)
multiplexd --gencerts mycert --keytype ed25519
```

### Generate Self-Signed Certificate Chains

```bash
# First, generate a self-signed private CA certificate
multiplexd --gencerts ca

# Then generate certificates signed by this private CA, so only its certificate needs to be listed in authcerts for verification
multiplexd --gencerts client1,client2,client3 --sign ca

# For identity.verify, name each peer's identity explicitly; certificates carry none by default
multiplexd --gencerts client1,client2,client3 --sign ca --identity east-1,east-2,west-1
```

### Certificate Options

| Option       | Values              | Description                                                                                           |
| ------------ | ------------------- | ----------------------------------------------------------------------------------------------------- |
| `--gencerts` | name[,name...]      | Comma-separated list of certificate names to generate                                                 |
| `--sni`      | hostname            | Server name for certificates (default: example.com)                                                   |
| `--identity` | name[,name...]      | Identity URI subjectAltName (`multiplexd:<identity>`) per certificate, paired positionally with `--gencerts`. Omitting the option generates certificates carrying no identity, which is the default; an empty entry is the empty identity, itself a valid one. An identity `identity.verify` could never match — over 255 octets, or holding a control character — is rejected before any key is generated; one over 63 octets is accepted with a warning, since multiplexd itself claims at most 63. Required by `identity.verify`. |
| `--sign`     | name                | Sign generated certificates with the named signer (uses `<name>-cert.pem` and `<name>-key.pem`). The signer must be a CA certificate (basicConstraints `CA:TRUE`), such as one generated without `--sign`; signing with a leaf fails before anything is written. |
| `--keytype`  | rsa, ecdsa, ed25519 | Key algorithm (default: rsa). `rsa` and `ecdsa` certificates load on either TLS backend; `ed25519` ones are usable only where OpenSSL is in use, since mbedTLS does not support Ed25519 in X.509 — a daemon built against it rejects the certificate at startup (`X509 - Requested OID is unknown`). |
| `--keysize`  | bits                | Key size in bits: RSA 4096 (default, range 2048-16384); ECDSA 256 (default), 384 or 521, selecting NIST P-256/384/521. Not accepted with `--keytype ed25519`, whose key size is fixed: giving one makes certificate generation fail. |

Generated files: `<name>-cert.pem` and `<name>-key.pem`.

### Generating Pre-Shared Keys

`--genpsk` writes one key per name as `<name>.psk`, owner-readable only, and
logs each key's identity label so a packet capture can be matched back to a
peer. Unlike `--gencerts` it works on every TLS backend, not just OpenSSL.

```sh
# One key per peer *pair* -- both ends hold the same file.
multiplexd --genpsk 'hub-east~spoke-1,hub-east~spoke-2'
```

An existing file is never overwritten: regenerating a key silently would lock
out the peer still holding the old one.

`--genpsk`, `--gencerts` and `--dump-config` each run once in place of the
daemon, so they cannot be combined: giving more than one is an argument error.
Nor do they take the daemon's options: `-d` and `-u` are an argument error with
any of them, and `-c` with `--genpsk` or `--gencerts` (only `--dump-config`
reads a config). Likewise `--sni`, `--identity`, `--sign`, `--keytype` and
`--keysize` are an argument error without `--gencerts`. `--loglevel` combines
with anything.

**Always generate keys this way.** The identity label a peer puts on the wire
is derived from its key, so publishing it hands an attacker an offline oracle:
against 32 random octets that is meaningless, against a passphrase it is fatal.
The 32-octet minimum checks *length, not entropy* — `sha256("hunter2")` in hex
passes it and is worth about 20 bits.

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

**TLS**: Certificate mode requires `cert`, `key`, and a trust source: `authcerts`, `system_trust: true`, or both. With no TLS credentials or trust source, the transport is plaintext. The `@path` prefix loads a PEM file at startup; bare strings are treated as inline PEM. Mutual authentication (mTLS) is always enforced. `system_trust` defaults to `false`; see the [TLS Security Model](#tls-security-model) before enabling it.

**Pre-shared keys**: `tls.psk` replaces certificates entirely — it is mutually
exclusive with `cert`, `key`, `authcerts` and `system_trust: true`, and a PSK handshake sends no
certificate in either direction. It maps a peer identity to the key shared with
that peer:

```json
{
    "mux_listen": "0.0.0.0:9000",
    "connect": "127.0.0.1:8080",
    "identity": {
        "claim": "hub-east",
        "listen": { "spoke-1": "127.0.1.1:8022" }
    },
    "tls": { "psk": { "spoke-1": "@hub-east~spoke-1.psk" } }
}
```

The spoke names the same file after *its* peer, since one key belongs to a
pair rather than to either end:

```json
{
    "identity": {
        "claim": "spoke-1",
        "mux_connect": ["hub-east.example:9000"],
        "listen": { "hub-east": "127.0.0.2:1080" }
    },
    "tls": { "psk": { "hub-east": "@hub-east~spoke-1.psk" } }
}
```

Notes:

- Identity binding is automatic; `identity.verify` is a certificate-mode option
  and is rejected alongside `tls.psk`. A peer proves possession of the key its
  label names, so a claim that disagrees with the key used is refused before
  any stream. A peer claiming no identity stays unidentified, as in certificate
  mode.
- **When dialing, only the first entry is offered** — both TLS backends accept
  a single client-side PSK. A node that dials while holding several keys logs a
  warning naming the one it will use.
- A PSK is always bound to SHA-256 on either TLS backend.
- Values are lowercase hex or `@path`; a loaded file may end with a newline.
  `tls.sni` is not sent: the ClientHello carries no server name, since there
  is no certificate for it to select.

### Parallel Tunnels

When `ENABLE_THREADS=ON`, each entry in `identity.mux_connect` runs on a dedicated thread. Repeating the same address opens multiple independent tunnels to that peer; new connections arriving on the matching `identity.listen` address are distributed round-robin across those currently established, so one tunnel reconnecting does not cost any connections while another is up.

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

### Multi-Peer Routing (`identity` extension)

The `identity` block lets a node advertise its own identity and maintain simultaneous sessions with multiple named peers.

- `identity.claim` is this node's identity string, sent in every mux hello. Limited to 63 octets (UTF-8, NUL excluded); a longer value is rejected at config load or reload time. The hello's identity extension allows 255 octets on the wire and a peer's claim is still accepted up to that, but JSON escaping expands a claim by up to six bytes per octet, so claiming at the wire limit could outgrow the smallest configurable frame and leave the hello unsendable. The same 63-octet limit applies to `identity.listen` keys, which must match a peer's claim.
- `identity.mux_connect` is a list of mux endpoint addresses to dial. One outbound session is created per address, and the peer's identity is learned from the `ServerHello`.
- `identity.listen` maps peer identities to local TCP listen addresses. Each listener routes accepted connections over the session whose peer announced that identity.
- All inbound mux streams, regardless of peer identity, are forwarded to the root `connect` target.
- If `identity.mux_connect` or `identity.listen` is configured, `identity.claim` is required.
- `identity.verify` (default `false`) binds the claim to the certificate: a peer that claims an identity is accepted only if the certificate it presented carries `multiplexd:<identity>` (percent-encoded) as a URI subjectAltName. A peer claiming no identity is unaffected and stays unidentified. It requires TLS — enabling it without `tls.cert`, `tls.key` and either `tls.authcerts` or `tls.system_trust`, or in a build without TLS, is a startup error rather than being ignored. Generate matching certificates with `--identity`.

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

### UDP Relay (`lossymux` extension)

Enable `mux.lossymux` on **both** ends to relay UDP as well as TCP. It is a bilateral hello extension, so it stays inactive unless both peers enable it.

```json
{
    "mux_connect": "server.example.com:8443",
    "listen": "127.0.0.1:5353",
    "mux": {
        "lossymux": { "enabled": true, "idle_timeout": 60, "queue": 64 }
    }
}
```

- **Same addresses as TCP.** A UDP socket is bound on every `listen` and `identity.listen` address, on the same host and port as the TCP listener. The peer delivers each flow to its `connect` target over UDP, and replies return the same way. Reverse forwarding and identity routing work exactly as for TCP.
- **One flow per client address.** Each client address:port is a flow, pinned to one tunnel. A flow lasts until `idle_timeout` seconds (default 60) pass without a datagram in either direction.
- **Best effort.** Datagrams carry no retransmission, flow control or ordering guarantee beyond the TCP transport's own. A datagram is dropped, not delayed, in any of these cases:
  - `queue` datagrams (default 64) are already waiting to be sent on a session;
  - the session is down or reconnecting;
  - the datagram is larger than `mux.max_frame_size` minus 8 bytes (16376 by default).
- **Visible drops.** Drops appear in `/stats` (the "Datagrams" line) and in `/metrics` (`multiplexd_datagrams_dropped_total`).
- **Reload.** The UDP sockets follow their TCP listeners across reloads. A session negotiates `lossymux` at its handshake, so enabling it on a running pair takes effect as the sessions reconnect.

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

Metrics come in two flavours (lossymux adds `multiplexd_datagrams_total`, `multiplexd_datagram_bytes_total`, `multiplexd_datagrams_dropped_total`, `multiplexd_udp_flows` and their `multiplexd_session_*` counterparts):

- **Process-wide totals** — the unlabeled series, e.g. `multiplexd_send_buffered_frames`. These cover every tunnel, and monotonic counters keep accumulating across tunnel closures.
- **Per-tunnel series** — the `multiplexd_session_*` family, labeled `identity` (the peer's identity) and `tunnel` (a monotonic, never-reused per-process index that stays stable across a tunnel's reconnects). Paired directional values carry `direction="rx"` / `direction="tx"`.

A tunnel is only labeled once its peer's announced identity names an `identity.listen` entry — whether the session was accepted on that listener or dialed from `identity.mux_connect`. Tunnels outside any identity, such as the top-level `mux_connect` session, inbound sessions from unconfigured peers, and dial-outs to a peer with no `identity.listen` entry, are counted in the totals but emit no per-tunnel series. Configuring `identity.listen` is therefore what turns per-tunnel breakdown on, and it also bounds label cardinality to what the configuration declares.

Per-tunnel counters cover live tunnels; process-wide counters also retain activity from tunnels that have closed.

`multiplexd_session_stream_establish_latency_seconds` is a summary over each tunnel's most recent 256 **active-open** stream establishments — a passive open records no SYN-to-SYN|ACK latency and is never observed. Quantiles come from that sliding window; `_count` is the monotonic number of observations behind them, so it tracks neither `multiplexd_session_stream_open_total` nor the established-stream total. A server-role tunnel that only accepts streams therefore reports `_count 0` and no quantiles. There is no `_sum`, since the sliding window cannot produce one.

`multiplexd_session_reconnects_total` is emitted only for dialed tunnels: a session the peer opened never reconnects, so it would report a constant zero.

#### `GET /config`

Returns the currently active configuration as JSON. TLS private key material is **not** included: `tls.cert`, `tls.key`, and `tls.authcerts` are erased from memory once loaded into the TLS context, whether that happened at startup or at the most recent config reload, so they come back as empty strings over the API. (This differs from `--dump-config`, which runs before that erase and does inline the PEM.) Consequently the body of a `GET /config` cannot be fed straight back to `PUT /config` for a TLS-enabled config — supply the certificate references (`@path`) or PEM yourself.

#### `PUT /config`

Replaces the active configuration with the JSON body of the request and performs a hot reload, identical in effect to `SIGHUP` with a new config file except for `api_listen` (below). The body must carry the full configuration, including TLS credentials (as `@path` references or inline PEM), and is capped at the same 65535-byte maximum as a config file loaded from disk. The body cannot change `api_listen`: its value must equal the running one exactly (as written, not as resolved), and an `api_listen` added, removed or changed is refused with `403 Forbidden` and a `text/plain` explanation, applying nothing — only a `SIGHUP` reload of the config file can move the API listener, so a page that reaches a loopback API (e.g. through DNS rebinding) cannot re-expose it on another address. Returns `204 No Content` on success, `400 Bad Request` if the body fails to parse, `403 Forbidden` if it changes `api_listen`, or `500 Internal Server Error` if the configuration cannot be applied — for instance a listener fails to bind, or the server has received `SIGINT`/`SIGTERM` and is shutting down (an API connection opened earlier stays usable until shutdown finishes, but a reload is refused throughout). The running configuration is left unchanged in every failure case.

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

Such a build runs every connection in plaintext. A config that sets `tls.cert`, `tls.key`, `tls.authcerts`, `tls.system_trust: true` or a non-empty `tls.psk` makes it fail at startup rather than run unencrypted; the other `tls` keys are ignored.

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
- [`scripts/linearity_test.py`](scripts/linearity_test.py) runs a bidirectional throughput/CPU linearity benchmark across increasing bandwidth limits and writes `build/linearity_report.md`; it works on every TLS backend, and in plaintext on a build without TLS. Its own unit tests, [`scripts/linearity_test_test.py`](scripts/linearity_test_test.py), are registered with `ctest` when CMake finds a Python 3 interpreter
- [`scripts/lint.py`](scripts/lint.py) runs clang-tidy on production sources and writes `build/lint.md`
- [`scripts/smoke_test.py`](scripts/smoke_test.py) runs a multi-scenario end-to-end smoke test against live server/client topologies: byte-exact bidirectional transfers, high stream concurrency, TCP half-close, bulk/interactive (DRR) coexistence, the observability API, hot config reload, identity routing with parallel tunnels, randomised TCP fuzzing, session resumption across transport loss, and graceful shutdown under load (`--quick` for a fast run)

## Deployment Notes

### TLS Security Model

With TLS enabled, multiplexd uses TLS 1.3 with mutual certificate authentication. By default, only the private trust store in `authcerts` is used: each peer must present a certificate and matching private key, and its certificate must chain to a configured trust anchor.

`tls.system_trust` is an explicit opt-in, disabled by default. Enabling it adds the system PEM CA bundle to `authcerts`; `authcerts` may then be omitted, but `cert` and `key` are still mandatory. This authorizes certificates from a wider set of issuers, potentially including public Web PKI CAs, for **both inbound and outbound peers**. Certificate strength checks and mutual authentication still apply. Trust selection does not perform DNS hostname verification: `tls.sni` selects a server certificate but does not authenticate the tunnel's address. Keep a private trust store unless all issuers in the system bundle are suitable transport authenticators for this deployment.

With `system_trust` enabled, multiplexd loads a PEM CA bundle from `SSL_CERT_FILE` when set, or discovers one automatically. Failure to load the bundle is a startup/reload error, even if `authcerts` is also present. Reload the configuration after changing the bundle.

For example, a certificate-mode configuration using only the system bundle contains:

```json
"tls": {
    "cert": "@node-cert.pem",
    "key": "@node-key.pem",
    "system_trust": true
}
```

Add `"authcerts": ["@private-ca.pem"]` to trust a private CA alongside the system roots. `tls.psk` cannot be combined with certificate trust configuration, including `system_trust: true`.

Operational requirements:

- `authcerts` should contain only a private CA certificate or explicitly trusted peer certificates.
- A CA certificate in `authcerts` authorizes every peer certificate issued by that CA; a leaf certificate entry authorizes only that specific peer.
- Compromise of a trusted CA key or an endpoint private key compromises peer authentication.
- `*-key.pem` files and `--dump-config` output contain private key material and must be protected accordingly.
- By default the `identity` extension (`identity.claim`) is a self-declared routing key, not cryptographically bound to the presenting certificate. With a shared CA or `system_trust`, any peer holding a certificate accepted by that trust store can claim any identity string. Bind claims with `identity.verify` (below), or disable `system_trust` and list per-peer leaf certificates in `authcerts` instead of a shared CA. Every trusted issuer must enforce which `multiplexd:` identities it certifies when `identity.verify` is used; trusting more issuers also gives each of them authority to certify those identities.
- `identity.verify` binds the claim to the certificate: a claimed identity must appear as a URI subjectAltName `multiplexd:<identity>` (percent-encoded, RFC 5280 §4.2.1.6) in the certificate the peer presented on that transport. This makes a shared CA safe against peer-to-peer impersonation, since the CA decides which identity each certificate may claim. Enforcement is local and per-direction: an enforcing node interoperates with a non-enforcing one, and each side independently decides whether to check the other. The check runs before any stream is admitted, and again on every resume, so a reconnecting transport cannot inherit a session's verified identity without proving it.
- `identity.verify` does not deny an *unidentified* peer. A peer that claims nothing is still accepted if its certificate chains to a configured trust anchor, and reaches the root `connect` target; only identity-routed access is gated. Claiming the empty string is not the same as claiming nothing: it is an identity like any other, so it must be named by the certificate (`--identity ""`) to pass.
- Rolling `identity.verify` out: upgrade binaries first, then reissue certificates, then enable the option. The `identity` config object rejects unknown keys, so a config containing `identity.verify` fails to load on an older binary; adding the URI subjectAltName is inert on every version, since nothing reads subjectAltNames unless the option is on.

#### Certificate disclosure, and what PSK mode changes

TLS 1.3 encrypts both `Certificate` messages, so a passive eavesdropper learns
nothing. An *active* one does: the server sends its certificate in the first
encrypted flight, before it has seen the client's, so **anyone who can reach
`mux_listen` and complete a key exchange can read it** — no client certificate
needed. A hub's `identity.verify` subjectAltName is therefore public to
scanners. Spoke certificates are not: a dialing client verifies the server
against its configured trust store and aborts before sending its own.

There is no way around this within certificate mode. TLS 1.3 has no
post-handshake *server* authentication, no anonymous suites, and a fixed flight
order, so a server cannot defer its certificate until the client proves itself.

`tls.psk` removes the exposure at the root, sending no certificate at all. If
you must keep certificates, use opaque identity strings so a harvested SAN
reveals no topology, or restrict who can reach the listener at all (an address
allowlist, or an authenticated underlay).

Note that pinning per-peer leaf certificates in `authcerts` does **not** stop
one trusted peer from claiming another's identity: `authcerts` is a flat trust
list with no identity binding. Only `identity.verify` (or `tls.psk`) binds a
claim to the key that made it.

### Connection Backoff

The `max_startups` option (`start:rate:full` format, where `rate` is a percentage from 0 to 100) rate-limits incoming session attempts: the first `start` are accepted freely; beyond that, each new attempt is rejected with probability `rate%` until `full` is reached.

### Power-Constrained Deployment

- Set `mux.idle_timeout` to close unused dialed sessions and stop their keepalive traffic. Short timeouts can increase connection setup work and latency when traffic resumes; `0` disables idle closure.
- Set `mux.nodelay: false` to batch small writes, reducing frame processing and network activity at the cost of up to 40 ms of added delay.
- Keep `mux.keepalive` as high as your network allows to reduce periodic wakeups and traffic. Leave `mux.tcp.keepalive: false` to avoid duplicate probes.
- Leave `ENABLE_THREADS=OFF` unless you need parallel session processing across CPU cores. This avoids per-session threads and cross-thread dispatch, at the cost of CPU parallelism.

### Memory-Constrained Deployment

- Set positive `max_sessions` and `mux.max_streams` limits to bound session and per-session stream counts. Lower limits reduce concurrency; `0` means unlimited.
- Set smaller explicit `mux.stream_window` and `mux.session_window` values to reduce receive buffering and unacknowledged send data. Values are bytes, with a minimum of 65536; `0` selects automatic sizing. Smaller windows can reduce throughput on high-latency links.
- Set `mux.mem_pressure.hi` to a positive byte threshold to throttle new receive-window grants as per-session buffered data grows. `mux.mem_pressure.lo` starts throttling and defaults to half of `hi`. These thresholds do not impose a hard memory cap.

### API Server

`api_listen` exposes unauthenticated runtime statistics. **Bind it to the loopback address** (`127.0.0.1` or `::1`); never expose it to untrusted networks. A warning is logged if a non-local address is configured, both at startup and whenever a config reload changes `api_listen` to a new address.

### Configuration Reload

Send `SIGHUP` to reread the configuration file, or send new JSON to `PUT /config`. Changing `api_listen` requires `SIGHUP`; the API returns `403 Forbidden` for that change.

- Existing sessions normally finish their current streams before outbound sessions reconnect with the new configuration. Draining has no deadline, so long-lived streams can delay reconnection indefinitely.
- `loglevel`, mux timeouts, keepalive, and flow-control settings apply immediately. TLS credentials and outbound target changes take effect on new connections; `identity.verify` is checked at the next handshake.
- Lowering `max_sessions` preserves current sessions and blocks new reservations until usage falls below the limit. Set `0` for unlimited sessions.
- Removing an `identity.listen` peer closes its sessions and streams immediately.

## Credits

Thanks to:
- [libev](http://software.schmorp.de/pkg/libev.html)
- [OpenSSL](https://www.openssl.org/)
- [mbedTLS](https://github.com/Mbed-TLS/mbedtls)
