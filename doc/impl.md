# multiplexd Internals

This document explains the reference implementation at the level where code is
too local and the specification is too normative: ownership, runtime topology,
cross-file control flow, and invariants.

The protocol contract, wire rules, and interoperability requirements belong in
[spec.md](spec.md). Enum inventories, field layouts, and single-function
mechanics belong in headers and nearby code comments. This file keeps only the
behavior that is hard to reconstruct from one file at a time.

## Contents

- [Contents](#contents)
- [1. Scope and Navigation](#1-scope-and-navigation)
  - [1.1 Component Overview](#11-component-overview)
  - [1.2 Control Ownership by Subsystem](#12-control-ownership-by-subsystem)
- [2. Ownership Model](#2-ownership-model)
- [3. Runtime State Carriers](#3-runtime-state-carriers)
- [4. State Transition Reference](#4-state-transition-reference)
  - [4.1 Session Progression](#41-session-progression)
  - [4.2 Stream Progression](#42-stream-progression)
- [5. libev Watcher Topology](#5-libev-watcher-topology)
  - [5.1 Watcher Coupling Flags](#51-watcher-coupling-flags)
- [6. Hello Handshake Processing](#6-hello-handshake-processing)
- [7. Inbound Data Path](#7-inbound-data-path)
- [8. Outbound Data Path](#8-outbound-data-path)
- [9. Scheduler and Control Batching Internals](#9-scheduler-and-control-batching-internals)
  - [9.1 Two-Phase Scheduling Model](#91-two-phase-scheduling-model)
  - [9.2 Ready Queue Fairness Model (DRR)](#92-ready-queue-fairness-model-drr)
  - [9.3 Control Packing and Tombstones](#93-control-packing-and-tombstones)
- [10. Flow-Control Bookkeeping and Backpressure](#10-flow-control-bookkeeping-and-backpressure)
  - [10.1 Counter Roles](#101-counter-roles)
  - [10.2 Critical Gating Rule](#102-critical-gating-rule)
  - [10.3 ACK Grant Triggering](#103-ack-grant-triggering)
  - [10.4 Receive-Buffer Pressure and Auto Window](#104-receive-buffer-pressure-and-auto-window)
- [11. Delayed ACK and Coalescing Timer Behavior](#11-delayed-ack-and-coalescing-timer-behavior)
- [12. BDP Estimator](#12-bdp-estimator)
  - [12.1 Core Equations](#121-core-equations)
  - [12.2 Probe Lifecycle](#122-probe-lifecycle)
  - [12.3 `effective_bdp` Update Rules](#123-effective_bdp-update-rules)
  - [12.4 Window Update and Lifecycle](#124-window-update-and-lifecycle)
- [13. Two Local I/O Modes](#13-two-local-io-modes)
- [14. Error Handling and Reset Semantics](#14-error-handling-and-reset-semantics)
  - [14.1 Session-Fatal Conditions](#141-session-fatal-conditions)
  - [14.2 Stream Abort Behavior](#142-stream-abort-behavior)
  - [14.3 RST Transmission and Unknown-Stream Handling](#143-rst-transmission-and-unknown-stream-handling)
  - [14.4 Session-Fatal Namespace Violations](#144-session-fatal-namespace-violations)
- [15. Teardown, Reconnect, and Idle Policies](#15-teardown-reconnect-and-idle-policies)
  - [15.1 Inbound Session Admission Control](#151-inbound-session-admission-control)
- [16. Implementation Invariants for Maintainers](#16-implementation-invariants-for-maintainers)
- [17. Source Map (Implementation)](#17-source-map-implementation)
- [18. Counters Architecture](#18-counters-architecture)
- [19. Identity Extension](#19-identity-extension)
- [20. Tunnel Layer Threading Model](#20-tunnel-layer-threading-model)
  - [20.1 Ownership](#201-ownership)
  - [20.2 Cross-Loop Paths](#202-cross-loop-paths)
  - [20.3 Server-to-Tunnel Control Path](#203-server-to-tunnel-control-path)
  - [20.4 Synchronous Resume Lookup](#204-synchronous-resume-lookup)
  - [20.5 Close Event and Final Teardown](#205-close-event-and-final-teardown)
  - [20.6 Practical Invariants](#206-practical-invariants)
- [21. Configuration Reload](#21-configuration-reload)
  - [21.1 Synchronous Phase](#211-synchronous-phase)
  - [21.2 Drain Behavior](#212-drain-behavior)
  - [21.3 Asynchronous Reconnect](#213-asynchronous-reconnect)
- [22. Per-Tunnel Frame Allocation](#22-per-tunnel-frame-allocation)

## 1. Scope and Navigation

Use this file for:

- runtime topology across listener, tunnel, session, and stream;
- send and receive paths through queues, buffers, watchers, and timers;
- fairness, backpressure, delayed flush, and resume behavior;
- teardown and late-traffic handling that span multiple modules;
- maintainer-facing invariants that are easy to break during refactors.

Do not use this file for:

- normative protocol rules, frame semantics, or wire compatibility;
- exhaustive API or enum listings;
- field-by-field struct descriptions.

### 1.1 Component Overview

```mermaid
graph TD
  SERVER["server\n(main orchestrator)"]
  LISTENER["listener\n(TCP accept / connect)\n+ bidirectional forwarding"]
  TUNNEL["tunnel\n(session resumption)"]
  API_SERVER["api_server\n(observability)"]
  MUX["mux\npublic API facade"]

  subgraph session_grp["Session"]
    SESSION["session\n(state machine)"]
    DISPATCH["dispatch\n(RX demultiplexer)"]
    SCHED["sched\n(TX DRR scheduler)"]
    HANDSHAKE["handshake\n(hello negotiation)"]
    ESTIMATOR["estimator\n(BDP / RTT)"]
  end

  WIRE["wire\n(socket / TLS I/O)\n+ frame queues"]
  STREAM["stream\n(per-stream FSM)\n+ flow control"]

  SERVER --> LISTENER
  SERVER --> TUNNEL
  SERVER --> API_SERVER
  LISTENER --> MUX
  TUNNEL --> MUX
  MUX --> SESSION
  SESSION --> DISPATCH
  SESSION --> SCHED
  SESSION --> HANDSHAKE
  SESSION --> ESTIMATOR
  SESSION --> WIRE
  SESSION --> STREAM
  DISPATCH --> STREAM
  SCHED --> STREAM
```

This graph is the ownership map for the rest of the document: listener and
tunnel connect the process to the mux core;
session is the coordination object; dispatch, sched, handshake, estimator, and wire each own one slice of
behavior but coordinate only through session and stream state.

### 1.2 Control Ownership by Subsystem

| Question                                                  | Owning code            |
| --------------------------------------------------------- | ---------------------- |
| Session construction, transport lifecycle, suspend/resume | `mux.c`, `session.c`   |
| Receive parse, stream lookup, namespace checks            | `recv.c`               |
| Outbound fairness, control batching, delayed flush        | `sched.c`              |
| Hello parsing, capability latching, resume handshake      | `handshake.c`          |
| Adaptive window growth                                    | `estimator.c`          |
| Reconnect policy, cross-thread relay, top-level ownership | `tunnel.c`, `server.c` |
| Configuration reload sequencing and live drain dispatch   | `server.c`             |

## 2. Ownership Model

The public mux API is intentionally thin. Most entry points schedule or forward
work into session and stream internals rather than owning policy themselves.

| Surface                            | Underlying Behavior                                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `mux_new` / `mux_close`            | Construct and finally release the session coordination object, including watchers, queues, and counters wiring. |
| `mux_start` / `mux_attach_fd`      | Choose between accepted-session handshake, outbound connect, or resume re-entry.                                |
| `mux_open_stream` / `mux_stream_*` | Mutate per-stream state, but always under session ownership on one libev loop thread.                           |
| `on_accept`                        | The only admission control point for passive-open streams.                                                      |
| `on_resume`                        | May replace a transient accepted session with a suspended session that steals the new transport.                |
| `MUX_EVENT_CLOSED`                 | Notification only; ownership is released later by `mux_close()`.                                                |

All mux and stream transitions remain single-threaded. The tunnel layer exists
to preserve that invariant when the process hosts multiple sessions; the
threading rules live in §20.

## 3. Runtime State Carriers

| Object  | Owns                                                                                                                                                                | Implicit Consequence                                                                                                                          |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Session | transport fd/TLS state, session sendbuf and oobbuf, fixed receive ring, unacked list, retransmit cursor, stream table, ready queue, timers, optional stats pointers | It is the only place where dispatch, sched, handshake, estimator, and wire meet; none of those submodules owns transport state independently. |
| Stream  | send queue, receive ring sized by `recv_window`, flow-control counters, half-close/reset flags, local I/O mode, coalescing membership                               | A stream can be logically closed before it disappears from the table; tombstone retention keeps late traffic deterministic.                   |

State enums are defined in `session.h` and `stream.h`; the diagrams below retain
only the transitions whose runtime coupling is referenced elsewhere in this document.

## 4. State Transition Reference

### 4.1 Session Progression

```mermaid
stateDiagram-v2
  [*] --> INIT

  INIT --> CONNECT: outbound transport attached
  INIT --> HANDSHAKE: accepted transport
  INIT --> CLOSED: close before start

  CONNECT --> HANDSHAKE: TCP or TLS connected
  CONNECT --> CLOSED: connect or TLS setup failed

  HANDSHAKE --> ESTABLISHED: hello exchange completed
  HANDSHAKE --> CLOSING: graceful shutdown
  HANDSHAKE --> CLOSED: protocol or handshake error

  ESTABLISHED --> SUSPENDED: resumable transport loss
  ESTABLISHED --> CLOSING: graceful shutdown or non-resumable EOF
  ESTABLISHED --> CLOSED: fatal protocol or transport error

  SUSPENDED --> CONNECT: outbound reconnect attaches fd
  SUSPENDED --> HANDSHAKE: inbound resume steals new fd
  SUSPENDED --> CLOSED: resume timeout or resume failure

  CLOSED --> CONNECT: demand-triggered reconnect (idle-close or resume-timeout expiry)

  CLOSING --> CLOSE_WAIT: local shutdown completed
  CLOSING --> CLOSED: shutdown error

  CLOSE_WAIT --> CLOSED: peer EOF observed and finalized
  CLOSED --> [*]
```

The enum names are less important than the control handoff: outbound reconnect
returns through CONNECT, inbound resume re-enters HANDSHAKE on a different
transport, and terminal `session_reset` skips the suspend path entirely.
The public API exposes a simplified `enum mux_state` with four externally
visible states (`ESTABLISHED`, `CONNECT`, `CLOSED`, `SUSPENDED`) via
`mux_state()`, which collapses the internal `SESSION_HANDSHAKE` → `CONNECT`,
`SESSION_CLOSING`/`SESSION_CLOSE_WAIT` → `CLOSED`, and `SESSION_INIT` → `CONNECT`.
Entering `SESSION_SUSPENDED` is observable on both roles: dialed and accepted
sessions both emit `MUX_EVENT_SUSPENDED`, while reconnect policy remains a
tunnel-layer decision.

One additional entry into `SESSION_SUSPENDED` is not shown in the diagram: a
client session (`!accepted`) that has already received a `session_id` from the
server may transition directly from `SESSION_HANDSHAKE` to `SESSION_SUSPENDED`
on transport error. This preserves streams and the unacked list for replay even
if the session was never fully established.

### 4.2 Stream Progression

```mermaid
stateDiagram-v2
  [*] --> INIT: active opener
  [*] --> SYN_RECEIVED: passive opener

  INIT --> SYN_SENT: SYN or SYN|PUSH sent
  INIT --> CLOSED: close before SYN leaves host

  SYN_SENT --> ESTABLISHED: SYN|ACK received
  SYN_SENT --> CLOSED: abort or RST

  SYN_RECEIVED --> ESTABLISHED: local side attached and SYN|ACK sent
  SYN_RECEIVED --> CLOSED: reject, abort, or RST

  ESTABLISHED --> FIN_WAIT: local FIN sent
  ESTABLISHED --> CLOSE_WAIT: peer FIN received
  ESTABLISHED --> CLOSED: abort or RST

  FIN_WAIT --> CLOSING: peer FIN received
  FIN_WAIT --> CLOSED: abort or RST

  CLOSE_WAIT --> CLOSING: local FIN sent
  CLOSE_WAIT --> CLOSED: abort or RST

  CLOSING --> CLOSED: both FINs seen and recv drained
  CLOSED --> [*]
```

For non-INIT streams, `STREAM_CLOSED` is a protocol-visible tombstone rather
than immediate removal. The delayed-cleanup policy allows dispatch to suppress
duplicate late traffic without maintaining a separate retired-stream map.

The following two sequence diagrams document the scheduler and callback handoffs
at the key state transitions: active opener and graceful close.

```mermaid
sequenceDiagram
  participant App as Local app
  participant Stream as Local stream
  participant Sched as session_on_send
  participant Dispatch as Peer dispatch
  participant Accept as on_accept
  participant Peer as Peer stream

  App->>Stream: mux_open_stream()
  Stream->>Sched: sched_wake() (lp queue + EV_WRITE)
  Sched->>Sched: sched_drain_lp() visits STREAM_INIT
  alt send_queue already has payload
    Sched->>Dispatch: SYN|PUSH
  else no queued payload
    Sched->>Dispatch: SYN
  end
  Sched->>Stream: stream_mark_syn_sent()
  Dispatch->>Dispatch: dispatch_no_stream()
  Dispatch->>Accept: on_accept()
  Accept-->>Peer: stream_attach_fd() or stream_io_start()
  Peer->>Stream: SYN|ACK + credit grant
  Stream->>Stream: dispatch_by_stream()
  Stream->>Stream: stream_recv_window() then stream_start()
  Stream->>App: on_event(MUX_EVENT_STREAM_ESTABLISHED)
  Note over Stream,Peer: SYN_SENT / SYN_RECEIVED collapse into ESTABLISHED once the SYN|ACK path completes
```

```mermaid
sequenceDiagram
  participant AppA as Local app
  participant StreamA as Local stream
  participant Sched as Scheduler
  participant StreamB as Peer stream
  participant AppB as Peer app

  AppA->>StreamA: mux_stream_shutdown()
  StreamA->>Sched: sched_wake()
  Sched->>StreamB: FIN
  Sched->>StreamA: stream_mark_fin_sent()<br/>ESTABLISHED -> FIN_WAIT
  StreamB->>StreamB: stream_recv_fin()<br/>ESTABLISHED -> CLOSE_WAIT
  StreamB->>AppB: buffered data drains, then EOF becomes visible
  AppB->>StreamB: mux_stream_shutdown()
  StreamB->>Sched: sched_wake()
  Sched->>StreamA: FIN
  Sched->>StreamB: stream_mark_fin_sent()<br/>CLOSE_WAIT -> CLOSING
  StreamA->>StreamA: stream_recv_fin()<br/>FIN_WAIT -> CLOSING
  Note over StreamA,StreamB: stream_mark_closed() runs only after both FINs are seen and recv buffer has drained
```

## 5. libev Watcher Topology

| Owner                | Watcher                 | Drives                                                                                     | Runtime Coupling                                                                                                                                                                     |
| -------------------- | ----------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Session              | `w_socket`              | transport read/write                                                                       | gated by `rx_open` and `tx_pending` rather than watcher churn                                                                                                                        |
| Session              | `w_timeout`             | inactivity timeout; reset on every inbound frame; teardown after `mux.timeout`s of silence | participates in hard teardown paths                                                                                                                                                  |
| Session              | `w_keepalive`           | one-way keepalive PROBE frames (encrypted TCP-keepalive over the tunnel)                   | armed only on the steady-state path                                                                                                                                                  |
| Session              | `w_send_timeout`        | pending-send stall detection (disabled when OS provides TCP_USER_TIMEOUT)                  | meaningful only while the one-frame sendbuf is pending                                                                                                                               |
| Session              | `w_connect_timeout`     | outbound connection / TLS timeout                                                          | stops at connect or TLS setup completion; triggers close on expiry                                                                                                                   |
| Session              | `w_coalesce`            | delayed ACK / grant / Nagle expiry                                                         | owns the shared per-stream delay list and deferred session ACK budget                                                                                                                |
| Session              | `w_idle_timeout`        | client idle-close / lazy reconnect                                                         | feeds the upper-layer reconnect policy                                                                                                                                               |
| Stream (socket mode) | `socket.w_io`           | local fd recv/send pump                                                                    | present only when a real local fd is attached                                                                                                                                        |
| Stream (socket mode) | `socket.w_timeout`      | local send/connect stall detection                                                         | local-edge analogue of session send timeout                                                                                                                                          |
| Stream (direct mode) | `direct.w_io`           | synthesized `EV_READ` / `EV_WRITE`                                                         | user-visible readiness is derived from stream state rather than kernel fd readiness                                                                                                  |
| Server               | `w_sighup`              | config reload trigger                                                                      | fires `server_reload()` synchronously on the server loop                                                                                                                             |
| Server               | `w_sigint`, `w_sigterm` | graceful shutdown trigger                                                                  | stops listeners, dispatches `mux_shutdown()` to every tunnel, arms `shutting_down` flag for the `w_maintenance` deadline                                                             |
| Server               | `w_maintenance`         | shutdown deadline, sleep detection                                                         | fires every second; runs two tasks in priority order: (1) force-exit after 2 s when `shutting_down`; (2) on a wall-clock jump ≥ 15 s, call `tunnel_drop_transport()` on every tunnel |
| Server               | `w_async` (threads)     | cross-thread event relay                                                                   | drains the server-side dispatcher queue after tunnel-to-server async relay                                                                                                           |

Per-stream coalescing uses `delay_ticks` and `delay_pending` flags instead of
per-stream timers, keeping all delayed-grant state under the single
session-level `w_coalesce` clock.

### 5.1 Watcher Coupling Flags

| Flag            | Purpose                                                                                                                                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rx_open`       | gates `EV_READ` on `w_socket`; cleared on transport EOF or error                                                                                                                                         |
| `tx_pending`    | gates `EV_WRITE` on `w_socket`; set when sendbuf or oobbuf has frames to flush; also set by TCP FIN or TLS `close_notify` receipt to wake `session_on_send` into the graceful-close path                 |
| `sched_queue`   | `enum` (NONE/DRR/LP) on each stream; `DRR` is the data ready queue, `LP` is the low-priority lifecycle queue (INIT SYN / CLOSED cleanup) drained by `session_on_send`; the queues are mutually exclusive |
| `delay_pending` | marks membership in the shared coalescing delay list                                                                                                                                                     |
| `nagle_flush`   | one-shot small-frame bypass after a delay-list expiry                                                                                                                                                    |

## 6. Hello Handshake Processing

The wire format is specified in [spec.md](spec.md); the implementation-specific
part is what the hello changes in runtime state.

| Decision point                        | Implementation consequence                                                                                                                                                                                                                                                |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stream 0 route                        | Hello, keepalive, and session ACK processing bypass the normal stream table.                                                                                                                                                                                              |
| `extensions.reject_inbound`           | Latches `peer_rejects_inbound_streams`, which blocks future active opener attempts.                                                                                                                                                                                       |
| Initial ClientHello                   | Server assigns the shared `session_id` and completes first-establishment handshake.                                                                                                                                                                                       |
| Resume ClientHello                    | `on_resume` may swap the transient accepted session for a suspended one that steals the new transport and replays unacked frames.                                                                                                                                         |
| ServerHello on the client             | Matching `session_id` + `resume_seq` confirms resume; otherwise the client drops old streams and adopts the new session identity.                                                                                                                                         |
| TLS `close_notify` received on client | Clears `has_session_id`; next reconnect starts a fresh session. Contrast: a plain TCP FIN retains `has_session_id` so resume is attempted. `close_notify` signals an explicit server-side teardown (e.g. version mismatch); a bare TCP FIN may be a dirty transport loss. |
| Handshake completion                  | Fires `MUX_EVENT_ESTABLISHED` or `MUX_EVENT_RESUMED` and re-arms steady-state watchers.                                                                                                                                                                                   |

The two sequence diagrams are kept separate because first establishment and resume
involve different ownership transfers, even though both conclude in the same
steady state.

```mermaid
sequenceDiagram
  participant Client
  participant CMux as Client session
  participant SMux as Server session

  Client->>CMux: mux_start()
  CMux->>CMux: connect_cb() then handshake_start()
  CMux->>SMux: ClientHello (no session_id)
  SMux->>SMux: handshake_process_hello()
  SMux->>CMux: ServerHello + session_id
  SMux->>SMux: session_handshake_done()
  Note over SMux: ESTABLISHED<br/>w_keepalive and w_coalesce armed<br/>on_event(MUX_EVENT_ESTABLISHED)
  CMux->>CMux: store server-assigned session_id
  CMux->>CMux: session_handshake_done()
  Note over CMux: ESTABLISHED<br/>w_keepalive and w_coalesce armed<br/>on_event(MUX_EVENT_ESTABLISHED)
```

```mermaid
sequenceDiagram
  participant Client as Suspended client session
  participant Transient as Transient server session
  participant Lookup as on_resume
  participant Suspended as Suspended server session

  Note over Client: the dialed tunnel supplies a new transport while SUSPENDED<br/>via immediate attempt 0, timer backoff, or demand-triggered reconnect
  Client->>Transient: ClientHello + session_id + resume_seq
  Transient->>Transient: handshake_process_hello()
  Transient->>Lookup: on_resume(session_id)
  Lookup-->>Transient: matching suspended session
  Transient->>Suspended: session_resume_transport(client_resume_seq)
  Suspended->>Suspended: unacked_resume_ack_recv()
  Suspended->>Suspended: steal fd, then reset transient session
  Suspended->>Client: ServerHello + session_id + resume_seq
  Suspended->>Suspended: session_handshake_done()
  Client->>Client: unacked_resume_ack_recv()
  Client->>Client: session_handshake_done()
  Note over Client,Suspended: retransmit_off=0 (head)<br/>remaining unacked frames replay<br/>on_event(MUX_EVENT_RESUMED)
```

On the normal transport-loss path, both peers have already emitted
`MUX_EVENT_LOST` then `MUX_EVENT_SUSPENDED` before this sequence begins. If the
accepted side has not noticed the break yet, `session_resume_transport()` forces
it through `SESSION_SUSPENDED` before stealing the new fd.

Resume replay may retransmit a prior SYN|ACK for a stream that has already
reached `STREAM_ESTABLISHED` or `STREAM_FIN_WAIT`. `dispatch_by_stream()` detects
this: it silently skips the SYN semantics (no second callback, no state
transition) but still applies the piggybacked ACK credit. This makes retransmit
replay safe even across streams whose opening handshake completed before the
transport was lost.

## 7. Inbound Data Path

```mermaid
flowchart LR
  A[transport read] --> B[session rx ring]
  B --> C{complete frame?}
  C -- no --> B
  C -- yes --> D{stream id == 0?}
  D -- yes --> E[hello / keepalive / session ACK]
  D -- no --> F{known stream?}
  F -- yes --> G[state-specific handler]
  F -- no --> H{opening SYN?}
  H -- yes --> I[passive-open / on_accept path]
  H -- no --> J[late traffic or namespace violation]
  G --> K[stream recvbuf]
  I --> K
  J --> L[RST once or session_reset]
  K --> M{local I/O mode}
  M -- socket --> N[attached fd EV_WRITE]
  M -- direct --> O[mux_stream_recv]
```

The ev callbacks an inbound byte crosses depend on local I/O mode. In the common
socket-mode case it is read by the transport watcher's `socket_cb` and written
out by the stream watcher's `local_cb` — two callbacks across two loop turns —
unless the recvbuf fast path drains it inline within the first callback.

```mermaid
sequenceDiagram
  autonumber
  participant Peer as Transport (mux fd)
  participant SCB as socket_cb (EV_READ)
  participant RB as stream recvbuf
  participant LCB as local_cb (EV_WRITE)
  participant App as Local fd

  Note over SCB: ev callback #1 — transport readable
  Peer->>SCB: session_on_recv → recv_one → wire_recv into session rx ring
  SCB->>SCB: dispatch_frame → dispatch_by_stream → handler
  alt direct mode
    SCB->>App: stream_feed_user, user pulls via mux_stream_recv
  else socket mode, recvbuf empty and fd writable
    SCB->>App: stream_recv_copy fast path: stream_local_write inline
  else socket mode, fd backpressured
    SCB->>RB: stream_recv_copy buffers the remainder
    SCB->>LCB: update_watcher arms EV_WRITE on the local fd
    Note over LCB: ev callback #2 — local fd writable
    RB->>LCB: local_cb → stream_flush_local drains recvbuf
    LCB->>App: stream_local_write
  end
```

| Design Constraint                                                                                                                                                                                                                                                         | Significance                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| The session receive ring is sized for `MUX_RECV_READAHEAD_FRAMES` (8) local full frames (`MUX_FRAME_HEADER_SIZE + max_payload`); it compacts when contiguous tail space runs out, grows on demand to assemble a single inbound frame larger than that, then shrinks back. | Receive-side work stays bounded for normal traffic without per-frame allocation, yet an oversized peer frame is still accepted. |
| Unknown non-zero streams split into opening SYN, retired-stream traffic, and namespace violations.                                                                                                                                                                        | Valid late traffic gets one terminal RST; session-level violations still close the whole session.                               |
| Socket mode normally spans `socket_cb` (EV_READ) then `local_cb` (EV_WRITE); the `stream_recv_copy` fast path collapses both into the first callback when the recvbuf is empty and the fd is writable.                                                                    | The extra loop turn only appears under local-fd backpressure, not on every frame.                                               |

**Frame-size asymmetry.** `max_payload` (config `max_frame_size`, default
16 KiB, clamped to `[MUX_MIN_FRAME_PAYLOAD, MUX_MAX_PAYLOAD_SIZE]`) bounds only
*outbound* framing: the send path chunks data into frames no larger than this,
and the implementation never emits an oversized frame. The receive path imposes
no matching limit — `dispatch_frame()` accepts any payload the 16-bit Length can
express (0–65535), growing the receive ring on demand to assemble a frame larger
than the local cap and shrinking it back afterward. The knob is therefore a
send-side chunking choice, not a negotiated wire limit (spec §2.3), so two peers
configured with different `max_frame_size` values interoperate. The sole place an
oversized inbound frame is rejected is an inbound PING whose payload exceeds
`max_payload`: it cannot be echoed into one of our own frames, so
`session_recv_ping()` closes the connection rather than send a truncated PONG
(spec §5.3.2).

## 8. Outbound Data Path

```mermaid
flowchart LR
  A[local producer] --> B{local mode}
  B -- socket --> C[local_on_recv]
  B -- direct --> D[mux_stream_send]
  C --> E[stream send_queue]
  D --> E
  E --> F[scheduler ready queue]
  F --> G{state + credit + Nagle}
  G -- blocked --> E
  G -- sendable --> H[sched_next_data]
  H --> I[session sendbuf: one frame max]
  I --> J[transport write]
  J --> K[session unacked list]
  K --> L[session ACK trim or resume replay]
```

Outbound mirrors the inbound shape. Local data is read by the stream watcher's
`local_cb` (or handed in directly via `mux_stream_send`), enqueued, and the
transport watcher's `session_on_send` later pulls it through `sched_next_data` onto the
wire — again two callbacks across two loop turns, unless `session_flush`'s
low-load fast path inlines `session_on_send` within the producing callback.

```mermaid
sequenceDiagram
  autonumber
  participant App as Local fd
  participant LCB as local_cb (EV_READ)
  participant SQ as send_queue + scheduler
  participant SCB as session_on_send (EV_WRITE)
  participant Peer as Transport (mux fd)

  Note over LCB: ev callback #1 — local fd readable
  alt socket mode
    App->>LCB: local_cb → socket_recv reads payload
    LCB->>SQ: stream_queue_send enqueues frame
    LCB->>SQ: session_eager_flush → sched_wake + session_notify (arm EV_WRITE)
  else direct mode
    Note over SQ: mux_stream_send enqueues from user context (no local_cb)
  end
  alt low-load fast path
    SQ->>SCB: session_flush inlines session_on_send (same callback)
  else under load
    Note over SCB: ev callback #2 — transport writable
  end
  SCB->>SCB: sched_drain_lp + send_pump → sched_next_data (state + credit + Nagle)
  SCB->>Peer: build one frame into sendbuf → wire_send
  SCB->>SCB: move frame to unacked list (ACK trim / resume replay)
```

| Design Constraint                                                                                                                                                           | Significance                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Socket-attached reads and `mux_stream_send()` feed the same per-stream send queue.                                                                                          | Local I/O mode does not change fairness or flow-control semantics.                                                     |
| `sched_next_data()` applies state, send credit, and Nagle as one dequeue gate.                                                                                              | A stalled sender can be blocked by any of the three; there is no single “sendable” bit.                                |
| The session sendbuf holds at most one frame at a time.                                                                                                                      | Transport backpressure interleaves with scheduling decisions and prevents a hot stream from monopolizing the socket.   |
| `w_send_timeout` matters only while that single frame remains pending.                                                                                                      | Send-stall detection tracks transport progress, not queue depth.                                                       |
| `session_eager_flush()` is called from socket-mode `local_cb()` after reading local data; if no transport I/O is already in flight it inlines `session_on_send()` directly. | Avoids one libev event loop iteration on the response path, halving round-trip latency for request/response workloads. |

## 9. Scheduler and Control Batching Internals

### 9.1 Two-Phase Scheduling Model

Both phases run inside `session_on_send` on the same `EV_WRITE` activation: the
lifecycle drain runs first, then the data pump.

| Phase                                        | Trigger                                                   | Work kept here                                                                                       | Why it is split this way                                                                 |
| -------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `sched_drain_lp()` (`session_on_send` entry) | `lp_pending` set and sendbuf clear (armed via `EV_WRITE`) | `STREAM_INIT` SYN / SYN\|PUSH, `STREAM_CLOSED` cleanup                                               | Batches lifecycle work so streams opened in one loop turn can launch together.           |
| `send_pump()` (`session_on_send` body)       | Transport became writable or was explicitly nudged        | sendbuf flush, retransmit replay, stream-0 out-of-band traffic, new control/data, per-stream ACK/FIN | Interleaves scheduling with socket backpressure instead of producing a long burst first. |

The lifecycle drain was formerly a separate `EV_IDLE` (`sched_cb`) barrier; it
now runs at the top of `session_on_send` so its frames coalesce into the same write. If
the sendbuf is still occupied when lifecycle work is queued, the drain is
deferred and the `session_on_send` epilogue (`sched_schedule()`) re-arms `EV_WRITE` once
the sendbuf clears.

When `send_stalled` is set, `EV_WRITE` stops scheduling fresh payload but still
flushes sendbuf, retransmit traffic, stream-0 control, and per-stream ACK/FIN
so the peer can drain the bottleneck. The `oobbuf` queue (PING/PONG
frames) is also exempt from `send_stalled`: the BDP estimator continues to
probe even during window exhaustion, which is exactly when an accurate BDP
reading is most needed.

Retransmit replay sends only PUSH data frames. `unacked_track_sent()` removes
stream-0 control frames (hello, standalone ACK, keepalive) from the unacked
list immediately after they are flushed to the wire, so they never appear in the
replay sequence. Replaying expired session-management traffic to a resumed peer
with fresh session state would be a protocol error.

### 9.2 Ready Queue Fairness Model (DRR)

| Step | Action                                                                                                                                                                    |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | Use `drr_active` if present; otherwise dequeue the next ready stream.                                                                                                     |
| 2    | On the first dequeue of the stream in a round, add one quantum (`session_max_payload(ss)`, the local max payload) to `deficit`.                                           |
| 3    | Send one PUSH frame and subtract its payload length from `deficit`.                                                                                                       |
| 4    | If the next queued frame still fits in `deficit`, keep the stream in `drr_active`; otherwise clear `drr_active` and re-enqueue it at the ready-queue tail (`sched_wake`). |
| 5    | Reset `deficit` when the stream drains; emit pending ACK/FIN after payload selection.                                                                                     |

| Mechanism                           | Invariant                                                                                                                   |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Tail re-enqueue                     | A stream that exhausts its budget is appended to the FIFO tail, so every other ready stream is served before it runs again. |
| `drr_active`                        | One stream may consume the rest of its quantum without a dequeue/re-enqueue round trip.                                     |
| Quantum = `session_max_payload(ss)` | Fairness is by bytes, not frames: many small frames and one full-size frame get the same byte budget per round.             |

### 9.3 Control Packing and Tombstones

| Mechanism                | Rule                                                                                                                                                                                                                                              | Rationale                                                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `sendbuf` / `oobbuf`     | stream-0 control frames (PROBE/PING/PONG) are queued in `oobbuf` and flushed alongside `sendbuf`; in-place compaction strips stream-0 frames from a packed sendbuf entry.                                                                         | Standalone ACK, FIN, RST, and keepalive traffic share one batching path through the transport write.               |
| Per-stream control flags | Per-stream ACK/FIN piggybacks are tracked by the stream's own `ack_pending`/FIN flags and emitted by `sched_send_ctrl_flags()` during DRR scheduling, or batched by `sched_flush_ctrl()` scanning the ready queue when no data frame is produced. | Streams that owe a credit grant or FIN emit one piggybacked header rather than a standalone frame.                 |
| Tombstone linger         | Non-INIT streams remain in the table for `MUX_TOMBSTONE_PERIOD_S` after `stream_mark_closed()`.                                                                                                                                                   | Dispatch can suppress duplicate late traffic and answer at most one final RST without a second retired-stream map. |
| INIT fast close          | Streams closed before a SYN leaves skip tombstone retention.                                                                                                                                                                                      | The peer never observed the stream id, so there is no late-traffic state to preserve.                              |

## 10. Flow-Control Bookkeeping and Backpressure

```mermaid
flowchart LR
  A[local producer] --> B[stream send_queue]
  B --> C{read credit / send credit\nstate / Nagle}
  C -- blocked --> B
  C -- sendable --> D[sched_next_data]
  D --> E[session sendbuf]
  E --> F[transport write]
  F --> G[session unacked list]
  G --> H{session ACK}
  H --> I[unacked_ack_trim]
  F --> J[inbound PUSH]
  J --> K[stream recvbuf]
  K --> L[local consumer]
  L --> M[stream_check_ack]
  M --> N[stream ACK / grant]
```

### 10.1 Counter Roles

| Counter set                     | Meaning                                                          | Implicit Invariant                                                                           |
| ------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `send_window`, `bytes_sent`     | cumulative peer grant vs cumulative payload sent                 | Send credit is tracked cumulatively; the implementation does not reason in per-frame grants. |
| `queued_send_bytes`             | payload accepted from the local producer but not yet transmitted | Read credit subtracts queued bytes as well as transmitted bytes.                             |
| `unacked_bytes`                 | in-flight payload associated with pending peer acknowledgement   | Coalescing and delayed-ACK logic cares about bytes already emitted, not just queue depth.    |
| `recv_window`, `buffered_bytes` | receive budget vs receive memory currently occupied              | Memory pressure scales grants without rewriting already-buffered data.                       |
| `grant_sent`, `bytes_received`  | already-advertised receive credit vs cumulative bytes delivered  | The next grant is derived from the delta, not from current buffer occupancy alone.           |

The most subtle gate is `stream_read_credit_avail()`: local socket reads stop
when `queued_send_bytes + bytes_sent` would exceed peer credit, so the sender
cannot over-admit data into `send_queue`.

On the receive side, window updates are quantized to `MUX_WINDOW_UNIT`, so up to
one full `session_max_payload(ss)` of over-window data is tolerated within
`recv_window`, which is the hard cap: `stream_recv_copy()` raises
`FLOW_CONTROL_ERROR` only when `buffered_bytes + payload_len` would exceed
`recv_window`. A peer may therefore hold slightly more credit outstanding than
the current window value without tripping a spurious error.

### 10.2 Critical Gating Rule

| Gate                  | Trips when                                                                                                         | Consequence                                                                                                                        |
| --------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Read credit           | `queued_send_bytes + bytes_sent >= send_window`                                                                    | Local socket reads stop before the peer grant is exhausted.                                                                        |
| Session send stall    | unacked bytes reach `session_window × MUX_WINDOW_UNIT` bytes                                                       | `EV_WRITE` stops scheduling fresh payload but still flushes sendbuf, retransmit traffic, stream-0 control, and per-stream ACK/FIN. |
| Expressible grant     | newly grantable credit is at least one `MUX_WINDOW_UNIT`                                                           | The `ack_pending` flag becomes meaningful only once the wire can represent the increment.                                          |
| Immediate ACK / grant | grantable credit reaches `2 * session_max_payload(ss)`, or `recv_seq - ack_seq >= clamp(session_window / 4, 2, 8)` | The implementation bypasses delayed ACK so both peers do not wait on each other's timers.                                          |

`unacked_ack_trim()` clears `send_stalled` and the receive path nudges the
scheduler only after a session ACK shrinks the unacked list below the cap.

### 10.3 ACK Grant Triggering

Grants follow three paths:

| Path                  | Condition                                                      | Wire shape                                                                              |
| --------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Immediate             | grantable credit reaches `2 * session_max_payload(ss)`         | Piggyback in the next data frame when possible; otherwise emit a standalone ACK header. |
| Delayed per-stream    | grant is expressible but does not meet the immediate threshold | Put the stream on the coalescing delay list and flush on the next coalescing tick.      |
| Immediate session ACK | `recv_seq - ack_seq >= clamp(session_window / 4, 2, 8)`        | Emit a session ACK immediately to relieve session-wide backpressure.                    |

### 10.4 Receive-Buffer Pressure and Auto Window

For `x = recv_buffered_bytes`, the receive-pressure scale is (with
`s_lo = conf.mux.mem_pressure.lo` and `s_hi = conf.mux.mem_pressure.hi`):

- `scale(x) = 1` for `x < s_lo`;
- `scale(x)` falls linearly from `1` to `1/8` for `s_lo <= x < s_hi`;
- `scale(x) = 1/8` for `x >= s_hi`.

`stream_grant_inc()` applies that scale and then enforces a one-unit floor for
any non-zero expressible grant, so receive pressure can slow credit growth but
cannot starve a live stream forever.

Automatic mode is opt-in per direction: `stream_window = 0` in config enables
`auto_stream_window`, and `session_window = 0` enables `auto_session_window`.
Either field may be auto without the other, but enabling either one activates
the shared BDP estimator (§12).  The estimator keeps an independent estimate
per link direction so asymmetric channel capacities yield independently sized
windows: `auto_stream_window` drives `stream_window` from the **rx** estimate
(`estimator.rx.effective_bdp`), while `auto_session_window` uses
`peer_stream_window` (updated on each SYN/SYN|ACK) as an initial floor and
then tracks the **tx** estimate (`estimator.tx.effective_bdp`) on each
PONG.  In auto mode the affected cap starts at `MUX_INITIAL_SEND_WINDOW /
MUX_WINDOW_UNIT` frames; `send_stalled` gates on `unacked_bytes >=
session_window × MUX_WINDOW_UNIT`, a byte-level cap that throttles payload
scheduling rather than closing the session.

Each direction is fed from its own source: inbound PUSH payload accumulates
into the rx sample via `estimator_add` (recv.c), and bytes that
`unacked_ack_trim` drains from the local `unacked` ring on an incoming session
ACK accumulate into the tx sample via `estimator_add_acked` (recv.c),
gated by the same `auto_stream_window || auto_session_window` condition.  The
tx sample reflects the sender's own achieved throughput × RTT (an "ack-clock"
BDP sample) and requires no inbound payload at all, so a near-pure sender
still grows its `session_window`.  See §12.1 for the per-direction equations.

## 11. Delayed ACK and Coalescing Timer Behavior

```mermaid
sequenceDiagram
  participant Peer
  participant Dispatch as dispatch_frame
  participant Stream as stream_recv_copy
  participant Timer as w_coalesce
  participant Sched as scheduler

  Peer->>Dispatch: PUSH
  Dispatch->>Dispatch: recv_seq++
  Dispatch->>Stream: queue payload
  Stream->>Sched: stream_check_ack()
  alt 2-frame grant
    Sched->>Peer: immediate ACK/grant
  else sub-threshold grant
    Sched->>Timer: arm delay list
    Timer->>Sched: tick expiry
    Sched->>Peer: delayed ACK/grant
  end
  alt session delta >= clamp(session_window / 4, 2, 8)
    Dispatch->>Peer: immediate session ACK
  else smaller delta
    Timer->>Peer: session ACK after at most 2 ticks
  end
```

One session-level timer, `w_coalesce`, serves both delayed-grant paths:

| Mechanism             | Arm condition                                             | Bound                                       | Effect on expiry                                                                                  |
| --------------------- | --------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Per-stream coalescing | stream placed on the delay list with `delay_ticks`        | `delay_ticks * 40 ms`                       | remove from the list, set one-shot `nagle_flush`, apply pending grant, and enqueue for scheduling |
| Deferred session ACK  | `recv_seq - ack_seq` stayed below the immediate threshold | `MUX_SESSION_ACK_MAX_TICKS * 40 ms` = 80 ms | emit a session ACK so the peer can trim its unacked list                                          |

This timer is shared, not per-stream. It starts after handshake completion,
restarts after resume handshake completion, and is stopped only when the
session leaves the steady-state path.

## 12. BDP Estimator

The estimator is active whenever `auto_stream_window` or `auto_session_window`
is enabled (`stream_window = 0` and/or `session_window = 0` in config).  It
learns a byte-granularity BDP **per link direction** from probe cycles driven
by either inbound PUSH payload (`estimator_add` → rx) or locally-sent bytes
that the peer has acked (`estimator_add_acked` → tx, called from
`unacked_ack_trim`).  Both directions share one PING/PONG probe cycle and the
RTT filter (RTT is inherently a round-trip quantity), but each keeps its own
bandwidth filter, BDP, `effective_bdp`, and STARTUP/TRACK phase, so an
asymmetric channel never sizes the slow direction's window from the fast
direction's bandwidth.  TCP handles congestion control; the estimator only
ensures the relevant windows stay ahead of the BDP:

- `session_update_stream_window` sets `stream_window` (when
  `auto_stream_window`) from the rx estimate on every PONG.
- `session_update_session_window` sets a floor for `session_window` (when
  `auto_session_window`) from `peer_stream_window` on every SYN/SYN|ACK, then
  tracks the tx estimate on every PONG.

```mermaid
flowchart LR
    A[inbound PUSH payload] --> B[estimator_add]
    B --> C["queue PING and accumulate rx sample"]
    A2["session ACK trims unacked ring"] --> B2[estimator_add_acked]
    B2 --> C2["queue PING and accumulate tx sample"]
    C --> D[PONG]
    C2 --> D
    D --> E["estimator_calculate (per direction d ∈ {rx, tx})"]
    E --> F["bdp[d] = bw_max[d] × rtt_min"]
    F --> G{"phase[d]"}
    G -- STARTUP --> H1["window_limited → ×3<br/>16 stable rounds → phase=TRACK"]
    G -- TRACK --> H2["bdp[d] > effective_bdp[d] → phase=STARTUP<br/>else effective_bdp[d] = bdp[d] × 1.25"]
    H1 & H2 --> I["session_update_stream_window (rx)"]
    H1 & H2 --> I2["session_update_session_window (tx)"]
    I --> J["stream_window = max(ceil(effective_bdp[rx] / MUX_WINDOW_UNIT), initial_frames)"]
    J --> K["grow: expand live stream recv_window immediately;<br/>shrink: lazily sync recv_window down in stream_check_ack once outstanding peer credit is consumed"]
    I2 --> O["session_window = max(peer_stream_window, ceil(effective_bdp[tx] / MUX_WINDOW_UNIT), initial_frames)"]

    L["inbound SYN or SYN|ACK"] --> M[peer_stream_window updated]
    M --> I2
```

### 12.1 Core Equations

`session_update_stream_window` and `session_update_session_window` convert
`effective_bdp` to frames with **ceiling** division, so even a 1-byte
headroom translates to at least one extra frame.

```text
rtt_min_ns = wndfilter_min(rtt_wnd, WND_RTT_MIN_NS) -- 600 s window, shared

-- per direction d ∈ {rx, tx}:
bw_sample[d]      = min(sample[d], clamp_max) × 1e9 / rtt_ns
bw_max[d]         = wndfilter_max(bw_wnd[d], WND_BW_MAX_NS) -- 86400 s window
bdp[d]            = bw_max[d] × rtt_min_ns / 1e9
demand[d]         = bw_sample[d] × rtt_min_ns / 1e9 -- sample normalized to one min-RTT
window_limited[d] = demand[d] + demand[d] / 2 > effective_bdp[d]
                                                -- demand > 2/3 target

-- STARTUP phase (bw_max[d] == 0 → no-op)
if window_limited[d]:
    effective_bdp[d] ×= 3 (capped at WNDSIZE_MAX); stable_rounds[d] = 0
else:
    stable_rounds[d]++
    if stable_rounds[d] >= STARTUP_STABLE_ROUNDS: phase[d] = TRACK

-- TRACK phase
if effective_bdp[d] != 0 and bdp[d] > effective_bdp[d]:
    phase[d] = STARTUP; stable_rounds[d] = 0 -- effective_bdp[d] left as-is
else:
    effective_bdp[d] = bdp[d] + bdp[d] / 4

initial_frames = MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT
stream_window  = max(ceil(effective_bdp[rx] / MUX_WINDOW_UNIT), initial_frames)
session_window = max(peer_stream_window, ceil(effective_bdp[tx] / MUX_WINDOW_UNIT), initial_frames)
```

The rx sample (fed by `estimator_add` from inbound PUSH payload) and the tx
sample (fed by `estimator_add_acked` from session-ACK-driven `unacked` ring
trims) share the same probe lifecycle: either one starts a cycle and queues a
PING, both accumulate independently while a PING is in flight, and a valid PONG
resets both to 0 at the end of the cycle (see
§12.2).  Beyond the shared cycle the directions never mix: each direction's
own sample drives its own `demand` and phase decisions, so a near-pure sender
(`sample[rx] ≈ 0`, `sample[tx] > 0`) gets the fast-startup ×3 ramp and TRACK
re-entry on its tx estimate while the idle rx estimate stays put.  `demand[d]`
is the per-direction sample **normalized to one min-RTT** (`bw_sample[d] ×
rtt_min_ns / 1e9`), not the raw byte count, so a transient RTT spike that
stretches a probe cycle and inflates `sample[d]` cannot trip spurious STARTUP
growth; for the same reason TRACK re-entry keys on the spike-immune `bdp[d]`,
not on `sample[d]`.  `clamp_max = INT_FAST64_MAX / 1e9` bounds each sample
before the `× 1e9` multiplication so neither can overflow `int_fast64_t`.

The `bw_wnd` 86400 s windows and the `rtt_wnd` 600 s window together act as a
natural floor: a measured peak bandwidth and minimum RTT persist for up to
their respective window sizes before an `effective_bdp` can fall materially
below the level it once supported.

Constants: `WNDSIZE_MAX = UINT16_MAX × MUX_WINDOW_UNIT`, `WNDSIZE_MIN = 4 × MUX_WINDOW_UNIT`, `STARTUP_STABLE_ROUNDS = 16`, `WND_BW_MAX_NS = 86400 s`, `WND_RTT_MIN_NS = 600 s`, `MUX_PING_RATE_LIMIT_NS = 1 s`.

### 12.2 Probe Lifecycle

| Event                                          | Effect                                                                                                                                                       |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| First eligible bytes with no probe in flight   | Start the calling direction's `sample = bytes`, queue PING with `last_probe_ns` payload, set `ping_in_flight`.                                               |
| More eligible bytes while PING is in flight    | Accumulate into the calling direction's `sample`; no static clamp — overflow guard applied during the `bw_sample` calculation.                               |
| `now − last_probe_ns < MUX_PING_RATE_LIMIT_NS` | Rate limit applies in every phase: skip without starting a probe; at most one cycle per `MUX_PING_RATE_LIMIT_NS` (1 s).                                      |
| Matching PONG (`sent_ns == last_probe_ns`)     | `estimator_calculate` updates the RTT filter and both directions' BW filters and `effective_bdp` per §12.3; advances `last_probe_ns` to gate the next probe. |
| Stale PONG (`sent_ns != last_probe_ns`)        | Discarded without updating any filter.                                                                                                                       |

The estimator has no dedicated timer and no probe timeout; probes are driven by
payload arrival and completed by a matching PONG.  An unanswered probe stays in
flight harmlessly: the ordered transport eventually delivers the PONG, and a
dead transport clears the state on suspend/disconnect.

### 12.3 `effective_bdp` Update Rules

Each valid PONG updates `rtt_wnd` (windowed-minimum RTT, shared) and then, for
each direction independently, `bw_wnd[d]` (windowed-maximum bandwidth); a zero
sample cannot raise a bandwidth peak.  `bdp[d]` is computed directly as
`bw_max[d] × rtt_min_ns / 1e9` without a separate BDP filter.
`effective_bdp[d]` is then adjusted according to that direction's phase
(`STARTUP` or `TRACK`), stored in `dir[d].phase`.

**STARTUP phase** — fast-start, searching for the bandwidth ceiling:

- **window_limited** (`demand[d] + demand[d]/2 > effective_bdp[d]`, i.e.
  `demand[d] > 2/3 × effective_bdp[d]`): the window is the throughput
  bottleneck; triple `effective_bdp[d]` (capped at `WNDSIZE_MAX`) and reset
  `stable_rounds[d]` to 0.
- **otherwise**: increment `stable_rounds[d]`; once it reaches
  `STARTUP_STABLE_ROUNDS` (16) consecutive non-window-limited cycles, the
  window is confirmed to have headroom — transition to TRACK.
- `bw_max[d] == 0` (no bandwidth sample yet): `effective_bdp[d]` is unchanged
  and `stable_rounds[d]` is not advanced.

**TRACK phase** — steady-state, tracking the current BDP:

- **Measured BDP outgrows the window** (`bdp[d] > effective_bdp[d]`, with the
  `effective_bdp[d] != 0` seed guard): link bandwidth has improved — re-enter
  STARTUP and reset `stable_rounds[d]` to 0, leaving `effective_bdp[d]`
  unchanged so STARTUP resumes growing from the current TRACK value. Keying on
  the spike-immune `bdp[d]` rather than the raw `sample[d]` avoids re-ramping
  on RTT jitter.
- **otherwise**: `effective_bdp[d] = bdp[d] + bdp[d] / 4`, where
  `bdp[d] = bw_max[d] × rtt_min_ns / 1e9`.

### 12.4 Window Update and Lifecycle

| Event                             | Result                                                                                                                                                                                                                                                                                                                                        |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Manual mode                       | The estimator is inert; configured frame counts are used as-is.                                                                                                                                                                                                                                                                               |
| Automatic `stream_window`         | `auto_stream_window = true`; effective `stream_window` starts at `initial_frames` and grows with the rx `effective_bdp` (fed by inbound PUSH payload); the `bw_wnd` 86400 s window buffers shrinks—the estimate cannot fall below the level it once supported until the old peak ages out.                                                    |
| Automatic `session_window`        | `auto_session_window = true`; `session_window` starts at `initial_frames`, is floored by `peer_stream_window` on each SYN/SYN\|ACK, and tracks the tx `effective_bdp` (fed by the session-ACK-driven ack-clock) on each PONG, so a pure sender grows it without any inbound payload (§12.1).                                                  |
| `session_update_stream_window()`  | `stream_window` is set to `max(ceil(effective_bdp[rx] / MUX_WINDOW_UNIT), initial_frames)`; live streams expand `recv_window` immediately on grow; on shrink, each stream's `recv_window` is lazily synced down by `stream_check_ack` once `buffered_bytes + outstanding ≤ target`.                                                           |
| `session_update_session_window()` | `session_window` is set to `max(peer_stream_window, ceil(effective_bdp[tx] / MUX_WINDOW_UNIT), initial_frames)`; on growth, clears `send_stalled` if `unacked_bytes` is now under the new limit and wakes the scheduler.                                                                                                                      |
| Disconnect / stop                 | `stream_window` is set to `max(CLAMP(effective_bdp[rx], WNDSIZE_MIN, WNDSIZE_MAX) / 2 / MUX_WINDOW_UNIT, initial_frames)` without modifying the estimator struct.  The learned RTT and bandwidth filters are preserved across reconnects; any in-flight probe is simply cleared (`ping_in_flight` reset) when the session leaves ESTABLISHED. |
| First enter auto mode on reload   | `estimator_init()` seeds both directions' `effective_bdp` from the current `stream_window * MUX_WINDOW_UNIT` and zeroes the rest of the estimator state.  Subsequent reloads that stay in auto mode preserve the learned state.                                                                                                               |

When `stream_window` decreases (TRACK trim to `bdp + bdp/4`, or manual reload), each
stream's `recv_window` is lazily synced to the new target inside
`stream_check_ack`: the shrink is applied as soon as
`buffered_bytes + outstanding ≤ target` (`outstanding = grant_sent − bytes_received`),
so the peer is never asked to respect a limit below what it has already been
granted.

## 13. Two Local I/O Modes

| Mode            | Local readiness source                                           | Outbound producer                             | Inbound consumer                        | Watchers                          |
| --------------- | ---------------------------------------------------------------- | --------------------------------------------- | --------------------------------------- | --------------------------------- |
| Socket-attached | kernel fd readiness                                              | attached-fd `EV_READ` pumps into `send_queue` | attached-fd `EV_WRITE` drains `recvbuf` | `socket.w_io`, `socket.w_timeout` |
| Direct          | `mux_stream_io_modify()` synthesizes readiness from stream state | `mux_stream_send()`                           | `mux_stream_recv()`                     | `direct.w_io`                     |

Both modes share the same queues, counters, ACK logic, and close semantics; the
only difference is how the local application edge is driven.

## 14. Error Handling and Reset Semantics

The wire rules live in [spec.md](spec.md#434--abrupt-shutdown). This section
keeps only the implementation-side reset path, late-traffic handling, and the
conditions that still escalate to whole-session failure.

### 14.1 Session-Fatal Conditions

| Trigger                            | Session-side result                                  |
| ---------------------------------- | ---------------------------------------------------- |
| Parse failure or transport failure | `session_reset()` → `SESSION_CLOSED`; non-resumable. |

### 14.2 Stream Abort Behavior

| Step                | Effect                                                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `stream_abort()`    | sends or schedules reset signaling, clears unsent data, discards buffered receive data, and closes stream state immediately                       |
| Stale-control purge | queued control headers for the same stream are removed before the reset path commits, so obsolete ACK/FIN traffic cannot precede the terminal RST |

### 14.3 RST Transmission and Unknown-Stream Handling

| Case                                               | Implementation result                                                                                                                                |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local live stream is aborted                       | discard stale queued non-RST frames for that stream, queue one RST with the chosen status, and transition the local stream state immediately         |
| Unknown-stream inbound RST                         | ignore it                                                                                                                                            |
| Retired-stream zero-length ACK or FIN              | ignore it                                                                                                                                            |
| Unknown-stream opening SYN                         | admit it through the passive-open path                                                                                                               |
| Valid non-SYN frame for an unknown non-zero stream | treat it as late traffic for a retired stream id, emit one terminal RST, remember that the id was already reset, then drop later duplicates silently |
| Late frame for an already closed live stream       | drop it in `dispatch_by_stream()` without reopening stream state                                                                                     |

This split keeps the session alive during stream teardown while still informing
the peer that the stream id is no longer live.

```mermaid
sequenceDiagram
  participant Stream as Local stream
  participant Session as Local session
  participant Dispatch as Peer dispatch
  participant Peer as Peer stream

  Stream->>Session: stream_abort(code)
  Session->>Session: session_discard_stream_frames(stream_id)
  Session->>Dispatch: RST + status
  Stream->>Stream: stream_stop(), state=CLOSED
  alt peer still has the stream
    Dispatch->>Peer: stream_recv_rst()
    Peer->>Peer: notify local side, discard recvbuf and send_queue
    Peer->>Peer: mark CLOSED
  else later valid non-SYN frame targets retired stream ID
    Peer->>Dispatch: non-SYN frame for unknown stream
    Dispatch->>Session: send RST once and remember stream_id
    Peer->>Dispatch: later duplicate late frame
    Dispatch->>Dispatch: drop silently
  end
```

### 14.4 Session-Fatal Namespace Violations

`dispatch_no_stream()` escalates to `session_reset()` only when the received
frame breaks session-level namespace invariants rather than merely targeting a
retired stream id.

| Violation                               | Why it is session-fatal                                                                                                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Invalid opening SYN flags               | an unknown stream may start only with `SYN` or `SYN \| PUSH`; anything else breaks the namespace before stream allocation even begins |
| Stream-id parity violation              | the peer used a stream id that is not legal for its endpoint role                                                                     |
| Reserved flag bits on an unknown stream | the frame is invalid at the session namespace boundary, not just at one stream                                                        |

These cases close the whole session immediately. They never enter
`SESSION_SUSPENDED`, so they are not resumable. Valid late non-SYN traffic for
a retired stream is handled by the single-RST path in Section 14.3 instead.

## 15. Teardown, Reconnect, and Idle Policies

| Situation                                                                           | Policy owner  | Outcome                                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Session teardown                                                                    | session layer | stop watchers first, then deep cleanup, then close transport, then hand control back to reconnect policy if applicable                                                                                                 |
| Resumable transport loss                                                            | session layer | enter `SESSION_SUSPENDED`, arm the resume timer, and emit `MUX_EVENT_SUSPENDED` on both dialed and accepted sessions                                                                                                   |
| Wall-clock jump ≥ 15 s detected by `maintenance_cb`                                 | server layer  | `tunnel_drop_transport()` shuts down the transport fd for every active tunnel; each session detects the loss via `MUX_EVENT_LOST` and `MUX_EVENT_SUSPENDED`; client tunnels re-dial via the normal transport-loss path |
| Dirty transport loss on a dialed tunnel with `idle_timeout == 0`                    | tunnel layer  | take immediate reconnect attempt 0 via `handle_transport_lost()` / `tunnel_do_connect()`                                                                                                                               |
| Dirty transport loss on an accepted tunnel                                          | tunnel layer  | observe `MUX_EVENT_SUSPENDED`, but do not start an outbound reconnect; wait for peer resume or timeout                                                                                                                 |
| Attempt 0 failed, or reconnect triggered from `MUX_EVENT_CLOSED` on a dialed tunnel | tunnel layer  | fall back to `tunnel_schedule_reconnect()` starting at 0.2 s and increment `reconnect_count`                                                                                                                           |
| Successful `MUX_EVENT_ESTABLISHED` or `MUX_EVENT_RESUMED` on a dialed tunnel        | tunnel layer  | reset `reconnect_count` to 0                                                                                                                                                                                           |
| Client idle timeout enabled                                                         | tunnel layer  | suppress attempt 0 and automatic CLOSED-time backoff; reconnect becomes demand-triggered from `open_stream_task()`                                                                                                     |
| Demand-triggered reconnect from `SESSION_CLOSED`                                    | tunnel layer  | `session_attach_fd()` accepts a new fd from `SESSION_CLOSED` (after idle-close or resume-timeout expiry), transitions to `SESSION_CONNECT`, and starts a new connection attempt                                        |
| Stream-id exhaustion                                                                | session layer | `session_open_stream()` returns `NULL`; session stays up and the caller retries after old streams leave the parity space                                                                                               |

### 15.1 Inbound Session Admission Control

The mux listener applies a three-layer guard (`is_startup_limited()`) before
creating an accepted tunnel:

| Layer | Config field                                 | Behavior                                                                                                                                                                                                             |
| ----- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | `max_sessions`                               | Hard cap on fully established sessions; excess connections are rejected immediately.                                                                                                                                 |
| 2     | `startup_limit_full`                         | Hard cap on half-open sessions; protects against SYN-flood-style connection floods.                                                                                                                                  |
| 3     | `startup_limit_start` / `startup_limit_rate` | Probabilistic shedding: once half-open count exceeds `startup_limit_start`, new connections are admitted with probability `1 − startup_limit_rate`. Provides graceful load reduction before the hard cap is reached. |

## 16. Implementation Invariants for Maintainers

| Invariant                                                                                                                      | Significance                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A budget-exhausted stream is re-enqueued at the ready-queue tail.                                                              | Tail re-enqueue keeps the DRR fairness boundary: every other ready stream is served before the re-enqueued one runs again.                                          |
| Read credit subtracts `queued_send_bytes` as well as transmitted bytes.                                                        | The local producer must not outrun peer credit by filling `send_queue` ahead of the wire.                                                                           |
| `nagle_flush` is one-shot.                                                                                                     | Delay expiry bypasses Nagle once, then normal gating resumes.                                                                                                       |
| Reset paths purge stale control before queuing RST.                                                                            | Obsolete ACK/FIN traffic must not precede the terminal reset.                                                                                                       |
| Cumulative counters rely on wrapping arithmetic.                                                                               | ACK, grant, and replay bookkeeping are expressed in cumulative domains rather than one-shot deltas.                                                                 |
| Stream 0 carries control traffic only.                                                                                         | Control routing must stay isolated from ordinary stream dispatch.                                                                                                   |
| `unacked_ack_trim()` treats `last_ack_recv` as cumulative; the session-ACK Extra field is an increment, not an absolute value. | Session ACK trim logic depends on cumulative progress, not on an echoed absolute sequence number.                                                                   |
| After `session_resume_transport()`, `retransmit_off` must point to the unacked-list head (0).                                  | Resume replay must start with the oldest unacked frame before any new traffic is enqueued.                                                                          |
| `recv_seq` is incremented before the per-stream handler runs.                                                                  | For sessions that survive, this matches the spec's processed-frame count; for frames that trigger `session_reset()`, the incremented value is never observed again. |

## 17. Source Map (Implementation)

| Concern                                                                                  | Files                                                                                        |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **Top-level orchestrators**                                                              |                                                                                              |
| Process supervisor, signal handling, config reload, statistics, API endpoints            | [src/server.c](../src/server.c), [src/server.h](../src/server.h)                             |
| Mux-listener accept loop and bidirectional forwarding                                    | [src/listener.c](../src/listener.c), [src/listener.h](../src/listener.h)                     |
| Session-per-thread tunnel, reconnect policy, cross-thread relay                          | [src/tunnel.c](../src/tunnel.c), [src/tunnel.h](../src/tunnel.h)                             |
| Built-in observability HTTP endpoints                                                    | [src/api_server.c](../src/api_server.c), [src/api_server.h](../src/api_server.h)             |
| **Mux core (`src/mux/`)**                                                                |                                                                                              |
| API wrappers and public entry points                                                     | [src/mux/mux.c](../src/mux/mux.c), [src/mux/mux.h](../src/mux/mux.h)                         |
| Session state machine, transport lifecycle, suspend/resume                               | [src/mux/session.c](../src/mux/session.c), [src/mux/session.h](../src/mux/session.h)         |
| BDP/RTT estimator                                                                        | [src/mux/estimator.c](../src/mux/estimator.c), [src/mux/estimator.h](../src/mux/estimator.h) |
| Stream queues, local I/O modes, half-close/reset behavior, flow-control accounting       | [src/mux/stream.c](../src/mux/stream.c), [src/mux/stream.h](../src/mux/stream.h)             |
| Frame header coding and frame-list helpers                                               | [src/mux/frame.c](../src/mux/frame.c), [src/mux/frame.h](../src/mux/frame.h)                 |
| Hello JSON encoding/parsing and handshake transitions                                    | [src/mux/handshake.c](../src/mux/handshake.c), [src/mux/handshake.h](../src/mux/handshake.h) |
| Receive layer (1/3): frame parse, stream dispatch, flow-control accounting               | [src/mux/recv.c](../src/mux/recv.c), [src/mux/recv.h](../src/mux/recv.h)                     |
| Schedule layer (2/3): ready-queue DRR fairness, lifecycle scheduling, coalescing timer   | [src/mux/sched.c](../src/mux/sched.c), [src/mux/sched.h](../src/mux/sched.h)                 |
| Send layer (3/3): producer drain (retransmit/OOB/DRR), frame packing, flush entry points | [src/mux/send.c](../src/mux/send.c), [src/mux/send.h](../src/mux/send.h)                     |
| Raw transport send/recv and shared session buffer ownership transitions                  | [src/mux/wire.c](../src/mux/wire.c), [src/mux/wire.h](../src/mux/wire.h)                     |
| Session-level reliability: unacked frame ring, retransmit and session-ACK bookkeeping    | [src/mux/unacked.c](../src/mux/unacked.c), [src/mux/unacked.h](../src/mux/unacked.h)         |

## 18. Counters Architecture

Aggregate counters are owned by the server and written through pointer blocks so
session hot paths never need to know the owning struct.

| Piece                         | Implementation rule                                                                                                                   |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `mux_session_counters`        | `mux.h` stores pointers into the server's flat counters; pointer types are atomic under `WITH_THREADS` and plain otherwise.           |
| Traffic subgroup              | `traffic` groups `byt_mux_recv`, `byt_mux_sent`, `byt_push_recv`, and `byt_push_sent` to mirror the flat `server_stats` layout.       |
| Update path                   | Sessions write counters directly through `COUNTER_ADD`; there is no snapshot aggregation phase.                                       |
| Stream-establish latency ring | `server_stats` keeps a fixed 256-entry ring and a monotonic counter; samples are written eagerly on `MUX_EVENT_STREAM_ESTABLISHED`.   |
| Read path                     | All aggregate reads go through `server_stats()`; per-session diagnostics are delivered by `on_event`, not by polling session objects. |

## 19. Identity Extension

The extension format is defined in [spec.md](spec.md); the implementation value
is that identity becomes a routing key.

| Item                                | Implementation note                                                                                            |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Hello payload                       | When configured, hello carries `extensions.identity = <claimed-id>` from `mux_session_opts.identity`.          |
| Latched state                       | The peer's identity is stored in `handshake_ctx.peer_identity` for the session lifetime.                       |
| Server-side routing                 | Accepted sessions are wired to the matching service listener by peer identity.                                 |
| Client-side routing                 | `handle_connected()` maps the peer identity returned in `ServerHello` to the matching `identity.listen` entry. |
| Config role: `identity.claim`       | local node identity, sent in every hello                                                                       |
| Config role: `identity.mux_connect` | one outbound mux session per entry                                                                             |
| Config role: `identity.listen`      | local listener keyed by peer identity                                                                          |
| Inbound mux streams                 | always forward to the root `connect` target regardless of advertised peer identity                             |

**Identity-bound certificate pinning (TLS).** Two trust layers combine. At the
TLS handshake the context trusts the *union* of the global `tls.authcerts` and
every per-identity `identity.authcerts.<peer>` certificate set, so any peer whose
certificate is in the union passes the handshake regardless of which identity it
later claims. After the session establishes, `server_on_established()` fetches
the peer certificate DER (`tunnel_peer_cert_der`) and calls
`server_check_identity_authcerts()`: when any `identity.authcerts` entries are
configured, the claimed `peer_identity` must have an entry whose certificate set
contains the presented certificate, otherwise the tunnel is closed (`"identity
not authorized by identity.authcerts"`). With no `identity.authcerts` configured
the check is a no-op and only the global union applies. This binds each
certificate to an identity, so a stolen key that clears the union handshake still
fails the post-handshake identity check (spec §10.1).

In client mode, one mux session per `identity.mux_connect` entry is created at
`server_start`; sessions are torn down in `server_stop` after the identity-based
wiring has been removed.

## 20. Tunnel Layer Threading Model

This section keeps only the ownership split and the crossings between the
server loop and tunnel loops. The mux core itself stays single-threaded per
session; the tunnel layer exists only to preserve that invariant while the
process hosts many sessions.

### 20.1 Ownership

| Owner                        | Owns or mutates                                                                                                  | How the other side reaches it                                                                                                    |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Server loop                  | listeners, signal watchers, `accepted_tunnels`, service-to-tunnel map, graceful shutdown state, relay dispatcher | tunnel loops relay events here; this is the only place that mutates process bookkeeping                                          |
| Tunnel loop (`WITH_THREADS`) | one mux session, all stream/session state under it, tunnel dispatcher, local inbound accept/connect path         | server loop submits control work through `dispatcher + ev_async`                                                                 |
| Resume lookup window         | `accepted_tunnels` under `accepted_mu`                                                                           | tunnel loop performs the only synchronous cross-thread query here; it does not gain shared access to mux state                   |
| Aggregate stats              | `server_stats` counters                                                                                          | updated from session threads atomically under `WITH_THREADS`, but counter writes do not transfer object ownership                |
| No-thread build              | server loop and tunnel loop collapse into one loop                                                               | dispatcher and relay become direct calls; wakeups, join, and shared-mutex resume lookup compile out, but ordering stays the same |

The local-only path stays on the tunnel loop: `tunnel_on_accept`, `stream_connect`,
and `mux_stream_attach` do not cross to the server loop.

### 20.2 Cross-Loop Paths

| Path                         | Primitive                                                  | Blocking | Rationale                                                        |
| ---------------------------- | ---------------------------------------------------------- | -------- | ---------------------------------------------------------------- |
| Server -> tunnel control     | `dispatcher + ev_async` via `t->disp` and `t->w_async`     | no       | start/config/open/shutdown must execute on the mux owner loop    |
| Tunnel -> server event relay | `dispatcher + ev_async` via `srv->disp` and `srv->w_async` | no       | session events must update server bookkeeping on the server loop |
| Resume lookup                | direct callback + shared `accepted_mu`                     | yes      | handshake needs an immediate answer before it can continue       |
| Final teardown               | `thrd_join()`                                              | yes      | last lifetime fence before freeing tunnel resources              |

Resume lookup and final teardown are the only synchronous cross-thread operations.
Ordinary event delivery, including `MUX_EVENT_CLOSED`, is asynchronous.

### 20.3 Server-to-Tunnel Control Path

`tunnel_dispatch()` is the write-side mailbox into the tunnel loop. It covers
startup, stream open, config/socket/TLS updates, shutdown, and the threaded
part of `tunnel_close()`.

```mermaid
sequenceDiagram
  participant S as Server loop
    participant TD as t->disp
    participant A as t->w_async
    participant T as Tunnel loop
    participant M as mux session

    S->>TD: dispatcher_invoke(task)
    S->>A: ev_async_send()
    T->>A: tunnel_async_cb()
    T->>TD: dispatcher_tick()
    TD->>M: task.func(task.data)
```

In `!WITH_THREADS`, the same ordering collapses into direct calls on the server
loop.

### 20.4 Synchronous Resume Lookup

Resume is the only cross-thread decision that cannot wait for the async relay
queue. The tunnel loop must synchronously ask the server loop whether a
matching accepted session exists in `accepted_tunnels`.

```mermaid
sequenceDiagram
  participant N as New tunnel loop
    participant H as Handshake parser
    participant TW as tunnel_on_resume wrapper
    participant S as server tunnel_on_resume
    participant MU as accepted_mu
    participant O as old accepted session

    N->>H: ClientHello(resume_seq, session_id)
    H->>TW: on_resume(new_ss, session_id)
    TW->>S: relay.cb.on_resume(...)
    S->>MU: shared lock
    S->>S: lookup accepted_tunnels[session_id]
    S->>O: validate accepted + state
    S->>MU: shared unlock
    alt match found
        S-->>TW: old mux_session
        TW-->>H: suspended session
        H->>O: session_resume_transport(...)
        H->>N: destroy transient session
    else no match
        S-->>TW: NULL
        TW-->>H: continue fresh handshake
    end
```

`accepted_mu` exists only for this lookup window. It protects table lifetime,
not general mux-session mutation.

### 20.5 Close Event and Final Teardown

Graceful shutdown starts from the server loop, but the actual `mux_shutdown()`
still runs on the owning tunnel loop. After `MUX_EVENT_CLOSED` is relayed back
to the server loop, `tunnel_close()` disconnects future relays, joins the
worker thread, then closes the session either on the worker or through the
server-side fallback path.

```mermaid
sequenceDiagram
  participant S as Server loop
    participant TD as t->disp
  participant T as Tunnel loop
    participant M as mux session
    participant RD as srv->disp

    S->>TD: tunnel_shutdown()
    T->>TD: dispatcher_tick()
    TD->>M: mux_shutdown()
    M->>T: reach MUX_EVENT_CLOSED
    T->>RD: enqueue CLOSED relay
    T->>T: tunnel loop stops, ev_run() returns
    S->>RD: relay_async_cb() + dispatcher_tick()
    S->>S: server tunnel_on_event(MUX_EVENT_CLOSED)
    S->>S: remove tables/maps entries
    S->>S: tunnel_close()
    S->>S: t->relay.cb = {0}
    alt teardown task still runs on worker
        S->>TD: task_tunnel_teardown
        S->>T: thrd_join()
        T->>M: mux_set_callbacks(0)
        T->>M: mux_close()
        T->>T: t->ss = NULL
    else worker already exited
        S->>T: thrd_join()
        S->>M: fallback mux_close(t->ss)
    end
    S->>RD: dispatcher_tick() to flush stale relay tasks
```

Forced stop adds one more relay-drain step before force-closing remaining
tunnels so a late `MUX_EVENT_CLOSED` cannot outlive the relay queue.

### 20.6 Practical Invariants

- Each mux session has exactly one execution loop at a time.
- All mux mutations happen on the tunnel loop, never directly on the server loop.
- Server bookkeeping stays on the server loop except for the shared-locked resume lookup.
- `accepted_mu` protects table lifetime, not general access to mux state.
- Normal event delivery is asynchronous; only resume lookup and `thrd_join()` block.

## 21. Configuration Reload

The reload sequence has a synchronous phase on the server event loop followed by an asynchronous drain-and-reconnect tail per session.

```mermaid
flowchart TD
  A([SIGHUP]) --> B[Parse new config from disk]
  B -- parse error --> Z1([Abort: keep running config])
  B -- ok --> C[Build new TLS contexts]
  C -- TLS error --> Z2([Abort: discard new config])
  C -- ok --> D[Dispatch drain to every live session]
  D --> E[Swap running config and TLS contexts]
  E --> F[Restart changed listeners]
  F --> G[Update routing tables]
  G --> H[Start any missing outbound sessions]
  H --> I([Free old config and TLS\nApply new log level])

  D -. per session, async .-> K[Apply live settings to existing session\nMark session as draining]
  K -. when last stream closes .-> L([Session closes and reconnects\nwith updated address and TLS])
```

### 21.1 Synchronous Phase

The synchronous phase runs entirely on the server event loop before SIGHUP handling returns.

| Stage            | Effect                                                                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Parse            | New config is read from disk. Any parse error aborts the reload and leaves the running config intact.                                                                           |
| TLS rebuild      | New TLS contexts are built from the new credentials. Any error aborts the reload.                                                                                               |
| Drain dispatch   | Each live session is told to drain asynchronously (see §21.2).                                                                                                                  |
| Config swap      | The new config and TLS contexts become the active ones before any listeners or sessions are created, so all subsequent accept and connect paths use the new config immediately. |
| Listener restart | Each listener whose bind address changed is stopped and restarted.                                                                                                              |
| Routing update   | The identity-peer listener table is rebuilt if the peer set changed.                                                                                                            |
| Session creation | Missing outbound sessions are started for any newly configured or previously closed slots.                                                                                      |
| Cleanup          | Old TLS contexts and config are freed; log level is updated.                                                                                                                    |

### 21.2 Drain Behavior

Each live session receives the updated settings and is marked draining before the synchronous phase completes. The following happen on the session's own loop:

- **Live settings applied immediately**: session timeouts, keepalive intervals, window sizes, `nodelay`, and memory pressure thresholds take effect for the existing session without a reconnect.
- **Outbound address updated**: the target address for reconnects is updated so the next connection attempt uses the new destination.
- **Drain armed**: the session stops admitting new inbound streams. When the last active stream closes, the session shuts down gracefully. A session already idle at drain time shuts down immediately.
- **Removed slots**: outbound sessions whose configuration slot was removed are prevented from reconnecting after they drain.

### 21.3 Asynchronous Reconnect

Once a drained session closes, the normal reconnect path (§15) re-dials using the updated address and the new TLS context from the already-swapped config. Accepted sessions do not reconnect; they are removed from the session table on close.

## 22. Per-Tunnel Frame Allocation

Each tunnel hands the mux core a per-tunnel `mux_frame_allocator` pointer block
(`tunnel_frame_alloc` / `tunnel_frame_free`), a thin wrapper over `malloc` /
`free` that sizes each object to the session's requested frame payload. There is
no shared server-wide pool, so frame allocation is contention-free per tunnel and
there is no server-level reclaim — the `w_maintenance` timer drains no frame pool.

Frame allocation on the send path can partially fail: `mux_stream_send()` chunks
the caller's buffer into frames one at a time and returns the number of bytes
actually enqueued, which may be less than requested if a frame cannot be
allocated. Callers must check the return value and retry or back off accordingly.
