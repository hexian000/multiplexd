# multiplexd Protocol Specification

## Abstract

This document specifies the multiplexd multiplexing protocol, which enables
multiple independent bidirectional byte streams to share a single transport
connection.  The underlying transport is either plain TCP or TLS 1.3.  The
protocol employs a fixed-size frame header, per-stream credit-based flow
control, and fairness requirements for outbound scheduling so that no single
stream monopolizes the transport connection.

## 1.  Introduction

This document defines the wire format, state machines, flow-control rules,
session lifecycle, and error-handling requirements of the multiplexd protocol.
The protocol is designed to be simple, efficient, and amenable to formal
verification.

### 1.1.  Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

### 1.2.  Notational Conventions

All multi-byte integer fields are transmitted in network byte order (big-endian)
unless otherwise stated.

The hyphenated form "stream-0" is used as a compound adjective (as in
"stream-0 frames"); the numeric ID itself is referred to as "stream 0" in
prose.

### 1.3.  Terminology

The following terms are used throughout this document:

- **client**: the endpoint that initiates the transport connection.

- **server**: the endpoint that accepts the transport connection.

- **endpoint**: either participant in a multiplexd session, without regard to
  which side initiated the transport connection.

- **session**: the protocol context shared by both endpoints over a single
  transport connection, including all associated streams and state.

- **stream**: a single ordered, bidirectional sequence of octets multiplexed
  within a session.

- **frame**: the basic unit of data exchanged between endpoints, consisting
  of an 8-octet header and an optional payload.

## 2.  Frame Format

### 2.1.  Frame Header

Every frame begins with a fixed 8-octet header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Flags     |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Stream ID           |             Extra             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field     | Size     | Description                                          |
| --------- | -------- | ---------------------------------------------------- |
| Version   | 1 octet  | Protocol version; see Section 2.2                    |
| Flags     | 1 octet  | Frame flags; see Section 3                           |
| Length    | 2 octets | Payload length in octets; range 0-16384              |
| Stream ID | 2 octets | Stream identifier; see Section 4.1                   |
| Extra     | 2 octets | Context-dependent field; interpreted per Section 2.4 |

### 2.2.  Version Field

The Version field identifies the protocol version of the frame.  In regular
mux frames, it MUST equal the negotiated protocol version (currently 1).

Value 0 is reserved for hello frames (Section 5.2.1) and MUST NOT appear in
regular mux frames.  Receivers MUST close the connection if a regular mux
frame carries Version 0, or if any frame carries an unrecognized version
value.

### 2.3.  Frame Payload

The header is followed by exactly Length octets of payload.  When Length is
zero, the frame carries no payload.  The maximum payload size is 16384 octets
(16 KiB).

### 2.4.  Extra Field Encoding

The Extra field is a 16-bit unsigned integer whose interpretation depends on
the frame flags.

#### 2.4.1.  Credit-Grant Encoding (SYN / ACK)

When RST is clear and either ACK is set or SYN is set with FIN clear, Extra
is interpreted as a Window Increment in units of 16384 octets.  A value of W
grants the peer W * 16384 additional octets of send credit beyond any credit
previously granted.

Each endpoint accumulates received increments into its cumulative send credit
(see Section 6.1); the cumulative total represents the maximum number of
payload octets the endpoint is permitted to transmit on the stream.

The minimum representable non-zero increment is 16384 octets; partial units
MUST NOT be advertised.

#### 2.4.2.  Status-Code Encoding (RST)

When RST is set, Extra MAY carry a stream status code.  The status code is
diagnostic and indicates the reason for the abrupt stream shutdown.

The following values are defined; future extensions MAY define additional
values:

| Value  | Name               | Description                                                                                                 |
| ------ | ------------------ | ----------------------------------------------------------------------------------------------------------- |
| 0x0000 | NO_ERROR           | No error or no additional detail.                                                                           |
| 0x0001 | PROTOCOL_ERROR     | Invalid flag/state combination, invalid stream ID parity, non-SYN first frame, or other protocol violation. |
| 0x0002 | FLOW_CONTROL_ERROR | Receiver-side window overflow or equivalent flow-control violation.                                         |
| 0x0003 | INTERNAL_ERROR     | Local I/O failure, timeout, or unexpected internal failure while servicing a stream.                        |
| 0x0004 | REFUSED_STREAM     | Stream refused before establishment due to policy or resource limits.                                       |
| 0x0005 | CANCEL             | Stream terminated by local endpoint policy after application-level close conditions.                        |

For frames with neither SYN, ACK, nor RST set, receivers MUST ignore Extra,
except for stream-0 frames with Flags = 0x00, whose Extra field is interpreted
as a keepalive subtype per Section 2.4.4.

#### 2.4.3.  Session Acknowledgement Encoding (Stream 0 + ACK)

When Stream ID is 0 and ACK is set, Extra carries a session-level frame
increment: the number of non-stream-0 frames the sender has processed since
its last session ACK frame.  This enables the peer to trim its unacknowledged
transmit queue.  Session ACK frames MUST have Length zero and carry no payload.
See Section 5.7.

#### 2.4.4.  Keepalive Subtype Encoding (Stream 0, Flags = 0x00)

When Stream ID is 0 and Flags is 0x00, Extra encodes a keepalive subtype:

| Extra  | Name  | Description                               |
| ------ | ----- | ----------------------------------------- |
| 0x0000 | PROBE | Ordinary keepalive probe; see Section 5.3 |
| 0x0001 | PING  | RTT probe request; see Section 5.3        |
| 0x0002 | PONG  | RTT probe response; see Section 5.3       |

Any other Extra value in this context is reserved; receivers MUST silently
discard such frames without closing the connection.

## 3.  Frame Flags

The Flags field is an 8-bit bitmask.  Multiple flags MAY be set simultaneously
except as noted below.

### 3.1.  Flag Overview

| Flag | Value | Meaning                                         |
| ---- | ----- | ----------------------------------------------- |
| FIN  | 0x01  | Sender will send no further data on this stream |
| SYN  | 0x02  | Stream open signal                              |
| RST  | 0x04  | Immediate stream abort                          |
| PUSH | 0x08  | Frame payload contains stream data              |
| ACK  | 0x10  | Window update (credit grant)                    |

### 3.2.  Flag Semantics

#### 3.2.1.  FIN (0x01)

FIN indicates that the sender will not transmit further data on this stream.
FIN MAY be combined with other non-RST flags where the stream state permits
(for example, PUSH|FIN to deliver a final payload together with the
end-of-stream signal).  When ACK is also set, Extra carries a credit grant per
Section 2.4.1; otherwise, senders MUST set Extra to zero.

#### 3.2.2.  SYN (0x02)

SYN is sent to open a stream or to complete stream establishment (for example,
as SYN|ACK).  When SYN is set and neither RST nor FIN is set, Extra carries
the sender's initial send-credit grant to the peer (see Section 6).

#### 3.2.3.  RST (0x04)

RST takes precedence over all other flags.  When RST is set, the receiver MUST
process RST as specified in Section 4.3.4 and MAY ignore all remaining flags
and any payload in the frame.  Extra MAY carry a stream status code
(Section 2.4.2).

#### 3.2.4.  PUSH (0x08)

When PUSH is set, the receiver MUST copy exactly Length octets from the frame
payload into the stream receive buffer.  When PUSH is clear, the receiver MAY
discard any payload octets present in the frame.

#### 3.2.5.  ACK (0x10)

The ACK flag name is modeled on TCP convention: like TCP's ACK, it advertises
available receive capacity, but unlike TCP it carries no delivery
acknowledgement.  When ACK is set, Extra carries a credit grant that the
receiver MUST add to its accumulated send credit (see Section 6).  When a
credit grant is pending, the sender SHOULD set ACK on the next outbound frame
for that stream so that the grant is conveyed without a separate round-trip.
When no other outbound frame is available for that stream, a standalone ACK
frame MAY be sent.

#### 3.2.6.  Recommended Processing Order

Upon receiving a frame, RST MUST be processed before any other flag validation.
For non-RST processing, an implementation MAY process flags in the following
order: SYN, ACK, PUSH, FIN.

### 3.3.  Reserved Flag Bits and Forward Compatibility

Flag bits 0x20, 0x40, and 0x80 are reserved for future extensions.

-  Senders compliant with this version MUST set all reserved bits to zero.

-  Absent a negotiated extension that activates a reserved bit, receivers MUST
   close the connection upon receiving a frame with that bit set.

-  Extensions that consume a reserved bit MUST specify interaction rules with
   FIN, SYN, RST, PUSH, and ACK and the Extra field interpretation, and MUST
   define a negotiation mechanism via the hello exchange (Section 5.2.2).

## 4.  Stream Management

### 4.1.  Stream ID Allocation

Stream IDs are 16-bit unsigned integers subject to the following rules:

-  Stream 0 is reserved for session-level control.  Frames addressed to stream 0
   with the ACK flag set carry session acknowledgements (Section 5.7).
   Stream-0 frames with Flags = 0x00 serve as keepalive probes or RTT probes
   (Section 5.3).  All stream-0 frames with any flag combination other than
   `0x00` or ACK set MUST be silently discarded.

-  Odd IDs (1, 3, 5, ...) are allocated exclusively by the client.

-  Even IDs (2, 4, 6, ...) are allocated exclusively by the server.

-  Receipt of a non-zero stream ID whose parity is not permitted for the peer
   is a protocol violation.  The receiver MUST close the connection.

-  IDs are allocated sequentially, incrementing by 2.  On 16-bit wraparound,
   stream 0 MUST be skipped: the sequence wraps from 65534 to 2 (server) and
   from 65535 to 1 (client).

-  An endpoint MUST NOT reuse an ID while a stream with that ID is in any state
   other than STREAM_CLOSED.  If all IDs in the endpoint's parity class are
   simultaneously active, that endpoint MUST NOT open additional streams until
   at least one stream in that parity class reaches STREAM_CLOSED.

-  An implementation MAY impose a configurable limit on the total number of
   concurrent streams and on the number of streams in the STREAM_SYN_SENT
   state.  When either limit is reached, new SYN frames SHOULD be rejected
   with RST.

### 4.2.  Stream States

| State               | Description                                                    |
| ------------------- | -------------------------------------------------------------- |
| STREAM_INIT         | Active opener created locally; SYN not yet sent                |
| STREAM_SYN_SENT     | Active opener: SYN sent, awaiting SYN\|ACK                     |
| STREAM_SYN_RECEIVED | Passive opener: SYN received, local stream setup in progress   |
| STREAM_ESTABLISHED  | Full-duplex data transfer                                      |
| STREAM_FIN_WAIT     | Local FIN sent; still receiving from peer                      |
| STREAM_CLOSE_WAIT   | Peer FIN received; local transmit side still open              |
| STREAM_CLOSING      | Both FINs exchanged; receive buffer still draining             |
| STREAM_CLOSED       | Stream terminated (graceful FIN path completed or RST handled) |

A locally created stream enters STREAM_INIT when it is opened and remains
there until its initial SYN-bearing flight is successfully submitted for
transmission.  Only that initial flight MAY carry payload (SYN|PUSH).  Once
submitted, the stream transitions to STREAM_SYN_SENT and awaits SYN|ACK.

### 4.2.1.  Base-Protocol Flag Combinations

For an existing non-zero stream, RST is valid in every state and MUST be
processed as specified in Section 4.3.4 before any other flag validation is
performed.

The following table lists the non-RST flag combinations defined by the base
protocol.  Active extensions MAY define additional valid flag combinations for
any state; this table is not exhaustive when extensions are in use.

| State               | Defined non-RST flag combinations                              | Notes                                                                                                |
| ------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| STREAM_INIT         | None                                                           | Pre-SYN active-open state.  Receipt of any non-RST frame is not defined by this document.            |
| STREAM_SYN_SENT     | SYN\|ACK, SYN\|ACK\|PUSH                                       | Completes stream establishment; PUSH delivers an optional fast-open payload from the passive opener. |
| STREAM_SYN_RECEIVED | None                                                           | While local stream setup is pending, no additional non-RST frame from the peer is defined.           |
| STREAM_ESTABLISHED  | ACK, PUSH, ACK\|PUSH, FIN, ACK\|FIN, PUSH\|FIN, ACK\|PUSH\|FIN | Full-duplex transfer.                                                                                |
| STREAM_FIN_WAIT     | ACK, PUSH, ACK\|PUSH, FIN, ACK\|FIN, PUSH\|FIN, ACK\|PUSH\|FIN | The peer MAY continue sending until it sends FIN.                                                    |
| STREAM_CLOSE_WAIT   | ACK, FIN, ACK\|FIN                                             | The peer has already sent FIN.  Duplicate FIN MAY be ignored, but additional data remains undefined. |
| STREAM_CLOSING      | ACK, FIN, ACK\|FIN                                             | Both FINs have been exchanged.  Duplicate FIN MAY be ignored while local receive data drains.        |
| STREAM_CLOSED       | None                                                           | Late frames for a closed stream are handled per Section 4.3.5.  An inbound RST SHOULD be ignored.    |

A non-RST flag combination not listed for the stream's current state, and not
defined by any active extension, is undefined for that state; the receiver MAY
send RST.

### 4.3.  Stream Lifecycle

#### 4.3.1.  Stream Initiation

Active opener (the endpoint that opens the stream):

1.  Allocate a stream ID from the appropriate parity class.

2.  Transition to STREAM_INIT.

3.  Submit the initial SYN-bearing flight and transition to STREAM_SYN_SENT:

    *  flags = SYN
    *  extra = initial send-credit grant to peer above the implicit 16384-octet
       default; see Section 6.5 for the initial-credit semantics (the grant
       formula is in Section 6.4).
    *  The SYN MAY carry an initial payload (Length > 0, PUSH set),
       constituting a fast-open.  This is valid only before the stream leaves
       STREAM_INIT.  The payload length MUST NOT exceed 16384 octets (the
       active opener's initial send credit toward the passive opener, Section 6.5).

4.  Upon receiving SYN|ACK, add extra * 16384 to the local accumulated send
    credit.  If PUSH is set, copy exactly Length octets from the frame payload
    into the stream receive buffer before any local stream-delivery processing.
    Transition to STREAM_ESTABLISHED.  The initial outbound credit grant was
    already conveyed in the SYN Extra field; a subsequent ACK is sent only if
    additional credit becomes available after establishment.

Passive opener (the endpoint that receives the SYN):

1.  Receive SYN.  Under the base protocol, a stream-opening SYN frame carries
    only SYN or SYN|PUSH; active extensions MAY define additional flags on the
   opening SYN.  Any flag combination not permitted by the base protocol or an
   active extension MUST cause the receiver to close the connection.
   Otherwise, transition to STREAM_SYN_RECEIVED and add extra * 16384 to the
   local accumulated send credit (above the implicit initial credit).

    *  If the stream cannot be accepted: send RST and transition to STREAM_CLOSED.

2.  Upon completion of local stream setup, send SYN|ACK:

    *  flags = SYN | ACK
    *  extra = initial send-credit grant to peer above the implicit 16384-octet
       default; see Section 6.
    *  The SYN|ACK MAY carry an initial payload (Length > 0, PUSH set),
       constituting a fast-open response.  The payload length MUST NOT exceed
       the passive opener's initial send credit toward the active opener: the
       implicit initial credit (16384 octets) plus the additional credit
       granted by the active opener's SYN Extra field (Section 6.5).

3.  Transition to STREAM_ESTABLISHED.

#### 4.3.2.  Data Transfer

Data is carried only in frames with the PUSH flag set.  Upon receiving such a
frame, the receiver MUST copy exactly Length octets into the stream receive
buffer before any local stream-delivery processing occurs.  When a window
update is pending, the sender SHOULD set the ACK flag on the same outbound
data frame.

Either endpoint MAY send data concurrently.  A sender MUST NOT transmit more
payload octets than the peer's advertised send window permits (Section 6).
While the active opener is in STREAM_INIT, it MAY send data only on the
initial SYN-bearing flight (SYN|PUSH).  Once the stream enters STREAM_SYN_SENT,
no further data frames are permitted until SYN|ACK is received and the stream
transitions to STREAM_ESTABLISHED.

#### 4.3.3.  Graceful Shutdown

Half-close is supported.  Either endpoint MAY independently close its send
side.

The FIN flag signals that the sender has no further data to deliver on this
stream.  FIN MAY be combined with the last data frame (PUSH|FIN).

Active close (initiating endpoint):

1.  Upon detecting local end-of-stream, send FIN (with or without final data)
    and transition to STREAM_FIN_WAIT.

2.  Continue receiving data from the peer.

3.  Upon receiving the peer's FIN, transition to STREAM_CLOSING.

4.  After the receive buffer is fully delivered to the local stream consumer,
    transition to STREAM_CLOSED.

Passive close (responding endpoint):

1.  Upon receiving the peer's FIN, transition to STREAM_CLOSE_WAIT.

2.  Continue sending data to the peer; the local transmit side remains open.

3.  Upon detecting local end-of-stream, send FIN and transition to
    STREAM_CLOSING.

4.  After any remaining receive buffer is delivered locally, transition to
    STREAM_CLOSED.

A stream transitions to STREAM_CLOSED when all of the following conditions
hold: a FIN has been sent, a FIN has been received, and the receive buffer has
been fully delivered to the local stream consumer.

#### 4.3.4.  Abrupt Shutdown

Either endpoint MAY send RST to unconditionally abort a stream.  Upon receiving
RST, the receiver MUST immediately transition the stream to STREAM_CLOSED and
MUST discard all outbound data pending transmission and all data buffered in
the receive queue.  No response frame is sent.

#### 4.3.5.  Closed-Stream Tombstone

When a stream transitions to STREAM_CLOSED, the implementation MUST retain a
tombstone record for that stream ID for an implementation-defined period before
freeing the entry from the stream table.

During the tombstone period:

-  An inbound RST MUST be silently discarded.

-  A zero-length ACK or ACK|FIN frame MAY be silently discarded as a
   routine acknowledgement trailing the graceful close.

-  Any other frame MAY be answered with a single RST (status
   PROTOCOL_ERROR).  After sending one RST, the implementation MUST
   suppress further RST replies for the same tombstone entry.

Once the tombstone period expires, the stream ID is freed and the entry is
removed from the stream table.  Frames arriving after that point are handled
as frames for an entirely unknown stream (Section 4.3.1 for SYN frames;
Section 8 otherwise).

## 5.  Session Management

### 5.1.  Session States

| State               | Description                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| SESSION_INIT        | Session object created; not yet started                                      |
| SESSION_CONNECT     | TCP connection in progress (client-local; no protocol wire exchange)         |
| SESSION_HANDSHAKE   | Protocol hello exchange in progress                                          |
| SESSION_ESTABLISHED | Session ready; stream operations are permitted                               |
| SESSION_SUSPENDED   | Transport lost; awaiting reconnect while streams are preserved (Section 5.8) |
| SESSION_CLOSING     | Graceful shutdown of the transport layer                                     |
| SESSION_CLOSE_WAIT  | Waiting for the peer to close the transport                                  |
| SESSION_CLOSED      | Session fully terminated                                                     |

### 5.2.  Protocol Handshake

Immediately after the transport connection is established (and after the TLS
handshake completes when TLS is in use), both endpoints exchange a single hello
message before any mux frames are sent.  The purpose of this exchange is to
verify protocol compatibility and to advertise endpoint capabilities.

Both endpoints enter SESSION_HANDSHAKE for the duration of this exchange.  Mux
frames MUST NOT be sent before both sides reach SESSION_ESTABLISHED.

#### 5.2.1.  Wire Format

Each hello message uses the standard frame header (Section 2.1) with the
following field values, followed immediately by a UTF-8-encoded JSON body:

-  Version: MUST be 0.  This distinguishes hello frames from regular mux
   frames, which carry Version = 1.  Receivers MUST close the connection if
   Version is not 0.

-  Flags, Stream ID, Extra: MUST be 0.  Receivers MUST close the connection
   if any of these fields is non-zero.

-  Length: the number of octets in the JSON body.  MUST NOT exceed 16384.

-  JSON Body: a single JSON object as defined in Section 5.2.2.

#### 5.2.2.  Message Fields

| Field      | Type    | Required    | Description                                                                                                  |
| ---------- | ------- | ----------- | ------------------------------------------------------------------------------------------------------------ |
| type       | string  | Yes         | MIME media type string; see Section 5.2 for the required value (`application/x-multiplexd-proto; version=1`) |
| msgid      | integer | Yes         | 0 = ClientHello; 1 = ServerHello                                                                             |
| session_id | string  | Conditional | 24-character Base64-encoded string (RFC 4648) encoding the server-assigned 16-byte shared session identity   |
| resume_seq | integer | No          | Number of the peer's non-stream-0 frames actually processed by this endpoint; see Section 5.7                |
| extensions | object  | No          | Extension negotiation; values are extension-specific objects; absent means {}                                |

Additional hello object members are extension points.  Receivers MUST ignore
unknown members and MUST NOT fail the handshake solely because such members are
present.

The `session_id` field is a 24-character Base64-encoded string (RFC 4648,
standard alphabet with padding) encoding the 16-byte server-assigned session
identity shared by both endpoints.  The server always includes `session_id` in
its ServerHello.  The client omits `session_id` in an initial ClientHello, and
includes it (echoing the server-assigned value) in a resume ClientHello.
Receivers MUST close the connection if `session_id` is present but malformed.

The `resume_seq` field carries the sender's processed prefix of the peer's
non-stream-0 frame sequence: the number of such frames this endpoint has
actually processed (see Section 5.7).  Frames strictly before this point have
already taken effect at the sender and MUST NOT be retransmitted on resume.
On an initial connection it is 0.  On a resume attempt it tells the peer from
which point retransmission should begin.  When this field is absent, the
sender is not requesting session resumption; the receiver MUST treat the
connection as a fresh session and MUST NOT attempt to resume.

The following JSON Schema (draft 2020-12) defines the normative structure of
the hello message object:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["type", "msgid"],
  "properties": {
    "type":       { "type": "string" },
    "msgid":      { "type": "integer", "enum": [0, 1] },
    "session_id": { "type": "string", "minLength": 24, "maxLength": 24 },
    "resume_seq": { "type": "integer", "minimum": 0 },
    "extensions": { "type": "object", "default": {} }
  },
  "additionalProperties": true
}
```

The `type` field is a MIME media type string.  Receivers MUST parse it per
[RFC2045] and verify:

1.  The media type is `application/x-multiplexd-proto` (case-insensitive per
    RFC 2045, Section 5.1).

2.  The `version` parameter equals `1` (case-insensitive).

Failure of either condition MUST cause the receiver to close the connection.

The `extensions` field is an object whose keys are extension names and whose
values are extension-specific objects.  Receivers MUST ignore any extension
entry they do not recognize and MUST NOT fail the handshake solely because this
field is present.

-  Extension keys defined in this specification are listed without a namespace
   prefix (Section 5.2.3).

-  Non-standard, experimental, or private extension keys MUST be prefixed with
   `x-` (analogous to the `x-` convention in MIME type naming [RFC2045]).
   Receivers MUST silently ignore unknown `x-`-prefixed extension entries.

After the handshake completes, the set of active extensions is the intersection
of the extensions advertised by both peers: an extension is considered active
only if both endpoints include its key in their respective `extensions` objects
with compatible parameters.  Extensions absent from either hello MUST be treated
as inactive for the session.

#### 5.2.3.  Defined Extensions

This section defines the hello extensions specified by this document.  Each
extension occupies one key in the `extensions` object of the hello message.

##### 5.2.3.1.  reject_inbound

```json
"extensions": { "reject_inbound": true }
```

| Field          | Type    | Default | Description                                      |
| -------------- | ------- | ------- | ------------------------------------------------ |
| reject_inbound | boolean | false   | Sender cannot accept new inbound streams if true |

When `reject_inbound` is true, this endpoint MUST NOT be asked to accept new
inbound streams.  An endpoint SHOULD NOT attempt to open streams toward a peer
that advertised `reject_inbound: true`.

The default (absent or false) indicates the endpoint MAY accept new inbound
streams.

##### 5.2.3.2.  identity

```json
"extensions": {
  "identity": "<claimed-id>"
}
```

| Field    | Type   | Description                                            |
| -------- | ------ | ------------------------------------------------------ |
| identity | string | UTF-8 identity claim; maximum 255 octets, NUL-excluded |

Either or both endpoints MAY include the `identity` extension.  The value
advertises the sender's identity to the peer.  If the receiver has a matching
peer entry, it uses the claimed identity to route inbound streams; otherwise it
stores it for informational purposes.  The receiving side SHOULD echo this
extension in its own hello if it also has an identity configured.

#### 5.2.4.  Handshake Flow

```
Client                          Server
  |                               |
  |--- ClientHello (msgid=0) ---> |
  |                               |
  | <-- ServerHello (msgid=1) --- |
  |                               |
SESSION_ESTABLISHED         SESSION_ESTABLISHED
```

1.  The client enters SESSION_HANDSHAKE and sends ClientHello (msgid = 0)
    without a `session_id` field and without `resume_seq`.

2.  The client then awaits a ServerHello.

3.  The server enters SESSION_HANDSHAKE upon transport establishment and
    awaits a ClientHello.

4.  After receiving and validating the ClientHello, the server sends a
    ServerHello (msgid = 1) containing its server-assigned `session_id`, then
    transitions to SESSION_ESTABLISHED.

5.  After receiving and validating the ServerHello, the client stores the
    server-assigned `session_id` as the shared session identity and transitions
    to SESSION_ESTABLISHED.

#### 5.2.5.  Handshake Error Handling

| Condition                               | Action           |
| --------------------------------------- | ---------------- |
| Version field is not 0                  | Close connection |
| Flags, Stream ID, or Extra is non-zero  | Close connection |
| Length field exceeds 16384              | Close connection |
| Connection closed before hello received | Close connection |
| Invalid JSON or missing required field  | Close connection |
| "type" media type mismatch              | Close connection |
| Protocol version mismatch               | Close connection |
| Unexpected msgid                        | Close connection |
| `session_id` present but malformed      | Close connection |

### 5.3.  Keepalive and RTT Probes

While the session is established, each endpoint periodically sends a keepalive
probe to detect unresponsive peers.  All frames in this section are addressed
to stream 0 with Flags = 0x00 and are dispatched by the Extra subtype field
(Section 2.4.4).

#### 5.3.1.  Keepalive Probe (PROBE)

A keepalive probe has all fields set to zero except the Version field:

```
version=0x01, flags=0x00, length=0, stream_id=0, extra=0x0000
```

Receipt of any frame (including keepalive probes and RTT probes) resets the
activity timer.  An endpoint that does not receive any frame within the
activity timeout interval SHOULD suspend or close the connection
(see Section 5.4).

#### 5.3.2.  RTT Probe Request (PING)

An endpoint MAY send a PING frame at any time during SESSION_ESTABLISHED to
measure the round-trip time:

```
version=0x01, flags=0x00, length=<N>, stream_id=0, extra=0x0001
```

The payload is an opaque byte sequence of implementation-defined length and
format, not interpreted by the protocol.  Implementations MAY embed a
timestamp in the payload to enable RTT computation upon receipt of the
corresponding PONG.

Upon receiving a PING, the endpoint MUST immediately transmit a PONG frame
(Section 5.3.3) whose payload is an exact byte-for-byte copy of the PING
payload.  PONG frames SHOULD be transmitted without deliberate delay and
SHOULD NOT be coalesced with other frames.  PING frames MUST NOT be gated by
the send-stall gate (Section 6.2).

Implementations SHOULD apply a rate limit to inbound PING frames to bound the
cost of PONG generation.  When the rate limit is exceeded, the excess PING
frames MAY be silently discarded without sending a PONG.  The rate limit
interval is implementation-defined.

#### 5.3.3.  RTT Probe Response (PONG)

A PONG frame is sent only in response to a PING:

```
version=0x01, flags=0x00, length=<N>, stream_id=0, extra=0x0002
```

The payload MUST be an exact copy of the triggering PING payload.  Upon
receiving a PONG, the sender MAY compute an RTT sample using the timestamp
or token embedded in the payload.  PONG frames MUST NOT be gated by the
send-stall gate (Section 6.2).

A sender MAY apply an implementation-defined timeout while awaiting a PONG.
If this timeout expires before the PONG arrives, the sender SHOULD treat the
transport as unresponsive.  When session resumption is supported
(Section 5.8) the sender SHOULD prefer suspending the session over closing it
so that streams can survive transient blackhole periods.

### 5.4.  Timeouts

Timeout values and keepalive intervals are implementation-defined.  An
endpoint MAY suspend or close the connection if a configurable inactivity
timeout expires without receiving any frame, including during
SESSION_HANDSHAKE.  Implementations that support session resumption
(Section 5.8) SHOULD prefer suspending the session on inactivity timeout
rather than closing it, allowing streams to survive short blackhole periods.
Only sessions that cannot be resumed (e.g., no shared session_id has been
negotiated) MUST be closed.

### 5.5.  Reconnection (Client)

Reconnection behavior, including backoff strategy and timing, is
implementation-defined.  When session resumption is in effect (Section 5.8),
reconnection attempts carry a resume ClientHello so that existing streams
survive the transport failure.

### 5.6.  Session Shutdown

To initiate a graceful shutdown, the local endpoint:

1.  Implicitly aborts any open streams that have not been individually closed;
    the transport-level teardown is sufficient to signal this to the peer.  No
    per-stream FIN or RST frames are sent as part of the session shutdown
    sequence.

2.  Initiates a transport-level shutdown: a TLS `close_notify` alert when TLS is
    in use, followed by a TCP half-close.

3.  Enters SESSION_CLOSING while the local transport teardown is in progress,
    then transitions to SESSION_CLOSE_WAIT and waits for the peer's
    corresponding shutdown notification before closing the transport
    connection.

Upon receiving an unexpected transport EOF before shutdown is negotiated, the
session is torn down immediately.

Any streams that are still open when the session closes are abruptly terminated.

### 5.7.  Session Acknowledgement

To enable session resumption (Section 5.8), each endpoint retains every
non-stream-0 frame it sends in an ordered unacknowledged-transmit list
(unacked list) until the peer confirms the frame has been processed.  Because
these frames must be held in memory for potential retransmission on resume, the
unacked list is a bounded resource; when the configured cap is reached the
endpoint stalls data-frame transmission, introducing session-level backpressure
(Section 5.7.2, Section 6.2).  Each endpoint also periodically acknowledges
the frames it has processed from the peer to allow the peer to trim its own
unacked list.

#### 5.7.1.  Per-Session Counters

Each endpoint maintains four 32-bit unsigned counters, all initialized to zero
at session establishment:

-  The *frame transmit count*: the number of non-stream-0 frames transmitted
   on this session, including retransmissions upon resume.  Incremented by one
   after each such frame is sent.

-  The *frame process count*: the number of non-stream-0 frames processed from
   the peer.  Incremented by one only after the frame's mandatory protocol
   effects have been applied.  For a PUSH-bearing frame, this includes copying
   its payload into the stream receive buffer before any local stream-delivery
   processing.

-  The *reported process count*: the frame process count most recently conveyed
   to the peer in a session ACK.  Initialized to zero.

-  The *confirmed transmit count*: the number of this endpoint's transmitted
   frames that the peer has confirmed as processed.  Advanced by `extra` when
   a session ACK is received.  Initialized to zero.

#### 5.7.2.  Unacknowledged-Transmit List

Every non-stream-0 frame that has been transmitted MUST be retained in the
unacked list until acknowledged.  The list preserves the original
transmission order.  On session teardown without resumption, the endpoint MUST
discard the list.

Because every unacked frame must be held in memory for potential retransmission
on resume, an implementation SHOULD configure an *unacked list cap*: a positive
integer upper bound on the unacked list length.  The cap is a local
configuration parameter that is never transmitted to the peer; the two
endpoints MAY be configured with different values, and such a difference MUST
NOT be treated as a protocol error.  When the unacked list length reaches the
cap, the send-stall gate (Section 6.2) closes, halting data-frame transmission
until the peer sends session ACKs that trim the list below the cap.

#### 5.7.3.  Sending Session ACKs

An endpoint SHOULD emit a session ACK frame when the frame process count
exceeds the reported process count.  The ACK MAY be deferred or piggybacked
onto the next outgoing control frame.

An endpoint MUST emit session ACKs with sufficient frequency to prevent the
peer's unacked list from reaching the cap (Section 5.7.2).  The specific
triggering mechanism is implementation-defined.

The Extra field of the session ACK frame carries the increment:

   extra = min(frame process count − reported process count, 65535)

After sending, the endpoint advances the reported process count by the emitted
increment.  If further frames remain unacknowledged, the endpoint MUST continue
emitting session ACK frames until the reported process count equals the frame
process count.

#### 5.7.4.  Receiving Session ACKs

Upon receiving a frame with Stream ID = 0 and ACK set, the endpoint MUST:

1.  Remove the first `extra` frames from the head of its unacked list, freeing
    the associated resources.

2.  Advance the confirmed transmit count by `extra`.

If `extra` exceeds the current length of the unacked list, the endpoint MUST
close the connection.

### 5.8.  Session Resumption

Session resumption allows a client to restore a session and all its streams
after an unclean TCP disconnect, provided the client reconnects within the
resumption timeout.

#### 5.8.1.  State Machine

When an established session loses its transport connection unexpectedly, the
endpoint MAY enter SESSION_SUSPENDED rather than SESSION_CLOSED.  In this
state:

-  All streams and the unacked list are preserved.
-  No transport I/O occurs.
-  The server waits up to the resumption timeout for the client to present a
   resume hello on a new TCP connection.
-  The client attempts reconnection; the specific reconnect attempt timeout is
   implementation-defined.  The client SHOULD attempt reconnection without
   delay; no backoff applies before the first attempt.

A session closed because of a protocol violation that requires connection
closure under Section 8 MUST transition directly to SESSION_CLOSED rather than
SESSION_SUSPENDED.  Such a session MUST NOT be resumed.

If the resumption timeout expires, the endpoint MUST transition to
SESSION_CLOSED, aborting all streams.

#### 5.8.2.  Resume Hello

A resume hello is a ClientHello that includes `session_id` set to the
server-assigned shared session identity and `resume_seq` set to the client's
processed prefix of the server's non-stream-0 frame sequence (Section 5.7.1).
An initial (non-resume) ClientHello omits the `session_id` field entirely.

A confirming ServerHello includes the same `session_id` (echoing the shared
identity back) and the server's processed prefix of the client's non-stream-0
frame sequence as `resume_seq`.  Both sides thus share a single authoritative
session identity assigned by the server.

#### 5.8.3.  Resume Handshake

```
Client (SUSPENDED)              Server (SUSPENDED)
  |
  |--- ClientHello                |
  |    session_id = shared_id     |
  |    resume_seq = C_proc ------>|
  |                               | (match session_id → suspended session)
  |                               | (trim frames before C_proc from unacked)
  | <--- ServerHello              |
  |      session_id = shared_id   |
  |      resume_seq = S_proc -----|
  | (session_id matches stored    |
  |  shared_id → confirmed        |
  |  resume; trim frames          |
  |  before S_proc)               |
SESSION_ESTABLISHED         SESSION_ESTABLISHED
  | (retransmit remaining         |
  |  unacked frames) ------------>|
  |         <---------------------|
```

In this procedure, `resume_seq` is authoritative for the already-processed
prefix.  A peer receiving `resume_seq = N` MUST treat all non-stream-0 frames
strictly before sequence number N as already processed by the sender and MUST
NOT retransmit them.

1.  The client opens a new TCP connection and sends a ClientHello with
    `session_id` = the shared session identity (server-assigned, stored after
    the previous successful handshake) and `resume_seq` = the client's
    processed prefix of the server's non-stream-0 frame sequence.

2.  The server matches `session_id` to a suspended session (indexed by the
    server-assigned identity).  If matched:

    a.  Trim from the head of the server's unacked list all frames strictly
      before `resume_seq` (frames the client has already processed).

    b.  Send ServerHello with the same `session_id` (the shared identity) and
      `resume_seq` set to the server's processed prefix of the client's
      non-stream-0 frame sequence.

    c.  Transition to SESSION_ESTABLISHED and retransmit all remaining frames
      in the unacked list before transmitting new frames.

3.  The client validates that the ServerHello `session_id` matches the stored
      shared identity and that `resume_seq` is present.  On confirmation: trim
      from the head of the client's unacked list all frames strictly before
      `resume_seq`, then transition to SESSION_ESTABLISHED and retransmit
      remaining unacked frames.

4.  If the server finds no matching suspended session, it treats the connection
    as a new session: it generates a fresh `session_id`, omits `resume_seq`,
    and proceeds with the normal handshake.  The client detects this because
    either `resume_seq` is absent in the ServerHello, or the `session_id` does
    not match the previously stored shared identity.  In either case the client
    MUST reset all existing streams, adopt the new `session_id` as the shared
    identity, and continue as a fresh session.

#### 5.8.4.  Retransmission

During retransmission, the endpoint transmits frames from the head of its
remaining unacked list.  The endpoint MUST NOT transmit new frames until all
frames in the unacked list have been retransmitted.  The frame transmit count
is incremented for each retransmitted frame upon transmission, and each is
subsequently acknowledged normally via session ACK.

## 6.  Flow Control

Flow control is applied independently per stream and per direction using a
credit-based model.  A payload octet MAY be transmitted only after the peer has
explicitly granted the corresponding credit via the Extra field interpreted as a
Window Increment (Section 2.4.1).

This protocol does not implement connection-level flow control.  The underlying
TCP send and receive buffers serve as the connection-level backstop; per-stream
flow control prevents any single stream from monopolizing those buffers.

### 6.1.  Credit Model

Each stream direction maintains a credit balance at the sender.  The sender
tracks two cumulative quantities, each represented as a 32-bit unsigned integer
and initialized to 16384 octets (the implicit initial credit, Section 6.5) at
stream creation:

-  The *accumulated send credit*: the total send credit received from the peer.

-  The *total payload transmitted*: the cumulative payload octets sent on this
   stream.

A sender MUST NOT transmit payload octets such that the total payload
transmitted would exceed the accumulated send credit.

Upon receiving a frame with ACK set (or a plain SYN frame), the endpoint adds
extra * 16384 to the accumulated send credit.  If the accumulated send credit
then exceeds the total payload transmitted, the sender MAY resume transmitting.

### 6.2.  Send-Stall Gate

The send-stall gate is the session-level backpressure mechanism introduced by
the resumption requirement (Section 5.7.2).  It bounds the memory used by the
unacked list by halting data-frame transmission when the list reaches the
configured cap.

The sender tracks one session-level quantity for this mechanism:

-  The *unacked list length*: the number of non-stream-0 frames currently
   retained in the unacked list.  It equals the frame transmit count minus the
   confirmed transmit count (Section 5.7.1) and is always non-negative.

The gate is *open* when the unacked list length is strictly less than the cap
(C), and *closed* when it equals or exceeds C.  If no cap is configured, the
gate is always open and no stalling occurs.

When the gate is closed, the endpoint MUST NOT transmit new PUSH frames for any
non-stream-0 stream.  The gate reopens, and normal PUSH transmission resumes,
as soon as incoming session ACKs reduce the unacked list length to strictly less
than C.

The following frames are exempt from the gate and MUST NOT be stalled
regardless of gate state:

-  All stream-0 frames: keepalive probes (PROBE), RTT probes (PING and PONG),
   and session ACKs.
-  RST frames for any stream.
-  ACK frames (credit grants) and FIN frames (stream half-close) for any
   non-stream-0 stream.

Stream-0 frames are exempt because they carry the session ACKs that unblock the
stalled sender and the RTT probes that maintain session liveness.  RST frames
are exempt because streams must always be abortable regardless of gate state.
ACK and FIN frames are exempt so that the peer can continue delivering data to
us and streams can complete their close handshake while PUSH transmission is
stalled; without them the peer's receive pipeline and stream lifecycle would
stall independently of the session window condition.

The send-stall gate operates at the session level and is independent of the
per-stream credit model (Section 6.1).  Transmitting a PUSH frame for a
non-stream-0 stream requires both conditions to hold: the stream MUST have
available per-stream credit and the gate MUST be open.  A stream with available
credit may still be blocked at the session level; conversely, opening the gate
does not grant per-stream credit.

### 6.3.  Receiver State

The receiver tracks the following per-stream quantities:

-  The *receive buffer capacity*: the maximum number of octets that may be
   concurrently buffered; configurable in the range 0 to 1,073,725,440 octets
   (0 selects automatic, BDP-driven sizing).

-  The *buffered data*: octets received but not yet delivered to the local
   stream consumer.

-  The *total payload received*: cumulative payload octets received on this
   stream.

-  The *total credit granted*: cumulative send credit already granted to the
   peer.  Initialized to 16384 octets (the implicit initial credit).

The *outstanding credit* is the total credit granted minus the total payload
received.  A receiver MUST NOT grant credit that would cause the sum of the
outstanding credit and the buffered data to exceed the receive buffer capacity;
credit is withheld until the local consumer reads buffered data.

### 6.4.  Window Updates

A credit grant is conveyed in any frame with ACK set.  The Extra field carries
the grant in units of 16384 octets.  Let the *available capacity* for the
stream be the receive buffer capacity minus the buffered data minus the
outstanding credit (Section 6.3).  The Extra value is:

   extra = floor(available capacity / 16384)

Upon sending such a frame, the receiver advances the total credit granted by
extra * 16384.

Window updates SHOULD be piggybacked on the next outbound data frame for the
stream (PUSH|ACK).  A standalone ACK frame MAY be sent when no data frame is
available for that stream.

To amortize round-trips, a window update SHOULD be withheld until the available
capacity reaches half the receive buffer capacity.

When this threshold is reached but no outbound data frame is immediately
available to carry the ACK as a PUSH|ACK, the endpoint MUST send a standalone
ACK immediately.  Credit that has accumulated below this threshold SHOULD be
withheld and conveyed opportunistically on the next outbound frame for the
stream, including any frame transmitted when the coalescing deferral
(Section 7.1) expires.

### 6.5.  Initial Credit

Each stream begins with an implicit send credit of 16384 octets in each
direction.  This credit is not transmitted on the wire; both endpoints
initialize the accumulated send credit and the total credit granted to this
value at stream creation.

The SYN and SYN|ACK frames MAY carry an additional credit grant via the Extra
field to raise the effective initial credit to the full receive-buffer size
without requiring a separate ACK round-trip.  This avoids the additional
round-trip that would otherwise be required before a stream could fully utilize
its receive window.

### 6.6.  Counter Representation and Arithmetic

The four per-stream quantities—accumulated send credit, total payload
transmitted, total payload received, and total credit granted—are each
represented as 32-bit unsigned integers.  All arithmetic on these quantities
uses unsigned modulo-2^32 arithmetic (wrapping), including differences such as
total credit granted minus total payload received, or accumulated send credit
minus total payload transmitted.

Wrapping arithmetic yields the correct result as long as the true value of any
such difference does not exceed 2^31 octets.  Because the receive buffer
capacity is at most 1,073,725,440 octets (Section 6.3) and the flow-control
protocol ensures that outstanding credit and buffered data each stay within
that bound, no counter pair diverges by more than that bound under a
well-behaved peer.  Wrapping arithmetic therefore always yields the correct
result in conformant sessions.

A single credit increment is computed as extra * 16384, where extra is a 16-bit
unsigned value (maximum 65535).  The maximum single increment is therefore
65535 * 16384 = 1,073,725,440 octets, which fits within a 32-bit unsigned
integer without overflow.

An implementation that receives a credit grant that would cause the outstanding
send credit (accumulated send credit minus total payload transmitted, using
wrapping arithmetic) to exceed 2^31 - 1 octets SHOULD treat this as a
FLOW_CONTROL_ERROR and send RST.  This bound corresponds to the range within
which the wrapping arithmetic above yields correct results; it does not depend
on either endpoint's configured receive buffer capacity, because that is a
local configuration parameter not advertised on the wire.  Differing receive
buffer capacities between endpoints are therefore both expected and permitted;
a mismatch MUST NOT be treated as a protocol error.

### 6.7.  Dynamic Window Sizing

Implementations MAY increase the receive buffer capacity (Section 6.3) for a
stream at any time during the session.  When the receive buffer capacity grows,
the receiver MUST immediately grant the additional credit to the peer so that
the enlarged window is usable without a further round-trip.

An implementation MAY similarly adjust the unacked list cap (Section 5.7.2)
upward at any time.  This cap is a local parameter and is never transmitted to
the peer.

## 7.  Scheduling

Outbound data-frame scheduling is implementation-defined.  When multiple
streams are ready concurrently, the sender SHOULD use a fair scheduling policy
that does not indefinitely starve any ready stream while continuing to transmit
data for other ready streams, and SHOULD prefer a byte-granularity policy so that a
stream sending large frames does not receive disproportionately more bandwidth
than a stream sending small frames of equal aggregate volume.

A stream is ready when it has pending outbound payload and the accumulated send
credit exceeds the total payload transmitted.

This requirement ensures that no single stream can monopolize the transport
connection regardless of its data volume.

### 7.1.  Small-Frame Coalescing

An implementation MAY delay transmission of a small outbound data frame
to reduce frame overhead, analogous to the Nagle algorithm in TCP.  This
optimization is OPTIONAL and applies only when both of the following
conditions hold:

-  The payload of the queued frame is smaller than the maximum payload size
   (16384 octets).

-  The stream has previously transmitted data that has not yet been
   followed by a credit-replenishing inbound window update from the peer
   (in-flight data is present on the stream).

When both conditions are satisfied, the sender MAY withhold the frame.
The frame MUST be transmitted immediately when any of the following conditions
is met:

1.  The payload of the buffered frame reaches the maximum payload size
    (16384 octets, a full frame is ready).

2.  The peer grants a credit update (inbound ACK), clearing the
    in-flight data backlog.

3.  The deferral timer expires.  Upon expiry, the endpoint MUST transmit the
    withheld frame, and SHOULD set ACK if a credit grant is pending for that
    stream at the time of transmission.

Implementations SHOULD provide a per-session or per-stream configuration
switch to disable this behavior, equivalent to TCP_NODELAY.  When the
switch is enabled, all outbound frames are transmitted immediately
regardless of frame size or in-flight state.  This switch controls only
the small-frame coalescing optimization; the credit-grant mechanism
described in Section 6.4 operates independently and MUST NOT be
suppressed when the switch is enabled.

## 8.  Error Handling

| Condition                                                                                              | Action                            |
| ------------------------------------------------------------------------------------------------------ | --------------------------------- |
| Duplicate SYN (stream already exists)                                                                  | Send RST                          |
| RST for unknown stream                                                                                 | Ignore                            |
| Zero-length ACK and/or FIN for unknown non-zero stream                                                 | Ignore                            |
| Other valid non-SYN frame for unknown non-zero stream                                                  | Send RST; keep session open       |
| SYN frame for new stream with invalid flags                                                            | Close connection                  |
| Stream ID parity violation                                                                             | Close connection                  |
| Flag combination undefined by the base protocol and all active extensions for the current stream state | MAY send RST                      |
| Sender exceeds advertised send window                                                                  | MAY send RST (FLOW_CONTROL_ERROR) |
| Frame Version field is 0 outside of SESSION_HANDSHAKE                                                  | Close connection                  |
| Frame Version field does not match negotiated version                                                  | Close connection                  |
| Length > 16384 in frame header                                                                         | Close connection                  |
| Reserved flag bit set in any frame                                                                     | Close connection                  |
| Transport read/write error                                                                             | Close connection                  |
| Activity timeout                                                                                       | Close connection                  |
| Send timeout (when send_timeout is configured)                                                         | Close connection                  |
| Session resumption timeout expired in SESSION_SUSPENDED                                                | Close connection; abort streams   |
| Session ACK `extra` exceeds unacked list length                                                        | Close connection                  |

## 9.  Protocol Versioning

The current protocol version is 0x01.  The wire-format semantics of the
Version field are specified in Section 2.2.

The protocol version is negotiated during the hello exchange (Section 5.2).
Both endpoints advertise their version via the `version` parameter of the
`type` field; both endpoints MUST verify that the peer's advertised version
matches their own.  A mismatch MUST cause the receiver to close the connection.

## 10.  Security Considerations

TLS 1.3 transport encryption is OPTIONAL.  When enabled:

-  Only TLS 1.3 is permitted; no fallback to earlier versions is allowed.

-  Mutual authentication (mTLS) is enforced.  Both endpoints MUST present a
   certificate.

-  The system certificate authority store is not consulted.  Authentication is
   performed exclusively by certificate pinning: each endpoint maintains an
   explicit list of trusted peer certificates.

When TLS is not in use, the protocol provides no confidentiality,
authentication, or integrity protection beyond what the underlying network
provides.

### 10.1.  Identity-Specific Certificate Pinning

Implementations MAY support per-identity certificate sets as a local policy
enforcement mechanism not visible on the wire.  When enabled:

-  The administrator configures a mapping from peer identity strings to
   per-identity trusted certificate lists.  Each entry specifies the set of
   certificates that a peer claiming that identity is permitted to present.

-  At the TLS layer, the TLS context is built from the union of all
   certificates in the map (together with any global `tls.authcerts` entries,
   if configured).  This allows any peer whose certificate is in the union to
   pass the TLS handshake, regardless of which identity it will later claim.

-  After the protocol hello exchange completes and the peer's claimed identity
   (the `identity` extension, Section 5.2.3.2) is known, the implementation
   verifies that the claimed identity appears as a key in the per-identity
   certificate map.  If it does not, the implementation MUST close the
   connection before any stream operations are permitted.

This mechanism ensures that a compromise of one peer's private key does not
grant the attacker the ability to impersonate a different peer, because even
though the attacker's certificate would pass the TLS handshake (it is in the
union set), the post-handshake identity check would fail — the attacker's
claimed identity does not correspond to the certificate they presented.

When per-identity certificate sets are configured, implementations SHOULD
still include a global `tls.authcerts` list for peers that are not listed in
the identity map, or for sessions where the peer does not claim an identity.

Regardless of transport, implementations MUST enforce:

-  Frame header field validation (version, length bounds).

-  Stream ID parity rules.

-  Flow control limits (MUST NOT transmit beyond the advertised send window).

-  Timeout enforcement to limit resource exhaustion by idle or unresponsive
   peers.

## 11.  References

### 11.1.  Normative References

[RFC2045]  Freed, N. and N. Borenstein, "Multipurpose Internet Mail
           Extensions (MIME) Part One: Format of Internet Message
           Bodies", RFC 2045, DOI 10.17487/RFC2045, November 1996,
           <https://www.rfc-editor.org/info/rfc2045>.

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
           Requirement Levels", BCP 14, RFC 2119,
           DOI 10.17487/RFC2119, March 1997,
           <https://www.rfc-editor.org/info/rfc2119>.

[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
           2119 Key Words", BCP 14, RFC 8174,
           DOI 10.17487/RFC8174, May 2017,
           <https://www.rfc-editor.org/info/rfc8174>.

### 11.2.  Informative References

   None.

## Appendix A.  Interoperability Test Vectors

The following interoperability tests are REQUIRED for conformant
implementations:

| ID   | Scenario                               | Test Vector                                                                   | Expected Result                                                                                                      |
| ---- | -------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| I-1  | Ignorable ACK on unknown stream        | First frame for unknown non-zero stream uses zero-length ACK without SYN      | Receiver MUST ignore the frame for stream-state purposes and keep the session open; it MAY still emit a session ACK  |
| I-2  | Illegal state-dependent data after FIN | Stream in STREAM_CLOSE_WAIT receives PUSH                                     | Receiver treats the data as undefined for state and MAY send RST                                                     |
| I-3  | ACK\|FIN Extra field interpretation    | Frame with ACK\|FIN and non-zero Extra                                        | Extra is interpreted as a credit grant per Section 2.4.1 (RST is clear, ACK is set)                                  |
| I-4  | Stream ID parity violation             | Client sends a frame with an even Stream ID                                   | Receiver MUST close the connection and MUST NOT resume the session                                                   |
| I-5  | Duplicate SYN for existing stream      | SYN received for an already-existing stream ID                                | Receiver sends RST                                                                                                   |
| I-6  | Fast-open credit boundary              | SYN\|PUSH frame with payload length exactly 16384 octets                      | Receiver accepts the frame and completes stream establishment; no RST sent                                           |
| I-7  | Out-of-order FIN then data             | Peer sends FIN, then sends PUSH on the same stream                            | Receiver treats post-FIN data as undefined and MAY send RST                                                          |
| I-8  | Out-of-order RST handling              | Peer sends RST followed by additional valid non-RST frames on the same stream | Receiver MUST keep the session open; it MAY send one RST for the now-unknown stream and MAY ignore later late frames |
| I-9  | Reserved flag bit set                  | Frame sets any reserved bit (0x20, 0x40, or 0x80)                             | Receiver MUST close the connection                                                                                   |
| I-10 | Hello version parameter mismatch       | ClientHello `type` field carries `version=2`                                  | Server MUST close the connection                                                                                     |
| I-11 | PING/PONG echo                         | Send PING (stream_id=0, flags=0x00, extra=0x0001) with any payload            | Receiver MUST reply with PONG (extra=0x0002) carrying the identical payload                                          |
| I-12 | Unknown keepalive subtype              | stream_id=0, flags=0x00, extra=0x0003                                         | Receiver MUST silently discard the frame; connection MUST remain open                                                |
| I-13 | Invalid opening SYN flags              | First frame for unknown non-zero stream uses SYN\|ACK                         | Receiver MUST close the connection and MUST NOT resume the session                                                   |

For each test, endpoints MUST record wire-level evidence (sent and received
frames, flags, stream IDs, and Extra values) sufficient to diagnose behavioral
mismatches.
