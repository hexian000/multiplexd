/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file wire.h
 * @brief Internal transport I/O and TLS wrapper interface.
 */

#ifndef MUX_WIRE_H
#define MUX_WIRE_H

#include "mux/frame.h"

#include <stdbool.h>
#include <stddef.h>

struct mux_session;
struct tls_connection;
struct tls_context;

/* Transport I/O state: socket buffers, TLS connection object, and
 * directional flow-control flags.  Embedded by value in mux_session. */
struct wire_ctx {
	/* true while the transport receive side is open (no EOF or error seen) */
	bool rx_open : 1;
	/* true when there is data ready to write to the transport */
	bool tx_pending : 1;
	/* true when the peer closed the transport cleanly (TCP FIN or TLS
	 * close_notify); false on connection errors or timeouts.  Set by
	 * wire_recv; cleared by session_attach_fd on reconnect. */
	bool rx_eof : 1;
	/* true when sendbuf.tail is a staging entry that can accept
	 * further small-frame packing via wire_sendbuf_push; false when
	 * the tail is a by-reference frame or the queue is empty. */
	bool sendbuf_staging : 1;
	/* Outbound frame list: the head is the current transport write
	 * target and may be partially flushed.  Small frames (<=256 B)
	 * are packed into a staging entry at the tail via wire_sendbuf_push;
	 * large frames, retransmit copies, and OOB frames are appended by
	 * reference.  When the head is not the staging entry it is flushed
	 * to the transport immediately; staging entries accumulate until full
	 * or until a reference entry follows. */
	struct mux_frame_list sendbuf;
	/* Out-of-band control queue (PROBE/PING/PONG), drained ahead of
	 * any non-retransmit regular frame.  Bypasses the send-stall gate
	 * (spec §6.2). */
	struct mux_frame_list oobbuf;
	/* Receive byte ring for parsing inbound frames. */
	struct ringbuf *recvbuf;
#if WITH_TLS
	struct tls_connection *tlsconn;
	/* Pending I/O direction required by the TLS layer (0, EV_READ, or
	 * EV_WRITE).  Overrides normal watcher event selection when TLS needs
	 * a cross-direction I/O (e.g. tls_send returns WANT_READ). */
	int tls_want;
	/* Weak reference to the current server-owned TLS context.
	 * Used by outbound sessions to create new TLS connections on reconnect. */
	struct tls_context *tlsctx;
#endif
};

/* Result of wire_shutdown: indicates whether the TLS/TCP close handshake
 * completed, is still in progress, or encountered an unrecoverable error. */
enum wire_shutdown_state {
	/* Unrecoverable error; caller must reset the session. */
	WIRE_SHUTDOWN_ERROR = -1,
	/* TLS close_notify exchanged (or plain TCP): ready for TCP half-close. */
	WIRE_SHUTDOWN_DONE = 0,
	/* Handshake in progress; retry when I/O is ready (tls_want updated). */
	WIRE_SHUTDOWN_PENDING = 1,
};

/* Write buf[0..*len) to the transport.  On return *len is the number of bytes
 * actually sent.  Returns false on unrecoverable error; the caller must not
 * access the session afterwards. */
bool wire_send(struct mux_session *ss, unsigned char *buf, size_t *len);

/* Read up to *len bytes from the transport into buf.  On return *len is the
 * number of bytes actually received.  Returns false on unrecoverable error. */
bool wire_recv(struct mux_session *ss, unsigned char *restrict buf, size_t *len);

/* Return true when the TLS layer has data buffered that can be read by
 * wire_recv without going back to the OS socket; always false for
 * plain-socket transports. */
bool wire_has_pending(const struct mux_session *ss);

/* Free all pending send buffers and reset the receive ring. */
void wire_discard_buffers(struct mux_session *ss);

/* Maximum total frame length (header + payload) that may be packed into a
 * sendbuf staging entry.  Frames at or below this threshold are memcpy'd
 * into the staging buffer and their originals returned to the pool; frames
 * above this threshold are appended by reference (zero-copy).
 * Value chosen to cover all pure control frames (8 B) and PING/PONG (16 B)
 * while keeping a clear boundary well below the 16 KB data frame size. */
#define MUX_CORK_APPEND_MAX 256u

/* Append @p frame to the sendbuf outbound queue.
 *   - Small frames (frame->len <= MUX_CORK_APPEND_MAX): memcpy'd into the
 *     tail staging entry if there is room, otherwise a new staging entry is
 *     allocated; the original frame is returned to the pool in both cases.
 *   - Large frames (frame->len > MUX_CORK_APPEND_MAX) and retransmit copies:
 *     appended by reference; the frame pointer is preserved for
 *     session_track_sent's retransmit_copy identity check. */
void wire_sendbuf_push(struct mux_session *ss, struct mux_frame *frame);

#if WITH_TLS
/* Update the TLS context used for future outbound reconnects.
 * No-op when the new context is the same as the current one. */
void wire_set_tlsctx(struct mux_session *ss, struct tls_context *tlsctx);

/* Initiate or advance TLS over the already-connected TCP socket.
 * For outbound sessions this creates wire.tlsconn from wire.tlsctx; for
 * accepted sessions it advances the pre-attached wire.tlsconn handshake.
 * Updates wire.tx_pending and wire.tls_want to reflect the next required I/O.
 * Returns false on failure; caller must reset the session. */
bool wire_tls_start(struct mux_session *ss);

/* Migrate the TLS connection from new_ss to ss (session resume path).
 * Frees any existing TLS connection on ss first.
 * Clears new_ss->wire.tlsconn and new_ss->wire.tlsctx after the transfer. */
void wire_migrate_tlsconn(
	struct mux_session *restrict ss, struct mux_session *restrict new_ss);
#endif

/* Free the current TLS connection object and clear the pointer.
 * No-op in plain-TCP builds. */
void wire_conn_free(struct mux_session *ss);

/* Drive the TLS close_notify exchange (WITH_TLS) or issue TCP SHUT_WR.
 * Returns WIRE_SHUTDOWN_PENDING when the TLS handshake needs more I/O,
 * WIRE_SHUTDOWN_DONE when the transport write side is fully shut down, or
 * WIRE_SHUTDOWN_ERROR on an unrecoverable error. */
enum wire_shutdown_state wire_shutdown(struct mux_session *ss);

/* Drain the read side while waiting for the peer's TCP FIN (or TLS
 * close_notify after our own shutdown).  Returns true when the peer
 * has cleanly closed the connection, false on error or unexpected data.
 * Does NOT modify wire.rx_open or wire.tls_want. */
bool wire_wait_eof(struct mux_session *ss);

#endif /* MUX_WIRE_H */
