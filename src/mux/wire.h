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
	/* true when the last flush left unsent residue (congested). */
	bool send_blocked : 1;
	/* true when the peer closed the transport cleanly (TCP FIN or TLS
	 * close_notify); false on connection errors or timeouts. */
	bool rx_eof : 1;
#if WITH_TLS
	/* true when the TLS library holds buffered plaintext readable without
	 * further I/O. */
	bool tls_readable : 1;
#endif
	/* true when sendbuf.tail is the open entry (pos == 0) that can still
	 * absorb packed small frames on its tail; false when frozen or empty. */
	bool sendbuf_staging : 1;
	/* Outbound frame list; the head is the current transport write target.
	 * A frame that still fits the open tail within one TLS record
	 * (MUX_MAX_RECORD) is packed onto it; others are appended by reference. */
	struct mux_frame_list sendbuf;
	/* Out-of-band control queue (PROBE/PING/PONG), drained ahead of any
	 * non-retransmit regular frame; bypasses the send-stall gate (spec §6.2). */
	struct mux_frame_list oobbuf;
	/* Receive byte ring for parsing inbound frames. */
	struct ringbuf *recvbuf;
#if WITH_TLS
	struct tls_connection *tlsconn;
	/* Pending I/O direction required by the TLS layer (0, EV_READ, or
	 * EV_WRITE).  Overrides normal watcher event selection when TLS needs
	 * a cross-direction I/O (e.g. tls_send returns WANT_READ). */
	int tls_want;
	/* Weak reference to the current server-owned TLS context. */
	struct tls_context *tlsctx;
	/* Memory transport (socket_offload disabled) only: outbound ciphertext the
	 * socket could not yet accept.  Lazily allocated; NULL otherwise. */
	struct ringbuf *rawbuf;
#endif /* WITH_TLS */
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
bool wire_send(struct mux_session *ss, const unsigned char *buf, size_t *len);

/* Read up to *len bytes from the transport into buf.  On return *len is the
 * number of bytes actually received.  Returns false on unrecoverable error. */
bool wire_recv(struct mux_session *ss, unsigned char *restrict buf, size_t *len);

/* Return true when the TLS layer has data buffered that can be read by
 * wire_recv without going back to the OS socket; always false for
 * plain-socket transports. */
bool wire_has_pending(const struct mux_session *ss);

/* Free all pending send buffers and reset the receive ring. */
void wire_discard_buffers(struct mux_session *ss);

/* Append @p frame to the sendbuf queue.  A frame that still fits the open tail
 * within one TLS record (MUX_MAX_RECORD) is memcpy-packed onto it (and freed);
 * any other frame is appended by reference (zero-copy) as the new open tail. */
void wire_sendbuf_push(struct mux_session *ss, struct mux_frame *frame);

/* Result of wire_flush. */
enum wire_flush_result {
	/* No buffered ciphertext remains (or the transport is not buffered). */
	WIRE_FLUSH_DONE,
	/* The socket is full; ciphertext is retained.  Retry on EV_WRITE. */
	WIRE_FLUSH_BLOCKED,
	/* Unrecoverable transport error; the caller must reset/suspend the session
	 * (as it does on a wire_send failure). */
	WIRE_FLUSH_ERROR,
};

/* Memory-transport TLS only: push outbound ciphertext to the socket,
 * retaining what cannot yet be accepted.  No-op for plaintext and
 * fd-backed TLS (returns WIRE_FLUSH_DONE). */
enum wire_flush_result wire_flush(struct mux_session *ss);

#if WITH_TLS
/* Update the TLS context used for future outbound reconnects.
 * No-op when the new context is the same as the current one. */
void wire_set_tlsctx(struct mux_session *ss, struct tls_context *tlsctx);

/* Set up TLS over the connected socket; outbound creates wire.tlsconn from
 * wire.tlsctx; accepted is a no-op (already attached).  Handshake is driven
 * implicitly by wire_send/wire_recv.  Returns false on failure. */
bool wire_tls_start(struct mux_session *ss);

#if !defined(NDEBUG)
/* Debug-only: trigger the TLS backend's KTLS-status log once the mux handshake
 * has completed.  No-op when the session is not using TLS.  Implemented by an
 * idempotent tls_handshake() call; compiled out entirely in release builds. */
void wire_tls_log_status(struct mux_session *ss);
#endif

/* Install a TLS connection onto ss during session resume and rebind its I/O
 * notifier to ss (the connection was created for the transient session that
 * carried the resume hello).  Frees any existing TLS connection on ss first. */
void wire_adopt_tlsconn(
	struct mux_session *restrict ss, struct tls_connection *restrict conn);

/* Free a detached TLS connection not owned by any session. */
void wire_tlsconn_free(struct tls_connection *conn);
#endif /* WITH_TLS */

/* Free the current TLS connection object and clear the pointer.
 * No-op in plain-TCP builds. */
void wire_conn_free(struct mux_session *ss);

/* Drive TLS close_notify (WITH_TLS) or issue TCP SHUT_WR; returns
 * WIRE_SHUTDOWN_PENDING when more I/O is needed, WIRE_SHUTDOWN_DONE
 * when shut down, or WIRE_SHUTDOWN_ERROR on error. */
enum wire_shutdown_state wire_shutdown(struct mux_session *ss);

/* Drain the read side waiting for peer's TCP FIN or TLS close_notify;
 * returns true on clean close, false on error or unexpected data.
 * Does not modify wire.rx_open or wire.tls_want. */
bool wire_wait_eof(struct mux_session *ss);

#endif /* MUX_WIRE_H */
