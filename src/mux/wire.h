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
	/* true when the kernel's TCP_USER_TIMEOUT is installed on the socket, so
	 * it -- not w_send_timeout -- covers "peer stopped acking". Persistent per
	 * connection; distinguishes "kernel handles the watchdog" from the timer's
	 * repeat, which update_send_timeout temporarily raises for an OOM stall the
	 * kernel cannot see and must be able to restore afterward. */
	bool kernel_send_timeout : 1;
	/* Outbound frame list; the head is the current transport write target.
	 * A frame that still fits the open tail within one TLS record
	 * (MUX_MAX_RECORD) is packed onto it; others are appended by reference. */
	struct mux_frame_list sendbuf;
	/* Out-of-band control queue (PROBE/PING/PONG), drained ahead of any
	 * non-retransmit regular frame; bypasses the send-stall gate (spec §6.2). */
	struct mux_frame_list oobbuf;
	/* Receive byte ring for parsing inbound frames. */
	struct bytebuf *recvbuf;
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
	struct bytebuf *rawbuf;
#endif /* WITH_TLS */
};

/* Result of mux_wire_shutdown: indicates whether the TLS/TCP close handshake
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
 * actually sent.  Returns false on unrecoverable error. */
bool mux_wire_send(
	struct mux_session *restrict ss, const unsigned char *restrict buf,
	size_t *restrict len);

/* Read up to *len bytes from the transport into buf.  On return *len is the
 * number of bytes actually received.  Returns false on unrecoverable error. */
bool mux_wire_recv(
	struct mux_session *restrict ss, unsigned char *restrict buf,
	size_t *restrict len);

/* Return true when the TLS layer has data buffered that can be read by
 * mux_wire_recv without going back to the OS socket; always false for
 * plain-socket transports. */
bool mux_wire_has_pending(const struct mux_session *restrict ss);

/* Free all pending send buffers and reset the receive ring. */
void mux_wire_discard_buffers(struct mux_session *restrict ss);

/* Append @p frame to the sendbuf queue.  A frame that still fits the open tail
 * within one TLS record (MUX_MAX_RECORD) is memcpy-packed onto it (and freed);
 * any other frame is appended by reference (zero-copy) as the new open tail. */
void mux_wire_sendbuf_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame);

/* Result of mux_wire_flush. */
enum wire_flush_result {
	/* No buffered ciphertext remains (or the transport is not buffered). */
	WIRE_FLUSH_DONE,
	/* The socket is full; ciphertext is retained.  Retry on EV_WRITE. */
	WIRE_FLUSH_BLOCKED,
	/* Unrecoverable transport error; the caller must reset/suspend the session
	 * (as it does on a mux_wire_send failure). */
	WIRE_FLUSH_ERROR,
};

/* Memory-transport TLS only: push outbound ciphertext to the socket,
 * retaining what cannot yet be accepted.  No-op for plaintext and
 * fd-backed TLS (returns WIRE_FLUSH_DONE). */
enum wire_flush_result mux_wire_flush(struct mux_session *restrict ss);

#if WITH_TLS
/* Update the TLS context used for future outbound reconnects. */
void mux_wire_set_tlsctx(
	struct mux_session *restrict ss, struct tls_context *restrict tlsctx);

/* Set up TLS over the connected socket; outbound creates wire.tlsconn from
 * wire.tlsctx; accepted is a no-op (already attached).  Handshake is driven
 * implicitly by mux_wire_send/mux_wire_recv.  Returns false on failure. */
bool mux_wire_tls_start(struct mux_session *restrict ss);

#if !defined(NDEBUG)
/* Debug-only: trigger the TLS backend's KTLS-status log once the mux handshake
 * has completed.  No-op when the session is not using TLS.  Implemented by an
 * idempotent tls_handshake() call; compiled out entirely in release builds. */
void mux_wire_tls_log_status(struct mux_session *restrict ss);
#endif

/* Install a TLS connection onto ss during session resume and rebind its I/O
 * notifier to ss (the connection was created for the transient session that
 * carried the resume hello).  Frees any existing TLS connection on ss first. */
void mux_wire_adopt_tlsconn(
	struct mux_session *restrict ss, struct tls_connection *restrict conn);

/* Free a detached TLS connection not owned by any session. */
void mux_wire_tlsconn_free(struct tls_connection *restrict conn);
#endif /* WITH_TLS */

/* Free the current TLS connection object and clear the pointer.
 * No-op in plain-TCP builds. */
void mux_wire_conn_free(struct mux_session *restrict ss);

/* Drive TLS close_notify (WITH_TLS) or issue TCP SHUT_WR; returns
 * WIRE_SHUTDOWN_PENDING when more I/O is needed, WIRE_SHUTDOWN_DONE
 * when shut down, or WIRE_SHUTDOWN_ERROR on error. */
enum wire_shutdown_state mux_wire_shutdown(struct mux_session *restrict ss);

/* Result of mux_wire_wait_eof. */
enum wire_eof_result {
	/* Peer's TCP FIN or TLS close_notify observed: the close is confirmed. */
	WIRE_EOF_CONFIRMED,
	/* Nothing to report yet (EAGAIN, or a TLS layer still mid-shutdown);
	 * not a confirmed close.  Retry on the next wakeup. */
	WIRE_EOF_PENDING,
	/* Unexpected application data after shutdown, or a hard I/O error. */
	WIRE_EOF_ERROR,
};

/* Drain the read side waiting for peer's TCP FIN or TLS close_notify.
 * Does not modify wire.rx_open or wire.tls_want. */
enum wire_eof_result mux_wire_wait_eof(struct mux_session *restrict ss);

#endif /* MUX_WIRE_H */
