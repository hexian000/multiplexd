/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file stream.h
 * @brief Internal mux stream state machine interface.
 */

#ifndef MUX_STREAM_H
#define MUX_STREAM_H

#include "mux/frame.h"
#include "mux/mux.h"

#include "utils/minmax.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_session;

enum stream_state {
	/* Active: stream created locally; initial SYN flight not queued yet */
	STREAM_INIT,
	/* Active: SYN sent, awaiting SYN|ACK */
	STREAM_SYN_SENT,
	/* Passive: SYN received, local setup in progress */
	STREAM_SYN_RECEIVED,
	/* Full-duplex data transfer active */
	STREAM_ESTABLISHED,
	/* Local FIN sent; still receiving data from peer */
	STREAM_FIN_WAIT,
	/* Peer FIN received; local transmit side still open */
	STREAM_CLOSE_WAIT,
	/* Both FINs exchanged; receive buffer still draining */
	STREAM_CLOSING,
	/* Both FINs exchanged and receive buffer fully delivered */
	STREAM_CLOSED,
};

struct stream {
	uint_least16_t id;

	/* State flags (shared by both modes) */
	bool is_ready : 1;
	/* true when this stream is in the low-priority (EV_IDLE) queue for SYN/cleanup. */
	bool lp_ready : 1;
	/* true = direct I/O mode; false = socket mode */
	bool is_direct : 1;
	/* Receive window update pending; a credit-bearing ACK must be sent to the peer. */
	bool ack_pending : 1;
	/* true when the local socket has sent EOF (or application called stream_shutdown) */
	bool rx_eof : 1;
	/* true when the local socket write side has been shut down */
	bool tx_shutdown : 1;
	/* Peer sent RST; mux_stream_recv() will return ECONNRESET */
	bool rst_received : 1;
	/* Single-owner halfopen accounting guard */
	bool halfopen_counted : 1;
	/* One-shot Nagle bypass set by the delay scheduler on expiry. */
	bool nagle_flush : 1;
	bool delay_pending : 1;
	/* RST has already been sent to the peer; no further RST may be sent. */
	bool rst_sent : 1;

	uint_least8_t delay_ticks;
	enum stream_state state;
	struct mux_session *session;
	struct stream *next;
	struct stream *delay_prev;
	struct stream *delay_next;

	/* Local I/O: the two modes are mutually exclusive */
	union {
		struct {
			ev_io w_io;
			ev_timer w_timeout;
			/* true once the non-blocking connect() has completed */
			bool connected : 1;

		} socket;
		struct {
			mux_stream_io *w_io;
		} direct;
	};

	/* Send buffer (data waiting to be sent to mux) */
	struct mux_frame_list send_queue;

	/* Receive buffer (data waiting to be sent to local socket) */
	struct ringbuf *recvbuf;

	/* Flow control - sender side */
	uint_least32_t bytes_sent;
	uint_least32_t send_window;
	/* Unacked bytes for Nagle algorithm: data sent but not yet ACK'd by peer */
	uint_least32_t unacked_bytes;
	/* DRR deficit counter: remaining byte budget accumulated across visits.
	 * Reset to zero when send_queue empties between scheduling rounds. */
	uint_least32_t deficit;
	/* Payload bytes queued locally but not yet moved into the mux send buffer. */
	uint_least32_t queued_send_bytes;

	/* Flow control - receiver side */
	uint_least32_t bytes_received;
	uint_least32_t buffered_bytes;
	uint_least32_t recv_window;
	/* Cumulative credit granted to the peer so far, in bytes (wrapping). */
	uint_least32_t grant_sent;
	/* Remaining budget for immediate-ACK cycles (TCP-style quickack). */
	uint8_t quickack_budget;
	intmax_t syn_sent_ns;
	/* One-shot linger before CLOSED cleanup re-enters EV_IDLE. */
	ev_timer w_tombstone;
};

static inline uint_fast32_t stream_avail_window(const struct stream *s)
{
	return s->recv_window > s->buffered_bytes ?
		       s->recv_window - s->buffered_bytes :
		       0;
}

/* Wrapping subtraction is safe because outstanding data stays well below 2^31. */
static inline uint_fast32_t stream_credit_avail(const struct stream *s)
{
	return (uint_fast32_t)(s->send_window - s->bytes_sent);
}

static inline uint_fast32_t stream_read_credit_avail(const struct stream *s)
{
	const uint_fast32_t send_credit = stream_credit_avail(s);
	return send_credit > s->queued_send_bytes ?
		       send_credit - s->queued_send_bytes :
		       0u;
}

/* Remaining receive space after subtracting credit the peer may still spend. */
static inline uint_fast32_t stream_grantable_bytes(const struct stream *s)
{
	const uint_fast32_t outstanding =
		(uint_fast32_t)(s->grant_sent - s->bytes_received);
	const uint_fast32_t avail = stream_avail_window(s);
	return avail > outstanding ? avail - outstanding : 0u;
}

/* Compute the window increment (in MUX_WINDOW_UNIT units) to grant the peer.
 * Applies session-level receive-pressure scaling; defined in stream.c. */
uint_fast32_t stream_grant_inc(const struct stream *s);

struct stream *
stream_new(struct mux_session *restrict ss, uint_fast16_t id, bool active_open);

void stream_free(struct stream *s);

void stream_attach_fd(struct stream *s, int fd);

void stream_io_start(struct ev_loop *loop, struct mux_stream_io *w);

void stream_mark_syn_sent(struct stream *s);

void stream_start(struct stream *s);

struct mux_frame *stream_dequeue_send(struct stream *restrict s);

void stream_on_send(struct stream *restrict s);

void stream_recv_copy(
	struct stream *restrict s, const unsigned char *restrict payload,
	size_t payload_len);

void stream_check_ack(struct stream *restrict s);

void stream_recv_window(struct stream *restrict s, uint_fast32_t window_inc);

void stream_mark_fin_sent(struct stream *s);

void stream_recv_fin(struct stream *s);

void stream_recv_rst(struct stream *s);

/* Close the stream with close(fd) semantics.
 * If the receive buffer has unread data, discard it and send RST to the peer.
 * Otherwise, perform an immediate teardown without sending any control frame
 * (the caller is responsible for prior protocol actions such as RST or FIN). */
void stream_close(struct stream *s);

/* Half-close the write side, equivalent to shutdown(fd, SHUT_WR).
 * Queues a FIN to the peer once all pending send data has been flushed.
 * The stream remains readable until the peer FIN arrives. */
void stream_shutdown(struct stream *s);

/* Format a stream log prefix into buf.
 * accepted stream: "me <- peer [N]:"
 * connected stream: "me -> peer [N]:"
 * me/peer use identity, fall back to IP, finally fall back to "[fd:N]".
 * Returns the snprintf byte count. */
int stream_format_tag(
	char *restrict buf, size_t buflen, const struct stream *restrict s);

#endif /* MUX_STREAM_H */
