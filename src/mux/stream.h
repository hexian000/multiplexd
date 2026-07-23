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

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_session;

/* One queue membership per stream at any time; the DRR data queue and
 * low-priority lifecycle queue are mutually exclusive. */
enum sched_queue {
	SCHED_QUEUE_NONE,
	SCHED_QUEUE_DRR,
	SCHED_QUEUE_LP,
};

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

struct mux_stream {
	uint_least16_t id;

	/* State flags (shared by both modes) */
	/* Which scheduling queue this stream belongs to; mutually exclusive. */
	uint_least8_t sched_queue : 2;
	/* true = direct I/O mode; false = socket mode */
	bool is_direct : 1;
	/* Direct mode only: the application has relinquished the stream via
	 * mux_stream_close() (close(fd) semantics), so it will never call
	 * mux_stream_recv() again. The library normally defers a direct-mode
	 * stream's final CLOSED transition to that call -- it must not free a
	 * stream the application still holds -- but once this is set there is no
	 * owner left to drive it, so the close paths complete it themselves.
	 * Distinct from direct.w_io == NULL, which merely means the watcher is
	 * currently stopped and says nothing about ownership. */
	bool user_closed : 1;
	/* Receive window update pending; a credit-bearing ACK must be sent to the peer. */
	bool ack_pending : 1;
	/* true when the local socket has sent EOF (or application called mux_stream_shutdown) */
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
	/* Locally aborted (internal error); mux_stream_recv() will return
	 * ECONNRESET, same as a peer-sent RST. */
	bool aborted : 1;

	uint_least8_t delay_ticks;
	enum stream_state state;
	struct mux_session *session;
	/* Singly-linked next pointer, shared by the DRR ready queue and the
	 * low-priority lifecycle queue (mutually exclusive; both strict FIFO). */
	struct mux_stream *next;
	struct mux_stream *delay_prev;
	struct mux_stream *delay_next;

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
	struct bytebuf *recvbuf;

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
	int_least64_t syn_sent_ns;
	/* One-shot linger before CLOSED cleanup re-enters the lp queue. */
	ev_timer w_tombstone;
};

static inline uint_fast32_t stream_avail_window(const struct mux_stream *s)
{
	return s->recv_window > s->buffered_bytes ?
		       s->recv_window - s->buffered_bytes :
		       0;
}

/* Wrapping subtraction is safe because outstanding data stays well below 2^31. */
static inline uint_fast32_t stream_credit_avail(const struct mux_stream *s)
{
	return (uint_fast32_t)(s->send_window - s->bytes_sent);
}

static inline uint_fast32_t stream_read_credit_avail(const struct mux_stream *s)
{
	const uint_fast32_t send_credit = stream_credit_avail(s);
	return send_credit > s->queued_send_bytes ?
		       send_credit - s->queued_send_bytes :
		       0u;
}

/* True when a FIN is due: the app has half-closed (rx_eof) and its data has
 * drained (send_queue empty), from a state that can still send one. Restricting
 * to ESTABLISHED/CLOSE_WAIT already excludes FIN_WAIT/CLOSING (so no separate
 * guard is needed) and the INIT/SYN_SENT/SYN_RECEIVED/CLOSED states that would
 * otherwise trip mux_stream_mark_fin_sent's unexpected-state warning. */
static inline bool stream_fin_pending(const struct mux_stream *restrict s)
{
	return s->rx_eof && s->send_queue.head == NULL &&
	       (s->state == STREAM_ESTABLISHED ||
		s->state == STREAM_CLOSE_WAIT);
}

/* True in the states from which the stream may still originate application
 * data: before its SYN has left (INIT), while established, or after the peer's
 * FIN with the local send side still open (CLOSE_WAIT). The single source of
 * truth for this flow-control predicate, shared by stream.c and mux.c. */
static inline bool stream_can_send_data(const struct mux_stream *restrict s)
{
	return s->state == STREAM_INIT || s->state == STREAM_ESTABLISHED ||
	       s->state == STREAM_CLOSE_WAIT;
}

/* True when a direct-mode stream has an EV_READ condition to deliver: buffered
 * receive data, a half/both-closed state the reader must observe, or a peer RST
 * / local abort. Shared by mux_stream_do_io_start() and mux_stream_io_modify(). At
 * mux_stream_do_io_start() the rst_received/aborted terms are always false (such a
 * stream has already been forced to STREAM_CLOSED and rejected as
 * unattachable), so sharing the fuller predicate is behavior-preserving. */
static inline bool stream_direct_read_ready(const struct mux_stream *restrict s)
{
	return bytebuf_readable(s->recvbuf) > 0 ||
	       s->state == STREAM_CLOSE_WAIT || s->state == STREAM_CLOSING ||
	       s->rst_received || s->aborted;
}

/* True when a direct-mode stream can accept an EV_WRITE: it may still originate
 * data and has peer credit to spend. Shared by mux_stream_do_io_start() and
 * mux_stream_io_modify(). */
static inline bool
stream_direct_write_ready(const struct mux_stream *restrict s)
{
	return stream_can_send_data(s) && stream_read_credit_avail(s) > 0;
}

/* Remaining receive space after subtracting credit the peer may still spend. */
static inline uint_fast32_t stream_grantable_bytes(const struct mux_stream *s)
{
	const uint_fast32_t outstanding =
		(uint_fast32_t)(s->grant_sent - s->bytes_received);
	const uint_fast32_t avail = stream_avail_window(s);
	return avail > outstanding ? avail - outstanding : 0u;
}

/* Compute the window increment (in MUX_WINDOW_UNIT units) to grant the peer.
 * Applies session-level receive-pressure scaling; defined in stream.c. */
uint_fast32_t mux_stream_grant_inc(const struct mux_stream *restrict s);

struct mux_stream *mux_stream_new(
	struct mux_session *restrict ss, uint_fast16_t id, bool active_open);

void mux_stream_free(struct mux_stream *s);

void mux_stream_attach_fd(struct mux_stream *s, int fd);

bool mux_stream_do_io_start(struct ev_loop *loop, struct mux_stream_io *w);

void mux_stream_mark_syn_sent(struct mux_stream *s);

void mux_stream_start(struct mux_stream *s);

/* Queue @p frame (payload already filled in, frame->len set) on @p s's send
 * queue, paying into the same send_buffered_frames/queued_send_bytes
 * bookkeeping every dequeue/free path decrements out of. */
void mux_stream_queue_send(struct mux_stream *s, struct mux_frame *frame);

struct mux_frame *mux_stream_dequeue_send(struct mux_stream *restrict s);

void mux_stream_notify_recv(struct mux_stream *restrict s);

/* Abort the stream locally and emit one peer-visible RST carrying @p code.
 * May free s when it is the last active stream of a draining session (the
 * shutdown cascade), so callers must re-check before touching it again. */
void mux_stream_abort(struct mux_stream *restrict s, enum mux_status code);

void mux_stream_recv_copy(
	struct mux_stream *restrict s, const unsigned char *restrict payload,
	size_t payload_len);

void mux_stream_check_ack(struct mux_stream *restrict s);

void mux_stream_recv_window(struct mux_stream *s, uint_fast32_t window_inc);

void mux_stream_mark_fin_sent(struct mux_stream *s);

void mux_stream_recv_fin(struct mux_stream *s);

void mux_stream_recv_rst(struct mux_stream *s, uint_fast16_t status);

/* close(fd) semantics: discard unread data and RST the peer; otherwise
 * immediate teardown (caller responsible for prior RST/FIN actions). */
void mux_stream_do_close(struct mux_stream *s);

/* Half-close the write side, equivalent to shutdown(fd, SHUT_WR).
 * Queues a FIN to the peer once all pending send data has been flushed.
 * The stream remains readable until the peer FIN arrives. */
void mux_stream_do_shutdown(struct mux_stream *s);

/* Format "[N] me <- peer:" (accepted) or "[N] me -> peer:" (connected)
 * into buf; me/peer use identity, then IP, then "[fd:N]".
 * Returns the snprintf byte count. */
int mux_stream_format_tag(
	char *restrict buf, size_t buflen, const struct mux_stream *restrict s);

#endif /* MUX_STREAM_H */
