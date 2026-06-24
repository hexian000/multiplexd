/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file sched.c
 * @brief Mux schedule layer (2/3): pick which stream sends next under DRR
 *        fairness, apply Nagle/ACK coalescing delay (w_coalesce), and stage the
 *        chosen frames into the send buffer.  Cross-layer note: OOB control and
 *        retransmit replay bypass this layer -- send_pump stages them directly.
 */

/*
 * Local scheduler invariants only; the full model lives in doc/impl.md.
 *
 * - sched_head/tail hold the ready FIFO via prev/next (doubly-linked, O(1)).
 * - drr_active is off the FIFO while it spends its byte budget across EV_WRITE
 *   visits.
 * - delay_head is an unsorted intrusive list; delay_prev/delay_next give O(1)
 *   expiration and cancellation.
 * - the low-priority (lp) queue owns lifecycle work (INIT/CLOSED); the DRR
 *   ready queue carries payload/control transmission.
 * - the ready FIFO and the lp queue share the same prev/next pair and are
 *   mutually exclusive (a stream is on at most one; the delay list uses
 *   delay_prev/next).
 */

#include "mux/sched.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/send.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "util.h"

#include "algo/hashtable.h"
#include "os/clock.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Bulk teardown callback: frees each stream; non-tombstone streams are failed. */
static bool stream_free_and_decount_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	UNUSED(table);
	UNUSED(key);
	struct mux_stream *restrict s = element;
	struct mux_session *restrict ss = data;
	if (s->state != STREAM_CLOSED) {
		COUNTER_ADD(ss->cnt.num_stream_failed, 1);
	}
	stream_free(s);
	return true;
}

void sched_free_streams(struct mux_session *restrict ss)
{
	ss->sched.sched_head = NULL;
	ss->sched.sched_tail = NULL;
	ss->sched.drr_active = NULL;
	ss->sched.lp_head = NULL;
	ss->sched.lp_tail = NULL;
	/* Clear delay_pending to prevent use-after-free in stream_stop
	 * during bulk teardown. */
	for (struct mux_stream *d = ss->sched.delay_head; d != NULL;
	     d = d->delay_next) {
		d->delay_pending = false;
	}
	ss->sched.delay_head = NULL;
	ss->unacked.stalled = false;
	ss->sched.num_tombstones = 0;
	ss->sched.next_stream_id = 0;
	if (ss->sched.streams != NULL) {
		table_iterate(
			ss->sched.streams, stream_free_and_decount_cb, ss);
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
}

bool sched_add_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	void *elem = s;
	ss->sched.streams = table_set(
		ss->sched.streams, (const void *)(uintptr_t)s->id, &elem);
	if (ss->sched.streams == NULL || elem == s) {
		return false;
	}
	ev_timer_stop(ss->loop, &ss->w_idle_timeout);
	return true;
}

static void sched_remove_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	void *elem = NULL;
	ss->sched.streams = table_del(
		ss->sched.streams, (const void *)(uintptr_t)s->id, &elem);
	if (elem == NULL) {
		return;
	}
	/* CLOSED streams already counted; fail only live streams freed here. */
	if (s->state != STREAM_CLOSED) {
		COUNTER_ADD(ss->cnt.num_stream_failed, 1);
	}
	if (table_size(ss->sched.streams) == 0) {
		if (ss->draining && ss->state == SESSION_ESTABLISHED) {
			session_initiate_shutdown(ss);
			return;
		}
		if (!ss->accepted && ss->conf.idle_timeout > 0) {
			ev_timer_again(ss->loop, &ss->w_idle_timeout);
		}
	}
}

struct mux_stream *sched_find_stream(
	struct mux_session *restrict ss, const uint_fast16_t stream_id)
{
	if (ss->sched.streams == NULL) {
		return NULL;
	}
	void *elem = NULL;
	const uint_least16_t id_key = (uint_least16_t)stream_id;
	if (table_find(
		    ss->sched.streams, (const void *)(uintptr_t)id_key,
		    &elem)) {
		return elem;
	}
	return NULL;
}

/* Find the next free stream ID via a wrap-around counter with parity
 * enforcement (client odd, server even), skipping STREAMID_CTRL and IDs already
 * in the table.  The +2 step avoids rapid reuse of recently freed IDs.  Returns
 * STREAMID_CTRL when all IDs of the matching parity are occupied. */
uint_least16_t sched_alloc_stream_id(struct mux_session *restrict ss)
{
	const uint_least16_t parity = ss->accepted ? 0u : 1u;
	uint_least16_t id = ss->sched.next_stream_id;

	/* First call or parity mismatch: start at the parity base. */
	if ((id & 1u) != parity || id == 0) {
		id = parity == 1u ? 1u : 2u;
	}

	for (size_t i = 0; i < 32768u; i++) {
		if (id != STREAMID_CTRL) {
			void *elem = NULL;
			const bool found =
				ss->sched.streams != NULL &&
				table_find(
					ss->sched.streams,
					(const void *)(uintptr_t)id, &elem);
			if (!found) {
				ss->sched.next_stream_id = (id + 2u) & 0xFFFFu;
				return id;
			}
		}
		id = (id + 2u) & 0xFFFFu;
	}

	LOGE_F("[fd:%d] stream IDs exhausted", ss->w_socket.fd);
	return STREAMID_CTRL;
}

static struct mux_stream *sched_dequeue(struct mux_session *restrict ss)
{
	struct mux_stream *s = ss->sched.sched_head;
	if (s != NULL) {
		ss->sched.sched_head = s->next;
		if (ss->sched.sched_head == NULL) {
			ss->sched.sched_tail = NULL;
		} else {
			ss->sched.sched_head->prev = NULL;
		}
		s->next = NULL;
		s->sched_queue = SCHED_QUEUE_NONE;
	}
	return s;
}

void sched_delay_remove(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	if (s->delay_prev != NULL) {
		s->delay_prev->delay_next = s->delay_next;
	} else {
		ss->sched.delay_head = s->delay_next;
	}
	if (s->delay_next != NULL) {
		s->delay_next->delay_prev = s->delay_prev;
	}
	s->delay_prev = NULL;
	s->delay_next = NULL;
	s->delay_pending = false;
	s->delay_ticks = 0;
}

static void
sched_enqueue(struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	/* Avoid double-enqueue: skip if owned by drr_active, LP, or tombstone timer. */
	if (s->sched_queue == SCHED_QUEUE_NONE && s != ss->sched.drr_active &&
	    !ev_is_active(&s->w_tombstone)) {
		s->sched_queue = SCHED_QUEUE_DRR;
		s->next = NULL;
		s->prev = ss->sched.sched_tail;
		if (ss->sched.sched_tail != NULL) {
			ss->sched.sched_tail->next = s;
		} else {
			ss->sched.sched_head = s;
		}
		ss->sched.sched_tail = s;
	}
}

/* Re-enqueue is suppressed while another queue, drr_active, or the tombstone
 * timer still owns the stream node. */
static void
sched_lp_enqueue(struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	if (s->sched_queue == SCHED_QUEUE_DRR || s == ss->sched.drr_active) {
		return;
	}
	if (ev_is_active(&s->w_tombstone)) {
		return;
	}
	if (s->sched_queue == SCHED_QUEUE_NONE) {
		s->sched_queue = SCHED_QUEUE_LP;
		s->next = NULL;
		s->prev = ss->sched.lp_tail;
		if (ss->sched.lp_tail != NULL) {
			ss->sched.lp_tail->next = s;
		} else {
			ss->sched.lp_head = s;
		}
		ss->sched.lp_tail = s;
	}
}

void sched_wake(struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	if (ss->state != SESSION_ESTABLISHED) {
		/* Before SESSION_ESTABLISHED the split queues are not active yet. */
		sched_enqueue(ss, s);
		return;
	}
	/* Keep INIT/CLOSED out of DRR.  If sendbuf is busy, the session_on_send epilogue
	 * re-arms the lp drain after the current frame drains. */
	if (s->state == STREAM_INIT || s->state == STREAM_CLOSED) {
		sched_lp_enqueue(ss, s);
		if (ss->wire.sendbuf.head == NULL) {
			sched_schedule(ss);
		} else {
			ss->wire.tx_pending = true;
		}
	} else {
		sched_enqueue(ss, s);
		ss->wire.tx_pending = true;
	}
	session_notify(ss);
}

void sched_schedule(struct mux_session *restrict ss)
{
	/* Guarded centrally so callers can request the drain unconditionally: an
	 * occupied sendbuf must defer it (the session_on_send epilogue re-arms on drain). */
	if (ss->sched.lp_head == NULL || ss->wire.sendbuf.head != NULL) {
		return;
	}
	ss->sched.lp_pending = true;
	session_notify(ss);
}

void sched_delay(
	struct mux_session *restrict ss, struct mux_stream *restrict s,
	const uint_fast8_t ticks)
{
	if (s->delay_pending) {
		/* Shorten deadline when the new request is sooner. */
		if (ticks < s->delay_ticks) {
			s->delay_ticks = ticks;
		}
		return;
	}
	s->delay_pending = true;
	s->delay_ticks = ticks;
	s->delay_prev = NULL;
	s->delay_next = ss->sched.delay_head;
	if (ss->sched.delay_head != NULL) {
		ss->sched.delay_head->delay_prev = s;
	} else {
		sched_coalesce_arm(ss);
	}
	ss->sched.delay_head = s;
}

static void sched_send_ctrl_flags(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	const bool has_ack_pending =
		(s->state != STREAM_INIT && s->state != STREAM_SYN_SENT &&
		 s->state != STREAM_SYN_RECEIVED && s->ack_pending);
	const bool has_fin_pending =
		(s->rx_eof &&
		 !(s->state == STREAM_FIN_WAIT || s->state == STREAM_CLOSING) &&
		 s->send_queue.head == NULL &&
		 (s->state == STREAM_ESTABLISHED ||
		  s->state == STREAM_CLOSE_WAIT));

	if (!has_ack_pending && !has_fin_pending) {
		return;
	}

	uint_fast8_t flags = 0;
	uint_fast32_t inc = 0;
	if (has_ack_pending) {
		inc = stream_grant_inc(s);
		if (inc > 0) {
			flags |= MUX_FLAG_ACK;
		}
	}
	if (has_fin_pending) {
		flags |= MUX_FLAG_FIN;
	}

	if (flags == 0) {
		/* Grantable sub-unit: clear ack_pending; stream_check_ack re-arms on recovery. */
		s->ack_pending = false;
		return;
	}

	if (!session_send_ctrl(ss, s->id, flags, inc)) {
		return;
	}
	if (flags & MUX_FLAG_ACK) {
		s->grant_sent += inc * MUX_WINDOW_UNIT;
		s->ack_pending = false;
		ss->unacked.ack_pending = true;
		/* Cancel the coalescing delay only when no Nagle-held data
		 * remains; otherwise the tick must still fire to flush
		 * the queued send frame. */
		if (s->send_queue.head == NULL && s->delay_pending) {
			sched_delay_remove(ss, s);
		}
	}
	if (flags & MUX_FLAG_FIN) {
		stream_mark_fin_sent(s);
	}
}

/* After sending a frame, decide whether to keep the DRR quantum active for the
 * next queued frame or yield and re-queue for the next round. */
static void sched_drr_continue(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	const struct mux_frame *const head = s->send_queue.head;
	if (head == NULL) {
		/* Discard surplus: credit is earned by sending,
		 * not by idle time. */
		ss->sched.drr_active = NULL;
		s->deficit = 0;
		return;
	}
	/* Sole ready stream: no contender to be fair to, so stay active and drain
	 * the whole queue in one pump (its records coalesce under TCP_CORK into a
	 * full segment) without paying a re-queue round-trip per frame.  It yields
	 * naturally when the queue empties (above) or the stream stalls on credit. */
	if (ss->sched.sched_head == NULL) {
		ss->sched.drr_active = s;
		return;
	}
	const size_t next_payload = head->len - MUX_FRAME_HEADER_SIZE;
	if (next_payload > 0 && s->deficit >= (uint_least32_t)next_payload) {
		/* Budget covers next frame: stay active to avoid an
		 * unnecessary re-queue round-trip. */
		ss->sched.drr_active = s;
		return;
	}
	/* Budget exhausted: yield and re-queue for the next round,
	 * preserving leftover deficit. */
	ss->sched.drr_active = NULL;
	sched_wake(ss, s);
}

/* Scan the DRR ready queue and stage at most one PUSH frame, skipping streams
 * that cannot currently produce (credit exhausted, queue empty, Nagle-held, or
 * non-ESTABLISHED).  INIT/CLOSED divert to the lp queue, SYN_SENT waits for the
 * handshake, drr_active continues off-queue.  Returns true iff a frame was
 * staged. */
bool sched_next_data(struct mux_session *restrict ss)
{
	for (;;) {
		struct mux_stream *s;
		const bool fresh_dequeue = (ss->sched.drr_active == NULL);

		if (!fresh_dequeue) {
			/* Continue the off-queue stream that still owns the round budget. */
			s = ss->sched.drr_active;
		} else {
			s = sched_dequeue(ss);
			if (s == NULL) {
				return false;
			}
		}

		if (s->state == STREAM_CLOSED) {
			ss->sched.drr_active = NULL;
			/* The tombstone timer owns CLOSED streams until the late-frame
			 * suppression window ends; only then may cleanup re-enter the lp
			 * queue. */
			if (!ev_is_active(&s->w_tombstone)) {
				sched_lp_enqueue(ss, s);
				sched_schedule(ss);
			}
			continue;
		}

		/* INIT only appears here for pre-established backlog; normal wakeups
		 * route it straight to the lp queue for SYN batching. */
		if (s->state == STREAM_INIT) {
			ss->sched.drr_active = NULL;
			sched_lp_enqueue(ss, s);
			sched_schedule(ss);
			continue;
		}
		/* SYN_SENT stays queued-only until the peer's SYN|ACK re-opens credit. */
		if (s->state == STREAM_SYN_SENT) {
			ss->sched.drr_active = NULL;
			continue;
		}

		LOGVV_F("[fd:%d] sched stream=%" PRIuLEAST16, ss->w_socket.fd,
			s->id);

		struct mux_frame *frame = stream_dequeue_send(s);
		if (frame != NULL) {
			const size_t payload =
				frame->len - MUX_FRAME_HEADER_SIZE;
			/* Credit one frame of quantum on a fresh dequeue (Nagle-held
			 * streams earn no budget), or to top up a stream draining
			 * continuously as the sole ready stream -- both keep the
			 * deficit >= payload invariant for the deduction below.  A
			 * contended stream continuing mid-round already has
			 * deficit >= next payload (sched_drr_continue), so it never
			 * tops up here. */
			if (fresh_dequeue ||
			    s->deficit < (uint_least32_t)payload) {
				s->deficit += ss->max_payload;
			}
			session_send_push(ss, s, frame);
			s->deficit -= (uint_least32_t)payload;
			stream_notify_recv(s);
			sched_drr_continue(ss, s);
			sched_send_ctrl_flags(ss, s);
			return true;
		}

		ss->sched.drr_active = NULL;
		/* Nagle may be holding a small frame; schedule a
		 * delayed flush if credit is available. */
		const struct mux_frame *const head = s->send_queue.head;
		if (head != NULL) {
			const size_t payload =
				head->len - MUX_FRAME_HEADER_SIZE;
			const uint_fast32_t credit = stream_credit_avail(s);
			if (payload > 0 && credit >= payload &&
			    !ss->conf.nodelay && s->unacked_bytes > 0 &&
			    payload < (size_t)ss->max_payload) {
				MUX_LOG_F(
					VERBOSE, ss,
					"data scheduler delays stream %" PRIuLEAST16
					" for Nagle: payload=%zu credit=%" PRIuFAST32
					" unacked=%" PRIuLEAST32,
					s->id, payload, credit,
					s->unacked_bytes);
				sched_delay(ss, s, MUX_NAGLE_TICKS);
			}
		} else {
			/* No data pending: discard any accumulated
			 * deficit so the stream does not jump ahead
			 * when it re-enters DRR with new data. */
			s->deficit = 0;
		}

		sched_send_ctrl_flags(ss, s);
	}
}

/* Emit pending per-stream ACK/FIN headers for all DRR-queued streams; the small
 * (8 B) control frames pack into one staging entry, so one flush suffices.
 * Never calls stream_check_ack -- ack_pending is set only by the receive dispatch
 * path; re-arming already-sent grants here would spin session_on_send at 100 % CPU
 * while send_stalled blocks new payload. */
void sched_flush_ctrl(struct mux_session *restrict ss)
{
	for (struct mux_stream *s = ss->sched.sched_head; s != NULL;
	     s = s->next) {
		if (s->state != STREAM_CLOSED) {
			sched_send_ctrl_flags(ss, s);
		}
	}
}

static void
sched_send_syn(struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	struct mux_frame *frame = stream_dequeue_send(s);
	if (frame != NULL) {
		LOGVV_F("[fd:%d] sent SYN|PUSH for stream=%" PRIuLEAST16
			" payload=%zu",
			ss->w_socket.fd, s->id,
			frame->len - MUX_FRAME_HEADER_SIZE);
		session_send_push(ss, s, frame);
		COUNTER_ADD(ss->cnt.num_stream_fastopen, 1);
		stream_mark_syn_sent(s);
		s->syn_sent_ns = (int_least64_t)clock_monotonic_ns();
		return;
	}
	const uint_fast32_t inc = stream_grant_inc(s);
	if (!session_send_ctrl(ss, s->id, MUX_FLAG_SYN, inc)) {
		return;
	}
	LOGVV_F("[fd:%d] sent SYN for stream %" PRIuLEAST16, ss->w_socket.fd,
		s->id);
	s->grant_sent += inc * MUX_WINDOW_UNIT;
	stream_mark_syn_sent(s);
	s->syn_sent_ns = (int_least64_t)clock_monotonic_ns();
}

/* Drain the low-priority lifecycle queue (INIT → SYN batching, CLOSED →
 * cleanup); data streams use the DRR queue.  Deferred to batch SYN flights for
 * streams opened together, and re-armed by the session_on_send epilogue if the
 * sendbuf is still occupied when lifecycle work remains. */
void sched_drain_lp(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED) {
		return;
	}

	while (ss->sched.lp_head != NULL) {
		struct mux_stream *const s = ss->sched.lp_head;
		ss->sched.lp_head = s->next;
		if (ss->sched.lp_head == NULL) {
			ss->sched.lp_tail = NULL;
		} else {
			ss->sched.lp_head->prev = NULL;
		}
		s->sched_queue = SCHED_QUEUE_NONE;
		s->next = NULL;

		if (s->state == STREAM_CLOSED) {
			sched_remove_stream(ss, s);
			stream_free(s);
			continue;
		}

		if (s->state == STREAM_INIT) {
			/* Defer SYN when a partially-written frame occupies
			 * sendbuf head; staging entries (pos==0) are safe. */
			if (ss->wire.sendbuf.head != NULL &&
			    ss->wire.sendbuf.head->pos > 0) {
				MUX_LOG_F(
					DEBUG, ss,
					"idle scheduler waiting for sendbuf drain before SYN"
					" on stream %" PRIuLEAST16
					" frame=%zu/%zu",
					s->id, ss->wire.sendbuf.head->pos,
					ss->wire.sendbuf.head->len);
				sched_lp_enqueue(ss, s);
				break;
			}
			sched_send_syn(ss, s);
			if (s->state == STREAM_INIT) {
				/* SYN send failed (OOM); no SYN reached the
				 * peer, so close locally without sending RST. */
				MUX_LOG_F(
					WARNING, ss,
					"SYN failed (OOM), closing stream %" PRIuLEAST16,
					s->id);
				stream_close(s);
			}
			/* SYN_SENT: data waits for SYN|ACK.  Continue batching
			 * while the sendbuf tail is still a staging entry: bare
			 * SYN frames pack into it, while a SYN+PUSH appended by
			 * reference closes the staging and ends the batch. */
			if (ss->wire.sendbuf.head != NULL &&
			    !ss->wire.sendbuf_staging) {
				break;
			}
		}
	}

	if (ss->sched.sched_head != NULL) {
		ss->wire.tx_pending = true;
	}
}

static void
sched_coalesce_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *restrict ss = w->data;
	ASSERT(loop == ss->loop);
	UNUSED(loop);
	/* Walk the list in-place: survivors stay; expired nodes are removed in
	 * O(1) and scheduled.  Reentrant sched_delay calls prepend to
	 * delay_head and are visited in the next tick. */
	for (struct mux_stream *s = ss->sched.delay_head; s != NULL;) {
		struct mux_stream *const next = s->delay_next;
		if (s->delay_ticks > 1) {
			s->delay_ticks--;
			s = next;
			continue;
		}
		const bool has_grant = stream_grantable_bytes(s) >=
				       (uint_fast32_t)MUX_WINDOW_UNIT;
		/* Expired: O(1) remove from list. */
		sched_delay_remove(ss, s);
		s->nagle_flush = true;
		if (has_grant) {
			s->ack_pending = true;
		}
		MUX_LOG_F(
			DEBUG, ss,
			"coalesce timer released stream %" PRIuLEAST16
			": ack=%d",
			s->id, has_grant);
		sched_wake(ss, s);
		s = next;
	}

	/* Emit deferred session-level ACK for non-stream-0 frames (spec §5.7.3).
	 * The force path (delta >= CLAMP(session_window / 4, 2, 8)) is handled
	 * immediately in process_frame upon receipt; this timer covers the
	 * normal deferred case and serves as a fallback on allocation failure. */
	if (ss->state == SESSION_ESTABLISHED &&
	    ss->unacked.recv_seq != ss->unacked.ack_seq) {
		ss->unacked.ack_ticks++;
		if (ss->unacked.ack_ticks >= MUX_SESSION_ACK_MAX_TICKS) {
			MUX_LOG_F(
				DEBUG, ss,
				"session ACK timer fired: delta=%" PRIuLEAST32,
				ss->unacked.recv_seq - ss->unacked.ack_seq);
			session_emit_ack(ss);
		}
	} else {
		ss->unacked.ack_ticks = 0;
	}
	/* Stop the coalescing timer when both the delay list and the session-ACK
	 * backlog are empty; sched_delay / sched_coalesce_arm will restart it
	 * when new work arrives. */
	if (ss->sched.delay_head == NULL &&
	    ss->unacked.recv_seq == ss->unacked.ack_seq) {
		ev_timer_stop(ss->loop, &ss->sched.w_coalesce);
	}
}

void sched_coalesce_arm(struct mux_session *restrict ss)
{
	if (!ev_is_active(&ss->sched.w_coalesce)) {
		ev_timer_again(ss->loop, &ss->sched.w_coalesce);
	}
}

void sched_init(struct mux_session *restrict ss)
{
	ev_timer_init(
		&ss->sched.w_coalesce, sched_coalesce_cb, 0.0,
		MUX_COALESCING_INTERVAL);
	ss->sched.w_coalesce.data = ss;
}
