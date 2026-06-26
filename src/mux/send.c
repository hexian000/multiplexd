/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file send.c
 * @brief Mux send layer (3/3): drain the producers (retransmit replay, OOB
 *        control, then the schedule layer's DRR data/control) into the wire send
 *        buffer and transmit it, packing small frames into one TLS record.
 *
 * send_pump is the schedule<->send seam: send_stage_next stages the next frame
 * (the producer ladder), the surrounding loop transmits the buffered bytes.
 * This file also hosts the frame producers (session_send_push/ctrl/oob,
 * session_emit_ack) and the flush entry points (session_flush,
 * session_flush_resp).
 */

#include "mux/send.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"

#include "os/clock.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void mux_notify_write(struct mux_session *ss)
{
	if (ss->state != SESSION_ESTABLISHED) {
		return;
	}
	if (!ss->wire.tx_pending) {
		MUX_LOG_F(
			DEBUG, ss,
			"wake write path: sendbuf=%d oobbuf=%d"
			" ready=%d stalled=%d",
			ss->wire.sendbuf.head != NULL,
			ss->wire.oobbuf.head != NULL,
			ss->sched.sched_head != NULL, ss->unacked.stalled);
	}
	ss->wire.tx_pending = true;
	session_notify(ss);
}

void session_emit_ack(struct mux_session *restrict ss)
{
	const uint_fast32_t delta = unacked_ack_delta(ss);
	const uint_fast32_t emit = MIN(delta, (uint_fast32_t)UINT16_MAX);
	if (session_send_ctrl(ss, STREAMID_CTRL, MUX_FLAG_ACK, emit)) {
		unacked_ack_emitted(ss, emit);
	}
}

static void
update_send_timeout(struct mux_session *restrict ss, const bool progress)
{
	if (!(ss->w_send_timeout.repeat > 0.0) ||
	    ss->state != SESSION_ESTABLISHED) {
		return;
	}
	if (ss->wire.sendbuf.head == NULL && ss->wire.oobbuf.head == NULL &&
	    ss->sched.sched_head == NULL) {
		ev_timer_stop(ss->loop, &ss->w_send_timeout);
		return;
	}
	if (!ev_is_active(&ss->w_send_timeout) || progress) {
		ev_timer_again(ss->loop, &ss->w_send_timeout);
	}
}

bool session_send_push(
	struct mux_session *ss, struct mux_stream *s, struct mux_frame *frame)
{
	ASSERT(frame->len > MUX_FRAME_HEADER_SIZE);
	const size_t payload_len = frame->len - MUX_FRAME_HEADER_SIZE;
	const bool send_syn = s->state == STREAM_INIT;

	/* Calculate window increment first so it can be carried in Extra.
	 * Piggyback ACK only when we can grant credits; extra=0 is useless. */
	const uint_fast32_t raw_inc = stream_grant_inc(s);
	uint_fast8_t flags = MUX_FLAG_PUSH;
	if (send_syn) {
		flags |= MUX_FLAG_SYN;
	} else if (
		(s->state == STREAM_ESTABLISHED ||
		 s->state == STREAM_CLOSE_WAIT) &&
		raw_inc > 0) {
		flags |= MUX_FLAG_ACK;
	}

	/* Piggyback FIN on last data frame.  Extra always carries the credit
	 * grant (raw_inc); ACK|FIN is a valid combination per spec §2.4.1. */
	const bool want_fin =
		!send_syn && s->rx_eof &&
		!(s->state == STREAM_FIN_WAIT || s->state == STREAM_CLOSING) &&
		s->send_queue.head == NULL;
	if (want_fin) {
		flags |= MUX_FLAG_FIN;
		stream_mark_fin_sent(s);
	}

	const uint_fast32_t extra = raw_inc;
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = flags,
		.length = (uint_least16_t)payload_len,
		.stream_id = s->id,
		.extra = extra,
	};

	unsigned char *p = frame->data;
	mux_write_header(p, &hdr);

	frame->pos = 0;
	frame->len = MUX_FRAME_HEADER_SIZE + payload_len;

	wire_sendbuf_push(ss, frame);

	if (payload_len > 0) {
		s->bytes_sent += payload_len;
		/* Nagle accounting. */
		s->unacked_bytes += (uint_least32_t)payload_len;
		COUNTER_ADD(
			ss->cnt.traffic.byt_push_sent,
			(uint_least64_t)payload_len);
	}

	s->grant_sent += raw_inc * MUX_WINDOW_UNIT;
	if (flags & MUX_FLAG_ACK) {
		s->ack_pending = false;
		ss->unacked.ack_pending = true;
	}
	/* ACK piggybacked on PUSH: cancel any pending delay. */
	if (s->delay_pending) {
		sched_delay_remove(ss, s);
	}

	if (LOGLEVEL(VERYVERBOSE)) {
		session_log_frame_header(ss, "frame out", p, &hdr);
	}
	return true;
}

/* Flush one send attempt for the sendbuf head.  Returns true when the caller
 * must stop pumping (transport blocked or session torn down), false when the
 * head was fully sent and popped. */
static bool flush_sendbuf_head(
	struct mux_session *restrict ss, bool *restrict made_progress)
{
	struct mux_frame *frame = ss->wire.sendbuf.head;
	if (frame == NULL) {
		return false;
	}
	ASSERT(frame->len > frame->pos);
	const size_t remaining = frame->len - frame->pos;

	size_t nsend = remaining;
	if (!wire_send(ss, frame->data + frame->pos, &nsend)) {
		if (ss->handshake.has_session_id &&
		    (ss->state == SESSION_ESTABLISHED ||
		     (ss->state == SESSION_HANDSHAKE && !ss->accepted))) {
			session_suspend(ss);
		} else {
			session_reset(ss);
		}
		return true;
	}
	if (nsend == 0) {
		/* Blocked: the head is in flight and must be re-presented
		 * byte-for-byte on retry (tls_send contract).  Close staging so
		 * wire_sendbuf_push cannot grow its length. */
		if (ss->wire.sendbuf_staging &&
		    frame == ss->wire.sendbuf.tail) {
			ss->wire.sendbuf_staging = false;
		}
		return true; /* transport buffer full */
	}
	*made_progress = true;

	if (ev_is_active(&ss->w_keepalive)) {
		ev_timer_again(ss->loop, &ss->w_keepalive);
	}
	COUNTER_ADD(ss->cnt.traffic.byt_mux_sent, (uint_least64_t)nsend);
	frame->pos += nsend;
	MUX_LOG_F(
		VERBOSE, ss, "mux sent %zu bytes (buf: %zu/%zu)", nsend,
		frame->pos, frame->len);

	if (frame->pos < frame->len) {
		/* Partial write: the head is now in flight (pos>0) and must be
		 * re-presented byte-for-byte on retry.  Close staging so a later
		 * wire_sendbuf_push cannot try to grow this frame's length. */
		if (ss->wire.sendbuf_staging &&
		    frame == ss->wire.sendbuf.tail) {
			ss->wire.sendbuf_staging = false;
		}
		return true; /* partial write */
	}

	/* Entry fully sent: pop from sendbuf head and hand off to the unacked ring.
	 * Capture the staging identity before the pop because sendbuf.tail changes. */
	struct mux_frame *const was_staging_tail =
		ss->wire.sendbuf_staging ? ss->wire.sendbuf.tail : NULL;
	struct mux_frame *const popped = mux_frame_list_pop(&ss->wire.sendbuf);
	ASSERT(popped == frame);
	(void)popped;
	if (frame == was_staging_tail) {
		ss->wire.sendbuf_staging = false;
	}
	unacked_track_sent(ss, frame);
	return false;
}

/* True while the sendbuf head must be flushed before producing more: a
 * partially-written entry (EAGAIN residue) or any reference entry.  The open
 * staging tail (pos==0) stays so more small frames can pack into it. */
static inline bool send_head_must_flush(const struct mux_session *restrict ss)
{
	const struct mux_frame *const h = ss->wire.sendbuf.head;
	if (h == NULL) {
		return false;
	}
	if (h->pos > 0) {
		return true;
	}
	return !(ss->wire.sendbuf_staging && h == ss->wire.sendbuf.tail);
}

/* Copy the next unacked frame and queue it at the sendbuf head for resume
 * replay.  Returns false on allocation failure (caller stops and retries on
 * the next wakeup). */
static bool send_queue_retransmit(
	struct mux_session *restrict ss, bool *restrict retransmitting)
{
	if (!*retransmitting) {
		MUX_LOG_F(
			DEBUG, ss, "retransmitting %zu unacked frames",
			ss->unacked.frames);
		*retransmitting = true;
	}
	const struct mux_frame *const orig = mux_frame_ring_peek(
		ss->unacked.ring, ss->unacked.retransmit_off);
	struct mux_frame *const copy =
		mux_frame_get(&ss->pool, ss->max_payload);
	if (copy == NULL) {
		LOGOOM();
		return false;
	}
	memcpy(copy->data, orig->data, orig->len);
	copy->pos = 0;
	copy->len = orig->len;
	/* The offset advances only after the replay copy is fully flushed. */
	ss->unacked.retransmit_copy = copy;
	mux_frame_list_push_front(&ss->wire.sendbuf, copy);
	return true;
}

/* Handle a transport whose read side closed while ESTABLISHED.  Returns true
 * when session_on_send must stop: suspended (resumable TCP FIN) or CLOSING (close_notify). */
static bool send_handle_rx_closed(struct mux_session *restrict ss)
{
	if (ss->wire.rx_open || ss->state != SESSION_ESTABLISHED) {
		return false;
	}
	/* TLS close_notify is terminal; a plain TCP FIN may still be resumable.
	 * Outbound TLS closes discard the cached session_id so the next reconnect
	 * starts fresh instead of attempting an invalid resume. */
	if (ss->handshake.has_session_id
#if WITH_TLS
	    && (ss->wire.tlsconn == NULL)
#endif
	) {
		/* Plain TCP FIN keeps resume state intact. */
		session_suspend(ss);
		return true;
	}
	wire_discard_buffers(ss);
	if (!ss->accepted) {
		ss->handshake.has_session_id = false;
	}
	session_set_state(ss, SESSION_CLOSING);
	ss->wire.tx_pending = true;
	update_send_timeout(ss, false);
	return true;
}

/* Outcome of staging one frame for send_pump. */
enum send_stage {
	SEND_STAGE_PRODUCED, /* a frame was staged; keep pumping */
	SEND_STAGE_DONE, /* nothing more to stage this round */
	SEND_STAGE_BLOCKED, /* transport blocked or torn down mid-stage; abort */
};

/* Stage the next frame into the send buffer by descending priority: retransmit
 * replay, OOB control, then the schedule layer's DRR data/control.  OOB and
 * retransmit bypass the scheduler; only steps reaching sched_next_data/
 * sched_flush_ctrl enter the schedule layer.  Does not transmit -- that is the
 * surrounding send_pump loop's job. */
static enum send_stage send_stage_next(
	struct mux_session *restrict ss, bool *restrict made_progress,
	bool *restrict retransmitting)
{
	/* 1. Resume replay takes precedence over new traffic. */
	if (ss->unacked.retransmit_off != SIZE_MAX) {
		/* Flush any pending frame before creating the next copy, else
		 * unacked_track_sent could misidentify copy N as a fresh frame
		 * and double-count its sequence number. */
		if (ss->wire.sendbuf.head != NULL &&
		    flush_sendbuf_head(ss, made_progress)) {
			return SEND_STAGE_BLOCKED;
		}
		if (ss->unacked.ring != NULL &&
		    ss->unacked.retransmit_off >= ss->unacked.ring->count) {
			ss->unacked.retransmit_off = SIZE_MAX;
			/* Replay drained: fall through to OOB/data this round. */
		} else if (send_queue_retransmit(ss, retransmitting)) {
			return SEND_STAGE_PRODUCED;
		} else {
			return SEND_STAGE_DONE; /* OOM: retry on the next wakeup */
		}
	}

	/* 2. OOB controls bypass send_stalled so keepalives/PONGs flow.  Pack
	 * them into staging so a PING/PONG coalesces with adjacent small frames
	 * instead of emitting its own tiny TLS record. */
	if (ss->wire.oobbuf.head != NULL) {
		struct mux_frame *const oob =
			mux_frame_list_pop(&ss->wire.oobbuf);
		wire_sendbuf_push(ss, oob);
		return SEND_STAGE_PRODUCED;
	}

	/* 3. send_stalled blocks new payload only; per-stream ACK/FIN must still
	 * flow so the peer can drain its window. */
	if (ss->unacked.stalled) {
		MUX_LOG_F(
			DEBUG, ss,
			"send loop paused by session window: unacked=%zu"
			" limit=%" PRIuLEAST32 " ready=%d",
			ss->unacked.frames, ss->session_window,
			ss->sched.sched_head != NULL);
		sched_flush_ctrl(ss);
		return SEND_STAGE_DONE;
	}

	/* 4. Produce one data frame, else drain pending control frames. */
	if (!sched_next_data(ss)) {
		sched_flush_ctrl(ss);
		return SEND_STAGE_DONE; /* nothing left to produce */
	}
	return SEND_STAGE_PRODUCED;
}

/* Pump the send pipeline until the transport blocks, the session is torn down,
 * or nothing is left.  Each turn transmits buffered bytes (send layer) then
 * stages the next frame (send_stage_next); small frames accumulate in a staging
 * entry and flush when full or at loop exit. */
static void
send_pump(struct mux_session *restrict ss, bool *restrict made_progress)
{
	bool retransmitting = false;
	for (;;) {
		/* Transmit reference entries and EAGAIN residue before staging
		 * more; the open staging tail (pos==0) stays to keep packing. */
		while (send_head_must_flush(ss)) {
			if (flush_sendbuf_head(ss, made_progress)) {
				return; /* transport blocked or session torn down */
			}
		}

		if (ss->state != SESSION_ESTABLISHED) {
			break; /* HANDSHAKE/CLOSING: flush leftover staging below */
		}

		const enum send_stage st =
			send_stage_next(ss, made_progress, &retransmitting);
		if (st == SEND_STAGE_BLOCKED) {
			return;
		}
		if (st == SEND_STAGE_DONE) {
			break;
		}
	}

	/* Transmit the staging entry (and any EAGAIN residue) left this round;
	 * reference entries were already drained by the top-of-loop flush. */
	if (ss->wire.sendbuf.head != NULL) {
		(void)flush_sendbuf_head(ss, made_progress);
	}
}

void session_on_send(struct mux_session *restrict ss)
{
	ss->wire.tx_pending = false;
	if (send_handle_rx_closed(ss)) {
		return;
	}

	/* Drain the low-priority lifecycle queue (INIT SYN / CLOSED cleanup) before
	 * pumping so its frames coalesce into this write.  Skip while resume replay
	 * is in flight: a frame staged ahead of the replay copies would desync
	 * cumulative-ACK accounting against the wire order. */
	if (ss->sched.lp_pending && ss->state == SESSION_ESTABLISHED &&
	    ss->unacked.retransmit_off == SIZE_MAX) {
		ss->sched.lp_pending = false;
		sched_drain_lp(ss);
	}

	bool made_progress = false;
	send_pump(ss, &made_progress);

	/* Residue means the transport blocked: keep EV_WRITE armed and set
	 * send_blocked so the discard path knows the sendbuf head is in flight. */
	const bool residue = (ss->wire.sendbuf.head != NULL);
	bool cipher_residue = false;
	/* Memory transport (socket_offload disabled): drain ciphertext the library produced once
	 * the frame pump idles, since recv/handshake records can outlive the send
	 * queue.  A no-op for plaintext, fd-backed TLS, and a non-empty sendbuf
	 * (whose wire_send already drains the ciphertext in order). */
	if (!residue) {
		switch (wire_flush(ss)) {
		case WIRE_FLUSH_DONE:
			break;
		case WIRE_FLUSH_BLOCKED:
			cipher_residue = true;
			break;
		case WIRE_FLUSH_ERROR:
			/* Mirror flush_sendbuf_head: a resumable transport
			 * suspends, otherwise reset. */
			if (ss->handshake.has_session_id &&
			    (ss->state == SESSION_ESTABLISHED ||
			     (ss->state == SESSION_HANDSHAKE &&
			      !ss->accepted))) {
				session_suspend(ss);
			} else {
				session_reset(ss);
			}
			return;
		}
	}
	if (residue || cipher_residue) {
		ss->wire.tx_pending = true;
	}
	ss->wire.send_blocked = residue;
	/* Resume the lifecycle drain (INIT SYN / CLOSED cleanup) now the sendbuf
	 * may have cleared; sched_schedule no-ops while it is still occupied. */
	sched_schedule(ss);
	update_send_timeout(ss, made_progress);
}

/* Run the send pump inline and settle the aftermath: emit CLOSED on teardown,
 * else recompute the watcher.  Low-load fast path; the caller guarantees
 * ESTABLISHED with a clear pipe (sendbuf empty, no TLS poll pending). */
static void session_flush_inline(struct mux_session *restrict ss)
{
	session_on_send(ss);
	if (ss->state == SESSION_CLOSED) {
		/* Teardown inside session_on_send (mirrors socket_cb epilogue);
		 * the reset path already stopped the watchers. */
		ss->last_modified = (int_least64_t)clock_monotonic_ns();
		session_emit(
			ss, MUX_EVENT_CLOSED,
			(union mux_event_data){
				.closed.clean = ss->wire.rx_eof,
			});
		return;
	}
	session_update_watcher(ss);
}

void session_eager_flush(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	sched_wake(ss, s);
	/* Arms EV_WRITE; the produced frames flush on the next iteration's drain
	 * (or inline via session_flush's low-load path at the local_cb epilogue). */
	session_notify(ss);
}

void session_flush(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED) {
		session_notify(ss);
		return;
	}

	sched_schedule(ss);
	/* Low-load fast path: an empty sendbuf means the transport write path is idle
	 * with nothing to coalesce against, so flush straight to the mux fd instead of
	 * waiting a loop turn for EV_WRITE.  Under load the sendbuf stays occupied and
	 * we fall through to the coalescing EV_WRITE drain. */
	if (ss->wire.sendbuf.head == NULL
#if WITH_TLS
	    && ss->wire.tls_want == 0
#endif
	) {
		session_flush_inline(ss);
		return;
	}
	session_notify(ss);
}

void session_flush_oob(struct mux_session *restrict ss)
{
	/* The queued OOB frame is flushed by the EV_WRITE drain (coalesced with any
	 * pending data). */
	session_notify(ss);
}

void session_flush_resp(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED || !ss->wire.tx_pending) {
		return;
	}
	sched_schedule(ss);
	/* Inline only when the pipe is clear (mirrors session_flush); under load
	 * the occupied sendbuf defers to the armed EV_WRITE drain.  Call
	 * session_on_send directly so teardown stays with the socket_cb epilogue. */
	if (ss->wire.sendbuf.head == NULL
#if WITH_TLS
	    && ss->wire.tls_want == 0
#endif
	) {
		session_on_send(ss);
	}
}

/* RST frames are kept (never suppress a queued RST); partially-flushed frames
 * (pos > 0) must finish to preserve framing sync, so they are never discarded. */
void session_discard_stream_frames(
	struct mux_session *restrict ss, const uint_fast16_t stream_id)
{
	struct mux_frame *prev = NULL;
	struct mux_frame *frame = ss->wire.sendbuf.head;
	while (frame != NULL) {
		struct mux_frame *const next = frame->next;
		bool discard = false;
		if (frame->pos == 0 && frame->len >= MUX_FRAME_HEADER_SIZE) {
			struct mux_header hdr;
			mux_read_header(frame->data, &hdr);
			discard =
				(hdr.stream_id == stream_id &&
				 (hdr.flags & MUX_FLAG_RST) == 0);
		}
		/* While send_blocked, sendbuf.head is in flight at the transport and
		 * the next tls_send must re-present the identical bytes; keep it and
		 * discard only the rest. */
		if (discard && ss->wire.send_blocked &&
		    frame == ss->wire.sendbuf.head) {
			discard = false;
		}
		if (!discard) {
			prev = frame;
			frame = next;
			continue;
		}

		/* Capture before the remove; afterwards sendbuf.tail no longer
		 * points at frame. */
		const bool discarding_open_tail =
			ss->wire.sendbuf_staging &&
			frame == ss->wire.sendbuf.tail;
		struct mux_frame *const removed =
			mux_frame_list_remove_after(&ss->wire.sendbuf, prev);
		ASSERT(removed == frame);
		(void)removed;
		if (ss->unacked.retransmit_copy == frame) {
			ss->unacked.retransmit_copy = NULL;
		}
		if (discarding_open_tail) {
			ss->wire.sendbuf_staging = false;
		}
		mux_frame_put(&ss->pool, frame);
		frame = next;
	}
}

bool session_send_ctrl(
	struct mux_session *ss, const uint_fast16_t stream_id,
	const uint_fast8_t flags, const uint_fast32_t extra)
{
	if (flags & MUX_FLAG_RST) {
		COUNTER_ADD(ss->cnt.num_rst_sent, 1);
	}
	struct mux_frame *frame = mux_frame_get(&ss->pool, ss->max_payload);
	if (frame == NULL) {
		LOGOOM();
		return false;
	}
	frame->pos = 0;
	frame->len = MUX_FRAME_HEADER_SIZE;

	const uint_fast32_t clamped = MIN(extra, (uint_fast32_t)UINT16_MAX);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = flags,
		.length = 0,
		.stream_id = stream_id,
		.extra = clamped,
	};

	mux_write_header(frame->data, &hdr);

	if (LOGLEVEL(VERYVERBOSE)) {
		session_log_frame_header(ss, "frame out", frame->data, &hdr);
	}
	wire_sendbuf_push(ss, frame);
	mux_notify_write(ss);
	return true;
}

bool session_send_oob(
	struct mux_session *restrict ss, const uint_fast8_t extra,
	const unsigned char *restrict payload, const size_t payload_len)
{
	ASSERT(payload_len <= ss->max_payload);
	struct mux_frame *frame = mux_frame_get(&ss->pool, ss->max_payload);
	if (frame == NULL) {
		LOGOOM();
		return false;
	}
	frame->pos = 0;
	frame->len = MUX_FRAME_HEADER_SIZE + payload_len;
	mux_frame_list_push(&ss->wire.oobbuf, frame);

	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)payload_len,
		.stream_id = STREAMID_CTRL,
		.extra = extra,
	};
	mux_write_header(frame->data, &hdr);
	unsigned char *restrict payload_ptr =
		frame->data + MUX_FRAME_HEADER_SIZE;
	if (payload_len > 0) {
		if (payload != NULL) {
			memcpy(payload_ptr, payload, payload_len);
		} else {
			memset(payload_ptr, 0, payload_len);
		}
	}

	if (LOGLEVEL(VERYVERBOSE)) {
		session_log_frame_header(ss, "frame out", frame->data, &hdr);
	}
	mux_notify_write(ss);
	return true;
}
