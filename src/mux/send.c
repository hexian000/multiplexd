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
 * This file also hosts the frame producers (mux_session_send_push/ctrl/oob,
 * mux_session_emit_ack) and the flush entry points (mux_session_flush,
 * mux_session_flush_resp).
 */

#include "mux/send.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/recv.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"

#include "meta/minmax.h"
#include "os/clock.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Flush one send attempt for the sendbuf head.  Returns true when the caller
 * must stop pumping (transport blocked or session torn down), false when the
 * head was fully sent and popped. */
static bool flush_sendbuf_head(
	struct mux_session *restrict ss, bool *restrict made_progress)
{
	struct mux_frame *const frame = ss->wire.sendbuf.head;
	if (frame == NULL) {
		return false;
	}
	ASSERT(frame->len > frame->pos);
	const size_t remaining = frame->len - frame->pos;

	size_t nsend = remaining;
	if (!mux_wire_send(ss, frame->data + frame->pos, &nsend)) {
		mux_session_suspend_or_reset(ss);
		return true;
	}
	if (nsend == 0) {
		/* Blocked: the head is in flight and must be re-presented
		 * byte-for-byte on retry (tls_send contract).  Close staging so
		 * mux_wire_sendbuf_push cannot grow its length. */
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
		 * mux_wire_sendbuf_push cannot try to grow this frame's length. */
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
	mux_unacked_track_sent(ss, frame);
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
	/* The head entry's leading partial_offset bytes are sub-frames the peer
	 * already acked; replay only the unacked remainder so resume never
	 * re-sends delivered data. */
	const size_t skip = ss->unacked.retransmit_off == 0 ?
				    ss->unacked.partial_offset :
				    0;
	struct mux_frame *const copy =
		mux_frame_get(&ss->pool, ss->max_payload);
	if (copy == NULL) {
		LOGOOM();
		return false;
	}
	memcpy(copy->data, orig->data + skip, orig->len - skip);
	copy->pos = 0;
	copy->len = orig->len - skip;
	/* The offset advances only after the replay copy is fully flushed.  Capture
	 * the original's logical count now, while orig is validly peeked, so the
	 * retire branch can advance retransmitted_frames without re-peeking a ring
	 * that may have been freed underneath it (the #47 use-after-free). */
	ss->unacked.retransmit_copy = copy;
	ss->unacked.retransmit_copy_count = orig->unacked_count;
	mux_frame_list_push_front(&ss->wire.sendbuf, copy);
	return true;
}

/* Outcome of staging one frame for send_pump. */
enum send_stage {
	SEND_STAGE_PRODUCED, /* a frame was staged; keep pumping */
	SEND_STAGE_DONE, /* nothing more to stage this round */
	SEND_STAGE_BLOCKED, /* transport blocked or torn down mid-stage; abort */
};

/* Stage the next frame in descending priority: retransmit replay, OOB
 * control, then DRR data/control via the schedule layer.  Does not
 * transmit — that is the surrounding send_pump's job. */
static enum send_stage send_stage_next(
	struct mux_session *restrict ss, bool *restrict made_progress,
	bool *restrict retransmitting)
{
	/* 1. Resume replay takes precedence over new traffic. */
	if (ss->unacked.retransmit_off != SIZE_MAX) {
		/* Flush any pending frame before creating the next copy, else
		 * mux_unacked_track_sent could misidentify copy N as a fresh frame
		 * and double-count its sequence number. */
		if (ss->wire.sendbuf.head != NULL &&
		    flush_sendbuf_head(ss, made_progress)) {
			return SEND_STAGE_BLOCKED;
		}
		if (ss->unacked.ring == NULL ||
		    ss->unacked.retransmit_off >= ss->unacked.ring->count) {
			unacked_set_replay_off(&ss->unacked, SIZE_MAX);
			/* Replay drained (or there was never a ring to replay): fall
			 * through to OOB/data this round instead of peeking a NULL
			 * ring in send_queue_retransmit. */
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
		mux_wire_sendbuf_push(ss, oob);
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
		mux_sched_flush_ctrl(ss);
		return SEND_STAGE_DONE;
	}

	/* 4. Produce one data frame, else drain pending control frames. */
	if (!mux_sched_next_data(ss)) {
		mux_sched_flush_ctrl(ss);
		return SEND_STAGE_DONE; /* nothing left to produce */
	}
	return SEND_STAGE_PRODUCED;
}

/* Pump until transport blocks, session tears down, or nothing is left;
 * each turn transmits buffered bytes then stages the next frame via
 * send_stage_next. */
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

/* True when there is send-side work outstanding: queued bytes, a resume
 * retransmit not yet fully replayed (including one stalled by a frame-pool
 * OOM before any copy reached wire.sendbuf -- send_queue_retransmit()'s
 * SEND_STAGE_DONE-on-failure path leaves retransmit_off set with sendbuf
 * still empty), or scheduler-side data/control waiting to be staged. */
static bool send_has_pending_work(const struct mux_session *restrict ss)
{
	return ss->wire.sendbuf.head != NULL || ss->wire.oobbuf.head != NULL ||
	       ss->sched.sched_head != NULL ||
	       ss->unacked.retransmit_off != SIZE_MAX;
}

static void
update_send_timeout(struct mux_session *restrict ss, const bool progress)
{
	if (ss->state != SESSION_ESTABLISHED) {
		return;
	}
	if (!send_has_pending_work(ss)) {
		ev_timer_stop(ss->loop, &ss->w_send_timeout);
		return;
	}
	/* When the kernel's TCP_USER_TIMEOUT is installed it covers "peer stopped
	 * acking data we already wrote to the socket", so this timer stays off
	 * (repeat == 0.0). The exception is a resume retransmit stalled on a
	 * frame-pool OOM: it never reached the socket, so the kernel has nothing
	 * to time out on -- raise a real userspace interval to retry that one
	 * case, then restore repeat == 0.0 (handing the watchdog back to the
	 * kernel) once the stall clears, so a redundant userspace watchdog does
	 * not persist for the rest of the connection. */
	const bool oom_stalled = ss->unacked.retransmit_off != SIZE_MAX &&
				 ss->wire.sendbuf.head == NULL;
	if (ss->wire.kernel_send_timeout) {
		if (oom_stalled) {
			if (ss->w_send_timeout.repeat == 0.0) {
				ev_timer_set(
					&ss->w_send_timeout, 0.0,
					(double)ss->conf.send_timeout);
				ev_timer_again(ss->loop, &ss->w_send_timeout);
			} else if (!ev_is_active(&ss->w_send_timeout) || progress) {
				ev_timer_again(ss->loop, &ss->w_send_timeout);
			}
		} else if (ss->w_send_timeout.repeat != 0.0) {
			ev_timer_stop(ss->loop, &ss->w_send_timeout);
			ev_timer_set(&ss->w_send_timeout, 0.0, 0.0);
		}
		return;
	}
	/* No kernel timeout: the userspace watchdog always covers egress. */
	if (!ev_is_active(&ss->w_send_timeout) || progress) {
		ev_timer_again(ss->loop, &ss->w_send_timeout);
	}
}

/* Handle a transport whose read side closed while ESTABLISHED.  Returns true
 * when mux_session_on_send must stop: suspended (resumable TCP FIN) or CLOSING (close_notify). */
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
		mux_session_suspend(ss);
		return true;
	}
	/* mux_wire_discard_buffers frees the live replay copy back to the pool;
	 * mux_unacked_free_all must then clear unacked.retransmit_copy (and
	 * retransmit_off + the ring) so a recycled frame cannot false-match the
	 * dangling pointer -- exactly as mux_session_initiate_shutdown pairs them. */
	mux_wire_discard_buffers(ss);
	mux_unacked_free_all(ss);
	if (!ss->accepted) {
		ss->handshake.has_session_id = false;
	}
	mux_session_set_state(ss, SESSION_CLOSING);
	ss->wire.tx_pending = true;
	return true;
}

void mux_session_on_send(struct mux_session *restrict ss)
{
	ss->wire.tx_pending = false;
	if (send_handle_rx_closed(ss)) {
		return;
	}

	/* Drain lifecycle queue before pumping so frames coalesce; skip during
	 * resume replay: a frame staged ahead of replay copies would desync
	 * cumulative-ACK accounting against wire order. */
	if (ss->sched.lp_pending && ss->state == SESSION_ESTABLISHED &&
	    ss->unacked.retransmit_off == SIZE_MAX) {
		ss->sched.lp_pending = false;
		mux_sched_drain_lp(ss);
	}

	bool made_progress = false;
	send_pump(ss, &made_progress);
	if (ss->state == SESSION_SUSPENDED || ss->state == SESSION_CLOSED) {
		/* flush_sendbuf_head suspended or reset the session mid-pump;
		 * mux_session_suspend/reset already settled the watchers and cleared
		 * tx_pending/lp_pending, so the epilogue below must not re-dirty
		 * them (send_has_pending_work would see the pre-armed
		 * retransmit_off = 0, mux_sched_schedule would re-set lp_pending). */
		return;
	}

	/* Residue means the transport blocked: keep EV_WRITE armed and set
	 * send_blocked so the discard path knows the sendbuf head is in flight. */
	const bool residue = (ss->wire.sendbuf.head != NULL);
	bool cipher_residue = false;
	/* Memory-transport TLS: drain ciphertext the library produced once the
	 * pump idles; recv/handshake records can outlive the send queue.  No-op
	 * for plaintext, fd-backed TLS, and a non-empty sendbuf. */
	if (!residue) {
		switch (mux_wire_flush(ss)) {
		case WIRE_FLUSH_DONE:
			break;
		case WIRE_FLUSH_BLOCKED:
			cipher_residue = true;
			break;
		case WIRE_FLUSH_ERROR:
			mux_session_suspend_or_reset(ss);
			return;
		}
	}
	/* send_has_pending_work also catches a resume retransmit stalled by a
	 * frame-pool OOM on the very first replay copy: send_pump's priority
	 * ladder returns before ever attempting oobbuf/sched_head in that
	 * case, so neither residue nor cipher_residue would otherwise notice
	 * that work is still queued there too. */
	if (residue || cipher_residue || send_has_pending_work(ss)) {
		ss->wire.tx_pending = true;
	}
	ss->wire.send_blocked = residue;
	/* Resume the lifecycle drain (INIT SYN / CLOSED cleanup) now the sendbuf
	 * may have cleared; mux_sched_schedule no-ops while it is still occupied. */
	mux_sched_schedule(ss);
	update_send_timeout(ss, made_progress);
	/* dispatch_frame's post-hello early return (recv.c)
	 * defers already-buffered frames behind tx_pending. If tx_pending has
	 * now genuinely settled to false -- e.g. every queued scheduler entry
	 * was non-sendable (tombstoned during suspension), so nothing was
	 * ever written to the peer -- no peer ACK is coming to trigger the
	 * EV_READ that would otherwise re-drive dispatch; redispatch directly. */
	if (!ss->wire.tx_pending && ss->state == SESSION_ESTABLISHED) {
		mux_session_dispatch_pending(ss);
	}
}

void mux_notify_write(struct mux_session *restrict ss)
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
	mux_session_notify(ss);
}

/* ss is deliberately not restrict: s->session aliases it at both call sites,
 * and the block reaches the session through both (mux_stream_grant_inc(s) ->
 * session_pressure_scale(s->session) on every call, and mux_stream_mark_fin_sent(s)
 * on the FIN path) while also modifying it through ss -- same reason
 * process_syn_payload leaves it unqualified. */
void mux_session_send_push(
	struct mux_session *ss, struct mux_stream *restrict s,
	struct mux_frame *restrict frame)
{
	ASSERT(frame->len > MUX_FRAME_HEADER_SIZE);
	const size_t payload_len = frame->len - MUX_FRAME_HEADER_SIZE;
	const bool send_syn = s->state == STREAM_INIT;

	/* Calculate window increment first so it can be carried in Extra.
	 * Piggyback ACK only when we can grant credits; extra=0 is useless. */
	const uint_fast32_t raw_inc = mux_stream_grant_inc(s);
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
	const bool want_fin = !send_syn && stream_fin_pending(s);
	if (want_fin) {
		flags |= MUX_FLAG_FIN;
	}

	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = flags,
		.length = (uint_least16_t)payload_len,
		.stream_id = s->id,
		.extra = (uint_least16_t)raw_inc,
	};

	unsigned char *const p = frame->data;
	mux_write_header(p, &hdr);

	frame->pos = 0;

	/* Log before pushing, as mux_session_send_ctrl does: mux_wire_sendbuf_push takes
	 * ownership, and its coalescing path copies the frame into the staging
	 * tail and returns it to the pool, so neither `frame` nor `p` may be read
	 * afterwards. */
	if (LOGLEVEL(VERYVERBOSE)) {
		mux_session_log_frame_header(ss, "frame out", p, &hdr);
	}

	mux_wire_sendbuf_push(ss, frame);

	if (payload_len > 0) {
		s->bytes_sent += (uint_least32_t)payload_len;
		/* Nagle accounting. */
		s->unacked_bytes += (uint_least32_t)payload_len;
		COUNTER_ADD(
			ss->cnt.traffic.byt_push_sent,
			(uint_least64_t)payload_len);
	}

	s->grant_sent += raw_inc * MUX_WINDOW_UNIT;
	if (flags & MUX_FLAG_ACK) {
		s->ack_pending = false;
	}
	/* ACK piggybacked on PUSH: cancel any pending delay. */
	if (s->delay_pending) {
		mux_sched_delay_remove(ss, s);
	}

	/* Last use of s: mux_stream_mark_fin_sent() may free it synchronously if
	 * this is the last active stream during a drain (same hazard fixed for
	 * mux_stream_recv_fin() in recv.c's dispatch_by_stream()). */
	if (want_fin) {
		mux_stream_mark_fin_sent(s);
	}
}

bool mux_session_send_ctrl(
	struct mux_session *restrict ss, const uint_fast16_t stream_id,
	const uint_fast8_t flags, const uint_fast32_t extra)
{
	struct mux_frame *const frame =
		mux_frame_get(&ss->pool, ss->max_payload);
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
		.extra = (uint_least16_t)clamped,
	};

	mux_write_header(frame->data, &hdr);

	if (LOGLEVEL(VERYVERBOSE)) {
		mux_session_log_frame_header(
			ss, "frame out", frame->data, &hdr);
	}
	/* mux_unacked_track_sent ring-tracks every non-STREAMID_CTRL frame it sees
	 * flushed, so wire order must match ring order or a peer's cumulative
	 * ACK can trim an entry that was never actually retransmitted.
	 * Defer such a frame behind oobbuf while replay is in
	 * progress instead of jumping the sendbuf head, so it waits for
	 * send_stage_next's step 1 like every other producer already does;
	 * mux_session_suspend() migrates a still-pending one into the resume log
	 * instead of dropping it if a second suspend intervenes. */
	if (stream_id != STREAMID_CTRL &&
	    ss->unacked.retransmit_off != SIZE_MAX) {
		mux_frame_list_push(&ss->wire.oobbuf, frame);
	} else {
		mux_wire_sendbuf_push(ss, frame);
	}
	/* Counted only once the RST is actually enqueued, matching every other
	 * traffic counter in this file (an OOM above returns before this). */
	if (flags & MUX_FLAG_RST) {
		COUNTER_ADD(ss->cnt.errors.num_rst_sent, 1);
	}
	mux_notify_write(ss);
	return true;
}

bool mux_session_send_oob(
	struct mux_session *restrict ss, const uint_fast8_t extra,
	const unsigned char *restrict payload, const size_t payload_len)
{
	ASSERT(payload_len <= ss->max_payload);
	struct mux_frame *const frame =
		mux_frame_get(&ss->pool, ss->max_payload);
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
	unsigned char *const restrict payload_ptr =
		frame->data + MUX_FRAME_HEADER_SIZE;
	if (payload_len > 0) {
		if (payload != NULL) {
			memcpy(payload_ptr, payload, payload_len);
		} else {
			memset(payload_ptr, 0, payload_len);
		}
	}

	if (LOGLEVEL(VERYVERBOSE)) {
		mux_session_log_frame_header(
			ss, "frame out", frame->data, &hdr);
	}
	mux_notify_write(ss);
	return true;
}

void mux_session_emit_ack(struct mux_session *restrict ss)
{
	const uint_least32_t emit =
		MIN(ss->unacked.unreported, (uint_least32_t)UINT16_MAX);
	if (mux_session_send_ctrl(ss, STREAMID_CTRL, MUX_FLAG_ACK, emit)) {
		mux_unacked_ack_emitted(ss, emit);
	}
}

/* Strip sub-frames belonging to stream_id (but not its RST) from every eligible
 * node of @p list. @p is_sendbuf gates the sendbuf-only concerns: the TLS
 * send-blocked in-flight head, the verbatim retransmit copy, and the staging
 * open-tail flag -- none of which apply to the oob queue.
 *
 * RST sub-frames are kept (never suppress a queued RST); partially-flushed
 * frames (pos > 0) must finish to preserve framing sync, so they are never
 * touched. mux_wire_sendbuf_push coalesces logical frames from *different* streams
 * into one physical entry, so each entry is walked header-by-header and only
 * the sub-frames belonging to stream_id are stripped -- deciding from the first
 * header alone would either free another stream's still-unsent data or leave
 * this stream's stale data to arrive after the RST. */
static void discard_stream_frames_from(
	struct mux_session *restrict ss, struct mux_frame_list *restrict list,
	const uint_fast16_t stream_id, const bool is_sendbuf)
{
	struct mux_frame *prev = NULL;
	struct mux_frame *frame = list->head;
	while (frame != NULL) {
		struct mux_frame *const next = frame->next;

		if (frame->pos != 0 || frame->len < MUX_FRAME_HEADER_SIZE) {
			prev = frame;
			frame = next;
			continue;
		}
#if WITH_TLS
		/* While send_blocked, a TLS-buffered sendbuf.head may already be
		 * in flight inside the library -- SSL_write's own contract
		 * requires the next call to re-present the identical bytes -- so
		 * keep it intact. Plain TCP's send(2) has no such requirement. */
		if (is_sendbuf && ss->wire.send_blocked &&
		    frame == list->head && ss->wire.tlsconn != NULL) {
			prev = frame;
			frame = next;
			continue;
		}
#endif /* WITH_TLS */
		/* A retransmit copy must replay its ring entry verbatim for resume
		 * byte-accounting, so it is never partially rewritten *or* removed:
		 * removing it would not advance retransmit_off, so send_stage_next
		 * would just re-copy the same ring entry (pure churn). In the rare
		 * resume+abort overlap its stale sub-frame still precedes the RST
		 * (the copy sits at the sendbuf head, the RST is enqueued later at
		 * the tail) -- the safe trade against desyncing the replay. */
		if (is_sendbuf && frame == ss->unacked.retransmit_copy) {
			prev = frame;
			frame = next;
			continue;
		}

		/* Pass 1: validate the concatenated layout and measure the bytes
		 * that survive (everything not belonging to stream_id, plus any
		 * RST sub-frame for it). */
		size_t kept = 0;
		bool malformed = false;
		{
			const unsigned char *src = frame->data;
			const unsigned char *const end =
				frame->data + frame->len;
			while ((size_t)(end - src) >= MUX_FRAME_HEADER_SIZE) {
				struct mux_header hdr;
				mux_read_header(src, &hdr);
				const size_t entry_len = MUX_FRAME_HEADER_SIZE +
							 (size_t)hdr.length;
				if ((size_t)(end - src) < entry_len) {
					malformed = true;
					break;
				}
				if (!(hdr.stream_id == stream_id &&
				      (hdr.flags & MUX_FLAG_RST) == 0)) {
					kept += entry_len;
				}
				src += entry_len;
			}
		}

		/* Nothing to strip, or an unexpected layout: leave as-is. */
		if (malformed || kept == frame->len) {
			prev = frame;
			frame = next;
			continue;
		}

		if (kept > 0) {
			/* Pass 2: compact the survivors down in place. */
			const unsigned char *src = frame->data;
			const unsigned char *const end =
				frame->data + frame->len;
			unsigned char *dst = frame->data;
			while ((size_t)(end - src) >= MUX_FRAME_HEADER_SIZE) {
				struct mux_header hdr;
				mux_read_header(src, &hdr);
				const size_t entry_len = MUX_FRAME_HEADER_SIZE +
							 (size_t)hdr.length;
				if (!(hdr.stream_id == stream_id &&
				      (hdr.flags & MUX_FLAG_RST) == 0)) {
					if (dst != src) {
						memmove(dst, src, entry_len);
					}
					dst += entry_len;
				}
				src += entry_len;
			}
			frame->len = (size_t)(dst - frame->data);
			prev = frame;
			frame = next;
			continue;
		}

		/* kept == 0: every sub-frame belonged to stream_id; drop the whole
		 * physical node. Capture the open-tail flag before the remove;
		 * afterwards list->tail no longer points at frame. */
		const bool discarding_open_tail = is_sendbuf &&
						  ss->wire.sendbuf_staging &&
						  frame == list->tail;
		struct mux_frame *const removed =
			mux_frame_list_remove_after(list, prev);
		ASSERT(removed == frame);
		(void)removed;
		if (discarding_open_tail) {
			ss->wire.sendbuf_staging = false;
		}
		mux_frame_put(&ss->pool, frame);
		frame = next;
	}
}

/* Strip a reset stream's still-queued frames from both egress lists so its
 * stale data cannot arrive ahead of the RST. Walks wire.oobbuf too, where
 * mux_session_send_ctrl parks real-stream control frames during resume replay. */
void mux_session_discard_stream_frames(
	struct mux_session *restrict ss, const uint_fast16_t stream_id)
{
	discard_stream_frames_from(ss, &ss->wire.sendbuf, stream_id, true);
	discard_stream_frames_from(ss, &ss->wire.oobbuf, stream_id, false);
}

/* Run the send pump inline and settle the aftermath: emit CLOSED on teardown,
 * else recompute the watcher.  Low-load fast path; the caller guarantees
 * ESTABLISHED with a clear pipe (sendbuf empty, no TLS poll pending). */
static void session_flush_inline(struct mux_session *restrict ss)
{
	mux_session_on_send(ss);
	if (ss->state == SESSION_CLOSED) {
		/* Teardown inside mux_session_on_send (mirrors socket_cb epilogue);
		 * the reset path already stopped the watchers. */
		ss->last_modified = (int_least64_t)clock_monotonic_ns();
		session_emit(
			ss, MUX_EVENT_CLOSED,
			(union mux_event_data){
				.closed.clean = ss->wire.rx_eof,
			});
		return;
	}
	mux_session_update_watcher(ss);
}

/* True when the transport pipe is clear: nothing staged in the send buffer and
 * (with TLS) no cross-direction want outstanding, so a flush may run inline
 * instead of deferring to the armed EV_WRITE drain. The one place the #if
 * WITH_TLS meaning of "clear" lives. */
static inline bool session_pipe_clear(const struct mux_session *restrict ss)
{
	return ss->wire.sendbuf.head == NULL
#if WITH_TLS
	       && ss->wire.tls_want == 0
#endif
		;
}

void mux_session_flush(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED) {
		mux_session_notify(ss);
		return;
	}

	mux_sched_schedule(ss);
	/* Low-load fast path: empty sendbuf means transport is idle with nothing
	 * to coalesce against — flush inline rather than waiting a loop turn for
	 * EV_WRITE; under load fall through to the coalescing drain. */
	if (session_pipe_clear(ss)) {
		session_flush_inline(ss);
		return;
	}
	mux_session_notify(ss);
}

void mux_session_flush_oob(struct mux_session *restrict ss)
{
	/* The queued OOB frame is flushed by the EV_WRITE drain (coalesced with any
	 * pending data). */
	mux_session_notify(ss);
}

void mux_session_flush_resp(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED || !ss->wire.tx_pending) {
		return;
	}
	mux_sched_schedule(ss);
	/* Inline only when the pipe is clear; under load the occupied sendbuf
	 * defers to the armed EV_WRITE drain.  Call mux_session_on_send directly so
	 * teardown stays with the socket_cb epilogue. */
	if (session_pipe_clear(ss)) {
		mux_session_on_send(ss);
	}
}

void mux_session_eager_flush(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	mux_sched_wake(ss, s);
	/* Arms EV_WRITE; the produced frames flush on the next iteration's drain
	 * (or inline via mux_session_flush's low-load path at the local_cb epilogue). */
	mux_session_notify(ss);
}
