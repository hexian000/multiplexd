/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file session.c
 * @brief Internal mux session state machine implementation.
 */

#include "mux/session.h"

#include "mux/dispatch.h"
#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/stream.h"
#include "mux/wire.h"
#include "util.h"

#include "algo/hashtable.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

static const char *session_state_str[] = {
	[SESSION_INIT] = "INIT",
	[SESSION_CONNECT] = "CONNECT",
	[SESSION_HANDSHAKE] = "HANDSHAKE",
	[SESSION_ESTABLISHED] = "ESTABLISHED",
	[SESSION_SUSPENDED] = "SUSPENDED",
	[SESSION_CLOSING] = "CLOSING",
	[SESSION_CLOSE_WAIT] = "CLOSE_WAIT",
	[SESSION_CLOSED] = "CLOSED",
};

/* -------------------------------------------------------------------------
 * Infrastructure & Lifecycle
 * Session state, lifecycle management, stream table, raw socket I/O.
 * ---------------------------------------------------------------------- */

static void
session_set_state(struct mux_session *ss, enum session_state newstate)
{
	if (ss->state == newstate) {
		return;
	}
	MUX_LOG_F(
		DEBUG, ss, "state: %s -> %s", session_state_str[ss->state],
		session_state_str[newstate]);
	const enum session_state oldstate = ss->state;

	if (oldstate == SESSION_ESTABLISHED) {
		ev_timer_stop(ss->loop, &ss->w_timeout);
		ev_timer_stop(ss->loop, &ss->w_keepalive);
		ev_timer_stop(ss->loop, &ss->w_send_timeout);
		ss->estimator.ping_in_flight = false;
		ss->stream_window = (uint_least32_t)MAX(
			estimator_window_size(&ss->estimator, ESTIMATOR_RX) /
				2 / MUX_WINDOW_UNIT,
			(size_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
		COUNTER_ADD(ss->cnt.num_session_disconnected, 1);
		COUNTER_SUB(ss->cnt.num_sessions, 1);
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss, MUX_EVENT_LOST,
				(union mux_event_data){ 0 });
		}
	} else if (
		(oldstate == SESSION_CONNECT ||
		 oldstate == SESSION_HANDSHAKE) &&
		newstate != SESSION_CONNECT && newstate != SESSION_HANDSHAKE &&
		newstate != SESSION_ESTABLISHED &&
		newstate != SESSION_SUSPENDED) {
		COUNTER_SUB(ss->cnt.num_session_halfopen, 1);
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss, MUX_EVENT_CONNECT_FAILED,
				(union mux_event_data){ 0 });
		}
	}

	ss->state = newstate;

	if ((newstate == SESSION_CONNECT || newstate == SESSION_HANDSHAKE) &&
	    oldstate != SESSION_CONNECT && oldstate != SESSION_HANDSHAKE) {
		COUNTER_ADD(ss->cnt.num_session_connect, 1);
		COUNTER_ADD(ss->cnt.num_session_halfopen, 1);
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss, MUX_EVENT_CONNECT,
				(union mux_event_data){ 0 });
		}
	} else if (newstate == SESSION_ESTABLISHED) {
		if (ss->connect_started > 0) {
			const int_fast64_t lat =
				clock_monotonic_ns() - ss->connect_started;
			ss->last_connect_latency_ns = lat;
			ss->connect_started = 0;
		}
		/* peer_addr is cleared by session_cleanup after each reconnect.
		 * It remains set across suspend, distinguishing first
		 * establishment (CONNECT) from transport resumption (RESUMED). */
		const bool first_establish =
			(ss->peer_addr.sa.sa_family == AF_UNSPEC);
		(void)socket_get_peer(ss->w_socket.fd, &ss->peer_addr);
		ev_timer_again(ss->loop, &ss->w_keepalive);
		COUNTER_ADD(ss->cnt.num_session_connected, 1);
		COUNTER_SUB(ss->cnt.num_session_halfopen, 1);
		COUNTER_ADD(ss->cnt.num_sessions, 1);
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss,
				first_establish ? MUX_EVENT_ESTABLISHED :
						  MUX_EVENT_RESUMED,
				(union mux_event_data){
					.connected.ns =
						ss->last_connect_latency_ns,
					.connected.peer_id =
						ss->handshake.peer_id,
					.connected.peer_identity =
						ss->handshake.peer_identity,
				});
		}
	}
}

static void session_stop(struct mux_session *ss)
{
	struct ev_loop *loop = ss->loop;
	ev_io_stop(loop, &ss->w_socket);
	ev_idle_stop(loop, &ss->sched.w_sched);
	ev_timer_stop(loop, &ss->w_timeout);
	ev_timer_stop(loop, &ss->w_keepalive);
	ev_timer_stop(loop, &ss->w_send_timeout);
	ev_timer_stop(loop, &ss->w_connect_timeout);
	ev_timer_stop(loop, &ss->sched.w_coalesce);
	ev_timer_stop(loop, &ss->w_idle_timeout);
	ss->stream_window = (uint_least32_t)MAX(
		estimator_window_size(&ss->estimator, ESTIMATOR_RX) / 2 /
			MUX_WINDOW_UNIT,
		(size_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
}

static void session_cleanup(struct mux_session *restrict ss)
{
	sched_free_streams(ss);
	wire_conn_free(ss);
	if (ss->w_socket.fd != -1) {
		SOCKET_CLOSE_FD(ss->w_socket.fd);
		ss->w_socket.fd = -1;
	}

	wire_discard_buffers(ss);
	unacked_ring_free_all(ss);
	ss->retransmit_copy = NULL;
}

static void handshake_cleanup(struct mux_session *restrict ss)
{
	free(ss->handshake.identity);
	free(ss->handshake.peer_id);
	free(ss->handshake.peer_identity);
}

void session_reset(struct mux_session *ss)
{
	if (ss->state == SESSION_CLOSED) {
		return;
	}
	MUX_LOG(VERBOSE, ss, "closing");
	session_set_state(ss, SESSION_CLOSED);
	session_stop(ss);
	session_cleanup(ss);

	if (ss->accepted) {
		return;
	}
	/* Reset peer_addr so the next establishment is recognised as first. */
	memset(&ss->peer_addr, 0, sizeof(ss->peer_addr));
	ss->num_halfopen = 0;
}

static void update_watcher(struct mux_session *restrict ss)
{
	int events = 0;
#if WITH_TLS
	if (ss->wire.tls_want != 0) {
		modify_io_events(ss->loop, &ss->w_socket, ss->wire.tls_want);
		return;
	}
#endif
	switch (ss->state) {
	case SESSION_CONNECT:
		events = EV_WRITE;
		break;
	case SESSION_HANDSHAKE:
	case SESSION_ESTABLISHED:
	case SESSION_CLOSING:
		if (ss->wire.rx_open) {
			events = EV_READ;
		}
		if (ss->wire.tx_pending || !ss->wire.rx_open) {
			events |= EV_WRITE;
		}
		/* Assert no abandonable sendable work when the write path is
		 * switched off.  send_stalled is the only legitimate exception:
		 * the session-level ACK handler owns re-arming EV_WRITE. */
		ASSERT(ss->state != SESSION_ESTABLISHED || ss->send_stalled ||
		       (events & EV_WRITE) ||
		       (ss->sched.sched_head == NULL &&
			ss->wire.sendbuf.head == NULL &&
			ss->wire.oobbuf.head == NULL));
		break;
	case SESSION_CLOSE_WAIT:
		/* Wait for peer to close; if receive is closed, drive teardown via write. */
		events = ss->wire.rx_open ? EV_READ : EV_WRITE;
		break;
	case SESSION_SUSPENDED:
		/* No transport I/O while waiting for reconnect. */
		/* falls through */
	default:
		return;
	}
	modify_io_events(ss->loop, &ss->w_socket, events);
}

void session_notify(struct mux_session *restrict ss)
{
	update_watcher(ss);
}

/* -------------------------------------------------------------------------
 * Connection & Frame Processing
 * Connection establishment, frame buffer management, frame parsing and
 * dispatch, send/recv flush, scheduler and control packet path.
 * ---------------------------------------------------------------------- */

/* Call session_reset then fire MUX_EVENT_CLOSED if the session closed.
 * expired is set when the event is triggered by a resume-timeout. */
void session_notify_closed(struct mux_session *restrict ss, const bool expired)
{
	session_reset(ss);
	if (ss->state == SESSION_CLOSED && ss->callbacks.on_event != NULL) {
		ss->callbacks.on_event(
			ss->userdata, ss, MUX_EVENT_CLOSED,
			(union mux_event_data){
				.closed.clean = ss->wire.rx_eof,
				.closed.expired = expired,
			});
	}
}

static void format_frame_flags(
	char *restrict buf, const size_t buflen, const uint_fast8_t flags)
{
	static const struct {
		uint_least8_t flag;
		const char *name;
	} names[] = {
		{ MUX_FLAG_SYN, "SYN" },   { MUX_FLAG_ACK, "ACK" },
		{ MUX_FLAG_FIN, "FIN" },   { MUX_FLAG_RST, "RST" },
		{ MUX_FLAG_PUSH, "PUSH" },
	};

	char *p = buf;
	const char *const end = buf + buflen;
	bool wrote = false;
	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		if ((flags & names[i].flag) == 0) {
			continue;
		}
		if (wrote && p + 1 < end) {
			*p++ = '|';
		}
		for (const char *s = names[i].name; *s != '\0' && p + 1 < end;
		     s++) {
			*p++ = *s;
		}
		wrote = true;
	}
	const uint_fast8_t unknown = flags & (uint_fast8_t)(~MUX_FLAG_MASK);
	if (unknown != 0) {
		const int ret = snprintf(
			p, (size_t)(end - p), "%sUNKNOWN(0x%02" PRIxFAST8 ")",
			wrote ? "|" : "", unknown);
		if (ret < 0 && buflen > 0) {
			buf[0] = '\0';
		}
		return;
	}
	if (!wrote) {
		const int ret = snprintf(buf, buflen, "NONE");
		if (ret < 0 && buflen > 0) {
			buf[0] = '\0';
		}
	} else if (p < end) {
		*p = '\0';
	}
}

void session_log_frame_header(
	struct mux_session *restrict ss, const char *restrict what,
	const unsigned char *restrict raw,
	const struct mux_header *restrict hdr)
{
	if (!LOGLEVEL(VERYVERBOSE)) {
		return;
	}
	char flags_str[64];
	format_frame_flags(flags_str, sizeof(flags_str), hdr->flags);

	LOG_BIN_F(
		VERYVERBOSE, raw, MUX_FRAME_HEADER_SIZE, 0,
		"[fd:%d] %s: stream_id=%" PRIuLEAST16 " length=%" PRIuLEAST16
		" flags=0x%02" PRIxLEAST8 "(%s)"
		" extra=%" PRIuLEAST16,
		ss->w_socket.fd, what, hdr->stream_id, hdr->length, hdr->flags,
		flags_str, hdr->extra);
}

static void mux_notify_write(struct mux_session *ss)
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
			ss->sched.sched_head != NULL, ss->send_stalled);
	}
	ss->wire.tx_pending = true;
	update_watcher(ss);
}

/* Emit a session-level ACK for all unacknowledged non-stream-0 frames.
 * Caller must ensure recv_seq != ack_seq. */
void session_emit_ack(struct mux_session *restrict ss)
{
	const uint_fast32_t delta = ss->recv_seq - ss->ack_seq;
	const uint_fast32_t emit = (delta > (uint_fast32_t)UINT16_MAX) ?
					   (uint_fast32_t)UINT16_MAX :
					   delta;
	if (session_send_ctrl(ss, STREAMID_CTRL, MUX_FLAG_ACK, emit)) {
		ss->ack_seq += emit;
		ss->session_ack_ticks = 0;
		ss->ack_pending = false;
	}
}

/* Update w_send_timeout after a send attempt:
 * - stop if nothing is pending (sendbuf, oobbuf, ready queue all empty)
 * - again if pending data exists and (progress was made OR timer is not running) */
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

/* ----------------------------------------------------------------
 * Unacked Ring Helpers — thin wrappers around mux_frame_ring with
 * session-level counter maintenance.
 * ---------------------------------------------------------------- */

/* O(1) append with automatic grow; updates session-level counters. */
static bool unacked_ring_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	size_t count)
{
	frame->unacked_count = count;
	if (!mux_frame_ring_push(&ss->unacked, frame)) {
		LOGOOM();
		return false;
	}
	ss->unacked_frames += count;
	COUNTER_ADD(ss->cnt.unacked_frames, count);
	ss->unacked_bytes += frame->len - count * MUX_FRAME_HEADER_SIZE;
	ss->send_seq += count;
	return true;
}

/* Add one unacked-ring entry worth @p count logical seqnums.  Hitting the
 * session cap only stalls new data dequeues; ACK/oob paths still run until
 * session_ack_trim drops the ring below session_window. */
static bool push_unacked(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	const size_t count)
{
	if (!unacked_ring_push(ss, frame, count)) {
		mux_frame_put(&ss->pool, frame);
		return false;
	}
	if (!ss->send_stalled &&
	    ss->unacked_bytes >= (size_t)ss->session_window * MUX_WINDOW_UNIT) {
		MUX_LOG_F(
			DEBUG, ss,
			"send stalled: unacked_bytes=%zu limit=%zu"
			" ready=%d sendbuf=%d oobbuf=%d"
			"; stalling data sends until peer acknowledges",
			ss->unacked_bytes,
			(size_t)ss->session_window * MUX_WINDOW_UNIT,
			ss->sched.sched_head != NULL,
			ss->wire.sendbuf.head != NULL,
			ss->wire.oobbuf.head != NULL);
		ss->send_stalled = true;
	}
	return true;
}

/* Keep flushed frames only when resume replay may need them.  Hello frames
 * and stream-0 controls are one-shot, retransmit copies only advance the
 * cursor, and bundled control frames are compacted before tracking.
 * This function handles both single-header frames and multi-header staging
 * frames produced by wire_sendbuf_push: it always walks the full header list
 * rather than short-circuiting on the first PUSH flag, so that a staging
 * frame containing a mix of PUSH and non-PUSH sub-frames is counted and
 * compacted correctly. */
static void session_track_sent(
	struct mux_session *restrict ss, struct mux_frame *restrict frame)
{
	ASSERT(frame->len >= MUX_FRAME_HEADER_SIZE);
	struct mux_header hdr;
	mux_read_header(frame->data, &hdr);

	/* Hello frames are handshake-only and never enter the resume log. */
	if (hdr.version == 0) {
		mux_frame_put(&ss->pool, frame);
		return;
	}

	/* Each retransmit copy corresponds to one original unacked entry. */
	if (ss->retransmit_copy == frame) {
		ss->retransmit_copy = NULL;
		ASSERT(ss->unacked != NULL &&
		       ss->retransmit_off < ss->unacked->count);
		ss->retransmit_off++;
		mux_frame_put(&ss->pool, frame);
		return;
	}

	/* Fast path: single-header frame (the common case).  The header walk
	 * below is only required for multi-header staging frames; a lone entry
	 * needs neither compaction nor a second header parse. */
	if (MUX_FRAME_HEADER_SIZE + (size_t)hdr.length == frame->len) {
		if (hdr.stream_id == STREAMID_CTRL) {
			mux_frame_put(&ss->pool, frame);
			return;
		}
		push_unacked(ss, frame, 1);
		return;
	}

	/* Walk all concatenated headers, strip stream-0 controls, and count
	 * the remaining entries.  For multi-header staging frames every
	 * sub-frame is counted. */
	unsigned char *dst = frame->data;
	const unsigned char *src = frame->data;
	const unsigned char *const end = frame->data + frame->len;
	size_t n = 0;
	while (src < end) {
		if ((size_t)(end - src) < MUX_FRAME_HEADER_SIZE) {
			MUX_LOG(ERROR, ss, "invalid internal frame layout");
			mux_frame_put(&ss->pool, frame);
			return;
		}
		mux_read_header(src, &hdr);
		const size_t entry_len = MUX_FRAME_HEADER_SIZE + hdr.length;
		if ((size_t)(end - src) < entry_len) {
			MUX_LOG(ERROR, ss, "invalid internal frame layout");
			mux_frame_put(&ss->pool, frame);
			return;
		}
		if (hdr.stream_id != STREAMID_CTRL) {
			if (dst != src) {
				memmove(dst, src, entry_len);
			}
			dst += entry_len;
			n++;
		}
		src += entry_len;
	}
	if (n == 0) {
		mux_frame_put(&ss->pool, frame);
		return;
	}
	frame->len = (size_t)(dst - frame->data);
	push_unacked(ss, frame, n);
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
		/* Track for Nagle algorithm: unacked data sent */
		s->unacked_bytes += (uint_least32_t)payload_len;
		COUNTER_ADD(
			ss->cnt.traffic.byt_push_sent,
			(uint_least64_t)payload_len);
	}

	s->grant_sent += raw_inc * MUX_WINDOW_UNIT;
	if (flags & MUX_FLAG_ACK) {
		s->ack_pending = false;
		ss->ack_pending = true;
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

/* Flush one send attempt for the current sendbuf head entry.
 * Returns true when the transport is still blocked (EAGAIN, partial write,
 * or TLS cross-direction stall); false when the head entry was fully sent
 * and removed from the queue (sendbuf may still have a following entry).
 * On fatal error session_reset or session_suspend has already been called. */
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
		return true; /* EAGAIN — transport buffer full */
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
	session_track_sent(ss, frame);
	return false;
}

/* EV_WRITE interleaves transport flushes with the next highest-priority work:
 * retransmit copy, oob control, queued frame, then freshly scheduled data.
 * Small frames are packed into staging entries at sendbuf tail via
 * wire_sendbuf_push; staging entries accumulate across loop iterations
 * and are flushed when full or at loop exit. */
static void send_cb(struct mux_session *restrict ss)
{
	ss->wire.tx_pending = false;

	/* TLS close_notify is terminal; a plain TCP FIN may still be resumable.
	 * Outbound TLS closes also discard the cached peer session_id so the next
	 * reconnect starts fresh instead of attempting an invalid resume. */
	if (!ss->wire.rx_open && ss->state == SESSION_ESTABLISHED) {
		if (ss->handshake.has_session_id
#if WITH_TLS
		    && (ss->wire.tlsconn == NULL)
#endif
		) {
			/* Plain TCP FIN keeps resume state intact. */
			session_suspend(ss);
			return;
		}
		wire_discard_buffers(ss);
		if (!ss->accepted) {
			ss->handshake.has_session_id = false;
		}
		session_set_state(ss, SESSION_CLOSING);
		ss->wire.tx_pending = true;
		update_send_timeout(ss, false);
		return;
	}

	bool made_progress = false;
	bool retransmitting = false;

	/* Flush partially-written EAGAIN residue from the previous call before
	 * producing more frames.  Without this, a TLS WANT_READ during HANDSHAKE
	 * would leave tls_want=EV_READ but tx_pending=false, so the sendbuf
	 * would stall until connect_timeout fires. */
	if (ss->wire.sendbuf.head != NULL && ss->wire.sendbuf.head->pos > 0) {
		if (flush_sendbuf_head(ss, &made_progress)) {
			if (ss->wire.sendbuf.head == NULL) {
				/* session_suspend/reset cleared the queue. */
				return;
			}
			MUX_LOG_F(
				DEBUG, ss,
				"send loop blocked on transport: sendbuf=%zu/%zu"
				" oobbuf=%d ready=%d",
				ss->wire.sendbuf.head->pos,
				ss->wire.sendbuf.head->len,
				ss->wire.oobbuf.head != NULL,
				ss->sched.sched_head != NULL);
			ss->wire.tx_pending = true;
			update_send_timeout(ss, made_progress);
			return;
		}
	}

	for (;;) {
		/* Flush reference entries from sendbuf head.  Reference entries
		 * (large frames, retransmit copies, OOB) cannot accumulate further
		 * and must be sent before producing more.  Staging entries with
		 * pos==0 are left in place to allow further packing.
		 * Staging entry = the sole entry in sendbuf with flag set. */
		if (ss->wire.sendbuf.head != NULL &&
		    !(ss->wire.sendbuf_staging &&
		      ss->wire.sendbuf.head == ss->wire.sendbuf.tail)) {
			if (flush_sendbuf_head(ss, &made_progress)) {
				if (ss->wire.sendbuf.head == NULL) {
					return;
				}
				MUX_LOG_F(
					DEBUG, ss,
					"send loop blocked on transport: sendbuf=%zu/%zu"
					" oobbuf=%d ready=%d",
					ss->wire.sendbuf.head->pos,
					ss->wire.sendbuf.head->len,
					ss->wire.oobbuf.head != NULL,
					ss->sched.sched_head != NULL);
				ss->wire.tx_pending = true;
				break;
			}
			continue;
		}

		if (ss->state != SESSION_ESTABLISHED) {
			/* Non-data state (HANDSHAKE, CLOSING): flush any
			 * accumulated staging entry and stop the produce loop. */
			if (ss->wire.sendbuf.head != NULL) {
				flush_sendbuf_head(ss, &made_progress);
				if (ss->wire.sendbuf.head != NULL) {
					ss->wire.tx_pending = true;
				}
			}
			break;
		}

		/* 2a. Resume replay takes precedence over new traffic. */
		if (ss->retransmit_off != SIZE_MAX) {
			/* Flush any frame in sendbuf before creating the next
			 * retransmit copy.  Without this, a copy of frame N
			 * could be in sendbuf while ss->retransmit_copy is
			 * overwritten with copy N+1; session_track_sent would
			 * then misidentify copy N as a new non-retransmit frame,
			 * double-counting its sequence number. */
			if (ss->wire.sendbuf.head != NULL) {
				if (flush_sendbuf_head(ss, &made_progress)) {
					if (ss->wire.sendbuf.head == NULL) {
						return;
					}
					ss->wire.tx_pending = true;
					break;
				}
			}
			if (ss->unacked != NULL &&
			    ss->retransmit_off >= ss->unacked->count) {
				ss->retransmit_off = SIZE_MAX;
			} else {
				if (!retransmitting) {
					MUX_LOG_F(
						DEBUG, ss,
						"retransmitting %zu unacked frames",
						ss->unacked_frames);
					retransmitting = true;
				}
				struct mux_frame *orig = mux_frame_ring_peek(
					ss->unacked, ss->retransmit_off);
				/* The offset advances only after the replay copy is fully flushed. */
				struct mux_frame *copy =
					mux_frame_get(&ss->pool);
				if (copy == NULL) {
					LOGOOM();
					break;
				}
				memcpy(copy->data, orig->data, orig->len);
				copy->pos = 0;
				copy->len = orig->len;
				ss->retransmit_copy = copy;
				mux_frame_list_push_front(
					&ss->wire.sendbuf, copy);
				continue;
			}
		}

		/* 2b. OOB controls bypass send_stalled so keepalives and PONGs still flow. */
		if (ss->wire.oobbuf.head != NULL) {
			struct mux_frame *oob =
				mux_frame_list_pop(&ss->wire.oobbuf);
			mux_frame_list_push_front(&ss->wire.sendbuf, oob);
			continue;
		}

		/* Flush accumulated staging entries before checking send_stalled
		 * so that unacked_frames / send_seq reflect the full set of frames
		 * already produced this round. */
		if (ss->wire.sendbuf.head != NULL) {
			if (flush_sendbuf_head(ss, &made_progress)) {
				if (ss->wire.sendbuf.head == NULL) {
					return;
				}
				ss->wire.tx_pending = true;
				break;
			}
		}

		/* 3. send_stalled blocks new payload only; per-stream ACK/FIN must still
		 * flow so the peer can drain its window and return session ACKs. */
		if (ss->send_stalled) {
			MUX_LOG_F(
				DEBUG, ss,
				"send loop paused by session window: unacked=%zu"
				" limit=%" PRIuLEAST32 " ready=%d",
				ss->unacked_frames, ss->session_window,
				ss->sched.sched_head != NULL);
			sched_flush_ctrl(ss);
			/* sched_flush_ctrl may have queued control frames for the next flush. */
			if (ss->wire.sendbuf.head != NULL) {
				continue;
			}
			break;
		}
		if (!sched_next_data(ss)) {
			/* No data frame produced: drain any pending control frames
			 * from DRR-queued streams before yielding. */
			sched_flush_ctrl(ss);
			if (ss->wire.sendbuf.head != NULL) {
				continue;
			}
			break; /* nothing to send */
		}
	}

	/* Flush any frames left in sendbuf after the produce loop exits. */
	if (ss->wire.sendbuf.head != NULL) {
		flush_sendbuf_head(ss, &made_progress);
		if (ss->wire.sendbuf.head != NULL) {
			ss->wire.tx_pending = true;
		}
	}

	update_send_timeout(ss, made_progress);
}

/* Read and dispatch one TLS record.  Returns true when a record was
 * successfully received and dispatched; returns false when no data is
 * available (EAGAIN) or on error. */
static bool recv_one(struct mux_session *restrict ss)
{
	if (!ringbuf_reserve(&ss->wire.recvbuf, 1, false)) {
		MUX_LOG(WARNING, ss, "receive buffer full");
		session_reset(ss);
		return false;
	}

	const size_t cap = ringbuf_write_space(ss->wire.recvbuf);
	if (cap == 0) {
		MUX_LOG(WARNING, ss, "receive buffer full");
		session_reset(ss);
		return false;
	}

	size_t nread = cap;
	unsigned char *const buf = ringbuf_write_ptr(ss->wire.recvbuf);

	if (!wire_recv(ss, buf, &nread)) {
		if (ss->handshake.has_session_id &&
		    (ss->state == SESSION_ESTABLISHED ||
		     (ss->state == SESSION_HANDSHAKE && !ss->accepted))) {
			session_suspend(ss);
		} else {
			session_reset(ss);
		}
		return false;
	}
	if (nread == 0) {
		/* TLS close_notify: wire_recv clears rx_open but returns true.
		 * During handshake there is no send-side handler to detect this;
		 * drive teardown immediately to avoid an EV_WRITE busy-wait loop.
		 * On a client resume attempt, suspend rather than reset so the
		 * unacked list and streams are preserved. */
		if (!ss->wire.rx_open && ss->state == SESSION_HANDSHAKE) {
			if (ss->handshake.has_session_id && !ss->accepted) {
				MUX_LOG(DEBUG, ss,
					"connection closed during resume handshake;"
					" re-suspending");
				session_suspend(ss);
			} else {
				MUX_LOG(DEBUG, ss,
					"connection closed during protocol handshake");
				session_reset(ss);
			}
		}
		return false;
	}

	ringbuf_produce(ss->wire.recvbuf, nread);
	ss->bytes_recv += (uint_least64_t)nread;
	COUNTER_ADD(ss->cnt.traffic.byt_mux_recv, (uint_least64_t)nread);
	if (ss->state == SESSION_ESTABLISHED) {
		ev_timer_again(ss->loop, &ss->w_timeout);
	}

	dispatch_frame(ss);
	return true;
}

static void recv_cb(struct mux_session *restrict ss)
{
	if (!recv_one(ss)) {
		return;
	}
	while (ss->state == SESSION_ESTABLISHED && wire_has_pending(ss)) {
		if (!recv_one(ss)) {
			break;
		}
	}
}

void session_eager_flush(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	const bool was_pending = ss->wire.tx_pending;
	sched_wake(ss, s);
	if (was_pending || ss->state != SESSION_ESTABLISHED) {
		return;
	}
	send_cb(ss);
	update_watcher(ss);
}

void session_flush(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED) {
		update_watcher(ss);
		return;
	}

	const bool want_write =
		(ss->wire.sendbuf.head != NULL || ss->wire.oobbuf.head != NULL);
	if (want_write) {
		if (!ss->wire.tx_pending) {
			MUX_LOG_F(
				DEBUG, ss,
				"flush requests write: sendbuf=%d"
				" oobbuf=%d ready=%d",
				ss->wire.sendbuf.head != NULL,
				ss->wire.oobbuf.head != NULL,
				ss->sched.sched_head != NULL);
		}
		ss->wire.tx_pending = true;
	}
	/* Re-arm EV_IDLE when sendbuf drains and lp queue has pending work. */
	if (ss->sched.lp_head != NULL && ss->wire.sendbuf.head == NULL) {
		ev_idle_start(ss->loop, &ss->sched.w_sched);
	}
	update_watcher(ss);
}

void session_flush_oob(struct mux_session *restrict ss)
{
	if (ss->wire.tx_pending || ss->state != SESSION_ESTABLISHED) {
		update_watcher(ss);
		return;
	}
	send_cb(ss);
	update_watcher(ss);
}

/* -------------------------------------------------------------------------
 * Event Callbacks & Public API
 * libev I/O, timer and idle callbacks; session creation, configuration,
 * and control packet public interface.
 * ---------------------------------------------------------------------- */

static void closing_cb(struct mux_session *ss)
{
	switch (wire_shutdown(ss)) {
	case WIRE_SHUTDOWN_PENDING:
		return;
	case WIRE_SHUTDOWN_DONE:
		session_set_state(ss, SESSION_CLOSE_WAIT);
		return;
	case WIRE_SHUTDOWN_ERROR:
		session_reset(ss);
		return;
	}
}

static void close_wait_cb(struct mux_session *ss)
{
	if (!wire_wait_eof(ss)) {
		MUX_LOG(DEBUG, ss, "unexpected state after shutdown");
	} else {
		MUX_LOG(VERBOSE, ss, "shutdown completed");
	}
	session_reset(ss);
}

static void handshake_start(struct mux_session *ss)
{
	session_set_state(ss, SESSION_HANDSHAKE);
	if (!ss->accepted) {
		/* Client: build and send ClientHello. */
		handshake_enqueue_hello(
			ss, PROTO_MSG_CLIENT_HELLO,
			ss->handshake.has_session_id /* resume request */);
	}
}

static void connect_cb(struct mux_session *ss)
{
	const int err = socket_get_error(ss->w_socket.fd);
	if (err != 0) {
		MUX_LOG_F(WARNING, ss, "connect: (%d) %s", err, strerror(err));
		session_reset(ss);
		return;
	}

	MUX_LOG(INFO, ss, "TCP connected");

#if WITH_TLS
	if (!wire_tls_start(ss)) {
		MUX_LOG(ERROR, ss, "TLS connect failed");
		session_reset(ss);
		return;
	}
	if (ss->wire.tlsconn != NULL) {
		handshake_start(ss);
		return;
	}
#endif /* WITH_TLS */

	handshake_start(ss);
}

static void socket_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct mux_session *restrict ss = w->data;
	ASSERT(loop == ss->loop);
	UNUSED(loop);
	MUX_LOG_F(
		VERBOSE, ss, "mux socket: state=%s revents=%d",
		session_state_str[ss->state], revents);

#if WITH_TLS
	/* Consume the pending TLS I/O request.  Fall through to recv_cb
	 * below to drive TLS handshake progress regardless of direction. */
	const bool tls_poll = (ss->wire.tls_want != 0);
	ss->wire.tls_want = 0;
#endif

	switch (ss->state) {
	case SESSION_CONNECT:
		connect_cb(ss);
		break;
	case SESSION_HANDSHAKE:
	case SESSION_ESTABLISHED:
		if ((revents & EV_READ) != 0
#if WITH_TLS
		    || tls_poll
#endif
		) {
			const bool was_handshake =
				(ss->state == SESSION_HANDSHAKE);
			recv_cb(ss);
			if (ss->state != SESSION_ESTABLISHED &&
			    ss->state != SESSION_HANDSHAKE) {
				break;
			}
			if (was_handshake && ss->state == SESSION_ESTABLISHED &&
			    ss->wire.tx_pending) {
				send_cb(ss);
				break;
			}
		}
		if ((revents & EV_WRITE) != 0) {
			send_cb(ss);
		}
		break;
	case SESSION_CLOSING:
		closing_cb(ss);
		break;
	case SESSION_CLOSE_WAIT:
		close_wait_cb(ss);
		break;
	default:
		FAILMSGF("unexpected session state %d", ss->state);
	}

	/* post-dispatch */
	if (ss->state == SESSION_CLOSED) {
		ss->last_modified = (int_least64_t)clock_monotonic_ns();
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss, MUX_EVENT_CLOSED,
				(union mux_event_data){
					.closed.clean = ss->wire.rx_eof,
				});
		}
		return;
	}
	session_flush(ss);
}

static void
connect_timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *restrict ss = w->data;
	ASSERT(loop == ss->loop);
	UNUSED(loop);
	const bool was_suspended = (ss->state == SESSION_SUSPENDED);
	switch (ss->state) {
	case SESSION_CONNECT:
	case SESSION_HANDSHAKE:
		MUX_LOG(WARNING, ss, "connect timeout");
		break;
	case SESSION_SUSPENDED:
		MUX_LOG(WARNING, ss, "session resume timed out");
		break;
	case SESSION_CLOSING:
	case SESSION_CLOSE_WAIT:
		MUX_LOG(WARNING, ss, "close timeout");
		break;
	default:
		FAILMSGF("unexpected session state %d", ss->state);
	}
	session_notify_closed(ss, was_suspended);
}

static void
send_timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *restrict ss = w->data;
	ASSERT(loop == ss->loop);
	UNUSED(loop);
	switch (ss->state) {
	case SESSION_ESTABLISHED:
		break;
	default:
		FAILMSGF("unexpected session state %d", ss->state);
	}
	MUX_LOG(WARNING, ss, "send timeout");
	if (ss->handshake.has_session_id) {
		session_suspend(ss);
		return;
	}
	session_notify_closed(ss, false);
}

static void timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *restrict ss = w->data;
	ASSERT(loop == ss->loop);
	UNUSED(loop);
	CHECKMSGF(
		ss->state == SESSION_ESTABLISHED, "unexpected session state %d",
		ss->state);
	/* When the session has a shared session_id, suspend rather than close
	 * so that streams survive short blackhole periods: the client will
	 * resume the session as soon as the network recovers.  Only sessions
	 * without a session_id (fresh connections that never completed a resume
	 * handshake) are torn down immediately. */
	if (ss->handshake.has_session_id) {
		MUX_LOG(WARNING, ss, "session timeout; suspending for resume");
		session_suspend(ss);
		return;
	}
	MUX_LOG(WARNING, ss, "session timeout");
	session_notify_closed(ss, false);
}

/* Handle an inbound PING (spec §5.3.2): immediately queue a PONG whose
 * payload is a byte-for-byte copy of the PING payload.  Silently discards
 * the PING when the rate limit is exceeded. */
void session_recv_ping(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	const int_fast64_t now = clock_monotonic_ns();
	if (now - ss->ping_recv_last_ns < MUX_PING_RATE_LIMIT_NS) {
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	/* Copy the PING payload from the receive buffer before discarding the
	 * frame; session_send_oob will copy it into oobbuf. */
	const unsigned char *ping_payload =
		ringbuf_read_ptr(ss->wire.recvbuf) + MUX_FRAME_HEADER_SIZE;
	const bool queued =
		session_send_oob(ss, MUX_CTRL_PONG, ping_payload, hdr->length);
	ringbuf_consume(ss->wire.recvbuf, frame_size);
	if (!queued) {
		/* OOM: PONG is silently dropped; the peer's estimator will
		 * time out and retry on the next measurement cycle. */
		return;
	}

	ss->ping_recv_last_ns = now;
	session_flush_oob(ss);
}

/* Expand the receive window of one stream to new_window bytes.  Called via
 * table_iterate; only grows already-granted per-stream receive credit. */
static bool update_stream_window_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	UNUSED(table);
	UNUSED(key);
	const uint_fast32_t new_window = *(const uint_fast32_t *)data;
	struct mux_stream *restrict s = element;
	if (new_window <= s->recv_window) {
		return true;
	}
	s->recv_window = new_window;
	stream_check_ack(s);
	return true;
}

void session_update_session_window(
	struct mux_session *restrict ss, const size_t window_bytes)
{
	const uint_least32_t initial_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	const size_t target_frames =
		(window_bytes + MUX_WINDOW_UNIT - 1) / MUX_WINDOW_UNIT;
	const uint_least32_t new_window = (uint_least32_t)MAX(
		MAX(ss->peer_stream_window, target_frames), initial_frames);
	if (ss->session_window == new_window) {
		return;
	}
	const bool grew = new_window > ss->session_window;
	ss->session_window = new_window;
	MUX_LOG_F(
		INFO, ss, "session window updated: session=%zu",
		(size_t)ss->session_window * MUX_WINDOW_UNIT);
	if (grew && ss->send_stalled &&
	    ss->unacked_bytes < (size_t)ss->session_window * MUX_WINDOW_UNIT) {
		MUX_LOG_F(
			DEBUG, ss,
			"send stall cleared by session window growth:"
			" unacked_bytes=%zu limit=%zu",
			ss->unacked_bytes,
			(size_t)ss->session_window * MUX_WINDOW_UNIT);
		ss->send_stalled = false;
		mux_notify_write(ss);
	}
}

static void session_update_stream_window(
	struct mux_session *restrict ss, const size_t window_bytes)
{
	const size_t target_frames =
		(window_bytes + MUX_WINDOW_UNIT - 1) / MUX_WINDOW_UNIT;
	const uint_least32_t frames =
		(uint_least32_t)MAX(target_frames, (size_t)1u);

	if (ss->stream_window == frames) {
		return;
	}
	const uint_least32_t old_stream = ss->stream_window;
	ss->stream_window = frames;
	if (frames > old_stream && ss->sched.streams != NULL) {
		uint_fast32_t w = (uint_fast32_t)frames * MUX_WINDOW_UNIT;
		table_iterate(ss->sched.streams, update_stream_window_cb, &w);
	}
	/* On shrink: leave per-stream recv_window intact now; each
	 * stream lazily syncs its recv_window down inside
	 * stream_check_ack once outstanding peer credit is consumed
	 * and the safety constraint is satisfied. */
	MUX_LOG_F(
		INFO, ss, "estimator updated: window=%zu stream=%zu",
		window_bytes, (size_t)ss->stream_window * MUX_WINDOW_UNIT);
}

/* Handle an inbound PONG (spec §5.3.3): feed the echoed timestamp into the
 * estimator, then apply its current BDP to the live window floors.  Also
 * clears the keepalive in-flight flag and resets the timer to the normal
 * keepalive interval so a successful PONG always defers the next probe. */
void session_recv_pong(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	if (hdr->length < MUX_PING_PAYLOAD_SIZE) {
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	const int_fast64_t sent_ns = (int_fast64_t)read_uint64(
		ringbuf_read_ptr(ss->wire.recvbuf) + MUX_FRAME_HEADER_SIZE);
	ringbuf_consume(ss->wire.recvbuf, frame_size);

	estimator_calculate(ss, sent_ns);
	if (ss->auto_stream_window) {
		session_update_stream_window(
			ss,
			estimator_window_size(&ss->estimator, ESTIMATOR_RX));
	}
	if (ss->auto_session_window) {
		session_update_session_window(
			ss,
			estimator_window_size(&ss->estimator, ESTIMATOR_TX));
	}

	/* Any PONG confirms the link is alive: reset the keepalive deadline
	 * to the full idle interval regardless of which path sent the PING. */
	const double keepalive = (double)ss->conf.keepalive;
	ev_timer_set(&ss->w_keepalive, 0.0, keepalive);
	if (ev_is_active(&ss->w_keepalive)) {
		ev_timer_again(ss->loop, &ss->w_keepalive);
	}
}

static void keepalive_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *restrict ss = w->data;
	ASSERT(loop == ss->loop);
	UNUSED(loop);
	CHECKMSGF(
		ss->state == SESSION_ESTABLISHED, "unexpected session state %d",
		ss->state);

	if (ss->estimator.ping_in_flight) {
		const int_fast64_t age_ns =
			clock_monotonic_ns() - ss->estimator.last_probe_ns;
		const int_fast64_t timeout_ns =
			(int_fast64_t)ss->conf.ping_timeout *
			INT64_C(1000000000);
		if (age_ns >= timeout_ns) {
			/* The probe has not been answered within ping_timeout. */
			if (ss->handshake.has_session_id) {
				MUX_LOG(WARNING, ss,
					"keepalive PING timeout; suspending for resume");
				session_suspend(ss);
			} else {
				MUX_LOG(WARNING, ss, "keepalive PING timeout");
				session_notify_closed(ss, false);
			}
			return;
		}
		/* Probe is still fresh (e.g. sent by the data path just before
		 * the keepalive interval expired); re-arm for remaining time. */
		const double remaining = (double)(timeout_ns - age_ns) / 1e9;
		ev_timer_set(&ss->w_keepalive, 0.0, remaining);
		ev_timer_again(ss->loop, &ss->w_keepalive);
		return;
	}

	if (!estimator_ping(ss)) {
		/* OOM: skip this cycle; the timer will fire again normally. */
		return;
	}
	const double ping_timeout = (double)ss->conf.ping_timeout;
	ev_timer_set(&ss->w_keepalive, 0.0, ping_timeout);
	ev_timer_again(ss->loop, &ss->w_keepalive);
	MUX_LOG(VERBOSE, ss, "keepalive PING sent");
	session_flush_oob(ss);
}

static void idle_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *restrict ss = w->data;
	ASSERT(loop == ss->loop);
	UNUSED(loop);
	CHECKMSGF(
		ss->state == SESSION_ESTABLISHED, "unexpected session state %d",
		ss->state);
	MUX_LOG(INFO, ss, "idle timeout, closing session");
	session_reset(ss);
	if (ss->state == SESSION_CLOSED) {
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss, MUX_EVENT_CLOSED,
				(union mux_event_data){
					.closed.clean = ss->wire.rx_eof,
				});
		}
	}
}

struct mux_session *
session_new(struct ev_loop *restrict loop, const struct mux_session_opts *opts)
{
	const struct mux_config *const conf = opts->conf;
	const int fd = opts->fd;
	const unsigned char *const id = opts->id;

	struct mux_session *ss = malloc(sizeof(struct mux_session));
	if (ss == NULL) {
		LOGOOM();
		return NULL;
	}
	*ss = (struct mux_session){
		.loop = loop,
		.conf = *conf,
		.pool = opts->pool,
		.tag = opts->tag,
		.callbacks = *opts->callbacks,
		.userdata = opts->userdata,
		.cnt = opts->cnt,
#if WITH_TLS
		.wire.tlsctx = opts->tlsctx,
		.wire.tlsconn = opts->conn,
#endif
		.state = SESSION_INIT,
		.last_modified = (int_least64_t)clock_monotonic_ns(),
		.accepted = (fd >= 0),
		.wire.rx_open = true,
		/* For accepted sessions, start timing from creation so setup time
		 * covers from accept() to SESSION_ESTABLISHED. */
		.connect_started = (fd >= 0) ? clock_monotonic_ns() : 0,
	};
	ss->retransmit_off = SIZE_MAX;

	ss->sched.streams = table_new(&mux_stream_table_opts);
	if (ss->sched.streams == NULL) {
		mux_frame_ring_free(&ss->unacked, &ss->pool);
		free(ss);
		return NULL;
	}
	ss->wire.recvbuf = ringbuf_new(131072);
	if (ss->wire.recvbuf == NULL) {
		LOGOOM();
		table_free(ss->sched.streams);
		mux_frame_ring_free(&ss->unacked, &ss->pool);
		free(ss);
		return NULL;
	}

	memcpy(ss->handshake.session_id, id, MUX_SESSION_ID_LEN);
	ss->handshake.has_session_id = (fd >= 0);

	if (opts->identity != NULL) {
		ss->handshake.identity = strdup(opts->identity);
	}
	if (opts->peer_id != NULL) {
		ss->handshake.peer_id = strdup(opts->peer_id);
	}

	ev_io_init(&ss->w_socket, socket_cb, fd, EV_READ);
	ss->w_socket.data = ss;

	const double timeout = (double)conf->timeout;
	ev_timer_init(&ss->w_timeout, timeout_cb, 0.0, timeout);
	ss->w_timeout.data = ss;

	const double keepalive = (double)conf->keepalive;
	ev_timer_init(&ss->w_keepalive, keepalive_cb, 0.0, keepalive);
	ss->w_keepalive.data = ss;

	const double send_timeout = (double)conf->send_timeout;
	ev_timer_init(&ss->w_send_timeout, send_timeout_cb, 0.0, send_timeout);
	ss->w_send_timeout.data = ss;

	const double connect_timeout = (double)conf->connect_timeout;
	ev_timer_init(
		&ss->w_connect_timeout, connect_timeout_cb, 0.0,
		connect_timeout);
	ss->w_connect_timeout.data = ss;

	sched_init(ss);

	const double idle_timeout = (double)conf->idle_timeout;
	ev_timer_init(&ss->w_idle_timeout, idle_cb, 0.0, idle_timeout);
	ss->w_idle_timeout.data = ss;
	/* Must follow all ev_timer_init calls (session_set_config uses ev_timer_set). */
	estimator_init(ss, MUX_INITIAL_SEND_WINDOW);
	session_set_config(ss, conf);
	COUNTER_ADD(ss->cnt.num_session_created, 1);
	return ss;
}

/* Initiate an immediate graceful shutdown: abandon all in-progress transfers,
 * close all streams, discard all buffered data, then enter SESSION_CLOSING so
 * that the transport-level close handshake (TLS close_notify then TCP FIN) can
 * proceed. */
void session_initiate_shutdown(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED &&
	    ss->state != SESSION_HANDSHAKE) {
		/* Not actively transferring data.  Force-close without
		 * allowing reconnection (session_reset would schedule a
		 * reconnect for outbound sessions, leaving the session
		 * alive with an active timer). */
		if (ss->state != SESSION_CLOSED) {
			session_set_state(ss, SESSION_CLOSED);
			session_stop(ss);
			session_cleanup(ss);
		}
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss, MUX_EVENT_CLOSED,
				(union mux_event_data){
					.closed.clean = ss->wire.rx_eof,
				});
		}
		return;
	}
	MUX_LOG(INFO, ss,
		"initiating graceful shutdown; dropping in-flight data");

	/* Stop all timers and the idle scheduler; keep the socket watcher. */
	struct ev_loop *restrict loop = ss->loop;
	ev_idle_stop(loop, &ss->sched.w_sched);
	ev_timer_stop(loop, &ss->w_timeout);
	ev_timer_stop(loop, &ss->w_keepalive);
	ev_timer_stop(loop, &ss->w_send_timeout);
	ev_timer_stop(loop, &ss->w_connect_timeout);
	ev_timer_stop(loop, &ss->sched.w_coalesce);
	ev_timer_stop(loop, &ss->w_idle_timeout);
	ss->stream_window = (uint_least32_t)MAX(
		estimator_window_size(&ss->estimator, ESTIMATOR_RX) / 2 /
			MUX_WINDOW_UNIT,
		(size_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));

	/* Free all streams: closes local fds, drains queues; no protocol
	 * frames are sent (per spec §5.6: streams are implicitly aborted). */
	sched_free_streams(ss);

	/* Discard all pending session-level data. */
	wire_discard_buffers(ss);
	unacked_ring_free_all(ss);

	session_set_state(ss, SESSION_CLOSING);
	ev_timer_set(
		&ss->w_connect_timeout, (double)ss->conf.connect_timeout, 0.0);
	ev_timer_start(loop, &ss->w_connect_timeout);
	ss->wire.tx_pending = true;
	update_watcher(ss);
}

void session_close(struct mux_session *restrict ss)
{
	MUX_LOG(VERBOSE, ss, "finalizing");
	session_stop(ss);
	session_cleanup(ss);
	ringbuf_free(ss->wire.recvbuf);
	handshake_cleanup(ss);
	COUNTER_ADD(ss->cnt.num_session_finalized, 1);
	free(ss);
}

void session_set_config(
	struct mux_session *restrict ss, const struct mux_config *restrict conf)
{
	const bool was_auto_stream_window = ss->auto_stream_window;
	const bool was_auto_session_window = ss->auto_session_window;
	ss->conf = *conf;
	ss->auto_stream_window = (conf->stream_window <= 0);
	ss->auto_session_window = (conf->session_window <= 0);
	const uint_least32_t initial_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	/* stream_window: auto (BDP-driven) or manual (fixed config). */
	if (ss->auto_stream_window) {
		if (!was_auto_stream_window) {
			/* Manual-to-auto: reset to the floor for a clean probe. */
			ss->stream_window = initial_frames;
		} else {
			/* Already auto: preserve the learned value (no floor). */
		}
	} else {
		ss->stream_window = (uint_least32_t)conf->stream_window;
	}
	/* session_window: auto (peer-driven) or manual (fixed config). */
	if (ss->auto_session_window) {
		if (!was_auto_session_window) {
			/* Switching from manual to auto: reset to the floor. */
			ss->session_window = initial_frames;
		} else {
			/* Already in auto mode: preserve the learned value,
			 * enforcing only the floor. */
			if (ss->session_window < initial_frames) {
				ss->session_window = initial_frames;
			}
		}
	} else {
		ss->session_window = (uint_least32_t)conf->session_window;
	}

	const double timeout = (double)conf->timeout;
	ev_timer_set(&ss->w_timeout, 0.0, timeout);
	if (ev_is_active(&ss->w_timeout)) {
		ev_timer_again(ss->loop, &ss->w_timeout);
	}

	const double keepalive = (double)conf->keepalive;
	ev_timer_set(&ss->w_keepalive, 0.0, keepalive);
	if (ev_is_active(&ss->w_keepalive)) {
		ev_timer_again(ss->loop, &ss->w_keepalive);
	}

	const double send_timeout = (double)conf->send_timeout;
	ev_timer_set(&ss->w_send_timeout, 0.0, send_timeout);
	if (ss->w_socket.fd != -1 &&
	    socket_user_timeout(ss->w_socket.fd, conf->send_timeout * 1000) ==
		    0) {
		ss->w_send_timeout.repeat = 0.0;
	}
	if (ss->w_send_timeout.repeat > 0.0) {
		if (ev_is_active(&ss->w_send_timeout)) {
			ev_timer_again(ss->loop, &ss->w_send_timeout);
		}
	} else {
		ev_timer_stop(ss->loop, &ss->w_send_timeout);
	}

	const double connect_timeout = (double)conf->connect_timeout;
	ev_timer_set(&ss->w_connect_timeout, 0.0, connect_timeout);
	if (ev_is_active(&ss->w_connect_timeout)) {
		ev_timer_again(ss->loop, &ss->w_connect_timeout);
	}

	const double idle_timeout = (double)conf->idle_timeout;
	if (idle_timeout > 0.0) {
		ev_timer_set(&ss->w_idle_timeout, 0.0, idle_timeout);
		if (ev_is_active(&ss->w_idle_timeout)) {
			ev_timer_again(ss->loop, &ss->w_idle_timeout);
		}
	} else {
		ev_timer_stop(ss->loop, &ss->w_idle_timeout);
		ev_timer_set(&ss->w_idle_timeout, 0.0, 0.0);
	}

	/* Seed the estimator only when first entering auto mode.  In the
	 * already-auto path the window and probe state have already converged;
	 * re-seeding would wipe the learned RTT/BW windows. */
	if (ss->auto_stream_window && !was_auto_stream_window) {
		estimator_init(ss, (size_t)ss->stream_window * MUX_WINDOW_UNIT);
	}
}

void session_drain(struct mux_session *restrict ss)
{
	ss->draining = true;
	/* If the session is already idle (established with no active streams),
	 * initiate a graceful shutdown immediately rather than waiting for a
	 * stream to close.  Subtract tombstones: closed streams linger as
	 * tombstones for late-frame suppression and are not "active". */
	if (ss->state == SESSION_ESTABLISHED && ss->sched.streams != NULL &&
	    table_size(ss->sched.streams) == ss->sched.num_tombstones) {
		session_initiate_shutdown(ss);
	}
}

void session_start(struct mux_session *restrict ss)
{
	if (ss->w_socket.fd == -1) {
		/* Client session without transport; caller must supply a
		 * connected fd via mux_attach_fd() before I/O begins. */
		return;
	}
	MUX_LOG(VERBOSE, ss, "starting");

#if WITH_TLS
	if (!wire_tls_start(ss)) {
		MUX_LOG(ERROR, ss, "TLS start failed");
		session_reset(ss);
		return;
	}
#endif

	if (socket_user_timeout(
		    ss->w_socket.fd, ss->conf.send_timeout * 1000) == 0) {
		ss->w_send_timeout.repeat = 0.0;
	}
	handshake_start(ss);
	update_watcher(ss);
	ev_timer_again(ss->loop, &ss->w_connect_timeout);
}

void session_attach_fd(struct mux_session *restrict ss, const int fd)
{
	CHECKMSGF(
		ss->state == SESSION_INIT || ss->state == SESSION_SUSPENDED ||
			ss->state == SESSION_CLOSED,
		"session_attach_fd: unexpected state %d", ss->state);

	/* Transitioning out of SUSPENDED: stop the resume timeout and
	 * restore repeat clobbered by session_suspend's one-shot reuse. */
	if (ss->state == SESSION_SUSPENDED) {
		ev_timer_stop(ss->loop, &ss->w_connect_timeout);
		ss->w_connect_timeout.repeat = (double)ss->conf.connect_timeout;
	}

	if (ss->sched.streams == NULL) {
		ss->sched.streams = table_new(&mux_stream_table_opts);
		if (ss->sched.streams == NULL) {
			LOGOOM();
			SOCKET_CLOSE_FD(fd);
			return;
		}
	}
	ss->wire.rx_open = true;
	ss->wire.tx_pending = false;
	ss->wire.rx_eof = false;
#if WITH_TLS
	ss->wire.tls_want = 0;
#endif
	ss->draining = false;

	/* Detach from the old transport fd before switching to the new one.
	 * When reconnecting from SUSPENDED the socket watcher is still
	 * active on the stale fd; ev_io_set alone only swaps the fd field
	 * without updating the backend, so explicitly stop first. */
	ev_io_stop(ss->loop, &ss->w_socket);
	ev_io_set(&ss->w_socket, fd, EV_WRITE);
	if (socket_user_timeout(fd, ss->conf.send_timeout * 1000) == 0) {
		ss->w_send_timeout.repeat = 0.0;
	}
	/* Start timing from attach so setup time covers from socket creation
	 * (tunnel_do_connect calls us immediately after connect()) to
	 * SESSION_ESTABLISHED. */
	ss->connect_started = clock_monotonic_ns();
	session_set_state(ss, SESSION_CONNECT);
	ev_io_start(ss->loop, &ss->w_socket);
	ev_timer_again(ss->loop, &ss->w_connect_timeout);

	MUX_LOG_F(DEBUG, ss, "transport attached [fd:%d]", fd);
}

struct mux_stream *session_open_stream(struct mux_session *restrict ss)
{
	if (ss->state == SESSION_CLOSED) {
		MUX_LOG(VERBOSE, ss, "open_stream: session closed");
		return NULL;
	}
	if (ss->state != SESSION_ESTABLISHED) {
		MUX_LOG_F(
			VERBOSE, ss,
			"open_stream: session not established (state=%s)",
			session_state_str[ss->state]);
		return NULL;
	}
	if (ss->draining) {
		MUX_LOG(VERBOSE, ss, "open_stream: session draining");
		return NULL;
	}
	if (ss->handshake.peer_rejects_inbound_streams) {
		MUX_LOG(ERROR, ss, "peer does not accept inbound streams");
		return NULL;
	}
	if (ss->conf.max_halfopen > 0 &&
	    ss->num_halfopen >= (size_t)ss->conf.max_halfopen) {
		MUX_LOG_F(
			VERBOSE, ss, "open_stream: max_halfopen (%d) reached",
			ss->conf.max_halfopen);
		return NULL;
	}
	if (ss->conf.max_streams > 0 &&
	    table_size(ss->sched.streams) - ss->sched.num_tombstones >=
		    (size_t)ss->conf.max_streams) {
		MUX_LOG_F(
			VERBOSE, ss, "open_stream: max_streams (%d) reached",
			ss->conf.max_streams);
		return NULL;
	}
	const uint_fast16_t id = sched_alloc_stream_id(ss);
	if (id == STREAMID_CTRL) {
		/* All stream IDs in this parity class are active (spec §4.1);
		 * reject the request and wait for existing streams to close. */
		MUX_LOG(VERBOSE, ss, "open_stream: stream IDs exhausted");
		return NULL;
	}

	struct mux_stream *s = stream_new(ss, id, true);
	if (s == NULL) {
		LOGOOM();
		return NULL;
	}
	if (!sched_add_stream(ss, s)) {
		MUX_LOG(ERROR, ss, "open_stream: stream_add failed");
		stream_free(s);
		return NULL;
	}
	s->send_window = MUX_DEFAULT_SEND_WINDOW;
	MUX_LOG_F(DEBUG, ss, "opened stream %" PRIuFAST16, id);
	sched_wake(ss, s);
	MUX_LOG_F(
		VERYVERBOSE, ss, "queued initial SYN for stream %" PRIuLEAST16,
		s->id);
	return s;
}

/* Discard all unsent non-RST frames for stream_id from the send queue.
 * RST frames are preserved so that a previously-queued RST is never suppressed.
 * A frame already partially flushed to wire (pos > 0) must be delivered in
 * full to preserve framing sync, so it is never discarded. */
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
		if (!discard) {
			prev = frame;
			frame = next;
			continue;
		}

		struct mux_frame *const removed =
			mux_frame_list_remove_after(&ss->wire.sendbuf, prev);
		ASSERT(removed == frame);
		(void)removed;
		if (ss->retransmit_copy == frame) {
			ss->retransmit_copy = NULL;
		}
		if (ss->wire.sendbuf_staging &&
		    ss->wire.sendbuf.tail == frame) {
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
	struct mux_frame *frame = mux_frame_get(&ss->pool);
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
	ASSERT(payload_len <= MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *frame = mux_frame_get(&ss->pool);
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

/* -------------------------------------------------------------------------
 * Send Path
 * Frame buffer management, send/recv flush, scheduler and control packet path.
 * ---------------------------------------------------------------------- */

void session_handshake_done(struct mux_session *ss)
{
	MUX_LOG(VERBOSE, ss, "mux negotiation completed");
	ev_timer_stop(ss->loop, &ss->w_connect_timeout);
	/* Distinguish fresh establish from resume before session_set_state
	 * clears connect_started and updates peer_addr. */
	const bool is_resume = (ss->peer_addr.sa.sa_family != AF_UNSPEC);
	session_set_state(ss, SESSION_ESTABLISHED);
	ev_timer_again(ss->loop, &ss->w_timeout);
	if (LOGLEVEL(NOTICE)) {
		char str[32];
		format_duration(
			str, sizeof(str),
			make_duration_nanos(ss->last_connect_latency_ns));
		const char *const verb = is_resume ? "resumed" : "established";
		if (ss->peer_addr.sa.sa_family != AF_UNSPEC) {
			char peer_str[64];
			sa_format(
				peer_str, sizeof(peer_str), &ss->peer_addr.sa);
			MUX_LOG_F(
				NOTICE, ss, "session %s peer=%s setup=%s", verb,
				peer_str, str);
		} else {
			MUX_LOG_F(NOTICE, ss, "session %s setup=%s", verb, str);
		}
	}
	ss->last_modified = (int_least64_t)clock_monotonic_ns();

	if (!ss->accepted) {
		if (ss->conf.idle_timeout > 0 &&
		    table_size(ss->sched.streams) == 0) {
			ev_timer_again(ss->loop, &ss->w_idle_timeout);
		}
	}

	/* Re-activate streams queued during suspension: data-ready via EV_WRITE,
	 * INIT/CLOSED lifecycle via EV_IDLE. */
	if (ss->sched.sched_head != NULL) {
		ss->wire.tx_pending = true;
	}
	if (ss->sched.lp_head != NULL && ss->wire.sendbuf.head == NULL) {
		ev_idle_start(ss->loop, &ss->sched.w_sched);
	}
	/* Re-arm w_coalesce on resume with preserved Nagle/ACK backlog or
	 * session ACK delta.  sched_coalesce_arm is idempotent. */
	if (ss->sched.delay_head != NULL || ss->recv_seq != ss->ack_seq) {
		sched_coalesce_arm(ss);
	}

	/* If draining was requested before the handshake completed and there
	 * are no active streams, initiate a graceful shutdown immediately. */
	if (ss->draining && ss->sched.streams != NULL &&
	    table_size(ss->sched.streams) == 0) {
		session_initiate_shutdown(ss);
	}
}

/* Sum payload bytes for @p count sub-frames starting at byte offset @p *offset
 * within frame @p f, advancing *offset past the summed sub-frames.  Used by
 * session_ack_trim to account bytes on ring trim; called only on frames that
 * passed the send path so the data is always valid. */
static size_t frame_payload_bytes_from(
	const struct mux_frame *restrict f, size_t *restrict offset,
	size_t count)
{
	const unsigned char *src = f->data + *offset;
	const unsigned char *const frame_end = f->data + f->len;
	size_t total = 0;
	while (count > 0 && src + MUX_FRAME_HEADER_SIZE <= frame_end) {
		struct mux_header hdr;
		mux_read_header(src, &hdr);
		total += hdr.length;
		src += MUX_FRAME_HEADER_SIZE + (size_t)hdr.length;
		count--;
	}
	*offset = (size_t)(src - f->data);
	return total;
}

/* Trim @p count logical frames from the unacked ring.  Returns false on protocol
 * violation (acked > unacked).  Clears send_stalled on underflow. */
bool session_ack_trim(struct mux_session *restrict ss, const uint_fast32_t count)
{
	if (count > ss->unacked_frames) {
		MUX_LOG_F(
			ERROR, ss,
			"session ACK overflow: count=%" PRIuFAST32
			" unacked=%zu",
			count, ss->unacked_frames);
		return false;
	}
	if (count == 0) {
		return true;
	}
	const uint_fast32_t trim = count;
	/* Update logical counters upfront. */
	ss->unacked_frames -= trim;
	COUNTER_SUB(ss->cnt.unacked_frames, trim);
	ss->last_ack_recv += trim;
	/* Walk physical frames from head; advance for fully-consumed entries,
	 * partial-consume the last frame in-place. */
	size_t remaining = trim;
	size_t popped = 0;
	size_t trimmed_bytes = 0;
	while (remaining > 0) {
		struct mux_frame *f = mux_frame_ring_peek(ss->unacked, 0);
		if (f == NULL) {
			/* Ring empty but logical counter says otherwise;
			 * clamp to prevent out-of-bounds access. */
			ss->unacked_frames += (uint_fast32_t)remaining;
			COUNTER_ADD(
				ss->cnt.unacked_frames,
				(uint_fast32_t)remaining);
			ss->unacked_bytes = 0;
			ss->unacked_partial_offset = 0;
			break;
		}
		size_t offset = ss->unacked_partial_offset;
		if (f->unacked_count > remaining) {
			/* Partial trim: account bytes for `remaining` sub-frames
			 * starting at the saved byte offset. */
			const size_t bytes =
				frame_payload_bytes_from(f, &offset, remaining);
			ss->unacked_bytes -= bytes;
			trimmed_bytes += bytes;
			ss->unacked_partial_offset = (uint_least32_t)offset;
			f->unacked_count -= remaining;
			remaining = 0;
		} else {
			/* Full pop: account remaining bytes for this entry. */
			const size_t bytes = frame_payload_bytes_from(
				f, &offset, f->unacked_count);
			ss->unacked_bytes -= bytes;
			trimmed_bytes += bytes;
			ss->unacked_partial_offset = 0;
			remaining -= f->unacked_count;
			(void)mux_frame_ring_pop(ss->unacked);
			mux_frame_put(&ss->pool, f);
			popped++;
		}
	}
	if ((ss->auto_stream_window || ss->auto_session_window) &&
	    trimmed_bytes > 0) {
		estimator_add_acked(ss, trimmed_bytes);
	}
	/* When retransmit is in-flight, each popped frame advances the ring
	 * head, so the offset from head must be reduced accordingly.  If the
	 * peer acked past our retransmit position the offset underflows to
	 * zero (restart from the new head).  Then clamp when the offset lands
	 * past the shrunken ring end. */
	if (ss->retransmit_off != SIZE_MAX) {
		if (ss->retransmit_off >= popped) {
			ss->retransmit_off -= popped;
		} else {
			ss->retransmit_off = 0;
		}
		if (ss->unacked != NULL &&
		    ss->retransmit_off >= ss->unacked->count) {
			ss->retransmit_off = SIZE_MAX;
		}
	}

	if (ss->send_stalled &&
	    ss->unacked_bytes < (size_t)ss->session_window * MUX_WINDOW_UNIT) {
		MUX_LOG_F(
			DEBUG, ss,
			"send stall cleared by session ACK: acked=%" PRIuFAST32
			" unacked_bytes=%zu limit=%zu ready=%d",
			trim, ss->unacked_bytes,
			(size_t)ss->session_window * MUX_WINDOW_UNIT,
			ss->sched.sched_head != NULL);
		ss->send_stalled = false;
		mux_notify_write(ss);
	}
	return true;
}

/* Close the transport layer only, preserving stream state and the unacked
 * ring so that the session can be resumed over a new connection.
 * Called when a transport error occurs on an established session or on a
 * client session mid-resume-handshake (SESSION_HANDSHAKE, has_session_id,
 * !accepted).  Sets state to SESSION_SUSPENDED and starts the resume timeout. */
void session_suspend(struct mux_session *restrict ss)
{
	ASSERT(ss->state == SESSION_ESTABLISHED ||
	       (ss->state == SESSION_HANDSHAKE && !ss->accepted &&
		ss->handshake.has_session_id));
	if (ss->state == SESSION_HANDSHAKE) {
		MUX_LOG(WARNING, ss,
			"transport lost during resume handshake; re-suspending");
	} else {
		MUX_LOG(WARNING, ss,
			"transport lost; session suspended awaiting resume");
	}
	session_set_state(ss, SESSION_SUSPENDED);

	/* Move partially flushed frames into the resume log before transport
	 * teardown.  Detaching the list first transfers ownership to
	 * session_track_sent and avoids double-free paths through session_reset. */
	if (ss->wire.sendbuf.head != NULL) {
		struct mux_frame_list captured = ss->wire.sendbuf;
		ss->wire.sendbuf = (struct mux_frame_list){ 0 };
		struct mux_frame *frame;
		while ((frame = mux_frame_list_pop(&captured)) != NULL) {
			if (frame == ss->retransmit_copy) {
				mux_frame_put(&ss->pool, frame);
			} else {
				session_track_sent(ss, frame);
			}
		}
	}

	/* Frames in sendbuf (including staging entries) were already captured
	 * above.  Staging entries go through session_track_sent which walks
	 * all concatenated headers — the same path as single-header frames. */
	ss->wire.sendbuf_staging = false;
	ss->retransmit_copy = NULL;

	/* OOB controls never replay across resume; drop the stale transport state. */
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);

	/* Resume replay always restarts from the current unacked head. */
	if (ss->unacked != NULL && ss->unacked->count > 0) {
		ss->retransmit_off = 0;
	} else {
		ss->retransmit_off = SIZE_MAX;
	}
	/* Close transport. */
	ev_io_stop(ss->loop, &ss->w_socket);
	ev_idle_stop(ss->loop, &ss->sched.w_sched);
	ev_timer_stop(ss->loop, &ss->w_timeout);
	ev_timer_stop(ss->loop, &ss->w_keepalive);
	ev_timer_stop(ss->loop, &ss->w_send_timeout);
	ev_timer_stop(ss->loop, &ss->w_connect_timeout);
	ev_timer_stop(ss->loop, &ss->sched.w_coalesce);
	ev_timer_stop(ss->loop, &ss->w_idle_timeout);

	wire_conn_free(ss);
	if (ss->w_socket.fd != -1) {
		SOCKET_CLOSE_FD(ss->w_socket.fd);
		ss->w_socket.fd = -1;
	}
	ringbuf_reset(ss->wire.recvbuf);
	ss->wire.rx_open = true;
	ss->wire.tx_pending = false;
#if WITH_TLS
	ss->wire.tls_want = 0;
#endif

	/* Reuse w_connect_timeout as a one-shot resume deadline.  send_timeout
	 * is not used in SESSION_SUSPENDED; it gates live sends only. */
	const double wait = (double)ss->conf.resume_timeout;
	ev_timer_set(&ss->w_connect_timeout, wait, 0.0);
	ev_timer_start(ss->loop, &ss->w_connect_timeout);

	/* Notify the upper layer after the session enters SUSPENDED. Dialed
	 * sessions may reconnect immediately; accepted sessions typically wait
	 * for the peer to resume. */
	if (ss->callbacks.on_event != NULL) {
		ss->callbacks.on_event(
			ss->userdata, ss, MUX_EVENT_SUSPENDED,
			(union mux_event_data){ 0 });
	}
}

/* Resume: migrate fd from @p new_ss, send ServerHello, retransmit, destroy @p new_ss.
 * Returns false on session_suspend or resume_ack_recv failure. */
bool session_resume_transport(
	struct mux_session *restrict ss, struct mux_session *restrict new_ss,
	const uint_least32_t client_resume_seq)
{
	/* Handle the race where the server session is still ESTABLISHED when
	 * the client reconnects (transport loss not yet detected server-side).
	 * Suspend the old transport first so the resume logic finds canonical
	 * SUSPENDED state. */
	if (ss->state == SESSION_ESTABLISHED) {
		session_suspend(ss);
		if (ss->state != SESSION_SUSPENDED) {
			/* session_suspend hit the unacked cap and reset ss. */
			if (ss->callbacks.on_event != NULL) {
				ss->callbacks.on_event(
					ss->userdata, ss, MUX_EVENT_CLOSED,
					(union mux_event_data){ 0 });
			}
			return false;
		}
	}

	MUX_LOG_F(
		INFO, ss,
		"resuming from suspended state, client_resume_seq=%" PRIuLEAST32,
		client_resume_seq);

	/* Trim the frames the client already received. */
	if (!session_resume_ack_recv(ss, client_resume_seq)) {
		session_reset(ss);
		/* The suspended session is now CLOSED but still in the caller's
		 * session list; emit MUX_EVENT_CLOSED via on_event so the owner
		 * can remove and clean it up. */
		if (ss->callbacks.on_event != NULL) {
			ss->callbacks.on_event(
				ss->userdata, ss, MUX_EVENT_CLOSED,
				(union mux_event_data){
					.closed.clean = ss->wire.rx_eof,
				});
		}
		return false;
	}

	/* Migrate the transport fd from the transient session. */
	const int new_fd = new_ss->w_socket.fd;
	/* Stop the transient's socket watcher before stealing its fd.
	 * Without this, session_reset(new_ss) -> session_stop -> ev_io_stop
	 * would fire on an active watcher with fd=-1, triggering a libev
	 * assertion (ev_io_stop: illegal fd). */
	ev_io_stop(new_ss->loop, &new_ss->w_socket);
	new_ss->w_socket.fd = -1; /* prevent close in new_ss cleanup */
#if WITH_TLS
	wire_migrate_tlsconn(ss, new_ss);
#endif
	if (ss->w_socket.fd != -1) {
		SOCKET_CLOSE_FD(ss->w_socket.fd);
	}

	/* Reset transport buffers */
	wire_discard_buffers(ss);
	ss->wire.rx_open = true;
	ss->wire.tx_pending = false;
#if WITH_TLS
	ss->wire.tls_want = 0;
#endif

	ev_io_set(&ss->w_socket, new_fd, EV_READ | EV_WRITE);

	ev_timer_stop(ss->loop, &ss->w_send_timeout);
	/* Stop the one-shot resume deadline that session_suspend started.
	 * Restore repeat so the subsequent ev_timer_again arms correctly. */
	ev_timer_stop(ss->loop, &ss->w_connect_timeout);
	ss->w_connect_timeout.repeat = (double)ss->conf.connect_timeout;

	/* Destroy the transient session (fd already stolen above). */
	/* Transfer the attach timestamp so setup time covers from session_new()
	 * to SESSION_ESTABLISHED on the resumed session too. */
	ss->connect_started = new_ss->connect_started;
	session_reset(new_ss);

	/* Send ServerHello identifying the client back to itself. */
	session_set_state(ss, SESSION_HANDSHAKE);
	/* Resume cancels any pending drain: the session is being
	 * re-established and must accept new streams again. */
	ss->draining = false;
	ev_timer_again(ss->loop, &ss->w_connect_timeout);
	if (!handshake_enqueue_hello(ss, PROTO_MSG_SERVER_HELLO, true)) {
		/* handshake_enqueue_hello already called session_reset(ss); inform the
		 * caller so it can remove the suspended session from its list. */
		if (ss->state == SESSION_CLOSED) {
			if (ss->callbacks.on_event != NULL) {
				ss->callbacks.on_event(
					ss->userdata, ss, MUX_EVENT_CLOSED,
					(union mux_event_data){
						.closed.clean = ss->wire.rx_eof,
					});
			}
		}
		return false;
	}
	session_handshake_done(ss);

	/* Start retransmit replay and I/O. */
	if (ss->unacked != NULL && ss->unacked->count > 0) {
		ss->retransmit_off = 0;
		ss->wire.tx_pending = true;
	}
	ev_io_start(ss->loop, &ss->w_socket);
	update_watcher(ss);
	return true;
}

/* Apply peer_ack from a resume hello: trim the unacked ring and set the
 * retransmit offset.  Returns false on protocol violation. */
bool session_resume_ack_recv(
	struct mux_session *restrict ss, const uint_least32_t peer_ack)
{
	if (peer_ack < ss->last_ack_recv) {
		MUX_LOG_F(
			ERROR, ss,
			"session resume: peer_ack %" PRIuLEAST32
			" < last_ack_recv %" PRIuLEAST32,
			peer_ack, ss->last_ack_recv);
		return false;
	}
	const uint_least32_t trim = peer_ack - ss->last_ack_recv;
	if (!session_ack_trim(ss, (uint_fast32_t)trim)) {
		return false;
	}
	/* Position the retransmit offset at the first remaining frame. */
	ss->retransmit_off =
		(ss->unacked != NULL && ss->unacked->count > 0) ? 0 : SIZE_MAX;
	return true;
}
