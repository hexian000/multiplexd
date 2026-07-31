/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file recv.c
 * @brief Mux receive layer (1/3): read and parse frames off the transport, run
 *        the per-frame logic -- stream dispatch, flow-control accounting,
 *        control-frame (PING/PONG) handling, receive-driven window updates --
 *        and hand payload to stream receive buffers.
 *
 * The mux fd is handled in three layers: receive (recv.c) -> schedule (sched.c)
 * -> send (send.c + wire.c).  Cross-layer seam: mux_session_flush_resp lets a
 * receive batch synchronously drive schedule+send (prompt PONG/ACK) rather than
 * waiting for the next EV_WRITE.
 */

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/recv.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "binary/serial.h"
#include "binary/serialize.h"
#include "meta/likely.h"
#include "meta/minmax.h"
#include "os/clock.h"
#include "strings/format.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static inline bool is_valid_peer_stream_id(
	const struct mux_session *ss, const uint_fast16_t stream_id)
{
	if (stream_id == STREAMID_CTRL) {
		return false;
	}
	if (ss->accepted) {
		return (stream_id & 1u) != 0;
	}
	return (stream_id & 1u) == 0;
}

static bool
validate_flags_by_stream(const struct mux_stream *s, const uint_fast8_t flags)
{
	const uint_fast8_t non_rst_flags =
		flags & (uint_fast8_t)(~MUX_FLAG_RST);

	switch (s->state) {
	case STREAM_SYN_SENT:
		if ((non_rst_flags & (MUX_FLAG_SYN | MUX_FLAG_ACK)) !=
		    (MUX_FLAG_SYN | MUX_FLAG_ACK)) {
			return false;
		}
		return (non_rst_flags & (uint_fast8_t) ~(
						MUX_FLAG_SYN | MUX_FLAG_ACK |
						MUX_FLAG_PUSH)) == 0;
	case STREAM_SYN_RECEIVED:
		break;
	case STREAM_ESTABLISHED:
	case STREAM_FIN_WAIT:
		if (non_rst_flags == 0) {
			return false;
		}
		/* Resume replay may duplicate a prior SYN|ACK; SYN becomes idempotent
		 * once ACK is present and the frame can fall through normally. */
		if ((non_rst_flags & MUX_FLAG_SYN) != 0) {
			return (non_rst_flags & MUX_FLAG_ACK) != 0;
		}
		return true;
	case STREAM_CLOSE_WAIT:
	case STREAM_CLOSING:
		if (non_rst_flags == 0) {
			return false;
		}
		/* Resume replay may duplicate a prior SYN|ACK sent before the
		 * stream progressed this far; same idempotent-SYN carve-out as
		 * ESTABLISHED/FIN_WAIT above (including staying permissive
		 * about PUSH, since a replayed fast-open SYN|ACK may carry a
		 * payload), so it isn't rejected as an invalid flag
		 * combination and RSTs a stream that should survive resume
		 * transparently. */
		if ((non_rst_flags & MUX_FLAG_SYN) != 0) {
			return (non_rst_flags & MUX_FLAG_ACK) != 0;
		}
		return (non_rst_flags &
			(uint_fast8_t) ~(MUX_FLAG_ACK | MUX_FLAG_FIN)) == 0;
	case STREAM_INIT:
	case STREAM_CLOSED:
		break;
	default:
		FAILMSGF("unexpected stream state: %d", s->state);
	}
	return false;
}

static inline bool
is_ignorable_unknown_terminal_frame(const struct mux_header *restrict hdr)
{
	const uint_fast8_t flags = hdr->flags & MUX_FLAG_MASK;

	if (hdr->length != 0) {
		return false;
	}
	if ((flags & (MUX_FLAG_ACK | MUX_FLAG_FIN)) == 0) {
		return false;
	}
	return (flags & (uint_fast8_t) ~(MUX_FLAG_ACK | MUX_FLAG_FIN)) == 0;
}

static void process_syn_payload(
	struct mux_session *ss, struct mux_stream *restrict s,
	const struct mux_header *restrict hdr, const size_t frame_size)
{
	/* mux_stream_start() has already collapsed SYN_SENT before SYN|PUSH reaches here. */
	if ((hdr->flags & MUX_FLAG_PUSH) && hdr->length > 0 &&
	    (s->state == STREAM_ESTABLISHED ||
	     s->state == STREAM_SYN_RECEIVED)) {
		/* Bound the fast-open payload by the credit this side has granted the
		 * peer, so bytes_received can never overtake grant_sent: nothing
		 * downstream enforces it, as mux_stream_recv_copy only guards recv_window,
		 * which floors at four frames (65536). Without this, a payload above
		 * the grant is copied in, and stream_grantable_bytes then evaluates
		 * (grant_sent - bytes_received) in wrapping uint_least32_t arithmetic
		 * (~4.29e9), so mux_stream_grant_inc returns 0 forever and the stream's
		 * credit loop never reopens.
		 *
		 * grant_sent is the exact bound on the SYN|ACK path (spec §4.3.1's
		 * implicit 16384 plus our own SYN's Extra), which is the path this
		 * check now guards. On the SYN path §4.3.1's flat 16384 cap is enforced
		 * upstream in dispatch_no_stream -- before on_accept attaches the stream
		 * and raises grant_sent past 16384 -- so every fast-open reaching here
		 * on that path is already within the flat cap and this remains only a
		 * redundant backstop there. */
		if (hdr->length > s->grant_sent) {
			MUX_LOG_F(
				WARNING, ss,
				"stream %" PRIuLEAST16
				": fast-open payload exceeds granted credit:"
				" length=%" PRIuLEAST16 " grant=%" PRIuLEAST32,
				s->id, hdr->length, s->grant_sent);
			mux_stream_abort(s, MUX_STATUS_FLOW_CONTROL_ERROR);
			/* Same drain-cascade hazard as below: mux_stream_abort can free the
			 * last active stream of a draining session, whose shutdown
			 * resets this recvbuf -- do not consume a ring it already
			 * reset. */
			if (session_streams_freed(ss)) {
				return;
			}
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* A fast-open payload is PUSH-frame payload like any other; count
		 * it into byt_push_recv, matching the ordinary PUSH path in
		 * dispatch_by_stream (mux.h documents no SYN exclusion). */
		COUNTER_ADD(
			ss->cnt.traffic.byt_push_recv,
			(uint_least64_t)hdr->length);
		mux_stream_recv_copy(
			s,
			bytebuf_read_ptr(ss->wire.recvbuf) +
				MUX_FRAME_HEADER_SIZE,
			hdr->length);
		/* Same drain-cascade hazard as dispatch_by_stream()'s PUSH branch:
		 * a fast-open payload can mux_stream_abort the last active stream of a
		 * draining session, whose shutdown frees the streams and resets this
		 * recvbuf -- do not consume a ring the cascade already reset. */
		if (session_streams_freed(ss)) {
			return;
		}
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		if (ss->auto_stream_window || ss->auto_session_window) {
			mux_estimator_add(ss, hdr->length);
			mux_session_flush_oob(ss);
		}
		return;
	}
	bytebuf_consume(ss->wire.recvbuf, frame_size);
}

/* Report stream establishment latency once, on the first SYN|ACK. */
static void stream_report_established(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	if (s->syn_sent_ns <= 0) {
		return;
	}
	const int_fast64_t latency = clock_monotonic_ns() - s->syn_sent_ns;
	s->syn_sent_ns = 0;
	session_emit(
		ss, MUX_EVENT_STREAM_ESTABLISHED,
		(union mux_event_data){ .stream_established.ns = latency });
	if (LOGLEVEL(DEBUG)) {
		char stream_tag_[256];
		char latency_str[32];
		(void)mux_stream_format_tag(
			stream_tag_, sizeof(stream_tag_), s);
		(void)format_duration(
			latency_str, sizeof(latency_str),
			make_duration_nanos(latency));
		LOG_F(DEBUG, "%s stream connected, latency=%s", stream_tag_,
		      latency_str);
	}
}

static void dispatch_by_stream(
	struct mux_session *ss, struct mux_stream *restrict s,
	const struct mux_header *restrict hdr)
{
	const uint_fast16_t stream_id = hdr->stream_id;
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr->length;

	/* CLOSED streams linger briefly so late frames can be handled without a
	 * second lookup structure. */
	if (UNLIKELY(s->state == STREAM_CLOSED)) {
		/* RST on closed stream: SHOULD be ignored (spec §4.2.1 table). */
		if (hdr->flags & MUX_FLAG_RST) {
			MUX_LOG_F(
				VERBOSE, ss,
				"RST for closed stream %" PRIuFAST16
				"; ignoring",
				stream_id);
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* Ignorable terminal frames (zero-length ACK / ACK|FIN): ignore. */
		if (is_ignorable_unknown_terminal_frame(hdr)) {
			MUX_LOG_F(
				VERBOSE, ss,
				"ignoring terminal frame for closed stream "
				"%" PRIuFAST16 ": flags=0x%02" PRIxLEAST8,
				stream_id,
				(uint_least8_t)(hdr->flags & MUX_FLAG_MASK));
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* First late non-SYN frame: reply with one RST, then suppress.
		 * Latch rst_sent from the enqueue result (like the #41 mux_stream_abort
		 * fix) so an OOM'd RST stays retryable on the next late frame
		 * instead of being permanently suppressed. */
		if (!s->rst_sent) {
			MUX_LOG_F(
				DEBUG, ss,
				"late frame for closed stream %" PRIuFAST16
				", sending RST",
				stream_id);
			s->rst_sent = mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_PROTOCOL_ERROR);
		} else {
			MUX_LOG_F(
				VERBOSE, ss,
				"dropping late frame for closed stream "
				"%" PRIuFAST16 ": flags=0x%02" PRIxLEAST8 " "
				"length=%" PRIuLEAST16,
				stream_id,
				(uint_least8_t)(hdr->flags & MUX_FLAG_MASK),
				hdr->length);
		}
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	if (UNLIKELY(hdr->flags & MUX_FLAG_RST)) {
		/* Consume before mux_stream_recv_rst(): closing the last active stream
		 * during a drain cascades into mux_session_initiate_shutdown() ->
		 * mux_wire_discard_buffers(), which resets this same recvbuf. */
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		mux_stream_recv_rst(s, hdr->extra);
		return;
	}

	const uint_fast8_t flags = hdr->flags & MUX_FLAG_MASK;
	if (UNLIKELY(!validate_flags_by_stream(s, flags))) {
		MUX_LOG_F(
			DEBUG, ss,
			"invalid flags 0x%02" PRIxLEAST8
			" for stream %" PRIuFAST16 " state=%d, sending RST",
			(uint_least8_t)flags, stream_id, s->state);
		/* Latch from the enqueue result so an OOM'd RST stays retryable
		 * (the tombstone's late-frame handler above re-sends it), matching
		 * the #41 mux_stream_abort fix. */
		if (!s->rst_sent) {
			s->rst_sent = mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_PROTOCOL_ERROR);
		}
		/* Not an actual peer RST -- hdr->extra belongs to the invalid
		 * frame, not a status code -- so report the reason we are
		 * locally tearing the stream down instead, matching the RST
		 * just sent above. Consume first: see the comment on the RST
		 * branch above. */
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		mux_stream_recv_rst(s, MUX_STATUS_PROTOCOL_ERROR);
		return;
	}

	/* ACK-only: clear Nagle unacked bytes and grant receive-window credit.
	 * SYN|ACK carries its own window update in the SYN branch below. */
	if ((flags & MUX_FLAG_ACK) && !(flags & MUX_FLAG_SYN)) {
		s->unacked_bytes = 0;
		mux_stream_recv_window(s, hdr->extra);
		/* mux_stream_recv_window() may mux_stream_abort on a spec §6.6 excessive-
		 * credit overflow; on the last active stream of a draining session
		 * that cascades into mux_sched_free_streams() (frees s) +
		 * mux_wire_discard_buffers() (resets this recvbuf). The PUSH copy, FIN
		 * handling, and consume further down would then touch the freed
		 * stream or the reset ring, and the post-copy guard below runs too
		 * late to cover this earlier free -- so stop once the free shows. */
		if (session_streams_freed(ss)) {
			return;
		}
	}

	/* SYN|ACK completes establishment.  A retransmit on resume may arrive
	 * when already ESTABLISHED/FIN_WAIT; consume idempotently. */
	if (flags & MUX_FLAG_SYN) {
		if (s->state != STREAM_SYN_SENT) {
			/* Idempotent retransmit: SYN|ACK already processed. */
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		MUX_LOG_F(
			VERBOSE, ss,
			"stream %" PRIuFAST16
			" received SYN|ACK: credit_inc=%" PRIuLEAST16
			" queued=%" PRIuLEAST32 " unacked=%" PRIuLEAST32,
			stream_id, hdr->extra, s->queued_send_bytes,
			s->unacked_bytes);
		/* Clear unacked bytes before mux_stream_recv_window so its watcher
		 * update and wakeup see the unlocked Nagle state. */
		s->unacked_bytes = 0;
		mux_stream_recv_window(s, hdr->extra);
		/* Defense-in-depth, mirroring the ACK-only guard above: a SYN|ACK
		 * grant on the initial send window cannot overflow §6.6 today (a
		 * SYN_SENT stream has been granted no prior credit), but keep every
		 * free-capable mux_stream_recv_window() call uniformly guarded so the
		 * drain-cascade invariant cannot silently drift. */
		if (session_streams_freed(ss)) {
			return;
		}
		/* Dividing send_window by MUX_WINDOW_UNIT recovers the peer
		 * stream_window; assigned unconditionally to track shrinks. */
		session_set_peer_stream_window(
			ss, (uint_least32_t)(s->send_window / MUX_WINDOW_UNIT));
		if (ss->auto_session_window) {
			mux_session_update_session_window(
				ss,
				mux_estimator_tx_window_size(&ss->estimator));
		}
		stream_report_established(ss, s);
		mux_stream_start(s);
		process_syn_payload(ss, s, hdr, frame_size);
		return;
	}

	/* ACK (incl. ACK|FIN): Extra is a credit grant, not a status code;
	 * mux_stream_recv_window was already called in the ACK-only block.  send_window
	 * is cumulative granted credit, not the peer's window, so do not derive
	 * peer_stream_window from ACK increments.  mux_stream_recv_window already emits
	 * the "peer ACK restored send credit" DEBUG log on the same condition. */

	if (LIKELY((flags & MUX_FLAG_PUSH) && hdr->length > 0)) {
		COUNTER_ADD(
			ss->cnt.traffic.byt_push_recv,
			(uint_least64_t)hdr->length);
		mux_stream_recv_copy(
			s,
			bytebuf_read_ptr(ss->wire.recvbuf) +
				MUX_FRAME_HEADER_SIZE,
			hdr->length);
		/* mux_stream_recv_copy() may mux_stream_abort on a recv-window/flow-control
		 * overflow or bytebuf OOM; on the last active stream of a draining
		 * session that cascades into mux_session_initiate_shutdown() ->
		 * mux_sched_free_streams() (frees s) + mux_wire_discard_buffers() (resets
		 * this recvbuf). The consume below would then run on a reset ring and
		 * mux_stream_recv_fin(s) on freed memory, so stop once the free shows. */
		if (session_streams_freed(ss)) {
			return;
		}
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		if (ss->auto_stream_window || ss->auto_session_window) {
			mux_estimator_add(ss, hdr->length);
			mux_session_flush_oob(ss);
		}
		if (flags & MUX_FLAG_FIN) {
			mux_stream_recv_fin(s);
		}
		return;
	}

	/* Consume before mux_stream_recv_fin(): see the comment on the RST branch
	 * above. */
	bytebuf_consume(ss->wire.recvbuf, frame_size);
	if (flags & MUX_FLAG_FIN) {
		mux_stream_recv_fin(s);
	}
}

static void dispatch_no_stream(
	struct mux_session *ss, const struct mux_header *restrict hdr)
{
	const uint_fast16_t stream_id = hdr->stream_id;
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr->length;
	const uint_fast8_t flags = hdr->flags;
	/* dispatch_frame rejects any reserved flag bit (spec §3.3) and resets the
	 * session before dispatch reaches here, so no reserved bit can be set at
	 * this point -- the branches below need only consider MUX_FLAG_MASK bits. */
	ASSERT((flags & (uint_fast8_t)(~MUX_FLAG_MASK)) == 0);

	if (flags & MUX_FLAG_RST) {
		MUX_LOG_F(
			VERBOSE, ss, "RST for unknown stream %" PRIuFAST16,
			stream_id);
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	if (flags & MUX_FLAG_SYN) {
		const uint_fast8_t allowed = MUX_FLAG_SYN | MUX_FLAG_PUSH;
		if ((flags & ~allowed) != 0) {
			MUX_LOG_F(
				DEBUG, ss,
				"invalid SYN flags 0x%02" PRIxLEAST8
				" for unknown stream %" PRIuFAST16
				", closing connection",
				(uint_least8_t)(flags & MUX_FLAG_MASK),
				stream_id);
			mux_session_reset(ss);
			return;
		}

		if (!is_valid_peer_stream_id(ss, hdr->stream_id)) {
			MUX_LOG_F(
				DEBUG, ss,
				"invalid peer stream id parity: stream=%" PRIuLEAST16
				", closing connection",
				hdr->stream_id);
			mux_session_reset(ss);
			return;
		}

		/* Spec §4.3.1: the active opener's fast-open payload on the opening
		 * SYN MUST NOT exceed the flat 16384-octet implicit initial credit
		 * (its send credit toward us before we grant anything). Enforce that
		 * constant here, before on_accept attaches the stream and raises
		 * grant_sent past 16384 -- past which process_syn_payload's live-grant
		 * check can no longer see the violation. A non-conforming opener is a
		 * protocol error, closed like the flag/parity violations above. */
		if ((flags & MUX_FLAG_PUSH) &&
		    hdr->length > MUX_DEFAULT_SEND_WINDOW) {
			MUX_LOG_F(
				DEBUG, ss,
				"fast-open payload %" PRIuLEAST16
				" exceeds the %u-octet initial credit for stream "
				"%" PRIuFAST16 ", closing connection",
				hdr->length, (unsigned)MUX_DEFAULT_SEND_WINDOW,
				stream_id);
			mux_session_reset(ss);
			return;
		}

		if (ss->draining) {
			MUX_LOG_F(
				VERBOSE, ss,
				"reject stream %" PRIuFAST16
				": session draining",
				stream_id);
			mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}

		if (ss->conf.max_streams > 0 &&
		    table_size(ss->sched.streams) - ss->sched.num_tombstones >=
			    (size_t)ss->conf.max_streams) {
			MUX_LOG_F(
				VERBOSE, ss,
				"reject stream %" PRIuFAST16
				": max_streams (%d) reached",
				stream_id, ss->conf.max_streams);
			mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}

		struct mux_stream *const s =
			mux_stream_new(ss, stream_id, false);
		if (s == NULL) {
			MUX_LOG(ERROR, ss, "stream allocation failed");
			/* This frame is already counted into recv_seq,
			 * so silently dropping it here (unlike the draining/max_streams
			 * branches above) would leave the peer's opener waiting in
			 * SYN_SENT with no error signal until an application timeout;
			 * mux_session_send_ctrl is itself OOM-tolerant, so this is safe to
			 * attempt even here. */
			mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_INTERNAL_ERROR);
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		if (!mux_sched_add_stream(ss, s)) {
			MUX_LOG(ERROR, ss, "failed to add stream to table");
			mux_stream_free(s);
			mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_INTERNAL_ERROR);
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* The peer's SYN carries its own receive window in extra; grant the
		 * initial default plus that window, exactly as the SYN|ACK path's
		 * mux_stream_recv_window() does. No cap at our stream_window: the peer
		 * owns its receive buffer, and extra=UINT16_MAX yields ~1 GiB, still
		 * inside spec §6.6's INT32_MAX bound (16384 * 65535 + 16384). Capping
		 * here also dropped the default frame's credit relative to SYN|ACK. */
		const uint_fast32_t extra_bytes =
			(uint_fast32_t)hdr->extra * MUX_WINDOW_UNIT;
		s->send_window = MUX_DEFAULT_SEND_WINDOW + extra_bytes;
		/* Derive peer_stream_window from extra, unconditionally so a shrinking
		 * peer window is tracked; +1 for the initial default window's frame. */
		session_set_peer_stream_window(
			ss, (uint_least32_t)hdr->extra + 1u);
		if (ss->auto_session_window) {
			mux_session_update_session_window(
				ss,
				mux_estimator_tx_window_size(&ss->estimator));
		}
		if (LOGLEVEL(INFO)) {
			char stream_tag_[256];
			(void)mux_stream_format_tag(
				stream_tag_, sizeof(stream_tag_), s);
			LOGI_F("%s stream accepted (send_window=%" PRIuLEAST32
			       ")",
			       stream_tag_, s->send_window);
		}
		if (ss->callbacks.on_accept == NULL) {
			MUX_LOG_F(
				WARNING, ss,
				"reject stream %" PRIuFAST16
				": on_accept is NULL",
				stream_id);
			/* Latch from the enqueue result so an OOM'd reject RST
			 * stays retryable (the late-frame handler re-sends it),
			 * and mark aborted so the rejected stream is still counted
			 * failed even when rst_sent stays false on OOM. */
			s->rst_sent = mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			s->aborted = true;
			mux_stream_do_close(s);
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}

		if (!ss->callbacks.on_accept(ss->userdata, ss, s)) {
			MUX_LOG_F(
				DEBUG, ss,
				"stream %" PRIuFAST16
				" rejected by on_accept, sending RST",
				stream_id);
			/* Latch from the enqueue result so an OOM'd reject RST
			 * stays retryable (the late-frame handler re-sends it),
			 * and mark aborted so the rejected stream is still counted
			 * failed even when rst_sent stays false on OOM. */
			s->rst_sent = mux_session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			s->aborted = true;
			mux_stream_do_close(s);
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* SYN-ACK will be sent once local connection is established */
		process_syn_payload(ss, s, hdr, frame_size);
		return;
	}

	if (is_ignorable_unknown_terminal_frame(hdr)) {
		MUX_LOG_F(
			VERBOSE, ss,
			"ignoring terminal control frame for unknown stream "
			"%" PRIuFAST16 ": flags=0x%02" PRIxLEAST8,
			stream_id, (uint_least8_t)(flags & MUX_FLAG_MASK));
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	/* IDs are never reused, so a non-SYN frame for an unknown stream is
	 * likely late data past the tombstone period: RST it, keep the session. */
	MUX_LOG_F(
		DEBUG, ss,
		"non-SYN frame for unknown stream %" PRIuFAST16 ", sending RST",
		stream_id);
	mux_session_send_ctrl(
		ss, stream_id, MUX_FLAG_RST, MUX_STATUS_PROTOCOL_ERROR);
	bytebuf_consume(ss->wire.recvbuf, frame_size);
}

/* Handle a control-stream frame.  Returns false if the session was reset and
 * frame dispatch should stop. */
static bool dispatch_ctrl_frame(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	if (hdr->flags & MUX_FLAG_ACK) {
		MUX_LOG_F(
			DEBUG, ss,
			"session ACK received: acked=%" PRIuLEAST16
			" unacked=%zu stalled=%d",
			hdr->extra, ss->unacked.frames, ss->unacked.stalled);
		const struct unacked_ack_result r =
			mux_unacked_ack_recv(ss, hdr->extra);
		if (!r.ok) {
			/* Peer acked more frames than were sent. */
			mux_session_reset(ss);
			return false;
		}
		/* unacked stays free of the estimator and send pipeline:
		 * drive both here from the result. */
		if ((ss->auto_stream_window || ss->auto_session_window) &&
		    r.trimmed_bytes > 0) {
			mux_estimator_add_acked(ss, r.trimmed_bytes);
		}
		if (r.unstalled) {
			mux_notify_write(ss);
		}
	}
	if (hdr->flags == 0) {
		switch (hdr->extra) {
		case MUX_CTRL_PING:
			mux_session_recv_ping(ss, hdr, frame_size);
			break;
		case MUX_CTRL_PONG:
			mux_session_recv_pong(ss, hdr, frame_size);
			break;
		default:
			/* MUX_CTRL_PROBE and reserved: discard */
			bytebuf_consume(ss->wire.recvbuf, frame_size);
			break;
		}
	} else {
		bytebuf_consume(ss->wire.recvbuf, frame_size);
	}
	return true;
}

static void dispatch_frame(struct mux_session *ss)
{
	while (bytebuf_readable(ss->wire.recvbuf) >= MUX_FRAME_HEADER_SIZE) {
		const unsigned char *const p =
			bytebuf_read_ptr(ss->wire.recvbuf);

		struct mux_header hdr;
		mux_read_header(p, &hdr);
		if (LOGLEVEL(VERYVERBOSE)) {
			mux_session_log_frame_header(ss, "frame in", p, &hdr);
		}

		/* hdr.length is a 16-bit field (max MUX_MAX_PAYLOAD_SIZE), so a peer
		 * may send a frame larger than our configured max_payload; recvbuf
		 * grows on demand and is shrunk after (mux_session_on_recv). We never
		 * send oversized frames. */
		const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr.length;
		if (bytebuf_readable(ss->wire.recvbuf) < frame_size) {
			return;
		}

		/* Dispatch hello frames (version = 0). */
		if (hdr.version == 0) {
			mux_handshake_process_hello(ss, &hdr, frame_size);
			if (ss->state == SESSION_CLOSED) {
				return;
			}
			if (ss->state == SESSION_ESTABLISHED &&
			    ss->wire.tx_pending) {
				return;
			}
			continue;
		}

		/* Mux frames MUST NOT be sent before both sides reach
		 * SESSION_ESTABLISHED (spec §5.2); a non-hello frame while still
		 * SESSION_HANDSHAKE is a protocol violation. */
		if (ss->state != SESSION_ESTABLISHED) {
			MUX_LOG_F(
				ERROR, ss,
				"mux frame (version=%" PRIuLEAST8
				") received before session established (state=%d),"
				" closing connection",
				hdr.version, ss->state);
			mux_session_reset(ss);
			return;
		}

		if (hdr.version != MUX_PROTOCOL_VERSION) {
			MUX_LOG_F(
				ERROR, ss,
				"unsupported protocol version %" PRIuLEAST8,
				hdr.version);
			mux_session_reset(ss);
			return;
		}

		/* Reserved flag bits must not be set (spec §3.3). */
		if (hdr.flags & (uint_fast8_t)(~MUX_FLAG_MASK)) {
			MUX_LOG_F(
				ERROR, ss,
				"reserved flag bits set: 0x%02" PRIxLEAST8
				", closing connection",
				(uint_least8_t)(hdr.flags &
						(uint_fast8_t)(~MUX_FLAG_MASK)));
			mux_session_reset(ss);
			return;
		}

		if (hdr.stream_id == STREAMID_CTRL) {
			if (!dispatch_ctrl_frame(ss, &hdr, frame_size)) {
				return;
			}
			/* dispatch_ctrl_frame can reset the session and still return
			 * true (e.g. mux_session_recv_ping's oversized-PING path), so apply
			 * the same post-dispatch state check the stream path below does
			 * rather than continuing to dispatch on a CLOSED session. */
			if (ss->state != SESSION_ESTABLISHED) {
				return;
			}
			continue;
		}

		/* Count received non-stream-0 frames for session ACK. */
		ss->unacked.recv_seq =
			(uint_least32_t)serial_add32(ss->unacked.recv_seq, 1u);
		ss->unacked.unreported++;
		/* Force a session ACK when the pending increment hits a fraction
		 * of session_window (spec §5.7.3 MUST), skipping the coalesce
		 * timer. */
		const uint_fast32_t ack_thresh =
			(uint_fast32_t)CLAMP(ss->session_window / 4u, 2u, 8u);
		if (ss->unacked.unreported >= ack_thresh) {
			MUX_LOG_F(
				DEBUG, ss,
				"forced session ACK: unreported=%" PRIuLEAST32,
				ss->unacked.unreported);
			mux_session_emit_ack(ss);
		}
		if (ss->unacked.unreported > 0) {
			mux_sched_coalesce_arm(ss);
		}

		if (hdr.flags & MUX_FLAG_RST) {
			COUNTER_ADD(ss->cnt.num_rst_recv, 1);
		}

		struct mux_stream *const s =
			mux_sched_find_stream(ss, hdr.stream_id);
		if (s != NULL) {
			dispatch_by_stream(ss, s, &hdr);
		} else {
			dispatch_no_stream(ss, &hdr);
		}
		if (ss->state != SESSION_ESTABLISHED) {
			return;
		}
	}
}

void mux_session_dispatch_pending(struct mux_session *restrict ss)
{
	dispatch_frame(ss);
}

/* Contiguous recvbuf window offered to one transport read.  The floor is one
 * full frame; mux.readahead widens it so a single recv() drains several frames
 * per syscall.  With socket_offload the TLS library owns the socket reads (its
 * read-ahead is set via SSL_CTX_set_read_ahead), so the floor is enough here. */
static size_t recv_window(const struct mux_session *restrict ss)
{
	const size_t frame = (size_t)MUX_FRAME_HEADER_SIZE + ss->max_payload;
#if WITH_TLS
	if (ss->conf.tls_socket_offload) {
		return frame;
	}
#endif
	if (ss->readahead > frame) {
		return ss->readahead;
	}
	return frame;
}

/* Read and dispatch one TLS record.  Returns true when a record was
 * successfully received and dispatched; returns false when no data is
 * available (EAGAIN) or on error. */
static bool recv_one(struct mux_session *restrict ss)
{
	/* Offer the read-ahead window so one plaintext recv() can drain several
	 * buffered frames per syscall.  The ring still grows on demand for a larger
	 * peer frame. */
	if (!mux_bytebuf_reserve(&ss->wire.recvbuf, recv_window(ss), true)) {
		LOGOOM();
		mux_session_reset(ss);
		return false;
	}

	const size_t cap = bytebuf_write_space(ss->wire.recvbuf);
	size_t nread = cap;
	unsigned char *const buf = bytebuf_write_ptr(ss->wire.recvbuf);

	if (!mux_wire_recv(ss, buf, &nread)) {
		mux_session_suspend_or_reset(ss);
		return false;
	}
	if (nread == 0) {
		/* TLS close_notify during handshake: no send-side handler detects
		 * it, so drive teardown here.  A client resume attempt suspends
		 * rather than resets to preserve streams. */
		if (!ss->wire.rx_open && ss->state == SESSION_HANDSHAKE) {
			if (ss->handshake.has_session_id && !ss->accepted) {
				MUX_LOG(DEBUG, ss,
					"connection closed during resume handshake;"
					" re-suspending");
				mux_session_suspend(ss);
			} else {
				MUX_LOG(DEBUG, ss,
					"connection closed during protocol handshake");
				mux_session_reset(ss);
			}
		}
		return false;
	}

	bytebuf_produce(ss->wire.recvbuf, nread);
	ss->bytes_recv += (uint_least64_t)nread;
	COUNTER_ADD(ss->cnt.traffic.byt_mux_recv, (uint_least64_t)nread);
	if (ss->state == SESSION_ESTABLISHED) {
		ev_timer_again(ss->loop, &ss->w_timeout);
	}

	dispatch_frame(ss);
	return true;
}

void mux_session_on_recv(struct mux_session *restrict ss)
{
	if (recv_one(ss)) {
		while (ss->state == SESSION_ESTABLISHED &&
		       mux_wire_has_pending(ss)) {
			if (!recv_one(ss)) {
				break;
			}
		}
	}
	/* Reclaim capacity grown for oversized frames; floor is one read-ahead
	 * window plus one partial frame to avoid regrowth churn. */
	mux_bytebuf_shrink(
		&ss->wire.recvbuf,
		recv_window(ss) +
			((size_t)MUX_FRAME_HEADER_SIZE + ss->max_payload));
	/* Flush responses (PONG, ACKs, credit) immediately rather than waiting
	 * for EV_WRITE; prompt PONG avoids inflating the peer's RTT sample. */
	mux_session_flush_resp(ss);
}

/* Handle an inbound PING (spec §5.3.2): queue a PONG echoing the payload
 * byte-for-byte.  Silently discards the PING when rate-limited; closes the
 * connection on an oversized PING, which cannot be echoed. */
void mux_session_recv_ping(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	/* A PONG must echo the PING payload byte-for-byte into one of our frames,
	 * so a PING larger than our configured frame payload cannot be answered:
	 * close the connection rather than reply with a truncated PONG. */
	if (hdr->length > ss->max_payload) {
		MUX_LOG_F(
			ERROR, ss,
			"oversized PING (%" PRIuLEAST16
			" bytes) cannot be echoed; closing connection",
			hdr->length);
		mux_session_reset(ss);
		return;
	}

	const int_fast64_t now = clock_monotonic_ns();
	if (now - ss->ping_recv_last_ns < MUX_PONG_RATE_LIMIT_NS) {
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	/* Read the PING payload before discarding the frame; mux_session_send_oob
	 * copies it into oobbuf. */
	const unsigned char *const ping_payload =
		bytebuf_read_ptr(ss->wire.recvbuf) + MUX_FRAME_HEADER_SIZE;
	const bool queued = mux_session_send_oob(
		ss, MUX_CTRL_PONG, ping_payload, hdr->length);
	bytebuf_consume(ss->wire.recvbuf, frame_size);
	if (!queued) {
		/* OOM: PONG dropped.  OOB is never retransmitted, so the peer's
		 * in-flight BDP probe stalls until the transport is re-established
		 * (suspend clears OOB state); liveness is unaffected (no PONG dep). */
		return;
	}

	ss->ping_recv_last_ns = now;
	mux_session_flush_oob(ss);
}

/* Expand the receive window of one stream to new_window bytes.  Called via
 * table_iterate; only grows already-granted per-stream receive credit. */
static bool update_stream_window_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	const uint_fast32_t new_window = *(const uint_fast32_t *)data;
	struct mux_stream *const restrict s = element;
	if (new_window <= s->recv_window) {
		return true;
	}
	s->recv_window = new_window;
	mux_stream_check_ack(s);
	return true;
}

/* Ceiling of window_bytes in MUX_WINDOW_UNIT frames, floored at the configured
 * initial send window; shared by the stream- and session-window updates. */
static uint_least32_t window_frames_floor(const size_t window_bytes)
{
	const uint_least32_t initial_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	const size_t target_frames =
		(window_bytes + MUX_WINDOW_UNIT - 1) / MUX_WINDOW_UNIT;
	return (uint_least32_t)MAX(target_frames, (size_t)initial_frames);
}

static void session_update_stream_window(
	struct mux_session *restrict ss, const size_t window_bytes)
{
	const uint_least32_t frames = window_frames_floor(window_bytes);

	if (ss->stream_window == frames) {
		return;
	}
	const uint_least32_t old_stream = ss->stream_window;
	session_set_stream_window(ss, frames);
	if (frames > old_stream && ss->sched.streams != NULL) {
		uint_fast32_t w = (uint_fast32_t)frames * MUX_WINDOW_UNIT;
		table_iterate(ss->sched.streams, update_stream_window_cb, &w);
	}
	/* On shrink: each stream lazily syncs recv_window down in
	 * mux_stream_check_ack once outstanding peer credit is consumed. */
	MUX_LOG_F(
		INFO, ss, "estimator updated: window=%zu stream=%zu",
		window_bytes, (size_t)ss->stream_window * MUX_WINDOW_UNIT);
}

/* Handle an inbound PONG (spec §5.3.3): feed the echoed timestamp into the
 * estimator, apply its BDP to the live window floors, and reset the keepalive
 * timer so a successful PONG always defers the next probe. */
void mux_session_recv_pong(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	if (hdr->length < MUX_PING_PAYLOAD_SIZE) {
		bytebuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	const int_fast64_t sent_ns = (int_fast64_t)read_uint64(
		bytebuf_read_ptr(ss->wire.recvbuf) + MUX_FRAME_HEADER_SIZE);
	bytebuf_consume(ss->wire.recvbuf, frame_size);

	mux_estimator_calculate(ss, sent_ns);
	if (ss->auto_stream_window) {
		session_update_stream_window(
			ss, mux_estimator_rx_window_size(&ss->estimator));
	}
	if (ss->auto_session_window) {
		mux_session_update_session_window(
			ss, mux_estimator_tx_window_size(&ss->estimator));
	}

	/* Any PONG confirms the link is alive: reset the keepalive deadline
	 * regardless of which path sent the PING. */
	const double keepalive = mux_keepalive_interval(ss);
	ev_timer_set(&ss->w_keepalive, 0.0, keepalive);
	if (ev_is_active(&ss->w_keepalive)) {
		ev_timer_again(ss->loop, &ss->w_keepalive);
	}
}

void mux_session_update_session_window(
	struct mux_session *restrict ss, const size_t window_bytes)
{
	const uint_least32_t frames = window_frames_floor(window_bytes);
	const uint_least32_t new_window = MAX(ss->peer_stream_window, frames);
	if (ss->session_window == new_window) {
		return;
	}
	const bool grew = new_window > ss->session_window;
	ss->session_window = new_window;
	MUX_LOG_F(
		INFO, ss, "session window updated: session=%zu",
		(size_t)ss->session_window * MUX_WINDOW_UNIT);
	if (grew && ss->unacked.stalled &&
	    ss->unacked.bytes < (size_t)ss->session_window * MUX_WINDOW_UNIT) {
		MUX_LOG_F(
			DEBUG, ss,
			"send stall cleared by session window growth:"
			" unacked_bytes=%zu limit=%zu",
			ss->unacked.bytes,
			(size_t)ss->session_window * MUX_WINDOW_UNIT);
		ss->unacked.stalled = false;
		mux_notify_write(ss);
	}
}
