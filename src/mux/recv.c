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
 * -> send (send.c + wire.c).  Cross-layer seam: session_flush_resp lets a
 * receive batch synchronously drive schedule+send (prompt PONG/ACK) rather than
 * waiting for the next EV_WRITE.
 */

#include "mux/recv.h"

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"
#include "util.h"

#include "algo/hashtable.h"
#include "os/clock.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/likely.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static inline bool
is_valid_peer_stream_id(struct mux_session *ss, const uint_fast16_t stream_id)
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
	struct mux_session *restrict ss, struct mux_stream *restrict s,
	const struct mux_header *restrict hdr, const size_t frame_size)
{
	/* stream_start() has already collapsed SYN_SENT before SYN|PUSH reaches here. */
	if ((hdr->flags & MUX_FLAG_PUSH) && hdr->length > 0 &&
	    (s->state == STREAM_ESTABLISHED ||
	     s->state == STREAM_SYN_RECEIVED)) {
		stream_recv_copy(
			s,
			ringbuf_read_ptr(ss->wire.recvbuf) +
				MUX_FRAME_HEADER_SIZE,
			hdr->length);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		if (ss->auto_stream_window || ss->auto_session_window) {
			estimator_add(ss, hdr->length);
			session_flush_oob(ss);
		}
		return;
	}
	ringbuf_consume(ss->wire.recvbuf, frame_size);
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
	if (ss->callbacks.on_event != NULL) {
		ss->callbacks.on_event(
			ss->userdata, ss, MUX_EVENT_STREAM_ESTABLISHED,
			(union mux_event_data){
				.stream_established.ns = latency,
			});
	}
	if (LOGLEVEL(DEBUG)) {
		char stream_tag_[256];
		char latency_str[32];
		(void)stream_format_tag(stream_tag_, sizeof(stream_tag_), s);
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
			ringbuf_consume(ss->wire.recvbuf, frame_size);
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
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* First late non-SYN frame: reply with one RST, then suppress. */
		if (!s->rst_sent) {
			s->rst_sent = true;
			MUX_LOG_F(
				DEBUG, ss,
				"late frame for closed stream %" PRIuFAST16
				", sending RST",
				stream_id);
			session_send_ctrl(
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
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	if (UNLIKELY(hdr->flags & MUX_FLAG_RST)) {
		stream_recv_rst(s);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	const uint_fast8_t flags = hdr->flags & MUX_FLAG_MASK;
	if (UNLIKELY(!validate_flags_by_stream(s, flags))) {
		MUX_LOG_F(
			DEBUG, ss,
			"invalid flags 0x%02x for stream %" PRIuFAST16
			" state=%d, sending RST",
			flags, stream_id, s->state);
		if (!s->rst_sent) {
			s->rst_sent = true;
			session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_PROTOCOL_ERROR);
		}
		stream_recv_rst(s);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	/* Snapshot credit before the window update, for ACK-only logging. */
	const uint_fast32_t credit_before =
		((flags & MUX_FLAG_ACK) && !(flags & MUX_FLAG_SYN)) ?
			stream_credit_avail(s) :
			0;

	/* ACK-only: clear Nagle unacked bytes and grant receive-window credit.
	 * SYN|ACK carries its own window update in the SYN branch below. */
	if ((flags & MUX_FLAG_ACK) && !(flags & MUX_FLAG_SYN)) {
		s->unacked_bytes = 0;
		stream_recv_window(s, hdr->extra);
	}

	/* SYN|ACK completes establishment.  A retransmit on resume may arrive
	 * when already ESTABLISHED/FIN_WAIT; consume idempotently. */
	if (flags & MUX_FLAG_SYN) {
		if (s->state != STREAM_SYN_SENT) {
			/* Idempotent retransmit: SYN|ACK already processed. */
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		MUX_LOG_F(
			VERBOSE, ss,
			"stream %" PRIuFAST16
			" received SYN|ACK: credit_inc=%" PRIuLEAST16
			" queued=%" PRIuLEAST32 " unacked=%" PRIuLEAST32,
			stream_id, hdr->extra, s->queued_send_bytes,
			s->unacked_bytes);
		/* Clear unacked bytes before stream_recv_window so its watcher
		 * update and wakeup see the unlocked Nagle state. */
		s->unacked_bytes = 0;
		stream_recv_window(s, hdr->extra);
		/* Dividing send_window by MUX_WINDOW_UNIT recovers the peer
		 * stream_window; assigned unconditionally to track shrinks. */
		ss->peer_stream_window =
			(uint_least32_t)(s->send_window / MUX_WINDOW_UNIT);
		if (ss->auto_session_window) {
			session_update_session_window(
				ss, estimator_tx_window_size(&ss->estimator));
		}
		stream_report_established(ss, s);
		stream_start(s);
		process_syn_payload(ss, s, hdr, frame_size);
		return;
	}

	/* ACK (incl. ACK|FIN): Extra is a credit grant, not a status code;
	 * stream_recv_window was already called in the ACK-only block. */
	if (flags & MUX_FLAG_ACK) {
		if (credit_before == 0 && hdr->extra > 0) {
			MUX_LOG_F(
				DEBUG, ss,
				"stream %" PRIuFAST16
				" peer ACK restored send credit: inc=%" PRIuLEAST16
				" queued=%" PRIuLEAST32,
				stream_id, hdr->extra, s->queued_send_bytes);
		}
		/* send_window is cumulative granted credit, not the peer's window;
		 * do not derive peer_stream_window from ACK increments. */
	}

	if (LIKELY((flags & MUX_FLAG_PUSH) && hdr->length > 0)) {
		COUNTER_ADD(
			ss->cnt.traffic.byt_push_recv,
			(uint_least64_t)hdr->length);
		stream_recv_copy(
			s,
			ringbuf_read_ptr(ss->wire.recvbuf) +
				MUX_FRAME_HEADER_SIZE,
			hdr->length);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		if (ss->auto_stream_window || ss->auto_session_window) {
			estimator_add(ss, hdr->length);
			session_flush_oob(ss);
		}
		if (flags & MUX_FLAG_FIN) {
			stream_recv_fin(s);
		}
		return;
	}

	if (flags & MUX_FLAG_FIN) {
		stream_recv_fin(s);
	}

	ringbuf_consume(ss->wire.recvbuf, frame_size);
}

static void dispatch_no_stream(
	struct mux_session *ss, const struct mux_header *restrict hdr)
{
	const uint_fast16_t stream_id = hdr->stream_id;
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr->length;
	const uint_fast8_t flags = hdr->flags;
	const uint_fast8_t unknown_flags =
		flags & (uint_fast8_t)(~MUX_FLAG_MASK);

	if (flags & MUX_FLAG_RST) {
		MUX_LOG_F(
			VERBOSE, ss, "RST for unknown stream %" PRIuFAST16,
			stream_id);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	if (flags & MUX_FLAG_SYN) {
		const uint_fast8_t allowed = MUX_FLAG_SYN | MUX_FLAG_PUSH;
		if (unknown_flags != 0 || (flags & ~allowed) != 0) {
			MUX_LOG_F(
				DEBUG, ss,
				"invalid SYN flags 0x%02x for unknown stream %" PRIuFAST16
				", closing connection",
				flags, stream_id);
			session_reset(ss);
			return;
		}

		if (!is_valid_peer_stream_id(ss, hdr->stream_id)) {
			MUX_LOG_F(
				DEBUG, ss,
				"invalid peer stream id parity: stream=%" PRIuLEAST16
				", closing connection",
				hdr->stream_id);
			session_reset(ss);
			return;
		}

		if (ss->draining) {
			MUX_LOG_F(
				VERBOSE, ss,
				"reject stream %" PRIuFAST16
				": session draining",
				stream_id);
			session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			ringbuf_consume(ss->wire.recvbuf, frame_size);
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
			session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}

		struct mux_stream *s = stream_new(ss, stream_id, false);
		if (s == NULL) {
			MUX_LOG(ERROR, ss, "stream allocation failed");
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		if (!sched_add_stream(ss, s)) {
			MUX_LOG(ERROR, ss, "failed to add stream to table");
			stream_free(s);
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* Cap the initial send window at our own stream_window so a peer
		 * advertising extra = UINT16_MAX cannot grow send_queue without
		 * bound.  Use stream_window (not wmem): the grant reflects the
		 * peer's stream_window, so the cap is a no-op between matched peers. */
		const uint_fast32_t extra_bytes =
			(uint_fast32_t)hdr->extra * MUX_WINDOW_UNIT;
		const uint_fast32_t max_window =
			(uint_fast32_t)ss->stream_window * MUX_WINDOW_UNIT;
		s->send_window =
			MIN(MUX_DEFAULT_SEND_WINDOW + extra_bytes, max_window);
		/* Derive peer_stream_window from extra (not the capped send_window),
		 * unconditionally so a shrinking peer window is tracked; +1 for the
		 * initial default send window's one frame. */
		ss->peer_stream_window = (uint_least32_t)hdr->extra + 1u;
		if (ss->auto_session_window) {
			session_update_session_window(
				ss, estimator_tx_window_size(&ss->estimator));
		}
		if (LOGLEVEL(INFO)) {
			char stream_tag_[256];
			(void)stream_format_tag(
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
			s->rst_sent = true;
			session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			stream_close(s);
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}

		if (!ss->callbacks.on_accept(ss->userdata, ss, s)) {
			MUX_LOG_F(
				DEBUG, ss,
				"stream %" PRIuFAST16
				" rejected by on_accept, sending RST",
				stream_id);
			s->rst_sent = true;
			session_send_ctrl(
				ss, stream_id, MUX_FLAG_RST,
				MUX_STATUS_REFUSED_STREAM);
			stream_close(s);
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		/* SYN-ACK will be sent once local connection is established */
		process_syn_payload(ss, s, hdr, frame_size);
		return;
	}

	if (unknown_flags == 0 && is_ignorable_unknown_terminal_frame(hdr)) {
		MUX_LOG_F(
			VERBOSE, ss,
			"ignoring terminal control frame for unknown stream "
			"%" PRIuFAST16 ": flags=0x%02x",
			stream_id, flags & MUX_FLAG_MASK);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	/* IDs are never reused, so a non-SYN frame for an unknown stream is
	 * likely late data past the tombstone period: RST it, keep the session. */
	if (unknown_flags == 0) {
		MUX_LOG_F(
			DEBUG, ss,
			"non-SYN frame for unknown stream %" PRIuFAST16
			", sending RST",
			stream_id);
		session_send_ctrl(
			ss, stream_id, MUX_FLAG_RST, MUX_STATUS_PROTOCOL_ERROR);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	MUX_LOG_F(
		DEBUG, ss,
		"unknown reserved flags 0x%02x for stream %" PRIuFAST16
		", closing connection",
		unknown_flags, stream_id);
	session_reset(ss);
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
			unacked_ack_trim(ss, hdr->extra);
		if (!r.ok) {
			/* Peer acked more frames than were sent. */
			session_reset(ss);
			return false;
		}
		/* unacked stays free of the estimator and send pipeline:
		 * drive both here from the result. */
		if ((ss->auto_stream_window || ss->auto_session_window) &&
		    r.trimmed_bytes > 0) {
			estimator_add_acked(ss, r.trimmed_bytes);
		}
		if (r.unstalled) {
			mux_notify_write(ss);
		}
	}
	if (hdr->flags == 0) {
		switch (hdr->extra) {
		case MUX_CTRL_PING:
			session_recv_ping(ss, hdr, frame_size);
			break;
		case MUX_CTRL_PONG:
			session_recv_pong(ss, hdr, frame_size);
			break;
		default:
			/* MUX_CTRL_PROBE and reserved: discard */
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			break;
		}
	} else {
		ringbuf_consume(ss->wire.recvbuf, frame_size);
	}
	return true;
}

static void dispatch_frame(struct mux_session *ss)
{
	while (ringbuf_readable(ss->wire.recvbuf) >= MUX_FRAME_HEADER_SIZE) {
		const unsigned char *const p =
			ringbuf_read_ptr(ss->wire.recvbuf);

		struct mux_header hdr;
		mux_read_header(p, &hdr);
		if (LOGLEVEL(VERYVERBOSE)) {
			session_log_frame_header(ss, "frame in", p, &hdr);
		}

		/* hdr.length is a 16-bit field (<= 65535), so a peer may send a
		 * payload larger than our own MUX_MAX_PAYLOAD_SIZE cap.  Accept it:
		 * the recvbuf grows on demand to assemble the frame contiguously and
		 * is shrunk back afterwards (session_on_recv).  We never send oversized. */
		const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr.length;
		if (ringbuf_readable(ss->wire.recvbuf) < frame_size) {
			return;
		}

		/* Dispatch hello frames (version = 0). */
		if (hdr.version == 0) {
			handshake_process_hello(ss, &hdr, frame_size);
			if (ss->state == SESSION_CLOSED) {
				return;
			}
			if (ss->state == SESSION_ESTABLISHED &&
			    ss->wire.tx_pending) {
				return;
			}
			continue;
		}

		if (hdr.version != MUX_PROTOCOL_VERSION) {
			MUX_LOG_F(
				ERROR, ss,
				"unsupported protocol version %" PRIuLEAST8,
				hdr.version);
			session_reset(ss);
			return;
		}

		/* Reserved flag bits must not be set (spec §3.3). */
		if (hdr.flags & (uint_fast8_t)(~MUX_FLAG_MASK)) {
			MUX_LOG_F(
				ERROR, ss,
				"reserved flag bits set: 0x%02x, closing connection",
				hdr.flags & (unsigned)(~MUX_FLAG_MASK));
			session_reset(ss);
			return;
		}

		if (hdr.stream_id == STREAMID_CTRL) {
			if (!dispatch_ctrl_frame(ss, &hdr, frame_size)) {
				return;
			}
			continue;
		}

		/* Count received non-stream-0 frames for session ACK. */
		ss->unacked.recv_seq++;
		/* Force a session ACK when the delta hits a fraction of
		 * session_window (spec §5.7.3 MUST), skipping the coalesce timer. */
		const uint_fast32_t ack_thresh =
			(uint_fast32_t)CLAMP(ss->session_window / 4u, 2u, 8u);
		if (ss->unacked.recv_seq - ss->unacked.ack_seq >= ack_thresh) {
			MUX_LOG_F(
				DEBUG, ss,
				"forced session ACK: delta=%" PRIuLEAST32,
				ss->unacked.recv_seq - ss->unacked.ack_seq);
			session_emit_ack(ss);
		}
		if (ss->unacked.recv_seq != ss->unacked.ack_seq) {
			sched_coalesce_arm(ss);
		}

		if (hdr.flags & MUX_FLAG_RST) {
			COUNTER_ADD(ss->cnt.num_rst_recv, 1);
		}

		struct mux_stream *s = sched_find_stream(ss, hdr.stream_id);
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

/* Read and dispatch one TLS record.  Returns true when a record was
 * successfully received and dispatched; returns false when no data is
 * available (EAGAIN) or on error. */
static bool recv_one(struct mux_session *restrict ss)
{
	/* Offer a MUX_RECV_READAHEAD read-ahead window so one plaintext recv()
	 * can drain several buffered frames per syscall.  The ring still grows on
	 * demand for a larger peer frame. */
	if (!ringbuf_reserve(&ss->wire.recvbuf, MUX_RECV_READAHEAD, true)) {
		LOGOOM();
		session_reset(ss);
		return false;
	}

	const size_t cap = ringbuf_write_space(ss->wire.recvbuf);
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
		/* TLS close_notify during handshake: no send-side handler detects
		 * it, so drive teardown here.  A client resume attempt suspends
		 * rather than resets to preserve streams. */
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

void session_on_recv(struct mux_session *restrict ss)
{
	if (recv_one(ss)) {
		while (ss->state == SESSION_ESTABLISHED &&
		       wire_has_pending(ss)) {
			if (!recv_one(ss)) {
				break;
			}
		}
	}
	/* Reclaim capacity the recvbuf grew to assemble an oversized inbound frame.
	 * The normal working set is one read-ahead window plus a leftover partial,
	 * so keep that floor to avoid regrowth churn on normal traffic; only genuine
	 * oversized growth is returned. */
	ringbuf_shrink(
		&ss->wire.recvbuf,
		MUX_RECV_READAHEAD +
			((size_t)MUX_FRAME_HEADER_SIZE + ss->max_payload));
	/* Respond to this batch now (PONG, ACKs, data unstalled by credit):
	 * socket_cb entered on EV_READ, so without this the egress would wait a
	 * loop turn.  Prompt PONG keeps the peer's RTT sample from absorbing our
	 * egress delay. */
	session_flush_resp(ss);
}

/* Handle an inbound PING (spec §5.3.2): queue a PONG echoing the payload
 * byte-for-byte.  Silently discards the PING when rate-limited; closes the
 * connection on an oversized PING, which cannot be echoed. */
void session_recv_ping(
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
		session_reset(ss);
		return;
	}

	const int_fast64_t now = clock_monotonic_ns();
	if (now - ss->ping_recv_last_ns < MUX_PONG_RATE_LIMIT_NS) {
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	/* Read the PING payload before discarding the frame; session_send_oob
	 * copies it into oobbuf. */
	const unsigned char *ping_payload =
		ringbuf_read_ptr(ss->wire.recvbuf) + MUX_FRAME_HEADER_SIZE;
	const bool queued =
		session_send_oob(ss, MUX_CTRL_PONG, ping_payload, hdr->length);
	ringbuf_consume(ss->wire.recvbuf, frame_size);
	if (!queued) {
		/* OOM: PONG dropped.  OOB is never retransmitted, so the peer's
		 * in-flight BDP probe stalls until the transport is re-established
		 * (suspend clears OOB state); liveness is unaffected (no PONG dep). */
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
	/* On shrink: each stream lazily syncs recv_window down in
	 * stream_check_ack once outstanding peer credit is consumed. */
	MUX_LOG_F(
		INFO, ss, "estimator updated: window=%zu stream=%zu",
		window_bytes, (size_t)ss->stream_window * MUX_WINDOW_UNIT);
}

/* Handle an inbound PONG (spec §5.3.3): feed the echoed timestamp into the
 * estimator, apply its BDP to the live window floors, and reset the keepalive
 * timer so a successful PONG always defers the next probe. */
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
			ss, estimator_rx_window_size(&ss->estimator));
	}
	if (ss->auto_session_window) {
		session_update_session_window(
			ss, estimator_tx_window_size(&ss->estimator));
	}

	/* Any PONG confirms the link is alive: reset the keepalive deadline
	 * regardless of which path sent the PING. */
	const double keepalive = keepalive_interval(ss);
	ev_timer_set(&ss->w_keepalive, 0.0, keepalive);
	if (ev_is_active(&ss->w_keepalive)) {
		ev_timer_again(ss->loop, &ss->w_keepalive);
	}
}
