/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file dispatch.c
 * @brief Internal mux frame dispatch implementation.
 */

#include "mux/dispatch.h"

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "os/clock.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/minmax.h"
#include "utils/slog.h"

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
validate_flags_by_stream(const struct stream *s, const uint_fast8_t flags)
{
	const uint_fast8_t non_rst_flags = flags & ~MUX_FLAG_RST;

	switch (s->state) {
	case STREAM_SYN_SENT:
		if ((non_rst_flags & (MUX_FLAG_SYN | MUX_FLAG_ACK)) !=
		    (MUX_FLAG_SYN | MUX_FLAG_ACK)) {
			return false;
		}
		return (non_rst_flags &
			~(MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_PUSH)) == 0;
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
		return (non_rst_flags & ~(MUX_FLAG_ACK | MUX_FLAG_FIN)) == 0;
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
	return (flags & ~(MUX_FLAG_ACK | MUX_FLAG_FIN)) == 0;
}

static void process_syn_payload(
	struct mux_session *restrict ss, struct stream *restrict s,
	const struct mux_header *restrict hdr, const size_t frame_size)
{
	/* stream_start() has already collapsed SYN_SENT before SYN|PUSH reaches here. */
	if ((hdr->flags & MUX_FLAG_PUSH) && hdr->length > 0 &&
	    (s->state == STREAM_ESTABLISHED ||
	     s->state == STREAM_SYN_RECEIVED)) {
		estimator_add(ss, hdr->length);
		stream_recv_copy(
			s,
			ringbuf_read_ptr(ss->wire.recvbuf) +
				MUX_FRAME_HEADER_SIZE,
			hdr->length);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}
	ringbuf_consume(ss->wire.recvbuf, frame_size);
}

/* Process frame for a known stream (found in stream table) */
static void dispatch_by_stream(
	struct mux_session *ss, struct stream *restrict s,
	const struct mux_header *restrict hdr)
{
	const uint_fast16_t stream_id = hdr->stream_id;
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr->length;

	/* CLOSED streams linger briefly so late frames can be handled without a
	 * second lookup structure. */
	if (s->state == STREAM_CLOSED) {
		/* RST on closed stream: SHOULD be ignored (spec §4.8 table). */
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

	if (hdr->flags & MUX_FLAG_RST) {
		stream_recv_rst(s);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	const uint_fast8_t flags = hdr->flags & MUX_FLAG_MASK;
	if (!validate_flags_by_stream(s, flags)) {
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

	/* SYN|ACK: completes stream establishment (guaranteed by validate_flags_by_stream).
	 * On session resume, a retransmitted SYN|ACK may arrive when the stream is already
	 * ESTABLISHED or FIN_WAIT; consume idempotently without re-applying. */
	if (flags & MUX_FLAG_SYN) {
		if (s->state != STREAM_SYN_SENT) {
			/* Idempotent retransmit: SYN|ACK already processed. */
			ringbuf_consume(ss->wire.recvbuf, frame_size);
			return;
		}
		MUX_LOG_F(
			VERBOSE, ss,
			"stream %" PRIuFAST16
			" received SYN|ACK: credit_inc=%" PRIuFAST32
			" queued=%" PRIuLEAST32 " unacked=%" PRIuLEAST32,
			stream_id, hdr->extra, s->queued_send_bytes,
			s->unacked_bytes);
		/* Nagle: clear unacked bytes before stream_recv_window so that
		 * the watcher update and scheduler wakeup inside see the
		 * unlocked state and re-enable EV_READ / dequeue correctly. */
		s->unacked_bytes = 0;
		stream_recv_window(s, hdr->extra);
		/* send_window = MUX_DEFAULT_SEND_WINDOW + extra * MUX_WINDOW_UNIT;
		 * dividing back gives the exact peer stream_window.  Assigned
		 * unconditionally so a shrinking peer window is tracked. */
		ss->peer_stream_window =
			(uint_least32_t)(s->send_window / MUX_WINDOW_UNIT);
		if (s->syn_sent_ns > 0) {
			const intmax_t latency =
				clock_monotonic_ns() - s->syn_sent_ns;
			s->syn_sent_ns = 0;
			if (ss->callbacks.on_event != NULL) {
				ss->callbacks.on_event(
					ss->userdata, ss,
					MUX_EVENT_STREAM_ESTABLISHED,
					(union mux_event_data){
						.stream_established.ns =
							latency,
					});
			}
			if (LOGLEVEL(DEBUG)) {
				char stream_tag_[256];
				char latency_str[32];
				(void)stream_format_tag(
					stream_tag_, sizeof(stream_tag_), s);
				(void)format_duration(
					latency_str, sizeof(latency_str),
					make_duration_nanos(latency));
				LOG_F(DEBUG, "%s stream connected, latency=%s",
				      stream_tag_, latency_str);
			}
		}
		stream_start(s);
		process_syn_payload(ss, s, hdr, frame_size);
		return;
	}

	/* ACK: grant credit whenever RST is clear and ACK is set.
	 * This includes ACK|FIN: Extra carries a credit grant, not a status code. */
	if (flags & MUX_FLAG_ACK) {
		const uint_fast32_t credit_before = stream_credit_avail(s);
		/* Nagle: clear unacked bytes before stream_recv_window so that
		 * the watcher update and scheduler wakeup inside see the
		 * unlocked state and re-enable EV_READ / dequeue correctly. */
		s->unacked_bytes = 0;
		stream_recv_window(s, hdr->extra);
		if (credit_before == 0 && hdr->extra > 0) {
			MUX_LOG_F(
				DEBUG, ss,
				"stream %" PRIuFAST16
				" peer ACK restored send credit: inc=%" PRIuFAST32
				" queued=%" PRIuLEAST32,
				stream_id, hdr->extra, s->queued_send_bytes);
		}
		/* send_window is cumulative granted credit, not the peer's window
		 * setting; do not derive peer_stream_window from ACK increments. */
	}

	if ((flags & MUX_FLAG_PUSH) && hdr->length > 0) {
		estimator_add(ss, hdr->length);
		stream_recv_copy(
			s,
			ringbuf_read_ptr(ss->wire.recvbuf) +
				MUX_FRAME_HEADER_SIZE,
			hdr->length);
		ringbuf_consume(ss->wire.recvbuf, frame_size);

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

/* Process frame for an unknown stream (not found in stream table) */
static void dispatch_no_stream(
	struct mux_session *ss, const struct mux_header *restrict hdr)
{
	const uint_fast16_t stream_id = hdr->stream_id;
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr->length;
	const uint_fast8_t flags = hdr->flags;
	const uint_fast8_t unknown_flags =
		flags & (uint_fast8_t)(~MUX_FLAG_MASK);

	/* RST for unknown stream - ignore */
	if (flags & MUX_FLAG_RST) {
		MUX_LOG_F(
			VERBOSE, ss, "RST for unknown stream %" PRIuFAST16,
			stream_id);
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}

	/* SYN - new incoming stream */
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

		struct stream *s = stream_new(ss, stream_id, false);
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
		/* Cap the initial send window at our own receive-buffer size
		 * (stream_window).  A malicious peer could advertise extra = UINT16_MAX
		 * and force the send_queue to grow without bound; capping at
		 * stream_window limits per-stream send_queue memory to the same budget
		 * as the receive buffer.  Use stream_window, not wmem: the peer's grant
		 * reflects its stream_window, so wmem would silently discard legitimate
		 * credits and starve the peer's outbound direction.
		 * When both peers run the same code, extra = stream_window - 1 and the
		 * MIN has no effect: send_window equals the peer's recv_window immediately
		 * after the handshake. */
		const uint_fast32_t extra_bytes =
			(uint_fast32_t)hdr->extra * MUX_WINDOW_UNIT;
		const uint_fast32_t max_window =
			(uint_fast32_t)ss->stream_window * MUX_MAX_PAYLOAD_SIZE;
		s->send_window =
			MIN(MUX_DEFAULT_SEND_WINDOW + extra_bytes, max_window);
		/* Use extra directly: send_window may be capped by our own
		 * stream_window, which would underestimate the peer's window.
		 * Assigned unconditionally so a shrinking peer window is tracked.
		 * The initial default send window contributes exactly one frame. */
		ss->peer_stream_window = (uint_least32_t)hdr->extra + 1u;
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

	/* Stream IDs are never reused within a session.  A valid non-SYN frame
	 * for an unknown stream is most likely late data after the tombstone
	 * period expired; reset that stream without tearing down the whole
	 * session. */
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

void dispatch_frame(struct mux_session *ss)
{
	while (ringbuf_readable(ss->wire.recvbuf) >= MUX_FRAME_HEADER_SIZE) {
		const unsigned char *const p =
			ringbuf_read_ptr(ss->wire.recvbuf);

		struct mux_header hdr;
		mux_read_header(p, &hdr);
		session_log_frame_header(ss, "frame in", p, &hdr);

		if (hdr.length > MUX_MAX_PAYLOAD_SIZE) {
			MUX_LOG_F(
				ERROR, ss,
				"invalid payload length %" PRIuLEAST16,
				hdr.length);
			session_reset(ss);
			return;
		}

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
			const bool ack_clears_stall =
				ss->send_stalled &&
				hdr.extra <= ss->unacked_frames &&
				ss->unacked_frames - hdr.extra <
					(size_t)ss->session_window;
			if ((hdr.flags & MUX_FLAG_ACK) && !ack_clears_stall) {
				MUX_LOG_F(
					DEBUG, ss,
					"session ACK received: acked=%" PRIuFAST32
					" unacked=%zu stalled=%d",
					hdr.extra, ss->unacked_frames,
					ss->send_stalled);
			}
			if ((hdr.flags & MUX_FLAG_ACK) &&
			    !session_ack_trim(ss, hdr.extra)) {
				/* Peer acked more frames than were sent. */
				session_reset(ss);
				return;
			}
			if (hdr.flags == 0) {
				switch (hdr.extra) {
				case MUX_CTRL_PING:
					session_recv_ping(ss, &hdr, frame_size);
					break;
				case MUX_CTRL_PONG:
					session_recv_pong(ss, &hdr, frame_size);
					break;
				default:
					/* PROBE (0x0000) and reserved: discard */
					ringbuf_consume(
						ss->wire.recvbuf, frame_size);
					break;
				}
			} else {
				ringbuf_consume(ss->wire.recvbuf, frame_size);
			}
			continue;
		}

		/* Count received non-stream-0 frames for session ACK. */
		ss->recv_seq++;
		/* Force-send session ACK immediately when the unacknowledged
		 * delta hits the threshold (spec §5.7.3 MUST), without
		 * waiting for the coalesce timer.  Use clamp(session_window/4,
		 * 2, 8) so the threshold stays small regardless of window size,
		 * avoiding the half-window starvation of the old formula. */
		const uint_fast32_t ack_thresh =
			(uint_fast32_t)CLAMP(ss->session_window / 4u, 2u, 8u);
		if (ss->recv_seq - ss->ack_seq >= ack_thresh) {
			MUX_LOG_F(
				DEBUG, ss,
				"forced session ACK: delta=%" PRIuFAST32,
				ss->recv_seq - ss->ack_seq);
			session_emit_ack(ss);
		}
		if (ss->recv_seq != ss->ack_seq) {
			sched_coalesce_arm(ss);
		}

		if (hdr.flags & MUX_FLAG_RST) {
			COUNTER_ADD(ss->cnt.num_rst_recv, 1);
		}

		struct stream *s = sched_find_stream(ss, hdr.stream_id);
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
