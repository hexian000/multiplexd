/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file unacked.c
 * @brief Internal mux session-level reliability implementation (spec §5.7).
 */

#include "mux/unacked.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"

#include "utils/debug.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Sum the payload bytes of @p count concatenated frame headers starting at
 * @p offset within @p f, advancing *offset past them.  Used by
 * unacked_ack_trim; only called on frames known to hold count headers. */
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

static bool unacked_ring_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	size_t count)
{
	frame->unacked_count = count;
	if (!mux_frame_ring_push(&ss->unacked.ring, frame)) {
		LOGOOM();
		return false;
	}
	ss->unacked.frames += count;
	COUNTER_ADD(ss->cnt.unacked_frames, count);
	ss->unacked.bytes += frame->len - count * MUX_FRAME_HEADER_SIZE;
	ss->unacked.send_seq += count;
	return true;
}

/* Add one ring entry worth @p count logical seqnums.  Hitting the session cap
 * only stalls new data dequeues; ACK/oob paths still run. */
static bool unacked_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	const size_t count)
{
	if (!unacked_ring_push(ss, frame, count)) {
		mux_frame_put(&ss->pool, frame);
		return false;
	}
	if (!ss->unacked.stalled &&
	    ss->unacked.bytes >= (size_t)ss->session_window * MUX_WINDOW_UNIT) {
		MUX_LOG_F(
			DEBUG, ss,
			"send stalled: unacked_bytes=%zu limit=%zu"
			" ready=%d sendbuf=%d oobbuf=%d"
			"; stalling data sends until peer acknowledges",
			ss->unacked.bytes,
			(size_t)ss->session_window * MUX_WINDOW_UNIT,
			ss->sched.sched_head != NULL,
			ss->wire.sendbuf.head != NULL,
			ss->wire.oobbuf.head != NULL);
		ss->unacked.stalled = true;
	}
	return true;
}

/* Keep flushed frames only when resume replay may need them: hello and
 * stream-0 controls are one-shot, retransmit copies only advance the cursor.
 * Walks the full header list so mixed PUSH/non-PUSH staging frames (from
 * wire_sendbuf_push) are counted and compacted correctly. */
void unacked_track_sent(
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
	if (ss->unacked.retransmit_copy == frame) {
		ss->unacked.retransmit_copy = NULL;
		ASSERT(ss->unacked.ring != NULL &&
		       ss->unacked.retransmit_off < ss->unacked.ring->count);
		ss->unacked.retransmit_off++;
		mux_frame_put(&ss->pool, frame);
		return;
	}

	/* Fast path: single-header frame needs no compaction or second parse. */
	if (MUX_FRAME_HEADER_SIZE + (size_t)hdr.length == frame->len) {
		if (hdr.stream_id == STREAMID_CTRL) {
			mux_frame_put(&ss->pool, frame);
			return;
		}
		unacked_push(ss, frame, 1);
		return;
	}

	/* Walk all concatenated headers, strip stream-0 controls, count the rest. */
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
	unacked_push(ss, frame, n);
}

struct unacked_ack_result
unacked_ack_trim(struct mux_session *restrict ss, const uint_fast32_t count)
{
	if (count > ss->unacked.frames) {
		MUX_LOG_F(
			ERROR, ss,
			"session ACK overflow: count=%" PRIuFAST32
			" unacked=%zu",
			count, ss->unacked.frames);
		return (struct unacked_ack_result){ .ok = false };
	}
	if (count == 0) {
		return (struct unacked_ack_result){ .ok = true };
	}
	const uint_fast32_t trim = count;
	ss->unacked.frames -= trim;
	COUNTER_SUB(ss->cnt.unacked_frames, trim);
	ss->unacked.last_ack_recv += trim;
	/* Walk physical frames from head; advance for fully-consumed entries,
	 * partial-consume the last frame in-place. */
	size_t remaining = trim;
	size_t popped = 0;
	size_t trimmed_bytes = 0;
	while (remaining > 0) {
		struct mux_frame *f = mux_frame_ring_peek(ss->unacked.ring, 0);
		if (f == NULL) {
			/* Ring empty but logical counter says otherwise;
			 * clamp to prevent out-of-bounds access. */
			ss->unacked.frames += (uint_fast32_t)remaining;
			COUNTER_ADD(
				ss->cnt.unacked_frames,
				(uint_fast32_t)remaining);
			ss->unacked.bytes = 0;
			ss->unacked.partial_offset = 0;
			break;
		}
		size_t offset = ss->unacked.partial_offset;
		if (f->unacked_count > remaining) {
			/* Partial trim: account bytes for `remaining` sub-frames
			 * starting at the saved byte offset. */
			const size_t bytes =
				frame_payload_bytes_from(f, &offset, remaining);
			ss->unacked.bytes -= bytes;
			trimmed_bytes += bytes;
			ss->unacked.partial_offset = (uint_least32_t)offset;
			f->unacked_count -= remaining;
			remaining = 0;
		} else {
			/* Full pop: account remaining bytes for this entry. */
			const size_t bytes = frame_payload_bytes_from(
				f, &offset, f->unacked_count);
			ss->unacked.bytes -= bytes;
			trimmed_bytes += bytes;
			ss->unacked.partial_offset = 0;
			remaining -= f->unacked_count;
			(void)mux_frame_ring_pop(ss->unacked.ring);
			mux_frame_put(&ss->pool, f);
			popped++;
		}
	}
	/* Each popped frame advances the ring head, so reduce the in-flight
	 * retransmit offset to match (floor 0), then clamp past the ring end. */
	if (ss->unacked.retransmit_off != SIZE_MAX) {
		if (ss->unacked.retransmit_off >= popped) {
			ss->unacked.retransmit_off -= popped;
		} else {
			ss->unacked.retransmit_off = 0;
		}
		if (ss->unacked.ring != NULL &&
		    ss->unacked.retransmit_off >= ss->unacked.ring->count) {
			ss->unacked.retransmit_off = SIZE_MAX;
		}
	}

	bool unstalled = false;
	if (ss->unacked.stalled &&
	    ss->unacked.bytes < (size_t)ss->session_window * MUX_WINDOW_UNIT) {
		MUX_LOG_F(
			DEBUG, ss,
			"send stall cleared by session ACK: acked=%" PRIuFAST32
			" unacked_bytes=%zu limit=%zu ready=%d",
			trim, ss->unacked.bytes,
			(size_t)ss->session_window * MUX_WINDOW_UNIT,
			ss->sched.sched_head != NULL);
		ss->unacked.stalled = false;
		unstalled = true;
	}
	return (struct unacked_ack_result){
		.ok = true,
		.trimmed_bytes = trimmed_bytes,
		.unstalled = unstalled,
	};
}

bool unacked_resume_ack_recv(
	struct mux_session *restrict ss, const uint_least32_t peer_ack)
{
	if (peer_ack < ss->unacked.last_ack_recv) {
		MUX_LOG_F(
			ERROR, ss,
			"session resume: peer_ack %" PRIuLEAST32
			" < last_ack_recv %" PRIuLEAST32,
			peer_ack, ss->unacked.last_ack_recv);
		return false;
	}
	const uint_least32_t trim = peer_ack - ss->unacked.last_ack_recv;
	/* No live send or estimator during resume, so the trim signals are
	 * deliberately ignored here. */
	const struct unacked_ack_result r =
		unacked_ack_trim(ss, (uint_fast32_t)trim);
	if (!r.ok) {
		return false;
	}
	/* Position the retransmit offset at the first remaining frame. */
	ss->unacked.retransmit_off =
		(ss->unacked.ring != NULL && ss->unacked.ring->count > 0) ?
			0 :
			SIZE_MAX;
	return true;
}

uint_fast32_t unacked_ack_delta(const struct mux_session *restrict ss)
{
	return ss->unacked.recv_seq - ss->unacked.ack_seq;
}

void unacked_ack_emitted(
	struct mux_session *restrict ss, const uint_fast32_t emit)
{
	ss->unacked.ack_seq += emit;
	ss->unacked.ack_ticks = 0;
	ss->unacked.ack_pending = false;
}

void unacked_free_all(struct mux_session *restrict ss)
{
	mux_frame_ring_free(&ss->unacked.ring, &ss->pool);
	ss->unacked.frames = 0;
	ss->unacked.bytes = 0;
	ss->unacked.partial_offset = 0;
	ss->unacked.retransmit_off = SIZE_MAX;
}
