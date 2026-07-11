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

#include "binary/serial.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static bool unacked_ring_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	size_t count)
{
	frame->unacked_count = count;
	if (!mux_frame_ring_push(&ss->unacked.ring, frame)) {
		/* unacked_push (the sole caller) logs this OOM itself, with
		 * more context than a bare LOGOOM() would add here. */
		return false;
	}
	ss->unacked.frames += count;
	COUNTER_ADD(ss->cnt.unacked_frames, count);
	ss->unacked.bytes += frame->len - count * MUX_FRAME_HEADER_SIZE;
	ss->unacked.send_seq = (uint_least32_t)serial_add32(
		ss->unacked.send_seq, (uint_fast32_t)count);
	return true;
}

/* Add one ring entry worth @p count logical seqnums.  Hitting the session cap
 * only stalls new data dequeues; ACK/oob paths still run. The frame is
 * already flushed to the peer by this point, so an OOM here is an
 * unrecoverable send_seq/peer desync, not a transient failure to retry. */
static void unacked_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	const size_t count)
{
	if (!unacked_ring_push(ss, frame, count)) {
		mux_frame_put(&ss->pool, frame);
		MUX_LOG(ERROR, ss,
			"unacked ring OOM after flush: send_seq desynced"
			" from peer, resetting session");
		session_reset(ss);
		return;
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
}

/* Keep flushed frames only when resume replay may need them; hello and
 * stream-0 controls are one-shot; retransmit copies only advance the cursor;
 * walks all header entries to handle mixed PUSH/non-PUSH staging frames. */
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
		/* spec §5.8.4: the transmit count is incremented for each
		 * retransmitted frame upon transmission too, not just the
		 * original send. */
		const struct mux_frame *const orig = mux_frame_ring_peek(
			ss->unacked.ring, ss->unacked.retransmit_off);
		ss->unacked.send_seq = (uint_least32_t)serial_add32(
			ss->unacked.send_seq,
			(uint_fast32_t)orig->unacked_count);
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

/* Logical frame count actually retransmitted so far this replay pass (ring
 * positions [0, retransmit_off)). Used by unacked_ack_recv to bound a
 * peer-supplied ACK received mid-replay so it can never trim an entry that has
 * not actually been retransmitted yet on this connection -- a coordinating
 * send-side safeguard is what keeps a conformant peer from ever reaching this
 * bound in the first place. Not applicable to unacked_resume_ack_recv's own
 * trim call below: that one reconciles the peer's resume_seq against deliveries
 * on the *old* connection, and session_suspend() pre-arms retransmit_off=0 in
 * anticipation of the upcoming replay before that call ever runs. */
static size_t
unacked_retransmitted_frames(const struct mux_session *restrict ss)
{
	if (ss->unacked.ring == NULL) {
		return 0;
	}
	size_t total = 0;
	for (size_t i = 0; i < ss->unacked.retransmit_off; i++) {
		total +=
			mux_frame_ring_peek(ss->unacked.ring, i)->unacked_count;
	}
	return total;
}

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
	ss->unacked.last_ack_recv =
		(uint_least32_t)serial_add32(ss->unacked.last_ack_recv, trim);
	/* Walk physical frames from head; advance for fully-consumed entries,
	 * partial-consume the last frame in-place. */
	size_t remaining = trim;
	size_t popped = 0;
	size_t trimmed_bytes = 0;
	while (remaining > 0) {
		struct mux_frame *const f =
			mux_frame_ring_peek(ss->unacked.ring, 0);
		if (f == NULL) {
			/* Ring empty but logical counter says otherwise: an
			 * internal accounting bug or corruption. Log it, then
			 * clamp to prevent out-of-bounds access. */
			MUX_LOG_F(
				ERROR, ss,
				"unacked ring/counter mismatch: ring empty with"
				" %zu frame(s) still unaccounted for",
				remaining);
			ss->unacked.frames += remaining;
			COUNTER_ADD(ss->cnt.unacked_frames, remaining);
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

struct unacked_ack_result
unacked_ack_recv(struct mux_session *restrict ss, const uint_fast32_t count)
{
	if (ss->unacked.retransmit_off != SIZE_MAX) {
		const size_t retransmitted = unacked_retransmitted_frames(ss);
		if (count > retransmitted) {
			MUX_LOG_F(
				ERROR, ss,
				"session ACK overflow during replay: count=%" PRIuFAST32
				" retransmitted=%zu",
				count, retransmitted);
			return (struct unacked_ack_result){ .ok = false };
		}
	}
	return unacked_ack_trim(ss, count);
}

bool unacked_resume_ack_recv(
	struct mux_session *restrict ss, const uint_least32_t peer_ack)
{
	if (serial_lt32(peer_ack, ss->unacked.last_ack_recv)) {
		MUX_LOG_F(
			ERROR, ss,
			"session resume: peer_ack %" PRIuLEAST32
			" < last_ack_recv %" PRIuLEAST32,
			peer_ack, ss->unacked.last_ack_recv);
		return false;
	}
	/* RFC 1982 defines no subtraction, so trim outstanding frames one at a
	 * time until the confirmed count reaches peer_ack: the loop counts real
	 * ring frames, never bare serial space.  No live send or estimator
	 * during resume, so the trim signals are deliberately ignored. */
	while (ss->unacked.last_ack_recv != peer_ack) {
		if (ss->unacked.frames == 0) {
			MUX_LOG_F(
				ERROR, ss,
				"session resume: peer_ack %" PRIuLEAST32
				" exceeds outstanding frames at %" PRIuLEAST32,
				peer_ack, ss->unacked.last_ack_recv);
			return false;
		}
		const size_t before = ss->unacked.frames;
		(void)unacked_ack_trim(ss, 1);
		if (ss->unacked.frames >= before) {
			/* Ring/counter mismatch clamped inside unacked_ack_trim;
			 * no progress is possible. */
			return false;
		}
	}
	/* Position the retransmit offset at the first remaining frame. */
	ss->unacked.retransmit_off =
		(ss->unacked.ring != NULL && ss->unacked.ring->count > 0) ?
			0 :
			SIZE_MAX;
	return true;
}

void unacked_ack_emitted(
	struct mux_session *restrict ss, const uint_fast32_t emit)
{
	ASSERT(emit <= ss->unacked.unreported);
	ss->unacked.unreported -= (uint_least32_t)emit;
	ss->unacked.ack_ticks = 0;
}

void unacked_free_all(struct mux_session *restrict ss)
{
	mux_frame_ring_free(&ss->unacked.ring, &ss->pool);
	/* Keep the server-wide gauge in lockstep with frames (unacked.h): every
	 * other frames mutation pairs with a COUNTER_ADD/SUB, and this teardown
	 * can run with frames > 0 (rejected resume, session cleanup, graceful
	 * close dropping in-flight data). */
	COUNTER_SUB(ss->cnt.unacked_frames, ss->unacked.frames);
	ss->unacked.frames = 0;
	ss->unacked.bytes = 0;
	ss->unacked.partial_offset = 0;
	ss->unacked.retransmit_off = SIZE_MAX;
}
