/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file unacked.c
 * @brief Internal mux session-level reliability implementation (spec §5.7).
 */

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/unacked.h"

#include "binary/serial.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static bool ring_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	const size_t count)
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
	return true;
}

/* Add one ring entry worth @p count logical seqnums.  Hitting the session cap
 * only stalls new data dequeues; ACK/oob paths still run. The frame is
 * already flushed to the peer by this point, so an OOM here means the resume
 * log can no longer reconstruct what the peer received -- an unrecoverable
 * desync, not a transient failure to retry. */
static void unacked_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame,
	const size_t count)
{
	if (!ring_push(ss, frame, count)) {
		mux_frame_put(&ss->pool, frame);
		MUX_LOG(ERROR, ss,
			"unacked ring OOM after flush: resume log desynced"
			" from peer, resetting session");
		mux_session_reset(ss);
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
void mux_unacked_track_sent(
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

	/* Each retransmit copy corresponds to one original unacked entry; advance
	 * the replay cursor past it and free the copy (the original stays in the
	 * ring until the peer ACKs it). */
	if (ss->unacked.retransmit_copy == frame) {
		ss->unacked.retransmit_copy = NULL;
		ASSERT(ss->unacked.ring != NULL &&
		       ss->unacked.retransmit_off < ss->unacked.ring->count);
		/* This entry has now been retransmitted; fold its logical count
		 * (captured in send_queue_retransmit) into the running total before
		 * advancing the cursor past it. */
		ss->unacked.retransmitted_frames +=
			ss->unacked.retransmit_copy_count;
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
			/* This frame is already on the wire, so dropping it now
			 * without tracking its sub-frames would leave the peer
			 * counting them into recv_seq while our ring never does --
			 * a later session ACK would then overflow unacked.frames
			 * and be misdiagnosed. Treat it as unrecoverable, like
			 * unacked_push's post-flush OOM. */
			mux_frame_put(&ss->pool, frame);
			MUX_LOG(ERROR, ss,
				"invalid internal frame layout (truncated"
				" header) after flush: resume log desynced from"
				" peer, resetting session");
			mux_session_reset(ss);
			return;
		}
		mux_read_header(src, &hdr);
		const size_t entry_len = MUX_FRAME_HEADER_SIZE + hdr.length;
		if ((size_t)(end - src) < entry_len) {
			mux_frame_put(&ss->pool, frame);
			MUX_LOG(ERROR, ss,
				"invalid internal frame layout (truncated"
				" payload) after flush: resume log desynced from"
				" peer, resetting session");
			mux_session_reset(ss);
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

/* Sum the payload bytes of @p count concatenated frame headers starting at
 * @p offset within @p f, advancing *offset past them.  Used by
 * mux_unacked_ack_trim; only called on frames known to hold count headers. */
static size_t frame_payload_bytes_from(
	const struct mux_frame *restrict f, size_t *restrict offset,
	size_t count)
{
	const unsigned char *src = f->data + *offset;
	const unsigned char *const frame_end = f->data + f->len;
	size_t total = 0;
	/* Difference form, not `src + MUX_FRAME_HEADER_SIZE <= frame_end`: the
	 * latter forms a pointer up to 8 bytes past one-past-the-end on a
	 * malformed frame (pointer-overflow UB). */
	while (count > 0 &&
	       (size_t)(frame_end - src) >= MUX_FRAME_HEADER_SIZE) {
		struct mux_header hdr;
		mux_read_header(src, &hdr);
		total += hdr.length;
		src += MUX_FRAME_HEADER_SIZE + (size_t)hdr.length;
		count--;
	}
	/* The caller only passes frames known to hold @p count headers; a leftover
	 * count would under-count bytes and latch mux_unacked_ack_trim's stall gate. */
	ASSERT(count == 0);
	*offset = (size_t)(src - f->data);
	return total;
}

struct unacked_ack_result
mux_unacked_ack_trim(struct mux_session *restrict ss, const uint_fast32_t count)
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
	/* Logical frames trimmed from ring positions already retransmitted this
	 * replay pass ([0, off0)); subtracted from retransmitted_frames below to
	 * keep it in lockstep with retransmit_off (see unacked.h). */
	const size_t off0 = ss->unacked.retransmit_off == SIZE_MAX ?
				    0 :
				    ss->unacked.retransmit_off;
	size_t trimmed_retransmitted = 0;
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
			if (popped < off0) {
				trimmed_retransmitted += remaining;
			}
			f->unacked_count -= remaining;
			remaining = 0;
		} else {
			/* Full pop: account remaining bytes for this entry. */
			const size_t bytes = frame_payload_bytes_from(
				f, &offset, f->unacked_count);
			ss->unacked.bytes -= bytes;
			trimmed_bytes += bytes;
			ss->unacked.partial_offset = 0;
			if (popped < off0) {
				trimmed_retransmitted += f->unacked_count;
			}
			remaining -= f->unacked_count;
			(void)mux_frame_ring_pop(ss->unacked.ring);
			mux_frame_put(&ss->pool, f);
			popped++;
		}
	}
	/* Each popped frame advances the ring head, so reduce the in-flight
	 * retransmit offset to match (floor 0), then clamp past the ring end.
	 * retransmitted_frames tracks the offset: shrink it by the retransmitted
	 * prefix trims (trimmed_retransmitted <= retransmitted_frames, so no
	 * underflow); the floor/clamp paths zero it via unacked_set_replay_off. */
	if (ss->unacked.retransmit_off != SIZE_MAX) {
		if (ss->unacked.retransmit_off >= popped) {
			ss->unacked.retransmit_off -= popped;
			ss->unacked.retransmitted_frames -=
				trimmed_retransmitted;
		} else {
			unacked_set_replay_off(&ss->unacked, 0);
		}
		if (ss->unacked.ring != NULL &&
		    ss->unacked.retransmit_off >= ss->unacked.ring->count) {
			unacked_set_replay_off(&ss->unacked, SIZE_MAX);
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

#ifndef NDEBUG
/* Debug-only ground truth for unacked.retransmitted_frames: the O(n) rescan of
 * the retransmitted prefix (ring positions [0, retransmit_off)) that the running
 * counter replaced (issue #45). Kept so every debug/sanitizer run cross-checks
 * the incrementally-maintained counter against a direct sum; compiled out of
 * shipped builds along with the ASSERT that calls it. Only ever called with
 * retransmit_off != SIZE_MAX, where the offset is a valid ring index. */
static size_t retransmitted_frames_verify(const struct mux_session *restrict ss)
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
#endif /* NDEBUG */

/* mux_unacked_ack_recv bounds a peer-supplied ACK received mid-replay by
 * retransmitted_frames so it can never trim an entry that has not actually been
 * retransmitted yet on this connection -- a coordinating send-side safeguard is
 * what keeps a conformant peer from ever reaching this bound in the first place.
 * Not applicable to mux_unacked_resume_ack_recv's own trim call below: that one
 * reconciles the peer's resume_seq against deliveries on the *old* connection,
 * and mux_session_suspend() pre-arms retransmit_off=0 in anticipation of the
 * upcoming replay before that call ever runs. */
struct unacked_ack_result
mux_unacked_ack_recv(struct mux_session *restrict ss, const uint_fast32_t count)
{
	if (ss->unacked.retransmit_off != SIZE_MAX) {
		ASSERT(ss->unacked.retransmitted_frames ==
		       retransmitted_frames_verify(ss));
		const size_t retransmitted = ss->unacked.retransmitted_frames;
		if (count > retransmitted) {
			MUX_LOG_F(
				ERROR, ss,
				"session ACK overflow during replay: count=%" PRIuFAST32
				" retransmitted=%zu",
				count, retransmitted);
			return (struct unacked_ack_result){ .ok = false };
		}
	}
	return mux_unacked_ack_trim(ss, count);
}

bool mux_unacked_resume_ack_recv(
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
		(void)mux_unacked_ack_trim(ss, 1);
		if (ss->unacked.frames >= before) {
			/* Ring/counter mismatch clamped inside mux_unacked_ack_trim;
			 * no progress is possible. */
			return false;
		}
	}
	/* Position the retransmit offset at the first remaining frame. */
	unacked_set_replay_off(
		&ss->unacked,
		(ss->unacked.ring != NULL && ss->unacked.ring->count > 0) ?
			0 :
			SIZE_MAX);
	return true;
}

void mux_unacked_ack_emitted(
	struct mux_session *restrict ss, const uint_fast32_t emit)
{
	ASSERT(emit <= ss->unacked.unreported);
	ss->unacked.unreported -= (uint_least32_t)emit;
	ss->unacked.ack_ticks = 0;
}

void mux_unacked_free_all(struct mux_session *restrict ss)
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
	unacked_set_replay_off(&ss->unacked, SIZE_MAX);
	/* The replay copy belonged to the ring just freed (or to the send buffer
	 * a caller discarded alongside it). Leaving the pointer set lets a frame
	 * the pool later hands back at the same address false-match the identity
	 * check in mux_unacked_track_sent, whose branch then peeks the freed ring --
	 * NULL here, with the guarding ASSERT compiled out of every shipped
	 * build. */
	ss->unacked.retransmit_copy = NULL;
	ss->unacked.retransmit_copy_count = 0;
	/* stalled is a pure function of bytes against the session window, so it
	 * falls with them: a session left holding the gate over an empty ring
	 * would never send another data frame. */
	ss->unacked.stalled = false;
}
