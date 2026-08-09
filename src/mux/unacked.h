/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file unacked.h
 * @brief Internal mux session-level reliability state (spec §5.7).
 */

#ifndef MUX_UNACKED_H
#define MUX_UNACKED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_session;
struct mux_frame;
struct mux_frame_ring;

/* Session-level reliability state (spec §5.7): the unacked frame ring, the
 * non-stream-0 sequence counters, the send-stall gate, and the resume
 * retransmit cursor.  Embedded by value in mux_session. */
struct unacked_ctx {
	/* Non-stream-0 frames flushed but not yet acked; frame ring with O(1)
	 * head trim. */
	struct mux_frame_ring *ring;
	/* Logical frame count in the ring (mirrors cnt.unacked_frames). */
	size_t frames;
	/* Payload bytes in the ring; drives the stall gate (byte-based so small
	 * frames cannot fill the window). */
	size_t bytes;
	/* Byte offset into the ring head entry while it is partially trimmed
	 * across mux_unacked_ack_trim calls; 0 once the head is fully popped. */
	uint_least32_t partial_offset;
	/* Count of non-stream-0 frames received. */
	uint_least32_t recv_seq;
	/* Frames processed but not yet reported in a session ACK (spec §5.7.3);
	 * a plain count, not a serial number. */
	uint_least32_t unreported;
	/* Cumulative count of non-stream-0 frames acknowledged by the peer;
	 * 32-bit serial number (RFC 1982) — resume comparison uses serial_lt32. */
	uint_least32_t last_ack_recv;
	/* Ticks since the last session ACK while frames are pending; reset on
	 * emission or when unreported == 0. */
	uint_least8_t ack_ticks;
	/* The unacked ring has reached the session window cap; data frame sends
	 * are suspended until the peer acknowledges frames. */
	bool stalled : 1;
	/* Offset of the first un-retransmitted frame during resume replay;
	 * SIZE_MAX when no retransmit is in progress. */
	size_t retransmit_off;
	/* Running total of logical frames actually retransmitted so far this replay
	 * pass: the sum of unacked_count over ring positions [0, retransmit_off),
	 * or 0 when retransmit_off == SIZE_MAX. Maintained incrementally (see
	 * mux_unacked_track_sent's retire branch and mux_unacked_ack_trim) so
	 * mux_unacked_ack_recv's replay bound is O(1) instead of rescanning the prefix
	 * on every peer ACK. Boundary resets go through unacked_set_replay_off. */
	size_t retransmitted_frames;
	/* Transient retransmit copy in flight; NULL otherwise. */
	struct mux_frame *retransmit_copy;
	/* Logical sub-frame count (unacked_count) of the ring entry whose replay
	 * copy is currently in flight, captured in send_queue_retransmit while the
	 * original is validly peeked; consumed by mux_unacked_track_sent's retire
	 * branch to advance retransmitted_frames without re-peeking the ring (which
	 * would reopen the #47 use-after-free). Valid only while retransmit_copy is
	 * non-NULL. */
	size_t retransmit_copy_count;
};

/* Position the resume-replay cursor at a boundary (0 to arm replay from the
 * ring head, SIZE_MAX for no replay) and reset the retransmitted-frame counter
 * to match. Every site that sets retransmit_off to a boundary routes through
 * here so the counter can never be left stale; the incremental maintenance
 * sites (mux_unacked_track_sent, mux_unacked_ack_trim) update both fields directly. */
static inline void
unacked_set_replay_off(struct unacked_ctx *restrict u, const size_t off)
{
	u->retransmit_off = off;
	u->retransmitted_frames = 0;
}

/* Result of mux_unacked_ack_trim: ok=false on protocol violation (peer acked
 * more than sent); trimmed_bytes/unstalled let the caller drive the BDP
 * estimator and EV_WRITE re-arm without coupling this module to them. */
struct unacked_ack_result {
	bool ok;
	size_t trimmed_bytes;
	bool unstalled;
};

/* Hand a fully-sent sendbuf frame to the unacked ring: strip stream-0 controls
 * and hello frames, retire retransmit copies (advancing the replay cursor), and
 * push the rest for possible resume replay.  Takes ownership of frame. */
void mux_unacked_track_sent(
	struct mux_session *restrict ss, struct mux_frame *restrict frame);

/* Trim count logical frames from the unacked ring; see struct
 * unacked_ack_result.  Internal primitive shared by mux_unacked_ack_recv and
 * mux_unacked_resume_ack_recv; callers processing a peer frame should use
 * mux_unacked_ack_recv instead (see below). */
struct unacked_ack_result
mux_unacked_ack_trim(struct mux_session *restrict ss, uint_fast32_t count);

/* Handle a session-level ACK from a peer frame received during normal
 * operation (dispatch_ctrl_frame's MUX_FLAG_ACK path). Bounds count by what
 * has actually been retransmitted so far when mid-replay, then trims via
 * mux_unacked_ack_trim; see struct unacked_ack_result. */
struct unacked_ack_result
mux_unacked_ack_recv(struct mux_session *restrict ss, uint_fast32_t count);

/* Apply the peer's resume_seq from a resume hello: trim the ring and position
 * the retransmit cursor.  Returns false on protocol violation; the ring may be
 * partially trimmed by then, so the caller must tear the session down. */
bool mux_unacked_resume_ack_recv(
	struct mux_session *restrict ss, uint_least32_t peer_ack);

/* Record that a session ACK covering emit frames was emitted. */
void mux_unacked_ack_emitted(
	struct mux_session *restrict ss, uint_fast32_t emit);

/* Discard all frames in the unacked ring, free the ring array, and reset the
 * ring's derived state (frame/byte totals, the send-stall gate, the retransmit
 * cursor and copy). The sequence counters (recv_seq, unreported,
 * last_ack_recv, ack_ticks) are left untouched for the caller to reset. */
void mux_unacked_free_all(struct mux_session *restrict ss);

#endif /* MUX_UNACKED_H */
