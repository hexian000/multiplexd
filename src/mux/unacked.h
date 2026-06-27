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
	 * across unacked_ack_trim calls; 0 once the head is fully popped. */
	uint_least32_t partial_offset;
	/* Count of non-stream-0 frames sent (advanced on each ring push);
	 * 32-bit serial number (RFC 1982). */
	uint_least32_t send_seq;
	/* Count of non-stream-0 frames received. */
	uint_least32_t recv_seq;
	/* recv_seq value at the time of the last session ACK emission. */
	uint_least32_t ack_seq;
	/* Cumulative send_seq acknowledged by the peer; 32-bit serial number
	 * (RFC 1982) — resume comparison uses serial_lt32. */
	uint_least32_t last_ack_recv;
	/* Ticks since the last session ACK while frames are pending; reset on
	 * emission or when recv_seq == ack_seq. */
	uint_least8_t ack_ticks;
	/* A stream ACK was sent since the last session ACK; schedule a
	 * session-level ACK piggyback. */
	bool ack_pending : 1;
	/* The unacked ring has reached the session window cap; data frame sends
	 * are suspended until the peer acknowledges frames. */
	bool stalled : 1;
	/* Offset of the first un-retransmitted frame during resume replay;
	 * SIZE_MAX when no retransmit is in progress. */
	size_t retransmit_off;
	/* Transient retransmit copy in flight; NULL otherwise. */
	struct mux_frame *retransmit_copy;
};

/* Result of unacked_ack_trim: ok=false on protocol violation (peer acked
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
void unacked_track_sent(struct mux_session *ss, struct mux_frame *frame);

/* Trim count logical frames from the unacked ring after a session-level ACK
 * from the peer; see struct unacked_ack_result. */
struct unacked_ack_result
unacked_ack_trim(struct mux_session *ss, uint_fast32_t count);

/* Apply the peer's resume_seq from a resume hello: trim the ring and position
 * the retransmit cursor.  Returns false on protocol violation. */
bool unacked_resume_ack_recv(struct mux_session *ss, uint_least32_t peer_ack);

/* recv_seq - ack_seq: the number of received frames awaiting a session ACK. */
uint_fast32_t unacked_ack_delta(const struct mux_session *ss);

/* Record that a session ACK covering emit frames was emitted. */
void unacked_ack_emitted(struct mux_session *ss, uint_fast32_t emit);

/* Discard all frames in the unacked ring, free the ring array, and reset
 * counters and the retransmit cursor. */
void unacked_free_all(struct mux_session *ss);

#endif /* MUX_UNACKED_H */
