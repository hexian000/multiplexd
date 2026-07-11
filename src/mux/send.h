/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file send.h
 * @brief Internal mux send pipeline: the transport write pump, the frame
 *        producers (PUSH/control/OOB), the session-ACK emitter, and the flush
 *        entry points.
 */

#ifndef MUX_SEND_H
#define MUX_SEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_session;
struct mux_stream;
struct mux_frame;

/* send is the outbound half of the session: it drains the scheduler and the
 * OOB/retransmit queues into the wire sendbuf and pumps the transport. */

/* Drain the send pipeline once: retransmit replay, OOB controls, then scheduled
 * data, flushing to the transport.  Entry point from session.c:socket_cb. */
void session_on_send(struct mux_session *ss);

/* Wake the write path (arm EV_WRITE) when there is egress to flush; no-op
 * unless SESSION_ESTABLISHED. */
void mux_notify_write(struct mux_session *ss);

/* Enqueue a PUSH data frame for stream s into the send buffer; takes ownership
 * of frame. */
bool session_send_push(
	struct mux_session *ss, struct mux_stream *s, struct mux_frame *frame);

/* Enqueue a packed control frame for stream_id with the given flags and extra. */
bool session_send_ctrl(
	struct mux_session *ss, uint_fast16_t stream_id, uint_fast8_t flags,
	uint_fast32_t extra);

/* Enqueue one out-of-band stream-0 frame (PROBE/PING/PONG).  payload_len is the
 * exact payload size to encode; pass NULL to zero-fill.  Returns false on OOM. */
bool session_send_oob(
	struct mux_session *ss, uint_fast8_t extra,
	const unsigned char *payload, size_t payload_len);

/* Emit a session-level ACK for all unacknowledged non-stream-0 frames.
 * Caller must ensure unreported != 0. */
void session_emit_ack(struct mux_session *ss);

/* Remove all unsent non-RST frames for stream_id from the session send buffer.
 * Must be called before sending a new RST so stale frames do not arrive ahead
 * of the RST. */
void session_discard_stream_frames(
	struct mux_session *ss, uint_fast16_t stream_id);

/* Flush the send buffer once; call after enqueuing control frames outside the
 * I/O callback. */
void session_flush(struct mux_session *ss);

/* Flush OOB control frames (PING/PONG/PROBE) to the wire; no-op unless
 * SESSION_ESTABLISHED. */
void session_flush_oob(struct mux_session *ss);

/* Immediate response to a receive batch: drain ready egress without waiting a
 * libev iteration.  Inline only when the transport pipe is clear, else leave it
 * for the armed EV_WRITE drain. */
void session_flush_resp(struct mux_session *ss);

/* Wake the scheduler for stream s and flush the send pipeline inline to avoid
 * an extra libev iteration.  Must only be called from the receive path. */
void session_eager_flush(struct mux_session *ss, struct mux_stream *s);

#endif /* MUX_SEND_H */
