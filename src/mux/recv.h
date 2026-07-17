/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file recv.h
 * @brief Internal mux receive pipeline: transport read pump, frame
 *        decode/dispatch, control-frame (PING/PONG) handling, and the
 *        receive-driven window updates.
 */

#ifndef MUX_RECV_H
#define MUX_RECV_H

#include <stddef.h>

struct mux_session;
struct mux_header;

/* recv is the inbound pump: it pulls bytes off the transport into the receive
 * ring, decodes frames, handles control frames (PING/PONG), and drives the
 * receive-side window updates. */

/* Drain the transport read side: read and dispatch as many complete frames as
 * are available.  Entry point from session.c:socket_cb on EV_READ. */
void session_on_recv(struct mux_session *ss);

/* Dispatch whatever complete frames are already buffered in wire.recvbuf,
 * without reading more from the transport.  Entry point from
 * send.c:session_on_send, for the one case nothing else re-drives dispatch:
 * a post-hello early return deferred already-buffered frames
 * behind tx_pending, and tx_pending has now settled to false without ever
 * writing a byte to the peer (e.g. every queued stream tombstoned during
 * suspension), so no peer ACK is coming to trigger a fresh EV_READ. */
void session_dispatch_pending(struct mux_session *ss);

/* Process an inbound PING: send PONG if rate limit permits. */
void session_recv_ping(
	struct mux_session *ss, const struct mux_header *hdr,
	size_t frame_size);

/* Process an inbound PONG: feed timestamp to the BDP estimator. */
void session_recv_pong(
	struct mux_session *ss, const struct mux_header *hdr,
	size_t frame_size);

/* Update session_window towards max(peer_stream_window,
 * ceil(window_bytes / MUX_WINDOW_UNIT), initial_frames).  Unconditional: the
 * callers gate on auto_session_window before calling. */
void session_update_session_window(struct mux_session *ss, size_t window_bytes);

#endif /* MUX_RECV_H */
