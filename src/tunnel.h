/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tunnel.h
 * @brief Tunnel wrapper around mux sessions.
 */

#ifndef TUNNEL_H
#define TUNNEL_H

#include "mux/mux.h"
#include "util.h"

#include <ev.h>
#include <stdbool.h>

struct server;
struct tunnel;

/* Callbacks invoked on the server loop for session lifecycle events.
 * Inbound stream policy is enforced by tunnel layer; streams are accepted
 * by default, then attached to sockets via tunnel_open_stream().
 * on_event fires for all mux events except MUX_EVENT_ESTABLISHED and
 * MUX_EVENT_RESUMED, which are routed to on_established and on_resumed. */
struct tunnel_callbacks {
	void (*on_event)(
		void *data, struct tunnel *t, enum mux_event,
		union mux_event_data);
	/* Fired when a handshake completes as a fresh session.  May fire more
	 * than once on the same tunnel when the server rejects a resume
	 * attempt and the client falls back to a new session; implementations
	 * must be idempotent with respect to any session pool they maintain. */
	void (*on_established)(void *data, struct tunnel *t, intmax_t lat_ns);
	/* Fired when the peer confirmed that the suspended session has been
	 * successfully resumed on the new transport. */
	void (*on_resumed)(void *data, struct tunnel *t, intmax_t lat_ns);
	struct mux_session *(*on_resume)(
		void *data, struct tunnel *new_t,
		const unsigned char *session_id);
};

struct tunnel_opts {
	const struct tunnel_callbacks *cb;
	void *data;
	const struct mux_config *mux_conf;
	/* Frame allocator for this tunnel's session; data field is overridden
	 * by tunnel_new() with the per-tunnel mcache. */
	struct mux_frame_allocator pool;
	/* Socket options applied to outbound mux connections. */
	struct socket_opts mux_socket;
	/* Socket options applied to inbound forwarded-stream connections. */
	struct socket_opts local_socket;
	int fd;
	const unsigned char *id;
	const char *connect_addr;
	const char *forward_addr;
	const char *identity;
	const char *peer_id;
#if WITH_TLS
	struct tls_context *tlsctx;
	struct tls_connection *conn;
#endif
};

/* Allocate a tunnel and create the underlying mux session.  Does NOT start
 * the tunnel thread; call tunnel_start() after successful registration.
 * Accepts ownership of opts->fd.  opts->connect_addr is the outbound address
 * for client-mode sessions (NULL for server-accepted).  opts->identity and
 * opts->peer_id are optional metadata that are copied if non-NULL.
 * Returns NULL on allocation failure. */
struct tunnel *
tunnel_new(struct server *srv, const struct tunnel_opts *restrict opts);

/* Start the tunnel thread and dispatch mux_start.  Must be called once after
 * tunnel_new() succeeds and the tunnel has been registered. */
void tunnel_start(struct tunnel *t);

/* Force-close the tunnel and release all resources.  Disconnects relay
 * callbacks, suppresses mux callbacks, closes the session, joins the
 * tunnel thread, and frees the tunnel struct.  Safe to call regardless
 * of whether the tunnel thread was started. */
void tunnel_close(struct tunnel *t);

/* Dispatch a graceful shutdown request to the session's tunnel loop.
 * The session performs a close handshake; MUX_EVENT_CLOSED is emitted
 * through on_event when done. */
void tunnel_shutdown(struct tunnel *t);

/* Drop the underlying transport connection without closing the mux session.
 * Dispatched to the tunnel loop; shuts down the socket so the mux layer
 * detects transport loss (MUX_EVENT_LOST) and w_reconnect re-establishes
 * the connection.  The mux session enters SUSPENDED state; its session ID
 * and stream state are preserved for resumption. */
void tunnel_drop_transport(struct tunnel *t);

/* --- Accessors --- */

int tunnel_fd(const struct tunnel *t);
enum mux_state tunnel_state(const struct tunnel *t);
struct mux_session *tunnel_session(const struct tunnel *t);
const char *tunnel_peer_id(const struct tunnel *t);
const char *tunnel_peer_identity(const struct tunnel *t);
const struct sockaddr *tunnel_peer_addr(const struct tunnel *t);
bool tunnel_is_accepted(const struct tunnel *t);
const unsigned char *tunnel_session_id(const struct tunnel *t);

/* Snapshot of per-tunnel statistics. */
struct tunnel_stats {
	/* borrowed pointer to the identity string for this tunnel's pool;
	 * NULL for the top-level mux_tunnel (no identity pool) */
	const char *peer_identity;
	/* borrowed pointer to the tunnel's diagnostic tag ("my <= peer") */
	const char *tag;
	/* true for passively-accepted (server-role) tunnels; used by
	 * server_stats() to avoid double-counting stream counters. */
	bool accepted;
	/* total tunnels in this identity's pool (1 for mux_tunnel) */
	size_t num_tunnels;
	bool established;
	size_t rx_window;
	size_t tx_window;
	intmax_t last_changed;
	/* Windowed-minimum RTT from PING/PONG probes, in nanoseconds; 0 if
	 * no measurement has been completed yet. */
	intmax_t rtt_ns;
	/* Instantaneous BDP (bw_wnd × rtt_ewma); 0 if not yet estimated.
	 * The effective BDP is reflected by rx_window and tx_window. */
	size_t bdp;
	/* Stream lifecycle counters (per-tunnel snapshot; aggregated by
	 * server_stats() across all active tunnels). */
	size_t num_streams;
	size_t num_stream_halfopen;
	uintmax_t num_stream_opened;
	uintmax_t num_stream_accepted;
	uintmax_t num_stream_fastopen;
	uintmax_t num_stream_established;
	uintmax_t num_stream_succeeded;
	uintmax_t num_stream_failed;
	/* Traffic byte counters (per-tunnel snapshot; aggregated by
	 * server_stats() across all active tunnels plus closed-tunnel
	 * accumulator in srv->counters). */
	uintmax_t byt_mux_recv;
	uintmax_t byt_mux_sent;
	/* PUSH-frame payload bytes only (no frame headers, no non-PUSH frames) */
	uintmax_t byt_push_recv;
	uintmax_t byt_push_sent;
	/* SYN->SYN|ACK latency ring (ns).  stream_establish_count is the
	 * monotonic write index; the ring holds the most recent
	 * min(stream_establish_count, 256) samples.
	 * Populated only for dialed tunnels (latency is measured client-side). */
	size_t stream_establish_count;
	intmax_t stream_establish_ns[256];
};

/* Populate *out with a consistent snapshot of tunnel statistics. */
void tunnel_stats(const struct tunnel *t, struct tunnel_stats *restrict out);

/* Dispatch a new outbound stream opening to the session's tunnel loop.
 * On allocation failure fd is closed and the call returns silently. */
void tunnel_open_stream(struct tunnel *t, int fd);

/* Options for a single-pass reload dispatch.  Applied atomically in the
 * tunnel thread: address updates precede the drain config, ensuring any
 * reconnect triggered by the drain uses the updated addresses. */
struct tunnel_reload_opts {
	struct mux_config conf;
	struct socket_opts mux_socket;
	struct socket_opts local_socket;
	/* When true, the session drains: it rejects new inbound streams and
	 * initiates graceful shutdown when its last active stream closes. */
	bool drain;
	/* When true, update the outbound connect address to connect_addr
	 * (NULL clears and disables reconnect). */
	bool update_connect_addr;
	const char *connect_addr;
	/* When true, stop the reconnect timer and set shutting_down.
	 * Mutually exclusive with update_connect_addr. */
	bool disable_reconnect;
	/* When true, update the stream forwarding address to forward_addr
	 * (NULL clears the target). */
	bool update_forward_addr;
	const char *forward_addr;
};

/* Dispatch a single-pass reload to the session's tunnel loop.
 * Address updates, drain config, socket options, and TLS context are all
 * applied in one atomic task.  On allocation failure the dispatch is
 * skipped and the error is logged; the caller's loop continues. */
void tunnel_reload(struct tunnel *t, const struct tunnel_reload_opts *opts);

#endif /* TUNNEL_H */
