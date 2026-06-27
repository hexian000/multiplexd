/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tunnel.h
 * @brief Tunnel wrapper around mux sessions.
 */

#ifndef TUNNEL_H
#define TUNNEL_H

#include "conf.h"
#include "mux/mux.h"
#if WITH_TLS
#include "tlsutil.h"
#endif
#include "util.h"

#include <ev.h>

#include <stdbool.h>

struct server;
struct tunnel;

/* Callbacks invoked on the server loop for session lifecycle events.
 * on_event fires for all mux events except ESTABLISHED and RESUMED, which are
 * routed to on_established and on_resumed. */
struct tunnel_callbacks {
	void (*on_event)(
		void *data, struct tunnel *t, enum mux_event,
		union mux_event_data);
	/* Fired when a handshake completes as a fresh session.  May fire more than
	 * once on the same tunnel (resume rejected → fresh session), so handlers
	 * must be idempotent. */
	void (*on_established)(
		void *data, struct tunnel *t, int_fast64_t lat_ns);
	/* Fired when the peer confirmed that the suspended session has been
	 * successfully resumed on the new transport. */
	void (*on_resumed)(void *data, struct tunnel *t, int_fast64_t lat_ns);
	/* Locate the suspended tunnel matching session_id for a resume.  May keep
	 * a lock held to pin the returned tunnel until on_resume_unpin; returns
	 * NULL (no lock obligation) when there is no match. */
	struct tunnel *(*on_resume_lookup)(
		void *data, struct tunnel *new_t,
		const unsigned char *session_id);
	/* Paired with on_resume_lookup: called once after each non-NULL lookup,
	 * after the handoff is enqueued, to release the pin lock.  NULL if
	 * on_resume_lookup takes no lock. */
	void (*on_resume_unpin)(void *data, struct tunnel *new_t);
};

struct tunnel_opts {
	const struct tunnel_callbacks *cb;
	void *data;
	const struct mux_config *mux_conf;
	/* Socket options applied to outbound mux connections. */
	struct conf_socket_opts mux_socket;
	/* Socket options applied to inbound forwarded-stream connections. */
	struct conf_socket_opts local_socket;
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

/* Allocate a tunnel and create the underlying mux session; does NOT start
 * the tunnel thread (call tunnel_start() after registration).  Takes
 * ownership of opts->fd; returns NULL on allocation failure. */
struct tunnel *
tunnel_new(struct server *srv, const struct tunnel_opts *restrict opts);

/* Start the tunnel thread and dispatch mux_start.  Must be called once after
 * tunnel_new() succeeds and the tunnel has been registered. */
void tunnel_start(struct tunnel *t);

/* Force-close: disconnect relay callbacks, suppress mux callbacks, close
 * the session, join the tunnel thread, and free the struct.  Safe even if
 * the tunnel thread was never started. */
void tunnel_close(struct tunnel *t);

/* Dispatch a graceful shutdown request to the session's tunnel loop.
 * The session performs a close handshake; MUX_EVENT_CLOSED is emitted
 * through on_event when done. */
void tunnel_shutdown(struct tunnel *t);

/* Drop the underlying transport without closing the mux session: dispatched to
 * the tunnel loop, it shuts the socket so the session enters SUSPENDED with its
 * state preserved, and w_reconnect re-establishes the connection. */
void tunnel_drop_transport(struct tunnel *t);

/* --- Accessors --- */

int tunnel_fd(const struct tunnel *t);
enum mux_state tunnel_state(const struct tunnel *t);
struct mux_session *tunnel_session(const struct tunnel *t);
const char *tunnel_peer_id(const struct tunnel *t);
/* Copy the peer identity (from the session thread's published snapshot) into buf;
 * returns whether a peer identity is present.  Safe to call from the server
 * thread while the tunnel's session thread runs. */
bool tunnel_peer_identity_copy(
	const struct tunnel *t, char *restrict buf, size_t buflen);
#if WITH_TLS
const unsigned char *tunnel_peer_cert_der(const struct tunnel *t, size_t *len);
#endif
const struct sockaddr *tunnel_peer_addr(const struct tunnel *t);
bool tunnel_is_accepted(const struct tunnel *t);
const unsigned char *tunnel_session_id(const struct tunnel *t);
/* Server-wide monotonic index, never reused; a stable per-tunnel handle. */
uint_least64_t tunnel_index(const struct tunnel *t);

/* Snapshot of per-tunnel statistics. */
struct tunnel_stats {
	/* borrowed pointer to the identity string for this tunnel's pool;
	 * NULL for the top-level mux_tunnel (no identity pool) */
	const char *peer_identity;
	/* Server-wide monotonic index, never reused. */
	uint_least64_t tunnel_index;
	/* the tunnel's diagnostic tag ("my <= peer"), copied from the session
	 * thread's published snapshot */
	char tag[256];
	/* true for passively-accepted (server-role) tunnels; used by
	 * server_stats() to avoid double-counting stream counters. */
	bool accepted;
	/* total tunnels in this identity's pool (1 for mux_tunnel) */
	size_t num_tunnels;
	bool established;
	size_t rx_window;
	size_t tx_window;
	int_least64_t last_changed;
	/* 0 if no measurement has been completed yet. */
	int_least64_t rtt_ns;
	/* Per-direction bandwidth-delay product in bytes; 0 if not yet
	 * estimated. */
	size_t bdp_rx;
	size_t bdp_tx;
	/* Per-tunnel stream lifecycle counters. */
	size_t num_streams;
	size_t num_stream_halfopen;
	uint_least64_t num_stream_opened;
	uint_least64_t num_stream_accepted;
	uint_least64_t num_stream_fastopen;
	uint_least64_t num_stream_established;
	uint_least64_t num_stream_succeeded;
	uint_least64_t num_stream_failed;
	/* Per-tunnel traffic byte counters. */
	uint_least64_t byt_mux_recv;
	uint_least64_t byt_mux_sent;
	/* PUSH-frame payload bytes only (no frame headers, no non-PUSH frames) */
	uint_least64_t byt_push_recv;
	uint_least64_t byt_push_sent;
	/* SYN->SYN|ACK latency ring (ns); stream_establish_count is the monotonic
	 * write index.  Populated only for dialed tunnels. */
	size_t stream_establish_count;
	int_least64_t stream_establish_ns[256];
};

/* Populate *out with a consistent snapshot of tunnel statistics. */
void tunnel_stats(const struct tunnel *t, struct tunnel_stats *restrict out);

/* Dispatch a new outbound stream opening to the session's tunnel loop.
 * On allocation failure fd is closed and the call returns silently. */
void tunnel_open_stream(struct tunnel *t, int fd);

/* Options for a single-pass reload dispatch, applied atomically in the tunnel
 * thread: address updates precede the drain config. */
struct tunnel_reload_opts {
	struct mux_config conf;
	struct conf_socket_opts mux_socket;
	struct conf_socket_opts local_socket;
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

/* Dispatch a single-pass reload to the session's tunnel loop; address
 * updates, drain config, socket options, and TLS context applied atomically.
 * On OOM the dispatch is skipped and the error is logged. */
void tunnel_reload(struct tunnel *t, const struct tunnel_reload_opts *opts);

#endif /* TUNNEL_H */
