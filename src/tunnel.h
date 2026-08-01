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
#include "shim/tls.h"
#endif

#include "sync/task.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sockaddr;
struct tunnel;

/* Server-level counter pointers for the mux session counters block.  Session
 * lifecycle only: every other counter in the block is per-tunnel and the tunnel
 * fills it in itself. */
struct tunnel_session_counters {
	mux_counter *num_session_created;
	mux_counter *num_session_connect;
	mux_counter *num_session_connected;
	mux_counter *num_session_disconnected;
	mux_counter *num_session_finalized;
	mux_gauge *num_sessions;
	mux_gauge *num_session_halfopen;
};

/* Abstract parent context for tunnel-to-server upstream calls. */
struct tunnel_context {
#if WITH_THREADS
	bool (*post_task)(void *user, struct task task);
	void (*flush_tasks)(void *user);
#endif
	bool (*verify_peer)(void *user, const char *peer_id);
	uint_least64_t (*alloc_index)(void *user);
	void *user;
#if !WITH_THREADS
	struct ev_loop *loop;
#endif
};

/* Callbacks invoked on the server loop for session lifecycle events.
 * on_event fires for all mux events except ESTABLISHED and RESUMED (routed to
 * on_established and on_resumed) and STREAM_ESTABLISHED (consumed by the tunnel
 * layer for latency stats and never relayed). */
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
	const struct mux_session_config *mux_conf;
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
	/* Server-level counter pointers; tunnel fills in per-tunnel fields. */
	const struct tunnel_session_counters *cnt;
	/* identity.verify: reject a peer whose claimed identity is not named by
	 * the certificate it presented on this transport.  Requires TLS; conf
	 * validation rejects the combination without it. */
	bool verify_identity;
	/* PSK mode: resolves an authenticated PSK label to the peer identity
	 * that owns it, or NULL when the label is unknown.  NULL in certificate
	 * mode.  Set instead of verify_identity, never alongside it: a PSK binder
	 * proves possession of the key its label names, so the binding is
	 * intrinsic rather than opt-in.  Borrowed; must outlive the tunnel. */
	const char *(*psk_identity_of)(void *ctx, const char *label);
	void *psk_ctx;
#if WITH_TLS
	/* Borrowed; the caller retains ownership on both success and failure
	 * (may be a shared, ref-counted handle reused across tunnels). */
	struct tls_context *tlsctx;
	/* Owned; freed by tunnel_new itself on failure (see below). */
	struct tls_connection *conn;
#endif
};

/* Allocate a tunnel and create the underlying mux session; does NOT start
 * the tunnel thread (call tunnel_start() after registration).  Takes
 * ownership of opts->fd (when fd >= 0) and opts->conn (when set) on both
 * success and failure; the caller must not close fd or free conn itself,
 * before or after the call.  opts->tlsctx is not owned; see struct
 * tunnel_opts.  Returns NULL on allocation failure. */
struct tunnel *tunnel_new(
	const struct tunnel_context *parent,
	const struct tunnel_opts *restrict opts);

/* Start the tunnel thread and dispatch mux_start.  Must be called once after
 * tunnel_new() succeeds and the tunnel has been registered.  Returns false if
 * the tunnel thread could not be created (thrd_nomem under load): the tunnel is
 * left un-started, and the caller must unregister it and tunnel_close() it
 * rather than treat it as live.  Always returns true without threads. */
bool tunnel_start(struct tunnel *t);

/* The monotonic counters a closed tunnel leaves behind.  A subset of struct
 * tunnel_stats holding no mux session state, so unlike tunnel_stats() it can
 * still be sampled once the session has been torn down. */
struct tunnel_final_counters {
	uint_least64_t num_stream_opened;
	uint_least64_t num_stream_accepted;
	uint_least64_t num_stream_fastopen;
	uint_least64_t num_stream_established;
	uint_least64_t num_stream_succeeded;
	uint_least64_t num_stream_failed;
	uint_least64_t num_reconnects;
	uint_least64_t num_rst_sent;
	uint_least64_t num_rst_recv;
	uint_least64_t num_stream_errors;
	size_t stream_establish_count;
	uint_least64_t byt_mux_recv;
	uint_least64_t byt_mux_sent;
	uint_least64_t byt_push_recv;
	uint_least64_t byt_push_sent;
};

/* Force-close: disconnect relay callbacks, suppress mux callbacks, close
 * the session, join the tunnel thread, and free the struct.  Safe even if
 * the tunnel thread was never started.
 *
 * When out is non-NULL it receives the tunnel's counters sampled after the
 * thread is joined and the session closed, so the increments teardown itself
 * makes are included -- mux_close() fails every stream still open, which a
 * tunnel_stats() taken before the call would miss entirely.  The one exception
 * is the OOM path where the thread cannot be told to stop and is abandoned
 * rather than joined: there *out is sampled before detaching and whatever the
 * abandoned thread counts afterwards is lost. */
void tunnel_close_final(struct tunnel *t, struct tunnel_final_counters *out);

/* tunnel_close_final() discarding the counters. */
void tunnel_close(struct tunnel *t);

/* Dispatch a graceful shutdown request to the session's tunnel loop.
 * The session performs a close handshake; MUX_EVENT_CLOSED is emitted
 * through on_event when done. */
void tunnel_shutdown(struct tunnel *t);

/* Drop the underlying transport without closing the mux session: dispatched to
 * the tunnel loop, it shuts the socket so the session enters SUSPENDED with its
 * state preserved. How the connection comes back depends on the tunnel: an
 * accepted one performs no local reconnect at all and waits for the peer to
 * resume (or for the resume timeout); a dialed one with idle_timeout == 0
 * re-dials immediately via handle_transport_lost(), w_reconnect being only the
 * failure backoff; a dialed one with idle_timeout > 0 reconnects on demand from
 * open_stream_task(). */
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
/* Copy the peer transport address (from the session thread's published snapshot)
 * into buf; returns whether an address is present.  Safe to call from the server
 * thread while the tunnel's session thread runs. */
bool tunnel_peer_addr_copy(
	const struct tunnel *t, struct sockaddr *restrict buf, size_t buflen);
bool tunnel_is_accepted(const struct tunnel *t);
const unsigned char *tunnel_session_id(const struct tunnel *t);
/* Server-wide monotonic index, never reused; a stable per-tunnel handle. */
uint_least64_t tunnel_index(const struct tunnel *t);

/* Fixed capacity of a tunnel's diagnostic-tag buffer, shared by struct tunnel
 * (its private working tag and its published snapshot) and by struct
 * tunnel_stats below, so the cross-struct tag copies in tunnel_stats() are
 * provably in bounds. Shrinking one alone would otherwise risk an OOB access. */
enum { TUNNEL_TAG_SIZE = 256 };

/* Fixed capacity of the SYN->SYN|ACK latency ring, shared by struct tunnel and
 * struct tunnel_stats below for the same reason. */
enum { TUNNEL_ESTABLISH_RING_SIZE = 256 };

/* Snapshot of per-tunnel statistics. */
struct tunnel_stats {
	/* borrowed pointer to the identity string for this tunnel's pool;
	 * NULL for the top-level mux_tunnel (no identity pool) */
	const char *peer_identity;
	/* Server-wide monotonic index, never reused. */
	uint_least64_t tunnel_index;
	/* the tunnel's diagnostic tag ("my <= peer"), copied from the session
	 * thread's published snapshot */
	char tag[TUNNEL_TAG_SIZE];
	/* total tunnels in this identity's pool (1 for mux_tunnel) */
	size_t num_tunnels;
	/* true for a passively-accepted (server-role) session.  Such a session
	 * never dials, so the counters only the dial path can bump -- currently
	 * num_reconnects -- stay zero for its whole life; the metrics layer reads
	 * this to skip emitting those series rather than publishing a constant
	 * zero per accepted tunnel. */
	bool accepted;
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
	/* Per-tunnel error and control counters. */
	uint_least64_t num_reconnects;
	uint_least64_t num_rst_sent;
	uint_least64_t num_rst_recv;
	uint_least64_t num_stream_errors;
	/* Per-tunnel buffer gauges. */
	size_t recv_buffered_bytes;
	size_t send_buffered_frames;
	size_t unacked_frames;
	/* Per-tunnel traffic byte counters. */
	uint_least64_t byt_mux_recv;
	uint_least64_t byt_mux_sent;
	/* PUSH-frame payload bytes only (no frame headers, no non-PUSH frames) */
	uint_least64_t byt_push_recv;
	uint_least64_t byt_push_sent;
	/* SYN->SYN|ACK latency ring (ns); stream_establish_count is the monotonic
	 * write index.  Fed by every active open, on accepted tunnels too. */
	size_t stream_establish_count;
	int_least64_t stream_establish_ns[TUNNEL_ESTABLISH_RING_SIZE];
	/* Percentiles (ns) over stream_establish_ns; valid when
	 * stream_establish_count > 0 and server_stats() was asked for them via
	 * want_tunnel_latency, else zero. */
	int_least64_t stream_establish_p50;
	int_least64_t stream_establish_p90;
	int_least64_t stream_establish_p99;
};

/* Populate *out with a consistent snapshot of this tunnel's own statistics.
 * out->peer_identity and out->num_tunnels are server-level facts this function
 * does not touch, and the stream_establish percentiles are derived by
 * server_stats(); the caller owns those and sets them around this call.  Every
 * other field is written here. */
void tunnel_stats(const struct tunnel *t, struct tunnel_stats *restrict out);

/* Dispatch a new outbound stream opening to the session's tunnel loop.
 * On allocation or dispatch failure fd is closed and the call returns
 * silently. */
void tunnel_open_stream(struct tunnel *t, int fd);

/* Options for a single-pass reload dispatch, applied atomically in the tunnel
 * thread: address updates precede the drain config. */
struct tunnel_reload_opts {
	struct mux_session_config conf;
#if WITH_TLS
	/* When non-NULL, the new per-tunnel TLS context, whose ownership transfers
	 * to tunnel_reload(): the tunnel adopts it and frees its previous one.
	 * NULL leaves the current context in place. */
	struct tls_context *tlsctx;
#endif
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
	/* New identity.verify setting; read at the next hello, so it takes
	 * effect on the session's next handshake (resume or reconnect) rather
	 * than mid-session. */
	bool verify_identity;
	/* New PSK resolver.  Must be refreshed together with the config: the
	 * table the old one closed over is freed once the reload completes. */
	const char *(*psk_identity_of)(void *ctx, const char *label);
	void *psk_ctx;
};

/* Dispatch a single-pass reload to the session's tunnel loop; address
 * updates, drain config, socket options, and TLS context applied atomically.
 * Takes ownership of opts->tlsctx either way: on OOM the dispatch is
 * skipped, the context is freed, and the error is logged. */
void tunnel_reload(struct tunnel *t, const struct tunnel_reload_opts *opts);

#endif /* TUNNEL_H */
