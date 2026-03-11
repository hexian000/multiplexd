/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file server.h
 * @brief Server lifecycle management and statistics snapshots.
 */

#ifndef SERVER_H
#define SERVER_H

#include "api_server.h"
#include "listener.h"
#include "mux/mux.h"
#include "tunnel.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/shared_mutex.h"
#endif

#include <ev.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct config;
struct hashtable;
#if WITH_THREADS
struct mpmc_queue;
#else
struct mcache;
#endif
struct tls_context;

/* Single event log entry for the session event ring buffer. */
struct evlog_entry {
	/* wall-clock time of the most recent occurrence */
	time_t timestamp;
	/* consecutive occurrence count */
	size_t count;
	/* event description */
	char message[256];
};

/*
 * Performance monitoring is split into two routes:
 *
 *   counters route — `struct server_counters`, embedded in `struct server`.
 *     Fields are updated from any thread via the pointer block
 *     `struct session_counters` (see mux/mux.h) using the COUNTER_ADD/SUB/
 *     LOAD/STORE macros with memory_order_relaxed.
 *     Two semantic kinds live here:
 *       - monotonic counters (lifecycle, traffic, RST, errors, reconnects)
 *       - aggregated gauges that need cross-thread updates
 *         (recv_buffered_bytes, send_buffered_frames, unacked_frames),
 *         which use atomic add/sub for the same reason.
 *
 *   stats route — `struct server_runtime_stats`, embedded in `struct server`.
 *     Owned exclusively by the server thread; updated by direct access
 *     without atomics or pointer indirection.  Used for one-shot
 *     diagnostic samples (event log, stream-establish latency ring).
 *     `tunnel_stats()` is also part of this route: per-tunnel gauges
 *     are collected at snapshot time from the owning session.
 *
 * `server_stats()` produces a unified snapshot (`struct server_stats`)
 * combining both routes for the API server.
 */

/* Live cumulative counters and aggregated gauges embedded in struct server
 * (counters route).  All uintmax_t fields follow Prometheus counter
 * semantics: they increase monotonically and wrap to 0 on overflow;
 * consumers computing rates must handle a decrease in value as a counter
 * reset. */
struct server_counters {
	/* accepted connections from mux_listener */
	uintmax_t num_accepted;
	/* served connections from mux_listener (reached num_halfopen++) */
	uintmax_t num_served;

	/* accepted connections from tcp_listener */
	uintmax_t num_accepted_tcp;
	/* served connections from tcp_listener */
	uintmax_t num_served_tcp;

	/* accepted connections from api_listener */
	uintmax_t num_accepted_api;
	/* served connections from api_listener */
	uintmax_t num_served_api;

	/* session lifecycle counters (monotonic) */
#if WITH_THREADS
	atomic_uintmax_t num_session_created;
	atomic_uintmax_t num_session_connect;
	atomic_uintmax_t num_session_connected;
	atomic_uintmax_t num_session_disconnected;
	atomic_uintmax_t num_session_finalized;
#else
	uintmax_t num_session_created;
	uintmax_t num_session_connect;
	uintmax_t num_session_connected;
	uintmax_t num_session_disconnected;
	uintmax_t num_session_finalized;
#endif
	/* session gauges: maintained alongside the monotonic counters above */
#if WITH_THREADS
	/* sessions currently in ESTABLISHED state */
	atomic_size_t num_sessions;
	/* sessions currently in CONNECT or HANDSHAKE state */
	atomic_size_t num_session_halfopen;
#else
	/* sessions currently in ESTABLISHED state */
	size_t num_sessions;
	/* sessions currently in CONNECT or HANDSHAKE state */
	size_t num_session_halfopen;
#endif
	/* stream gauges: maintained alongside the monotonic counters above */
#if WITH_THREADS
	/* streams currently in any active (non-closed) state */
	atomic_size_t num_streams;
	/* streams currently in INIT, SYN_SENT, or SYN_RECEIVED state */
	atomic_size_t num_stream_halfopen;
#else
	/* streams currently in any active (non-closed) state */
	size_t num_streams;
	/* streams currently in INIT, SYN_SENT, or SYN_RECEIVED state */
	size_t num_stream_halfopen;
#endif
	/* stream lifecycle counters (monotonic) */
#if WITH_THREADS
	atomic_uintmax_t num_stream_opened;
	/* total passive-open streams accepted from remote peer */
	atomic_uintmax_t num_stream_accepted;
	/* total active-open streams whose first flight used SYN|PUSH */
	atomic_uintmax_t num_stream_fastopen;
	atomic_uintmax_t num_stream_established;
	atomic_uintmax_t num_stream_succeeded;
	atomic_uintmax_t num_stream_failed;
#else
	uintmax_t num_stream_opened;
	/* total passive-open streams accepted from remote peer */
	uintmax_t num_stream_accepted;
	/* total active-open streams whose first flight used SYN|PUSH */
	uintmax_t num_stream_fastopen;
	uintmax_t num_stream_established;
	uintmax_t num_stream_succeeded;
	uintmax_t num_stream_failed;
#endif

	/* mux connections dropped by startup_limit */
	uintmax_t num_rejected;
#if WITH_TLS
	/* TLS accept failures (server mode) */
	uintmax_t num_tls_failures;
#endif
	/* client-mode reconnect attempts */
#if WITH_THREADS
	atomic_uintmax_t num_reconnects;
	/* RST frames sent (aggregated) */
	atomic_uintmax_t num_rst_sent;
	/* RST frames received (aggregated) */
	atomic_uintmax_t num_rst_recv;
	/* stream_abort() calls (aggregated) */
	atomic_uintmax_t num_stream_errors;
#else
	uintmax_t num_reconnects;
	/* RST frames sent (aggregated) */
	uintmax_t num_rst_sent;
	/* RST frames received (aggregated) */
	uintmax_t num_rst_recv;
	/* stream_abort() calls (aggregated) */
	uintmax_t num_stream_errors;
#endif

	/* bytes currently buffered in per-stream recvbuf rings (aggregated) */
#if WITH_THREADS
	atomic_size_t recv_buffered_bytes;
	/* frames currently queued in per-stream send_queue (aggregated) */
	atomic_size_t send_buffered_frames;
	/* frames held in the session unacked list (aggregated, spec §6.7.2) */
	atomic_size_t unacked_frames;

	/* aggregated traffic counters; updated atomically by session threads. */
	atomic_uintmax_t traffic_byt_mux_recv;
	atomic_uintmax_t traffic_byt_mux_sent;
	atomic_uintmax_t traffic_byt_local_recv;
	atomic_uintmax_t traffic_byt_local_sent;
#else
	size_t recv_buffered_bytes;
	/* frames currently queued in per-stream send_queue (aggregated) */
	size_t send_buffered_frames;
	/* frames held in the session unacked list (aggregated, spec §6.7.2) */
	size_t unacked_frames;

	/* aggregated traffic counters. */
	uintmax_t traffic_byt_mux_recv;
	uintmax_t traffic_byt_mux_sent;
	uintmax_t traffic_byt_local_recv;
	uintmax_t traffic_byt_local_sent;
#endif
};

/* One-shot diagnostic samples owned by the server thread (stats route).
 * Accessed without synchronization; consumers must run on the server
 * thread or call server_stats() to obtain a snapshot copy. */
struct server_runtime_stats {
	/* ring buffer of SYN->SYN|ACK latency samples */
	size_t stream_establish_count;
	intmax_t stream_establish_ns[256];

	/* ring buffer recording session established/disconnected events */
	struct evlog_entry eventlog[16];
	/* number of valid entries */
	size_t eventlog_len;
	/* next write position */
	size_t eventlog_pos;
};

/* Per-identity snapshot populated by server_stats(). */
struct identity_stats {
	/* borrowed pointer into identity_peers[i].id */
	const char *id;
	/* number of tunnels in the pool */
	size_t num_tunnels;
	/* true when at least one session is in MUX_STATE_ESTABLISHED */
	bool connected;
	/* tunnel statistics from the first established session;
	 * zero-initialised when !connected */
	struct tunnel_stats tunnel;
};

/* Collected snapshot of server statistics; all fields are plain (non-atomic)
 * types, safe to read without synchronization after server_stats() returns.
 * Organized into two groups matching the two monitoring routes. */
struct server_stats {
	/* --- counters route snapshot (mirrors struct server_counters) --- */
	uintmax_t num_accepted;
	uintmax_t num_served;
	uintmax_t num_accepted_tcp;
	uintmax_t num_served_tcp;
	uintmax_t num_accepted_api;
	uintmax_t num_served_api;
	uintmax_t num_session_created;
	uintmax_t num_session_connect;
	uintmax_t num_session_connected;
	uintmax_t num_session_disconnected;
	uintmax_t num_session_finalized;
	size_t num_sessions;
	size_t num_session_halfopen;
	size_t num_streams;
	size_t num_stream_halfopen;
	uintmax_t num_stream_opened;
	uintmax_t num_stream_accepted;
	uintmax_t num_stream_fastopen;
	uintmax_t num_stream_established;
	uintmax_t num_stream_succeeded;
	uintmax_t num_stream_failed;
	uintmax_t num_rejected;
#if WITH_TLS
	uintmax_t num_tls_failures;
#endif
	uintmax_t num_reconnects;
	uintmax_t num_rst_sent;
	uintmax_t num_rst_recv;
	uintmax_t num_stream_errors;
	size_t recv_buffered_bytes;
	size_t send_buffered_frames;
	size_t unacked_frames;
	uintmax_t traffic_byt_mux_recv;
	uintmax_t traffic_byt_mux_sent;
	uintmax_t traffic_byt_local_recv;
	uintmax_t traffic_byt_local_sent;

	/* --- stats route snapshot (mirrors struct server_runtime_stats
	 * and per-identity tunnel_stats) --- */
	size_t stream_establish_count;
	intmax_t stream_establish_ns[256];
	struct evlog_entry eventlog[16];
	size_t eventlog_len;
	size_t eventlog_pos;
	struct identity_stats identities[16];
	size_t num_identities;
};

struct server {
	struct ev_loop *loop;
	struct config *conf;
	/* path to the config file, used for SIGHUP reload */
	const char *conf_path;
#if WITH_THREADS
	/* Server-level lock-free frame pool shared across all tunnel threads.
	 * Behaves as a leaky buffer: push failure frees the frame immediately. */
	struct mpmc_queue *frame_pool;
#else
	/* Server-level frame allocator cache (single-threaded). */
	struct mcache *frame_pool;
#endif
#if WITH_TLS
	/* TLS context for accepted mux connections (server role). */
	struct tls_context *server_tlsctx;
	/* TLS context for initiated mux connections (client role). */
	struct tls_context *client_tlsctx;
#endif

	struct listener tcp_listener;
	struct listener mux_listener;
	struct listener api_listener;

	/* Per-identity listener and the pool of mux sessions serving it. */
	struct identity_listener {
		struct listener listener;
		/* Peer identity expected in hellos — not owned. */
		const char *peer_identity;
		/* Active tunnels for this identity (dialed in client mode,
		 * accepted with matching peer identity in server mode).
		 * Owned array; all elements are non-NULL. */
		struct tunnel **tunnels;
		size_t num_tunnels;
		/* Round-robin dispatch cursor into tunnels[]. */
		size_t rr_next;
	} *identities;
	size_t num_identities;

	/* Keyed by tunnel_session_id() (the server-assigned 16-byte session
	 * identity).  Contains accepted (inbound) sessions only; dialed
	 * sessions are tracked via mux_tunnel / identities[i].tunnels[]. */
	struct hashtable *accepted_tunnels;
	/* Single dialed session for the top-level mux_connect entry, or NULL. */
	struct tunnel *mux_tunnel;
	/* Dialed identity_connect sessions, indexed by conf->identity_connect[].
	 * Elements are set to NULL when wired into identities[i].tunnels[] or after
	 * tunnel_close().  Tracked here so server_stop() can reach them even if
	 * the handshake has not completed yet. */
	struct tunnel **identity_tunnels;
	size_t num_identity_tunnels;

	intmax_t started;

	ev_signal w_sighup;
	ev_signal w_sigint;
	ev_signal w_sigterm;
	/* Graceful shutdown deadline: fires 2 s after signal to force exit. */
	ev_timer w_shutdown;
	/* Cross-thread relay: ev_async + dispatcher for session threads. */
#if WITH_THREADS
	ev_async w_async;
	struct dispatcher *disp;
	/* Shared mutex protecting accepted_sessions for cross-thread lookups.
	 * Held exclusively by the server thread when adding or removing entries;
	 * held shared by worker threads during relay_on_resume. */
	smtx_t accepted_mu;
#endif

	struct server_counters counters;
	struct server_runtime_stats runtime;

	/* Rate tracking state for POST /stats bandwidth display */
	struct {
		uintmax_t byt_mux_recv, byt_mux_sent;
		uintmax_t byt_local_recv, byt_local_sent;
		intmax_t timestamp;
		bool is_set;
	} rate_tracker;
};

/**
 * @brief Allocate and initialize a server instance.
 * @param loop The main event loop that owns the server.
 * @param conf The validated configuration; ownership transfers to the server.
 * @return A new server on success, or NULL on allocation/setup failure.
 */
struct server *server_new(struct ev_loop *loop, struct config *conf);

/**
 * @brief Start listeners, background workers, and outbound sessions.
 * @param s The server to start.
 * @return true on success, false on startup failure.
 */
bool server_start(struct server *s);

/**
 * @brief Stop listeners and initiate shutdown of active sessions.
 * @param s The server to stop.
 */
void server_stop(struct server *s);

/**
 * @brief Free a stopped server and all owned resources.
 * @param s The server to free; NULL is allowed.
 */
void server_free(struct server *s);

/**
 * @brief Collect a consistent snapshot of all server statistics.
 * @param s The server to inspect.
 * @param out Output snapshot filled on success.
 */
void server_stats(
	const struct server *restrict s, struct server_stats *restrict out);

#endif /* SERVER_H */
