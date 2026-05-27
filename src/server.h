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

/* Session event ring buffer; owned by the server thread. */
struct evlog {
	struct evlog_entry entries[16];
	size_t len; /* valid entries */
	size_t pos; /* next write position */
};

/*
 * Two monitoring routes feed `server_stats()`:
 *
 *   counters route — `struct server_counters` in `struct server`.
 *     Updated from any thread via `struct mux_session_counters` (mux/mux.h)
 *     using COUNTER_* macros with memory_order_relaxed.
 *
 *   stats route — diagnostic fields in `struct server`, server-thread-only.
 *     Covers the event log, stream-establish latency ring, and per-tunnel
 *     gauges collected at snapshot time by `tunnel_stats()`.
 */

/* Live cumulative counters and aggregated gauges embedded in struct server
 * (counters route).  All uintmax_t fields follow Prometheus counter
 * semantics: they increase monotonically and wrap to 0 on overflow;
 * consumers computing rates must handle a decrease in value as a counter
 * reset. */
struct server_counters {
	/* listener counters — updated on the server thread only */
	struct {
		/* accepted connections from mux_listener */
		uintmax_t num_accepted;
		/* served connections from mux_listener (reached num_halfopen++) */
		uintmax_t num_served;
		/* accepted/served connections from tcp_listener */
		uintmax_t num_accepted_tcp;
		uintmax_t num_served_tcp;
		/* accepted/served connections from api_listener */
		uintmax_t num_accepted_api;
		uintmax_t num_served_api;
		/* mux connections dropped by startup_limit */
		uintmax_t num_rejected;
#if WITH_TLS
		/* TLS accept failures (server mode) */
		uintmax_t num_tls_failures;
#endif
	};

	/* session lifecycle counters (monotonic) and gauges */
	struct {
#if WITH_THREADS
		atomic_uintmax_t num_session_created;
		atomic_uintmax_t num_session_connect;
		atomic_uintmax_t num_session_connected;
		atomic_uintmax_t num_session_disconnected;
		atomic_uintmax_t num_session_finalized;
		/* sessions currently in ESTABLISHED state */
		atomic_size_t num_sessions;
		/* sessions currently in CONNECT or HANDSHAKE state */
		atomic_size_t num_session_halfopen;
#else
		uintmax_t num_session_created;
		uintmax_t num_session_connect;
		uintmax_t num_session_connected;
		uintmax_t num_session_disconnected;
		uintmax_t num_session_finalized;
		/* sessions currently in ESTABLISHED state */
		size_t num_sessions;
		/* sessions currently in CONNECT or HANDSHAKE state */
		size_t num_session_halfopen;
#endif
	};

	/* error and control counters */
	struct {
#if WITH_THREADS
		/* client-mode reconnect attempts */
		atomic_uintmax_t num_reconnects;
		/* RST frames sent (aggregated) */
		atomic_uintmax_t num_rst_sent;
		/* RST frames received (aggregated) */
		atomic_uintmax_t num_rst_recv;
		/* stream_abort() calls (aggregated) */
		atomic_uintmax_t num_stream_errors;
#else
		/* client-mode reconnect attempts */
		uintmax_t num_reconnects;
		/* RST frames sent (aggregated) */
		uintmax_t num_rst_sent;
		/* RST frames received (aggregated) */
		uintmax_t num_rst_recv;
		/* stream_abort() calls (aggregated) */
		uintmax_t num_stream_errors;
#endif
	};

	/* per-stream buffer gauges (aggregated) */
	struct {
#if WITH_THREADS
		/* bytes currently buffered in per-stream recvbuf rings */
		atomic_size_t recv_buffered_bytes;
		/* frames currently queued in per-stream send_queue */
		atomic_size_t send_buffered_frames;
		/* frames held in the session unacked list (spec §6.7.2) */
		atomic_size_t unacked_frames;
#else
		/* bytes currently buffered in per-stream recvbuf rings */
		size_t recv_buffered_bytes;
		/* frames currently queued in per-stream send_queue */
		size_t send_buffered_frames;
		/* frames held in the session unacked list (spec §6.7.2) */
		size_t unacked_frames;
#endif
	};

	/* Traffic byte counters for closed tunnels; accumulated on the server
	 * thread in handle_closed().  Active tunnel traffic is summed at
	 * snapshot time in server_stats() via tunnel_stats(). */
	struct {
		uintmax_t traffic_byt_mux_recv;
		uintmax_t traffic_byt_mux_sent;
	};
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
	/* --- stream counters (aggregated from tunnel_stats[] at snapshot time) --- */
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

	/* --- stats route snapshot (mirrors the runtime diagnostic fields
	 * and per-identity tunnel_stats) --- */
	/* number of latency samples in the ring (capped at 256); 0 = no data */
	size_t stream_establish_count;
	/* SYN->SYN|ACK latency percentiles (ns); valid when count > 0 */
	intmax_t stream_establish_p50;
	intmax_t stream_establish_p90;
	intmax_t stream_establish_p99;
	intmax_t stream_establish_pmax;

	/* borrowed pointer into struct server; valid until free(server_stats(s)) */
	const struct evlog *evlog;

	/* number of entries in tunnels[] (mux_tunnel + identity pool members
	 * + accepted tunnels not wired into any identity pool) */
	size_t num_tunnels;
	/* one entry per active tunnel; peer_identity is NULL for mux_tunnel */
	struct tunnel_stats tunnels[];
};

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
};

struct server {
	struct ev_loop *loop;
	struct config *conf;
	/* path to the config file, used for SIGHUP reload */
	const char *conf_path;
#if WITH_ALLOC_CACHE
#if WITH_THREADS
	/* Server-level frame allocator shared across all tunnel threads. */
	struct mpmc_queue *frame_pool;
#else
	/* Server-level frame allocator (single-threaded). */
	struct mcache *frame_pool;
#endif
#endif /* WITH_ALLOC_CACHE */
#if WITH_TLS
	/* TLS context for accepted mux connections (server role). */
	struct tls_context *server_tlsctx;
	/* TLS context for initiated mux connections (client role). */
	struct tls_context *client_tlsctx;
#endif

	struct listener mux_listener;
	struct listener local_listener;
	struct listener api_listener;

	/* Per-identity listeners keyed by peer_identity string.
	 * Each value is a heap-allocated struct identity_listener *. */
	struct hashtable *identities;

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
	/* Maintenance timer: runs every second for frame-pool release, system
	 * suspend detection, and (when shutting_down) the 2 s force-exit deadline. */
	ev_timer w_maintenance;
	/* Set by signal_cb on SIGINT/SIGTERM; suppresses non-shutdown tasks in
	 * maintenance_cb and gates the early-exit check in handle_closed. */
	bool shutting_down;
	/* Monotonic timestamp (ns) when shutdown was initiated; used by
	 * maintenance_cb to enforce the 2 s force-exit deadline. */
	intmax_t shutdown_start_ns;
	/* Wall-clock timestamp of the previous maintenance tick; used to detect
	 * large time jumps (system suspend/resume) for transport reconnection. */
	time_t last_maintenance_wall;
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

	/* stats route: server-thread-only diagnostics; read via server_stats() */
	struct evlog evlog; /* session event ring buffer */

	/* Rate tracking state for POST /stats bandwidth display */
	struct {
		uintmax_t byt_mux_recv, byt_mux_sent;
		intmax_t timestamp;
		bool is_set;
	} rate_tracker;
};

/**
 * @brief Apply a pre-parsed configuration to a running server (hot-reload).
 *
 * Takes ownership of new_conf. On success new_conf becomes s->conf and the
 * function returns true. On failure (e.g., TLS setup error) new_conf is freed,
 * the server retains its current configuration, and the function returns false.
 *
 * @param s The running server.
 * @param new_conf Validated configuration to apply.
 * @return true on success, false on failure.
 */
bool server_apply_config(struct server *restrict s, struct config *new_conf);

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
 * @brief Allocate and return a consistent snapshot of all server statistics.
 * @param s The server to inspect.
 * @return Heap-allocated snapshot; caller must free(). NULL on OOM (logged).
 */
struct server_stats *server_stats(const struct server *restrict s);

#endif /* SERVER_H */
