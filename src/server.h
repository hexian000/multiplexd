/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file server.h
 * @brief Server lifecycle management and statistics snapshots.
 */

#ifndef SERVER_H
#define SERVER_H

#include "listener.h"
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
#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct api_ctx;
struct config;
struct hashtable;
struct tls_context;

/* Single event log entry for the session event ring buffer. */
struct server_evlog_entry {
	/* wall-clock time of the most recent occurrence */
	time_t timestamp;
	/* consecutive occurrence count */
	size_t count;
	char message[256];
};

/* Session event ring buffer; owned by the server thread. */
struct server_evlog {
	struct server_evlog_entry entries[16];
	/* valid entries */
	size_t len;
	/* next write position */
	size_t pos;
};

/* server_stats() has two routes: counters (relaxed-atomic per-session
 * COUNTER_* fields) and stats (per-tunnel diagnostics via tunnel_stats(),
 * published under pub_mtx or written to relaxed-atomic mirrors). */

/* Counters and gauges embedded in struct server (counters route).
 * uint_least64_t fields are monotonic Prometheus counters (wrap to 0). */
struct server_counters {
	/* listener counters — updated on the server thread only */
	struct {
		/* accepted connections from mux_listener */
		uint_least64_t num_accepted;
		/* served connections from mux_listener (reached num_halfopen++) */
		uint_least64_t num_served;
		/* accepted/served connections from tcp_listener */
		uint_least64_t num_accepted_tcp;
		uint_least64_t num_served_tcp;
		/* accepted/served connections from api_listener */
		uint_least64_t num_accepted_api;
		uint_least64_t num_served_api;
		/* mux connections dropped by startup_limit */
		uint_least64_t num_rejected;
#if WITH_TLS
		/* TLS accept failures (server mode) */
		uint_least64_t num_tls_failures;
#endif
	};

	/* session lifecycle counters (monotonic) and gauges */
	struct {
#if WITH_THREADS
		atomic_uint_least64_t num_session_created;
		atomic_uint_least64_t num_session_connect;
		atomic_uint_least64_t num_session_connected;
		atomic_uint_least64_t num_session_disconnected;
		atomic_uint_least64_t num_session_finalized;
		/* sessions currently in ESTABLISHED state */
		atomic_size_t num_sessions;
		/* sessions currently in CONNECT or HANDSHAKE state */
		atomic_size_t num_session_halfopen;
#else /* WITH_THREADS */
		uint_least64_t num_session_created;
		uint_least64_t num_session_connect;
		uint_least64_t num_session_connected;
		uint_least64_t num_session_disconnected;
		uint_least64_t num_session_finalized;
		/* sessions currently in ESTABLISHED state */
		size_t num_sessions;
		/* sessions currently in CONNECT or HANDSHAKE state */
		size_t num_session_halfopen;
#endif /* WITH_THREADS */
	};

	/* Monotonic per-tunnel counters accumulated from closed tunnels
	 * (server_close_and_fold); live tunnels are summed at snapshot time
	 * via tunnel_stats().  Server-thread only, so plain.  The per-tunnel
	 * gauges have no base here: they drain to zero as a session tears down,
	 * so summing live tunnels is already exact. */
	struct {
		uint_least64_t num_stream_opened;
		uint_least64_t num_stream_accepted;
		uint_least64_t num_stream_fastopen;
		uint_least64_t num_stream_established;
		uint_least64_t num_stream_succeeded;
		uint_least64_t num_stream_failed;
		/* client-mode reconnect attempts */
		uint_least64_t num_reconnects;
		uint_least64_t num_rst_sent;
		uint_least64_t num_rst_recv;
		/* stream_abort() calls */
		uint_least64_t num_stream_errors;
		/* establishment-latency observations, i.e. the monotonic
		 * tunnel_stats::stream_establish_count write index */
		uint_least64_t num_stream_establish_samples;
		uint_least64_t traffic_byt_mux_recv;
		uint_least64_t traffic_byt_mux_sent;
		uint_least64_t traffic_byt_push_recv;
		uint_least64_t traffic_byt_push_sent;
	} closed;
};

/* Snapshot of server statistics; plain (non-atomic) fields, safe to read
 * unsynchronized after server_stats() returns. */
struct server_stats {
	/* --- counters route snapshot (mirrors struct server_counters) --- */
	uint_least64_t num_accepted;
	uint_least64_t num_served;
	uint_least64_t num_accepted_tcp;
	uint_least64_t num_served_tcp;
	uint_least64_t num_accepted_api;
	uint_least64_t num_served_api;
	uint_least64_t num_session_created;
	uint_least64_t num_session_connect;
	uint_least64_t num_session_connected;
	uint_least64_t num_session_disconnected;
	uint_least64_t num_session_finalized;
	size_t num_sessions;
	size_t num_session_halfopen;
	/* --- stream counters (aggregated from tunnel_stats[] at snapshot time) --- */
	size_t num_streams;
	size_t num_stream_halfopen;
	uint_least64_t num_stream_opened;
	uint_least64_t num_stream_accepted;
	uint_least64_t num_stream_fastopen;
	uint_least64_t num_stream_established;
	uint_least64_t num_stream_succeeded;
	uint_least64_t num_stream_failed;
	uint_least64_t num_rejected;
#if WITH_TLS
	uint_least64_t num_tls_failures;
#endif
	uint_least64_t num_reconnects;
	uint_least64_t num_rst_sent;
	uint_least64_t num_rst_recv;
	uint_least64_t num_stream_errors;
	size_t recv_buffered_bytes;
	size_t send_buffered_frames;
	size_t unacked_frames;
	uint_least64_t traffic_byt_mux_recv;
	uint_least64_t traffic_byt_mux_sent;
	uint_least64_t traffic_byt_push_recv;
	uint_least64_t traffic_byt_push_sent;
	/* Monotonic count of establishment-latency observations over every
	 * tunnel, live and closed.  This is how many samples the percentiles
	 * below summarize over the process's life, unlike the windowed
	 * stream_establish_count; only active opens are observed, so it tracks
	 * neither num_stream_established nor num_stream_opened. */
	uint_least64_t num_stream_establish_samples;

	/* --- stats route snapshot --- */
	/* merged sample count across all tunnels (<=256 per tunnel, so up to
	 * 256*num_tunnels); 0 = no data.  A window occupancy, not a total: it
	 * drops as tunnels close, so never expose it as a Prometheus _count. */
	size_t stream_establish_count;
	/* SYN->SYN|ACK latency percentiles (ns); valid when count > 0 */
	int_least64_t stream_establish_p50;
	int_least64_t stream_establish_p90;
	int_least64_t stream_establish_p99;
	int_least64_t stream_establish_pmax;

	/* borrowed pointer into struct server; valid until free(server_stats(s)) */
	const struct server_evlog *evlog;

	/* number of entries in tunnels[] */
	size_t num_tunnels;
	/* one entry per active tunnel; peer_identity is NULL for mux_tunnel */
	struct tunnel_stats tunnels[];
};

/* Per-identity listener and the pool of mux sessions serving it. */
struct identity_listener {
	struct listener listener;
	/* Peer identity expected in hellos — not owned. */
	const char *peer_identity;
	/* Active tunnels for this identity; owned, all non-NULL. */
	struct tunnel **tunnels;
	size_t num_tunnels;
	/* Allocated capacity of tunnels[]; always a power of two. */
	size_t cap_tunnels;
	/* Round-robin dispatch cursor into tunnels[]. */
	size_t rr_next;
};

struct server {
	struct ev_loop *loop;
	struct config *conf;
	/* path to the config file, used for SIGHUP reload */
	const char *conf_path;
	/* Explicit --loglevel from the CLI, or -1 when not given. When set it
	 * overrides the config's loglevel on every SIGHUP reload
	 * (server_apply_config), mirroring main()'s boot-path choice so a reload
	 * cannot silently revert the operator's override. */
	int loglevel_override;
#if WITH_TLS
	/* TLS context for accepted mux connections (server role). */
	struct tls_context *server_tlsctx;
	/* Decoded tls.psk table; NULL in certificate mode.  Backs the TLS
	 * lookup callback and the tunnel layer's label -> identity mapping. */
	struct psk_table *psk;
	/* TLS context for initiated mux connections (client role). */
	struct tls_context *client_tlsctx;
#endif

	struct listener mux_listener;
	struct listener local_listener;
	struct listener api_listener;
	/* Head of the live api_listener connections, an intrusive list owned by
	 * api_server.c and swept by api_server_stop(). */
	struct api_ctx *api_conns;

	/* Per-identity listeners keyed by peer_identity string.
	 * Each value is a heap-allocated struct identity_listener *. */
	struct hashtable *identities;

	/* accepted_tunnels maps accepted session_id to tunnel pointer */
	struct hashtable *accepted_tunnels;
	/* Round-robin cursor into accepted_tunnels for tcp_serve()'s no-identity,
	 * no-mux_tunnel fallback; an opaque table_next() cursor, not an index
	 * (mirrors identity_listener.rr_next's role for the identity case). */
	size_t accepted_rr_cursor;
	/* Single dialed session for the top-level mux_connect entry, or NULL. */
	struct tunnel *mux_tunnel;
	/* identity_tunnels contains the dialed tunnels ptr */
	struct tunnel **identity_tunnels;
	size_t num_identity_tunnels;
	/* monotonically-increasing index */
	uint_least64_t next_tunnel_index;

	int_least64_t started;

	ev_signal w_sighup;
	ev_signal w_sigint;
	ev_signal w_sigterm;
	/* Maintenance timer: runs every second for system suspend detection,
	 * re-dialing drained identity slots, and (when shutting_down) the 2 s
	 * force-exit deadline. */
	ev_timer w_maintenance;
	/* Set by signal_cb on SIGINT/SIGTERM; suppresses non-shutdown tasks in
	 * maintenance_cb and gates the early-exit check in handle_closed. */
	bool shutting_down;
	/* Monotonic timestamp (ns) when shutdown was initiated; used by
	 * maintenance_cb to enforce the 2 s force-exit deadline. */
	int_least64_t shutdown_start_ns;
	/* Wall-clock timestamp of the previous maintenance tick; used to detect
	 * large time jumps (system suspend/resume) for transport reconnection. */
	time_t last_maintenance_wall;
	/* Cross-thread relay: ev_async + dispatcher for session threads. */
#if WITH_THREADS
	ev_async w_async;
	struct dispatcher *disp;
	/* Shared mutex protecting accepted_tunnels; exclusive on the server thread
	 * for add/remove, shared on worker threads for lookups. */
	smtx_t accepted_mu;
#endif

	struct server_counters counters;

	/* stats route: server-thread-only diagnostics; read via server_stats() */
	struct server_evlog evlog;

	/* Rate tracking state for POST /stats bandwidth display */
	struct {
		uint_least64_t byt_mux_recv, byt_mux_sent;
		uint_least64_t byt_push_recv, byt_push_sent;
		int_least64_t timestamp;
		bool is_set;
	} rate_tracker;
};

/* Apply a pre-parsed configuration to a running server (hot-reload); takes
 * ownership of @p new_conf. On success it becomes s->conf; on failure it is
 * freed, the server keeps its current config, and this returns false. */
bool server_apply_config(struct server *restrict s, struct config *new_conf);

/* Allocate and initialize a server; @p conf becomes s->conf on success but the
 * caller retains ownership of it. NULL on allocation/setup failure, in which
 * case conf is likewise left for the caller to free. Note that a later
 * server_apply_config() reload frees the config passed here and installs a new
 * one, so the caller must free the current s->conf, not the pointer it passed. */
struct server *server_new(struct ev_loop *loop, struct config *conf);

/* Start listeners, background workers, and outbound sessions; false on failure. */
bool server_start(struct server *s);

/* Stop listeners, drop any connection the management API still holds, and
 * initiate shutdown of active sessions. */
void server_stop(struct server *s);

/* Free a stopped server and all owned resources; NULL is allowed. Releases the
 * async watcher server_new() armed, so the ev_loop must outlive this call and a
 * server that never had a config applied needs no server_stop() first. Once
 * server_apply_config() has run, tunnels exist and are started even if
 * server_start() never was, and only server_stop() tears them down: freeing
 * without it leaves live tunnel threads posting into a destroyed dispatcher.
 * Does not free s->conf --
 * the caller owns the config (see server_new) and must free it separately, using
 * the current s->conf since a reload may have replaced it. */
void server_free(struct server *s);

/* Allocate a consistent snapshot of all server statistics (caller frees);
 * NULL on OOM (logged).
 *
 * @p want_tunnel_latency additionally derives each tunnel's own
 * stream_establish_p50/p90/p99 from its latency ring, which sorts up to
 * TUNNEL_ESTABLISH_RING_SIZE samples per tunnel on the server thread.  Only GET
 * /metrics exposes those per-tunnel percentiles; every other caller passes
 * false and leaves the fields zero.  The merged process-wide percentiles are
 * always derived -- /stats reports them too. */
struct server_stats *
server_stats(const struct server *restrict s, bool want_tunnel_latency);

/* Report forwarding listeners that currently have no established tunnel to
 * forward over (e.g. the peer is unreachable).  For each such listener @p cb is
 * invoked with its identifier: the peer identity for identity listeners, or the
 * configured local listen address for the top-level listener.  Returns the
 * number of offline listeners (0 means healthy); @p cb may be NULL to only
 * count.  On-demand mode (mux.idle_timeout > 0) always reports healthy, since
 * tunnels disconnect when idle by design.  Must run on the server loop; per
 * tunnel liveness is read from the relaxed-atomic mirror via tunnel_state(). */
size_t server_offline_listeners(
	const struct server *restrict s,
	void (*cb)(void *data, const char *identifier), void *data);

#if WITH_TLS
/* One decoded tls.psk entry: the peer identity it belongs to, the key itself,
 * and the wire label derived from that key.  The label is what a peer offers
 * in its ClientHello; mapping it back to the identity is what lets the tunnel
 * layer check a claimed identity against the one that actually authenticated. */
struct psk_table_entry {
	char identity[MUX_MAX_CLAIM_LEN + 1];
	char label[TLS_PSK_LABEL_MAX + 1];
	unsigned char key[TLS_PSK_MAX_LEN];
	size_t key_len;
};

/* Built once at startup and owned by the server; outlives the TLS contexts,
 * whose lookup callback reads it during every handshake. */
struct psk_table {
	size_t count;
	struct psk_table_entry entries[];
};

/* Decode conf->tls_psk and derive each label; NULL when none are configured
 * or on failure (which is logged). */
struct psk_table *server_psk_table_new(const struct config *restrict conf);
void server_psk_table_free(struct psk_table *restrict t);

/* The peer identity owning @p label, or NULL when no entry matches.  The
 * caller has an authenticated label from tls_peer_psk_label(), so a non-NULL
 * result names the peer that proved possession of that key. */
const char *server_psk_identity_of(
	const struct psk_table *restrict t, const char *restrict label);
#endif /* WITH_TLS */

#endif /* SERVER_H */
