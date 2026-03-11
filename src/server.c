/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "api_server.h"
#include "conf.h"
#include "listener.h"
#include "mux/mux.h"
#include "tlsutil.h"
#include "tunnel.h"
#include "util.h"

#include "algo/hashtable.h"
#include "math/rand.h"
#include "os/clock.h"
#include "os/daemon.h"
#include "os/signal.h"
#include "os/socket.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/queue.h"
#include "sync/shared_mutex.h"
#else
#include "utils/mcache.h"
#endif
#include "utils/arraysize.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <ev.h>
#include <sys/socket.h>

#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SESSIONID_KEY(id_ptr)                                                  \
	((struct hashkey){ .len = MUX_SESSION_ID_LEN, .data = (id_ptr) })

#define IDENTITY_KEY(id_str)                                                   \
	((struct hashkey){ .len = strlen(id_str), .data = (id_str) })

/* Iterator over all tunnel objects owned by a server.
 * Yields mux_tunnel first, then each identities[i].tunnels[j] in order,
 * then each identity_tunnels[i] (skipping NULLs), then all
 * accepted_sessions in table order.
 * Zero-initialize before first call; returns NULL when done. */
struct tunnel_iter {
	/* 0 = dialed (mux_tunnel + identities + identity_tunnels),
	 * 1 = accepted_sessions */
	size_t phase;
	/* phase 0: 0           → mux_tunnel
	 *           1..ns       → identities[sub-1].tunnels[sub2]
	 *           ns+1..ns+ni → identity_tunnels[sub-ns-1]
	 * phase 1: opaque table_next cursor */
	size_t sub;
	/* inner cursor: index within identities[sub-1].tunnels[] */
	size_t sub2;
};

/* Add tunnel t to service listener sl's pool.
 * Returns false on OOM (already logged); caller may continue. */
static bool identity_listener_add(
	struct identity_listener *restrict sl, struct tunnel *restrict t)
{
	struct tunnel **arr =
		realloc(sl->tunnels, (sl->num_tunnels + 1) * sizeof(*arr));
	if (arr == NULL) {
		LOGOOM();
		return false;
	}
	arr[sl->num_tunnels++] = t;
	sl->tunnels = arr;
	return true;
}

/* Remove tunnel t from service listener sl's pool (swap-remove).
 * Returns true if the tunnel was found and removed. */
static bool identity_listener_remove(
	struct identity_listener *restrict sl, struct tunnel *restrict t)
{
	for (size_t i = 0; i < sl->num_tunnels; i++) {
		if (sl->tunnels[i] != t) {
			continue;
		}
		sl->tunnels[i] = sl->tunnels[--sl->num_tunnels];
		if (sl->rr_next >= sl->num_tunnels) {
			sl->rr_next = 0;
		}
		return true;
	}
	return false;
}

/* Pick the next tunnel from sl's pool using round-robin.
 * Returns NULL when the pool is empty. */
static struct tunnel *
identity_listener_pick(struct identity_listener *restrict sl)
{
	if (sl->num_tunnels == 0) {
		return NULL;
	}
	if (sl->rr_next >= sl->num_tunnels) {
		sl->rr_next = 0;
	}
	struct tunnel *t = sl->tunnels[sl->rr_next];
	sl->rr_next = (sl->rr_next + 1) % sl->num_tunnels;
	return t;
}

static struct tunnel *tunnel_iter_next(
	const struct server *restrict s, struct tunnel_iter *restrict it)
{
	if (it->phase == 0) {
		/* mux_tunnel slot */
		if (it->sub == 0) {
			it->sub = 1;
			if (s->mux_tunnel != NULL) {
				return s->mux_tunnel;
			}
		}
		/* identities slots: iterate over the pool for each identity */
		while (it->sub <= s->num_identities) {
			const struct identity_listener *const sl =
				&s->identities[it->sub - 1];
			if (it->sub2 < sl->num_tunnels) {
				return sl->tunnels[it->sub2++];
			}
			it->sub2 = 0;
			it->sub++;
		}
		/* identity_tunnels slots */
		const size_t base = s->num_identities + 1;
		while (it->sub < base + s->num_identity_tunnels) {
			struct tunnel *t = s->identity_tunnels[it->sub - base];
			it->sub++;
			if (t != NULL) {
				return t;
			}
		}
		it->phase = 1;
		it->sub = 0;
	}
	/* accepted_sessions */
	void *elem = NULL;
	if (!table_next(s->accepted_tunnels, &it->sub, NULL, &elem)) {
		return NULL;
	}
	return elem;
}

/* Log session establishment/close with peer address formatting */
#define SESSION_EVLOGF(srv, t, fmt, ...)                                       \
	do {                                                                   \
		const char *id_ = tunnel_peer_identity(t);                     \
		if (id_ == NULL) {                                             \
			id_ = tunnel_peer_id(t);                               \
		}                                                              \
		if (id_ != NULL) {                                             \
			server_evlogf((srv), "`%s' " fmt, id_, __VA_ARGS__);   \
			break;                                                 \
		}                                                              \
		const struct sockaddr *const peer_ = tunnel_peer_addr(t);      \
		if (peer_ != NULL) {                                           \
			char addr_str[72];                                     \
			(void)sa_format(addr_str, sizeof(addr_str), peer_);    \
			server_evlogf(                                         \
				(srv), "%s " fmt, addr_str, __VA_ARGS__);      \
			break;                                                 \
		}                                                              \
		server_evlogf(                                                 \
			(srv), "[fd:%d] " fmt, tunnel_fd(t), __VA_ARGS__);     \
	} while (0)
#define SESSION_EVLOG(srv, t, message) SESSION_EVLOGF(srv, t, "%s", message)

static void
server_evlogf(struct server *restrict srv, const char *restrict fmt, ...)
{
	struct server_runtime_stats *restrict stats = &srv->runtime;
	const size_t evlog_size = ARRAY_SIZE(stats->eventlog);
	const time_t now = time(NULL);
	/* Format directly into the candidate slot. */
	struct evlog_entry *restrict entry =
		&stats->eventlog[stats->eventlog_pos];
	va_list ap;
	va_start(ap, fmt);
	if (vsnprintf(entry->message, sizeof(entry->message), fmt, ap) < 0) {
		entry->message[0] = '\0';
	}
	va_end(ap);
	/* Merge into the previous entry if the message is identical. */
	if (stats->eventlog_len > 0) {
		const size_t prev =
			(stats->eventlog_pos + evlog_size - 1) % evlog_size;
		struct evlog_entry *restrict last = &stats->eventlog[prev];
		if (strncmp(last->message, entry->message,
			    sizeof(last->message)) == 0) {
			last->timestamp = now;
			last->count++;
			return;
		}
	}
	entry->timestamp = now;
	entry->count = 1;
	stats->eventlog_pos = (stats->eventlog_pos + 1) % evlog_size;
	if (stats->eventlog_len < evlog_size) {
		stats->eventlog_len++;
	}
}

static void session_on_connected(
	struct server *restrict srv, struct tunnel *t,
	const char *restrict verb, intmax_t lat_ns)
{
	char lat_str[16];
	(void)format_duration(
		lat_str, sizeof(lat_str), make_duration_nanos(lat_ns));
	SESSION_EVLOGF(srv, t, "session %s (setup: %s)", verb, lat_str);
}

static void handle_connected(
	struct server *restrict srv, struct tunnel *restrict t, intmax_t lat_ns)
{
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session established", tunnel_fd(t),
	       is_server ? "server" : "client");
	session_on_connected(srv, t, "established", lat_ns);
	if (!is_server) {
		/* Clear the identity_tunnels staging slot (set during server_start
		 * before the handshake completed) so tunnel_iter does not count
		 * the session twice (via identities and identity_tunnels). */
		for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
			if (srv->identity_tunnels[i] == t) {
				srv->identity_tunnels[i] = NULL;
				break;
			}
		}
		/* Wire the dialed session into the matching identity pool. */
		const char *const peer_id = tunnel_peer_identity(t);
		if (peer_id != NULL) {
			for (size_t i = 0; i < srv->num_identities; i++) {
				if (srv->identities[i].peer_identity != NULL &&
				    strcmp(srv->identities[i].peer_identity,
					   peer_id) == 0) {
					(void)identity_listener_add(
						&srv->identities[i], t);
					break;
				}
			}
		}
		return;
	}
	const char *const peer_identity = tunnel_peer_identity(t);
	if (peer_identity != NULL) {
		for (size_t i = 0; i < srv->num_identities; i++) {
			if (srv->identities[i].peer_identity != NULL &&
			    strcmp(srv->identities[i].peer_identity,
				   peer_identity) == 0) {
				(void)identity_listener_add(
					&srv->identities[i], t);
				break;
			}
		}
	}
}

static void handle_resumed(
	struct server *restrict srv, struct tunnel *restrict t, intmax_t lat_ns)
{
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session resumed", tunnel_fd(t),
	       is_server ? "server" : "client");
	session_on_connected(srv, t, "resumed", lat_ns);
}

static void
handle_disconnected(struct server *restrict srv, struct tunnel *restrict t)
{
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session disconnected", tunnel_fd(t),
	       is_server ? "server" : "client");
	SESSION_EVLOG(srv, t, "session disconnected");
}

static void
handle_stream_established(struct server *restrict srv, intmax_t lat_ns)
{
	const size_t idx = srv->runtime.stream_establish_count %
			   ARRAY_SIZE(srv->runtime.stream_establish_ns);
	srv->runtime.stream_establish_ns[idx] = lat_ns;
	srv->runtime.stream_establish_count++;
}

static void handle_closed(
	struct server *restrict srv, struct tunnel *restrict t,
	const union mux_event_data edata)
{
	LOGN_F("[fd:%d] session closed", tunnel_fd(t));
	if (edata.closed.expired) {
		SESSION_EVLOG(srv, t, "suspended session expired");
	}

	if (tunnel_is_accepted(t)) {
#if WITH_THREADS
		THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
		srv->accepted_tunnels = table_del(
			srv->accepted_tunnels,
			SESSIONID_KEY(tunnel_session_id(t)), NULL);
#if WITH_THREADS
		THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
	} else if (t == srv->mux_tunnel) {
		srv->mux_tunnel = NULL;
	}
	for (size_t i = 0; i < srv->num_identities; i++) {
		if (identity_listener_remove(&srv->identities[i], t)) {
			break;
		}
	}
	for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
		if (srv->identity_tunnels[i] == t) {
			srv->identity_tunnels[i] = NULL;
			break;
		}
	}

	/* Join the tunnel thread; the relay stopped it before dispatching
	 * this event, so ev_run() has already returned by now. */
	tunnel_close(t);

	/* During graceful shutdown, exit the event loop once all sessions
	 * have finished their close handshake.
	 * All accepted sessions gone and no dialed sessions remaining. */
	if (ev_is_active(&srv->w_shutdown) &&
	    table_size(srv->accepted_tunnels) == 0 && srv->mux_tunnel == NULL) {
		bool any_peer = false;
		for (size_t i = 0; i < srv->num_identities; i++) {
			if (srv->identities[i].num_tunnels > 0) {
				any_peer = true;
				break;
			}
		}
		if (!any_peer) {
			ev_timer_stop(srv->loop, &srv->w_shutdown);
			ev_break(srv->loop, EVBREAK_ALL);
		}
	}
}

static void tunnel_on_event(
	void *data, struct tunnel *t, enum mux_event event,
	union mux_event_data edata)
{
	struct server *restrict srv = data;
	switch (event) {
	case MUX_EVENT_CONNECT:
		break;
	case MUX_EVENT_ESTABLISHED:
		handle_connected(srv, t, edata.connected.ns);
		break;
	case MUX_EVENT_CONNECT_FAILED:
		break;
	case MUX_EVENT_SUSPENDED:
		/* Handled by the tunnel layer; no server-level action needed. */
		break;
	case MUX_EVENT_RESUMED:
		handle_resumed(srv, t, edata.connected.ns);
		break;
	case MUX_EVENT_LOST:
		handle_disconnected(srv, t);
		break;
	case MUX_EVENT_STREAM_ESTABLISHED:
		handle_stream_established(srv, edata.stream_established.ns);
		break;
	case MUX_EVENT_CLOSED:
		handle_closed(srv, t, edata);
		break;
	}
}

/* Locate a suspended (or still-established) session matching the client's
 * session_id.  Called during session resumption handshake (spec §6.8).
 * Acquires accepted_mu for the duration of the table lookup. */
static struct mux_session *tunnel_on_resume(
	void *data, struct tunnel *new_t, const unsigned char *session_id)
{
	UNUSED(new_t);
	struct server *restrict srv = data;

#if WITH_THREADS
	THRD_ASSERT(smtx_sharedlock(&srv->accepted_mu));
#endif
	void *elem = NULL;
	struct tunnel *candidate = NULL;
	if (table_find(
		    srv->accepted_tunnels, SESSIONID_KEY(session_id), &elem)) {
		candidate = elem;
		const enum mux_state st = tunnel_state(candidate);
		if (st != MUX_STATE_SUSPENDED && st != MUX_STATE_ESTABLISHED) {
			candidate = NULL;
		} else if (!tunnel_is_accepted(candidate)) {
			/* Never resume a client-mode session: only server-mode
			 * sessions maintain stable address state. */
			candidate = NULL;
		} else if (st == MUX_STATE_ESTABLISHED) {
			LOGW_F("[fd:%d] resume matched ESTABLISHED session,"
			       " suspending old transport",
			       tunnel_fd(candidate));
		}
	}
#if WITH_THREADS
	THRD_ASSERT(smtx_sharedunlock(&srv->accepted_mu));
#endif
	return candidate != NULL ? tunnel_session(candidate) : NULL;
}

static void identity_tcp_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	UNUSED(loop);
	UNUSED(sa);
	struct identity_listener *restrict sl = DOWNCAST(
		struct listener, struct identity_listener, listener, l);
	struct tunnel *restrict t = identity_listener_pick(sl);
	if (t == NULL) {
		LOGD_F("[fd:%d] no session for identity \"%s\","
		       " closing",
		       fd, sl->peer_identity);
		CLOSE_FD(fd);
		return;
	}
	/* Dispatch mux_open_stream to the session's tunnel thread. */
	l->srv->counters.num_served_tcp++;
	tunnel_open_stream(t, fd);
}

static void tcp_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	UNUSED(loop);
	UNUSED(sa);
	struct server *restrict srv = l->srv;
	struct tunnel *restrict t = srv->mux_tunnel;
	if (t == NULL && srv->accepted_tunnels != NULL) {
		size_t cursor = 0;
		void *elem;
		if (table_next(srv->accepted_tunnels, &cursor, NULL, &elem)) {
			t = elem;
		}
	}
	if (t == NULL) {
		LOGD_F("[fd:%d] no active session, closing", fd);
		CLOSE_FD(fd);
		return;
	}

	/* Dispatch mux_open_stream to the session's tunnel thread. */
	srv->counters.num_served_tcp++;
	tunnel_open_stream(t, fd);
}

static bool is_startup_limited(const struct server *restrict srv)
{
	const struct config *restrict conf = srv->conf;
	const struct server_counters *restrict stats = &srv->counters;
#if WITH_THREADS
	const size_t n_sessions = atomic_load_explicit(
		&stats->num_sessions, memory_order_relaxed);
	const size_t n_halfopen = atomic_load_explicit(
		&stats->num_session_halfopen, memory_order_relaxed);
#else
	const size_t n_sessions = stats->num_sessions;
	const size_t n_halfopen = stats->num_session_halfopen;
#endif

	/* Check maximum session limit */
	if (conf->max_sessions > 0 && n_sessions > (size_t)conf->max_sessions) {
		LOGVV("session limit exceeded, rejecting new connection");
		return true;
	}

	/* Check full startup limit */
	if (conf->startup_limit_full > 0 &&
	    n_halfopen > (size_t)conf->startup_limit_full) {
		LOGVV("full startup limit exceeded, rejecting new connection");
		return true;
	}

	/* Check probabilistic startup limit */
	if (conf->startup_limit_start > 0 &&
	    n_halfopen > (size_t)conf->startup_limit_start) {
		if (frand() * 100.0 < conf->startup_limit_rate) {
			LOGVV("startup limit reached, rejecting new connection");
			return true;
		}
	}
	return false;
}

/* Maximum frames held in the server-level pool.
 * 128 × 16 KiB ≈ 2 MiB total pool budget. */
#define FRAME_POOL_CAPACITY 128

static struct mux_frame *server_frame_alloc(void *data)
{
#if WITH_THREADS
	struct mux_frame *frame = mqueue_pop(data);
	if (frame != NULL) {
		return frame;
	}
	return malloc(mux_frame_object_size());
#else
	return mcache_get(data);
#endif
}

static void server_frame_free(void *data, struct mux_frame *frame)
{
#if WITH_THREADS
	if (!mqueue_push(data, frame)) {
		free(frame);
	}
#else
	mcache_put(data, frame);
#endif
}

static struct mux_config server_make_mux_config(struct server *restrict srv)
{
	return srv->conf->mux;
}

static void proto_session_id_new(unsigned char *const id)
{
	write_uint64(id, rand64());
	write_uint64(id + sizeof(uint64_t), rand64());
}

static void
server_new_session_id(const struct server *restrict s, unsigned char *sid)
{
	do {
		proto_session_id_new(sid);
	} while (table_find(s->accepted_tunnels, SESSIONID_KEY(sid), NULL));
}

static bool server_register_session(struct server *restrict s, struct tunnel *t)
{
	void *elem = t;
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	s->accepted_tunnels = table_set(
		s->accepted_tunnels, SESSIONID_KEY(tunnel_session_id(t)),
		&elem);
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
	if (elem == t) {
		LOGOOM();
		tunnel_close(t);
		return false;
	}
	ASSERT(elem == NULL);
	return true;
}

static void mux_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	(void)loop;
	struct server *restrict srv = l->srv;
	if (LOGLEVEL(DEBUG)) {
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), sa);
#if WITH_THREADS
		const size_t n_sessions = atomic_load_explicit(
			&srv->counters.num_sessions, memory_order_relaxed);
		const size_t n_halfopen = atomic_load_explicit(
			&srv->counters.num_session_halfopen,
			memory_order_relaxed);
#else
		const size_t n_sessions = srv->counters.num_sessions;
		const size_t n_halfopen = srv->counters.num_session_halfopen;
#endif
		LOGD_F("accepting from: `%s'; established=%zu, halfopen=%zu",
		       addr_str, n_sessions, n_halfopen);
	}

	if (is_startup_limited(srv)) {
		srv->counters.num_rejected++;
		CLOSE_FD(fd);
		return;
	}

#if WITH_TLS
	struct tls_connection *conn = NULL;
	if (srv->server_tlsctx != NULL) {
		conn = tls_accept(srv->server_tlsctx, fd);
		if (conn == NULL) {
			LOGE_F("[fd:%d] TLS accept failed", fd);
			srv->counters.num_tls_failures++;
			CLOSE_FD(fd);
			return;
		}
	}
#endif

	struct mux_config mux_conf = server_make_mux_config(srv);
	const struct tunnel_callbacks callbacks = {
		.on_event = tunnel_on_event,
		.on_resume = tunnel_on_resume,
	};
	unsigned char sid[MUX_SESSION_ID_LEN];
	server_new_session_id(srv, sid);
	const struct tunnel_opts opts = {
		.cb = &callbacks,
		.data = srv,
		.mux_conf = &mux_conf,
		.pool = { server_frame_alloc, server_frame_free,
			  srv->frame_pool },
		.mux_socket = srv->conf->mux_socket,
		.local_socket = srv->conf->local_socket,
		.fd = fd,
		.id = sid,
		.connect_addr = NULL,
		.forward_addr = srv->conf->connect,
		.bind_addr = srv->conf->mux_listen,
		.identity = srv->conf->identity_claim,
		.peer_id = NULL,
#if WITH_TLS
		.tlsctx = NULL,
		.conn = conn,
#endif
	};

	struct tunnel *const t = tunnel_new(srv, &opts);
	if (t == NULL) {
		LOGE_F("[fd:%d] failed to create tunnel", fd);
#if WITH_TLS
		if (conn != NULL) {
			tls_conn_free(conn);
		}
#endif
		CLOSE_FD(fd);
		return;
	}

	if (!server_register_session(srv, t)) {
		return;
	}

	srv->counters.num_served++;
	/* mux_start() starts libev watchers on the tunnel's loop; dispatch
	 * to the tunnel thread. */
	tunnel_start(t);
	LOGI_F("[fd:%d] accepted mux connection", fd);
}

/* NULL-safe string equality: returns true iff both strings are identical
 * (including both NULL). */
static bool strnull_eq(const char *a, const char *b)
{
	if (a == NULL && b == NULL) {
		return true;
	}
	if (a == NULL || b == NULL) {
		return false;
	}
	return strcmp(a, b) == 0;
}

static const struct tunnel_callbacks client_callbacks = {
	.on_event = tunnel_on_event,
};

#if WITH_TLS
/* Build fresh server and client TLS contexts from new_conf.
 * On success, zeroes the sensitive credential strings and returns true.
 * On failure, frees any partially-created context and returns false;
 * the caller is responsible for freeing new_conf. */
static bool server_reload_make_tls(
	const struct config *restrict new_conf,
	struct tls_context **restrict out_server,
	struct tls_context **restrict out_client)
{
	*out_server = NULL;
	*out_client = NULL;
	if (new_conf->tls_cert == NULL || new_conf->tls_key == NULL) {
		return true;
	}
	if (new_conf->mux_listen != NULL) {
		*out_server = tls_ctx_server(
			new_conf->tls_cert, new_conf->tls_key,
			new_conf->authcerts, new_conf->authcerts_count,
			new_conf->tls_ciphersuites);
		if (*out_server == NULL) {
			LOGE("failed to create server TLS context"
			     " during reload");
			return false;
		}
	}
	if (new_conf->mux_connect != NULL ||
	    new_conf->identity_connect_count > 0) {
		*out_client = tls_ctx_client(
			new_conf->tls_cert, new_conf->tls_key,
			new_conf->authcerts, new_conf->authcerts_count,
			new_conf->tls_ciphersuites);
		if (*out_client == NULL) {
			LOGE("failed to create client TLS context"
			     " during reload");
			if (*out_server != NULL) {
				tls_ctx_free(*out_server);
				*out_server = NULL;
			}
			return false;
		}
	}
	memset(new_conf->tls_cert, 0, strlen(new_conf->tls_cert));
	memset(new_conf->tls_key, 0, strlen(new_conf->tls_key));
	for (size_t i = 0; i < new_conf->authcerts_count; i++) {
		memset(new_conf->authcerts[i], 0,
		       strlen(new_conf->authcerts[i]));
	}
	return true;
}
#endif /* WITH_TLS */

/* Single-pass reload: update addresses and apply drain config in one
 * per-tunnel dispatch.  Sessions drain as soon as their last stream closes;
 * outbound tunnels reconnect with the fresh config afterwards. */
static void server_drain_tunnels(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf
#if WITH_TLS
	,
	struct tls_context *new_client_tlsctx
#endif
)
{
	const bool forward_changed =
		!strnull_eq(old_conf->connect, new_conf->connect);
	struct mux_config drain_conf = new_conf->mux;
	drain_conf.reject_inbound = true;
#if WITH_TLS
	drain_conf.tlsctx = new_client_tlsctx;
#endif
	const size_t old_ni = s->num_identity_tunnels;
	const size_t new_ni = new_conf->identity_connect_count;
	struct tunnel_iter it = { 0 };
	struct tunnel *t;
	while ((t = tunnel_iter_next(s, &it)) != NULL) {
		struct tunnel_reload_opts opts = {
			.conf = drain_conf,
			.drain = true,
			.mux_socket = new_conf->mux_socket,
			.local_socket = new_conf->local_socket,
			.update_forward_addr = forward_changed,
			.forward_addr = new_conf->connect,
		};
		if (t == s->mux_tunnel) {
			if (!strnull_eq(
				    old_conf->mux_connect,
				    new_conf->mux_connect)) {
				if (new_conf->mux_connect != NULL) {
					opts.update_connect_addr = true;
					opts.connect_addr =
						new_conf->mux_connect;
				} else {
					opts.disable_reconnect = true;
				}
			}
		} else {
			for (size_t i = 0; i < old_ni; i++) {
				if (s->identity_tunnels[i] != t) {
					continue;
				}
				if (i >= new_ni) {
					/* Slot removed: prevent reconnect
					 * after drain. */
					opts.disable_reconnect = true;
				} else if (!strnull_eq(
						   old_conf->identity_connect[i],
						   new_conf->identity_connect
							   [i])) {
					opts.update_connect_addr = true;
					opts.connect_addr =
						new_conf->identity_connect[i];
				}
				break;
			}
		}
		tunnel_reload(t, &opts);
	}
}

/* Stop and restart tcp, mux, and api listeners whose bind addresses changed. */
static void server_reload_listeners(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf)
{
	struct ev_loop *const loop = s->loop;
	if (!strnull_eq(old_conf->listen, new_conf->listen)) {
		if (s->tcp_listener.w_accept.fd != -1) {
			listener_stop(&s->tcp_listener, loop);
		}
		if (new_conf->listen != NULL) {
			union sockaddr_max addr;
			bool ok = true;
			RESOLVE_BINDADDR(
				&addr, new_conf->listen, tcpbind, ok = false);
			if (!ok) {
				LOGE_F("failed to parse listen address"
				       " on reload: %s",
				       new_conf->listen);
			} else if (!listener_start(
					   &s->tcp_listener, loop, &addr.sa)) {
				LOGE_F("failed to restart TCP listener"
				       " on reload: %s",
				       new_conf->listen);
			} else if (LOGLEVEL(NOTICE)) {
				char str[64];
				sa_format(str, sizeof(str), &addr.sa);
				LOGN_F("listening on %s (TCP)", str);
			}
		}
	}
	if (!strnull_eq(old_conf->mux_listen, new_conf->mux_listen)) {
		if (s->mux_listener.w_accept.fd != -1) {
			listener_stop(&s->mux_listener, loop);
		}
		if (new_conf->mux_listen != NULL) {
			union sockaddr_max addr;
			bool ok = true;
			RESOLVE_BINDADDR(
				&addr, new_conf->mux_listen, tcpbind,
				ok = false);
			if (!ok) {
				LOGE_F("failed to parse mux_listen"
				       " address on reload: %s",
				       new_conf->mux_listen);
			} else if (!listener_start(
					   &s->mux_listener, loop, &addr.sa)) {
				LOGE_F("failed to restart mux listener"
				       " on reload: %s",
				       new_conf->mux_listen);
			} else if (LOGLEVEL(NOTICE)) {
				char str[64];
				sa_format(str, sizeof(str), &addr.sa);
				LOGN_F("mux listening on %s", str);
			}
		}
	}
	if (!strnull_eq(old_conf->api_listen, new_conf->api_listen)) {
		if (s->api_listener.w_accept.fd != -1) {
			listener_stop(&s->api_listener, loop);
		}
		if (new_conf->api_listen != NULL) {
			union sockaddr_max addr;
			bool ok = true;
			RESOLVE_BINDADDR(
				&addr, new_conf->api_listen, tcpbind,
				ok = false);
			if (!ok) {
				LOGE_F("failed to parse api_listen"
				       " address on reload: %s",
				       new_conf->api_listen);
			} else if (!listener_start(
					   &s->api_listener, loop, &addr.sa)) {
				LOGE_F("failed to restart API listener"
				       " on reload: %s",
				       new_conf->api_listen);
			} else if (LOGLEVEL(NOTICE)) {
				char str[64];
				sa_format(str, sizeof(str), &addr.sa);
				LOGN_F("API server listening on %s", str);
			}
		}
	}
}

/* Rebuild the identity_peers identity listener array if the peer table
 * changed; otherwise fix peer_identity and socket_opts pointers into the
 * new config. */
static void server_reload_identities(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf)
{
	const size_t old_np = old_conf->identity_peers_count;
	const size_t new_np = new_conf->identity_peers_count;
	bool peers_changed = (old_np != new_np);
	for (size_t i = 0; !peers_changed && i < new_np; i++) {
		if (!strnull_eq(
			    old_conf->identity_peers[i].id,
			    new_conf->identity_peers[i].id) ||
		    !strnull_eq(
			    old_conf->identity_peers[i].listen,
			    new_conf->identity_peers[i].listen)) {
			peers_changed = true;
		}
	}
	if (!peers_changed) {
		/* Same peer table: fix peer_identity pointers to point
		 * into new_conf instead of old_conf. */
		for (size_t i = 0; i < s->num_identities; i++) {
			s->identities[i].peer_identity =
				new_conf->identity_peers[i].id;
			s->identities[i].listener.socket_opts =
				&new_conf->local_socket;
		}
		return;
	}
	for (size_t i = 0; i < s->num_identities; i++) {
		struct listener *restrict l = &s->identities[i].listener;
		if (l->w_accept.fd != -1) {
			listener_stop(l, s->loop);
		}
	}
	struct identity_listener *new_svc = NULL;
	if (new_np > 0) {
		new_svc = malloc(new_np * sizeof(*new_svc));
		if (new_svc == NULL) {
			LOGOOM();
			return;
		}
	}
	for (size_t i = 0; i < new_np; i++) {
		const struct identity_peer *restrict p =
			&new_conf->identity_peers[i];
		struct identity_listener *restrict sl = &new_svc[i];
		sl->peer_identity = p->id;
		sl->tunnels = NULL;
		sl->num_tunnels = 0;
		sl->rr_next = 0;
		/* Migrate live tunnel pool if peer_identity matches an existing
		 * identity entry. */
		for (size_t j = 0; j < s->num_identities; j++) {
			if (s->identities[j].peer_identity != NULL &&
			    p->id != NULL &&
			    strcmp(s->identities[j].peer_identity, p->id) ==
				    0) {
				/* Transfer ownership of the pool array. */
				sl->tunnels = s->identities[j].tunnels;
				sl->num_tunnels = s->identities[j].num_tunnels;
				sl->rr_next = s->identities[j].rr_next;
				s->identities[j].tunnels = NULL;
				s->identities[j].num_tunnels = 0;
				break;
			}
		}
		listener_init(
			&sl->listener, &new_conf->local_socket,
			identity_tcp_serve, s, &s->counters.num_accepted_tcp);
		sl->listener.data = sl;
		if (p->listen != NULL) {
			union sockaddr_max addr;
			bool ok = true;
			RESOLVE_BINDADDR(&addr, p->listen, tcpbind, ok = false);
			if (!ok) {
				LOGE_F("failed to parse identity listen"
				       " address on reload: %s",
				       p->listen);
			} else if (!listener_start(
					   &sl->listener, s->loop, &addr.sa)) {
				LOGE_F("failed to restart identity listener for"
				       " \"%s\" on reload",
				       p->id);
			} else if (LOGLEVEL(NOTICE)) {
				char str[64];
				sa_format(str, sizeof(str), &addr.sa);
				LOGN_F("identity \"%s\" listening on %s (TCP)",
				       p->id, str);
			}
		}
	}
	/* Free any orphaned pool arrays not migrated to the new table. */
	for (size_t i = 0; i < s->num_identities; i++) {
		free(s->identities[i].tunnels);
	}
	free(s->identities);
	s->identities = new_svc;
	s->num_identities = new_np;
}

/* Create a new mux_connect tunnel if one is configured but not yet live. */
static void server_reload_mux_tunnel(
	struct server *restrict s, const struct config *restrict new_conf)
{
	if (s->mux_tunnel != NULL || new_conf->mux_connect == NULL) {
		return;
	}
	struct mux_config mux_conf = server_make_mux_config(s);
	unsigned char sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(sid);
	const struct tunnel_opts opts = {
		.cb = &client_callbacks,
		.data = s,
		.mux_conf = &mux_conf,
		.pool = { server_frame_alloc, server_frame_free,
			  s->frame_pool },
		.mux_socket = new_conf->mux_socket,
		.local_socket = new_conf->local_socket,
		.fd = -1,
		.id = sid,
		.connect_addr = new_conf->mux_connect,
		.forward_addr = new_conf->connect,
		.identity = new_conf->identity_claim,
		.peer_id = NULL,
#if WITH_TLS
		.tlsctx = s->client_tlsctx,
		.conn = NULL,
#endif
	};
	struct tunnel *const t = tunnel_new(s, &opts);
	if (t == NULL) {
		LOGE("failed to create mux tunnel on reload");
		return;
	}
	s->mux_tunnel = t;
	tunnel_start(t);
}

/* Replace closed identity_connect slots and extend the array on count
 * increase.  Live slots are left untouched (their connect_addr was updated
 * by server_drain_tunnels). */
static void server_reload_identity_tunnels(
	struct server *restrict s, const struct config *restrict new_conf)
{
	const size_t old_ni = s->num_identity_tunnels;
	const size_t new_ni = new_conf->identity_connect_count;
	const size_t common_ni = old_ni < new_ni ? old_ni : new_ni;

	/* Replace slots where the previous tunnel has already closed
	 * (set to NULL by handle_closed via the identity_tunnels fix). */
	for (size_t i = 0; i < common_ni; i++) {
		if (s->identity_tunnels[i] != NULL) {
			/* Tunnel is still live; connect_addr was already
			 * updated in the pre-drain step above. */
			continue;
		}
		struct mux_config mux_conf = server_make_mux_config(s);
		unsigned char sid[MUX_SESSION_ID_LEN];
		proto_session_id_new(sid);
		const struct tunnel_opts opts = {
			.cb = &client_callbacks,
			.data = s,
			.mux_conf = &mux_conf,
			.pool = { server_frame_alloc, server_frame_free,
				  s->frame_pool },
			.mux_socket = new_conf->mux_socket,
			.local_socket = new_conf->local_socket,
			.fd = -1,
			.id = sid,
			.connect_addr = new_conf->identity_connect[i],
			.forward_addr = new_conf->connect,
			.identity = new_conf->identity_claim,
			.peer_id = NULL,
#if WITH_TLS
			.tlsctx = s->client_tlsctx,
			.conn = NULL,
#endif
		};
		struct tunnel *const t = tunnel_new(s, &opts);
		if (t == NULL) {
			LOGE_F("failed to create identity tunnel[%zu]"
			       " on reload",
			       i);
		} else {
			s->identity_tunnels[i] = t;
			tunnel_start(t);
		}
	}

	/* Extend the array for new entries beyond the old count. */
	if (new_ni <= old_ni) {
		return;
	}
	struct tunnel **new_arr =
		realloc(s->identity_tunnels, new_ni * sizeof(*new_arr));
	if (new_arr == NULL) {
		LOGOOM();
		return;
	}
	s->identity_tunnels = new_arr;
	/* Zero new slots before starting any tunnel so server_stop() sees a
	 * clean array even if a subsequent tunnel_new() fails. */
	for (size_t i = old_ni; i < new_ni; i++) {
		s->identity_tunnels[i] = NULL;
	}
	s->num_identity_tunnels = new_ni;
	for (size_t i = old_ni; i < new_ni; i++) {
		struct mux_config mux_conf = server_make_mux_config(s);
		unsigned char sid[MUX_SESSION_ID_LEN];
		proto_session_id_new(sid);
		const struct tunnel_opts opts = {
			.cb = &client_callbacks,
			.data = s,
			.mux_conf = &mux_conf,
			.pool = { server_frame_alloc, server_frame_free,
				  s->frame_pool },
			.mux_socket = new_conf->mux_socket,
			.local_socket = new_conf->local_socket,
			.fd = -1,
			.id = sid,
			.connect_addr = new_conf->identity_connect[i],
			.forward_addr = new_conf->connect,
			.identity = new_conf->identity_claim,
			.peer_id = NULL,
#if WITH_TLS
			.tlsctx = s->client_tlsctx,
			.conn = NULL,
#endif
		};
		struct tunnel *const t = tunnel_new(s, &opts);
		if (t == NULL) {
			LOGE_F("failed to create identity tunnel[%zu]"
			       " on reload",
			       i);
		} else {
			s->identity_tunnels[i] = t;
			tunnel_start(t);
		}
	}
}

static void server_reload(struct server *restrict s)
{
	const char *const conf_path = s->conf_path;
	LOGI_F("reloading config: %s", conf_path);
	(void)systemd_notify(SYSTEMD_STATE_RELOADING);

	struct config *const new_conf = conf_parsefile(conf_path);
	if (new_conf == NULL) {
		LOGE_F("failed to reload config: %s", conf_path);
		return;
	}

#if WITH_TLS
	struct tls_context *new_server_tlsctx = NULL;
	struct tls_context *new_client_tlsctx = NULL;
	if (!server_reload_make_tls(
		    new_conf, &new_server_tlsctx, &new_client_tlsctx)) {
		conf_free(new_conf);
		return;
	}
#endif

	struct config *const old_conf = s->conf;

	server_drain_tunnels(
		s, old_conf, new_conf
#if WITH_TLS
		,
		new_client_tlsctx
#endif
	);

	/* Swap config and TLS contexts before starting any new tunnels or
	 * listeners so that server_make_mux_config(), identity_tcp_serve(),
	 * and mux_serve() all see the new configuration immediately. */
	s->conf = new_conf;
	s->tcp_listener.socket_opts = &new_conf->local_socket;
	s->mux_listener.socket_opts = &new_conf->mux_socket;
	for (size_t i = 0; i < s->num_identities; i++) {
		s->identities[i].listener.socket_opts = &new_conf->local_socket;
	}

#if WITH_TLS
	struct tls_context *const old_server_tlsctx = s->server_tlsctx;
	struct tls_context *const old_client_tlsctx = s->client_tlsctx;
	s->server_tlsctx = new_server_tlsctx;
	s->client_tlsctx = new_client_tlsctx;
#endif

	server_reload_listeners(s, old_conf, new_conf);
	server_reload_identities(s, old_conf, new_conf);
	server_reload_mux_tunnel(s, new_conf);
	server_reload_identity_tunnels(s, new_conf);

#if WITH_TLS
	if (old_server_tlsctx != NULL) {
		tls_ctx_free(old_server_tlsctx);
	}
	if (old_client_tlsctx != NULL) {
		tls_ctx_free(old_client_tlsctx);
	}
#endif

	slog_setlevel(new_conf->loglevel);
	conf_free(old_conf);

	LOGN("config reloaded");
	server_evlogf(s, "config reloaded");
	(void)systemd_notify(SYSTEMD_STATE_READY);
}

static void
shutdown_timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	UNUSED(w);
	LOGW("shutdown timeout: forcing exit");
	ev_break(loop, EVBREAK_ALL);
}

#if WITH_THREADS
static void relay_async_cb(struct ev_loop *loop, ev_async *w, const int revents)
{
	CHECK_REVENTS(revents, EV_ASYNC);
	UNUSED(loop);
	struct server *restrict srv = w->data;
	dispatcher_tick(srv->disp);
}
#endif

static void signal_cb(struct ev_loop *loop, ev_signal *w, const int revents)
{
	CHECK_REVENTS(revents, EV_SIGNAL);
	struct server *restrict s = w->data;
	const int signo = w->signum;

	switch (signo) {
	case SIGHUP:
		server_reload(s);
		break;
	case SIGINT:
	case SIGTERM:
		LOGI_F("received (%d) %s, initiating shutdown", signo,
		       os_strsignal(signo));
		(void)systemd_notify(SYSTEMD_STATE_STOPPING);

		/* Stop accepting new connections and incoming signals. */
		ev_signal_stop(loop, &s->w_sighup);
		ev_signal_stop(loop, &s->w_sigint);
		ev_signal_stop(loop, &s->w_sigterm);

		if (s->tcp_listener.w_accept.fd != -1) {
			listener_stop(&s->tcp_listener, loop);
		}
		if (s->mux_listener.w_accept.fd != -1) {
			listener_stop(&s->mux_listener, loop);
		}
		if (s->api_listener.w_accept.fd != -1) {
			listener_stop(&s->api_listener, loop);
		}
		for (size_t i = 0; i < s->num_identities; i++) {
			struct listener *restrict l =
				&s->identities[i].listener;
			if (l->w_accept.fd != -1) {
				listener_stop(l, loop);
			}
		}

		/* Initiate graceful shutdown on every active session.
		 * Each session will close itself and emit MUX_EVENT_CLOSED when done.
		 * Snapshot first: MUX_EVENT_CLOSED handling modifies accepted_tunnels and
		 * identities, which would invalidate a live iterator. */
		{
			const size_t n =
				(s->accepted_tunnels != NULL ?
					 table_size(s->accepted_tunnels) :
					 0) +
				1 + s->num_identities + s->num_identity_tunnels;
			struct tunnel *snapshot[n];
			size_t count = 0;
			struct tunnel_iter it = { 0 };
			struct tunnel *t;
			while ((t = tunnel_iter_next(s, &it)) != NULL) {
				snapshot[count++] = t;
			}
			/* mux_shutdown() writes session internals; dispatch to
			 * each session's tunnel thread. */
			for (size_t i = 0; i < count; i++) {
				tunnel_shutdown(snapshot[i]);
			}
		}

		if (s->mux_tunnel == NULL &&
		    (s->accepted_tunnels == NULL ||
		     table_size(s->accepted_tunnels) == 0)) {
			bool any = false;
			for (size_t i = 0; i < s->num_identities; i++) {
				if (s->identities[i].num_tunnels > 0) {
					any = true;
					break;
				}
			}
			if (!any) {
				ev_break(loop, EVBREAK_ALL);
				break;
			}
		}

		/* Keep the event loop running; it exits when all sessions close
		 * or the 2-second deadline fires. */
		ev_timer_init(&s->w_shutdown, shutdown_timeout_cb, 2.0, 0.0);
		s->w_shutdown.data = s;
		ev_timer_start(loop, &s->w_shutdown);
		break;
	default:
		break;
	}
}
struct server *server_new(struct ev_loop *loop, struct config *conf)
{
	struct server *srv = malloc(sizeof(struct server));
	if (srv == NULL) {
		LOGOOM();
		return NULL;
	}
	*srv = (struct server){
		.loop = loop,
		.conf = conf,
		.identities = NULL,
		.num_identities = 0,
	};
	listener_init(
		&srv->tcp_listener, &conf->local_socket, tcp_serve, srv,
		&srv->counters.num_accepted_tcp);
	listener_init(
		&srv->mux_listener, &conf->mux_socket, mux_serve, srv,
		&srv->counters.num_accepted);
	static const struct socket_opts api_socket_opts = {
		.tcp_nodelay = true,
		.tcp_keepalive = false,
		.backlog = 16,
	};
	listener_init(
		&srv->api_listener, &api_socket_opts, api_serve, srv,
		&srv->counters.num_accepted_api);
	srv->started = clock_monotonic_ns();

#if WITH_THREADS
	srv->frame_pool = mqueue_new(FRAME_POOL_CAPACITY);
#else
	srv->frame_pool =
		mcache_new(FRAME_POOL_CAPACITY, mux_frame_object_size());
#endif
	if (srv->frame_pool == NULL) {
		LOGOOM();
		free(srv);
		return NULL;
	}

#if WITH_THREADS
	if (smtx_init(&srv->accepted_mu) != thrd_success) {
		LOGOOM();
		mqueue_free(srv->frame_pool);
		free(srv);
		return NULL;
	}
#endif

	srv->accepted_tunnels = table_new(0);
	if (srv->accepted_tunnels == NULL) {
		LOGOOM();
		server_free(srv);
		return NULL;
	}

#if WITH_TLS
	if (conf->tls_cert != NULL && conf->tls_key != NULL) {
		if (conf->mux_listen != NULL) {
			srv->server_tlsctx = tls_ctx_server(
				conf->tls_cert, conf->tls_key, conf->authcerts,
				conf->authcerts_count, conf->tls_ciphersuites);
			if (srv->server_tlsctx == NULL) {
				LOGE("failed to create server TLS context");
				server_free(srv);
				return NULL;
			}
		}
		bool has_identity_connect = (conf->identity_connect_count > 0);
		if (conf->mux_connect != NULL || has_identity_connect) {
			srv->client_tlsctx = tls_ctx_client(
				conf->tls_cert, conf->tls_key, conf->authcerts,
				conf->authcerts_count, conf->tls_ciphersuites);
			if (srv->client_tlsctx == NULL) {
				LOGE("failed to create client TLS context");
				server_free(srv);
				return NULL;
			}
		}
		memset(conf->tls_cert, 0, strlen(conf->tls_cert));
		memset(conf->tls_key, 0, strlen(conf->tls_key));
		for (size_t i = 0; i < conf->authcerts_count; i++) {
			memset(conf->authcerts[i], 0,
			       strlen(conf->authcerts[i]));
		}
	}
#endif

	ev_signal_init(&srv->w_sighup, signal_cb, SIGHUP);
	srv->w_sighup.data = srv;
	ev_set_priority(&srv->w_sighup, EV_MAXPRI);

	ev_signal_init(&srv->w_sigint, signal_cb, SIGINT);
	srv->w_sigint.data = srv;
	ev_set_priority(&srv->w_sigint, EV_MAXPRI);

	ev_signal_init(&srv->w_sigterm, signal_cb, SIGTERM);
	srv->w_sigterm.data = srv;
	ev_set_priority(&srv->w_sigterm, EV_MAXPRI);

#if WITH_THREADS
	srv->disp = dispatcher_create(16);
	if (srv->disp == NULL) {
		LOGOOM();
		server_free(srv);
		return NULL;
	}
	ev_async_init(&srv->w_async, relay_async_cb);
	srv->w_async.data = srv;
#endif

	return srv;
}

bool server_start(struct server *restrict s)
{
	struct ev_loop *restrict loop = s->loop;
	const struct config *restrict conf = s->conf;

#if WITH_THREADS
	ev_async_start(s->loop, &s->w_async);
#endif

	if (conf->connect != NULL) {
		union sockaddr_max connect_addr;
		bool ok = true;
		RESOLVE_ADDR(&connect_addr, conf->connect, tcp, ok = false);
		if (!ok) {
			LOGE_F("failed to resolve connect address: %s",
			       conf->connect);
			return false;
		}
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			sa_format(addr_str, sizeof(addr_str), &connect_addr.sa);
			LOGN_F("connect target: %s", addr_str);
		}
	}

	if (conf->listen != NULL) {
		union sockaddr_max listen_addr;
		bool ok = true;
		RESOLVE_BINDADDR(
			&listen_addr, conf->listen, tcpbind, ok = false);
		if (!ok) {
			LOGE_F("failed to parse listen address: %s",
			       conf->listen);
			return false;
		}
		if (!listener_start(&s->tcp_listener, loop, &listen_addr.sa)) {
			LOGE("failed to start TCP listener");
			return false;
		}
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			sa_format(addr_str, sizeof(addr_str), &listen_addr.sa);
			LOGN_F("listening on %s (TCP)", addr_str);
		}
	}

	if (conf->mux_listen != NULL) {
		union sockaddr_max mux_addr;
		bool ok = true;
		RESOLVE_BINDADDR(
			&mux_addr, conf->mux_listen, tcpbind, ok = false);
		if (!ok) {
			LOGE_F("failed to parse mux_listen address: %s",
			       conf->mux_listen);
			return false;
		}
		if (!listener_start(&s->mux_listener, loop, &mux_addr.sa)) {
			LOGE("failed to start mux listener");
			return false;
		}
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			sa_format(addr_str, sizeof(addr_str), &mux_addr.sa);
			LOGN_F("mux listening on %s", addr_str);
		}
	}

	if (conf->mux_connect != NULL) {
		struct mux_config mux_conf = server_make_mux_config(s);
		unsigned char sid[MUX_SESSION_ID_LEN];
		proto_session_id_new(sid);
		const struct tunnel_opts opts = {
			.cb = &client_callbacks,
			.data = s,
			.mux_conf = &mux_conf,
			.pool = { server_frame_alloc, server_frame_free,
				  s->frame_pool },
			.mux_socket = conf->mux_socket,
			.local_socket = conf->local_socket,
			.fd = -1,
			.id = sid,
			.connect_addr = conf->mux_connect,
			.forward_addr = conf->connect,
			.identity = conf->identity_claim,
			.peer_id = NULL,
#if WITH_TLS
			.tlsctx = s->client_tlsctx,
			.conn = NULL,
#endif
		};
		struct tunnel *const t = tunnel_new(s, &opts);
		if (t == NULL) {
			LOGE("failed to create tunnel for mux session");
			return false;
		}
		s->mux_tunnel = t;
		/* mux_start() starts watchers on the tunnel's loop; dispatch. */
		tunnel_start(t);
	}

	/* Identity listeners: each identity.listen entry gets its own
	 * identity listener. Tunnel wiring happens dynamically at handshake
	 * time using the peer's announced identity as the lookup key. */
	{
		const size_t n = conf->identity_peers_count;
		if (n > 0) {
			s->identities =
				malloc(n * sizeof(struct identity_listener));
			if (s->identities == NULL) {
				LOGOOM();
				return false;
			}
			for (size_t i = 0; i < n; i++) {
				const struct identity_peer *restrict p =
					&conf->identity_peers[i];
				struct identity_listener *restrict sl =
					&s->identities[i];
				sl->peer_identity = p->id;
				sl->tunnels = NULL;
				sl->num_tunnels = 0;
				sl->rr_next = 0;
				listener_init(
					&sl->listener, &conf->local_socket,
					identity_tcp_serve, s,
					&s->counters.num_accepted_tcp);
				sl->listener.data = sl;
				union sockaddr_max addr;
				bool ok = true;
				RESOLVE_BINDADDR(
					&addr, p->listen, tcpbind, ok = false);
				if (!ok) {
					LOGE_F("failed to parse identity listen"
					       " address: %s",
					       p->listen);
					return false;
				}
				if (!listener_start(
					    &sl->listener, loop, &addr.sa)) {
					LOGE_F("failed to start identity"
					       " listener for \"%s\" at %s",
					       p->id, p->listen);
					return false;
				}
				s->num_identities = i + 1;
				if (LOGLEVEL(NOTICE)) {
					char resolved[64];
					sa_format(
						resolved, sizeof(resolved),
						&addr.sa);
					LOGN_F("identity \"%s\" listening on"
					       " %s (TCP)",
					       p->id, resolved);
				}
			}
		}
	}

	/* Create one dedicated mux session per identity.mux_connect address.
	 * The session announces identity_claim in the hello; the peer's
	 * identity is discovered after the handshake and used to wire the
	 * session to the matching identity listener in handle_connected. */
	{
		const size_t n = conf->identity_connect_count;
		if (n > 0) {
			s->identity_tunnels =
				malloc(n * sizeof(struct tunnel *));
			if (s->identity_tunnels == NULL) {
				LOGOOM();
				return false;
			}
			/* Zero the array before starting any tunnel so that a
			 * partial allocation is visible to server_stop() via
			 * num_identity_tunnels without stale pointers. */
			for (size_t i = 0; i < n; i++) {
				s->identity_tunnels[i] = NULL;
			}
			s->num_identity_tunnels = n;
		}
	}
	for (size_t i = 0; i < conf->identity_connect_count; i++) {
		struct mux_config mux_conf = server_make_mux_config(s);
		unsigned char sid[MUX_SESSION_ID_LEN];
		proto_session_id_new(sid);
		const struct tunnel_opts opts = {
			.cb = &client_callbacks,
			.data = s,
			.mux_conf = &mux_conf,
			.pool = { server_frame_alloc, server_frame_free,
				  s->frame_pool },
			.mux_socket = conf->mux_socket,
			.local_socket = conf->local_socket,
			.fd = -1,
			.id = sid,
			.connect_addr = conf->identity_connect[i],
			.forward_addr = conf->connect,
			.identity = conf->identity_claim,
			.peer_id = NULL,
#if WITH_TLS
			.tlsctx = s->client_tlsctx,
			.conn = NULL,
#endif
		};
		struct tunnel *const t = tunnel_new(s, &opts);
		if (t == NULL) {
			LOGE_F("failed to create tunnel for identity"
			       " mux_connect[%zu]",
			       i);
			return false;
		}

		/* mux_start() starts watchers on the tunnel's loop; dispatch. */
		tunnel_start(t);
		s->identity_tunnels[i] = t;
	}

	if (conf->api_listen != NULL) {
		union sockaddr_max api_addr;
		bool ok = true;
		RESOLVE_BINDADDR(
			&api_addr, conf->api_listen, tcpbind, ok = false);
		if (!ok) {
			LOGE_F("failed to parse api_listen address: %s",
			       conf->api_listen);
			return false;
		}
		const enum ipclass cls = sa_ipclassify(&api_addr.sa);
		if (cls != IPCLASS_LOOPBACK && cls != IPCLASS_LINKLOCAL &&
		    cls != IPCLASS_SITELOCAL) {
			LOGW("binding API server to non-local address may be insecure");
		}
		if (!listener_start(&s->api_listener, loop, &api_addr.sa)) {
			LOGE("failed to start API listener");
			return false;
		}
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			sa_format(addr_str, sizeof(addr_str), &api_addr.sa);
			LOGN_F("API server listening on %s", addr_str);
		}
	}

	ev_signal_start(loop, &s->w_sighup);
	ev_signal_start(loop, &s->w_sigint);
	ev_signal_start(loop, &s->w_sigterm);

	LOGN("server started");
	return true;
}

void server_stop(struct server *srv)
{
	if (srv == NULL) {
		return;
	}
	LOGN("stopping server");
	struct ev_loop *loop = srv->loop;

	ev_signal_stop(loop, &srv->w_sighup);
	ev_signal_stop(loop, &srv->w_sigint);
	ev_signal_stop(loop, &srv->w_sigterm);
	ev_timer_stop(loop, &srv->w_shutdown);
#if WITH_THREADS
	ev_async_stop(loop, &srv->w_async);
	dispatcher_tick(srv->disp);
#endif

	if (srv->tcp_listener.w_accept.fd != -1) {
		listener_stop(&srv->tcp_listener, loop);
	}
	if (srv->mux_listener.w_accept.fd != -1) {
		listener_stop(&srv->mux_listener, loop);
	}
	if (srv->api_listener.w_accept.fd != -1) {
		listener_stop(&srv->api_listener, loop);
	}
	for (size_t i = 0; i < srv->num_identities; i++) {
		struct listener *restrict l = &srv->identities[i].listener;
		if (l->w_accept.fd != -1) {
			listener_stop(l, loop);
		}
	}

	/* Drain any close notifications that arrived just before the relay was
	 * stopped.  Sessions that closed gracefully during the shutdown window
	 * will have their cleanup tasks here; processing them now avoids the
	 * race where server_stop tries to force-close a session whose tunnel
	 * thread has already exited. */
#if WITH_THREADS
	dispatcher_tick(srv->disp);
#endif

	/* Force-close any sessions that did not finish their shutdown
	 * handshake within the deadline. */
	{
		struct tunnel_iter it = { 0 };
		struct tunnel *t;
		while ((t = tunnel_iter_next(srv, &it)) != NULL) {
			tunnel_close(t);
		}
	}
	srv->mux_tunnel = NULL;
	for (size_t i = 0; i < srv->num_identities; i++) {
		free(srv->identities[i].tunnels);
		srv->identities[i].tunnels = NULL;
		srv->identities[i].num_tunnels = 0;
	}
	free(srv->identity_tunnels);
	srv->identity_tunnels = NULL;
	srv->num_identity_tunnels = 0;
	if (srv->accepted_tunnels != NULL) {
		table_free(srv->accepted_tunnels);
		srv->accepted_tunnels = NULL;
	}
}

void server_free(struct server *srv)
{
	if (srv == NULL) {
		return;
	}
#if WITH_TLS
	if (srv->server_tlsctx != NULL) {
		tls_ctx_free(srv->server_tlsctx);
	}
	if (srv->client_tlsctx != NULL) {
		tls_ctx_free(srv->client_tlsctx);
	}
#endif
	table_free(srv->accepted_tunnels);
#if WITH_THREADS
	smtx_destroy(&srv->accepted_mu);
#endif
	free(srv->identities);
#if WITH_THREADS
	if (srv->disp != NULL) {
		dispatcher_destroy(srv->disp);
	}
#endif
	if (srv->frame_pool != NULL) {
#if WITH_THREADS
		struct mux_frame *frame;
		while ((frame = mqueue_pop(srv->frame_pool)) != NULL) {
			free(frame);
		}
		mqueue_free(srv->frame_pool);
#else
		mcache_free(srv->frame_pool);
#endif
	}
	free(srv);
}

void server_stats(
	const struct server *restrict s, struct server_stats *restrict out)
{
	*out = (struct server_stats){ 0 };

	const struct server_counters *restrict c = &s->counters;
	out->num_accepted = c->num_accepted;
	out->num_served = c->num_served;
	out->num_accepted_tcp = c->num_accepted_tcp;
	out->num_served_tcp = c->num_served_tcp;
	out->num_accepted_api = c->num_accepted_api;
	out->num_served_api = c->num_served_api;
	out->num_rejected = c->num_rejected;
#if WITH_TLS
	out->num_tls_failures = c->num_tls_failures;
#endif

#if WITH_THREADS
	out->num_session_created = atomic_load_explicit(
		&c->num_session_created, memory_order_relaxed);
	out->num_session_connect = atomic_load_explicit(
		&c->num_session_connect, memory_order_relaxed);
	out->num_session_connected = atomic_load_explicit(
		&c->num_session_connected, memory_order_relaxed);
	out->num_session_disconnected = atomic_load_explicit(
		&c->num_session_disconnected, memory_order_relaxed);
	out->num_session_finalized = atomic_load_explicit(
		&c->num_session_finalized, memory_order_relaxed);
	out->num_sessions =
		atomic_load_explicit(&c->num_sessions, memory_order_relaxed);
	out->num_session_halfopen = atomic_load_explicit(
		&c->num_session_halfopen, memory_order_relaxed);
	out->num_streams =
		atomic_load_explicit(&c->num_streams, memory_order_relaxed);
	out->num_stream_halfopen = atomic_load_explicit(
		&c->num_stream_halfopen, memory_order_relaxed);
	out->num_stream_opened = atomic_load_explicit(
		&c->num_stream_opened, memory_order_relaxed);
	out->num_stream_accepted = atomic_load_explicit(
		&c->num_stream_accepted, memory_order_relaxed);
	out->num_stream_fastopen = atomic_load_explicit(
		&c->num_stream_fastopen, memory_order_relaxed);
	out->num_stream_established = atomic_load_explicit(
		&c->num_stream_established, memory_order_relaxed);
	out->num_stream_succeeded = atomic_load_explicit(
		&c->num_stream_succeeded, memory_order_relaxed);
	out->num_stream_failed = atomic_load_explicit(
		&c->num_stream_failed, memory_order_relaxed);
	out->num_rst_sent =
		atomic_load_explicit(&c->num_rst_sent, memory_order_relaxed);
	out->num_rst_recv =
		atomic_load_explicit(&c->num_rst_recv, memory_order_relaxed);
	out->num_stream_errors = atomic_load_explicit(
		&c->num_stream_errors, memory_order_relaxed);
	out->num_reconnects =
		atomic_load_explicit(&c->num_reconnects, memory_order_relaxed);
	out->traffic_byt_mux_recv = atomic_load_explicit(
		&c->traffic_byt_mux_recv, memory_order_relaxed);
	out->traffic_byt_mux_sent = atomic_load_explicit(
		&c->traffic_byt_mux_sent, memory_order_relaxed);
	out->traffic_byt_local_recv = atomic_load_explicit(
		&c->traffic_byt_local_recv, memory_order_relaxed);
	out->traffic_byt_local_sent = atomic_load_explicit(
		&c->traffic_byt_local_sent, memory_order_relaxed);
	out->recv_buffered_bytes = atomic_load_explicit(
		&c->recv_buffered_bytes, memory_order_relaxed);
	out->send_buffered_frames = atomic_load_explicit(
		&c->send_buffered_frames, memory_order_relaxed);
	out->unacked_frames =
		atomic_load_explicit(&c->unacked_frames, memory_order_relaxed);
#else
	out->num_session_created = c->num_session_created;
	out->num_session_connect = c->num_session_connect;
	out->num_session_connected = c->num_session_connected;
	out->num_session_disconnected = c->num_session_disconnected;
	out->num_session_finalized = c->num_session_finalized;
	out->num_sessions = c->num_sessions;
	out->num_session_halfopen = c->num_session_halfopen;
	out->num_streams = c->num_streams;
	out->num_stream_halfopen = c->num_stream_halfopen;
	out->num_stream_opened = c->num_stream_opened;
	out->num_stream_accepted = c->num_stream_accepted;
	out->num_stream_fastopen = c->num_stream_fastopen;
	out->num_stream_established = c->num_stream_established;
	out->num_stream_succeeded = c->num_stream_succeeded;
	out->num_stream_failed = c->num_stream_failed;
	out->num_rst_sent = c->num_rst_sent;
	out->num_rst_recv = c->num_rst_recv;
	out->num_stream_errors = c->num_stream_errors;
	out->num_reconnects = c->num_reconnects;
	out->traffic_byt_mux_recv = c->traffic_byt_mux_recv;
	out->traffic_byt_mux_sent = c->traffic_byt_mux_sent;
	out->traffic_byt_local_recv = c->traffic_byt_local_recv;
	out->traffic_byt_local_sent = c->traffic_byt_local_sent;
	out->recv_buffered_bytes = c->recv_buffered_bytes;
	out->send_buffered_frames = c->send_buffered_frames;
	out->unacked_frames = c->unacked_frames;
#endif

	const struct server_runtime_stats *restrict r = &s->runtime;
	out->stream_establish_count = r->stream_establish_count;
	memcpy(out->stream_establish_ns, r->stream_establish_ns,
	       sizeof(out->stream_establish_ns));
	memcpy(out->eventlog, r->eventlog, sizeof(out->eventlog));
	out->eventlog_len = r->eventlog_len;
	out->eventlog_pos = r->eventlog_pos;

	out->num_identities =
		MIN(s->num_identities, ARRAY_SIZE(out->identities));
	for (size_t i = 0; i < out->num_identities; i++) {
		const struct identity_listener *restrict sl = &s->identities[i];
		out->identities[i].id = sl->peer_identity;
		out->identities[i].num_tunnels = sl->num_tunnels;
		out->identities[i].connected = false;
		for (size_t j = 0; j < sl->num_tunnels; j++) {
			if (tunnel_state(sl->tunnels[j]) ==
			    MUX_STATE_ESTABLISHED) {
				out->identities[i].connected = true;
				tunnel_stats(
					sl->tunnels[j],
					&out->identities[i].tunnel);
				break;
			}
		}
	}
}
