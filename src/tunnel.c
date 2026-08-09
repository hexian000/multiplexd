/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tunnel.c
 * @brief Tunnel implementation: one mux session, its connect/reconnect and
 *        drain lifecycle, local stream opens, and the relay of session events
 *        back to the server.  WITH_THREADS gives each tunnel its own event loop
 *        and thread; otherwise it runs on the server's loop.
 */

#include "tunnel.h"

#include "conf.h"
#include "mux/mux.h"
#if WITH_TLS
#include "shim/tls.h"
#endif
#include "shim/util.h"

#include "math/rand.h"
#include "meta/arraysize.h"
#include "meta/minmax.h"
#include "os/clock.h"
#include "os/socket.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#endif
#include "sync/task.h"
#include "utils/debug.h"
#include "utils/mcache.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#if WITH_THREADS
#include <stdatomic.h>
#include <threads.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define TUNNEL_LOG_F(level, t, format, ...)                                    \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, "%s: " format, (t)->tag, __VA_ARGS__);            \
	} while (0)

#define TUNNEL_LOG(level, t, message) TUNNEL_LOG_F(level, t, "%s", message)

/* Server-thread counterpart of TUNNEL_LOG_F. t->tag is the session thread's
 * private working buffer, rewritten in place by tunnel_set_tag on every
 * establish, so reading it from the server thread is a data race; go through
 * the pub.mu-guarded snapshot the design already provides for cross-thread
 * reads, as tunnel_stats/tunnel_fd do. Defined here beside its sibling; every
 * use is below tunnel_pub_lock's definition. */
#define TUNNEL_LOG_PUB_F(level, t, format, ...)                                \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char pub_tag_[TUNNEL_TAG_SIZE];                                \
		tunnel_pub_lock(t);                                            \
		(void)memcpy(pub_tag_, (t)->pub.tag, sizeof(pub_tag_));        \
		tunnel_pub_unlock(t);                                          \
		LOG_F(level, "%s: " format, pub_tag_, __VA_ARGS__);            \
	} while (0)

#define TUNNEL_LOG_PUB(level, t, message)                                      \
	TUNNEL_LOG_PUB_F(level, t, "%s", message)

/* Number of frames retained in the per-tunnel allocator cache. */
#define TUNNEL_FRAME_CACHE_SIZE 16

/* Interval between frame_cache trims, in seconds. */
#define TUNNEL_MAINTENANCE_INTERVAL 10.0

#if WITH_THREADS
/* Intrusive FIFO node for a local connection accepted on the parent loop and
 * awaiting a stream open on the owning tunnel's thread; see
 * struct tunnel::open_head. */
struct pending_open {
	int fd;
	struct pending_open *next;
};
#endif

struct tunnel {
#if WITH_THREADS
	thrd_t thread;
	bool started;
	ev_async w_async;
	struct dispatcher *disp;
	/* Local connections accepted on the parent loop and awaiting a stream
	 * open on this tunnel's own thread.  The bounded task ring (disp) cannot
	 * hold a concurrent-open burst larger than its capacity, so opens are
	 * queued here instead of posted onto it and drained by tunnel_async_cb --
	 * decoupling the number of simultaneous opens from the ring size so no
	 * accepted connection is dropped.  open_mu guards the list between the
	 * parent thread (producer) and this tunnel's thread (consumer). */
	mtx_t open_mu;
	struct pending_open *open_head;
	struct pending_open *open_tail;
#endif /* WITH_THREADS */
	struct ev_loop *loop;
	/* Wrapped callbacks registered with the mux session. */
	struct mux_callbacks cb;
	/* Back-pointer to the mux session running on this tunnel's loop. */
	struct mux_session *ss;
	/* Per-tunnel frame cache. */
	struct mcache *frame_cache;
	ev_timer w_maintenance;

	/* Relay: re-dispatch or pass-through mux callbacks.  relay.cb is set once
	 * at creation and never mutated afterwards, so it is safe to read on both
	 * threads; the relay is instead torn down via relay_disconnected below. */
	struct {
		struct tunnel_context parent;
		struct tunnel_callbacks cb;
	} relay;
	/* Relay disconnect flag, set by tunnel_close() on the server thread.  Once
	 * set, the relay producer (session thread) stops enqueuing and the consumer
	 * (server thread) skips invoking, so the close state is carried by this
	 * atomic instead of by mutating relay.cb.  Relaxed-atomic; the final
	 * lifetime fence is thrd_join(). */
#if WITH_THREADS
	atomic_bool relay_disconnected;
#endif

	/* Callback data passed to wrapped callbacks. */
	void *callback_data;
	/* Stream forwarding address; NULL means reject all inbound streams. Owned. */
	char *forward_addr;
	/* Reconnect state for outbound (client) tunnels. */
	/* strdup'd from opts->connect_addr; NULL for accepted tunnels. Owned. */
	char *connect_addr;
	/* Backoff timer for reconnect attempts. */
	ev_timer w_reconnect;
	/* Backoff state: incremented per retry; reset on CONNECTED or RESUMED. */
	int reconnect_count;
	/* Set when tunnel_shutdown is called; suppresses reconnect on CLOSED. */
	bool shutting_down;
	/* true for passively-accepted (server-role) sessions; set at creation. */
	bool accepted;
	/* identity.verify: a claimed peer identity must be named by the
	 * certificate presented on this transport.  Set at creation, refreshed by
	 * reload_task, and read on this tunnel's thread at each hello. */
	bool verify_identity;
	/* PSK mode: resolves an authenticated label to its peer identity; NULL
	 * in certificate mode.  Same lifetime rules as verify_identity. */
	const char *(*psk_identity_of)(void *ctx, const char *label);
	void *psk_ctx;
	/* Server-wide monotonic index, never reused. */
	uint_least64_t tunnel_index;
	/* Owned copies of session metadata strings. */
	char *identity;
	char *peer_id;
	char *peer_identity;
	/* Session log tag: "my <= peer" or "my => peer". */
	char tag[TUNNEL_TAG_SIZE];
	/* Socket options cached at creation; updated on reload. */
	struct conf_socket_opts mux_socket;
	struct conf_socket_opts local_socket;
#if WITH_TLS
	/* Per-tunnel TLS context (client role); owned.  Shares parsed credentials
	 * with sibling tunnels via tls_ctx_ref() but each tunnel frees its own
	 * handle, so the lifetime is single-owner: adopted at creation, replaced in
	 * reload_task, and freed in tunnel_close -- all on this tunnel's thread (or
	 * the server thread before start / after thrd_join).  The mux session
	 * borrows it via ss->wire.tlsctx.  NULL for accepted tunnels (they hold a
	 * tls_connection instead) and for plaintext. */
	struct tls_context *tlsctx;
#endif /* WITH_TLS */

	/* Relaxed-atomic cross-thread block: every field below is written on the
	 * session thread and read on the server thread (the /stats path).  Each is
	 * an independent relaxed atomic, so the block needs no lock.  (Grouped only
	 * for clarity; the fields are still accessed as t->last_changed etc.) */
	struct {
		/* Monotonic ns of the last transport state change. */
#if WITH_THREADS
		atomic_int_least64_t last_changed;
#else
		int_least64_t last_changed;
#endif
		/* Per-tunnel stream lifecycle counters; updated by the session
		 * thread via the mux_session_counters pointer-block. */
		struct {
#if WITH_THREADS
			atomic_size_t num_streams;
			atomic_size_t num_stream_halfopen;
			atomic_uint_least64_t num_stream_opened;
			atomic_uint_least64_t num_stream_accepted;
			atomic_uint_least64_t num_stream_fastopen;
			atomic_uint_least64_t num_stream_established;
			atomic_uint_least64_t num_stream_succeeded;
			atomic_uint_least64_t num_stream_failed;
#else /* WITH_THREADS */
			size_t num_streams;
			size_t num_stream_halfopen;
			uint_least64_t num_stream_opened;
			uint_least64_t num_stream_accepted;
			uint_least64_t num_stream_fastopen;
			uint_least64_t num_stream_established;
			uint_least64_t num_stream_succeeded;
			uint_least64_t num_stream_failed;
#endif /* WITH_THREADS */
		} stream_cnt;
		/* Per-tunnel traffic byte counters; updated by the session thread
		 * via the mux_session_counters pointer-block. */
		struct {
#if WITH_THREADS
			atomic_uint_least64_t byt_mux_recv;
			atomic_uint_least64_t byt_mux_sent;
			/* PUSH-frame payload bytes only */
			atomic_uint_least64_t byt_push_recv;
			atomic_uint_least64_t byt_push_sent;
#else /* WITH_THREADS */
			uint_least64_t byt_mux_recv;
			uint_least64_t byt_mux_sent;
			/* PUSH-frame payload bytes only */
			uint_least64_t byt_push_recv;
			uint_least64_t byt_push_sent;
#endif /* WITH_THREADS */
		} traffic_cnt;
		/* Per-tunnel error and control counters.  The session thread bumps
		 * the RST and stream-error fields through the
		 * mux_session_counters block; num_reconnects is bumped by this
		 * tunnel's own thread. */
		struct {
			mux_counter num_reconnects;
			mux_counter num_rst_sent;
			mux_counter num_rst_recv;
			mux_counter num_stream_errors;
		} error_cnt;
		/* Per-tunnel buffer gauges; updated by the session thread via the
		 * mux_session_counters pointer-block. */
		struct {
			mux_gauge recv_buffered_bytes;
			mux_gauge send_buffered_frames;
			mux_gauge unacked_frames;
		} buf_gauge;
		/* SYN->SYN|ACK latency ring; written per stream-established on the
		 * session thread (handle_stream_established), read on the server
		 * thread (tunnel_stats).  High-frequency, so relaxed-atomic. */
#if WITH_THREADS
		atomic_size_t stream_establish_count;
		atomic_int_least64_t
			stream_establish_ns[TUNNEL_ESTABLISH_RING_SIZE];
#else
		size_t stream_establish_count;
		int_least64_t stream_establish_ns[TUNNEL_ESTABLISH_RING_SIZE];
#endif
	};

	/* pub.mu guards the rest of pub: a coherent diagnostic snapshot published
	 * by the session thread and read by the server thread under the same lock.
	 * Strings are not atomic so the mutex guards a consistent copy;
	 * peer_identity is inlined to avoid touching a freeable heap pointer. */
	struct {
#if WITH_THREADS
		mtx_t mu;
#endif
		char tag[TUNNEL_TAG_SIZE];
		char peer_identity[256];
		bool has_peer_identity;
		/* Transport fd and peer address, snapshotted from the session on
		 * each (re)connect. */
		int fd;
		union sockaddr_max peer_addr;
		bool has_peer_addr;
	} pub;
};

/* TPUB_STORE/TPUB_LOAD/TPUB_ADD: relaxed-atomic access to a scalar tunnel field
 * owned by one thread (last_changed, stream_establish ring/count, the counters
 * this tunnel bumps itself) and read by the server thread.  Operate on the field
 * lvalue. */
#if WITH_THREADS
#define TPUB_STORE(field, v)                                                   \
	atomic_store_explicit(&(field), (v), memory_order_relaxed)
#define TPUB_LOAD(field) atomic_load_explicit(&(field), memory_order_relaxed)
#define TPUB_ADD(field, v)                                                     \
	((void)atomic_fetch_add_explicit(&(field), (v), memory_order_relaxed))
#else
#define TPUB_STORE(field, v) ((void)((field) = (v)))
#define TPUB_LOAD(field) (field)
#define TPUB_ADD(field, v) ((void)((field) += (v)))
#endif /* WITH_THREADS */

/* Lock/unlock the per-tunnel stats-snapshot mutex.  Takes const because the
 * snapshot read path holds a const tunnel; the mutex is not part of the object's
 * const-observable state (the build uses no -Wcast-qual). */
static void tunnel_pub_lock(const struct tunnel *restrict t)
{
#if WITH_THREADS
	THRD_ASSERT(mtx_lock((mtx_t *)&t->pub.mu));
#else
	(void)t;
#endif
}

static void tunnel_pub_unlock(const struct tunnel *restrict t)
{
#if WITH_THREADS
	THRD_ASSERT(mtx_unlock((mtx_t *)&t->pub.mu));
#else
	(void)t;
#endif
}

/* Publish the coherent diagnostic snapshot (tag, peer_identity, transport fd and
 * peer address) under pub_mtx so the server thread can read it race-free.  Runs
 * on the session thread. */
static void tunnel_publish_pub(struct tunnel *restrict t)
{
	const int fd = mux_fd(t->ss);
	const struct sockaddr *const peer_addr = mux_peer_addr(t->ss);
	tunnel_pub_lock(t);
	(void)memcpy(t->pub.tag, t->tag, sizeof(t->pub.tag));
	if (t->peer_identity != NULL) {
		(void)snprintf(
			t->pub.peer_identity, sizeof(t->pub.peer_identity),
			"%s", t->peer_identity);
		t->pub.has_peer_identity = true;
	} else {
		t->pub.peer_identity[0] = '\0';
		t->pub.has_peer_identity = false;
	}
	t->pub.fd = fd;
	if (peer_addr != NULL) {
		(void)memcpy(
			&t->pub.peer_addr, peer_addr, sizeof(t->pub.peer_addr));
		t->pub.has_peer_addr = true;
	} else {
		t->pub.has_peer_addr = false;
	}
	tunnel_pub_unlock(t);
}

static bool stream_connect(
	const struct tunnel *restrict t, struct mux_stream *stream,
	const char *target)
{
	union sockaddr_max connect_addr;
	if (!resolve_addr(&connect_addr, target, SA_RESOLVE_TCP)) {
		TUNNEL_LOG_F(
			WARNING, t,
			"stream %" PRIuLEAST16
			": name resolution failed for \"%.256s\"",
			mux_stream_id(stream), target);
		return false;
	}

	const int fd =
		socket(connect_addr.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: (%d) %s", err, strerror(err));
		return false;
	}

	/* No exec() is ever performed in this codebase, so a cloexec failure
	 * is harmless; only a failed nonblock switch must abort the connect. */
	(void)socket_set_cloexec(fd);
	if (!socket_set_nonblock(fd)) {
		socket_close(fd);
		return false;
	}
	(void)socket_set_buffer(
		fd, t->local_socket.tcp_sndbuf, t->local_socket.tcp_rcvbuf);
	(void)socket_set_tcp(
		fd, t->local_socket.tcp_nodelay, t->local_socket.tcp_keepalive);

	const int ret = connect(fd, &connect_addr.sa, sa_len(&connect_addr.sa));
	if (ret != 0) {
		const int err = errno;
		if (err != EINPROGRESS) {
			LOGE_F("connect: (%d) %s", err, strerror(err));
			socket_close(fd);
			return false;
		}
	}

	if (LOGLEVEL(DEBUG)) {
		char addr_str[64];
		(void)sa_format(addr_str, sizeof(addr_str), &connect_addr.sa);
		TUNNEL_LOG_F(
			DEBUG, t,
			"stream %" PRIuLEAST16 ": connecting [fd:%d] to %s",
			mux_stream_id(stream), fd, addr_str);
	}
	mux_stream_attach_fd(stream, fd);
	return true;
}

static bool tunnel_on_accept(
	void *data, const struct mux_session *ss, struct mux_stream *stream)
{
	(void)ss;
	const struct tunnel *const restrict t = data;
	if (t->forward_addr == NULL) {
		TUNNEL_LOG_F(
			WARNING, t,
			"stream %" PRIuLEAST16 ": no connect target configured",
			mux_stream_id(stream));
		return false;
	}
	return stream_connect(t, stream, t->forward_addr);
}

#if WITH_THREADS
/* Task argument for an on_event relay dispatched to the relay loop. */
struct relay_event_arg {
	struct tunnel *t;
	enum mux_event event;
	union mux_event_data data;
};

static void relay_dispatch_on_event(void *p)
{
	struct relay_event_arg *const restrict arg = p;
	struct tunnel *const restrict t = arg->t;
	const enum mux_event event = arg->event;
	const union mux_event_data data = arg->data;
	free(arg);
	if (!atomic_load_explicit(
		    &t->relay_disconnected, memory_order_relaxed) &&
	    t->relay.cb.on_event != NULL) {
		t->relay.cb.on_event(t->callback_data, t, event, data);
	}
}

/* Task argument for on_established / on_resumed relays. */
struct relay_connected_arg {
	struct tunnel *t;
	int_fast64_t lat_ns;
	void (*cb)(void *, struct tunnel *, int_fast64_t);
};

static void relay_dispatch_connected(void *p)
{
	struct relay_connected_arg *const restrict arg = p;
	struct tunnel *const restrict t = arg->t;
	const int_fast64_t lat_ns = arg->lat_ns;
	void (*const cb)(void *, struct tunnel *, int_fast64_t) = arg->cb;
	free(arg);
	if (cb != NULL &&
	    !atomic_load_explicit(
		    &t->relay_disconnected, memory_order_relaxed)) {
		cb(t->callback_data, t, lat_ns);
	}
}
#endif /* WITH_THREADS */

static void relay_connected(
	struct tunnel *restrict t,
	void (*cb)(void *, struct tunnel *, int_fast64_t),
	const int_fast64_t lat_ns)
{
	if (cb == NULL) {
		return;
	}
#if WITH_THREADS
	if (atomic_load_explicit(&t->relay_disconnected, memory_order_relaxed)) {
		return;
	}
	struct relay_connected_arg *const restrict arg = malloc(sizeof(*arg));
	if (arg == NULL) {
		LOGOOM();
		return;
	}
	*arg = (struct relay_connected_arg){
		.t = t,
		.lat_ns = lat_ns,
		.cb = cb,
	};
	const bool posted = t->relay.parent.post_task(
		t->relay.parent.user,
		(struct task){ .func = relay_dispatch_connected, .data = arg });
	if (!posted) {
		TUNNEL_LOG(
			ERROR, t,
			"failed to dispatch relay connected event (queue full)");
		free(arg);
		return;
	}
#else /* WITH_THREADS */
	cb(t->callback_data, t, lat_ns);
#endif /* WITH_THREADS */
}

static const double tunnel_reconnect_delays[] = {
	0.2,  2.0,  2.0,  5.0,	 5.0,	15.0,  15.0,
	15.0, 60.0, 60.0, 120.0, 300.0, 600.0,
};

static void tunnel_schedule_reconnect(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL || t->shutting_down) {
		return;
	}
	const int idx =
		CLAMP(t->reconnect_count, 0,
		      (int)(ARRAY_SIZE(tunnel_reconnect_delays) - 1));
	const double delay =
		tunnel_reconnect_delays[idx] * (0.8 + frand() * 0.4);
	t->reconnect_count++;
	TPUB_ADD(t->error_cnt.num_reconnects, 1);
	TUNNEL_LOG_F(
		INFO, t, "reconnect scheduled in %.1fs (attempt %d)", delay,
		t->reconnect_count);
	t->w_reconnect.repeat = delay;
	ev_timer_again(t->loop, &t->w_reconnect);
}

static bool tunnel_do_connect(struct tunnel *restrict t)
{
	const char *const addr_str = t->connect_addr;

	union sockaddr_max addr;
	if (!resolve_addr(&addr, addr_str, SA_RESOLVE_TCP)) {
		TUNNEL_LOG_F(ERROR, t, "failed to resolve: %.256s", addr_str);
		return false;
	}

	const int fd = socket(addr.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: (%d) %s", err, strerror(err));
		return false;
	}
	(void)socket_set_cloexec(fd);
	if (!socket_set_nonblock(fd)) {
		socket_close(fd);
		return false;
	}
	(void)socket_set_buffer(
		fd, t->mux_socket.tcp_sndbuf, t->mux_socket.tcp_rcvbuf);
#if WITH_TCP_NOTSENT_LOWAT
	if (t->mux_socket.tcp_notsent_lowat > 0) {
		(void)socket_notsent_lowat(fd, t->mux_socket.tcp_notsent_lowat);
	}
#endif
	(void)socket_set_tcp(
		fd, t->mux_socket.tcp_nodelay, t->mux_socket.tcp_keepalive);

	if (LOGLEVEL(DEBUG)) {
		char log_addr_str[64];
		(void)sa_format(log_addr_str, sizeof(log_addr_str), &addr.sa);
		TUNNEL_LOG_F(
			DEBUG, t, "[fd:%d] try connecting to %s", fd,
			log_addr_str);
	}

	const int ret = connect(fd, &addr.sa, sa_len(&addr.sa));
	if (ret != 0) {
		const int err = errno;
		if (err != EINPROGRESS) {
			LOGE_F("connect: (%d) %s", err, strerror(err));
			socket_close(fd);
			return false;
		}
	}

	if (LOGLEVEL(NOTICE)) {
		char log_addr_str[64];
		(void)sa_format(log_addr_str, sizeof(log_addr_str), &addr.sa);
		TUNNEL_LOG_F(
			NOTICE, t, "[fd:%d] connecting to %s", fd,
			log_addr_str);
	}
	mux_attach_fd(t->ss, fd);
	return true;
}

static void
tunnel_reconnect_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct tunnel *const restrict t = w->data;
	ASSERT(loop == t->loop);
	(void)loop;
	ev_timer_stop(loop, &t->w_reconnect);
	if (t->connect_addr == NULL) {
		/* Nothing to dial: an accepted tunnel, or one whose address a
		 * reload cleared. Matches the guard every other reconnect entry
		 * point already has. */
		return;
	}
	if (tunnel_do_connect(t)) {
		return;
	}
	TUNNEL_LOG(WARNING, t, "connect failed, scheduling retry");
	tunnel_schedule_reconnect(t);
}

static const struct mux_session_config *tunnel_conf(const struct tunnel *t)
{
	return mux_conf(t->ss);
}

/* Dirty disconnect on a dialed tunnel: reconnect immediately (attempt 0)
 * before backoff, unless the tunnel is shutting down (a reload drained its
 * removed slot) or demand-triggered reconnect is in use. */
static void handle_transport_lost(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL || t->shutting_down ||
	    tunnel_conf(t)->idle_timeout != 0) {
		return;
	}
	TUNNEL_LOG(INFO, t, "transport lost, reconnecting");
	ev_timer_stop(t->loop, &t->w_reconnect);
	TPUB_ADD(t->error_cnt.num_reconnects, 1);
	if (!tunnel_do_connect(t)) {
		TUNNEL_LOG(WARNING, t, "connect failed, scheduling retry");
		tunnel_schedule_reconnect(t);
	}
}

static void tunnel_set_tag_part(
	char *restrict buf, const size_t buflen, const char *restrict text)
{
	const int ret = snprintf(buf, buflen, "%s", text);
	if (ret < 0) {
		buf[0] = '\0';
	}
}

/* The tag prefixes every log record this session emits, and either half of it
 * may be an identity -- the peer's is only NUL-excluded by doc/spec.md 5.2.3.2,
 * so a claim holding CR/LF or ESC would forge records through every one of
 * them.  Escape both halves here, the single point where the tag is built. */
static void tunnel_set_tag(
	char *restrict tag, const size_t taglen, const char *restrict my,
	const char *restrict arrow, const char *restrict peer)
{
	char my_esc[IDENTITY_ESCAPED_MAX];
	char peer_esc[IDENTITY_ESCAPED_MAX];
	escape_identity(my_esc, sizeof(my_esc), my, ESCAPE_PLAIN);
	escape_identity(peer_esc, sizeof(peer_esc), peer, ESCAPE_PLAIN);
	const int ret =
		snprintf(tag, taglen, "%s%s%s", my_esc, arrow, peer_esc);
	if (ret < 0) {
		tag[0] = '\0';
	}
}

static void handle_connected(
	struct tunnel *restrict t, struct mux_session *restrict ss,
	const union mux_event_data edata)
{
	t->reconnect_count = 0;

	free(t->peer_identity);
	/* The peer's claimed identity (from its hello), distinct from t->peer_id
	 * (the immutable local label set at tunnel creation). */
	const char *const peer_identity = edata.connected.peer_identity;
	t->peer_identity = peer_identity != NULL ? strdup(peer_identity) : NULL;
	if (peer_identity != NULL && t->peer_identity == NULL) {
		LOGOOM();
	}

	/* Rebuild the diagnostic tag once the peer identity is known; skipped when
	 * the peer sent no identity (the connect-time "=> ?" tag is retained). */
	if (peer_identity != NULL) {
		if (t->accepted) {
			/* Update tag for accepted identity sessions; runs on the
			 * session thread.  The parent's verify_peer callback
			 * provides thread-safe identity table lookup. */
			const bool matched = t->relay.parent.verify_peer(
				t->relay.parent.user, peer_identity);
			/* t->identity is conf->identity.claim frozen at creation
			 * and may be NULL (accepted before any identity was
			 * configured, then a reload added one); guard it like the
			 * dialed branch does -- passing NULL to "%s" is UB. */
			const char *const my =
				(matched && t->identity != NULL) ? t->identity :
								   "?";
			tunnel_set_tag(
				t->tag, sizeof(t->tag), my,
				" <= ", peer_identity);
		} else {
			/* server.c server_on_established wires
			 * identities[].tunnels[]; here we just update the tag. */
			char my[64];
			if (t->identity != NULL) {
				tunnel_set_tag_part(
					my, sizeof(my), t->identity);
			} else {
				union sockaddr_max addr;
				if (socket_get_addr(mux_fd(ss), &addr)) {
					(void)sa_format(
						my, sizeof(my), &addr.sa);
				} else {
					tunnel_set_tag_part(
						my, sizeof(my), "?");
				}
			}
			tunnel_set_tag(
				t->tag, sizeof(t->tag), my, " => ",
				peer_identity);
		}
	}
	/* Publish tag + peer_identity for the server thread's stats path. */
	tunnel_publish_pub(t);
}

/* Returns false when the event should not be relayed to the server: the
 * tunnel persists locally and reconnects later instead of being torn down,
 * either via the backoff timer or, for idle_timeout tunnels, on demand. */
static bool handle_closed(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL || t->shutting_down) {
		ev_timer_stop(t->loop, &t->w_reconnect);
		return true;
	}
	if (tunnel_conf(t)->idle_timeout != 0) {
		/* On-demand tunnel: no backoff timer; tunnel_open_fd()
		 * redials on the next inbound connection. */
		ev_timer_stop(t->loop, &t->w_reconnect);
		return false;
	}
	/* Both clean and dirty closes schedule a backoff reconnect; no
	 * immediate attempt to avoid CLOSED-event busy loops. */
	tunnel_schedule_reconnect(t);
	return false;
}

static void handle_stream_established(struct tunnel *t, int_fast64_t lat_ns)
{
	const size_t count = TPUB_LOAD(t->stream_establish_count);
	const size_t idx = count % ARRAY_SIZE(t->stream_establish_ns);
	TPUB_STORE(t->stream_establish_ns[idx], lat_ns);
	TPUB_STORE(t->stream_establish_count, count + 1);
}

static void tunnel_on_event(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	struct tunnel *restrict t = data;

	/* Update reconnect state before relaying to the server loop. */
	switch (event) {
	case MUX_EVENT_LOST:
		TPUB_STORE(t->last_changed, clock_monotonic_ns());
		break;
	case MUX_EVENT_SUSPENDED:
		handle_transport_lost(t);
		break;
	case MUX_EVENT_ESTABLISHED:
	case MUX_EVENT_RESUMED:
		/* Both bring the transport up: stamp last_changed and run the
		 * connected handler. (RESUMED previously skipped the stamp,
		 * freezing tunnel_stats' last_changed at the pre-LOST time.) */
		TPUB_STORE(t->last_changed, clock_monotonic_ns());
		handle_connected(t, ss, edata);
		break;
	case MUX_EVENT_STREAM_ESTABLISHED:
		handle_stream_established(t, edata.stream_established.ns);
		return;
	case MUX_EVENT_CLOSED:
		if (!handle_closed(t)) {
			return;
		}
		break;
	default:
		break;
	}

	if (event == MUX_EVENT_ESTABLISHED) {
		relay_connected(
			t, t->relay.cb.on_established, edata.connected.ns);
		return;
	}
	if (event == MUX_EVENT_RESUMED) {
		relay_connected(t, t->relay.cb.on_resumed, edata.connected.ns);
		return;
	}

#if WITH_THREADS
	if (t->relay.cb.on_event != NULL &&
	    !atomic_load_explicit(
		    &t->relay_disconnected, memory_order_relaxed)) {
		struct relay_event_arg *restrict arg = malloc(sizeof(*arg));
		if (arg == NULL) {
			LOGOOM();
			return;
		}
		*arg = (struct relay_event_arg){
			.t = t,
			.event = event,
			.data = edata,
		};
		const bool posted = t->relay.parent.post_task(
			t->relay.parent.user,
			(struct task){
				.func = relay_dispatch_on_event,
				.data = arg,
			});
		if (!posted) {
			/* Unrecoverable for MUX_EVENT_CLOSED: the tunnel thread
			 * exits right after, so nothing re-posts it and the
			 * server never runs handle_closed for this tunnel --
			 * an accepted tunnel stays in accepted_tunnels and a
			 * dialed identity tunnel wedges its staging slot until
			 * the next peers-changed reload. Log loudly; the
			 * sibling tunnel_post sites all do. */
			TUNNEL_LOG_F(
				ERROR, t,
				"failed to dispatch relay event %d (queue full)",
				(int)event);
			free(arg);
			return;
		}
	}
#else /* WITH_THREADS */
	if (t->relay.cb.on_event != NULL) {
		t->relay.cb.on_event(t->callback_data, t, event, edata);
	}
#endif /* WITH_THREADS */
}

/* Open one accepted local connection as a new stream.  Runs on this tunnel's
 * own thread (or inline without threads); the caller guarantees t->ss is live. */
static void tunnel_open_fd(struct tunnel *restrict t, const int fd)
{
	struct mux_stream *const stream = mux_stream_open(t->ss);
	if (stream == NULL) {
		/* Demand-triggered reconnect: when idle-closed/suspended with
		 * idle_timeout set, reconnect so the next open_stream succeeds.
		 * Suppressed once shutting_down: a reload that removed this slot
		 * must not redial the now-stale connect_addr. */
		if (!t->shutting_down && t->connect_addr != NULL &&
		    tunnel_conf(t)->idle_timeout > 0 &&
		    !ev_is_active(&t->w_reconnect) &&
		    (mux_state(t->ss) == MUX_STATE_SUSPENDED ||
		     mux_state(t->ss) == MUX_STATE_CLOSED)) {
			if (!tunnel_do_connect(t)) {
				tunnel_schedule_reconnect(t);
			}
		}
		TUNNEL_LOG_F(
			DEBUG, t, "[fd:%d] session not ready, closing", fd);
		socket_close(fd);
		return;
	}
	/* Start reading from local socket immediately.  One frame may be read
	 * before the SYN is sent and piggybacked as SYN|PUSH (fast open). */
	mux_stream_attach_fd(stream, fd);
	TUNNEL_LOG_F(
		DEBUG, t, "[fd:%d] new stream %" PRIuLEAST16, fd,
		mux_stream_id(stream));
}

#if WITH_THREADS
/* Detach the queued opens and either open each (session live) or close it
 * (session already torn down earlier in this async tick).  Runs on the tunnel
 * thread. */
static void tunnel_drain_pending_opens(struct tunnel *restrict t)
{
	THRD_ASSERT(mtx_lock(&t->open_mu));
	struct pending_open *node = t->open_head;
	t->open_head = t->open_tail = NULL;
	THRD_ASSERT(mtx_unlock(&t->open_mu));
	while (node != NULL) {
		struct pending_open *const restrict next = node->next;
		if (t->ss != NULL) {
			tunnel_open_fd(t, node->fd);
		} else {
			socket_close(node->fd);
		}
		free(node);
		node = next;
	}
}

static void tunnel_async_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	(void)loop;
	(void)revents;
	struct tunnel *const restrict t = w->data;
	dispatcher_tick(t->disp);
	/* After the ring: a queued task may have been task_tunnel_teardown, which
	 * clears t->ss, so the drain must tolerate a torn-down session. */
	tunnel_drain_pending_opens(t);
}

static int tunnel_thread(void *arg)
{
	struct tunnel *const restrict t = arg;
	/* Seed this thread's own PRNG. rand64()/frand() keep xoshiro256** state in
	 * thread-local storage and only the main thread ever called srand64(), so
	 * without this every tunnel thread would replay the identical frand()
	 * sequence -- collapsing the reconnect-backoff jitter (and session.c's
	 * keepalive jitter) that exists to de-correlate tunnels. Mix the unique
	 * tunnel_index (via the golden-ratio odd constant) with a monotonic clock
	 * so threads started at the same instant still get distinct seeds. */
	srand64((uint_fast64_t)clock_monotonic_ns() ^
		((uint_fast64_t)t->tunnel_index *
		 UINT64_C(0x9E3779B97F4A7C15)));
	ev_run(t->loop, 0);
	/* If ev_run exits before task_tunnel_teardown is dispatched, drain it
	 * here so mux_close/free(ss) always run on the allocating thread. */
	dispatcher_tick(t->disp);
	return 0;
}
#endif /* WITH_THREADS */

/* Enqueue a task on this tunnel's own loop/thread, reporting whether it was
 * accepted. The queue is bounded (a fixed-capacity ring), so dispatcher_invoke
 * returns false when it is full — i.e. the tunnel thread is slow to drain it;
 * callers own the task's heap payload, if any, and must free it and report the
 * failure rather than leak or assert. Runs inline without threads. */
static bool tunnel_post(struct tunnel *restrict t, struct task task)
{
#if WITH_THREADS
	if (!dispatcher_invoke(t->disp, task)) {
		return false;
	}
	ev_async_send(t->loop, &t->w_async);
	return true;
#else /* WITH_THREADS */
	(void)t;
	task.func(task.data);
	return true;
#endif /* WITH_THREADS */
}

#if WITH_THREADS
/* Carries a detached transport to the suspended tunnel's own loop/thread. */
struct resume_attach_arg {
	struct tunnel *old_t;
	struct mux_transport transport;
	uint_least32_t resume_seq;
};

static void tunnel_resume_attach_task(void *p)
{
	struct resume_attach_arg *restrict arg = p;
	/* Runs on old_t's own loop/thread. old_t is NOT pinned while this runs --
	 * on_resume_unpin releases the accepted_mu shared lock right after the post
	 * that enqueued this task. Safety rests on FIFO ordering instead: tearing
	 * old_t down first removes it from accepted_tunnels under accepted_mu
	 * *exclusive*, which cannot proceed until the shared lock this post ran
	 * under is released, so the teardown task is enqueued strictly after this
	 * attach task in old_t's queue -- old_t->ss is still live here. */
	mux_resume_attach(arg->old_t->ss, &arg->transport, arg->resume_seq);
	free(arg);
}
#endif /* WITH_THREADS */

/* Move a detached transport onto the suspended tunnel old_t and resume it.
 * The attach must run on old_t's own loop, so post it there.  Always consumes
 * @p transport. */
static void tunnel_handoff_resume(
	struct tunnel *restrict old_t, struct mux_transport *restrict transport,
	const uint_least32_t resume_seq)
{
#if WITH_THREADS
	struct resume_attach_arg *restrict arg = malloc(sizeof(*arg));
	if (arg != NULL) {
		*arg = (struct resume_attach_arg){
			.old_t = old_t,
			.transport = *transport,
			.resume_seq = resume_seq,
		};
		if (tunnel_post(
			    old_t,
			    (struct task){ tunnel_resume_attach_task, arg })) {
			return;
		}
		free(arg);
	} else {
		LOGOOM();
	}
	/* Hand-off failed: drop the transport.  old_t stays suspended and recovers
	 * on its own resume timeout. */
	mux_transport_discard(transport);
#else /* WITH_THREADS */
	mux_resume_attach(old_t->ss, transport, resume_seq);
#endif /* WITH_THREADS */
}

/* mux on_verify_identity: enforce identity.verify.  A peer that claims an
 * identity must present a certificate naming it (spec Section 10.1); a peer
 * claiming none is left unidentified, which is the behavior without this
 * option, and reaches only the root forwarding target. */
static bool tunnel_on_verify_identity(
	void *data, struct mux_session *ss, const char *identity)
{
	const struct tunnel *restrict t = data;
#if WITH_TLS
	/* PSK mode binds identity without a switch: the binder already proved
	 * the peer holds the key its label names, so all that remains is to
	 * confirm the claim agrees with the peer that actually authenticated.
	 * A peer claiming nothing stays unidentified, as in certificate mode. */
	if (t->psk_identity_of != NULL) {
		if (identity == NULL) {
			return true;
		}
		struct tls_connection *const conn = mux_tls_conn(ss);
		char label[TLS_PSK_LABEL_MAX + 1];
		size_t label_len = sizeof(label);
		if (conn == NULL ||
		    !tls_peer_psk_label(conn, label, &label_len)) {
			char esc[IDENTITY_ESCAPED_MAX];
			escape_identity(
				esc, sizeof(esc), identity, ESCAPE_PLAIN);
			LOGE_F("[fd:%d] identity \"%s\" cannot be verified:"
			       " session did not authenticate with a PSK",
			       tunnel_fd(t), esc);
			return false;
		}
		const char *const owner = t->psk_identity_of(t->psk_ctx, label);
		if (owner == NULL || strcmp(owner, identity) != 0) {
			char esc[IDENTITY_ESCAPED_MAX];
			escape_identity(
				esc, sizeof(esc), identity, ESCAPE_PLAIN);
			LOGE_F("[fd:%d] peer claims identity \"%s\" but"
			       " authenticated with the key of \"%s\"",
			       tunnel_fd(t), esc,
			       owner != NULL ? owner : "(unknown)");
			return false;
		}
		return true;
	}
#endif /* WITH_TLS */
	if (!t->verify_identity || identity == NULL) {
		return true;
	}
#if WITH_TLS
	struct tls_connection *const conn = mux_tls_conn(ss);
	if (conn == NULL) {
		/* conf validation rejects identity.verify without TLS creds, so
		 * reaching a plaintext session here would mean the option is
		 * silently doing nothing.  Fail closed instead. */
		char esc[IDENTITY_ESCAPED_MAX];
		escape_identity(esc, sizeof(esc), identity, ESCAPE_PLAIN);
		LOGE_F("[fd:%d] identity \"%s\" cannot be verified: session is"
		       " not using TLS",
		       tunnel_fd(t), esc);
		return false;
	}
	if (!identity_matches_cert(conn, identity)) {
		char esc[IDENTITY_ESCAPED_MAX];
		escape_identity(esc, sizeof(esc), identity, ESCAPE_PLAIN);
		LOGE_F("[fd:%d] peer claims identity \"%s\" but its certificate"
		       " does not name it",
		       tunnel_fd(t), esc);
		return false;
	}
	return true;
#else /* WITH_TLS */
	(void)ss;
	char esc[IDENTITY_ESCAPED_MAX];
	escape_identity(esc, sizeof(esc), identity, ESCAPE_PLAIN);
	LOGE_F("[fd:%d] identity \"%s\" cannot be verified: built without TLS",
	       tunnel_fd(t), esc);
	return false;
#endif /* WITH_TLS */
}

/* True when identity.verify permits attaching new_ss's transport to old_t: the
 * identity claimed on the new transport must equal the one the session being
 * resumed already carries, with both-absent counting as equal.
 *
 * The new claim was already checked against this transport's certificate at
 * hello time (tunnel_on_verify_identity, which runs before the resume handoff),
 * so requiring equality here is what stops a resume from carrying a session's
 * verified identity onto a transport that never proved it -- including a resume
 * hello that drops the identity extension entirely.
 *
 * The claim is read from the session rather than old_t's published snapshot:
 * that snapshot is only refreshed on MUX_EVENT_CONNECTED, which has not fired
 * for new_ss yet.  old_t's snapshot is pinned by the caller's lookup and is
 * pub-locked, so reading it from this thread is safe.
 *
 * Must run before mux_transport_detach(), which moves new_ss's identity onto
 * the transport and leaves NULL behind; afterwards this would compare against
 * an absent claim.  Requiring equality here is also what keeps that move safe
 * under identity.verify: the identity the resumed session adopts is then the
 * one just proved against the certificate on the new transport. */
static bool tunnel_resume_identity_ok(
	const struct tunnel *restrict t,
	const struct mux_session *restrict new_ss,
	const struct tunnel *restrict old_t)
{
	if (!t->verify_identity) {
		return true;
	}
	const char *const claimed = mux_peer_identity(new_ss);
	char resumed[256];
	const bool has_resumed =
		tunnel_peer_identity_copy(old_t, resumed, sizeof(resumed));
	const bool ok = has_resumed == (claimed != NULL) &&
			(claimed == NULL || strcmp(claimed, resumed) == 0);
	if (!ok) {
		LOGW_F("[fd:%d] resume rejected: claimed identity does not match"
		       " the session being resumed",
		       tunnel_fd(t));
	}
	return ok;
}

/* mux on_resume: a resume hello arrived on the transient session new_ss.  Find
 * the suspended tunnel, detach new_ss's transport and hand it off, returning
 * true so the mux layer tears new_ss down. */
static bool tunnel_on_resume(
	void *data, struct mux_session *new_ss, const unsigned char *session_id,
	const uint_least32_t resume_seq)
{
	struct tunnel *restrict t = data;
	if (t->relay.cb.on_resume_lookup == NULL) {
		return false;
	}
	struct tunnel *restrict old_t =
		t->relay.cb.on_resume_lookup(t->callback_data, t, session_id);
	if (old_t != NULL && !tunnel_resume_identity_ok(t, new_ss, old_t)) {
		/* Release the pin the lookup took before dropping the match, so
		 * the unpin stays paired one-to-one with a non-NULL lookup. */
		if (t->relay.cb.on_resume_unpin != NULL) {
			t->relay.cb.on_resume_unpin(t->callback_data, t);
		}
		old_t = NULL;
	}
	bool handled = false;
	if (old_t != NULL) {
		struct mux_transport transport;
		mux_transport_detach(new_ss, &transport);
		tunnel_handoff_resume(old_t, &transport, resume_seq);
		if (t->relay.cb.on_resume_unpin != NULL) {
			t->relay.cb.on_resume_unpin(t->callback_data, t);
		}
		handled = true;
	}
	return handled;
}

static struct mux_frame *tunnel_frame_alloc(void *data, const size_t size)
{
	struct mcache *const restrict cache = data;
	ASSERT(size == cache->elem_size);
	(void)size;
	return mcache_get(cache);
}

static void tunnel_frame_free(void *data, struct mux_frame *frame)
{
	mcache_put(data, frame);
}

static void
tunnel_maintenance_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct tunnel *const restrict t = w->data;
	ASSERT(loop == t->loop);
	(void)loop;
	/* Release one cached frame per tick: a steady stream keeps refilling the
	 * cache, while an idle tunnel drains it back to malloc over time. */
	mcache_shrink(t->frame_cache, 1);
}

/* Tear down a partially-initialized tunnel on any tunnel_new failure exit
 * after `t` was allocated; safe at any point since t is calloc-zeroed.
 * owns_fd_conn is false once mux_new has taken fd/conn ownership (mux.h). */
static void tunnel_new_cleanup(
	struct tunnel *restrict t, struct mux_session *restrict ss,
	const bool owns_fd_conn, const struct tunnel_opts *restrict opts)
{
	if (ss != NULL) {
		mux_close(ss);
	}
	if (t->loop != NULL) {
		ev_timer_stop(t->loop, &t->w_maintenance);
#if WITH_THREADS
		ev_async_stop(t->loop, &t->w_async);
#endif
	}
	if (t->frame_cache != NULL) {
		mcache_free(t->frame_cache);
	}
#if WITH_THREADS
	if (t->disp != NULL) {
		dispatcher_destroy(t->disp);
	}
	if (t->loop != NULL) {
		ev_loop_destroy(t->loop);
	}
#endif
	free(t->forward_addr);
	free(t->connect_addr);
	free(t->identity);
	free(t->peer_id);
	free(t);
	if (owns_fd_conn) {
		if (opts->fd >= 0) {
			socket_close(opts->fd);
		}
#if WITH_TLS
		tls_conn_free(opts->conn);
#endif
	}
}

struct tunnel *tunnel_new(
	const struct tunnel_context *parent,
	const struct tunnel_opts *restrict opts)
{
	const struct tunnel_callbacks *const cb = opts->cb;
	void *const data = opts->data;
	const struct mux_session_config *const conf = opts->mux_conf;
	const int fd = opts->fd;
	const unsigned char *const id = opts->id;
	const char *const connect_addr = opts->connect_addr;
	const char *const forward_addr = opts->forward_addr;
	const char *const identity = opts->identity;
	const char *const peer_id = opts->peer_id;
	const struct tunnel_session_counters *const cnt = opts->cnt;
#if WITH_TLS
	struct tls_context *const tlsctx = opts->tlsctx;
	struct tls_connection *const conn = opts->conn;
#endif

	struct tunnel *restrict t = calloc(1, sizeof(struct tunnel));
	if (t == NULL) {
		if (fd >= 0) {
			socket_close(fd);
		}
#if WITH_TLS
		tls_conn_free(conn);
#endif
		return NULL;
	}
	t->relay.parent = *parent;
	t->relay.cb = *cb;
	t->callback_data = data;
	t->forward_addr = forward_addr != NULL ? strdup(forward_addr) : NULL;
	t->connect_addr = connect_addr != NULL ? strdup(connect_addr) : NULL;
	TPUB_STORE(t->last_changed, clock_monotonic_ns());
	t->reconnect_count = 0;
	t->shutting_down = false;
	t->accepted = (fd >= 0);
	t->identity = identity != NULL ? strdup(identity) : NULL;
	t->peer_id = peer_id != NULL ? strdup(peer_id) : NULL;
	t->peer_identity = NULL;
	if ((forward_addr != NULL && t->forward_addr == NULL) ||
	    (connect_addr != NULL && t->connect_addr == NULL) ||
	    (identity != NULL && t->identity == NULL) ||
	    (peer_id != NULL && t->peer_id == NULL)) {
		LOGOOM();
		tunnel_new_cleanup(t, NULL, true, opts);
		return NULL;
	}
	t->tunnel_index = parent->alloc_index(parent->user);
	t->mux_socket = opts->mux_socket;
	t->local_socket = opts->local_socket;
#if WITH_TLS
	/* Adopt ownership of the client TLS context (NULL for accepted/plaintext);
	 * the mux session below borrows it.  Unlike opts->fd/opts->conn (which
	 * tunnel_new always fully owns, including on failure - see below), a
	 * tunnel_new failure leaves opts->tlsctx owned by the caller: it may be a
	 * shared, ref-counted handle the caller still needs for other tunnels. */
	t->tlsctx = tlsctx;
#endif
	t->verify_identity = opts->verify_identity;
	t->psk_identity_of = opts->psk_identity_of;
	t->psk_ctx = opts->psk_ctx;
	t->cb = (struct mux_callbacks){
		.on_accept = tunnel_on_accept,
		.on_event = tunnel_on_event,
		.on_verify_identity = tunnel_on_verify_identity,
		.on_resume =
			cb->on_resume_lookup != NULL ? tunnel_on_resume : NULL,
	};
#if WITH_THREADS
	t->started = false;
	t->loop = ev_loop_new(EVFLAG_AUTO);
	if (t->loop == NULL) {
		tunnel_new_cleanup(t, NULL, true, opts);
		return NULL;
	}
	t->disp = dispatcher_create(16);
	if (t->disp == NULL) {
		tunnel_new_cleanup(t, NULL, true, opts);
		return NULL;
	}
	ev_async_init(&t->w_async, tunnel_async_cb);
	t->w_async.data = t;
	ev_async_start(t->loop, &t->w_async);
#else /* WITH_THREADS */
	t->loop = parent->loop;
#endif /* WITH_THREADS */
	ev_timer_init(
		&t->w_reconnect, tunnel_reconnect_cb, 0.0,
		tunnel_reconnect_delays[0]);
	t->w_reconnect.data = t;
	/* Per-tunnel L1 allocator: a fixed-size frame cache (mcache) over malloc,
	 * each object sized to the session's frame payload. conf_load_mux()
	 * always clamps this to at least MUX_MIN_FRAME_PAYLOAD, so no fallback
	 * is needed here. */
	const size_t frame_obj_size =
		mux_frame_object_size((size_t)conf->max_frame_payload);
	t->frame_cache = mcache_new(TUNNEL_FRAME_CACHE_SIZE, frame_obj_size);
	if (t->frame_cache == NULL) {
		LOGOOM();
		tunnel_new_cleanup(t, NULL, true, opts);
		return NULL;
	}
	ev_timer_init(
		&t->w_maintenance, tunnel_maintenance_cb,
		TUNNEL_MAINTENANCE_INTERVAL, TUNNEL_MAINTENANCE_INTERVAL);
	t->w_maintenance.data = t;
	ev_timer_start(t->loop, &t->w_maintenance);
	const struct mux_frame_allocator pool = {
		.alloc = tunnel_frame_alloc,
		.free = tunnel_frame_free,
		.data = t->frame_cache,
	};
	{
		char my[64];
		char peer[64];
		if (fd >= 0) {
			/* Accepted session: peer addr from socket; my from
			 * identity, then local socket address. */
			{
				union sockaddr_max addr;
				if (socket_get_peer(fd, &addr)) {
					(void)sa_format(
						peer, sizeof(peer), &addr.sa);
				} else {
					tunnel_set_tag_part(
						peer, sizeof(peer), "?");
				}
			}
			if (identity != NULL) {
				tunnel_set_tag_part(my, sizeof(my), identity);
			} else {
				union sockaddr_max addr;
				if (socket_get_addr(fd, &addr)) {
					(void)sa_format(
						my, sizeof(my), &addr.sa);
				} else {
					tunnel_set_tag_part(
						my, sizeof(my), "?");
				}
			}
		} else {
			/* Dialed session: my from identity; peer from
			 * connect_addr (always prefer over peer_id). */
			tunnel_set_tag_part(
				my, sizeof(my),
				identity != NULL ? identity : "?");
			tunnel_set_tag_part(
				peer, sizeof(peer),
				connect_addr != NULL ? connect_addr : "?");
		}
		const char *const arrow = (fd >= 0) ? " <= " : " => ";
		tunnel_set_tag(t->tag, sizeof(t->tag), my, arrow, peer);
	}
	const struct mux_session_opts ss_opts = {
		.callbacks = &t->cb,
		.userdata = t,
		.conf = conf,
		.pool = pool,
		.tag = t->tag,
		.fd = fd,
		.id = id,
		.identity = identity,
		.peer_id = peer_id,
		.cnt = {
			.session = {
				.num_session_created =
					cnt->num_session_created,
				.num_session_connect =
					cnt->num_session_connect,
				.num_session_connected =
					cnt->num_session_connected,
				.num_session_disconnected =
					cnt->num_session_disconnected,
				.num_session_finalized =
					cnt->num_session_finalized,
				.num_sessions = cnt->num_sessions,
				.num_session_halfopen =
					cnt->num_session_halfopen,
			},
			.stream = {
				.num_streams = &t->stream_cnt.num_streams,
				.num_stream_halfopen =
					&t->stream_cnt.num_stream_halfopen,
				.num_stream_opened =
					&t->stream_cnt.num_stream_opened,
				.num_stream_accepted =
					&t->stream_cnt.num_stream_accepted,
				.num_stream_fastopen =
					&t->stream_cnt.num_stream_fastopen,
				.num_stream_established =
					&t->stream_cnt.num_stream_established,
				.num_stream_succeeded =
					&t->stream_cnt.num_stream_succeeded,
				.num_stream_failed =
					&t->stream_cnt.num_stream_failed,
			},
			.errors = {
				.num_rst_sent = &t->error_cnt.num_rst_sent,
				.num_rst_recv = &t->error_cnt.num_rst_recv,
				.num_stream_errors =
					&t->error_cnt.num_stream_errors,
			},
			.buffers = {
				.recv_buffered_bytes =
					&t->buf_gauge.recv_buffered_bytes,
				.send_buffered_frames =
					&t->buf_gauge.send_buffered_frames,
				.unacked_frames =
					&t->buf_gauge.unacked_frames,
			},
			.traffic = {
				.byt_mux_recv = &t->traffic_cnt.byt_mux_recv,
				.byt_mux_sent = &t->traffic_cnt.byt_mux_sent,
				.byt_push_recv = &t->traffic_cnt.byt_push_recv,
				.byt_push_sent = &t->traffic_cnt.byt_push_sent,
			},
		},
#if WITH_TLS
		.tlsctx = tlsctx,
		.conn = conn,
#endif
	};
	struct mux_session *const restrict ss = mux_new(t->loop, &ss_opts);
	if (ss == NULL) {
		/* mux_new takes ownership of fd/conn on both success and
		 * failure (mux.h), so owns_fd_conn is false from here on. */
		tunnel_new_cleanup(t, NULL, false, opts);
		return NULL;
	}
#if WITH_THREADS
	/* Init the mutexes last so the failure paths above need no mtx_destroy;
	 * only tunnel_close pairs with these. */
	if (mtx_init(&t->pub.mu, mtx_plain) != thrd_success) {
		tunnel_new_cleanup(t, ss, false, opts);
		return NULL;
	}
	if (mtx_init(&t->open_mu, mtx_plain) != thrd_success) {
		mtx_destroy(&t->pub.mu);
		tunnel_new_cleanup(t, ss, false, opts);
		return NULL;
	}
#endif /* WITH_THREADS */
	t->ss = ss;
	/* Publish the creation-time tag for the stats path before the thread runs. */
	tunnel_publish_pub(t);
	return t;
}

static void task_mux_start(void *p)
{
	mux_start(p);
}

static void tunnel_initial_connect_task(void *p)
{
	struct tunnel *const restrict t = p;
	if (!tunnel_do_connect(t)) {
		tunnel_schedule_reconnect(t);
	}
}

bool tunnel_start(struct tunnel *t)
{
#if WITH_THREADS
	/* thrd_create fails for real under load (thrd_nomem), so this cannot be a
	 * THRD_ASSERT: that is a plain assert, compiled out of every shipped build
	 * (-DNDEBUG), which would leave the tunnel marked started with no thread
	 * behind it -- queued tasks never running while the server treats it as
	 * live, and tunnel_close later joining a calloc-zeroed thrd_t. Leaving
	 * started false instead routes tunnel_close to its "thread never started"
	 * path, and there is no thread to run the startup dispatches below. The
	 * false return lets the caller unregister and tunnel_close() the tunnel so
	 * it is not left registered-but-dead for the life of the process. */
	const int ret = thrd_create(&t->thread, tunnel_thread, t);
	if (ret != thrd_success) {
		/* thrd_nomem is the transient case worth naming; the bare
		 * enumerator is implementation-defined and means nothing to an
		 * operator reading the log. */
		if (ret == thrd_nomem) {
			TUNNEL_LOG(
				ERROR, t,
				"failed to create tunnel thread (OOM)");
		} else {
			TUNNEL_LOG_F(
				ERROR, t,
				"failed to create tunnel thread (thrd error %d)",
				ret);
		}
		return false;
	}
	t->started = true;
#endif /* WITH_THREADS */
	/* task_mux_start/tunnel_initial_connect_task carry no separate heap
	 * payload (just t/t->ss), so a failed dispatch has nothing to free --
	 * only report it. */
	if (!tunnel_post(t, (struct task){ task_mux_start, t->ss })) {
		TUNNEL_LOG(ERROR, t, "failed to dispatch startup (queue full)");
	}
	if (t->connect_addr != NULL &&
	    !tunnel_post(t, (struct task){ tunnel_initial_connect_task, t })) {
		TUNNEL_LOG(
			ERROR, t,
			"failed to dispatch initial connect (queue full)");
	}
	return true;
}

#if WITH_THREADS
/* Final dispatched task on the tunnel thread: suppress callbacks, close
 * session, stop event loop.  Clears t->ss so tunnel_close knows it ran. */
static void task_tunnel_teardown(void *p)
{
	struct tunnel *const restrict t = p;
	ev_timer_stop(t->loop, &t->w_reconnect);
	ev_timer_stop(t->loop, &t->w_maintenance);
	mux_set_callbacks(t->ss, &(struct mux_callbacks){ 0 });
	mux_close(t->ss);
	t->ss = NULL;
	ev_async_stop(t->loop, &t->w_async);
}
#endif /* WITH_THREADS */

/* The single place the monotonic counters are loaded from their storage, so
 * tunnel_stats() and tunnel_close_final() cannot drift on which of them are
 * atomic mirrors and which are published under the pub lock.  Touches no mux
 * session state, so it stays valid after the session is closed. */
static void tunnel_load_counters(
	const struct tunnel *restrict t,
	struct tunnel_final_counters *restrict out)
{
#if WITH_THREADS
	out->num_stream_opened = (uint_least64_t)atomic_load_explicit(
		&t->stream_cnt.num_stream_opened, memory_order_relaxed);
	out->num_stream_accepted = (uint_least64_t)atomic_load_explicit(
		&t->stream_cnt.num_stream_accepted, memory_order_relaxed);
	out->num_stream_fastopen = (uint_least64_t)atomic_load_explicit(
		&t->stream_cnt.num_stream_fastopen, memory_order_relaxed);
	out->num_stream_established = (uint_least64_t)atomic_load_explicit(
		&t->stream_cnt.num_stream_established, memory_order_relaxed);
	out->num_stream_succeeded = (uint_least64_t)atomic_load_explicit(
		&t->stream_cnt.num_stream_succeeded, memory_order_relaxed);
	out->num_stream_failed = (uint_least64_t)atomic_load_explicit(
		&t->stream_cnt.num_stream_failed, memory_order_relaxed);
	out->byt_mux_recv = (uint_least64_t)atomic_load_explicit(
		&t->traffic_cnt.byt_mux_recv, memory_order_relaxed);
	out->byt_mux_sent = (uint_least64_t)atomic_load_explicit(
		&t->traffic_cnt.byt_mux_sent, memory_order_relaxed);
	out->byt_push_recv = (uint_least64_t)atomic_load_explicit(
		&t->traffic_cnt.byt_push_recv, memory_order_relaxed);
	out->byt_push_sent = (uint_least64_t)atomic_load_explicit(
		&t->traffic_cnt.byt_push_sent, memory_order_relaxed);
#else /* WITH_THREADS */
	out->num_stream_opened = t->stream_cnt.num_stream_opened;
	out->num_stream_accepted = t->stream_cnt.num_stream_accepted;
	out->num_stream_fastopen = t->stream_cnt.num_stream_fastopen;
	out->num_stream_established = t->stream_cnt.num_stream_established;
	out->num_stream_succeeded = t->stream_cnt.num_stream_succeeded;
	out->num_stream_failed = t->stream_cnt.num_stream_failed;
	out->byt_mux_recv = t->traffic_cnt.byt_mux_recv;
	out->byt_mux_sent = t->traffic_cnt.byt_mux_sent;
	out->byt_push_recv = t->traffic_cnt.byt_push_recv;
	out->byt_push_sent = t->traffic_cnt.byt_push_sent;
#endif /* WITH_THREADS */
	out->num_reconnects = TPUB_LOAD(t->error_cnt.num_reconnects);
	out->num_rst_sent = TPUB_LOAD(t->error_cnt.num_rst_sent);
	out->num_rst_recv = TPUB_LOAD(t->error_cnt.num_rst_recv);
	out->num_stream_errors = TPUB_LOAD(t->error_cnt.num_stream_errors);
	out->stream_establish_count = TPUB_LOAD(t->stream_establish_count);
}

#if WITH_THREADS
/* Close every still-queued open and free its node.  Called once the tunnel
 * thread has stopped (or never started), when the pending connections can no
 * longer be served. */
static void tunnel_flush_pending_opens(struct tunnel *restrict t)
{
	struct pending_open *node = t->open_head;
	t->open_head = t->open_tail = NULL;
	while (node != NULL) {
		struct pending_open *const restrict next = node->next;
		socket_close(node->fd);
		free(node);
		node = next;
	}
}
#endif /* WITH_THREADS */

void tunnel_close_final(struct tunnel *t, struct tunnel_final_counters *out)
{
#if WITH_THREADS
	/* Disconnect the relay so any queued or in-flight relay tasks become
	 * no-ops.  Must precede the teardown dispatch to prevent new relay tasks. */
	atomic_store_explicit(
		&t->relay_disconnected, true, memory_order_relaxed);

	if (t->started) {
		/* Suppress mux callbacks, close session, stop event loop. Retry
		 * once: a concurrent free on another thread may let it succeed. */
		bool teardown_posted = tunnel_post(
			t, (struct task){ task_tunnel_teardown, t });
		if (!teardown_posted) {
			teardown_posted = tunnel_post(
				t, (struct task){ task_tunnel_teardown, t });
		}
		if (!teardown_posted) {
			/* thrd_join() below would hang the caller forever, since
			 * the worker loop has no other way to learn it should
			 * stop; detach and leave it running instead. */
			TUNNEL_LOG_PUB(
				ERROR, t,
				"failed to dispatch teardown after retry"
				" (queue full), abandoning tunnel thread");
			/* Sample before detaching: the abandoned thread keeps
			 * counting, and t is never freed, so this is the last
			 * point the caller can account for any of it. */
			if (out != NULL) {
				tunnel_load_counters(t, out);
			}
			THRD_ASSERT(thrd_detach(t->thread));
			return;
		}
		THRD_ASSERT(thrd_join(t->thread, NULL));
		/* If task_tunnel_teardown never ran (tunnel self-closed first),
		 * t->ss is still alive; free it here, safe after thrd_join. */
		if (t->ss != NULL) {
			mux_close(t->ss);
		}
		/* Flush the server dispatcher so this tunnel's already-queued relay
		 * tasks run now (freeing their arg allocations against a
		 * disconnected relay) before t is freed below -- otherwise they
		 * would later dereference a freed t. Note: flush_tasks
		 * (server_flush_tasks -> dispatcher_tick) drains the *whole* shared
		 * queue, not just t's tasks, so any other live tunnel's pending relay
		 * task also executes here. This is reentrant (server.c's
		 * handle_closed -> tunnel_close is itself invoked from
		 * dispatcher_tick) but safe:
		 * relay_disconnected plus the FIFO absorb duplicate events before any
		 * state-mutating code runs. Recursion depth is bounded by the number
		 * of concurrently pending relay tasks; a per-tunnel drain would need a
		 * filtering dispatcher variant (contrib/csnippets, read-only). */
		t->relay.parent.flush_tasks(t->relay.parent.user);
	} else {
		/* Thread never started; just release mux session resources. */
		ev_timer_stop(t->loop, &t->w_reconnect);
		ev_timer_stop(t->loop, &t->w_maintenance);
		mux_close(t->ss);
	}
	ev_async_stop(t->loop, &t->w_async);
	/* The tunnel thread is stopped (joined) or never ran, so no drain can race
	 * this: close any opens still queued -- they can no longer be served. */
	tunnel_flush_pending_opens(t);
	dispatcher_destroy(t->disp);
	ev_loop_destroy(t->loop);
#else /* WITH_THREADS */
	ev_timer_stop(t->loop, &t->w_reconnect);
	ev_timer_stop(t->loop, &t->w_maintenance);
	mux_close(t->ss);
#endif /* WITH_THREADS */
	/* After the join and every mux_close() path above, so the counters
	 * teardown bumped -- one num_stream_failed per stream still open -- are
	 * part of the sample.  The counters live in t, not in the session, so
	 * reading them here is safe although t->ss is already gone. */
	if (out != NULL) {
		tunnel_load_counters(t, out);
	}
	free(t->forward_addr);
	free(t->connect_addr);
	free(t->identity);
	free(t->peer_id);
	free(t->peer_identity);
#if WITH_TLS
	/* Safe after mux_close above: the session no longer borrows it. */
	tls_ctx_free(t->tlsctx);
#endif
#if WITH_THREADS
	mtx_destroy(&t->open_mu);
	mtx_destroy(&t->pub.mu);
#endif
	/* After mux_close: any frames released during teardown are now back in
	 * the cache, so it is safe to drop. */
	mcache_free(t->frame_cache);
	free(t);
}

void tunnel_close(struct tunnel *t)
{
	tunnel_close_final(t, NULL);
}

static void task_mux_shutdown(void *p)
{
	mux_shutdown(p);
}

static void task_set_shutting_down(void *p)
{
	struct tunnel *restrict t = p;
	t->shutting_down = true;
	ev_timer_stop(t->loop, &t->w_reconnect);
}

void tunnel_shutdown(struct tunnel *t)
{
	/* Both tasks carry no separate heap payload; attempt both regardless
	 * of the first outcome (matching a plain no-throw dispatch) and report
	 * each failure instead of leaking silently. */
	if (!tunnel_post(t, (struct task){ task_set_shutting_down, t })) {
		TUNNEL_LOG_PUB(
			ERROR, t, "failed to dispatch shutdown (queue full)");
	}
	if (!tunnel_post(t, (struct task){ task_mux_shutdown, t->ss })) {
		TUNNEL_LOG_PUB(
			ERROR, t, "failed to dispatch shutdown (queue full)");
	}
}

static void task_drop_transport(void *p)
{
	const struct tunnel *const restrict t = p;
	const int fd = mux_fd(t->ss);
	if (fd < 0) {
		return;
	}
	/* shutdown(), not close(): w_socket.fd is only closed by
	 * session_suspend/session_cleanup (session.h's w_socket contract);
	 * shutdown() still drives the mux layer to notice via EOF/error. */
	if (shutdown(fd, SHUT_RDWR) != 0) {
		const int err = errno;
		TUNNEL_LOG_F(
			DEBUG, t, "drop_transport shutdown: (%d) %s", err,
			strerror(err));
	}
}

void tunnel_drop_transport(struct tunnel *t)
{
	if (!tunnel_post(t, (struct task){ task_drop_transport, t })) {
		TUNNEL_LOG_PUB(
			ERROR, t,
			"failed to dispatch drop_transport (queue full)");
	}
}

int tunnel_fd(const struct tunnel *t)
{
	tunnel_pub_lock(t);
	const int fd = t->pub.fd;
	tunnel_pub_unlock(t);
	return fd;
}

enum mux_state tunnel_state(const struct tunnel *t)
{
	return mux_state(t->ss);
}

struct mux_session *tunnel_session(const struct tunnel *t)
{
	return t->ss;
}

const char *tunnel_peer_id(const struct tunnel *t)
{
	return t->peer_id;
}

bool tunnel_peer_identity_copy(
	const struct tunnel *t, char *restrict buf, const size_t buflen)
{
	tunnel_pub_lock(t);
	const bool has = t->pub.has_peer_identity;
	if (buflen > 0) {
		(void)snprintf(buf, buflen, "%s", t->pub.peer_identity);
	}
	tunnel_pub_unlock(t);
	return has;
}

bool tunnel_peer_addr_copy(
	const struct tunnel *t, struct sockaddr *restrict buf,
	const size_t buflen)
{
	tunnel_pub_lock(t);
	const bool has = t->pub.has_peer_addr;
	if (has && buflen > 0) {
		(void)memcpy(
			buf, &t->pub.peer_addr,
			MIN(buflen, sizeof(t->pub.peer_addr)));
	}
	tunnel_pub_unlock(t);
	return has;
}

bool tunnel_is_accepted(const struct tunnel *t)
{
	return t->accepted;
}

const unsigned char *tunnel_session_id(const struct tunnel *t)
{
	return mux_session_id(t->ss);
}

uint_least64_t tunnel_index(const struct tunnel *t)
{
	return t->tunnel_index;
}

void tunnel_stats(const struct tunnel *t, struct tunnel_stats *restrict out)
{
	/* mux_state/mux_session_stats read relaxed-atomic mirrors; safe here. */
	out->established = mux_state(t->ss) == MUX_STATE_ESTABLISHED;
	/* fixed at creation and never rewritten, so plain. */
	out->accepted = t->accepted;
	out->tunnel_index = t->tunnel_index;
	/* tag is a string, so copy it from the published snapshot under the lock. */
	tunnel_pub_lock(t);
	(void)memcpy(out->tag, t->pub.tag, sizeof(out->tag));
	tunnel_pub_unlock(t);
	struct mux_session_stats snap;
	mux_session_stats(t->ss, &snap);
	out->rx_window = snap.rx_window;
	out->tx_window = snap.tx_window;
	out->rtt_ns = snap.rtt;
	out->bdp_rx = snap.bdp_rx;
	out->bdp_tx = snap.bdp_tx;
	out->last_changed = TPUB_LOAD(t->last_changed);
#if WITH_THREADS
	out->num_streams = (size_t)atomic_load_explicit(
		&t->stream_cnt.num_streams, memory_order_relaxed);
	out->num_stream_halfopen = (size_t)atomic_load_explicit(
		&t->stream_cnt.num_stream_halfopen, memory_order_relaxed);
#else /* WITH_THREADS */
	out->num_streams = t->stream_cnt.num_streams;
	out->num_stream_halfopen = t->stream_cnt.num_stream_halfopen;
#endif /* WITH_THREADS */
	struct tunnel_final_counters cnt;
	tunnel_load_counters(t, &cnt);
	out->num_stream_opened = cnt.num_stream_opened;
	out->num_stream_accepted = cnt.num_stream_accepted;
	out->num_stream_fastopen = cnt.num_stream_fastopen;
	out->num_stream_established = cnt.num_stream_established;
	out->num_stream_succeeded = cnt.num_stream_succeeded;
	out->num_stream_failed = cnt.num_stream_failed;
	out->num_reconnects = cnt.num_reconnects;
	out->num_rst_sent = cnt.num_rst_sent;
	out->num_rst_recv = cnt.num_rst_recv;
	out->num_stream_errors = cnt.num_stream_errors;
	out->stream_establish_count = cnt.stream_establish_count;
	out->byt_mux_recv = cnt.byt_mux_recv;
	out->byt_mux_sent = cnt.byt_mux_sent;
	out->byt_push_recv = cnt.byt_push_recv;
	out->byt_push_sent = cnt.byt_push_sent;
	out->recv_buffered_bytes = TPUB_LOAD(t->buf_gauge.recv_buffered_bytes);
	out->send_buffered_frames =
		TPUB_LOAD(t->buf_gauge.send_buffered_frames);
	out->unacked_frames = TPUB_LOAD(t->buf_gauge.unacked_frames);
	for (size_t i = 0; i < ARRAY_SIZE(t->stream_establish_ns); i++) {
		out->stream_establish_ns[i] =
			TPUB_LOAD(t->stream_establish_ns[i]);
	}
}

void tunnel_open_stream(struct tunnel *t, const int fd)
{
#if WITH_THREADS
	/* Queue the open and wake the tunnel thread rather than posting onto the
	 * fixed-capacity task ring: a burst of simultaneous opens larger than the
	 * ring would otherwise overflow it and the accepted connection would be
	 * dropped.  The queue grows with the burst, so none is lost. */
	struct pending_open *const restrict node = malloc(sizeof(*node));
	if (node == NULL) {
		LOGOOM();
		socket_close(fd);
		return;
	}
	node->fd = fd;
	node->next = NULL;
	THRD_ASSERT(mtx_lock(&t->open_mu));
	if (t->open_tail != NULL) {
		t->open_tail->next = node;
	} else {
		t->open_head = node;
	}
	t->open_tail = node;
	THRD_ASSERT(mtx_unlock(&t->open_mu));
	ev_async_send(t->loop, &t->w_async);
#else /* WITH_THREADS */
	tunnel_open_fd(t, fd);
#endif /* WITH_THREADS */
}

struct reload_arg {
	struct tunnel *t;
	struct mux_session *ss;
	struct mux_session_config conf;
#if WITH_TLS
	/* New per-tunnel TLS context; owned (adopted in reload_task, freed on the
	 * failure paths). NULL leaves the current context in place. */
	struct tls_context *tlsctx;
#endif
	struct conf_socket_opts mux_socket;
	struct conf_socket_opts local_socket;
	bool drain;
	bool update_connect_addr;
	/* Owned; NULL is valid. */
	char *connect_addr;
	bool disable_reconnect;
	bool update_forward_addr;
	/* Owned; NULL is valid. */
	char *forward_addr;
	bool verify_identity;
	const char *(*psk_identity_of)(void *ctx, const char *label);
	void *psk_ctx;
};

static void reload_task(void *p)
{
	struct reload_arg *const restrict arg = p;
	struct tunnel *const restrict t = arg->t;
	if (arg->update_connect_addr) {
		free(t->connect_addr);
		t->connect_addr = arg->connect_addr;
		if (t->connect_addr == NULL) {
			/* tunnel.h documents a NULL address as also disabling
			 * reconnect. Stop the backoff timer here or a pending
			 * tick would reach tunnel_do_connect with no address --
			 * it has no NULL guard, unlike every other caller. */
			ev_timer_stop(t->loop, &t->w_reconnect);
		}
	}
	if (arg->disable_reconnect) {
		t->shutting_down = true;
		ev_timer_stop(t->loop, &t->w_reconnect);
	}
	if (arg->update_forward_addr) {
		free(t->forward_addr);
		t->forward_addr = arg->forward_addr;
	}
	/* Read at the next hello, so this takes effect on the session's next
	 * handshake rather than mid-session. */
	t->verify_identity = arg->verify_identity;
	t->psk_identity_of = arg->psk_identity_of;
	t->psk_ctx = arg->psk_ctx;
#if WITH_TLS
	/* Adopt the new per-tunnel TLS context (ownership transferred via the
	 * reload).  mux_set_tlsctx() below repoints the wire to it, after which the
	 * old one is safe to free here on this (the owning) thread. */
	struct tls_context *old_tlsctx = NULL;
	if (arg->tlsctx != NULL) {
		old_tlsctx = t->tlsctx;
		t->tlsctx = arg->tlsctx;
	}
#endif /* WITH_TLS */
	mux_set_config(arg->ss, &arg->conf);
#if WITH_TLS
	if (arg->tlsctx != NULL) {
		mux_set_tlsctx(arg->ss, arg->tlsctx);
	}
	tls_ctx_free(old_tlsctx);
#endif
	if (arg->drain) {
		mux_drain(arg->ss);
	}
	t->mux_socket = arg->mux_socket;
	t->local_socket = arg->local_socket;
	free(arg);
}

void tunnel_reload(struct tunnel *t, const struct tunnel_reload_opts *opts)
{
	struct reload_arg *const restrict arg = malloc(sizeof(*arg));
	if (arg == NULL) {
		LOGOOM();
#if WITH_TLS
		/* Ownership of the new context transferred to us; release it. */
		tls_ctx_free(opts->tlsctx);
#endif
		return;
	}
	*arg = (struct reload_arg){
		.t = t,
		.ss = t->ss,
		.conf = opts->conf,
#if WITH_TLS
		.tlsctx = opts->tlsctx,
#endif
		.mux_socket = opts->mux_socket,
		.local_socket = opts->local_socket,
		.drain = opts->drain,
		.update_connect_addr = opts->update_connect_addr,
		.disable_reconnect = opts->disable_reconnect,
		.update_forward_addr = opts->update_forward_addr,
		.verify_identity = opts->verify_identity,
		.psk_identity_of = opts->psk_identity_of,
		.psk_ctx = opts->psk_ctx,
	};
	if (opts->update_connect_addr && opts->connect_addr != NULL) {
		arg->connect_addr = strdup(opts->connect_addr);
		if (arg->connect_addr == NULL) {
			LOGOOM();
			free(arg);
#if WITH_TLS
			tls_ctx_free(opts->tlsctx);
#endif
			return;
		}
	}
	if (opts->update_forward_addr && opts->forward_addr != NULL) {
		arg->forward_addr = strdup(opts->forward_addr);
		if (arg->forward_addr == NULL) {
			LOGOOM();
			free(arg->connect_addr);
			free(arg);
#if WITH_TLS
			tls_ctx_free(opts->tlsctx);
#endif
			return;
		}
	}
	if (!tunnel_post(t, (struct task){ reload_task, arg })) {
		TUNNEL_LOG_PUB(
			ERROR, t, "failed to dispatch reload (queue full)");
		free(arg->connect_addr);
		free(arg->forward_addr);
#if WITH_TLS
		tls_ctx_free(arg->tlsctx);
#endif
		free(arg);
	}
}
