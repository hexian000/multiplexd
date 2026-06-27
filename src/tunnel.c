/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "tunnel.h"

#include "conf.h"
#include "mux/mux.h"
#include "server.h"
#if WITH_TLS
#include "tlsutil.h"
#endif
#include "util.h"

#include "algo/hashtable.h"
#include "math/rand.h"
#include "os/clock.h"
#include "os/socket.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/shared_mutex.h"
#endif
#include "sync/task.h"
#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/mcache.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <assert.h>
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
#include <unistd.h>

#define TUNNEL_LOG_F(level, t, format, ...)                                    \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, "%s: " format, (t)->tag, __VA_ARGS__);            \
	} while (0)

#define TUNNEL_LOG(level, t, message) TUNNEL_LOG_F(level, t, "%s", message)

/* Number of frames retained in the per-tunnel allocator cache. */
#define TUNNEL_FRAME_CACHE_SIZE 16

/* Interval between frame_cache trims, in seconds. */
#define TUNNEL_MAINTENANCE_INTERVAL 10.0

static void task_mux_start(void *p)
{
	mux_start(p);
}

static void tunnel_set_tag_part(
	char *restrict buf, const size_t buflen, const char *restrict text)
{
	const int ret = snprintf(buf, buflen, "%s", text);
	if (ret < 0) {
		buf[0] = '\0';
	}
}

static void tunnel_set_tag(
	char *restrict tag, const size_t taglen, const char *restrict my,
	const char *restrict arrow, const char *restrict peer)
{
	const int ret = snprintf(tag, taglen, "%s%s%s", my, arrow, peer);
	if (ret < 0) {
		tag[0] = '\0';
	}
}

struct tunnel {
#if WITH_THREADS
	thrd_t thread;
	bool started;
	ev_async w_async;
	struct dispatcher *disp;
#endif
	struct ev_loop *loop;
	/* Wrapped callbacks registered with the mux session. */
	struct mux_callbacks cb;
	/* Back-pointer to the mux session running on this tunnel's loop. */
	struct mux_session *ss;
	/* Per-tunnel frame cache. */
	struct mcache *frame_cache;
	ev_timer w_maintenance;

	/* Relay: re-dispatch or pass-through mux callbacks. */
	struct {
		struct server *srv;
		struct tunnel_callbacks cb;
	} relay;

	/* Monotonic ns of the last transport state change.  Written on the session
	 * thread, read on the server thread (tunnel_stats); relaxed-atomic. */
#if WITH_THREADS
	atomic_int_least64_t last_changed;
#else
	int_least64_t last_changed;
#endif

	/* Snapshot published by the session thread under pub_mtx and read by
	 * the server thread; strings are not atomic so the mutex guards a coherent
	 * copy; peer_identity is inlined to avoid touching a freeable heap pointer. */
#if WITH_THREADS
	mtx_t pub_mtx;
#endif
	struct {
		char tag[256];
		char peer_identity[256];
		bool has_peer_identity;
	} pub;

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
	/* Server-wide monotonic index, never reused. */
	uint_least64_t tunnel_index;
	/* Owned copies of session metadata strings. */
	char *identity;
	char *peer_id;
	char *peer_identity;
#if WITH_TLS
	/* Peer's X.509 certificate in DER format, extracted after TLS
	 * handshake completes.  Owned; NULL when TLS is not in use. */
	unsigned char *peer_cert_der;
	size_t peer_cert_der_len;
#endif
	/* Session log tag: "my <= peer" or "my => peer". */
	char tag[256];
	/* Socket options cached at creation; updated on reload. */
	struct conf_socket_opts mux_socket;
	struct conf_socket_opts local_socket;
	/* Per-tunnel stream lifecycle counters; updated by the session thread
	 * via mux_session_counters pointer-block. */
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
#else
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
	 * via mux_session_counters pointer-block. */
	struct {
#if WITH_THREADS
		atomic_uint_least64_t byt_mux_recv;
		atomic_uint_least64_t byt_mux_sent;
		/* PUSH-frame payload bytes only */
		atomic_uint_least64_t byt_push_recv;
		atomic_uint_least64_t byt_push_sent;
#else
		uint_least64_t byt_mux_recv;
		uint_least64_t byt_mux_sent;
		/* PUSH-frame payload bytes only */
		uint_least64_t byt_push_recv;
		uint_least64_t byt_push_sent;
#endif /* WITH_THREADS */
	} traffic_cnt;
	/* SYN->SYN|ACK latency ring; written per stream-established on the session
	 * thread (handle_stream_established), read on the server thread
	 * (tunnel_stats).  High-frequency, so relaxed-atomic rather than locked. */
#if WITH_THREADS
	atomic_size_t stream_establish_count;
	atomic_int_least64_t stream_establish_ns[256];
#else
	size_t stream_establish_count;
	int_least64_t stream_establish_ns[256];
#endif
};

/* TPUB_STORE/TPUB_LOAD: relaxed-atomic access to a session-thread-owned scalar
 * tunnel field (last_changed, stream_establish ring/count) read by the server
 * thread.  Operate on the field lvalue. */
#if WITH_THREADS
#define TPUB_STORE(field, v)                                                   \
	atomic_store_explicit(&(field), (v), memory_order_relaxed)
#define TPUB_LOAD(field) atomic_load_explicit(&(field), memory_order_relaxed)
#else
#define TPUB_STORE(field, v) ((void)((field) = (v)))
#define TPUB_LOAD(field) (field)
#endif /* WITH_THREADS */

/* Lock/unlock the per-tunnel stats-snapshot mutex.  Takes const because the
 * snapshot read path holds a const tunnel; the mutex is not part of the object's
 * const-observable state (the build uses no -Wcast-qual). */
static void tunnel_pub_lock(const struct tunnel *restrict t)
{
#if WITH_THREADS
	THRD_ASSERT(mtx_lock((mtx_t *)&t->pub_mtx));
#else
	(void)t;
#endif
}

static void tunnel_pub_unlock(const struct tunnel *restrict t)
{
#if WITH_THREADS
	THRD_ASSERT(mtx_unlock((mtx_t *)&t->pub_mtx));
#else
	(void)t;
#endif
}

/* Publish the coherent diagnostic snapshot (tag + peer_identity) under pub_mtx
 * so the server thread can read it race-free.  Runs on the session thread. */
static void tunnel_publish_pub(struct tunnel *restrict t)
{
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
			": name resolution failed for \"%s\"",
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

	if (socket_set_cloexec(fd) != 0 || socket_set_nonblock(fd) != 0) {
		SOCKET_CLOSE_FD(fd);
		return false;
	}
	socket_set_buffer(
		fd, t->local_socket.tcp_sndbuf, t->local_socket.tcp_rcvbuf);
	socket_set_tcp(
		fd, t->local_socket.tcp_nodelay, t->local_socket.tcp_keepalive);

	const int ret = connect(fd, &connect_addr.sa, sa_len(&connect_addr.sa));
	if (ret != 0) {
		const int err = errno;
		if (err != EINPROGRESS) {
			LOGE_F("connect: (%d) %s", err, strerror(err));
			SOCKET_CLOSE_FD(fd);
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
	mux_stream_attach(stream, fd);
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
	if (t->relay.cb.on_event != NULL) {
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
	if (cb != NULL) {
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
	(void)dispatcher_invoke(
		t->relay.srv->disp,
		(struct task){ .func = relay_dispatch_connected, .data = arg });
	ev_async_send(t->relay.srv->loop, &t->relay.srv->w_async);
#else
	cb(t->callback_data, t, lat_ns);
#endif /* WITH_THREADS */
}

static const double tunnel_reconnect_delays[] = {
	0.2,  2.0,  2.0,  5.0,	 5.0,	15.0,  15.0,
	15.0, 60.0, 60.0, 120.0, 300.0, 600.0,
};

static void tunnel_schedule_reconnect(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL) {
		return;
	}
	const int idx =
		CLAMP(t->reconnect_count, 0,
		      (int)(ARRAY_SIZE(tunnel_reconnect_delays) - 1));
	const double delay =
		tunnel_reconnect_delays[idx] * (0.8 + frand() * 0.4);
	t->reconnect_count++;
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(
		&t->relay.srv->counters.num_reconnects, (uint_least64_t)1,
		memory_order_relaxed);
#else
	t->relay.srv->counters.num_reconnects++;
#endif
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
		TUNNEL_LOG_F(ERROR, t, "failed to resolve: %s", addr_str);
		return false;
	}

	const int fd = socket(addr.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: (%d) %s", err, strerror(err));
		return false;
	}
	if (socket_set_cloexec(fd) != 0 || socket_set_nonblock(fd) != 0) {
		SOCKET_CLOSE_FD(fd);
		return false;
	}
	socket_set_buffer(
		fd, t->mux_socket.tcp_sndbuf, t->mux_socket.tcp_rcvbuf);
#if WITH_TCP_NOTSENT_LOWAT
	if (t->mux_socket.tcp_notsent_lowat > 0) {
		socket_notsent_lowat(fd, t->mux_socket.tcp_notsent_lowat);
	}
#endif
	socket_set_tcp(
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
			SOCKET_CLOSE_FD(fd);
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
	if (tunnel_do_connect(t)) {
		return;
	}
	TUNNEL_LOG(WARNING, t, "connect failed, scheduling retry");
	tunnel_schedule_reconnect(t);
}

static const struct mux_config *tunnel_conf(const struct tunnel *t)
{
	return mux_conf(t->ss);
}

/* Dirty disconnect on a dialed tunnel: reconnect immediately (attempt 0)
 * before backoff, unless demand-triggered reconnect is in use. */
static void handle_transport_lost(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL || tunnel_conf(t)->idle_timeout != 0) {
		return;
	}
	TUNNEL_LOG(INFO, t, "transport lost, reconnecting");
	ev_timer_stop(t->loop, &t->w_reconnect);
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(
		&t->relay.srv->counters.num_reconnects, (uint_least64_t)1,
		memory_order_relaxed);
#else
	t->relay.srv->counters.num_reconnects++;
#endif
	if (!tunnel_do_connect(t)) {
		TUNNEL_LOG(WARNING, t, "connect failed, scheduling retry");
		tunnel_schedule_reconnect(t);
	}
}

static void handle_connected(
	struct tunnel *restrict t, struct mux_session *restrict ss,
	const union mux_event_data edata)
{
	t->reconnect_count = 0;

	free(t->peer_identity);
	const char *const peer_id = edata.connected.peer_identity;
	t->peer_identity = peer_id != NULL ? strdup(peer_id) : NULL;
	if (peer_id != NULL && t->peer_identity == NULL) {
		LOGOOM();
	}

#if WITH_TLS
	/* Extract the peer cert DER for identity validation (safe to read the
	 * TLS connection on the tunnel thread). */
	free(t->peer_cert_der);
	t->peer_cert_der = NULL;
	t->peer_cert_der_len = 0;
	{
		struct tls_connection *const tlsconn = mux_tls_conn(ss);
		if (tlsconn != NULL) {
			(void)tls_peer_cert_der(
				tlsconn, &t->peer_cert_der,
				&t->peer_cert_der_len);
		}
	}
#endif /* WITH_TLS */

	/* Rebuild the diagnostic tag once the peer identity is known; skipped when
	 * the peer sent no identity (the connect-time "=> ?" tag is retained). */
	if (peer_id != NULL) {
		if (t->accepted) {
			/* Update tag for accepted identity sessions; runs on the
			 * session thread, so srv->identities must be read under
			 * accepted_mu (pins the table across SIGHUP reload swaps). */
			struct server *const srv = t->relay.srv;
#if WITH_THREADS
			THRD_ASSERT(smtx_sharedlock(&srv->accepted_mu));
#endif
			const bool matched =
				table_find(srv->identities, peer_id, NULL);
#if WITH_THREADS
			THRD_ASSERT(smtx_sharedunlock(&srv->accepted_mu));
#endif
			const char *const my = matched ? t->identity : "?";
			tunnel_set_tag(
				t->tag, sizeof(t->tag), my, " <= ", peer_id);
		} else {
			/* server.c server_on_established wires
			 * identities[].tunnels[]; here we just update the tag. */
			char my[64];
			if (t->identity != NULL) {
				tunnel_set_tag_part(
					my, sizeof(my), t->identity);
			} else {
				union sockaddr_max addr;
				if (socket_get_addr(mux_fd(ss), &addr) > 0) {
					(void)sa_format(
						my, sizeof(my), &addr.sa);
				} else {
					tunnel_set_tag_part(
						my, sizeof(my), "?");
				}
			}
			tunnel_set_tag(
				t->tag, sizeof(t->tag), my, " => ", peer_id);
		}
	}
	/* Publish tag + peer_identity for the server thread's stats path. */
	tunnel_publish_pub(t);
}

/* Returns false when the event should not be relayed to the server:
 * the session closed while reconnect is pending, so the tunnel persists. */
static bool handle_closed(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL || tunnel_conf(t)->idle_timeout != 0 ||
	    t->shutting_down) {
		ev_timer_stop(t->loop, &t->w_reconnect);
		return true;
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
		TPUB_STORE(t->last_changed, clock_monotonic_ns());
		handle_connected(t, ss, edata);
		break;
	case MUX_EVENT_RESUMED:
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
	if (t->relay.cb.on_event != NULL) {
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
		(void)dispatcher_invoke(
			t->relay.srv->disp,
			(struct task){
				.func = relay_dispatch_on_event,
				.data = arg,
			});
		ev_async_send(t->relay.srv->loop, &t->relay.srv->w_async);
	}
#else
	if (t->relay.cb.on_event != NULL) {
		t->relay.cb.on_event(t->callback_data, t, event, edata);
	}
#endif /* WITH_THREADS */
}

#if WITH_THREADS
static void tunnel_async_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	(void)loop;
	(void)revents;
	struct tunnel *const restrict t = w->data;
	dispatcher_tick(t->disp);
}

static int tunnel_thread(void *arg)
{
	struct tunnel *const restrict t = arg;
	ev_run(t->loop, 0);
	/* If ev_run exits before task_tunnel_teardown is dispatched, drain it
	 * here so mux_close/free(ss) always run on the allocating thread. */
	dispatcher_tick(t->disp);
	return 0;
}
#endif /* WITH_THREADS */

/* Enqueue a task on this tunnel's own loop/thread, reporting whether it was
 * accepted (the queue can be full).  Runs inline without threads. */
static bool tunnel_post(struct tunnel *restrict t, struct task task)
{
#if WITH_THREADS
	if (!dispatcher_invoke(t->disp, task)) {
		return false;
	}
	ev_async_send(t->loop, &t->w_async);
	return true;
#else
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
	/* Runs on old_t's loop; old_t is pinned alive by the accepted_mu lock the
	 * server holds across the post. */
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
#else
	mux_resume_attach(old_t->ss, transport, resume_seq);
#endif /* WITH_THREADS */
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

struct tunnel *
tunnel_new(struct server *srv, const struct tunnel_opts *restrict opts)
{
	const struct tunnel_callbacks *const cb = opts->cb;
	void *const data = opts->data;
	const struct mux_config *const conf = opts->mux_conf;
	const int fd = opts->fd;
	const unsigned char *const id = opts->id;
	const char *const connect_addr = opts->connect_addr;
	const char *const forward_addr = opts->forward_addr;
	const char *const identity = opts->identity;
	const char *const peer_id = opts->peer_id;
#if WITH_TLS
	struct tls_context *const tlsctx = opts->tlsctx;
	struct tls_connection *const conn = opts->conn;
#endif

	struct tunnel *restrict t = calloc(1, sizeof(struct tunnel));
	if (t == NULL) {
		return NULL;
	}
	t->relay.srv = srv;
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
		free(t->forward_addr);
		free(t->connect_addr);
		free(t->identity);
		free(t->peer_id);
		free(t);
		return NULL;
	}
	t->tunnel_index = ++srv->next_tunnel_index;
	t->mux_socket = opts->mux_socket;
	t->local_socket = opts->local_socket;
	t->cb = (struct mux_callbacks){
		.on_accept = tunnel_on_accept,
		.on_event = tunnel_on_event,
		.on_resume =
			cb->on_resume_lookup != NULL ? tunnel_on_resume : NULL,
	};
#if WITH_THREADS
	t->started = false;
	t->loop = ev_loop_new(EVFLAG_AUTO);
	if (t->loop == NULL) {
		free(t->forward_addr);
		free(t->connect_addr);
		free(t->identity);
		free(t->peer_id);
		free(t);
		return NULL;
	}
	t->disp = dispatcher_create(16);
	if (t->disp == NULL) {
		ev_loop_destroy(t->loop);
		free(t->forward_addr);
		free(t->connect_addr);
		free(t->identity);
		free(t->peer_id);
		free(t);
		return NULL;
	}
	ev_async_init(&t->w_async, tunnel_async_cb);
	t->w_async.data = t;
	ev_async_start(t->loop, &t->w_async);
#else
	t->loop = srv->loop;
#endif /* WITH_THREADS */
	ev_timer_init(
		&t->w_reconnect, tunnel_reconnect_cb, 0.0,
		tunnel_reconnect_delays[0]);
	t->w_reconnect.data = t;
	/* Per-tunnel L1 allocator: a fixed-size frame cache (mcache) over malloc,
	 * each object sized to the session's frame payload. */
	const size_t frame_obj_size = mux_frame_object_size(
		conf->max_frame_payload > 0 ?
			(size_t)conf->max_frame_payload :
			(size_t)mux_conf_default.max_frame_payload);
	t->frame_cache = mcache_new(TUNNEL_FRAME_CACHE_SIZE, frame_obj_size);
	if (t->frame_cache == NULL) {
		LOGOOM();
#if WITH_THREADS
		ev_async_stop(t->loop, &t->w_async);
		dispatcher_destroy(t->disp);
		ev_loop_destroy(t->loop);
#endif
		free(t->forward_addr);
		free(t->connect_addr);
		free(t->identity);
		free(t->peer_id);
		free(t);
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
				if (socket_get_peer(fd, &addr) > 0) {
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
				if (socket_get_addr(fd, &addr) > 0) {
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
			.num_session_created = &srv->counters.num_session_created,
			.num_session_connect = &srv->counters.num_session_connect,
			.num_session_connected =
				&srv->counters.num_session_connected,
			.num_session_disconnected =
				&srv->counters.num_session_disconnected,
			.num_session_finalized =
				&srv->counters.num_session_finalized,
			.num_sessions = &srv->counters.num_sessions,
			.num_session_halfopen =
				&srv->counters.num_session_halfopen,
			.num_streams = &t->stream_cnt.num_streams,
			.num_stream_halfopen =
				&t->stream_cnt.num_stream_halfopen,
			.num_stream_opened = &t->stream_cnt.num_stream_opened,
			.num_stream_accepted =
				&t->stream_cnt.num_stream_accepted,
			.num_stream_fastopen =
				&t->stream_cnt.num_stream_fastopen,
			.num_stream_established =
				&t->stream_cnt.num_stream_established,
			.num_stream_succeeded =
				&t->stream_cnt.num_stream_succeeded,
			.num_stream_failed = &t->stream_cnt.num_stream_failed,
			.num_rst_sent = &srv->counters.num_rst_sent,
			.num_rst_recv = &srv->counters.num_rst_recv,
			.num_stream_errors = &srv->counters.num_stream_errors,
			.recv_buffered_bytes = &srv->counters.recv_buffered_bytes,
			.send_buffered_frames = &srv->counters.send_buffered_frames,
			.unacked_frames = &srv->counters.unacked_frames,
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
		ev_timer_stop(t->loop, &t->w_maintenance);
#if WITH_THREADS
		ev_async_stop(t->loop, &t->w_async);
		dispatcher_destroy(t->disp);
		ev_loop_destroy(t->loop);
#endif
		mcache_free(t->frame_cache);
		free(t->forward_addr);
		free(t->connect_addr);
		free(t->identity);
		free(t->peer_id);
		free(t);
		return NULL;
	}
#if WITH_THREADS
	/* Init the stats-snapshot mutex last so the failure paths above need no
	 * mtx_destroy; only tunnel_close pairs with this. */
	if (mtx_init(&t->pub_mtx, mtx_plain) != thrd_success) {
		mux_close(ss);
		ev_timer_stop(t->loop, &t->w_maintenance);
		ev_async_stop(t->loop, &t->w_async);
		dispatcher_destroy(t->disp);
		ev_loop_destroy(t->loop);
		mcache_free(t->frame_cache);
		free(t->forward_addr);
		free(t->connect_addr);
		free(t->identity);
		free(t->peer_id);
		free(t);
		return NULL;
	}
#endif /* WITH_THREADS */
	t->ss = ss;
	/* Publish the creation-time tag for the stats path before the thread runs. */
	tunnel_publish_pub(t);
	return t;
}

static void tunnel_dispatch(struct tunnel *t, struct task task)
{
	/* These tasks are mandatory (start/connect/teardown); the per-tunnel
	 * dispatcher is sized so they always fit. */
	const bool ok = tunnel_post(t, task);
	assert(ok);
	(void)ok;
}

static void tunnel_initial_connect_task(void *p)
{
	struct tunnel *const restrict t = p;
	if (!tunnel_do_connect(t)) {
		tunnel_schedule_reconnect(t);
	}
}

void tunnel_start(struct tunnel *t)
{
#if WITH_THREADS
	THRD_ASSERT(thrd_create(&t->thread, tunnel_thread, t));
	t->started = true;
#endif
	tunnel_dispatch(t, (struct task){ task_mux_start, t->ss });
	if (t->connect_addr != NULL) {
		tunnel_dispatch(
			t, (struct task){ tunnel_initial_connect_task, t });
	}
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

void tunnel_close(struct tunnel *t)
{
#if WITH_THREADS
	/* Null relay callbacks so any queued relay tasks become no-ops.
	 * Must precede the teardown dispatch to prevent new relay tasks. */
	t->relay.cb = (struct tunnel_callbacks){ 0 };

	if (t->started) {
		/* Suppress mux callbacks, close session, stop event loop. */
		tunnel_dispatch(t, (struct task){ task_tunnel_teardown, t });
		THRD_ASSERT(thrd_join(t->thread, NULL));
		/* If task_tunnel_teardown never ran (tunnel self-closed first),
		 * t->ss is still alive; free it here, safe after thrd_join. */
		if (t->ss != NULL) {
			mux_close(t->ss);
		}
		/* Flush relay tasks already queued in the server dispatcher.
		 * Their callbacks are NULL, so they only free arg allocations. */
		dispatcher_tick(t->relay.srv->disp);
	} else {
		/* Thread never started; just release mux session resources. */
		ev_timer_stop(t->loop, &t->w_reconnect);
		mux_close(t->ss);
	}
	ev_async_stop(t->loop, &t->w_async);
	dispatcher_destroy(t->disp);
	ev_loop_destroy(t->loop);
#else
	ev_timer_stop(t->loop, &t->w_reconnect);
	ev_timer_stop(t->loop, &t->w_maintenance);
	mux_close(t->ss);
#endif /* WITH_THREADS */
	free(t->forward_addr);
	free(t->connect_addr);
	free(t->identity);
	free(t->peer_id);
	free(t->peer_identity);
#if WITH_TLS
	free(t->peer_cert_der);
#endif
#if WITH_THREADS
	mtx_destroy(&t->pub_mtx);
#endif
	/* After mux_close: any frames released during teardown are now back in
	 * the cache, so it is safe to drop. */
	mcache_free(t->frame_cache);
	free(t);
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
	tunnel_dispatch(t, (struct task){ task_set_shutting_down, t });
	tunnel_dispatch(t, (struct task){ task_mux_shutdown, t->ss });
}

static void task_drop_transport(void *p)
{
	const struct tunnel *const restrict t = p;
	const int fd = mux_fd(t->ss);
	if (fd < 0) {
		return;
	}
	/* Close the transport socket so the mux layer triggers
	 * MUX_EVENT_SUSPENDED and w_reconnect re-establishes the connection. */
	if (close(fd) != 0) {
		const int err = errno;
		TUNNEL_LOG_F(
			DEBUG, t, "drop_transport close: (%d) %s", err,
			strerror(err));
	}
}

void tunnel_drop_transport(struct tunnel *t)
{
	tunnel_dispatch(t, (struct task){ task_drop_transport, t });
}

int tunnel_fd(const struct tunnel *t)
{
	return mux_fd(t->ss);
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

#if WITH_TLS
const unsigned char *tunnel_peer_cert_der(const struct tunnel *t, size_t *len)
{
	if (len != NULL) {
		*len = t->peer_cert_der_len;
	}
	return t->peer_cert_der;
}
#endif

const struct sockaddr *tunnel_peer_addr(const struct tunnel *t)
{
	return mux_peer_addr(t->ss);
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
#else
	out->num_streams = t->stream_cnt.num_streams;
	out->num_stream_halfopen = t->stream_cnt.num_stream_halfopen;
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
	out->stream_establish_count = TPUB_LOAD(t->stream_establish_count);
	for (size_t i = 0; i < ARRAY_SIZE(t->stream_establish_ns); i++) {
		out->stream_establish_ns[i] =
			TPUB_LOAD(t->stream_establish_ns[i]);
	}
}

struct open_stream_arg {
	struct tunnel *t;
	struct mux_session *ss;
	int fd;
};

static void open_stream_task(void *p)
{
	struct open_stream_arg *const restrict arg = p;
	struct tunnel *const restrict t = arg->t;
	const int fd = arg->fd;
	struct mux_stream *const stream = mux_open_stream(arg->ss);
	if (stream == NULL) {
		/* Demand-triggered reconnect: when idle-closed/suspended with
		 * idle_timeout set, reconnect so the next open_stream succeeds. */
		if (t->connect_addr != NULL &&
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
		SOCKET_CLOSE_FD(fd);
		free(arg);
		return;
	}
	/* Start reading from local socket immediately.  One frame may be read
	 * before the SYN is sent and piggybacked as SYN|PUSH (fast open). */
	mux_stream_attach(stream, fd);
	TUNNEL_LOG_F(
		DEBUG, t, "[fd:%d] new stream %" PRIuLEAST16, fd,
		mux_stream_id(stream));
	free(arg);
}

void tunnel_open_stream(struct tunnel *t, const int fd)
{
	struct open_stream_arg *const restrict arg = malloc(sizeof(*arg));
	if (arg == NULL) {
		LOGOOM();
		SOCKET_CLOSE_FD(fd);
		return;
	}
	*arg = (struct open_stream_arg){ .t = t, .ss = t->ss, .fd = fd };
	tunnel_dispatch(t, (struct task){ open_stream_task, arg });
}

struct reload_arg {
	struct tunnel *t;
	struct mux_session *ss;
	struct mux_config conf;
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
};

static void reload_task(void *p)
{
	struct reload_arg *const restrict arg = p;
	struct tunnel *const restrict t = arg->t;
	if (arg->update_connect_addr) {
		free(t->connect_addr);
		t->connect_addr = arg->connect_addr;
	}
	if (arg->disable_reconnect) {
		t->shutting_down = true;
		ev_timer_stop(t->loop, &t->w_reconnect);
	}
	if (arg->update_forward_addr) {
		free(t->forward_addr);
		t->forward_addr = arg->forward_addr;
	}
	mux_set_config(arg->ss, &arg->conf);
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
		return;
	}
	*arg = (struct reload_arg){
		.t = t,
		.ss = t->ss,
		.conf = opts->conf,
		.mux_socket = opts->mux_socket,
		.local_socket = opts->local_socket,
		.drain = opts->drain,
		.update_connect_addr = opts->update_connect_addr,
		.disable_reconnect = opts->disable_reconnect,
		.update_forward_addr = opts->update_forward_addr,
	};
	if (opts->update_connect_addr && opts->connect_addr != NULL) {
		arg->connect_addr = strdup(opts->connect_addr);
		if (arg->connect_addr == NULL) {
			LOGOOM();
			free(arg);
			return;
		}
	}
	if (opts->update_forward_addr && opts->forward_addr != NULL) {
		arg->forward_addr = strdup(opts->forward_addr);
		if (arg->forward_addr == NULL) {
			LOGOOM();
			free(arg->connect_addr);
			free(arg);
			return;
		}
	}
	tunnel_dispatch(t, (struct task){ reload_task, arg });
}
