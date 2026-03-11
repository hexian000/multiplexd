/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "tunnel.h"

#include "server.h"
#include "util.h"

#include "mux/mux.h"
#include "os/clock.h"
#include "os/socket.h"
#include <stdint.h>
#if WITH_THREADS
#include "sync/dispatcher.h"
#endif
#include "sync/task.h"
#include "utils/arraysize.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/socket.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#if WITH_THREADS
#include <threads.h>
#endif

static void task_mux_start(void *p)
{
	mux_start(p);
}

#define TUNNEL_LOG_F(level, t, format, ...)                                    \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, "%s " format, (t)->tag, __VA_ARGS__);             \
	} while (0)

#define TUNNEL_LOG(level, t, message) TUNNEL_LOG_F(level, t, "%s", message)

static void tunnel_set_tag_part(
	char *restrict buf, const size_t buflen, const char *restrict text)
{
	if (snprintf(buf, buflen, "%s", text) < 0) {
		buf[0] = '\0';
	}
}

static void tunnel_set_tag(
	char *restrict tag, const size_t taglen, const char *restrict my,
	const char *restrict arrow, const char *restrict peer)
{
	if (snprintf(tag, taglen, "%s%s%s:", my, arrow, peer) < 0) {
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

	/* Relay: re-dispatch or pass-through mux callbacks. */
	struct {
		struct server *srv;
		/* Callbacks to invoke. */
		struct tunnel_callbacks cb;
	} relay;

	intmax_t last_changed;

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
	/* Owned copies of session metadata strings. */
	char *identity;
	char *peer_id;
	char *peer_identity;
	/* Session log tag: "my <= peer:" or "my => peer:". Owned buffer. */
	char tag[256];
	/* Socket options cached at creation; updated on reload. */
	struct socket_opts mux_socket;
	struct socket_opts local_socket;
};

static const struct mux_config *tunnel_conf(const struct tunnel *t);

static bool stream_connect(
	const struct tunnel *restrict t, struct stream *stream,
	const char *target)
{
	union sockaddr_max connect_addr;
	bool ok = true;
	RESOLVE_ADDR(&connect_addr, target, tcp, ok = false);
	if (!ok) {
		TUNNEL_LOG_F(
			WARNING, t,
			"stream %" PRIu16 ": name resolution failed for \"%s\"",
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
		CLOSE_FD(fd);
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
			CLOSE_FD(fd);
			return false;
		}
	}

	if (LOGLEVEL(DEBUG)) {
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), &connect_addr.sa);
		TUNNEL_LOG_F(
			DEBUG, t,
			"stream %" PRIu16 ": connecting [fd:%d] to %s",
			mux_stream_id(stream), fd, addr_str);
	}
	mux_stream_attach(stream, fd);
	return true;
}

static bool
tunnel_on_accept(void *data, struct mux_session *ss, struct stream *stream)
{
	UNUSED(ss);
	const struct tunnel *restrict t = data;
	if (t->forward_addr == NULL) {
		TUNNEL_LOG_F(
			WARNING, t,
			"stream %" PRIu16 ": no connect target configured",
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
	struct relay_event_arg *restrict arg = p;
	struct tunnel *restrict t = arg->t;
	const enum mux_event event = arg->event;
	const union mux_event_data data = arg->data;
	free(arg);
	if (t->relay.cb.on_event != NULL) {
		t->relay.cb.on_event(t->callback_data, t, event, data);
	}
}
#endif /* WITH_THREADS */

static const double tunnel_reconnect_delays[] = {
	0.2, 2.0, 2.0, 5.0, 5.0, 15.0, 15.0, 15.0, 60.0, 60.0, 120.0, 300.0,
};

static void tunnel_schedule_reconnect(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL) {
		return;
	}
	const int idx =
		CLAMP(t->reconnect_count, 0,
		      (int)(ARRAY_SIZE(tunnel_reconnect_delays) - 1));
	const double delay = tunnel_reconnect_delays[idx];
	t->reconnect_count++;
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(
		&t->relay.srv->counters.num_reconnects, (uintmax_t)1,
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
	bool ok = true;
	RESOLVE_ADDR(&addr, addr_str, tcp, ok = false);
	if (!ok) {
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
		CLOSE_FD(fd);
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
		sa_format(log_addr_str, sizeof(log_addr_str), &addr.sa);
		TUNNEL_LOG_F(
			DEBUG, t, "[fd:%d] try connecting to %s", fd,
			log_addr_str);
	}

	const int ret = connect(fd, &addr.sa, sa_len(&addr.sa));
	if (ret != 0) {
		const int err = errno;
		if (err != EINPROGRESS) {
			LOGE_F("connect: (%d) %s", err, strerror(err));
			CLOSE_FD(fd);
			return false;
		}
	}

	if (LOGLEVEL(NOTICE)) {
		char log_addr_str[64];
		sa_format(log_addr_str, sizeof(log_addr_str), &addr.sa);
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
	struct tunnel *restrict t = w->data;
	ASSERT(loop == t->loop);
	UNUSED(loop);
	ev_timer_stop(loop, &t->w_reconnect);
	if (tunnel_do_connect(t)) {
		return;
	}
	TUNNEL_LOG(WARNING, t, "connect failed, scheduling retry");
	tunnel_schedule_reconnect(t);
}

/* Dirty disconnect on a dialed tunnel: attempt to reconnect immediately
 * (attempt 0) before engaging the backoff timer, unless demand-triggered
 * reconnect is in use. */
static void handle_transport_lost(struct tunnel *restrict t)
{
	if (t->connect_addr == NULL || tunnel_conf(t)->idle_timeout != 0) {
		return;
	}
	TUNNEL_LOG(INFO, t, "transport lost, reconnecting");
	ev_timer_stop(t->loop, &t->w_reconnect);
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(
		&t->relay.srv->counters.num_reconnects, (uintmax_t)1,
		memory_order_relaxed);
#else
	t->relay.srv->counters.num_reconnects++;
#endif
	if (!tunnel_do_connect(t)) {
		TUNNEL_LOG(WARNING, t, "connect failed, scheduling retry");
		tunnel_schedule_reconnect(t);
	}
}

static void
handle_connected(struct tunnel *restrict t, const union mux_event_data edata)
{
	t->reconnect_count = 0;

	free(t->peer_identity);
	const char *const peer_id = edata.connected.peer_identity;
	t->peer_identity = peer_id != NULL ? strdup(peer_id) : NULL;
	if (peer_id != NULL && t->peer_identity == NULL) {
		LOGOOM();
	}
	if (t->accepted) {
		if (peer_id == NULL) {
			return;
		}
		/* Update tag for accepted identity sessions once peer identity
		 * is known from the completed handshake. */
		const struct server *const srv = t->relay.srv;
		bool matched = false;
		for (size_t i = 0; i < srv->num_identities; i++) {
			if (srv->identities[i].peer_identity != NULL &&
			    strcmp(srv->identities[i].peer_identity, peer_id) ==
				    0) {
				matched = true;
				break;
			}
		}
		const char *const my = matched ? t->identity : "?";
		tunnel_set_tag(t->tag, sizeof(t->tag), my, " <= ", peer_id);
	} else {
		if (peer_id == NULL) {
			return;
		}
		/* Wiring into identities[].tunnels[] is done by the server thread
		 * in server.c handle_connected after the event is dispatched.
		 * Here we only update the diagnostic tag. */
		const struct server *const srv = t->relay.srv;
		bool matched = false;
		for (size_t i = 0; i < srv->num_identities; i++) {
			if (srv->identities[i].peer_identity != NULL &&
			    strcmp(srv->identities[i].peer_identity, peer_id) ==
				    0) {
				matched = true;
				break;
			}
		}
		const char *const my = t->identity != NULL ? t->identity : "?";
		if (matched) {
			tunnel_set_tag(
				t->tag, sizeof(t->tag), my, " => ", peer_id);
		}
	}
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
	/* Both clean and dirty closes use the backoff timer.  An immediate
	 * reconnect attempt is not made here to avoid a busy loop: if the
	 * attempt were to fail asynchronously it would fire another CLOSED
	 * event and start the cycle again.  Clean closes use a normal delay
	 * so we do not hammer a server that exited intentionally; dirty closes
	 * (timeout, resume expiry, etc.) use the same backoff ladder. */
	tunnel_schedule_reconnect(t);
	return false;
}

static void tunnel_on_event(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	UNUSED(ss);
	struct tunnel *restrict t = data;

	/* Update reconnect state before relaying to the server loop. */
	switch (event) {
	case MUX_EVENT_LOST:
		t->last_changed = clock_monotonic_ns();
		break;
	case MUX_EVENT_SUSPENDED:
		handle_transport_lost(t);
		break;
	case MUX_EVENT_ESTABLISHED:
		t->last_changed = clock_monotonic_ns();
		handle_connected(t, edata);
		break;
	case MUX_EVENT_RESUMED:
		handle_connected(t, edata);
		break;
	case MUX_EVENT_CLOSED:
		if (!handle_closed(t)) {
			return;
		}
		break;
	default:
		break;
	}

#if WITH_THREADS
	if (t->relay.cb.on_event != NULL) {
		struct relay_event_arg *restrict arg = malloc(sizeof(*arg));
		if (arg == NULL) {
			LOGOOM();
			return;
		}
		*arg = (struct relay_event_arg){ .t = t,
						 .event = event,
						 .data = edata };
		(void)dispatcher_invoke(
			t->relay.srv->disp,
			(struct task){ .func = relay_dispatch_on_event,
				       .data = arg });
		ev_async_send(t->relay.srv->loop, &t->relay.srv->w_async);
	}
#else
	if (t->relay.cb.on_event != NULL) {
		t->relay.cb.on_event(t->callback_data, t, event, edata);
	}
#endif
}

static struct mux_session *tunnel_on_resume(
	void *data, struct mux_session *new_ss, const unsigned char *session_id)
{
	UNUSED(new_ss);
	struct tunnel *restrict t = data;
	if (t->relay.cb.on_resume == NULL) {
		return NULL;
	}
	return t->relay.cb.on_resume(t->callback_data, t, session_id);
}

#if WITH_THREADS
static void tunnel_async_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	(void)loop;
	(void)revents;
	struct tunnel *restrict t = w->data;
	dispatcher_tick(t->disp);
}

static int tunnel_thread(void *arg)
{
	struct tunnel *restrict t = arg;
	ev_run(t->loop, 0);
	/* ev_run may exit naturally when the session closes all its watchers
	 * before tunnel_close() has had a chance to dispatch task_tunnel_teardown.
	 * In that case the teardown task sits unconsumed in the dispatcher queue.
	 * Drain it here on the tunnel thread so that mux_close() (and thus
	 * free(ss)) always runs on the thread that allocated the session,
	 * preventing a cross-thread free that corrupts glibc's per-thread tcache. */
	dispatcher_tick(t->disp);
	return 0;
}
#endif /* WITH_THREADS */

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
	const char *const bind_addr = opts->bind_addr;
	const char *const identity = opts->identity;
	const char *const peer_id = opts->peer_id;
#if WITH_TLS
	struct tls_context *const tlsctx = opts->tlsctx;
	struct tls_connection *const conn = opts->conn;
#endif

	struct tunnel *restrict t = malloc(sizeof(struct tunnel));
	if (t == NULL) {
		return NULL;
	}
	t->relay.srv = srv;
	t->relay.cb = *cb;
	t->callback_data = data;
	t->forward_addr = forward_addr != NULL ? strdup(forward_addr) : NULL;
	t->connect_addr = connect_addr != NULL ? strdup(connect_addr) : NULL;
	t->last_changed = clock_monotonic_ns();
	t->reconnect_count = 0;
	t->shutting_down = false;
	t->accepted = (fd >= 0);
	t->identity = identity != NULL ? strdup(identity) : NULL;
	t->peer_id = peer_id != NULL ? strdup(peer_id) : NULL;
	t->peer_identity = NULL;
	t->mux_socket = opts->mux_socket;
	t->local_socket = opts->local_socket;
	t->cb = (struct mux_callbacks){
		.on_accept = tunnel_on_accept,
		.on_event = tunnel_on_event,
		.on_resume = cb->on_resume != NULL ? tunnel_on_resume : NULL,
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
#endif
	ev_timer_init(
		&t->w_reconnect, tunnel_reconnect_cb, 0.0,
		tunnel_reconnect_delays[0]);
	t->w_reconnect.data = t;
	const struct mux_frame_allocator pool = opts->pool;
	/* Compute the initial session tag. */
	{
		char my[64];
		char peer[64];
		if (fd >= 0) {
			/* Accepted session: peer addr from socket; my from
			 * identity, then bind_addr config, then local socket. */
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
			} else if (bind_addr != NULL) {
				tunnel_set_tag_part(my, sizeof(my), bind_addr);
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
			.num_streams = &srv->counters.num_streams,
			.num_stream_halfopen =
				&srv->counters.num_stream_halfopen,
			.num_stream_opened = &srv->counters.num_stream_opened,
			.num_stream_accepted = &srv->counters.num_stream_accepted,
			.num_stream_fastopen = &srv->counters.num_stream_fastopen,
			.num_stream_established =
				&srv->counters.num_stream_established,
			.num_stream_succeeded = &srv->counters.num_stream_succeeded,
			.num_stream_failed = &srv->counters.num_stream_failed,
			.num_rst_sent = &srv->counters.num_rst_sent,
			.num_rst_recv = &srv->counters.num_rst_recv,
			.num_stream_errors = &srv->counters.num_stream_errors,
			.recv_buffered_bytes = &srv->counters.recv_buffered_bytes,
			.send_buffered_frames = &srv->counters.send_buffered_frames,
			.unacked_frames = &srv->counters.unacked_frames,
			.traffic = {
				.byt_mux_recv =
					&srv->counters.traffic_byt_mux_recv,
				.byt_mux_sent =
					&srv->counters.traffic_byt_mux_sent,
				.byt_local_recv =
					&srv->counters.traffic_byt_local_recv,
				.byt_local_sent =
					&srv->counters.traffic_byt_local_sent,
			},
		},
#if WITH_TLS
		.tlsctx = tlsctx,
		.conn = conn,
#endif
	};
	struct mux_session *restrict ss = mux_new(t->loop, &ss_opts);
	if (ss == NULL) {
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
	t->ss = ss;
	return t;
}

static void tunnel_dispatch(struct tunnel *t, struct task task)
{
#if WITH_THREADS
	const bool ok = dispatcher_invoke(t->disp, task);
	assert(ok);
	(void)ok;
	ev_async_send(t->loop, &t->w_async);
#else
	(void)t;
	task.func(task.data);
#endif
}

static void tunnel_initial_connect_task(void *p)
{
	struct tunnel *restrict t = p;
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
/* Suppress mux callbacks, close the session, and stop the event loop.
 * Runs on the tunnel thread as the final dispatched task; suppressing
 * callbacks first guarantees no new tasks are enqueued into relay_disp
 * after this point, so the tunnel's dispatcher is empty when ev_run()
 * returns and thrd_join() completes.  Clears t->ss after freeing it so
 * that tunnel_close can detect whether the task actually ran. */
static void task_tunnel_teardown(void *p)
{
	struct tunnel *restrict t = p;
	ev_timer_stop(t->loop, &t->w_reconnect);
	mux_set_callbacks(t->ss, &(struct mux_callbacks){ 0 });
	mux_close(t->ss);
	t->ss = NULL;
	ev_async_stop(t->loop, &t->w_async);
}
#endif /* WITH_THREADS */

void tunnel_close(struct tunnel *t)
{
#if WITH_THREADS
	/* Disconnect relay callbacks first.  Any relay_dispatch_on_event or
	 * relay_dispatch_on_closed task already queued in the server
	 * dispatcher will see NULL callbacks and become no-ops (freeing
	 * any arg allocation without invoking the callback).  This must
	 * happen before dispatching the teardown task to the tunnel thread
	 * so that no new relay tasks can be enqueued after this point. */
	t->relay.cb = (struct tunnel_callbacks){ 0 };

	if (t->started) {
		/* Suppress mux callbacks, close session, stop event loop. */
		tunnel_dispatch(t, (struct task){ task_tunnel_teardown, t });
		THRD_ASSERT(thrd_join(t->thread, NULL));
		/* If task_tunnel_teardown did not run (graceful close: the tunnel
		 * thread stopped itself in tunnel_on_closed before processing the
		 * task, or a race where tunnel_on_closed fired concurrently), the
		 * session is still allocated.  Free it here on the relay thread;
		 * this is safe because thrd_join guarantees the tunnel thread is
		 * fully done with t->ss. */
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
	/* Common cleanup. */
	ev_async_stop(t->loop, &t->w_async);
	dispatcher_destroy(t->disp);
	ev_loop_destroy(t->loop);
#else
	ev_timer_stop(t->loop, &t->w_reconnect);
	mux_close(t->ss);
#endif
	free(t->forward_addr);
	free(t->connect_addr);
	free(t->identity);
	free(t->peer_id);
	free(t->peer_identity);
	free(t);
}

int tunnel_fd(const struct tunnel *t)
{
	return mux_fd(t->ss);
}

enum mux_state tunnel_state(const struct tunnel *t)
{
	return mux_state(t->ss);
}

static const struct mux_config *tunnel_conf(const struct tunnel *t)
{
	return mux_conf(t->ss);
}

struct mux_session *tunnel_session(const struct tunnel *t)
{
	return t->ss;
}

const char *tunnel_peer_id(const struct tunnel *t)
{
	return t->peer_id;
}

const char *tunnel_peer_identity(const struct tunnel *t)
{
	return t->peer_identity;
}

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

void tunnel_stats(const struct tunnel *t, struct tunnel_stats *restrict out)
{
	out->established = mux_state(t->ss) == MUX_STATE_ESTABLISHED;
	mux_stream_window(t->ss, &out->rx_window, &out->tx_window);
	out->last_changed = t->last_changed;
	out->rtt_ns = mux_session_rtt_ns(t->ss);
}

struct open_stream_arg {
	struct tunnel *t;
	struct mux_session *ss;
	int fd;
};

static void open_stream_task(void *p)
{
	struct open_stream_arg *restrict arg = p;
	struct tunnel *restrict t = arg->t;
	const int fd = arg->fd;
	struct stream *stream = mux_open_stream(arg->ss);
	if (stream == NULL) {
		/* Demand-triggered reconnect: if the session is idle-closed or
		 * suspended and idle_timeout is set, initiate a new transport
		 * connection so the next open_stream attempt succeeds. */
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
		CLOSE_FD(fd);
		free(arg);
		return;
	}
	/* Start reading from local socket immediately.  One frame may be read
	 * before the SYN is sent and piggybacked as SYN|PUSH (fast open). */
	mux_stream_attach(stream, fd);
	TUNNEL_LOG_F(
		DEBUG, t, "[fd:%d] new stream %" PRIu16, fd,
		mux_stream_id(stream));
	free(arg);
}

void tunnel_open_stream(struct tunnel *t, const int fd)
{
	struct open_stream_arg *restrict arg = malloc(sizeof(*arg));
	if (arg == NULL) {
		LOGOOM();
		CLOSE_FD(fd);
		return;
	}
	*arg = (struct open_stream_arg){ .t = t, .ss = t->ss, .fd = fd };
	tunnel_dispatch(t, (struct task){ open_stream_task, arg });
}

struct reload_arg {
	struct tunnel *t;
	struct mux_session *ss;
	struct mux_config conf;
	struct socket_opts mux_socket;
	struct socket_opts local_socket;
	bool drain;
	bool update_connect_addr;
	char *connect_addr; /* owned; NULL is valid */
	bool disable_reconnect;
	bool update_forward_addr;
	char *forward_addr; /* owned; NULL is valid */
};

static void reload_task(void *p)
{
	struct reload_arg *restrict arg = p;
	struct tunnel *restrict t = arg->t;
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
	struct reload_arg *restrict arg = malloc(sizeof(*arg));
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
