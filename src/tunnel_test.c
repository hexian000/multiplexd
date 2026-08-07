/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* tunnel_test.c - black-box tests for tunnel lifecycle/accessors;
 * real util/conf/listener/server/tunnel/api_server + mux library linked;
 * exercised via the public API. */

#include "tunnel.h"

#include "conf.h"
#include "mux/mux.h"
#include "server.h"

#include "meta/arraysize.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/task.h"
#endif
#include "utils/testing.h"

#include <ev.h>

#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#if WITH_THREADS
#include <threads.h>
#include <time.h>
#endif
#include <unistd.h>

static const struct mux_session_config g_conf = {
	.timeout = 30,
	.keepalive = 1,
	.send_timeout = 1,
	.connect_timeout = 1,
	.max_streams = 8,
	.stream_window = 2,
	.session_window = 2,
	.max_frame_payload = 16384 - MUX_FRAME_HEADER_SIZE,
};

static const struct conf_socket_opts g_mux_socket = { .backlog = 1 };
static const struct conf_socket_opts g_local_socket = { .backlog = 1 };

static const struct tunnel_callbacks g_empty_cbs = { 0 };

/* ── tunnel_context helpers for tests ────────────────────────────────── */

#if WITH_THREADS
static bool test_post_task(void *user, struct task task)
{
	struct server *const restrict s = user;
	if (!dispatcher_invoke(s->disp, task)) {
		return false;
	}
	ev_async_send(s->loop, &s->w_async);
	return true;
}

static void test_flush_tasks(void *user)
{
	dispatcher_tick(((struct server *)user)->disp);
}
#endif /* WITH_THREADS */

static bool test_verify_peer(void *user, const char *peer_id)
{
	(void)user;
	(void)peer_id;
	return false;
}

static uint_least64_t test_alloc_index(void *user)
{
	return ++((struct server *)user)->next_tunnel_index;
}

static struct tunnel_session_counters
test_make_tunnel_counters(struct server *restrict srv)
{
	return (struct tunnel_session_counters){
		.num_session_created = &srv->counters.num_session_created,
		.num_session_connect = &srv->counters.num_session_connect,
		.num_session_connected = &srv->counters.num_session_connected,
		.num_session_disconnected =
			&srv->counters.num_session_disconnected,
		.num_session_finalized = &srv->counters.num_session_finalized,
		.num_sessions = &srv->counters.num_sessions,
		.num_session_halfopen = &srv->counters.num_session_halfopen,
	};
}

static struct tunnel_context
test_make_tunnel_context(struct server *restrict srv)
{
	return (struct tunnel_context){
#if WITH_THREADS
		.post_task = test_post_task,
		.flush_tasks = test_flush_tasks,
#endif
		.verify_peer = test_verify_peer,
		.alloc_index = test_alloc_index,
		.user = srv,
#if !WITH_THREADS
		.loop = srv->loop,
#endif
	};
}

/* ─────────────────────────────────────────────────────────────────────── */

static const unsigned char g_zero_id[MUX_SESSION_ID_LEN];

static uint_least64_t test_num_reconnects(const struct tunnel *t)
{
	struct tunnel_stats snap;
	tunnel_stats(t, &snap);
	return snap.num_reconnects;
}

#if !WITH_THREADS
static void reconnect_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)loop;
	(void)revents;
	*(bool *)w->data = true;
}
#endif /* !WITH_THREADS */

static bool wait_for_reconnects(
	struct ev_loop *loop, const struct tunnel *t, uint_least64_t minimum)
{
#if WITH_THREADS
	(void)loop;
	/* Tunnel runs in its own thread; poll with bounded sleep — unavoidable
	 * without timer mocking or production-code synchronization hooks. */
	for (int i = 0; i < 1000; i++) {
		if (test_num_reconnects(t) >= minimum) {
			return true;
		}
		(void)thrd_sleep(
			&(struct timespec){ .tv_nsec = 10000000L }, NULL);
	}
	return test_num_reconnects(t) >= minimum;
#else /* WITH_THREADS */
	/* Drive the shared event loop with EVRUN_ONCE so no sleep is needed;
	 * a 10-second guard prevents an infinite hang if no reconnect fires. */
	bool timed_out = false;
	ev_timer tw;
	tw.data = &timed_out;
	ev_timer_init(&tw, reconnect_timeout_cb, 10.0, 0.0);
	ev_timer_start(loop, &tw);
	while (!timed_out && test_num_reconnects(t) < minimum) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &tw);
	return !timed_out && test_num_reconnects(t) >= minimum;
#endif /* WITH_THREADS */
}

T_DECLARE_CASE(test_tunnel_new_close_no_start)
{
	(void)_t_;
	/* Verify that a tunnel can be destroyed before tunnel_start() without
	 * crashing or leaking resources. */
	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	/* A zero-initialised server is safe for the no-start close path:
	 * tunnel_close never touches srv->disp/loop when !t->started, and stats
	 * are read via pre-captured pointers. */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	/* Without threads the tunnel borrows srv->loop; give it a real one
	 * so that ev_*_stop calls in session_stop are safe. */
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif /* !WITH_THREADS */

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* fds[0] is owned by the tunnel; close only the other end. */
	(void)close(fds[1]);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif
}

T_DECLARE_CASE(test_tunnel_accessors_after_new)
{
	/* Verify that accessors return correct values after tunnel_new()
	 * and before tunnel_start(). */
	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	(void)close(fds[1]);

	/* Capture the accessor reads before teardown frees the tunnel, so a
	 * failed assertion cannot longjmp out with the tunnel still live. */
	const bool accepted = tunnel_is_accepted(t);
	const int fd = tunnel_fd(t);
	const bool has_session = tunnel_session(t) != NULL;

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	/* An accepted tunnel (fd >= 0) must be flagged as accepted. */
	T_EXPECT(accepted);
	/* tunnel_fd must return the fd passed at creation. */
	T_EXPECT_EQ(fd, fds[0]);
	/* Session accessor must return a non-NULL session. */
	T_EXPECT(has_session);
}

T_DECLARE_CASE(test_tunnel_reconnect_rearms_after_failed_retry)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	T_CHECK(tunnel_start(t));

	/* Capture the reconnect result while the tunnel thread is live, then join
	 * it via tunnel_close before asserting: a failed assertion must not
	 * longjmp out with the thread still writing into this frame. */
	const bool reconnected = wait_for_reconnects(srv.loop, t, 2);

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT(reconnected);
}

/* tunnel.h documents update_connect_addr with a NULL address as "clears and
 * disables reconnect", but reload_task only cleared it -- a backoff timer armed
 * before the reload then fired into tunnel_do_connect with no address, and that
 * is the one reconnect entry point with no NULL guard, so resolve_addr walked
 * into strlen(NULL). Drive exactly the documented usage: reconnect-loop a
 * tunnel so the timer is pending, clear the address, then let the loop run past
 * the backoff. */
T_DECLARE_CASE(test_tunnel_reload_null_addr_disables_reconnect)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	T_CHECK(tunnel_start(t));
	/* Let it fail and arm the backoff timer at least once. */
	const bool reconnected = wait_for_reconnects(srv.loop, t, 1);

	/* The documented "clears and disables reconnect" form. */
	struct tunnel_reload_opts reload = {
		.conf = g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.update_connect_addr = true,
		.connect_addr = NULL,
	};
	tunnel_reload(t, &reload);
	/* Run well past the shortest backoff so a surviving timer would fire. */
	const uint_least64_t before = test_num_reconnects(t);
	(void)wait_for_reconnects(srv.loop, t, before + 2);
	const uint_least64_t after = test_num_reconnects(t);

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT(reconnected);
	/* No further dial attempts: the timer was stopped, and had it fired the
	 * NULL address would have crashed rather than counted. */
	T_EXPECT_EQ(after, before);
}

T_DECLARE_CASE(test_tunnel_reconnect_on_transport_lost)
{
	/* MUX_EVENT_CLOSED must schedule a reconnect even with no relay on_event
	 * callback — a regression where tunnel_on_event was not registered when
	 * cb->on_event was NULL. */
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 1) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	char connect_addr[32];
	(void)snprintf(
		connect_addr, sizeof(connect_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	T_CHECK(tunnel_start(t));

	/* Accept the connection and immediately close it. */
#if WITH_THREADS
	bool accept_ready;
#endif
	{
#if !WITH_THREADS
		/* tunnel_do_connect ran inline in tunnel_start; the TCP connection
		 * is already in the accept queue before we reach this point. */
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			(void)close(cfd);
		}
#else /* WITH_THREADS */
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };
		accept_ready = poll(&pfd, 1, 1000) > 0;
		/* lfd is a blocking listen socket, so only accept once poll has
		 * reported a pending connection; on a poll timeout (loaded host,
		 * or the connect failure this test probes) skip the accept and
		 * let the T_EXPECT(accept_ready) below fail cleanly instead of
		 * blocking forever. */
		if (accept_ready) {
			const int cfd = accept(lfd, NULL, NULL);
			if (cfd >= 0) {
				(void)close(cfd);
			}
		}
#endif /* WITH_THREADS */
	}
	(void)close(lfd);

	/* MUX_EVENT_CLOSED fires: tunnel_on_event schedules a reconnect.  Capture
	 * the results while the tunnel thread is live, then join it via
	 * tunnel_close before asserting. */
	const bool reconnected = wait_for_reconnects(srv.loop, t, 1);

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
	T_EXPECT(accept_ready);
#else
	ev_loop_destroy(loop);
#endif
	T_EXPECT(reconnected);
}

T_DECLARE_CASE(test_tunnel_reconnect_after_connect_timeout)
{
	/* connect_timeout must cover the whole CONNECT+HANDSHAKE phase: the
	 * server accepts TCP but never sends the hello, so the timeout fires,
	 * delivers MUX_EVENT_CLOSED, and drives backoff.  Asserts >= 2 reconnects. */
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 4) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	char connect_addr[32];
	(void)snprintf(
		connect_addr, sizeof(connect_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));
	{
		const int flags = fcntl(lfd, F_GETFL, 0);
		T_CHECK(flags >= 0);
		T_CHECK(fcntl(lfd, F_SETFL, flags | O_NONBLOCK) == 0);
	}

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	T_CHECK(tunnel_start(t));

	/* Accept and hold incoming connections without replying; connect_timeout
	 * (1 s) fires, triggering MUX_EVENT_CLOSED and reconnect backoff. */
	int held_fds[8];
	int num_held = 0;
	bool ok = false;
#if WITH_THREADS
	for (int i = 0; i < 1000; i++) {
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			if (num_held < (int)ARRAY_SIZE(held_fds)) {
				held_fds[num_held++] = cfd;
			} else {
				(void)close(cfd);
			}
		}
		if (test_num_reconnects(t) >= 2) {
			ok = true;
			break;
		}
		(void)thrd_sleep(
			&(struct timespec){ .tv_nsec = 10000000L }, NULL);
	}
#else /* !WITH_THREADS */
	{
		/* Drive the event loop one event at a time; accept between steps so
		 * each TCP connect is captured before the next timer fires.  The
		 * 10-second guard prevents an infinite hang if connect_timeout or
		 * the reconnect timer never fires. */
		bool timed_out = false;
		ev_timer tw;
		tw.data = &timed_out;
		ev_timer_init(&tw, reconnect_timeout_cb, 10.0, 0.0);
		ev_timer_start(srv.loop, &tw);
		while (!timed_out && test_num_reconnects(t) < 2) {
			const int cfd = accept(lfd, NULL, NULL);
			if (cfd >= 0) {
				if (num_held < (int)ARRAY_SIZE(held_fds)) {
					held_fds[num_held++] = cfd;
				} else {
					(void)close(cfd);
				}
			}
			ev_run(srv.loop, EVRUN_ONCE);
		}
		ev_timer_stop(srv.loop, &tw);
		ok = !timed_out && test_num_reconnects(t) >= 2;
	}
#endif /* WITH_THREADS */
	/* ok was captured above while the tunnel thread was live; join the thread
	 * via tunnel_close and release the fixture before asserting, so a failed
	 * assertion cannot longjmp out with the thread still running. */
	tunnel_close(t);

	for (int i = 0; i < num_held; i++) {
		(void)close(held_fds[i]);
	}
	(void)close(lfd);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT(ok);
}

T_DECLARE_CASE(test_tunnel_state_returns_connecting_after_new)
{
	/* Freshly created outbound tunnel (fd=-1, not started) must report
	 * MUX_STATE_CONNECT. */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* Capture the state before teardown frees the tunnel. */
	const enum mux_state state = tunnel_state(t);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT_EQ(state, (enum mux_state)MUX_STATE_CONNECT);
}

T_DECLARE_CASE(test_tunnel_stats_initial_zero)
{
	/* All stream/traffic counters must be zero after tunnel_new()
	 * and before tunnel_start(). */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* tunnel_stats snapshots into the local stats, so it is safe to tear the
	 * tunnel down before asserting on the captured copy. */
	struct tunnel_stats stats;
	tunnel_stats(t, &stats);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT_EQ(stats.num_streams, (size_t)0);
	T_EXPECT_EQ(stats.num_stream_opened, (uint_least64_t)0);
	T_EXPECT_EQ(stats.byt_mux_recv, (uint_least64_t)0);
	T_EXPECT_EQ(stats.byt_mux_sent, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_reconnects, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_rst_sent, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_rst_recv, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_stream_errors, (uint_least64_t)0);
	T_EXPECT_EQ(stats.recv_buffered_bytes, (size_t)0);
	T_EXPECT_EQ(stats.send_buffered_frames, (size_t)0);
	T_EXPECT_EQ(stats.unacked_frames, (size_t)0);
}

T_DECLARE_CASE(test_tunnel_open_stream_burst_not_dropped)
{
#if !WITH_THREADS
	(void)_t_;
	/* Without threads tunnel_open_stream opens inline; there is no bounded task
	 * ring to overflow, so the drop this pins cannot occur. */
	T_SKIPNOW();
#else
	/* A burst of concurrent opens larger than the tunnel's task-ring capacity
	 * (16) must not drop any accepted connection.  Create an accepted tunnel but
	 * do NOT start its thread, so nothing drains the queue, then hand it a burst
	 * well above the ring capacity and confirm every accepted connection is
	 * still open (held for later service), not closed.  Pre-fix, each open was
	 * posted onto the 16-slot ring and the fd was closed once the ring filled,
	 * dropping the burst's tail; the peer end then saw EOF. */
	enum { BURST = 64 };
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	int tpair[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, tpair) == 0);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = tpair[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	(void)close(tpair[1]);

	/* ours[] is the end we keep (to observe closure); sp[1] is handed to the
	 * tunnel, which now owns and eventually closes it. */
	int ours[BURST];
	int made = 0;
	for (; made < BURST; made++) {
		int sp[2];
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
			break;
		}
		ours[made] = sp[0];
		tunnel_open_stream(t, sp[1]);
	}

	/* Probe every handed-off connection via the retained peer while the tunnel
	 * is still live -- immune to fd-number reuse, unlike probing the handed-off
	 * descriptor directly.  A closed (dropped) peer reads EOF (recv == 0); a
	 * held one would block, so recv returns -1/EAGAIN. */
	int dropped = 0;
	for (int i = 0; i < made; i++) {
		char b;
		if (recv(ours[i], &b, 1, MSG_DONTWAIT) == 0) {
			dropped++;
		}
	}

	tunnel_close(t); /* flushes and closes any still-queued opens */
	for (int i = 0; i < made; i++) {
		(void)close(ours[i]);
	}
	dispatcher_destroy(srv.disp);

	/* The whole burst was issued, and none of it was dropped. */
	T_EXPECT_EQ(made, (int)BURST);
	T_EXPECT_EQ(dropped, 0);
#endif /* WITH_THREADS */
}

static const struct testing_suite suite[] = {
	T_CASE(test_tunnel_new_close_no_start),
	T_CASE(test_tunnel_accessors_after_new),
	T_CASE(test_tunnel_reconnect_rearms_after_failed_retry),
	T_CASE(test_tunnel_reload_null_addr_disables_reconnect),
	T_CASE(test_tunnel_reconnect_on_transport_lost),
	T_CASE(test_tunnel_reconnect_after_connect_timeout),
	T_CASE(test_tunnel_state_returns_connecting_after_new),
	T_CASE(test_tunnel_stats_initial_zero),
	T_CASE(test_tunnel_open_stream_burst_not_dropped),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
