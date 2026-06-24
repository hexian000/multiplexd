/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* tunnel_test.c - black-box tests for tunnel lifecycle/accessors in tunnel.c,
 * exercised against the assembled server stack via the public API.
 * Dependencies: links the real util/conf/listener/server/tunnel/api_server and
 * the mux library. */

#include "conf.h"
#include "mux/mux.h"
#include "server.h"
#include "tunnel.h"

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
#include <unistd.h>

static const struct mux_config g_conf = {
	.timeout = 30,
	.keepalive = 1,
	.send_timeout = 1,
	.connect_timeout = 1,
	.max_streams = 8,
	.stream_window = 2,
	.session_window = 2,
};

static const struct conf_socket_opts g_mux_socket = { .backlog = 1 };
static const struct conf_socket_opts g_local_socket = { .backlog = 1 };

static const struct tunnel_callbacks g_empty_cbs = { 0 };

static const unsigned char g_zero_id[MUX_SESSION_ID_LEN];

static uint_least64_t test_num_reconnects(const struct server *srv)
{
#if WITH_THREADS
	return atomic_load_explicit(
		&srv->counters.num_reconnects, memory_order_relaxed);
#else
	return srv->counters.num_reconnects;
#endif
}

static bool wait_for_reconnects(
	struct ev_loop *loop, const struct server *srv, uint_least64_t minimum)
{
	for (int i = 0; i < 100; i++) {
		if (loop != NULL) {
			ev_run(loop, EVRUN_NOWAIT);
		}
		if (test_num_reconnects(srv) >= minimum) {
			return true;
		}
		(void)poll(NULL, 0, 10);
	}
	if (loop != NULL) {
		ev_run(loop, EVRUN_NOWAIT);
	}
	return test_num_reconnects(srv) >= minimum;
}

T_DECLARE_CASE(test_tunnel_new_close_no_start)
{
	(void)_t_;
	/*
	 * Verify that a tunnel created from a socketpair can be destroyed
	 * before the tunnel thread is ever started, without crashing or
	 * leaking resources.
	 */
	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	/* A zero-initialised server is safe for the no-start close path:
	 * tunnel_close never touches srv->disp/loop when !t->started, and stats
	 * are read via pre-captured pointers. */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	/*
	 * Without threads the tunnel borrows srv->loop; give it a real one
	 * so that session_stop's ev_*_stop calls are safe even for inactive
	 * watchers.
	 */
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif /* !WITH_THREADS */

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = fds[0],
		.id = g_zero_id,
	};

	struct tunnel *t = tunnel_new(&srv, &opts);
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
	/*
	 * Verify that accessor functions return correct values immediately
	 * after tunnel_new() and before tunnel_start().
	 */
	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = fds[0],
		.id = g_zero_id,
	};

	struct tunnel *t = tunnel_new(&srv, &opts);
	T_CHECK(t != NULL);
	(void)close(fds[1]);

	/* An accepted tunnel (fd >= 0) must be flagged as accepted. */
	T_EXPECT(tunnel_is_accepted(t));
	/* tunnel_fd must return the fd passed at creation. */
	T_EXPECT_EQ(tunnel_fd(t), fds[0]);
	/* Session accessor must return a non-NULL session. */
	T_EXPECT(tunnel_session(t) != NULL);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif
}

T_DECLARE_CASE(test_tunnel_reconnect_rearms_after_failed_retry)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
	};

	struct tunnel *t = tunnel_new(&srv, &opts);
	T_CHECK(t != NULL);
	tunnel_start(t);

	T_EXPECT(wait_for_reconnects(srv.loop, &srv, 2));

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif
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
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
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
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
	};

	struct tunnel *t = tunnel_new(&srv, &opts);
	T_CHECK(t != NULL);
	tunnel_start(t);

	/* Accept the connection and immediately close it. */
	{
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };
		(void)poll(&pfd, 1, 1000);
		int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			(void)close(cfd);
		}
	}
	(void)close(lfd);

	/* MUX_EVENT_CLOSED fires: tunnel_on_event schedules a reconnect. */
	T_EXPECT(wait_for_reconnects(srv.loop, &srv, 1));

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif
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
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
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
		int flags = fcntl(lfd, F_GETFL, 0);
		T_CHECK(flags >= 0);
		T_CHECK(fcntl(lfd, F_SETFL, flags | O_NONBLOCK) == 0);
	}

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
	};

	struct tunnel *t = tunnel_new(&srv, &opts);
	T_CHECK(t != NULL);
	tunnel_start(t);

	/*
	 * Accept each incoming TCP connection and hold it without replying.
	 * connect_timeout (1 s) will fire, triggering MUX_EVENT_CLOSED and
	 * the next reconnect backoff.
	 */
	int held_fds[8];
	int num_held = 0;
	bool ok = false;
	for (int i = 0; i < 300; i++) {
#if !WITH_THREADS
		ev_run(srv.loop, EVRUN_NOWAIT);
#endif
		int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			if (num_held <
			    (int)(sizeof(held_fds) / sizeof(held_fds[0]))) {
				held_fds[num_held++] = cfd;
			} else {
				(void)close(cfd);
			}
		}
		if (test_num_reconnects(&srv) >= 2) {
			ok = true;
			break;
		}
		(void)poll(NULL, 0, 10);
	}
	T_EXPECT(ok);

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
}

T_DECLARE_CASE(test_tunnel_state_returns_connecting_after_new)
{
	/*
	 * Verify that a freshly created outbound tunnel (fd = -1, not yet
	 * started) reports MUX_STATE_CONNECT, confirming that the session is
	 * in its initial state rather than already established or closed.
	 */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
	};

	struct tunnel *t = tunnel_new(&srv, &opts);
	T_CHECK(t != NULL);

	T_EXPECT_EQ(tunnel_state(t), (enum mux_state)MUX_STATE_CONNECT);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif
}

T_DECLARE_CASE(test_tunnel_stats_initial_zero)
{
	/*
	 * Verify that all stream and traffic counters are zero immediately
	 * after tunnel_new() and before tunnel_start().
	 */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
	};

	struct tunnel *t = tunnel_new(&srv, &opts);
	T_CHECK(t != NULL);

	struct tunnel_stats stats;
	tunnel_stats(t, &stats);
	T_EXPECT_EQ(stats.num_streams, (size_t)0);
	T_EXPECT_EQ(stats.num_stream_opened, (uint_least64_t)0);
	T_EXPECT_EQ(stats.byt_mux_recv, (uint_least64_t)0);
	T_EXPECT_EQ(stats.byt_mux_sent, (uint_least64_t)0);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif
}

/* Multi-threaded concurrency tests (WITH_THREADS only) */

#if WITH_THREADS

#include <stdatomic.h>
#include <threads.h>

#include "sync/dispatcher.h"
#include "sync/shared_mutex.h"
#include "sync/task.h"

/* Inline concurrency helpers */

struct test_barrier {
	mtx_t mu;
	cnd_t cv;
	atomic_uint count;
	unsigned int total;
};

static void test_barrier_init(struct test_barrier *b, unsigned int n)
{
	(void)mtx_init(&b->mu, mtx_plain);
	(void)cnd_init(&b->cv);
	atomic_init(&b->count, 0);
	b->total = n;
}

static void test_barrier_destroy(struct test_barrier *b)
{
	mtx_destroy(&b->mu);
	cnd_destroy(&b->cv);
}

static void test_barrier_wait(struct test_barrier *b)
{
	(void)mtx_lock(&b->mu);
	const unsigned int n = atomic_fetch_add(&b->count, 1u) + 1u;
	if (n == b->total) {
		atomic_store(&b->count, 0u);
		(void)cnd_broadcast(&b->cv);
	} else {
		while (atomic_load(&b->count) != 0u) {
			(void)cnd_wait(&b->cv, &b->mu);
		}
	}
	(void)mtx_unlock(&b->mu);
}

typedef int (*test_thread_fn)(void *);

static int test_spawn_thread(thrd_t *thr, test_thread_fn fn, void *arg)
{
	return thrd_create(thr, fn, arg);
}

static int test_thread_join(thrd_t thr)
{
	int ret = 0;
	(void)thrd_join(thr, &ret);
	return ret;
}

/* Test: dispatcher roundtrip */

struct dispatcher_ctx {
	struct test_barrier *barrier;
	struct dispatcher *disp;
	int *result;
};

static void dispatcher_task_cb(void *p)
{
	int *result = p;
	*result = 42;
}

static int dispatcher_worker(void *arg)
{
	struct dispatcher_ctx *const ctx = arg;
	test_barrier_wait(ctx->barrier);
	struct task t = { .func = dispatcher_task_cb, .data = ctx->result };
	if (!dispatcher_invoke(ctx->disp, t)) {
		return 1;
	}
	return 0;
}

T_DECLARE_CASE(test_dispatcher_roundtrip)
{
	struct test_barrier barrier;
	test_barrier_init(&barrier, 2);
	struct dispatcher *disp = dispatcher_create(4);
	T_CHECK(disp != NULL);
	int result = 0;
	struct dispatcher_ctx ctx = { .barrier = &barrier,
				      .disp = disp,
				      .result = &result };
	thrd_t thr;
	T_EXPECT_EQ(
		test_spawn_thread(&thr, dispatcher_worker, &ctx), thrd_success);
	test_barrier_wait(&barrier);
	/* Join the worker before ticking: dispatcher_invoke only enqueues, so the
	 * join establishes that the task is queued (happens-before) before the
	 * dispatcher drains it.  Ticking concurrently with the worker would race —
	 * an empty tick could run before the enqueue and leave result unset. */
	T_EXPECT_EQ(test_thread_join(thr), 0);
	dispatcher_tick(disp);
	T_EXPECT_EQ(result, 42);
	dispatcher_join(disp);
	test_barrier_destroy(&barrier);
}

/* Test: shared_mutex multiple readers */

struct smtx_ctx {
	smtx_t *mu;
	struct test_barrier *start_barrier;
	struct test_barrier *done_barrier;
	atomic_int *counter;
};

static int smtx_reader(void *arg)
{
	struct smtx_ctx *const ctx = arg;
	test_barrier_wait(ctx->start_barrier);
	if (smtx_sharedlock(ctx->mu) != thrd_success) {
		return 1;
	}
	atomic_fetch_add(ctx->counter, 1);
	test_barrier_wait(ctx->done_barrier);
	smtx_sharedunlock(ctx->mu);
	return 0;
}

T_DECLARE_CASE(test_shared_mutex_multiple_readers)
{
	smtx_t mu;
	T_EXPECT_EQ(smtx_init(&mu), 0);
	struct test_barrier start_barrier, done_barrier;
	test_barrier_init(&start_barrier, 3);
	test_barrier_init(&done_barrier, 3);
	atomic_int counter;
	atomic_init(&counter, 0);
	struct smtx_ctx ctx = { .mu = &mu,
				.start_barrier = &start_barrier,
				.done_barrier = &done_barrier,
				.counter = &counter };
	thrd_t r1, r2;
	T_EXPECT_EQ(test_spawn_thread(&r1, smtx_reader, &ctx), thrd_success);
	T_EXPECT_EQ(test_spawn_thread(&r2, smtx_reader, &ctx), thrd_success);
	test_barrier_wait(&start_barrier);
	test_barrier_wait(&done_barrier);
	T_EXPECT_EQ(atomic_load(&counter), 2);
	T_EXPECT_EQ(test_thread_join(r1), 0);
	T_EXPECT_EQ(test_thread_join(r2), 0);
	smtx_destroy(&mu);
	test_barrier_destroy(&start_barrier);
	test_barrier_destroy(&done_barrier);
}

T_DECLARE_CASE(test_shared_mutex_exclusive_blocks_readers)
{
	smtx_t mu;
	T_EXPECT_EQ(smtx_init(&mu), 0);
	T_EXPECT_EQ(smtx_lock(&mu), thrd_success);
	T_EXPECT(smtx_trysharedlock(&mu) != thrd_success);
	smtx_unlock(&mu);
	T_EXPECT_EQ(smtx_sharedlock(&mu), thrd_success);
	smtx_sharedunlock(&mu);
	smtx_destroy(&mu);
}

/* Test: atomic counters cross-thread */

static int atomic_worker(void *arg)
{
	atomic_uint_least64_t *const cnt = arg;
	for (int i = 0; i < 10000; i++) {
		atomic_fetch_add_explicit(cnt, 1, memory_order_relaxed);
	}
	return 0;
}

T_DECLARE_CASE(test_atomic_counters_cross_thread)
{
	atomic_uint_least64_t counter;
	atomic_init(&counter, 0);
	thrd_t t1, t2, t3;
	T_EXPECT_EQ(
		test_spawn_thread(&t1, atomic_worker, &counter), thrd_success);
	T_EXPECT_EQ(
		test_spawn_thread(&t2, atomic_worker, &counter), thrd_success);
	T_EXPECT_EQ(
		test_spawn_thread(&t3, atomic_worker, &counter), thrd_success);
	T_EXPECT_EQ(test_thread_join(t1), 0);
	T_EXPECT_EQ(test_thread_join(t2), 0);
	T_EXPECT_EQ(test_thread_join(t3), 0);
	T_EXPECT_EQ(atomic_load(&counter), (uint_least64_t)30000);
}

#endif /* WITH_THREADS */

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_tunnel_new_close_no_start);
	T_RUN_CASE(t, test_tunnel_accessors_after_new);
	T_RUN_CASE(t, test_tunnel_reconnect_rearms_after_failed_retry);
	T_RUN_CASE(t, test_tunnel_reconnect_on_transport_lost);
	T_RUN_CASE(t, test_tunnel_reconnect_after_connect_timeout);
	T_RUN_CASE(t, test_tunnel_state_returns_connecting_after_new);
	T_RUN_CASE(t, test_tunnel_stats_initial_zero);
#if WITH_THREADS
	T_RUN_CASE(t, test_dispatcher_roundtrip);
	T_RUN_CASE(t, test_shared_mutex_multiple_readers);
	T_RUN_CASE(t, test_shared_mutex_exclusive_blocks_readers);
	T_RUN_CASE(t, test_atomic_counters_cross_thread);
#endif
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
