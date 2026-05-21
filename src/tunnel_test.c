/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "tunnel.h"
#include "server.h"

#include "mux/frame.h"
#include "mux/mux.h"

#include "utils/testing.h"

#include <arpa/inet.h>
#include <ev.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct mux_frame *test_pool_alloc(void *data)
{
	(void)data;
	return malloc(sizeof(struct mux_frame));
}

static void test_pool_free(void *data, struct mux_frame *f)
{
	(void)data;
	free(f);
}

static const struct mux_frame_allocator g_pool = {
	.alloc = test_pool_alloc,
	.free = test_pool_free,
	.data = NULL,
};

static const struct mux_config g_conf = {
	.ping_timeout = 5,
	.keepalive = 1,
	.send_timeout = 1,
	.connect_timeout = 1,
	.max_streams = 8,
	.stream_window = 2,
	.session_window = 2,
};

static const struct socket_opts g_mux_socket = { .backlog = 1 };
static const struct socket_opts g_local_socket = { .backlog = 1 };

static const struct tunnel_callbacks g_empty_cbs = { 0 };

static const unsigned char g_zero_id[MUX_SESSION_ID_LEN];

static uintmax_t test_num_reconnects(const struct server *srv)
{
#if WITH_THREADS
	return atomic_load_explicit(
		&srv->counters.num_reconnects, memory_order_relaxed);
#else
	return srv->counters.num_reconnects;
#endif
}

static bool wait_for_reconnects(
	struct ev_loop *loop, const struct server *srv, uintmax_t minimum)
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

	/*
	 * A zero-initialised server is safe for the no-start close path
	 * because tunnel_close never dereferences srv->disp or srv->loop
	 * when t->started == false.  The stats counters (atomic or plain
	 * size_t) are accessed only via pre-captured pointers; their
	 * zero-initialised values are valid.
	 */
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
#endif

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.pool = g_pool,
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
		.pool = g_pool,
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
		.pool = g_pool,
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
	/*
	 * Verify that MUX_EVENT_CLOSED (triggered when the remote side
	 * immediately closes the accepted connection) causes reconnect to be
	 * scheduled even when no relay on_event callback is registered.
	 * This exercises the bug where tunnel_on_event was not registered
	 * with the mux session when cb->on_event was NULL.
	 */
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
		.pool = g_pool,
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
	/*
	 * Verify that connect_timeout covers the entire CONNECT+HANDSHAKE
	 * phase.  The server accepts TCP connections but never sends the mux
	 * hello, so the mux handshake never completes.  Once connect_timeout
	 * fires, MUX_EVENT_CLOSED is delivered to the tunnel layer, which
	 * schedules the next reconnect backoff.  The test asserts that at
	 * least two reconnects occur, confirming that the timeout drives the
	 * backoff progression beyond the first attempt.
	 */
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
		.pool = g_pool,
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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_tunnel_new_close_no_start);
	T_RUN_CASE(t, test_tunnel_accessors_after_new);
	T_RUN_CASE(t, test_tunnel_reconnect_rearms_after_failed_retry);
	T_RUN_CASE(t, test_tunnel_reconnect_on_transport_lost);
	T_RUN_CASE(t, test_tunnel_reconnect_after_connect_timeout);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
