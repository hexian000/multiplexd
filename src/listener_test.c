/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* listener_test.c - black-box tests for the socket listener in listener.c via
 * its public API. Dependencies: links the real util.c and listener.c. */

#include "listener.h"

#include "conf.h"

#include "utils/testing.h"

#include <ev.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const struct conf_socket_opts g_socket_opts = {
	.backlog = 4,
};

static int g_serve_fd;
static int g_serve_calls;

static void watchdog_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)revents;
	*(bool *)w->data = true;
	ev_break(loop, EVBREAK_ONE);
}

static void test_serve(
	struct listener *l, struct ev_loop *loop, int fd,
	const struct sockaddr *sa)
{
	(void)l;
	(void)loop;
	(void)sa;
	g_serve_fd = fd;
	g_serve_calls++;
	(void)close(fd);
}

static int get_bound_port(const struct listener *restrict l)
{
	const int fd = l->w_accept.fd;
	if (fd < 0) {
		return -1;
	}
	struct sockaddr_in sa = { 0 };
	socklen_t len = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
		return -1;
	}
	return (int)ntohs(sa.sin_port);
}

static struct sockaddr_in make_loopback_any(void)
{
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	return sa;
}

T_DECLARE_CASE(test_listener_start_binds_port)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	const struct sockaddr_in sa = make_loopback_any();
	T_CHECK(listener_start(&l, loop, (const struct sockaddr *)&sa));

	const int port = get_bound_port(&l);
	T_EXPECT(port > 0);

	listener_stop(&l, loop);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_listener_stop_after_start)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	const struct sockaddr_in sa = make_loopback_any();
	T_CHECK(listener_start(&l, loop, (const struct sockaddr *)&sa));
	listener_stop(&l, loop);

	/* After stop the listening fd must be released. */
	T_EXPECT_EQ(l.w_accept.fd, -1);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_listener_start_bad_addr_fails)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	/* 192.0.2.1 is TEST-NET-1 (RFC 5737) and is never a local interface
	 * address; bind() must fail with EADDRNOTAVAIL. */
	struct sockaddr_in bad;
	memset(&bad, 0, sizeof(bad));
	bad.sin_family = AF_INET;
	bad.sin_addr.s_addr = htonl(0xC0000201u); /* 192.0.2.1 */
	bad.sin_port = 0;

	T_EXPECT(!listener_start(&l, loop, (const struct sockaddr *)&bad));

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_listener_serve_fn_called)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	g_serve_fd = -1;
	g_serve_calls = 0;

	struct listener l;
	uint_least64_t accepted = 0;
	listener_init(&l, &g_socket_opts, test_serve, NULL, &accepted);

	const struct sockaddr_in sa = make_loopback_any();
	T_CHECK(listener_start(&l, loop, (const struct sockaddr *)&sa));

	const int port = get_bound_port(&l);
	T_CHECK(port > 0);

	/* Connect a client so there is something to accept. */
	struct sockaddr_in peer;
	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	peer.sin_port = htons((uint16_t)port);

	const int cfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(cfd >= 0);
	T_CHECK(connect(cfd, (const struct sockaddr *)&peer, sizeof(peer)) ==
		0);

	/* Drive the event loop once so accept_cb fires; a watchdog timer
	 * fails the test instead of hanging the suite if it never does. */
	bool timed_out = false;
	ev_timer w_watchdog;
	ev_timer_init(&w_watchdog, watchdog_cb, 2.0, 0.0);
	w_watchdog.data = &timed_out;
	ev_timer_start(loop, &w_watchdog);

	ev_run(loop, EVRUN_ONCE);

	ev_timer_stop(loop, &w_watchdog);
	T_EXPECT(!timed_out);
	T_EXPECT_EQ(g_serve_calls, 1);
	T_EXPECT(accepted >= 1u);

	(void)close(cfd);
	listener_stop(&l, loop);
	ev_loop_destroy(loop);
}

/* accept_cb drains the whole kernel accept queue in one wakeup (its for(;;)
 * loop), not one connection per callback. Two clients are queued before a
 * single ev_run, and both must be served in it. */
T_DECLARE_CASE(test_listener_accept_drains_multiple_in_one_wakeup)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	g_serve_fd = -1;
	g_serve_calls = 0;

	struct listener l;
	uint_least64_t accepted = 0;
	listener_init(&l, &g_socket_opts, test_serve, NULL, &accepted);

	const struct sockaddr_in sa = make_loopback_any();
	T_CHECK(listener_start(&l, loop, (const struct sockaddr *)&sa));
	const int port = get_bound_port(&l);
	T_CHECK(port > 0);

	struct sockaddr_in peer;
	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	peer.sin_port = htons((uint16_t)port);

	/* Blocking connects complete the handshake synchronously, so both sit in
	 * the accept queue before the single ev_run below. */
	int cfd[2];
	for (int i = 0; i < 2; i++) {
		cfd[i] = socket(AF_INET, SOCK_STREAM, 0);
		T_CHECK(cfd[i] >= 0);
		T_CHECK(connect(cfd[i], (const struct sockaddr *)&peer,
				sizeof(peer)) == 0);
	}

	bool timed_out = false;
	ev_timer w_watchdog;
	ev_timer_init(&w_watchdog, watchdog_cb, 2.0, 0.0);
	w_watchdog.data = &timed_out;
	ev_timer_start(loop, &w_watchdog);

	ev_run(loop, EVRUN_ONCE); /* a single wakeup */

	ev_timer_stop(loop, &w_watchdog);
	T_EXPECT(!timed_out);
	/* Both accepted in the one wakeup; a single-accept-per-callback loop
	 * would reach only 1 here. */
	T_EXPECT_EQ(g_serve_calls, 2);
	T_EXPECT(accepted >= 2u);

	for (int i = 0; i < 2; i++) {
		(void)close(cfd[i]);
	}
	listener_stop(&l, loop);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_listener_stop_and_restart_binds_again)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	const struct sockaddr_in sa = make_loopback_any();
	T_CHECK(listener_start(&l, loop, (const struct sockaddr *)&sa));

	const int port1 = get_bound_port(&l);
	T_EXPECT(port1 > 0);

	listener_stop(&l, loop);
	T_EXPECT_EQ(l.w_accept.fd, -1);

	/* Start again; must successfully bind a new port. */
	T_CHECK(listener_start(&l, loop, (const struct sockaddr *)&sa));

	const int port2 = get_bound_port(&l);
	T_EXPECT(port2 > 0);

	listener_stop(&l, loop);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_listener_accept_network_error_keeps_accepting)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	/* A UDP socket can never complete accept(2); the kernel rejects it
	 * with EOPNOTSUPP, one of the per-connection network errors accept(2)
	 * documents as needing EAGAIN-like handling. */
	const int bad_fd = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(bad_fd >= 0);
	ev_io_set(&l.w_accept, bad_fd, EV_READ);
	ev_io_start(loop, &l.w_accept);

	ev_feed_event(loop, &l.w_accept, EV_READ);
	ev_invoke_pending(loop);

	/* Must keep accepting: the accept watcher stays armed and no backoff
	 * is scheduled. */
	T_EXPECT(ev_is_active(&l.w_accept));
	T_EXPECT(!ev_is_active(&l.w_timer));

	listener_stop(&l, loop);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_listener_accept_invalid_fd_backs_off)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	/* EBADF is not one of the per-connection network errors above and
	 * must still trigger backoff. ev_io_start is skipped: -1 is not a
	 * valid descriptor to register with the backend. */
	ev_io_set(&l.w_accept, -1, EV_READ);

	ev_feed_event(loop, &l.w_accept, EV_READ);
	ev_invoke_pending(loop);

	/* Must back off: the fallback path arms the retry timer. */
	T_EXPECT(ev_is_active(&l.w_timer));

	listener_stop(&l, loop);
	ev_loop_destroy(loop);
}

static const struct testing_suite suite[] = {
	T_CASE(test_listener_start_binds_port),
	T_CASE(test_listener_stop_after_start),
	T_CASE(test_listener_start_bad_addr_fails),
	T_CASE(test_listener_serve_fn_called),
	T_CASE(test_listener_accept_drains_multiple_in_one_wakeup),
	T_CASE(test_listener_stop_and_restart_binds_again),
	T_CASE(test_listener_accept_network_error_keeps_accepting),
	T_CASE(test_listener_accept_invalid_fd_backs_off),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
