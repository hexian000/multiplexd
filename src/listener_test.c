/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "listener.h"
#include "util.h"

#include "mux/mux.h"

#include "utils/testing.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const struct socket_opts g_socket_opts = {
	.backlog = 4,
};

static int g_serve_fd;
static int g_serve_calls;

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
	struct sockaddr_in sa;
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
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
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
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
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
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	/*
	 * 192.0.2.1 is TEST-NET-1 (RFC 5737) and is never a local interface
	 * address; bind() must fail with EADDRNOTAVAIL.
	 */
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
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	g_serve_fd = -1;
	g_serve_calls = 0;

	struct listener l;
	uintmax_t accepted = 0;
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
	peer.sin_port = htons((unsigned)port & 0xFFFFu);

	const int cfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(cfd >= 0);
	T_CHECK(connect(cfd, (const struct sockaddr *)&peer, sizeof(peer)) ==
		0);

	/* Drive the event loop once so accept_cb fires. */
	ev_run(loop, EVRUN_ONCE);

	T_EXPECT_EQ(g_serve_calls, 1);
	T_EXPECT((uintmax_t)accepted >= 1u);

	(void)close(cfd);
	listener_stop(&l, loop);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_listener_stop_and_restart_binds_again)
{
	struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_listener_start_binds_port);
	T_RUN_CASE(t, test_listener_stop_after_start);
	T_RUN_CASE(t, test_listener_start_bad_addr_fails);
	T_RUN_CASE(t, test_listener_serve_fn_called);
	T_RUN_CASE(t, test_listener_stop_and_restart_binds_again);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
