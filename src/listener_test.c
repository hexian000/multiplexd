/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* listener_test.c - black-box tests for the socket listener in listener.c via
 * its public API. Dependencies: links the real util.c and listener.c. */

#include "listener.h"

#include "conf.h"

#include "os/socket.h"
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
/* Peer address the serve callback received (accept-time @p accepted_sa) and the
 * accepted descriptor's own getpeername(), captured before the fd is closed. */
static union sockaddr_max g_serve_peer;
static union sockaddr_max g_serve_getpeer;
static bool g_serve_getpeer_ok;

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
	g_serve_fd = fd;
	g_serve_calls++;
	/* Record the accept-time peer address and the accepted fd's actual peer
	 * before ownership is released by closing it, so a case can verify both
	 * listener.h contracts (valid connected descriptor, correct peer). */
	sa_copy(&g_serve_peer.sa, sa);
	socklen_t getpeerlen = sizeof(g_serve_getpeer);
	g_serve_getpeer_ok =
		fd >= 0 &&
		getpeername(fd, &g_serve_getpeer.sa, &getpeerlen) == 0;
	(void)close(fd);
}

static void reset_serve_spy(void)
{
	g_serve_fd = -1;
	g_serve_calls = 0;
	g_serve_getpeer_ok = false;
	memset(&g_serve_peer, 0, sizeof(g_serve_peer));
	memset(&g_serve_getpeer, 0, sizeof(g_serve_getpeer));
}

static int get_bound_port(const struct listener *restrict l)
{
	const int fd = l->w_accept.fd;
	if (fd < 0) {
		return -1;
	}
	union sockaddr_max sa;
	memset(&sa, 0, sizeof(sa));
	socklen_t len = sizeof(sa);
	if (getsockname(fd, &sa.sa, &len) != 0) {
		return -1;
	}
	switch (sa.sa.sa_family) {
	case AF_INET:
		return (int)ntohs(sa.in.sin_port);
	case AF_INET6:
		return (int)ntohs(sa.in6.sin6_port);
	default:
		break;
	}
	return -1;
}

/* Build a loopback address for @p family with an "any" (ephemeral) port. */
static union sockaddr_max make_loopback_any(const int family)
{
	union sockaddr_max sa;
	memset(&sa, 0, sizeof(sa));
	switch (family) {
	case AF_INET:
		sa.in.sin_family = AF_INET;
		sa.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		break;
	case AF_INET6:
		sa.in6.sin6_family = AF_INET6;
		sa.in6.sin6_addr = in6addr_loopback;
		break;
	default:
		break;
	}
	return sa;
}

/* Set the port of a loopback address built by make_loopback_any. */
static void set_loopback_port(union sockaddr_max *restrict sa, const int port)
{
	switch (sa->sa.sa_family) {
	case AF_INET:
		sa->in.sin_port = htons((uint16_t)port);
		break;
	case AF_INET6:
		sa->in6.sin6_port = htons((uint16_t)port);
		break;
	default:
		break;
	}
}

/* Whether @p sa is its family's loopback address with a nonzero (ephemeral)
 * port. */
static bool is_loopback_with_port(const union sockaddr_max *restrict sa)
{
	switch (sa->sa.sa_family) {
	case AF_INET:
		return sa->in.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
		       sa->in.sin_port != 0;
	case AF_INET6:
		return memcmp(&sa->in6.sin6_addr, &in6addr_loopback,
			      sizeof(struct in6_addr)) == 0 &&
		       sa->in6.sin6_port != 0;
	default:
		break;
	}
	return false;
}

/* Whether the runtime has a usable IPv6 loopback (socket + bind [::1]:0). */
static bool ipv6_loopback_available(void)
{
	const int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		return false;
	}
	const union sockaddr_max sa = make_loopback_any(AF_INET6);
	const bool ok = bind(fd, &sa.sa, sa_len(&sa.sa)) == 0;
	(void)close(fd);
	return ok;
}

T_DECLARE_CASE(test_listener_start_binds_port)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	const union sockaddr_max sa = make_loopback_any(AF_INET);
	T_CHECK(listener_start(&l, loop, &sa.sa));

	/* Capture then tear down before asserting: a failing T_EXPECT longjmps
	 * out of the case, so cleanup must run first or it leaks the loop and the
	 * listening fd. */
	const int port = get_bound_port(&l);
	listener_stop(&l, loop);
	ev_loop_destroy(loop);

	T_EXPECT(port > 0);
}

T_DECLARE_CASE(test_listener_stop_after_start)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	const union sockaddr_max sa = make_loopback_any(AF_INET);
	T_CHECK(listener_start(&l, loop, &sa.sa));
	listener_stop(&l, loop);

	/* After stop the listening fd must be released. */
	const int accept_fd = l.w_accept.fd;
	ev_loop_destroy(loop);

	T_EXPECT_EQ(accept_fd, -1);
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

	const bool started =
		listener_start(&l, loop, (const struct sockaddr *)&bad);
	/* Defensive: on the unexpected success path, release the socket. */
	if (started) {
		listener_stop(&l, loop);
	}
	ev_loop_destroy(loop);

	T_EXPECT(!started);
}

/* Everything serve_one_connection observes about one accepted connection,
 * snapshotted before teardown so the assertions can run leak-free. */
struct serve_capture {
	bool timed_out;
	int serve_calls;
	uint_least64_t accepted;
	int serve_fd;
	bool getpeer_ok;
	bool client_ok;
	union sockaddr_max serve_peer;
	union sockaddr_max serve_getpeer;
	union sockaddr_max client;
};

/* Assert the listener.h serve-callback contracts for @p family against a
 * captured connection: exactly one serve, a valid accepted fd, and an
 * accepted_sa that is the connecting loopback client's address (accept-time ==
 * getpeername == client). Split out of serve_one_connection to keep each
 * function's complexity in check. */
T_DECLARE_SUBCASE(
	assert_serve_capture, int family, const struct serve_capture *c)
{
	T_EXPECT(!c->timed_out);
	T_EXPECT_EQ(c->serve_calls, 1);
	T_EXPECT(c->accepted >= 1u);

	/* The serve callback got a valid, connected descriptor. */
	T_EXPECT(c->serve_fd >= 0);
	T_EXPECT(c->getpeer_ok);
	T_EXPECT(c->client_ok);

	/* accepted_sa carries the requested family, equals the accepted fd's
	 * getpeername (peer at accept time), and both equal the connecting
	 * client's own local address. */
	T_EXPECT((int)c->serve_peer.sa.sa_family == family);
	T_EXPECT(sa_equals(&c->serve_peer.sa, &c->serve_getpeer.sa));
	T_EXPECT(sa_equals(&c->serve_getpeer.sa, &c->client.sa));

	/* That peer is the loopback address with a real ephemeral port. */
	T_EXPECT(is_loopback_with_port(&c->serve_peer));
}

/* Drive one accepted connection through the listener for @p family, snapshot
 * the result, tear down, then assert — so a failing T_EXPECT can never leak the
 * loop or sockets. */
T_DECLARE_SUBCASE(serve_one_connection, int family)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	reset_serve_spy();

	struct listener l;
	uint_least64_t accepted = 0;
	listener_init(&l, &g_socket_opts, test_serve, NULL, &accepted);

	const union sockaddr_max sa = make_loopback_any(family);
	T_CHECK(listener_start(&l, loop, &sa.sa));

	const int port = get_bound_port(&l);
	T_CHECK(port > 0);

	/* Connect a client so there is something to accept. */
	union sockaddr_max peer = make_loopback_any(family);
	set_loopback_port(&peer, port);

	const int cfd = socket(family, SOCK_STREAM, 0);
	T_CHECK(cfd >= 0);
	T_CHECK(connect(cfd, &peer.sa, sa_len(&peer.sa)) == 0);

	/* The client's own local address; the accepted socket's peer must equal
	 * it. Captured while cfd is open, i.e. before teardown. */
	struct serve_capture cap;
	memset(&cap, 0, sizeof(cap));
	socklen_t clientlen = sizeof(cap.client);
	cap.client_ok = getsockname(cfd, &cap.client.sa, &clientlen) == 0;

	/* Drive the event loop once so accept_cb fires; a watchdog timer fails
	 * the test instead of hanging the suite if it never does. */
	bool timed_out = false;
	ev_timer w_watchdog;
	ev_timer_init(&w_watchdog, watchdog_cb, 2.0, 0.0);
	w_watchdog.data = &timed_out;
	ev_timer_start(loop, &w_watchdog);

	ev_run(loop, EVRUN_ONCE);

	ev_timer_stop(loop, &w_watchdog);

	/* Snapshot everything the assertions read, then tear down before any
	 * assertion can longjmp past the cleanup. */
	cap.timed_out = timed_out;
	cap.serve_calls = g_serve_calls;
	cap.accepted = accepted;
	cap.serve_fd = g_serve_fd;
	cap.getpeer_ok = g_serve_getpeer_ok;
	cap.serve_peer = g_serve_peer;
	cap.serve_getpeer = g_serve_getpeer;

	(void)close(cfd);
	listener_stop(&l, loop);
	ev_loop_destroy(loop);

	T_CALL_SUBCASE(assert_serve_capture, family, &cap);
}

T_DECLARE_CASE(test_listener_serve_fn_called)
{
	T_CALL_SUBCASE(serve_one_connection, AF_INET);
}

/* IPv6 coverage for the family-agnostic listener_start/accept path: bind
 * [::1]:0, connect, and drive one accept. Skips gracefully when the runtime
 * has no usable IPv6 loopback rather than failing. */
T_DECLARE_CASE(test_listener_serve_fn_called_ipv6)
{
	if (!ipv6_loopback_available()) {
		T_SKIPNOW();
	}
	T_CALL_SUBCASE(serve_one_connection, AF_INET6);
}

/* accept_cb drains the whole kernel accept queue in one wakeup (its for(;;)
 * loop), not one connection per callback. Two clients are queued before a
 * single ev_run, and both must be served in it. */
T_DECLARE_CASE(test_listener_accept_drains_multiple_in_one_wakeup)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	reset_serve_spy();

	struct listener l;
	uint_least64_t accepted = 0;
	listener_init(&l, &g_socket_opts, test_serve, NULL, &accepted);

	const union sockaddr_max sa = make_loopback_any(AF_INET);
	T_CHECK(listener_start(&l, loop, &sa.sa));
	const int port = get_bound_port(&l);
	T_CHECK(port > 0);

	union sockaddr_max peer = make_loopback_any(AF_INET);
	set_loopback_port(&peer, port);

	/* Blocking connects complete the handshake synchronously, so both sit in
	 * the accept queue before the single ev_run below. */
	int cfd[2];
	for (int i = 0; i < 2; i++) {
		cfd[i] = socket(AF_INET, SOCK_STREAM, 0);
		T_CHECK(cfd[i] >= 0);
		T_CHECK(connect(cfd[i], &peer.sa, sa_len(&peer.sa)) == 0);
	}

	bool timed_out = false;
	ev_timer w_watchdog;
	ev_timer_init(&w_watchdog, watchdog_cb, 2.0, 0.0);
	w_watchdog.data = &timed_out;
	ev_timer_start(loop, &w_watchdog);

	ev_run(loop, EVRUN_ONCE); /* a single wakeup */

	ev_timer_stop(loop, &w_watchdog);

	const bool timed_out_v = timed_out;
	const int serve_calls = g_serve_calls;
	const uint_least64_t accepted_v = accepted;

	for (int i = 0; i < 2; i++) {
		(void)close(cfd[i]);
	}
	listener_stop(&l, loop);
	ev_loop_destroy(loop);

	T_EXPECT(!timed_out_v);
	/* Both accepted in the one wakeup; a single-accept-per-callback loop
	 * would reach only 1 here. */
	T_EXPECT_EQ(serve_calls, 2);
	T_EXPECT(accepted_v >= 2u);
}

T_DECLARE_CASE(test_listener_stop_and_restart_binds_again)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct listener l;
	listener_init(&l, &g_socket_opts, test_serve, NULL, NULL);

	const union sockaddr_max sa = make_loopback_any(AF_INET);
	T_CHECK(listener_start(&l, loop, &sa.sa));

	const int port1 = get_bound_port(&l);

	listener_stop(&l, loop);
	const int accept_fd = l.w_accept.fd;

	/* Start again; must successfully bind a new port. */
	T_CHECK(listener_start(&l, loop, &sa.sa));

	const int port2 = get_bound_port(&l);

	listener_stop(&l, loop);
	ev_loop_destroy(loop);

	T_EXPECT(port1 > 0);
	T_EXPECT_EQ(accept_fd, -1);
	T_EXPECT(port2 > 0);
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

	const bool accept_active = ev_is_active(&l.w_accept);
	const bool timer_active = ev_is_active(&l.w_timer);

	listener_stop(&l, loop);
	ev_loop_destroy(loop);

	/* Must keep accepting: the accept watcher stays armed and no backoff
	 * is scheduled. */
	T_EXPECT(accept_active);
	T_EXPECT(!timer_active);
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

	const bool timer_active = ev_is_active(&l.w_timer);

	listener_stop(&l, loop);
	ev_loop_destroy(loop);

	/* Must back off: the fallback path arms the retry timer. */
	T_EXPECT(timer_active);
}

/* Recovery contract for the accept-error backoff: the existing backoff test
 * only asserts the retry timer is armed. This fires timer_cb (without waiting
 * out the 0.5 s backoff) and verifies it restarts the accept watcher and that
 * connections are served again. */
T_DECLARE_CASE(test_listener_accept_backoff_timer_restarts_accept)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	reset_serve_spy();

	struct listener l;
	uint_least64_t accepted = 0;
	listener_init(&l, &g_socket_opts, test_serve, NULL, &accepted);

	const union sockaddr_max sa = make_loopback_any(AF_INET);
	T_CHECK(listener_start(&l, loop, &sa.sa));
	const int port = get_bound_port(&l);
	T_CHECK(port > 0);

	/* Enter the backed-off state accept_cb leaves after a fatal accept
	 * error: accept watcher stopped, retry timer armed. */
	ev_io_stop(loop, &l.w_accept);
	ev_timer_again(loop, &l.w_timer);
	T_CHECK(!ev_is_active(&l.w_accept));
	T_CHECK(ev_is_active(&l.w_timer));

	/* Fire the retry timer without waiting for the backoff interval. */
	ev_feed_event(loop, &l.w_timer, EV_TIMER);
	ev_invoke_pending(loop);

	/* timer_cb restarts the accept watcher and stops itself. */
	const bool accept_active = ev_is_active(&l.w_accept);
	const bool timer_active = ev_is_active(&l.w_timer);

	/* And a fresh connection is served again. */
	union sockaddr_max peer = make_loopback_any(AF_INET);
	set_loopback_port(&peer, port);
	const int cfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(cfd >= 0);
	T_CHECK(connect(cfd, &peer.sa, sa_len(&peer.sa)) == 0);

	bool timed_out = false;
	ev_timer w_watchdog;
	ev_timer_init(&w_watchdog, watchdog_cb, 2.0, 0.0);
	w_watchdog.data = &timed_out;
	ev_timer_start(loop, &w_watchdog);
	ev_run(loop, EVRUN_ONCE);
	ev_timer_stop(loop, &w_watchdog);

	const bool timed_out_v = timed_out;
	const int serve_calls = g_serve_calls;
	const uint_least64_t accepted_v = accepted;

	(void)close(cfd);
	listener_stop(&l, loop);
	ev_loop_destroy(loop);

	T_EXPECT(accept_active);
	T_EXPECT(!timer_active);
	T_EXPECT(!timed_out_v);
	T_EXPECT_EQ(serve_calls, 1);
	T_EXPECT(accepted_v >= 1u);
}

static const struct testing_suite suite[] = {
	T_CASE(test_listener_start_binds_port),
	T_CASE(test_listener_stop_after_start),
	T_CASE(test_listener_start_bad_addr_fails),
	T_CASE(test_listener_serve_fn_called),
	T_CASE(test_listener_serve_fn_called_ipv6),
	T_CASE(test_listener_accept_drains_multiple_in_one_wakeup),
	T_CASE(test_listener_stop_and_restart_binds_again),
	T_CASE(test_listener_accept_network_error_keeps_accepting),
	T_CASE(test_listener_accept_invalid_fd_backs_off),
	T_CASE(test_listener_accept_backoff_timer_restarts_accept),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
