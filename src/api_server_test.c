/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * api_server_test.c - unit tests for the REST API server.
 *
 * Each test constructs a minimal struct server (no server_start()), pairs two
 * AF_UNIX socket ends with socketpair(), and passes the server-side fd to
 * api_serve().  The client-side fd is driven by a local ev_loop through the
 * standard wait_until() predicate pattern.
 *
 * Covered routes
 *   GET  /healthy              → 200, empty body
 *   GET  /stats                → 200, text/plain, sessions/streams lines
 *   POST /stats                → 200, text/plain, Server Load line
 *   GET  /metrics              → 200, text/plain Prometheus format, multiplexd_* lines
 *   GET  /nonexistent          → 404
 *   DELETE /stats              → 405
 *   oversized request          → 413
 *   keep-alive reuse           → two successive 200s on one connection
 *   Connection: close          → 200 then peer EOF
 */

#include "api_server.h"
#include "conf.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "os/clock.h"
#include "os/socket.h"
#include "server.h"
#include "util.h"

#include "utils/testing.h"

#include <ev.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif

#if WITH_THREADS
#define STORE_STAT(field, value)                                               \
	atomic_store_explicit(&(field), (value), memory_order_relaxed)
#else
#define STORE_STAT(field, value) ((field) = (value))
#endif

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

enum {
	/* Size of the buffer used to collect a single HTTP response. */
	RESP_BUF_SIZE = 16384,
	/* Timeout in seconds for a complete HTTP response to arrive. */
	API_RESP_TIMEOUT_MS = 2000,
};

/* -------------------------------------------------------------------------
 * Fixture
 * ---------------------------------------------------------------------- */

/*
 * Minimal test fixture: a struct server initialised without server_start().
 * api_server.c only reads srv.conf, srv.started, srv.stats, and srv.sessions,
 * so everything else can be zero-initialised.
 */
struct apifx {
	struct ev_loop *loop;
	struct config conf;
	struct server srv;
	struct listener api_listener;
	int cli_fd;
};

static struct mux_frame *api_test_alloc(void *data)
{
	UNUSED(data);
	return malloc(sizeof(struct mux_frame));
}

static void api_test_free(void *data, struct mux_frame *frame)
{
	UNUSED(data);
	free(frame);
}

static struct tunnel *make_established_tunnel(
	struct apifx *restrict fx, const char *restrict peer_id,
	const size_t num_streams)
{
	static const struct tunnel_callbacks cb = { 0 };
	static const unsigned char session_id[MUX_SESSION_ID_LEN] = { 0 };
	fx->conf.mux.timeout = 60;
	fx->conf.mux.keepalive = 25;
	fx->conf.mux.send_timeout = 15;
	fx->conf.mux.connect_timeout = 15;
	fx->conf.mux.stream_window = 2;
	fx->conf.mux.session_window = 128;
	fx->conf.mux.max_streams = 32;
	fx->conf.mux.max_halfopen = 16;
	fx->conf.mux.nodelay = true;

	const struct tunnel_opts opts = {
		.cb = &cb,
		.data = NULL,
		.mux_conf = &fx->conf.mux,
		.pool = { api_test_alloc, api_test_free, NULL },
		.fd = -1,
		.id = session_id,
		.connect_addr = "127.0.0.1:1",
		.forward_addr = NULL,
		.identity = "self",
		.peer_id = peer_id,
	};
	struct tunnel *const t = tunnel_new(&fx->srv, &opts);
	if (t == NULL) {
		return NULL;
	}
	struct mux_session *const ss = tunnel_session(t);
	ss->stream_window = 2;
	ss->peer_stream_window = 4;
	ss->state = SESSION_ESTABLISHED;
	for (size_t i = 0; i < num_streams; i++) {
		struct mux_stream *const s =
			stream_new(ss, (uint_fast16_t)(i * 2u + 1u), true);
		if (s == NULL) {
			tunnel_close(t);
			return NULL;
		}
		if (!sched_add_stream(ss, s)) {
			stream_free(s);
			tunnel_close(t);
			return NULL;
		}
	}
	return t;
}

static int apifx_setup(struct apifx *restrict fx)
{
	*fx = (struct apifx){
		.cli_fd = -1,
	};

	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}

	fx->conf = (struct config){
		.mux_listen = NULL,
	};

	fx->srv = (struct server){
		.conf = &fx->conf,
		.started = clock_monotonic_ns(),
		.accepted_tunnels = NULL,
	};

	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	/* fds[0] = server side (transferred to api_serve), fds[1] = client side */
	if (socket_set_nonblock(fds[0]) != 0 ||
	    socket_set_nonblock(fds[1]) != 0) {
		close(fds[0]);
		close(fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}

	fx->cli_fd = fds[1];
	fx->api_listener.srv = &fx->srv;
	api_serve(&fx->api_listener, fx->loop, fds[0], NULL);
	return 0;
}

struct teardown_waiter {
	bool ticked;
	bool timed_out;
	ev_timer w_tick;
	ev_timer w_timeout;
};

static void
teardown_waiter_tick_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	UNUSED(loop);
	UNUSED(revents);
	struct teardown_waiter *restrict tw = w->data;
	tw->ticked = true;
}

static void
teardown_waiter_timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	UNUSED(loop);
	UNUSED(revents);
	struct teardown_waiter *restrict tw = w->data;
	tw->timed_out = true;
}

static void apifx_teardown(struct apifx *restrict fx)
{
	if (fx == NULL) {
		return;
	}
	if (fx->srv.identities != NULL) {
		for (size_t i = 0; i < fx->srv.num_identities; i++) {
			for (size_t j = 0;
			     j < fx->srv.identities[i].num_tunnels; j++) {
				tunnel_close(fx->srv.identities[i].tunnels[j]);
			}
			free(fx->srv.identities[i].tunnels);
			fx->srv.identities[i].tunnels = NULL;
			fx->srv.identities[i].num_tunnels = 0;
		}
		free(fx->srv.identities);
		fx->srv.identities = NULL;
		fx->srv.num_identities = 0;
	}
	if (fx->cli_fd >= 0) {
		close(fx->cli_fd);
		fx->cli_fd = -1;
	}
	/* Drive one event-loop tick to process the EOF from the closed client fd.
	 * Timeout is a guard to keep teardown bounded if no event is pending. */
	struct teardown_waiter tw = {
		.ticked = false,
		.timed_out = false,
	};
	ev_timer_init(&tw.w_tick, teardown_waiter_tick_cb, 0.0, 0.0);
	ev_timer_init(&tw.w_timeout, teardown_waiter_timeout_cb, 0.1, 0.0);
	tw.w_tick.data = &tw;
	tw.w_timeout.data = &tw;
	ev_timer_start(fx->loop, &tw.w_tick);
	ev_timer_start(fx->loop, &tw.w_timeout);
	while (!tw.ticked && !tw.timed_out) {
		ev_run(fx->loop, EVRUN_ONCE);
	}
	ev_timer_stop(fx->loop, &tw.w_tick);
	ev_timer_stop(fx->loop, &tw.w_timeout);
	ev_loop_destroy(fx->loop);
	fx->loop = NULL;
}

/* -------------------------------------------------------------------------
 * wait_until() helper (same predicate-driven pattern as server_test.c)
 * ---------------------------------------------------------------------- */

typedef int (*apifx_predicate_fn)(void *ctx);

struct condition_waiter {
	bool timed_out;
	ev_timer w_timer;
};

static void
condition_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	UNUSED(loop);
	UNUSED(revents);
	struct condition_waiter *restrict cw = w->data;
	cw->timed_out = true;
}

/*
 * Drives fx->loop until predicate(ctx) returns non-zero or timeout expires.
 * Returns 0 on success (predicate returned > 0), -1 on error or timeout.
 */
static int wait_until(
	struct apifx *restrict fx, const double timeout_sec,
	apifx_predicate_fn predicate, void *ctx)
{
	struct condition_waiter cw = { .timed_out = false };
	ev_timer_init(&cw.w_timer, condition_waiter_timer_cb, timeout_sec, 0.0);
	cw.w_timer.data = &cw;
	ev_timer_start(fx->loop, &cw.w_timer);

	while (!cw.timed_out) {
		const int status = predicate(ctx);
		if (status != 0) {
			ev_timer_stop(fx->loop, &cw.w_timer);
			return status > 0 ? 0 : -1;
		}
		ev_run(fx->loop, EVRUN_ONCE);
	}

	ev_timer_stop(fx->loop, &cw.w_timer);
	errno = ETIMEDOUT;
	return -1;
}

/* -------------------------------------------------------------------------
 * do_send() — write an exact number of bytes to a non-blocking fd.
 * Small AF_UNIX payloads (< 64 KiB) never block in practice; the EAGAIN
 * branch is reached only under unusual system load and is handled by
 * retrying the write in a tight loop (no ev_loop involvement needed for
 * writes, unlike reads which require the server side to drain first).
 * ---------------------------------------------------------------------- */

static int do_send(const int fd, const void *restrict data, const size_t len)
{
	const char *restrict ptr = data;
	size_t sent = 0;
	while (sent < len) {
		const ssize_t n = write(fd, ptr + sent, len - sent);
		if (n < 0) {
			const int err = errno;
			if (err == EINTR || err == EAGAIN ||
			    err == EWOULDBLOCK || err == ENOBUFS ||
			    err == ENOMEM) {
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		sent += (size_t)n;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Response collection predicate
 * ---------------------------------------------------------------------- */

struct resp_wait_ctx {
	int fd;
	char buf[RESP_BUF_SIZE];
	size_t nread;
};

/*
 * Non-blocking incremental response reader.
 * Returns +1 when a complete HTTP response has been received (headers fully
 * parsed and body fully received as indicated by Content-Length), 0 when more
 * data is still pending, -1 on error.
 */
static int resp_wait_predicate(void *ptr)
{
	struct resp_wait_ctx *restrict ctx = ptr;

	if (ctx->nread < sizeof(ctx->buf) - 1u) {
		const ssize_t n =
			read(ctx->fd, ctx->buf + ctx->nread,
			     sizeof(ctx->buf) - 1u - ctx->nread);
		if (n < 0) {
			const int err = errno;
			if (err == EINTR || err == EAGAIN ||
			    err == EWOULDBLOCK || err == ENOBUFS ||
			    err == ENOMEM) {
				return 0;
			}
			return -1;
		}
		if (n == 0) {
			/* EOF: treat as complete if we already have headers */
			return ctx->nread > 0 ? 1 : -1;
		}
		ctx->nread += (size_t)n;
		ctx->buf[ctx->nread] = '\0';
	}

	/* Check that the header section has arrived */
	const char *restrict hend = strstr(ctx->buf, "\r\n\r\n");
	if (hend == NULL) {
		return 0;
	}

	/* Determine body length from Content-Length header */
	const char *restrict cl = strstr(ctx->buf, "\r\nContent-Length: ");
	size_t content_length = 0;
	if (cl != NULL) {
		content_length = (size_t)strtoul(cl + 18, NULL, 10);
	}

	const size_t body_offset = (size_t)(hend - ctx->buf) + 4u;
	if (ctx->nread >= body_offset + content_length) {
		return 1;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * EOF predicate — used by test_connection_close
 * ---------------------------------------------------------------------- */

struct eof_wait_ctx {
	int fd;
};

static int eof_wait_predicate(void *ptr)
{
	const struct eof_wait_ctx *restrict ctx = ptr;
	char buf[1];
	const ssize_t n = read(ctx->fd, buf, sizeof(buf));
	if (n < 0) {
		const int err = errno;
		if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK ||
		    err == ENOBUFS || err == ENOMEM) {
			return 0;
		}
		return -1;
	}
	return n == 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Response inspection helpers
 * ---------------------------------------------------------------------- */

/* Returns the HTTP status code from the response in buf, or -1 on failure. */
static int parse_status(const char *restrict buf)
{
	static const char pfx[] = "HTTP/1.1 ";
	const size_t pfx_len = sizeof(pfx) - 1u;
	if (strncmp(buf, pfx, pfx_len) != 0) {
		return -1;
	}
	char *end;
	const long code = strtol(buf + pfx_len, &end, 10);
	if (end == buf + pfx_len || code < 100 || code > 999) {
		return -1;
	}
	return (int)code;
}

/*
 * Returns true when needle appears anywhere in the NUL-terminated response
 * buf.  For header-only checks (e.g. Content-Type) this is sufficient because
 * the relevant strings do not appear elsewhere; for body-only checks the same
 * holds for the stats field names used below.
 */
static bool resp_contains(const char *restrict buf, const char *restrict needle)
{
	return strstr(buf, needle) != NULL;
}

/* -------------------------------------------------------------------------
 * Individual test fixtures — small inline request strings
 * ---------------------------------------------------------------------- */

#define REQ_HEALTHY_GET                                                        \
	"GET /healthy HTTP/1.1\r\n"                                            \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_STATS_GET                                                          \
	"GET /stats HTTP/1.1\r\n"                                              \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_STATS_GET_NOBANNER                                                 \
	"GET /stats?nobanner=1 HTTP/1.1\r\n"                                   \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_STATS_POST                                                         \
	"POST /stats HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"Content-Length: 0\r\n"                                                \
	"\r\n"

#define REQ_METRICS_GET                                                        \
	"GET /metrics HTTP/1.1\r\n"                                            \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_NOTFOUND_GET                                                       \
	"GET /nonexistent HTTP/1.1\r\n"                                        \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_STATS_DELETE                                                       \
	"DELETE /stats HTTP/1.1\r\n"                                           \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_HEALTHY_CLOSE                                                      \
	"GET /healthy HTTP/1.1\r\n"                                            \
	"Host: test\r\n"                                                       \
	"Connection: close\r\n"                                                \
	"\r\n"

#define REQ_HEALTHY_HTTP10                                                     \
	"GET /healthy HTTP/1.0\r\n"                                            \
	"Host: test\r\n"                                                       \
	"\r\n"

/* -------------------------------------------------------------------------
 * Helper — perform a single HTTP exchange on fx and fill rctx.
 * Returns 0 on success, -1 on timeout or error.
 * ---------------------------------------------------------------------- */

static int do_exchange(
	struct apifx *restrict fx, struct resp_wait_ctx *restrict rctx,
	const char *restrict request)
{
	*rctx = (struct resp_wait_ctx){ .fd = fx->cli_fd, .nread = 0 };
	if (do_send(fx->cli_fd, request, strlen(request)) != 0) {
		return -1;
	}
	return wait_until(
		fx, (double)API_RESP_TIMEOUT_MS / 1000.0, resp_wait_predicate,
		rctx);
}

/*
 * Performs a single HTTP exchange and aborts the test case immediately on
 * failure.  rctx->buf is valid for inspection when this subcase returns.
 */
T_DECLARE_SUBCASE(
	assert_exchange, struct apifx *restrict fx,
	struct resp_wait_ctx *restrict rctx, const char *restrict request)
{
	if (do_exchange(fx, rctx, request) != 0) {
		T_LOG("response timeout or send error");
		T_FAILNOW();
	}
}

/* =========================================================================
 * Test cases
 * ===================================================================== */

T_DECLARE_CASE(test_healthy_get)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Content-Length: 0"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_stats_get_text)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "text/plain"));
	T_EXPECT(resp_contains(rctx.buf, "Sessions"));
	T_EXPECT(resp_contains(rctx.buf, "Streams"));
	T_EXPECT(resp_contains(rctx.buf, "Stream Opens"));
	T_EXPECT(resp_contains(rctx.buf, "fastopen"));
	T_EXPECT(resp_contains(rctx.buf, "Stream Latency"));
#if WITH_TLS
	T_EXPECT(resp_contains(rctx.buf, "TLS Failures"));
#endif
	T_EXPECT(resp_contains(rctx.buf, "RST Frames"));
	T_EXPECT(resp_contains(rctx.buf, "Stream Errors"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_stats_get_nobanner)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET_NOBANNER);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "text/plain"));
	T_EXPECT(resp_contains(rctx.buf, "Server Time"));
	T_EXPECT(!resp_contains(rctx.buf, "multiplexd "));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_stats_post_text)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_POST);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "text/plain"));
	T_EXPECT(resp_contains(rctx.buf, "Reconnects"));
	T_EXPECT(resp_contains(rctx.buf, "Server Load"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_metrics_get)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "text/plain; version=0.0.4"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_sessions "));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_stream_open_total"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_stream_fastopen_total"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_bytes_total"));
	T_EXPECT(resp_contains(
		rctx.buf, "multiplexd_stream_establish_latency_seconds_count"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_not_found)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_NOTFOUND_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 404);

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_method_not_allowed)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_DELETE);
	T_EXPECT_EQ(parse_status(rctx.buf), 405);

	apifx_teardown(&fx);
}

/*
 * Sends a request whose headers exceed HTTP_MAX_ENTITY (8192 bytes), causing
 * the receive buffer to fill before the header terminator is seen.  The server
 * must respond with 413 Entity Too Large.
 *
 * Request structure (no \r\n\r\n within the first 8192 bytes):
 *   "GET / HTTP/1.1\r\nX-Pad: " (23 bytes) + 8192 × 'a' (total ≈ 8 KiB)
 */
T_DECLARE_CASE(test_request_too_large)
{
	struct apifx fx;
	char *big_req = NULL;

	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	static const char pfx[] = "GET / HTTP/1.1\r\nX-Pad: ";
	const size_t pfx_len = sizeof(pfx) - 1u;
	const size_t pad_len = 65536;
	const size_t total = pfx_len + pad_len;

	big_req = malloc(total);
	if (big_req == NULL) {
		T_LOG("malloc failed");
		T_FAIL();
		goto cleanup;
	}
	memcpy(big_req, pfx, pfx_len);
	memset(big_req + pfx_len, 'a', pad_len);

	if (do_send(fx.cli_fd, big_req, total) != 0) {
		T_LOG("do_send failed");
		T_FAIL();
		goto cleanup;
	}

	struct resp_wait_ctx rctx = { .fd = fx.cli_fd };
	if (wait_until(
		    &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
		    resp_wait_predicate, &rctx) != 0) {
		T_LOG("response timeout");
		T_FAIL();
		goto cleanup;
	}
	T_EXPECT_EQ(parse_status(rctx.buf), 413);

cleanup:
	free(big_req);
	apifx_teardown(&fx);
}

/*
 * Sends two GET /healthy requests on the same HTTP/1.1 connection (default
 * keep-alive) and verifies that both receive a 200 response without
 * reconnecting.
 */
T_DECLARE_CASE(test_keepalive)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx1;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx1, REQ_HEALTHY_GET);
	T_EXPECT_EQ(parse_status(rctx1.buf), 200);
	T_EXPECT(resp_contains(rctx1.buf, "keep-alive"));

	/* Second request on the same connection */
	struct resp_wait_ctx rctx2;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx2, REQ_HEALTHY_GET);
	T_EXPECT_EQ(parse_status(rctx2.buf), 200);

	apifx_teardown(&fx);
}

/*
 * Sends "Connection: close" and verifies the server closes the connection
 * after sending the response.
 */
T_DECLARE_CASE(test_connection_close)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_CLOSE);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Connection: close"));

	/* After the response the server must have closed srv_fd; expect EOF. */
	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	if (wait_until(
		    &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
		    eof_wait_predicate, &ectx) != 0) {
		T_LOG("expected EOF after Connection: close not received");
		T_FAIL();
	}

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_stats_get_includes_identity_rows)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = calloc(2, sizeof(*fx.srv.identities));
	T_CHECK(fx.srv.identities != NULL);
	fx.srv.num_identities = 2;
	fx.srv.identities[0].peer_identity = "peer-offline";
	struct tunnel *t0 = make_established_tunnel(&fx, "peer-offline", 0);
	T_CHECK(t0 != NULL);
	/* Reset to non-established so tunnel_stats() reports !established. */
	tunnel_session(t0)->state = SESSION_CONNECT;
	fx.srv.identities[0].tunnels = malloc(sizeof(struct tunnel *));
	T_CHECK(fx.srv.identities[0].tunnels != NULL);
	fx.srv.identities[0].tunnels[0] = t0;
	fx.srv.identities[0].num_tunnels = 1;
	fx.srv.identities[1].peer_identity = "peer-online";
	struct tunnel *restrict t1 =
		make_established_tunnel(&fx, "peer-online", 3);
	T_CHECK(t1 != NULL);
	fx.srv.identities[1].tunnels = malloc(sizeof(struct tunnel *));
	T_CHECK(fx.srv.identities[1].tunnels != NULL);
	fx.srv.identities[1].tunnels[0] = t1;
	fx.srv.identities[1].num_tunnels = 1;

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "> Sessions"));
	T_EXPECT(resp_contains(rctx.buf, "peer-offline"));
	T_EXPECT(resp_contains(rctx.buf, "offline"));
	T_EXPECT(resp_contains(rctx.buf, "peer-online"));
	T_EXPECT(resp_contains(rctx.buf, "W=Rx"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_stats_identity_shows_window_when_rtt_known)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = calloc(1, sizeof(*fx.srv.identities));
	T_CHECK(fx.srv.identities != NULL);
	fx.srv.num_identities = 1;
	fx.srv.identities[0].peer_identity = "peer-rtt";
	struct tunnel *restrict t1 =
		make_established_tunnel(&fx, "peer-rtt", 1);
	T_CHECK(t1 != NULL);
	struct mux_session *const ss = tunnel_session(t1);
	/* 20 ms RTT — stored in seconds in the estimator window */
	ss->estimator.rtt_wnd[0].val = 0.020;
	fx.srv.identities[0].tunnels = malloc(sizeof(struct tunnel *));
	T_CHECK(fx.srv.identities[0].tunnels != NULL);
	fx.srv.identities[0].tunnels[0] = t1;
	fx.srv.identities[0].num_tunnels = 1;

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "peer-rtt"));
	T_EXPECT(resp_contains(rctx.buf, "W=Rx"));
	T_EXPECT(resp_contains(rctx.buf, "RTT"));
	T_EXPECT(!resp_contains(rctx.buf, "BW=Rx"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_metrics_reports_identity_window_bytes)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = calloc(1, sizeof(*fx.srv.identities));
	T_CHECK(fx.srv.identities != NULL);
	fx.srv.num_identities = 1;
	fx.srv.identities[0].peer_identity = "peer-win";
	struct tunnel *restrict t1 =
		make_established_tunnel(&fx, "peer-win", 1);
	T_CHECK(t1 != NULL);
	struct mux_session *const ss = tunnel_session(t1);
	ss->stream_window = 2;
	ss->peer_stream_window = 4;
	fx.srv.identities[0].tunnels = malloc(sizeof(struct tunnel *));
	T_CHECK(fx.srv.identities[0].tunnels != NULL);
	fx.srv.identities[0].tunnels[0] = t1;
	fx.srv.identities[0].num_tunnels = 1;

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	/* rx_window = 2 * 16384 = 32768, tx_window = 4 * 16384 = 65536 */
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_rx_window_bytes{identity=\"peer-win\",tag=\"self => 127.0.0.1:1\"} 32768"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_tx_window_bytes{identity=\"peer-win\",tag=\"self => 127.0.0.1:1\"} 65536"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_stats_post_tracks_rate_deltas)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.started = clock_monotonic_ns() - 5 * 1000 * 1000 * 1000LL;
	STORE_STAT(fx.srv.counters.traffic_byt_mux_recv, 2048);
	STORE_STAT(fx.srv.counters.traffic_byt_mux_sent, 4096);
	STORE_STAT(fx.srv.counters.traffic_byt_local_recv, 1024);
	STORE_STAT(fx.srv.counters.traffic_byt_local_sent, 512);

	struct resp_wait_ctx rctx1;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx1, REQ_STATS_POST);
	T_EXPECT_EQ(parse_status(rctx1.buf), 200);
	T_EXPECT(resp_contains(rctx1.buf, "Mux Throughput"));
	T_EXPECT(resp_contains(rctx1.buf, "Server Load"));
	T_EXPECT(fx.srv.rate_tracker.is_set);
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_mux_recv, (uintmax_t)2048);
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_mux_sent, (uintmax_t)4096);
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_local_recv, (uintmax_t)1024);
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_local_sent, (uintmax_t)512);

	STORE_STAT(fx.srv.counters.traffic_byt_mux_recv, 3072);
	STORE_STAT(fx.srv.counters.traffic_byt_mux_sent, 6144);
	STORE_STAT(fx.srv.counters.traffic_byt_local_recv, 1536);
	STORE_STAT(fx.srv.counters.traffic_byt_local_sent, 768);
	fx.srv.rate_tracker.timestamp =
		clock_monotonic_ns() - 2 * 1000 * 1000 * 1000LL;

	struct resp_wait_ctx rctx2;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx2, REQ_STATS_POST);
	T_EXPECT_EQ(parse_status(rctx2.buf), 200);
	T_EXPECT(resp_contains(rctx2.buf, "Mux Throughput"));
	T_EXPECT(resp_contains(rctx2.buf, "TCP Throughput"));
	T_EXPECT(resp_contains(rctx2.buf, "Server Load"));
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_mux_recv, (uintmax_t)3072);
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_mux_sent, (uintmax_t)6144);
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_local_recv, (uintmax_t)1536);
	T_EXPECT_EQ(fx.srv.rate_tracker.byt_local_sent, (uintmax_t)768);

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_metrics_reports_non_zero_mux_counters)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	STORE_STAT(fx.srv.counters.num_reconnects, 7);
	STORE_STAT(fx.srv.counters.num_rst_sent, 11);
	STORE_STAT(fx.srv.counters.num_rst_recv, 17);
	STORE_STAT(fx.srv.counters.num_stream_errors, 19);
	STORE_STAT(fx.srv.counters.traffic_byt_mux_recv, 1234);
	STORE_STAT(fx.srv.counters.traffic_byt_mux_sent, 2345);
	STORE_STAT(fx.srv.counters.traffic_byt_local_recv, 3456);
	STORE_STAT(fx.srv.counters.traffic_byt_local_sent, 4567);

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_reconnects_total 7"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_rst_sent_total 11"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_rst_recv_total 17"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_stream_errors_total 19"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_bytes_total{direction=\"recv\",link=\"mux\"} 1234"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_bytes_total{direction=\"sent\",link=\"local\"} 4567"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_not_found_keepalive_followed_by_success)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx1;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx1, REQ_NOTFOUND_GET);
	T_EXPECT_EQ(parse_status(rctx1.buf), 404);
	T_EXPECT(resp_contains(rctx1.buf, "Connection: keep-alive"));

	struct resp_wait_ctx rctx2;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx2, REQ_HEALTHY_GET);
	T_EXPECT_EQ(parse_status(rctx2.buf), 200);
	T_EXPECT(resp_contains(rctx2.buf, "Content-Length: 0"));

	apifx_teardown(&fx);
}

T_DECLARE_CASE(test_connection_close_on_non_keepalive_request)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_HTTP10);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Connection: close"));

	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	if (wait_until(
		    &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
		    eof_wait_predicate, &ectx) != 0) {
		T_LOG("expected EOF after HTTP/1.0 request not received");
		T_FAIL();
	}

	apifx_teardown(&fx);
}

/* =========================================================================
 * main
 * ===================================================================== */

int main(void)
{
	loadlibs();

	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_healthy_get);
	T_RUN_CASE(t, test_stats_get_text);
	T_RUN_CASE(t, test_stats_get_nobanner);
	T_RUN_CASE(t, test_stats_post_text);
	T_RUN_CASE(t, test_metrics_get);
	T_RUN_CASE(t, test_not_found);
	T_RUN_CASE(t, test_method_not_allowed);
	T_RUN_CASE(t, test_request_too_large);
	T_RUN_CASE(t, test_keepalive);
	T_RUN_CASE(t, test_connection_close);
	T_RUN_CASE(t, test_stats_get_includes_identity_rows);
	T_RUN_CASE(t, test_stats_identity_shows_window_when_rtt_known);
	T_RUN_CASE(t, test_metrics_reports_identity_window_bytes);
	T_RUN_CASE(t, test_stats_post_tracks_rate_deltas);
	T_RUN_CASE(t, test_metrics_reports_non_zero_mux_counters);
	T_RUN_CASE(t, test_not_found_keepalive_followed_by_success);
	T_RUN_CASE(t, test_connection_close_on_non_keepalive_request);

	unloadlibs();
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
