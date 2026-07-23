/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* api_server_test.c - black-box tests for the REST API server (real stack
 * linked); each test drives a socketpair via api_serve(); covers healthy,
 * stats, metrics, 404/405/413, keep-alive, and Connection: close. */

#include "api_server.h"

#include "conf.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "server.h"
#include "tunnel.h"

#include "algo/hashtable.h"
#include "os/clock.h"
#include "os/socket.h"
#include "strings/format.h"
#include "sync/task.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <locale.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if WITH_THREADS
#define STORE_STAT(field, value)                                               \
	atomic_store_explicit(&(field), (value), memory_order_relaxed)
#else
#define STORE_STAT(field, value) ((field) = (value))
#endif

/* Constants */

enum {
	/* Size of the buffer used to collect a single HTTP response. */
	RESP_BUF_SIZE = 16384,
	/* Timeout in milliseconds for a complete HTTP response. */
	API_RESP_TIMEOUT_MS = 2000,
	/* Re-poll cadence for the client fd while waiting (see wait_until). */
	API_POLL_INTERVAL_MS = 5,
	/* Timeout for a single blocked write to become writable again (do_send);
	 * matches server_test.c's IO_WAIT_TIMEOUT_MS for the same wait shape. */
	IO_WAIT_TIMEOUT_MS = 20000,
};

/* ── tunnel_context helpers for the test fixture ─────────────────────── */

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

static void test_inc_reconnect(void *user)
{
	(void)user;
}

#if WITH_THREADS
static bool test_post_task(void *user, struct task task)
{
	(void)user;
	(void)task;
	return false;
}

static void test_flush_tasks(void *user)
{
	(void)user;
}
#endif /* WITH_THREADS */

static struct tunnel_session_counters
test_make_tunnel_counters(struct server *srv)
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
		.num_rst_sent = &srv->counters.num_rst_sent,
		.num_rst_recv = &srv->counters.num_rst_recv,
		.num_stream_errors = &srv->counters.num_stream_errors,
		.recv_buffered_bytes = &srv->counters.recv_buffered_bytes,
		.send_buffered_frames = &srv->counters.send_buffered_frames,
		.unacked_frames = &srv->counters.unacked_frames,
	};
}

static struct tunnel_context test_make_tunnel_context(struct server *srv)
{
	return (struct tunnel_context){
#if WITH_THREADS
		.post_task = test_post_task,
		.flush_tasks = test_flush_tasks,
#endif
		.verify_peer = test_verify_peer,
		.alloc_index = test_alloc_index,
		.inc_reconnect = test_inc_reconnect,
		.user = srv,
#if !WITH_THREADS
		.loop = srv->loop,
#endif
	};
}

/* ─────────────────────────────────────────────────────────────────────── */

/* Fixture */

/* Minimal fixture: struct server without server_start(); api_server only
 * reads conf, started, stats, and sessions. */
struct apifx {
	struct ev_loop *loop;
	struct config conf;
	struct server srv;
	struct listener api_listener;
	int cli_fd;
};

static struct tunnel *make_established_tunnel(
	struct apifx *restrict fx, const char *restrict peer_id,
	const size_t num_streams)
{
	static const struct tunnel_callbacks cb = { 0 };
	static const unsigned char session_id[MUX_SESSION_ID_LEN] = { 0 };
	fx->conf.mux.timeout = 600;
	fx->conf.mux.keepalive = 25;
	fx->conf.mux.send_timeout = 15;
	fx->conf.mux.connect_timeout = 15;
	fx->conf.mux.stream_window = 2;
	fx->conf.mux.session_window = 128;
	fx->conf.mux.max_streams = 32;
	fx->conf.mux.max_halfopen = 16;
	fx->conf.mux.nodelay = true;

	const struct mux_config mux_cfg = conf_get_mux(&fx->conf);
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&fx->srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&fx->srv);
	const struct tunnel_opts opts = {
		.cb = &cb,
		.data = NULL,
		.mux_conf = &mux_cfg,
		.fd = -1,
		.id = session_id,
		.connect_addr = "127.0.0.1:1",
		.forward_addr = NULL,
		.identity = "self",
		.peer_id = peer_id,
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	if (t == NULL) {
		return NULL;
	}
	struct mux_session *const ss = tunnel_session(t);
	/* White-box setup: use the setters / mirror so the stats path (which reads
	 * the relaxed-atomic mirrors) observes the fabricated state. */
	session_set_stream_window(ss, 2);
	session_set_peer_stream_window(ss, 4);
	ss->state = SESSION_ESTABLISHED;
	PUB_STORE(ss->_pub_state, SESSION_ESTABLISHED);
	for (size_t i = 0; i < num_streams; i++) {
		struct mux_stream *const s =
			mux_stream_new(ss, (uint_fast16_t)(i * 2u + 1u), true);
		if (s == NULL) {
			tunnel_close(t);
			return NULL;
		}
		if (!mux_sched_add_stream(ss, s)) {
			mux_stream_free(s);
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
		.mux = { .max_frame_payload =
				 mux_conf_default.max_frame_payload },
	};

	fx->srv = (struct server){
		.conf = &fx->conf,
		.loop = fx->loop,
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
	if (!socket_set_nonblock(fds[0]) || !socket_set_nonblock(fds[1])) {
		(void)close(fds[0]);
		(void)close(fds[1]);
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
	(void)loop;
	(void)revents;
	struct teardown_waiter *const restrict tw = w->data;
	tw->ticked = true;
}

static void
teardown_waiter_timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)revents;
	struct teardown_waiter *const restrict tw = w->data;
	tw->timed_out = true;
}

static void apifx_teardown(struct apifx *restrict fx)
{
	if (fx == NULL) {
		return;
	}
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(fx->srv.identities, &cursor, NULL, &elem)) {
			struct identity_listener *const sl = elem;
			for (size_t j = 0; j < sl->num_tunnels; j++) {
				tunnel_close(sl->tunnels[j]);
			}
			free((void *)sl->tunnels);
			sl->tunnels = NULL;
			sl->num_tunnels = 0;
			free(sl);
		}
		table_free(fx->srv.identities);
		fx->srv.identities = NULL;
	}
	if (fx->cli_fd >= 0) {
		(void)close(fx->cli_fd);
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

/* wait_until() helper (same predicate-driven pattern as server_test.c) */

typedef int (*apifx_predicate_fn)(void *ctx);

struct condition_waiter {
	bool timed_out;
	ev_timer w_timeout;
	ev_timer w_poll;
};

static void
condition_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)revents;
	struct condition_waiter *const restrict cw = w->data;
	cw->timed_out = true;
}

static void
condition_waiter_poll_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
	/* No state to update: this watcher exists only to bound how long
	 * ev_run() blocks so the loop re-polls the client fd (see wait_until). */
}

/* Drives fx->loop until predicate returns nonzero or timeout expires.
 * The poll timer re-enters the loop so the predicate re-checks the fd
 * on platforms where AF_UNIX delivery is asynchronous. */
static int wait_until(
	struct apifx *restrict fx, const double timeout_sec,
	apifx_predicate_fn predicate, void *ctx)
{
	struct condition_waiter cw = { .timed_out = false };
	ev_timer_init(
		&cw.w_timeout, condition_waiter_timer_cb, timeout_sec, 0.0);
	cw.w_timeout.data = &cw;
	ev_timer_start(fx->loop, &cw.w_timeout);

	const double poll_interval = (double)API_POLL_INTERVAL_MS / 1000.0;
	ev_timer_init(
		&cw.w_poll, condition_waiter_poll_cb, poll_interval,
		poll_interval);
	cw.w_poll.data = &cw;
	ev_timer_start(fx->loop, &cw.w_poll);

	while (!cw.timed_out) {
		const int status = predicate(ctx);
		if (status != 0) {
			ev_timer_stop(fx->loop, &cw.w_timeout);
			ev_timer_stop(fx->loop, &cw.w_poll);
			return status > 0 ? 0 : -1;
		}
		ev_run(fx->loop, EVRUN_ONCE);
	}

	ev_timer_stop(fx->loop, &cw.w_timeout);
	ev_timer_stop(fx->loop, &cw.w_poll);
	errno = ETIMEDOUT;
	return -1;
}

/* fd_waiter: wait for a specific fd event (or timeout), driving fx->loop so
 * the server side (sharing the same loop) gets a chance to drain the
 * socketpair -- same pattern as server_test.c's write_full/wait_fd_events. */

struct fd_waiter {
	bool done;
	bool timed_out;
	int revents;
	ev_io w_io;
	ev_timer w_timer;
};

static void fd_waiter_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	struct fd_waiter *const restrict waiter = w->data;
	waiter->revents = revents;
	waiter->done = true;
	ev_io_stop(loop, &waiter->w_io);
	ev_timer_stop(loop, &waiter->w_timer);
}

static void
fd_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)revents;
	struct fd_waiter *const restrict waiter = w->data;
	waiter->timed_out = true;
	waiter->done = true;
	ev_timer_stop(loop, &waiter->w_timer);
	ev_io_stop(loop, &waiter->w_io);
}

static int wait_fd_events(
	struct apifx *restrict fx, const int fd, const int events,
	const double timeout_sec)
{
	struct fd_waiter waiter = {
		.done = false,
		.timed_out = false,
		.revents = 0,
	};
	ev_io_init(&waiter.w_io, fd_waiter_io_cb, fd, events);
	ev_timer_init(&waiter.w_timer, fd_waiter_timer_cb, timeout_sec, 0.0);
	waiter.w_io.data = &waiter;
	waiter.w_timer.data = &waiter;
	ev_io_start(fx->loop, &waiter.w_io);
	ev_timer_start(fx->loop, &waiter.w_timer);

	while (!waiter.done) {
		ev_run(fx->loop, EVRUN_ONCE);
	}

	/* Prefer reported I/O over the timeout: a clock jump can make libev fire
	 * the timeout and the io watcher in the same iteration, and the data must
	 * not be discarded in that case. */
	if (waiter.revents != 0) {
		return waiter.revents;
	}
	return 0;
}

/* do_send(): writes exactly len bytes to a non-blocking fd. On EAGAIN,
 * drives fx->loop via wait_fd_events (not busy-spin) so the server side
 * can drain the socketpair on the same loop. Returns 0 on success, else
 * the errno describing the failure (e.g. ETIMEDOUT, EPIPE). */

static int
do_send(struct apifx *restrict fx, const int fd, const void *restrict data,
	const size_t len)
{
	const char *const restrict ptr = data;
	size_t sent = 0;
	while (sent < len) {
		const ssize_t n =
			send(fd, ptr + sent, len - sent, MSG_NOSIGNAL);
		if (n < 0) {
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				if ((wait_fd_events(
					     fx, fd, EV_WRITE,
					     (double)IO_WAIT_TIMEOUT_MS /
						     1000.0) &
				     EV_WRITE) == 0) {
					return ETIMEDOUT;
				}
				continue;
			}
			return err;
		}
		if (n == 0) {
			return ECONNRESET;
		}
		sent += (size_t)n;
	}
	return 0;
}

/* Response collection predicate */

struct resp_wait_ctx {
	int fd;
	char buf[RESP_BUF_SIZE];
	size_t nread;
};

/* Non-blocking incremental response reader.  Returns +1 on a complete response
 * (headers parsed, body received per Content-Length), 0 if pending, -1 on error. */
static int resp_wait_predicate(void *ptr)
{
	struct resp_wait_ctx *const restrict ctx = ptr;

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
	const char *const restrict hend = strstr(ctx->buf, "\r\n\r\n");
	if (hend == NULL) {
		return 0;
	}

	/* Determine body length from Content-Length header */
	const char *const restrict cl =
		strstr(ctx->buf, "\r\nContent-Length: ");
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

/* EOF predicate — used by test_connection_close */

struct eof_wait_ctx {
	int fd;
};

static int eof_wait_predicate(void *ptr)
{
	const struct eof_wait_ctx *const restrict ctx = ptr;
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

/* 413 path: server closes, which may surface as a reset discarding the
 * queued response. Treat any non-pending result as success so both
 * a 413 and a peer reset are acceptable. */
static int oversized_wait_predicate(void *ptr)
{
	return resp_wait_predicate(ptr) != 0 ? 1 : 0;
}

/* Response inspection helpers */

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

/* Returns true when needle appears anywhere in the NUL-terminated response;
 * sufficient here since the checked strings are unambiguous. */
static bool resp_contains(const char *restrict buf, const char *restrict needle)
{
	return strstr(buf, needle) != NULL;
}

/* The Date header's day/month names must always be the RFC
 * 7231-mandated English abbreviations, regardless of the process locale
 * set by init()'s own setlocale(LC_ALL, ""). Parses the full IMF-fixdate
 * structure (not just the two name fields) so a malformed date -- e.g.
 * strftime returning 0 under an overflowing localized expansion,
 * producing an empty Date header -- fails this check too, not just a
 * wrong-language one. */
static bool resp_date_is_english_imf_fixdate(const char *restrict buf)
{
	const char *const p = strstr(buf, "\r\nDate: ");
	if (p == NULL) {
		return false;
	}
	char wday[8] = { 0 };
	char mon[8] = { 0 };
	/* %*d suppresses assignment for the numeric fields: their values
	 * aren't needed, only that they are present and well-formed, and
	 * %d's own error reporting is otherwise unchecked (cert-err34-c). */
	if (sscanf(p,
		   "\r\nDate: %7[A-Za-z], %*d %7[A-Za-z] %*d %*d:%*d:%*d GMT",
		   wday, mon) != 2) {
		return false;
	}
	static const char *const wday_name[7] = { "Sun", "Mon", "Tue", "Wed",
						  "Thu", "Fri", "Sat" };
	static const char *const mon_name[12] = { "Jan", "Feb", "Mar", "Apr",
						  "May", "Jun", "Jul", "Aug",
						  "Sep", "Oct", "Nov", "Dec" };
	bool wday_ok = false;
	for (size_t i = 0; i < 7; i++) {
		wday_ok = wday_ok || strcmp(wday, wday_name[i]) == 0;
	}
	bool mon_ok = false;
	for (size_t i = 0; i < 12; i++) {
		mon_ok = mon_ok || strcmp(mon, mon_name[i]) == 0;
	}
	return wday_ok && mon_ok;
}

/* Individual test fixtures — small inline request strings */

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

#define REQ_HEALTHY_MULTI_TOKEN_CLOSE                                          \
	"GET /healthy HTTP/1.1\r\n"                                            \
	"Host: test\r\n"                                                       \
	"Connection: keep-alive, close\r\n"                                    \
	"\r\n"

/* A 34-octet token list whose trailing "close" lands past the old 32-byte
 * value buffer; truncation to "...cl" dropped the token and held the socket. */
#define REQ_HEALTHY_LONG_CLOSE                                                 \
	"GET /healthy HTTP/1.1\r\n"                                            \
	"Host: test\r\n"                                                       \
	"Connection: TE, Upgrade, HTTP2-Settings, close\r\n"                   \
	"\r\n"

/* RFC 7230 3.2.2: a repeated list-valued Connection header is the combined
 * list; the pre-fix last-one-wins overwrite served "close" then "TE" as
 * keep-alive. */
#define REQ_HEALTHY_REPEATED_CLOSE                                             \
	"GET /healthy HTTP/1.1\r\n"                                            \
	"Host: test\r\n"                                                       \
	"Connection: close\r\n"                                                \
	"Connection: TE\r\n"                                                   \
	"\r\n"

#define REQ_HEALTHY_HTTP10                                                     \
	"GET /healthy HTTP/1.0\r\n"                                            \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_TRANSFER_ENCODING_CHUNKED                                          \
	"PUT /config HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"Transfer-Encoding: chunked\r\n"                                       \
	"\r\n"

#define REQ_DUPLICATE_CONTENT_LENGTH                                           \
	"PUT /config HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"Content-Length: 5\r\n"                                                \
	"Content-Length: 5\r\n"                                                \
	"\r\n"                                                                 \
	"12345"

/* strtoul() accepts a leading '+' that RFC 7230 3.3.2's Content-Length =
 * 1*DIGIT grammar disallows. */
#define REQ_CONTENT_LENGTH_PLUS_SIGN                                           \
	"PUT /config HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"Content-Length: +29\r\n"                                              \
	"\r\n"                                                                 \
	"{\"mux_connect\":\"127.0.0.1:1\"}"

/* Network-path-reference request-target: url_parse() treats "config" as a
 * host with no further path segment, so .path is legitimately NULL. */
#define REQ_MALFORMED_URL_DOUBLE_SLASH                                         \
	"GET //config HTTP/1.1\r\n"                                            \
	"Host: test\r\n"                                                       \
	"\r\n"

/* No leading slash: url_parse() reports this via .defacto, leaving .path
 * NULL (zero-initialized). */
#define REQ_MALFORMED_URL_NO_SLASH                                             \
	"GET x HTTP/1.1\r\n"                                                   \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_CONFIG_GET                                                         \
	"GET /config HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"\r\n"

#define REQ_CONFIG_PUT_MALFORMED                                               \
	"PUT /config HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"Content-Length: 9\r\n"                                                \
	"\r\n"                                                                 \
	"{bad json"

/* A query component whose percent-encoding is invalid: url_query_component()'s
 * unescape() rejects "%ZZ", exercising handle_stats()'s malformed-query 400. */
#define REQ_STATS_MALFORMED_QUERY                                              \
	"GET /stats?%ZZ HTTP/1.1\r\n"                                          \
	"Host: test\r\n"                                                       \
	"\r\n"

/* PUT /config with neither Content-Length nor Transfer-Encoding reaches
 * handle_config_put()'s 411 Length Required branch. */
#define REQ_CONFIG_PUT_NO_LENGTH                                               \
	"PUT /config HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"\r\n"

/* PUT /config with an explicit empty body reaches the empty-body 400 branch. */
#define REQ_CONFIG_PUT_EMPTY_BODY                                              \
	"PUT /config HTTP/1.1\r\n"                                             \
	"Host: test\r\n"                                                       \
	"Content-Length: 0\r\n"                                                \
	"\r\n"

/* Helper — perform a single HTTP exchange on fx and fill rctx.
 * Returns 0 on success, -1 on timeout or error. */

static int do_exchange(
	struct apifx *restrict fx, struct resp_wait_ctx *restrict rctx,
	const char *restrict request)
{
	*rctx = (struct resp_wait_ctx){ .fd = fx->cli_fd, .nread = 0 };
	if (do_send(fx, fx->cli_fd, request, strlen(request)) != 0) {
		return -1;
	}
	return wait_until(
		fx, (double)API_RESP_TIMEOUT_MS / 1000.0, resp_wait_predicate,
		rctx);
}

/* Single HTTP exchange; T_FAILNOW on error. rctx->buf valid on return. */
T_DECLARE_SUBCASE(
	assert_exchange, struct apifx *restrict fx,
	struct resp_wait_ctx *restrict rctx, const char *restrict request)
{
	if (do_exchange(fx, rctx, request) != 0) {
		T_LOG("response timeout or send error");
		T_FAILNOW();
	}
}

/* Test cases */

T_DECLARE_CASE(test_healthy_get)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	/* This test binary never calls init(), so LC_TIME is still "C" here
	 * -- switch to a genuinely non-English locale (best effort; a no-op
	 * if unavailable, matching how init()'s own setlocale(LC_ALL, "")
	 * silently keeps "C" when the environment's requested locale isn't
	 * installed) so the Date header's day/month names are checked
	 * against an LC_TIME that would actually produce different output
	 * through strftime, not one indistinguishable from "C" on a minimal
	 * system. */
	const char *const prev_locale = setlocale(LC_TIME, NULL);
	char saved_locale[64] = { 0 };
	if (prev_locale != NULL) {
		(void)snprintf(
			saved_locale, sizeof(saved_locale), "%s", prev_locale);
	}
	(void)setlocale(LC_TIME, "zh_CN.utf8");

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_GET);
	/* Restore the locale and tear down before asserting so a failing T_EXPECT
	 * can't skip either (rctx.buf is a stack buffer, safe to read afterward). */
	(void)setlocale(LC_TIME, saved_locale[0] != '\0' ? saved_locale : "C");
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Content-Length: 0"));
	T_EXPECT(resp_date_is_english_imf_fixdate(rctx.buf));
}

T_DECLARE_CASE(test_stats_get_text)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
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
}

T_DECLARE_CASE(test_stats_buffered_data_uses_configured_frame_size)
{
	/* "Buffered Data" Tx must scale with the configured wire frame size
	 * (header + configured payload cap), not a hardcoded constant. */
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}
	fx.conf.mux.max_frame_payload = 65536 - MUX_FRAME_HEADER_SIZE;
	STORE_STAT(fx.srv.counters.send_buffered_frames, 10);
	STORE_STAT(fx.srv.counters.unacked_frames, 0);

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer and the expected/stale figures below derive only from
	 * constants, so all are safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);

	char expect_tx[16];
	(void)format_iec_bytes(
		expect_tx, sizeof(expect_tx), (double)(10 * 65536));
	T_EXPECT(resp_contains(rctx.buf, expect_tx));

	/* The pre-fix hardcoded 16384 must not appear as the Tx figure. */
	char stale_tx[16];
	(void)format_iec_bytes(
		stale_tx, sizeof(stale_tx), (double)(10 * 16384));
	if (strcmp(expect_tx, stale_tx) != 0) {
		T_EXPECT(!resp_contains(rctx.buf, stale_tx));
	}
}

T_DECLARE_CASE(test_stats_get_nobanner)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET_NOBANNER);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "text/plain"));
	T_EXPECT(resp_contains(rctx.buf, "Server Time"));
	T_EXPECT(!resp_contains(rctx.buf, "multiplexd "));
}

T_DECLARE_CASE(test_stats_post_text)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_POST);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "text/plain"));
	T_EXPECT(resp_contains(rctx.buf, "Reconnects"));
	T_EXPECT(resp_contains(rctx.buf, "Server Load"));
}

T_DECLARE_CASE(test_metrics_get)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "text/plain; version=0.0.4"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_sessions "));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_stream_open_total"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_stream_fastopen_total"));
	T_EXPECT(resp_contains(
		rctx.buf, "multiplexd_stream_establish_latency_seconds_count"));
}

T_DECLARE_CASE(test_not_found)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_NOTFOUND_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 404);
}

T_DECLARE_CASE(test_method_not_allowed)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_DELETE);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 405);
}

/* Headers exceed HTTP_MAX_ENTITY with no terminator; server rejects with
 * 413 and closes. The close may surface as a reset (see
 * oversized_wait_predicate). */
T_DECLARE_CASE(test_request_too_large)
{
	struct apifx fx;
	char *big_req = NULL;

	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	static const char pfx[] = "GET / HTTP/1.1\r\nX-Pad: ";
	const size_t pfx_len = sizeof(pfx) - 1u;
	/* pad_len exceeds HTTP_MAX_ENTITY and this system's default AF_UNIX
	 * send-buffer capacity, so do_send() blocks on EAGAIN and exercises
	 * wait_fd_events instead of a single uninterrupted write. */
	const size_t pad_len = 262144;
	const size_t total = pfx_len + pad_len;

	big_req = malloc(total);
	if (big_req == NULL) {
		T_LOG("malloc failed");
		T_FAIL();
		goto cleanup;
	}
	memcpy(big_req, pfx, pfx_len);
	memset(big_req + pfx_len, 'a', pad_len);

	/* A payload large enough to force EAGAIN may itself be cut short by
	 * the server aborting once it detects the oversized entity; a
	 * mid-send reset is valid, not just a mid-read one (see below). */
	const int send_err = do_send(&fx, fx.cli_fd, big_req, total);
	if (send_err != 0 && send_err != EPIPE && send_err != ECONNRESET) {
		T_LOG("do_send failed");
		T_FAIL();
		goto cleanup;
	}

	struct resp_wait_ctx rctx = { .fd = fx.cli_fd };
	if (wait_until(
		    &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
		    oversized_wait_predicate, &rctx) != 0) {
		T_LOG("response timeout");
		T_FAIL();
		goto cleanup;
	}
	/* Accept either a 413 or a connection reset before the response could be
	 * read; aborting the oversized request is valid server behaviour. */
	const int status = parse_status(rctx.buf);
	/* Tear down before asserting so a failing T_EXPECT can't skip cleanup
	 * (status is captured above; rctx.buf is a stack buffer, safe afterward). */
	free(big_req);
	apifx_teardown(&fx);
	if (status > 0) {
		T_EXPECT_EQ(status, 413);
	}
	return;

cleanup:
	free(big_req);
	apifx_teardown(&fx);
}

/* Two GET /healthy on the same HTTP/1.1 connection (keep-alive reuse);
 * both must return 200. */
T_DECLARE_CASE(test_keepalive)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx1;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx1, REQ_HEALTHY_GET);

	/* Second request on the same connection */
	struct resp_wait_ctx rctx2;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx2, REQ_HEALTHY_GET);
	/* Teardown after the last exchange but before asserting so a failing
	 * T_EXPECT can't skip it (both rctx buffers are stack buffers, safe to
	 * read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx1.buf), 200);
	T_EXPECT(resp_contains(rctx1.buf, "keep-alive"));
	T_EXPECT_EQ(parse_status(rctx2.buf), 200);
}

/* "Connection: close": server must close after sending the response. */
T_DECLARE_CASE(test_connection_close)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_CLOSE);

	/* After the response the server must have closed srv_fd; expect EOF. */
	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	const bool got_eof = wait_until(
				     &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
				     eof_wait_predicate, &ectx) == 0;

	/* Teardown after the last fx use (the EOF wait) but before asserting so a
	 * failing T_EXPECT can't skip it; rctx.buf is a stack buffer and the EOF
	 * result is captured above, both safe to read afterward. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Connection: close"));
	if (!got_eof) {
		T_LOG("expected EOF after Connection: close not received");
		T_FAIL();
	}
}

/* RFC 7230 6.1: "close" as one token in a Connection list ("keep-alive, close")
 * must still close the connection; the pre-fix exact-string match treated the
 * whole value as keep-alive. */
T_DECLARE_CASE(test_connection_close_multi_token)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(
		assert_exchange, &fx, &rctx, REQ_HEALTHY_MULTI_TOKEN_CLOSE);

	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	const bool got_eof = wait_until(
				     &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
				     eof_wait_predicate, &ectx) == 0;

	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Connection: close"));
	if (!got_eof) {
		T_LOG("expected EOF after multi-token Connection: close");
		T_FAIL();
	}
}

/* A "close" token past the old 32-byte value buffer must still close: the
 * value is parsed at receipt now, not truncated into a fixed copy. */
T_DECLARE_CASE(test_connection_close_long_token_list)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_LONG_CLOSE);

	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	const bool got_eof = wait_until(
				     &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
				     eof_wait_predicate, &ectx) == 0;

	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Connection: close"));
	if (!got_eof) {
		T_LOG("expected EOF after long-list Connection: close");
		T_FAIL();
	}
}

/* A repeated Connection header combines (RFC 7230 3.2.2): "close" then "TE"
 * must close, not be overwritten to keep-alive by the last line. */
T_DECLARE_CASE(test_connection_close_repeated_header)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_REPEATED_CLOSE);

	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	const bool got_eof = wait_until(
				     &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
				     eof_wait_predicate, &ectx) == 0;

	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Connection: close"));
	if (!got_eof) {
		T_LOG("expected EOF after repeated Connection: close");
		T_FAIL();
	}
}

T_DECLARE_CASE(test_stats_get_includes_identity_rows)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl0 = calloc(1, sizeof(*sl0));
	T_CHECK(sl0 != NULL);
	sl0->peer_identity = "peer-offline";
	struct tunnel *const t0 =
		make_established_tunnel(&fx, "peer-offline", 0);
	T_CHECK(t0 != NULL);
	/* Reset to non-established so tunnel_stats() reports !established. */
	tunnel_session(t0)->state = SESSION_CONNECT;
	sl0->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl0->tunnels != NULL);
	sl0->tunnels[0] = t0;
	sl0->num_tunnels = 1;
	{
		void *slot = sl0;
		fx.srv.identities =
			table_set(fx.srv.identities, sl0->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}
	struct identity_listener *const sl1 = calloc(1, sizeof(*sl1));
	T_CHECK(sl1 != NULL);
	sl1->peer_identity = "peer-online";
	struct tunnel *const restrict t1 =
		make_established_tunnel(&fx, "peer-online", 3);
	T_CHECK(t1 != NULL);
	sl1->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl1->tunnels != NULL);
	sl1->tunnels[0] = t1;
	sl1->num_tunnels = 1;
	{
		void *slot = sl1;
		fx.srv.identities =
			table_set(fx.srv.identities, sl1->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET);
	/* Tear the fixture down before asserting: a failing T_EXPECT longjmps out
	 * of the case, so running teardown first keeps the identity pool, tunnels,
	 * and fds from leaking on an assertion failure. rctx.buf is a stack buffer,
	 * unaffected by teardown. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "> Sessions"));
	T_EXPECT(resp_contains(rctx.buf, "peer-offline"));
	T_EXPECT(resp_contains(rctx.buf, "offline"));
	T_EXPECT(resp_contains(rctx.buf, "peer-online"));
	T_EXPECT(resp_contains(rctx.buf, "W=Rx"));
}

T_DECLARE_CASE(test_healthy_offline)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);

	/* An identity listener whose only tunnel is not established (peer
	 * unreachable).  tunnel_state() reads the relaxed-atomic _pub_state
	 * mirror, so the published state must be reset, not just ss->state. */
	struct identity_listener *const sl_down = calloc(1, sizeof(*sl_down));
	T_CHECK(sl_down != NULL);
	sl_down->peer_identity = "peer-down";
	struct tunnel *const t_down =
		make_established_tunnel(&fx, "peer-down", 0);
	T_CHECK(t_down != NULL);
	struct mux_session *const ss_down = tunnel_session(t_down);
	ss_down->state = SESSION_CONNECT;
	PUB_STORE(ss_down->_pub_state, SESSION_CONNECT);
	sl_down->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl_down->tunnels != NULL);
	sl_down->tunnels[0] = t_down;
	sl_down->num_tunnels = 1;
	{
		void *slot = sl_down;
		fx.srv.identities = table_set(
			fx.srv.identities, sl_down->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	/* A second identity listener that is established stays healthy and must
	 * not be reported. */
	struct identity_listener *const sl_up = calloc(1, sizeof(*sl_up));
	T_CHECK(sl_up != NULL);
	sl_up->peer_identity = "peer-up";
	struct tunnel *const t_up = make_established_tunnel(&fx, "peer-up", 1);
	T_CHECK(t_up != NULL);
	sl_up->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl_up->tunnels != NULL);
	sl_up->tunnels[0] = t_up;
	sl_up->num_tunnels = 1;
	{
		void *slot = sl_up;
		fx.srv.identities = table_set(
			fx.srv.identities, sl_up->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 503);
	T_EXPECT(resp_contains(rctx.buf, "offline: peer-down"));
	T_EXPECT(!resp_contains(rctx.buf, "offline: peer-up"));
}

/* A peer identity carrying C0 control bytes must be escaped in the plaintext
 * /healthy status line, not emitted raw: TAB/CR keep their C-style \t/\r, and
 * any other control byte -- e.g. ESC, the primary ANSI cursor-motion trigger --
 * becomes an inert \xNN so a crafted identity cannot drive the operator's
 * terminal. */
T_DECLARE_CASE(test_healthy_escapes_control_chars_in_identity)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);

	/* TAB (\t), ESC (\x1b), and CR (\r) in an offline listener's identity. */
	static const char evil_id[] = "a\tb\033c\rd";
	struct identity_listener *const sl = calloc(1, sizeof(*sl));
	T_CHECK(sl != NULL);
	sl->peer_identity = evil_id;
	struct tunnel *const t = make_established_tunnel(&fx, evil_id, 0);
	T_CHECK(t != NULL);
	struct mux_session *const ss = tunnel_session(t);
	ss->state = SESSION_CONNECT;
	PUB_STORE(ss->_pub_state, SESSION_CONNECT);
	sl->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl->tunnels != NULL);
	sl->tunnels[0] = t;
	sl->num_tunnels = 1;
	{
		void *slot = sl;
		fx.srv.identities =
			table_set(fx.srv.identities, sl->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 503);
	/* TAB/CR keep their C-style escapes; ESC becomes an inert \x1b. */
	T_EXPECT(resp_contains(rctx.buf, "offline: a\\tb\\x1bc\\rd"));
	/* No raw ESC byte reaches the terminal. */
	T_EXPECT(!resp_contains(rctx.buf, "\033"));
}

T_DECLARE_CASE(test_healthy_all_online)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl = calloc(1, sizeof(*sl));
	T_CHECK(sl != NULL);
	sl->peer_identity = "peer-up";
	struct tunnel *const t = make_established_tunnel(&fx, "peer-up", 1);
	T_CHECK(t != NULL);
	sl->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl->tunnels != NULL);
	sl->tunnels[0] = t;
	sl->num_tunnels = 1;
	{
		void *slot = sl;
		fx.srv.identities =
			table_set(fx.srv.identities, sl->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Content-Length: 0"));
}

T_DECLARE_CASE(test_stats_identity_shows_window_when_rtt_known)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl_rtt = calloc(1, sizeof(*sl_rtt));
	T_CHECK(sl_rtt != NULL);
	sl_rtt->peer_identity = "peer-rtt";
	struct tunnel *const restrict t1 =
		make_established_tunnel(&fx, "peer-rtt", 1);
	T_CHECK(t1 != NULL);
	struct mux_session *const ss = tunnel_session(t1);
	/* 20 ms RTT */
	ss->estimator.rtt = INT64_C(20000000);
	session_publish_estimate(ss);
	sl_rtt->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl_rtt->tunnels != NULL);
	sl_rtt->tunnels[0] = t1;
	sl_rtt->num_tunnels = 1;
	{
		void *slot = sl_rtt;
		fx.srv.identities = table_set(
			fx.srv.identities, sl_rtt->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "peer-rtt"));
	T_EXPECT(resp_contains(rctx.buf, "W=Rx"));
	T_EXPECT(resp_contains(rctx.buf, "RTT"));
	T_EXPECT(!resp_contains(rctx.buf, "BW=Rx"));
}

/* server_stats must count a tunnel that is both s->mux_tunnel and an identity-
 * pool member exactly once: server_on_established pools every dialed tunnel
 * whose peer identity matches an identity.listen key, mux_tunnel included, so
 * without dedup it appears twice in tunnels[] and its streams/traffic/latency
 * are aggregated twice into /stats and /metrics. */
T_DECLARE_CASE(test_server_stats_dedups_mux_tunnel_in_identity_pool)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}
	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct tunnel *const t = make_established_tunnel(&fx, "peer-dup", 3);
	T_CHECK(t != NULL);
	/* Same tunnel is both the top-level mux_tunnel and an identity-pool
	 * member (teardown frees it once, via the pool). */
	fx.srv.mux_tunnel = t;
	struct identity_listener *const sl = calloc(1, sizeof(*sl));
	T_CHECK(sl != NULL);
	sl->peer_identity = "peer-dup";
	sl->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl->tunnels != NULL);
	sl->tunnels[0] = t;
	sl->num_tunnels = 1;
	{
		void *slot = sl;
		fx.srv.identities =
			table_set(fx.srv.identities, sl->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct server_stats *const snap = server_stats(&fx.srv);
	const size_t num_tunnels = snap != NULL ? snap->num_tunnels : 0;
	free(snap);
	fx.srv.mux_tunnel = NULL; /* freed via the pool by teardown */
	apifx_teardown(&fx);
	T_EXPECT_EQ(num_tunnels, (size_t)1);
}

/* /metrics float samples must use a '.' decimal separator regardless of
 * LC_NUMERIC: the daemon's init() runs setlocale(LC_ALL, ""), and under a
 * comma-decimal operator locale a stdio %g would emit "0,02", which Prometheus
 * rejects, failing the whole scrape.  Best-effort like test_healthy_get: a
 * comma-decimal locale must be installed to actually exercise the hazard, but
 * the '.' assertion holds either way.  rtt = 20 ms -> session_rtt_seconds 0.02. */
T_DECLARE_CASE(test_metrics_floats_use_c_numeric_locale)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl_rtt = calloc(1, sizeof(*sl_rtt));
	T_CHECK(sl_rtt != NULL);
	sl_rtt->peer_identity = "peer-loc";
	struct tunnel *const restrict t1 =
		make_established_tunnel(&fx, "peer-loc", 1);
	T_CHECK(t1 != NULL);
	struct mux_session *const ss = tunnel_session(t1);
	ss->estimator.rtt = INT64_C(20000000); /* 20 ms */
	session_publish_estimate(ss);
	sl_rtt->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl_rtt->tunnels != NULL);
	sl_rtt->tunnels[0] = t1;
	sl_rtt->num_tunnels = 1;
	{
		void *slot = sl_rtt;
		fx.srv.identities = table_set(
			fx.srv.identities, sl_rtt->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	/* Best-effort switch to a comma-decimal locale; a no-op if none is
	 * installed (matching init()'s own silent fallback to "C"). */
	const char *const prev_locale = setlocale(LC_NUMERIC, NULL);
	char saved_locale[64] = { 0 };
	if (prev_locale != NULL) {
		(void)snprintf(
			saved_locale, sizeof(saved_locale), "%s", prev_locale);
	}
	static const char *const comma_locales[] = {
		"de_DE.utf8", "de_DE.UTF-8", "fr_FR.utf8", "nl_NL.utf8", NULL
	};
	for (const char *const *loc = comma_locales; *loc != NULL; loc++) {
		if (setlocale(LC_NUMERIC, *loc) != NULL) {
			break;
		}
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	(void)setlocale(
		LC_NUMERIC, saved_locale[0] != '\0' ? saved_locale : "C");
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_rtt_seconds{identity=\"peer-loc\",tunnel=\"1\"} 0.02"));
}

T_DECLARE_CASE(test_metrics_reports_identity_window_bytes)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl_win = calloc(1, sizeof(*sl_win));
	T_CHECK(sl_win != NULL);
	sl_win->peer_identity = "peer-win";
	struct tunnel *const restrict t1 =
		make_established_tunnel(&fx, "peer-win", 1);
	T_CHECK(t1 != NULL);
	struct mux_session *const ss = tunnel_session(t1);
	session_set_stream_window(ss, 2);
	session_set_peer_stream_window(ss, 4);
	sl_win->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl_win->tunnels != NULL);
	sl_win->tunnels[0] = t1;
	sl_win->num_tunnels = 1;
	{
		void *slot = sl_win;
		fx.srv.identities = table_set(
			fx.srv.identities, sl_win->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	/* rx_window = 2 * 16384 = 32768, tx_window = 4 * 16384 = 65536.
	 * tunnel label is the server-wide monotonic index assigned at
	 * tunnel_new(); 1 for the first tunnel created in a fresh fixture. */
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_window_bytes{identity=\"peer-win\",tunnel=\"1\",direction=\"rx\"} 32768"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_window_bytes{identity=\"peer-win\",tunnel=\"1\",direction=\"tx\"} 65536"));
	/* The window rises and falls, so the series is a gauge, not a counter --
	 * a counter-typed gauge breaks rate()/increase() and reset detection. */
	T_EXPECT(resp_contains(
		rctx.buf, "# TYPE multiplexd_session_window_bytes gauge"));
}

/* Each tunnel series must expose samples under the exact name its # TYPE line
 * declares. Guards against a metric name diverging between the header and the
 * sample lines (a compile-clean break that would leave # TYPE naming a series
 * with no samples and the samples carrying an untyped name). */
T_DECLARE_CASE(test_metrics_session_counter_type_matches_samples)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl = calloc(1, sizeof(*sl));
	T_CHECK(sl != NULL);
	sl->peer_identity = "peer-cnt";
	struct tunnel *const restrict t1 =
		make_established_tunnel(&fx, "peer-cnt", 1);
	T_CHECK(t1 != NULL);
	sl->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl->tunnels != NULL);
	sl->tunnels[0] = t1;
	sl->num_tunnels = 1;
	{
		void *slot = sl;
		fx.srv.identities =
			table_set(fx.srv.identities, sl->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	/* Both counter series (keep_cond is unconditionally true) must emit a
	 * sample under the same name their # TYPE line declares. */
	T_EXPECT(resp_contains(
		rctx.buf, "# TYPE multiplexd_session_bytes_total counter"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_bytes_total{identity=\"peer-cnt\",tunnel=\"1\",direction=\"rx\"} "));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_bytes_total{identity=\"peer-cnt\",tunnel=\"1\",direction=\"tx\"} "));
	T_EXPECT(resp_contains(
		rctx.buf,
		"# TYPE multiplexd_session_payload_bytes_total counter"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_payload_bytes_total{identity=\"peer-cnt\",tunnel=\"1\",direction=\"rx\"} "));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_payload_bytes_total{identity=\"peer-cnt\",tunnel=\"1\",direction=\"tx\"} "));
}

/* A peer identity containing structural characters must be escaped in the
 * Prometheus label value; an unescaped one could corrupt the /metrics
 * exposition or inject spoofed lines. The Prometheus 0.0.4 text format defines
 * escapes for only \\, \", and \n -- \t and \r are NOT valid escapes and would
 * make the whole scrape unparseable, so they must be emitted as literal bytes,
 * not backslash-escaped. */
T_DECLARE_CASE(test_metrics_escapes_special_chars_in_identity)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	/* Exercises every escape class: quote, newline, backslash (all
	 * Prometheus-legal) plus TAB and CR (must stay literal in a label). */
	static const char evil_id[] = "a\"b\nc\\d\te\rf";
	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl = calloc(1, sizeof(*sl));
	T_CHECK(sl != NULL);
	sl->peer_identity = evil_id;
	struct tunnel *const t = make_established_tunnel(&fx, evil_id, 1);
	T_CHECK(t != NULL);
	sl->tunnels = (struct tunnel **)malloc(sizeof(struct tunnel *));
	T_CHECK(sl->tunnels != NULL);
	sl->tunnels[0] = t;
	sl->num_tunnels = 1;
	{
		void *slot = sl;
		fx.srv.identities =
			table_set(fx.srv.identities, sl->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	/* Quote/newline/backslash escaped; TAB and CR left as literal bytes. */
	T_EXPECT(resp_contains(rctx.buf, "identity=\"a\\\"b\\nc\\\\d\te\rf\""));
	/* The raw (injection-capable) quote form absent. */
	T_EXPECT(!resp_contains(rctx.buf, "identity=\"a\"b"));
	/* No invalid Prometheus escape sequence for TAB or CR anywhere. */
	T_EXPECT(!resp_contains(rctx.buf, "\\t"));
	T_EXPECT(!resp_contains(rctx.buf, "\\r"));
}

T_DECLARE_CASE(test_metrics_unique_tunnel_label_for_repeated_peer_identity)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	/* Two tunnels sharing the same peer identity "peer-dup" — the
	 * situation that previously caused duplicate Prometheus label sets. */
	fx.srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(fx.srv.identities != NULL);
	struct identity_listener *const sl = calloc(1, sizeof(*sl));
	T_CHECK(sl != NULL);
	sl->peer_identity = "peer-dup";
	struct tunnel *const t1 = make_established_tunnel(&fx, "peer-dup", 0);
	T_CHECK(t1 != NULL);
	struct tunnel *const t2 = make_established_tunnel(&fx, "peer-dup", 0);
	T_CHECK(t2 != NULL);
	sl->tunnels = (struct tunnel **)malloc(2 * sizeof(struct tunnel *));
	T_CHECK(sl->tunnels != NULL);
	sl->tunnels[0] = t1;
	sl->tunnels[1] = t2;
	sl->num_tunnels = 2;
	{
		void *slot = sl;
		fx.srv.identities =
			table_set(fx.srv.identities, sl->peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	/* The two tunnel_indexes are 1 and 2 (first two tunnels in a fresh
	 * fixture).  Each label set must appear exactly once. */
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_bytes_total{identity=\"peer-dup\",tunnel=\"1\",direction=\"rx\"}"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_bytes_total{identity=\"peer-dup\",tunnel=\"2\",direction=\"rx\"}"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_bytes_total{identity=\"peer-dup\",tunnel=\"1\",direction=\"tx\"}"));
	T_EXPECT(resp_contains(
		rctx.buf,
		"multiplexd_session_bytes_total{identity=\"peer-dup\",tunnel=\"2\",direction=\"tx\"}"));
}

T_DECLARE_CASE(test_stats_post_tracks_rate_deltas)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	fx.srv.started = clock_monotonic_ns() - 5LL * 1000 * 1000 * 1000;
	fx.srv.counters.traffic_byt_mux_recv = 2048;
	fx.srv.counters.traffic_byt_mux_sent = 4096;

	struct resp_wait_ctx rctx1;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx1, REQ_STATS_POST);
	/* Capture the post-first-POST rate-tracker state before the counter
	 * mutation and second POST below overwrite it, so these values can be
	 * asserted after teardown rather than read from the freed fixture. */
	const bool rt1_is_set = fx.srv.rate_tracker.is_set;
	const uint_least64_t rt1_recv = fx.srv.rate_tracker.byt_mux_recv;
	const uint_least64_t rt1_sent = fx.srv.rate_tracker.byt_mux_sent;

	fx.srv.counters.traffic_byt_mux_recv = 3072;
	fx.srv.counters.traffic_byt_mux_sent = 6144;
	fx.srv.rate_tracker.timestamp =
		clock_monotonic_ns() - 2LL * 1000 * 1000 * 1000;

	struct resp_wait_ctx rctx2;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx2, REQ_STATS_POST);
	/* Capture the post-second-POST rate-tracker state before teardown. */
	const uint_least64_t rt2_recv = fx.srv.rate_tracker.byt_mux_recv;
	const uint_least64_t rt2_sent = fx.srv.rate_tracker.byt_mux_sent;

	/* Teardown before asserting so a failing T_EXPECT can't skip it; the rctx
	 * buffers are stack buffers and every fx field read is captured above. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx1.buf), 200);
	T_EXPECT(resp_contains(rctx1.buf, "Mux Throughput"));
	T_EXPECT(resp_contains(rctx1.buf, "Server Load"));
	T_EXPECT(rt1_is_set);
	T_EXPECT_EQ(rt1_recv, (uint_least64_t)2048);
	T_EXPECT_EQ(rt1_sent, (uint_least64_t)4096);
	T_EXPECT_EQ(parse_status(rctx2.buf), 200);
	T_EXPECT(resp_contains(rctx2.buf, "Mux Throughput"));
	T_EXPECT(resp_contains(rctx2.buf, "Server Load"));
	T_EXPECT_EQ(rt2_recv, (uint_least64_t)3072);
	T_EXPECT_EQ(rt2_sent, (uint_least64_t)6144);
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
	fx.srv.counters.traffic_byt_mux_recv = 1234;
	fx.srv.counters.traffic_byt_mux_sent = 2345;

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_METRICS_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_reconnects_total 7"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_rst_sent_total 11"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_rst_recv_total 17"));
	T_EXPECT(resp_contains(rctx.buf, "multiplexd_stream_errors_total 19"));
}

T_DECLARE_CASE(test_not_found_keepalive_followed_by_success)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx1;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx1, REQ_NOTFOUND_GET);

	struct resp_wait_ctx rctx2;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx2, REQ_HEALTHY_GET);
	/* Teardown after the last exchange but before asserting so a failing
	 * T_EXPECT can't skip it (both rctx buffers are stack buffers, safe to
	 * read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx1.buf), 404);
	T_EXPECT(resp_contains(rctx1.buf, "Connection: keep-alive"));
	T_EXPECT_EQ(parse_status(rctx2.buf), 200);
	T_EXPECT(resp_contains(rctx2.buf, "Content-Length: 0"));
}

T_DECLARE_CASE(test_connection_close_on_non_keepalive_request)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_HEALTHY_HTTP10);

	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	const bool got_eof = wait_until(
				     &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
				     eof_wait_predicate, &ectx) == 0;

	/* Teardown after the last fx use (the EOF wait) but before asserting so a
	 * failing T_EXPECT can't skip it; rctx.buf is a stack buffer and the EOF
	 * result is captured above, both safe to read afterward. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "Connection: close"));
	if (!got_eof) {
		T_LOG("expected EOF after HTTP/1.0 request not received");
		T_FAIL();
	}
}

/* A Transfer-Encoding this server cannot decode must be rejected (501) and
 * the connection closed, not misparsed as a zero-length-body request
 * followed by the chunked body as the start of the next request. */
T_DECLARE_CASE(test_transfer_encoding_rejected)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(
		assert_exchange, &fx, &rctx, REQ_TRANSFER_ENCODING_CHUNKED);

	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	const bool got_eof = wait_until(
				     &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
				     eof_wait_predicate, &ectx) == 0;

	/* Teardown after the last fx use (the EOF wait) but before asserting so a
	 * failing T_EXPECT can't skip it; rctx.buf is a stack buffer and the EOF
	 * result is captured above, both safe to read afterward. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 501);
	if (!got_eof) {
		T_LOG("expected EOF after rejected Transfer-Encoding request");
		T_FAIL();
	}
}

/* A second Content-Length header is a framing ambiguity, not "last one
 * wins": must be rejected (400) and the connection closed. */
T_DECLARE_CASE(test_duplicate_content_length_rejected)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(
		assert_exchange, &fx, &rctx, REQ_DUPLICATE_CONTENT_LENGTH);

	struct eof_wait_ctx ectx = { .fd = fx.cli_fd };
	const bool got_eof = wait_until(
				     &fx, (double)API_RESP_TIMEOUT_MS / 1000.0,
				     eof_wait_predicate, &ectx) == 0;

	/* Teardown after the last fx use (the EOF wait) but before asserting so a
	 * failing T_EXPECT can't skip it; rctx.buf is a stack buffer and the EOF
	 * result is captured above, both safe to read afterward. */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 400);
	if (!got_eof) {
		T_LOG("expected EOF after rejected duplicate Content-Length");
		T_FAIL();
	}
}

/* A leading '+' is not part of RFC 7230's Content-Length = 1*DIGIT
 * grammar; strtoul() would otherwise accept it silently and proceed to a
 * real server_apply_config() reload (204), so this needs the same
 * properly constructed struct server as test_config_put_success rather
 * than the minimal apifx fixture. */
T_DECLARE_CASE(test_content_length_plus_sign_rejected)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct config *const conf = conf_new_default();
	T_CHECK(conf != NULL);

	struct server *const srv = server_new(loop, conf);
	T_CHECK(srv != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(socket_set_nonblock(fds[0]));
	T_CHECK(socket_set_nonblock(fds[1]));
	api_serve(&srv->api_listener, loop, fds[0], NULL);

	struct apifx fx = { .loop = loop, .cli_fd = fds[1] };

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(
		assert_exchange, &fx, &rctx, REQ_CONTENT_LENGTH_PLUS_SIGN);
	T_EXPECT_EQ(parse_status(rctx.buf), 400);

	(void)close(fds[1]);
	server_stop(srv);
	/* server_apply_config() would swap srv->conf and free the original;
	 * server_free() does not touch conf, so free whichever is current. */
	struct config *const final_conf = srv->conf;
	server_free(srv);
	conf_free(final_conf);
	ev_loop_destroy(loop);
}

/* url_parse() legitimately returns true with .path == NULL for a
 * network-path-reference request-target ("//...") or one with no leading
 * slash at all ("x"). api_handle() must reject these with 400 instead of
 * dereferencing the NULL path; the connection (and the server) must survive
 * to serve a subsequent request. */
T_DECLARE_CASE(test_malformed_url_path_rejected)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx1;
	T_CALL_SUBCASE(
		assert_exchange, &fx, &rctx1, REQ_MALFORMED_URL_DOUBLE_SLASH);

	struct resp_wait_ctx rctx2;
	T_CALL_SUBCASE(
		assert_exchange, &fx, &rctx2, REQ_MALFORMED_URL_NO_SLASH);

	/* Prove the server process and connection are both still healthy. */
	struct resp_wait_ctx rctx3;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx3, REQ_HEALTHY_GET);
	/* Teardown after the last exchange but before asserting so a failing
	 * T_EXPECT can't skip it (all rctx buffers are stack buffers, safe to
	 * read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx1.buf), 400);
	T_EXPECT(resp_contains(rctx1.buf, "Connection: keep-alive"));
	T_EXPECT_EQ(parse_status(rctx2.buf), 400);
	T_EXPECT_EQ(parse_status(rctx3.buf), 200);
}

T_DECLARE_CASE(test_config_get_returns_json)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_CONFIG_GET);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 200);
	T_EXPECT(resp_contains(rctx.buf, "application/json"));
	T_EXPECT(resp_contains(
		rctx.buf, "application/x-multiplexd-config; version=1"));
}

T_DECLARE_CASE(test_config_put_malformed_body)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_CONFIG_PUT_MALFORMED);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 400);
}

/* handle_stats() rejects a query component it cannot unescape with 400; the
 * suite otherwise only sends the well-formed /stats?nobanner=1. */
T_DECLARE_CASE(test_stats_malformed_query_rejected)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_STATS_MALFORMED_QUERY);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 400);
}

/* PUT /config with no Content-Length (and no Transfer-Encoding) reaches the 411
 * Length Required branch -- distinct from the chunked path, which 501s before
 * dispatch. */
T_DECLARE_CASE(test_config_put_no_content_length)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_CONFIG_PUT_NO_LENGTH);
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 411);
}

/* PUT /config with Content-Length: 0 reaches the empty-body 400 branch ("a
 * config body can never legitimately be empty"). */
T_DECLARE_CASE(test_config_put_empty_body_rejected)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, REQ_CONFIG_PUT_EMPTY_BODY);
	apifx_teardown(&fx);
	T_EXPECT_EQ(parse_status(rctx.buf), 400);
}

/* A body over the old 8192-byte HTTP_MAX_ENTITY cap must now reach config
 * validation (400: missing transport) instead of being rejected purely for
 * size (413), proving the PUT /config ceiling now tracks CONF_MAXSIZE. */
T_DECLARE_CASE(test_config_put_large_body_not_rejected_for_size)
{
	struct apifx fx;
	if (apifx_setup(&fx) != 0) {
		T_FATAL("apifx_setup failed");
	}

	enum { FILLER_LEN = 20000 };
	char filler[FILLER_LEN + 1];
	memset(filler, 'a', FILLER_LEN);
	filler[FILLER_LEN] = '\0';

	/* tls.ciphersuites has no maxLength and, with no tls.cert/tls.key set,
	 * is never handed to a TLS library — an inert way to inflate the body
	 * well past the old cap without touching any other subsystem. */
	char body[FILLER_LEN + 64];
	const int body_len = snprintf(
		body, sizeof(body), "{\"tls\":{\"ciphersuites\":\"%s\"}}",
		filler);
	T_CHECK(body_len > 8192 && (size_t)body_len < sizeof(body));

	char req[FILLER_LEN + 128];
	const int req_len = snprintf(
		req, sizeof(req),
		"PUT /config HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s",
		body_len, body);
	T_CHECK(req_len > 0 && (size_t)req_len < sizeof(req));

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, req);
	/* Teardown before asserting so a failing T_EXPECT can't skip it (rctx.buf
	 * is a stack buffer, safe to read afterward). */
	apifx_teardown(&fx);
	/* Not 413: a >8KiB body must not be rejected purely for size. 400
	 * because the config lacks a required transport. */
	T_EXPECT_EQ(parse_status(rctx.buf), 400);
}

/* Exercises the real server_apply_config() reload, so it needs a properly
 * constructed struct server rather than the minimal apifx fixture. */
T_DECLARE_CASE(test_config_put_success)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);

	struct config *const conf = conf_new_default();
	T_CHECK(conf != NULL);

	struct server *const srv = server_new(loop, conf);
	T_CHECK(srv != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(socket_set_nonblock(fds[0]));
	T_CHECK(socket_set_nonblock(fds[1]));
	api_serve(&srv->api_listener, loop, fds[0], NULL);

	/* do_exchange/wait_until only touch fx.loop and fx.cli_fd; the rest of
	 * struct apifx is unused since this test builds its own server. */
	struct apifx fx = { .loop = loop, .cli_fd = fds[1] };

	static const char body[] = "{\"mux_connect\":\"127.0.0.1:1\"}";
	char req[256];
	const int req_len = snprintf(
		req, sizeof(req),
		"PUT /config HTTP/1.1\r\n"
		"Host: test\r\n"
		"Connection: close\r\n"
		"Content-Length: %zu\r\n"
		"\r\n"
		"%s",
		sizeof(body) - 1, body);
	T_CHECK(req_len > 0 && (size_t)req_len < sizeof(req));

	struct resp_wait_ctx rctx;
	T_CALL_SUBCASE(assert_exchange, &fx, &rctx, req);
	T_EXPECT_EQ(parse_status(rctx.buf), 204);

	(void)close(fds[1]);
	server_stop(srv);
	/* server_apply_config() swapped srv->conf and freed the original;
	 * server_free() does not touch conf, so free whichever is current. */
	struct config *const final_conf = srv->conf;
	server_free(srv);
	conf_free(final_conf);
	ev_loop_destroy(loop);
}

/* main */

static const struct testing_suite suite[] = {
	T_CASE(test_healthy_get),
	T_CASE(test_stats_get_text),
	T_CASE(test_stats_buffered_data_uses_configured_frame_size),
	T_CASE(test_stats_get_nobanner),
	T_CASE(test_stats_post_text),
	T_CASE(test_metrics_get),
	T_CASE(test_not_found),
	T_CASE(test_method_not_allowed),
	T_CASE(test_request_too_large),
	T_CASE(test_keepalive),
	T_CASE(test_connection_close),
	T_CASE(test_connection_close_multi_token),
	T_CASE(test_connection_close_long_token_list),
	T_CASE(test_connection_close_repeated_header),
	T_CASE(test_stats_get_includes_identity_rows),
	T_CASE(test_healthy_offline),
	T_CASE(test_healthy_escapes_control_chars_in_identity),
	T_CASE(test_healthy_all_online),
	T_CASE(test_stats_identity_shows_window_when_rtt_known),
	T_CASE(test_server_stats_dedups_mux_tunnel_in_identity_pool),
	T_CASE(test_metrics_reports_identity_window_bytes),
	T_CASE(test_metrics_session_counter_type_matches_samples),
	T_CASE(test_metrics_floats_use_c_numeric_locale),
	T_CASE(test_metrics_escapes_special_chars_in_identity),
	T_CASE(test_metrics_unique_tunnel_label_for_repeated_peer_identity),
	T_CASE(test_stats_post_tracks_rate_deltas),
	T_CASE(test_metrics_reports_non_zero_mux_counters),
	T_CASE(test_not_found_keepalive_followed_by_success),
	T_CASE(test_connection_close_on_non_keepalive_request),
	T_CASE(test_transfer_encoding_rejected),
	T_CASE(test_duplicate_content_length_rejected),
	T_CASE(test_content_length_plus_sign_rejected),
	T_CASE(test_malformed_url_path_rejected),
	T_CASE(test_config_get_returns_json),
	T_CASE(test_config_put_malformed_body),
	T_CASE(test_stats_malformed_query_rejected),
	T_CASE(test_config_put_no_content_length),
	T_CASE(test_config_put_empty_body_rejected),
	T_CASE(test_config_put_large_body_not_rejected_for_size),
	T_CASE(test_config_put_success),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
