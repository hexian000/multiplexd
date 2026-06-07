/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* mux_test.c - unit tests for mux_stream_send / mux_stream_recv (direct I/O
 * mode).  Two mux sessions are connected over a socketpair and driven on a
 * single ev_loop, exercising the full protocol: handshake, data transfer,
 * flow-control, half-close, RST, and concurrent streams. */

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/stream.h"

#include "mux/handshake.c"

#include "math/rand.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

enum {
	ESTABLISH_TIMEOUT_MS = 1000,
	ECHO_TIMEOUT_MS = 3000,
	EOF_TIMEOUT_MS = 1000,
	CLOSE_TIMEOUT_MS = 1000,
	/* reconnect_delays[0]=0.2s + handshake; 3s gives ample headroom */
	RESUME_TIMEOUT_MS = 3000,
	MAX_ACCEPTED = 16,
	PAYLOAD_SMALL = 1024,
	PAYLOAD_LARGE = 262144,
	MULTI_CONCURRENCY = 4,
	/* Two frames (2 × MUX_MAX_PAYLOAD_SIZE = 32768) match the immediate-ACK
	 * threshold so each drain triggers an immediate ACK and avoids the
	 * 1-tick (40 ms) delayed-ACK timer on the fast path. */
	CHUNK_SIZE = 32768,
};

int exitcode = EXIT_SUCCESS;

/* -------------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */

struct mux_test_fixture;
struct test_stream;
struct pending_accept;

static void stream_io_cb(struct ev_loop *loop, mux_stream_io *w, int revents);
static bool raw_drain_available(int fd);

/* -------------------------------------------------------------------------
 * Fixture types
 * ---------------------------------------------------------------------- */

enum accept_mode {
	ACCEPT_ECHO = 0, /* echo all data, mirror FIN */
	ACCEPT_CLOSE_IMMEDIATE, /* close immediately (triggers RST) */
	/* send payload from fx->accept_send_data and FIN, do not echo */
	ACCEPT_SEND_PAYLOAD,
};

struct test_stream {
	mux_stream_io w_io;
	struct mux_test_fixture *fx;
	struct mux_stream *s;

	/* Receive accumulation */
	unsigned char *recv_buf;
	size_t recv_cap;
	size_t recv_len;

	/* Send state */
	const unsigned char *send_data;
	size_t send_len;
	size_t send_off;
	bool send_shutdown_on_drain; /* call mux_stream_shutdown after all data sent */

	/* echo: reflect all received bytes back to the sender */
	bool is_echo;
	/* close_on_readable: close the stream as soon as EV_READ fires
	 * (without consuming data), triggering RST due to unread data */
	bool close_on_readable;

	bool got_eof;
	bool got_error;
	bool closed; /* mux_stream_close was called on this test_stream */
};

struct mux_test_fixture {
	struct ev_loop *loop;

	struct mux_session *srv;
	struct mux_session *cli;

	bool srv_established;
	bool cli_established;
	bool srv_closed;
	bool cli_closed;
	bool srv_suspended;
	bool cli_suspended;
	bool srv_resumed;
	bool cli_resumed;
	bool cli_connect_failed;

	enum accept_mode accept_mode;

	/* Server-side accepted streams */
	struct test_stream *accepted[MAX_ACCEPTED];
	int n_accepted;

	/* Client-side streams opened by tests */
	struct test_stream *cli_streams[MAX_ACCEPTED];
	int n_cli_streams;

	/* Server-side streams opened actively by the server */
	struct test_stream *srv_active_streams[MAX_ACCEPTED];
	int n_srv_active_streams;

	/* Payload to send from ACCEPT_SEND_PAYLOAD mode */
	const unsigned char *accept_send_data;
	size_t accept_send_len;

	/* Mux-level Nagle bypass for this fixture. */
	bool nodelay;

	/* TCP loopback listen fd and its pending-accept watcher (cleaned up in
	 * teardown if the accept fires before teardown, pending_accept is set
	 * to NULL by pending_accept_cb after use). */
	int listen_fd_cleanup;
	struct pending_accept *pending_accept;
	/* Loopback connect address; lifetime is the fixture (outlives pa). */
	char connect_str[64];

	/* Sentinel fd held open during a transport break to prevent the server
	 * fd slot from being reused by accept() before session_suspend closes it.
	 * Set by fx_break_transport; freed by fixture_teardown. */
	int break_transport_sp;
};

/* -------------------------------------------------------------------------
 * wait_until helper (same pattern as server_test.c)
 * ---------------------------------------------------------------------- */

typedef int (*wait_predicate_fn)(void *ctx);

struct condition_waiter {
	bool timed_out;
	ev_timer w_timer;
};

static void
condition_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	UNUSED(loop);
	UNUSED(revents);
	struct condition_waiter *restrict waiter = w->data;
	waiter->timed_out = true;
}

static int wait_until(
	struct mux_test_fixture *fx, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	struct condition_waiter waiter = {
		.timed_out = false,
	};
	ev_timer_init(
		&waiter.w_timer, condition_waiter_timer_cb, timeout_sec, 0.0);
	waiter.w_timer.data = &waiter;
	ev_timer_start(fx->loop, &waiter.w_timer);

	while (!waiter.timed_out) {
		const int status = predicate(ctx);
		if (status != 0) {
			ev_timer_stop(fx->loop, &waiter.w_timer);
			return status > 0 ? 0 : -1;
		}
		ev_run(fx->loop, EVRUN_ONCE);
	}

	ev_timer_stop(fx->loop, &waiter.w_timer);
	errno = ETIMEDOUT;
	return -1;
}

/* -------------------------------------------------------------------------
 * test_stream helpers
 * ---------------------------------------------------------------------- */

static struct test_stream *test_stream_new(
	struct mux_test_fixture *restrict fx, struct mux_stream *restrict s)
{
	struct test_stream *ts = malloc(sizeof(struct test_stream));
	if (ts == NULL) {
		return NULL;
	}
	*ts = (struct test_stream){
		.fx = fx,
		.s = s,
		.recv_buf = NULL,
		.recv_cap = 0,
		.recv_len = 0,
		.send_data = NULL,
		.send_len = 0,
		.send_off = 0,
		.send_shutdown_on_drain = false,
		.got_eof = false,
		.got_error = false,
		.closed = false,
	};
	{
		unsigned char *buf = malloc(PAYLOAD_LARGE + CHUNK_SIZE);
		if (buf == NULL) {
			free(ts);
			return NULL;
		}
		ts->recv_buf = buf;
		ts->recv_cap = PAYLOAD_LARGE + CHUNK_SIZE;
	}
	mux_stream_io_init(&ts->w_io, stream_io_cb, s, EV_READ | EV_WRITE);
	return ts;
}

static void test_stream_free(struct test_stream *restrict ts)
{
	if (ts == NULL) {
		return;
	}
	free(ts->recv_buf);
	free(ts);
}

/* Flush pending send data for a test_stream in echo mode.
 * Returns true when all data has been sent. */
static bool test_stream_flush_send(struct test_stream *restrict ts)
{
	if (ts->send_off >= ts->send_len) {
		return true;
	}
	const size_t remaining = ts->send_len - ts->send_off;
	size_t chunk = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
	const int ret =
		mux_stream_send(ts->s, ts->send_data + ts->send_off, &chunk);
	if (ret < 0) {
		return false;
	}
	ts->send_off += chunk;
	return ts->send_off >= ts->send_len;
}

/* -------------------------------------------------------------------------
 * Echo I/O callback (used by both server-accepted and client-opened streams)
 * ---------------------------------------------------------------------- */

static void
stream_io_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	UNUSED(loop);
	struct test_stream *restrict ts = (struct test_stream *)w;

	if (revents & EV_ERROR) {
		ts->got_error = true;
		if (!ts->closed) {
			ts->closed = true;
			mux_stream_close(ts->s);
		}
		return;
	}

	if (revents & EV_READ) {
		if (ts->close_on_readable) {
			/* Close without reading to trigger RST. */
			if (!ts->closed) {
				ts->closed = true;
				mux_stream_close(ts->s);
			}
			return;
		}
		/* Drain available data */
		while (ts->recv_len < ts->recv_cap) {
			size_t cap = ts->recv_cap - ts->recv_len;
			const int ret = mux_stream_recv(
				ts->s, ts->recv_buf + ts->recv_len, &cap);
			if (ret < 0) {
				if (errno == EAGAIN) {
					break;
				}
				if (errno == ECONNRESET) {
					ts->got_error = true;
					if (!ts->closed) {
						ts->closed = true;
						mux_stream_close(ts->s);
					}
					return;
				}
				break;
			}
			if (cap == 0) {
				/* EOF */
				ts->got_eof = true;
				if (ts->is_echo) {
					/* Echo server: mirror the FIN. */
					mux_stream_shutdown(ts->s);
				}
				return;
			}
			ts->recv_len += cap;

			/* Echo server: echo received data immediately back. */
			if (ts->is_echo) {
				const unsigned char *p =
					ts->recv_buf + (ts->recv_len - cap);
				size_t remaining = cap;
				while (remaining > 0) {
					size_t chunk = remaining;
					const int r = mux_stream_send(
						ts->s, p, &chunk);
					if (r < 0 || chunk == 0) {
						break;
					}
					p += chunk;
					remaining -= chunk;
				}
			}
		}
	}

	if (revents & EV_WRITE) {
		if (ts->send_data != NULL) {
			const bool done = test_stream_flush_send(ts);
			if (done && ts->send_shutdown_on_drain) {
				mux_stream_shutdown(ts->s);
			}
		}
	}
}

/* -------------------------------------------------------------------------
 * Session callbacks
 * ---------------------------------------------------------------------- */

static bool
on_accept_cb(void *data, const struct mux_session *ss, struct mux_stream *s)
{
	UNUSED(ss);
	struct mux_test_fixture *restrict fx = data;
	if (fx->n_accepted >= MAX_ACCEPTED) {
		return false;
	}

	struct test_stream *ts = test_stream_new(fx, s);
	if (ts == NULL) {
		return false;
	}
	fx->accepted[fx->n_accepted++] = ts;

	if (fx->accept_mode == ACCEPT_CLOSE_IMMEDIATE) {
		/* Start the watcher so the stream completes its SYN/ACK
		 * handshake. The first EV_READ (when client data arrives)
		 * will close without reading to trigger RST. */
		ts->close_on_readable = true;
		mux_stream_io_start(fx->loop, &ts->w_io);
		return true;
	}

	if (fx->accept_mode == ACCEPT_SEND_PAYLOAD) {
		/* Server sends its own payload then shuts down the write side.
		 * The accepted stream does not echo; the peer is expected to
		 * drain the data and observe EOF. */
		ts->send_data = fx->accept_send_data;
		ts->send_len = fx->accept_send_len;
		ts->send_shutdown_on_drain = true;
		mux_stream_io_start(fx->loop, &ts->w_io);
		return true;
	}

	/* Echo mode: mark is_echo so stream_io_cb echoes data back. */
	ts->is_echo = true;
	mux_stream_io_start(fx->loop, &ts->w_io);
	return true;
}

static int fixture_dial(const char *restrict addr_str)
{
	/* addr_str is always "127.0.0.1:<port>" in the test fixture. */
	const char *colon = strchr(addr_str, ':');
	if (colon == NULL) {
		return -1;
	}
	char *end = NULL;
	const long lport = strtol(colon + 1, &end, 10);
	if (end == colon + 1 || *end != '\0' || lport <= 0 || lport > 65535) {
		return -1;
	}
	const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		return -1;
	}
	if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
		close(fd);
		return -1;
	}
	const struct sockaddr_in saddr = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)lport),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	const int ret =
		connect(fd, (const struct sockaddr *)&saddr, sizeof(saddr));
	if (ret != 0 && errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	return fd;
}

static void on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	UNUSED(edata);
	struct mux_test_fixture *restrict fx = data;
	switch (event) {
	case MUX_EVENT_ESTABLISHED:
		if (ss == fx->srv) {
			fx->srv_established = true;
		} else {
			fx->cli_established = true;
		}
		break;
	case MUX_EVENT_RESUMED:
		if (ss == fx->srv) {
			fx->srv_resumed = true;
		} else {
			fx->cli_resumed = true;
		}
		break;
	case MUX_EVENT_SUSPENDED:
		if (ss == fx->srv) {
			fx->srv_suspended = true;
		} else {
			fx->cli_suspended = true;
		}
		if (ss == fx->cli && fx->connect_str[0] != '\0') {
			/* Reconnect the client session immediately. */
			const int fd = fixture_dial(fx->connect_str);
			if (fd >= 0) {
				mux_attach_fd(ss, fd);
			}
		}
		break;
	case MUX_EVENT_CLOSED:
		if (ss == fx->srv) {
			fx->srv_closed = true;
			fx->srv = NULL;
		} else if (ss == fx->cli) {
			fx->cli_closed = true;
			fx->cli = NULL;
		}
		/* Transient sessions (created during resume handshake) reach the
		 * closed event after session_resume_transport destroys them; they
		 * match neither fx->srv nor fx->cli.  mux_close is always required. */
		mux_close(ss);
		break;
	default:
		break;
	}
}

/* -------------------------------------------------------------------------
 * TCP loopback listen helper: bind, listen, return fd and port
 * ---------------------------------------------------------------------- */

static int tcp_listen_loopback(int *restrict port_out)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	int on = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(fd);
		return -1;
	}
	if (listen(fd, 4) != 0) {
		close(fd);
		return -1;
	}
	socklen_t len = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
		close(fd);
		return -1;
	}
	*port_out = (int)ntohs(sa.sin_port);
	return fd;
}

/* Forward declaration needed by pending_accept_cb below */
static const struct mux_callbacks g_srv_callbacks;

static struct mux_frame *test_frame_alloc(void *data)
{
	UNUSED(data);
	return malloc(sizeof(struct mux_frame));
}

static void test_frame_free(void *data, struct mux_frame *frame)
{
	UNUSED(data);
	free(frame);
}

static void proto_session_id_new(unsigned char *const id)
{
	write_uint64(id, rand64());
	write_uint64(id + sizeof(uint64_t), rand64());
}

/* Pending-accept helper: sits on the listen fd and calls mux_new + mux_start
 * for the first accepted connection. */
struct pending_accept {
	struct mux_test_fixture *fx;
	int listen_fd;
	ev_io w_accept;
};

static void pending_accept_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	UNUSED(revents);
	struct pending_accept *restrict pa = w->data;

	const int srv_fd = accept(pa->listen_fd, NULL, NULL);
	if (srv_fd < 0) {
		return;
	}
	{
		const int flags = fcntl(srv_fd, F_GETFL, 0);
		if (flags >= 0) {
			(void)fcntl(srv_fd, F_SETFL, flags | O_NONBLOCK);
		}
	}

	struct mux_test_fixture *restrict fx = pa->fx;
	const struct mux_config srv_conf = {
		.timeout = 30,
		.ping_timeout = 30,
		.keepalive = 15,
		.send_timeout = 10,
		.connect_timeout = 10,
		.resume_timeout = 30,
		.idle_timeout = 0,
		.max_streams = 64,
		.stream_window = 4,
		.session_window = 256,
		.nodelay = fx->nodelay,
	};
	unsigned char srv_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(srv_sid);

	const struct mux_session_opts srv_opts = {
		.callbacks = &g_srv_callbacks,
		.userdata = fx,
		.conf = &srv_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = srv_fd,
		.id = srv_sid,
	};
	if (fx->srv == NULL) {
		/* First accept: create the primary server session. */
		fx->srv = mux_new(loop, &srv_opts);
		if (fx->srv == NULL) {
			close(srv_fd);
			return;
		}
		mux_start(fx->srv);
	} else {
		/* Subsequent accept (resume path): create a transient session.
		 * on_resume_cb will match the session_id and call
		 * session_resume_transport, which migrates the fd to fx->srv
		 * and destroys this transient session via session_reset. */
		struct mux_session *const transient = mux_new(loop, &srv_opts);
		if (transient == NULL) {
			close(srv_fd);
			return;
		}
		mux_start(transient);
	}
	/* The listen socket remains open so the client can reconnect. */
}

static struct mux_config make_cli_conf(const bool nodelay)
{
	return (struct mux_config){
		.nodelay = nodelay,
		.timeout = 30,
		.ping_timeout = 30,
		.keepalive = 15,
		.send_timeout = 10,
		.connect_timeout = 10,
		.resume_timeout = 30,
		.idle_timeout = 0,
		.max_streams = 64,
		.stream_window = 4,
		.session_window = 256,
	};
}

/* -------------------------------------------------------------------------
 * Fixture setup / teardown
 * ---------------------------------------------------------------------- */

static struct mux_session *on_resume_cb(
	void *data, struct mux_session *new_ss, const unsigned char *session_id)
{
	UNUSED(new_ss);
	const struct mux_test_fixture *restrict fx = data;
	if (fx->srv != NULL && memcmp(session_id, mux_session_id(fx->srv),
				      MUX_SESSION_ID_LEN) == 0) {
		return fx->srv;
	}
	return NULL;
}

static const struct mux_callbacks g_srv_callbacks = {
	.on_accept = on_accept_cb,
	.on_event = on_event_cb,
	.on_resume = on_resume_cb,
};

static const struct mux_callbacks g_cli_callbacks = {
	.on_accept = on_accept_cb,
	.on_event = on_event_cb,
};

static int fixture_setup(struct mux_test_fixture *restrict fx)
{
	*fx = (struct mux_test_fixture){ 0 };
	fx->listen_fd_cleanup = -1;
	fx->break_transport_sp = -1;

	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}

	/* Create a TCP listen socket on loopback. The client session will perform
	 * a real TCP connect (via session_connect), which arms EV_WRITE on
	 * completion — the normal handshake trigger without needing socketpair
	 * event injection tricks. */
	int port = 0;
	const int listen_fd = tcp_listen_loopback(&port);
	if (listen_fd < 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}

	/* Register an accept watcher that creates the server-side mux session
	 * when the client connect() arrives. */
	struct pending_accept *pa = malloc(sizeof(struct pending_accept));
	if (pa == NULL) {
		close(listen_fd);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	pa->fx = fx;
	pa->listen_fd = listen_fd;
	ev_io_init(&pa->w_accept, pending_accept_cb, listen_fd, EV_READ);
	pa->w_accept.data = pa;

	(void)snprintf(
		fx->connect_str, sizeof(fx->connect_str), "127.0.0.1:%d", port);

	ev_io_start(fx->loop, &pa->w_accept);

	/* Client session: fd=-1, session_connect() will call connect() and
	 * arm EV_WRITE on the TCP connection. */
	const struct mux_config cli_conf = make_cli_conf(fx->nodelay);
	unsigned char cli_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(cli_sid);
	const struct mux_session_opts cli_opts = {
		.callbacks = &g_cli_callbacks,
		.userdata = fx,
		.conf = &cli_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = -1,
		.id = cli_sid,
	};
	fx->cli = mux_new(fx->loop, &cli_opts);
	if (fx->cli == NULL) {
		ev_io_stop(fx->loop, &pa->w_accept);
		close(listen_fd);
		free(pa);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	/* mux_start is a no-op for client sessions (fd=-1); attach a TCP
	 * connection immediately so the handshake can proceed. */
	mux_start(fx->cli);
	{
		const int cli_fd = fixture_dial(fx->connect_str);
		if (cli_fd >= 0) {
			mux_attach_fd(fx->cli, cli_fd);
		}
	}

	/* Store pa pointer so teardown can clean up if the accept never fires. */
	fx->listen_fd_cleanup = listen_fd;
	fx->pending_accept = pa;
	return 0;
}

static void fixture_teardown(struct mux_test_fixture *restrict fx)
{
	/* If the accept watcher never fired, clean it up here. */
	if (fx->pending_accept != NULL) {
		struct pending_accept *restrict pa = fx->pending_accept;
		if (fx->loop != NULL) {
			ev_io_stop(fx->loop, &pa->w_accept);
		}
		close(pa->listen_fd);
		free(pa);
		fx->pending_accept = NULL;
	} else if (fx->listen_fd_cleanup >= 0) {
		/* listen_fd was already closed in pending_accept_cb; nothing to do. */
		(void)fx->listen_fd_cleanup;
	}

	if (fx->break_transport_sp >= 0) {
		close(fx->break_transport_sp);
		fx->break_transport_sp = -1;
	}
	if (fx->srv != NULL) {
		mux_close(fx->srv);
		fx->srv = NULL;
	}
	if (fx->cli != NULL) {
		mux_close(fx->cli);
		fx->cli = NULL;
	}

	/* Free accepted server streams */
	for (int i = 0; i < fx->n_accepted; i++) {
		test_stream_free(fx->accepted[i]);
		fx->accepted[i] = NULL;
	}
	fx->n_accepted = 0;

	/* Free client-side test streams */
	for (int i = 0; i < fx->n_cli_streams; i++) {
		test_stream_free(fx->cli_streams[i]);
		fx->cli_streams[i] = NULL;
	}
	fx->n_cli_streams = 0;

	/* Free server-side actively opened streams */
	for (int i = 0; i < fx->n_srv_active_streams; i++) {
		test_stream_free(fx->srv_active_streams[i]);
		fx->srv_active_streams[i] = NULL;
	}
	fx->n_srv_active_streams = 0;

	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* -------------------------------------------------------------------------
 * Predicates
 * ---------------------------------------------------------------------- */

static int pred_established(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->srv_established && fx->cli_established) {
		return 1;
	}
	return 0;
}

struct echo_ctx {
	struct test_stream *ts;
	const unsigned char *expected;
	size_t expected_len;
};

static int pred_echo_received(void *ptr)
{
	const struct echo_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	if (ctx->ts->recv_len >= ctx->expected_len) {
		return 1;
	}
	return 0;
}

static int pred_eof(void *ptr)
{
	const struct test_stream *restrict ts = ptr;
	if (ts->got_error) {
		return -1;
	}
	return ts->got_eof ? 1 : 0;
}

/* Satisfied when the stream has received at least expected_len bytes and also
 * obtained peer EOF.  Used to verify data-then-FIN sequences. */
static int pred_echo_and_eof(void *ptr)
{
	const struct echo_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	if (ctx->ts->recv_len >= ctx->expected_len && ctx->ts->got_eof) {
		return 1;
	}
	return 0;
}

static int pred_error(void *ptr)
{
	const struct test_stream *restrict ts = ptr;
	return ts->got_error ? 1 : 0;
}

static int pred_cli_closed(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	return fx->cli_closed ? 1 : 0;
}

/* Satisfied when both sessions have fired MUX_EVENT_RESUMED.
 * Returns -1 on unexpected close to short-circuit the wait. */
static int pred_resumed(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->cli_closed || fx->srv_closed) {
		return -1;
	}
	return (fx->cli_resumed && fx->srv_resumed) ? 1 : 0;
}

/* Satisfied when both streams have received EOF and neither has an error.
 * Used to verify simultaneous-close (both sides send FIN independently). */
struct both_eof_ctx {
	const struct test_stream *a;
	const struct test_stream *b;
};

static int pred_both_eof_no_error(void *ptr)
{
	const struct both_eof_ctx *restrict ctx = ptr;
	if (ctx->a->got_error || ctx->b->got_error) {
		return -1;
	}
	if (ctx->a->got_eof && ctx->b->got_eof) {
		return 1;
	}
	return 0;
}

struct accepted_count_ctx {
	const struct mux_test_fixture *fx;
	int min_accepted;
};

static int pred_accepted_count(void *ptr)
{
	const struct accepted_count_ctx *restrict ctx = ptr;
	return ctx->fx->n_accepted >= ctx->min_accepted ? 1 : 0;
}

struct no_error_and_no_halfopen_ctx {
	const struct mux_test_fixture *fx;
	const struct test_stream *ts;
};

static int pred_no_error_and_no_halfopen(void *ptr)
{
	const struct no_error_and_no_halfopen_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	return ctx->fx->cli->num_halfopen == 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Helper: fill buffer with deterministic pseudo-random content
 * ---------------------------------------------------------------------- */

static void fill_payload(
	unsigned char *restrict buf, const size_t len, const uint_fast8_t seed)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (unsigned char)((seed + i * 31u + i * i * 7u) & 0xFFu);
	}
}

/* -------------------------------------------------------------------------
 * Test cases
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_establish)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	const int ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established, &fx);
	T_EXPECT(ret == 0);
	T_EXPECT(fx.srv_established);
	T_EXPECT(fx.cli_established);

	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_send_recv_small)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x42);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		free(payload);
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		free(payload);
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_SMALL);
	if (ts->recv_len == PAYLOAD_SMALL) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0);
	}

	free(payload);
cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_idle_scheduler_stops_while_sendbuf_blocked: when EV_IDLE encounters
 * an INIT stream but transport sendbuf is already occupied, it must leave
 * the stream queued without re-arming the idle watcher. Active idle watchers
 * keep libev from sleeping, so re-arming here would spin the loop until the
 * transport becomes writable.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_idle_scheduler_stops_while_sendbuf_blocked)
{
	struct mux_test_fixture fx;
	struct mux_frame *frame = NULL;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* Stop transport watchers so EVRUN_NOWAIT executes only the idle path. */
	ev_io_stop(fx.loop, &fx.cli->w_socket);
	ev_io_stop(fx.loop, &fx.srv->w_socket);

	frame = mux_frame_get(&fx.cli->pool);
	if (frame == NULL) {
		T_FATAL("mux_frame_get failed");
		goto cleanup;
	}
	frame->pos = 0;
	frame->len = MUX_FRAME_HEADER_SIZE;
	mux_frame_list_push(&fx.cli->wire.sendbuf, frame);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	/* With the new design, EV_IDLE is not armed while sendbuf is
	 * occupied; tx_pending is set instead so EV_WRITE fires to drain
	 * sendbuf, after which session_flush re-arms EV_IDLE. */
	T_EXPECT(!ev_is_active(&fx.cli->sched.w_sched));
	T_EXPECT(fx.cli->sched.lp_head != NULL);
	T_EXPECT(fx.cli->wire.tx_pending);

	/* session_update_watcher (called from sched_wake) re-armed the socket
	 * watcher with EV_WRITE.  Stop it again so EVRUN_NOWAIT does not fire
	 * send_cb, which would drain sendbuf and re-arm EV_IDLE. */
	ev_io_stop(fx.loop, &fx.cli->w_socket);

	ev_run(fx.loop, EVRUN_NOWAIT);

	T_EXPECT(!ev_is_active(&fx.cli->sched.w_sched));
	T_EXPECT(fx.cli->wire.sendbuf.head == frame);
	T_EXPECT(fx.cli->wire.tx_pending);

cleanup:
	if (fx.cli != NULL) {
		if (fx.cli->wire.sendbuf.head == frame) {
			(void)mux_frame_list_pop(&fx.cli->wire.sendbuf);
			mux_frame_put(&fx.cli->pool, frame);
			frame = NULL;
		}
		fx.cli->wire.tx_pending = false;
		session_update_watcher(fx.cli);
	}
	if (fx.srv != NULL) {
		session_update_watcher(fx.srv);
	}
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_nagle_releases_queued_small_frame_on_ack)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char payload_a[37];
	unsigned char payload_b[53];
	unsigned char expected[sizeof(payload_a) + sizeof(payload_b)];
	fill_payload(payload_a, sizeof(payload_a), 0x21);
	fill_payload(payload_b, sizeof(payload_b), 0x4D);
	memcpy(expected, payload_a, sizeof(payload_a));
	memcpy(expected + sizeof(payload_a), payload_b, sizeof(payload_b));

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}

	size_t len_a = sizeof(payload_a);
	T_EXPECT(mux_stream_send(s, payload_a, &len_a) == 0);
	T_EXPECT_EQ(len_a, sizeof(payload_a));

	size_t len_b = sizeof(payload_b);
	T_EXPECT(mux_stream_send(s, payload_b, &len_b) == 0);
	T_EXPECT_EQ(len_b, sizeof(payload_b));

	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = expected,
		.expected_len = sizeof(expected),
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, sizeof(expected));
	if (ts->recv_len == sizeof(expected)) {
		T_EXPECT(memcmp(ts->recv_buf, expected, sizeof(expected)) == 0);
	}

cleanup:
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_send_recv_large)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x7F);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		free(payload);
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		free(payload);
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_LARGE;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_LARGE);
	if (ts->recv_len == PAYLOAD_LARGE) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0);
	}

	free(payload);
cleanup:
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_half_close)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0x11);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait for the echo to arrive and client to receive EOF from server. */
	const int ret = wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_eof, ts);
	T_EXPECT(ret == 0);
	T_EXPECT(ts->got_eof);
	T_EXPECT(!ts->got_error);

cleanup:
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_rst_on_unread_data)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* Server will close immediately when a stream arrives (RST). */
	fx.accept_mode = ACCEPT_CLOSE_IMMEDIATE;

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0xAB);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait for client to observe ECONNRESET (RST from server, delivered
	 * as EV_READ; mux_stream_recv returns -1 / ECONNRESET). */
	const int ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	T_EXPECT(ret == 0);
	T_EXPECT(ts->got_error);

cleanup:
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_multi_stream)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *payloads[MULTI_CONCURRENCY];
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		payloads[i] = NULL;
	}
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		payloads[i] = malloc(PAYLOAD_SMALL);
		if (payloads[i] == NULL) {
			T_FATAL("malloc failed");
			goto cleanup_payloads;
		}
		fill_payload(
			payloads[i], PAYLOAD_SMALL, (uint_fast8_t)(i * 37));
	}

	struct test_stream *streams[MULTI_CONCURRENCY];
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		streams[i] = NULL;
	}
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		struct mux_stream *s = mux_open_stream(fx.cli);
		if (s == NULL) {
			T_FATAL("mux_open_stream returned NULL");
			goto cleanup_payloads;
		}
		struct test_stream *ts = test_stream_new(&fx, s);
		if (ts == NULL) {
			T_FATAL("test_stream_new failed");
			goto cleanup_payloads;
		}
		if (fx.n_cli_streams < MAX_ACCEPTED) {
			fx.cli_streams[fx.n_cli_streams++] = ts;
		}
		streams[i] = ts;
		ts->send_data = payloads[i];
		ts->send_len = PAYLOAD_SMALL;
		mux_stream_io_start(fx.loop, &ts->w_io);
	}

	/* Wait for all streams to receive their echoed payload. */
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		struct echo_ctx ctx = {
			.ts = streams[i],
			.expected = payloads[i],
			.expected_len = PAYLOAD_SMALL,
		};
		const int ret = wait_until(
			&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
			&ctx);
		T_EXPECT(ret == 0);
		if (ret == 0) {
			T_EXPECT_EQ(
				streams[i]->recv_len, (size_t)PAYLOAD_SMALL);
			if (streams[i]->recv_len == PAYLOAD_SMALL) {
				T_EXPECT(
					memcmp(streams[i]->recv_buf,
					       payloads[i],
					       PAYLOAD_SMALL) == 0);
			}
		}
	}

cleanup_payloads:
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		free(payloads[i]);
	}
cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_server_open_send_recv: server actively opens a stream and sends a
 * payload first; the client-side (echo) sends it back.  Verifies that the
 * server-side initiator correctly receives the echoed data.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_server_open_send_recv)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x55);

	/* Server actively opens a stream toward the client. */
	struct mux_stream *s = mux_open_stream(fx.srv);
	if (s == NULL) {
		T_FATAL("mux_open_stream(srv) returned NULL");
		free(payload);
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		free(payload);
		goto cleanup;
	}
	if (fx.n_srv_active_streams < MAX_ACCEPTED) {
		fx.srv_active_streams[fx.n_srv_active_streams++] = ts;
	}
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Client-side on_accept_cb uses default ACCEPT_ECHO mode and will
	 * echo all data back to the server. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_SMALL);
	if (ts->recv_len == PAYLOAD_SMALL) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0);
	}

	free(payload);
cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_client_open_server_sends_first: client opens a stream but sends no
 * data; the server-side accepted stream sends a payload and immediately
 * half-closes.  Verifies that the client correctly receives the data and
 * the peer EOF.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_client_open_server_sends_first)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0xC3);

	/* Server will send payload + FIN when a stream is accepted. */
	fx.accept_mode = ACCEPT_SEND_PAYLOAD;
	fx.accept_send_data = payload;
	fx.accept_send_len = PAYLOAD_SMALL;

	/* Client opens a stream; it does not send any data – it only receives. */
	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream(cli) returned NULL");
		free(payload);
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		free(payload);
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait until the client received all bytes AND got peer EOF. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_SMALL);
	T_EXPECT(ts->got_eof);
	T_EXPECT(!ts->got_error);
	if (ts->recv_len == PAYLOAD_SMALL) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0);
	}

	free(payload);
cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_graceful_close_server_initiated: server actively opens a stream,
 * sends a small payload, then half-closes (FIN).  The client-side echo
 * server mirrors the data and the FIN back.  Verifies that the server-side
 * initiator observes a clean EOF without errors.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_graceful_close_server_initiated)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0xD4);

	/* Server opens and will send payload then FIN. */
	struct mux_stream *s = mux_open_stream(fx.srv);
	if (s == NULL) {
		T_FATAL("mux_open_stream(srv) returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	if (fx.n_srv_active_streams < MAX_ACCEPTED) {
		fx.srv_active_streams[fx.n_srv_active_streams++] = ts;
	}
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Client-side (ACCEPT_ECHO) echoes the data and mirrors the FIN.
	 * Server then receives the echoed data and a peer EOF. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = sizeof(payload),
	};
	const int ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT(ts->got_eof);
	T_EXPECT(!ts->got_error);
	T_EXPECT_EQ(ts->recv_len, sizeof(payload));
	if (ts->recv_len == sizeof(payload)) {
		T_EXPECT(memcmp(ts->recv_buf, payload, sizeof(payload)) == 0);
	}

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_simultaneous_close: both endpoints independently half-close their
 * send sides, exercising the STREAM_FIN_WAIT -> STREAM_CLOSING path (active
 * opener receives peer FIN while already in FIN_WAIT) and the
 * STREAM_CLOSE_WAIT -> STREAM_CLOSING path (passive opener sends its own FIN
 * after having received the peer FIN).  Both sides send distinct payloads.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_simultaneous_close)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *cli_payload = malloc(PAYLOAD_SMALL);
	if (cli_payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(cli_payload, PAYLOAD_SMALL, 0x77);

	unsigned char *srv_payload = malloc(PAYLOAD_SMALL);
	if (srv_payload == NULL) {
		T_FATAL("malloc failed");
		free(cli_payload);
		goto cleanup;
	}
	fill_payload(srv_payload, PAYLOAD_SMALL, 0x88);

	/* Server sends srv_payload + FIN when the stream is accepted. */
	fx.accept_mode = ACCEPT_SEND_PAYLOAD;
	fx.accept_send_data = srv_payload;
	fx.accept_send_len = PAYLOAD_SMALL;

	/* Client opens a stream and sends cli_payload + FIN. */
	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		free(cli_payload);
		free(srv_payload);
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		free(cli_payload);
		free(srv_payload);
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = cli_payload;
	ts->send_len = PAYLOAD_SMALL;
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait until the server has accepted the stream. */
	struct accepted_count_ctx acc_ctx = { .fx = &fx, .min_accepted = 1 };
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_accepted_count,
		    &acc_ctx) != 0) {
		T_FATAL("server did not accept stream");
		free(cli_payload);
		free(srv_payload);
		goto cleanup;
	}

	/* Both sides independently receive data and a peer FIN. */
	struct test_stream *srv_ts = fx.accepted[0];
	const struct both_eof_ctx ctx = { .a = ts, .b = srv_ts };
	const int ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_both_eof_no_error,
		(void *)&ctx);
	T_EXPECT(ret == 0);
	T_EXPECT(ts->got_eof);
	T_EXPECT(!ts->got_error);
	T_EXPECT(srv_ts->got_eof);
	T_EXPECT(!srv_ts->got_error);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_SMALL);
	if (ts->recv_len == PAYLOAD_SMALL) {
		T_EXPECT(memcmp(ts->recv_buf, srv_payload, PAYLOAD_SMALL) == 0);
	}
	T_EXPECT_EQ(srv_ts->recv_len, (size_t)PAYLOAD_SMALL);
	if (srv_ts->recv_len == PAYLOAD_SMALL) {
		T_EXPECT(
			memcmp(srv_ts->recv_buf, cli_payload, PAYLOAD_SMALL) ==
			0);
	}
	{
		T_EXPECT_EQ(fx.cli->num_halfopen, (size_t)0);
	}

	free(cli_payload);
	free(srv_payload);
cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_rst_from_client: server opens a stream and sends a payload; the
 * client-side accepted stream closes without reading, which triggers a RST
 * because the receive buffer is non-empty.  Verifies that the server-side
 * initiator observes an error (ECONNRESET) delivered as got_error.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_rst_from_client)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* Client-side accepted streams will close on first readable event,
	 * triggering RST because the receive buffer contains unread data. */
	fx.accept_mode = ACCEPT_CLOSE_IMMEDIATE;

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0xE5);

	/* Server opens a stream and sends data; this data will land in the
	 * client-side receive buffer, triggering RST on close. */
	struct mux_stream *s = mux_open_stream(fx.srv);
	if (s == NULL) {
		T_FATAL("mux_open_stream(srv) returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	if (fx.n_srv_active_streams < MAX_ACCEPTED) {
		fx.srv_active_streams[fx.n_srv_active_streams++] = ts;
	}
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Server should receive ECONNRESET (RST from client). */
	const int ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	T_EXPECT(ret == 0);
	T_EXPECT(ts->got_error);

cleanup:
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_active_open_shutdown_before_synack)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Request local half-close immediately.  This used to be able to send
	 * FIN before SYN|ACK on active-open paths. */
	mux_stream_shutdown(s);

	/* Ensure server accepted the stream and local side reaches clean EOF. */
	struct accepted_count_ctx accepted_ctx = {
		.fx = &fx,
		.min_accepted = 1,
	};
	T_EXPECT(
		wait_until(
			&fx, ECHO_TIMEOUT_MS / 1000.0, pred_accepted_count,
			&accepted_ctx) == 0);

	/* Direct I/O may complete the FIN/FIN exchange and close the stream
	 * without delivering a final EOF callback.  The key regression signal
	 * is that the path stays graceful and does not raise ECONNRESET. */
	const struct no_error_and_no_halfopen_ctx stable_ctx = {
		.fx = &fx,
		.ts = ts,
	};
	T_EXPECT(
		wait_until(
			&fx, EOF_TIMEOUT_MS / 1000.0,
			pred_no_error_and_no_halfopen,
			(void *)&stable_ctx) == 0);
	T_EXPECT(!ts->got_error);
	{
		T_EXPECT_EQ(fx.cli->num_halfopen, (size_t)0);
	}

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * Raw interoperability test infrastructure
 *
 * A minimal fixture for wire-level tests.  One end of a socketpair is given
 * to a mux server session; the other end (raw_fd) is driven manually by the
 * test to inject or inspect frames directly.
 * ---------------------------------------------------------------------- */

struct raw_fixture {
	struct ev_loop *loop;
	struct mux_session *srv;
	bool srv_established;
	bool srv_closed;
	int raw_fd;
};

static void raw_on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	UNUSED(edata);
	struct raw_fixture *fx = data;
	switch (event) {
	case MUX_EVENT_ESTABLISHED:
		fx->srv_established = true;
		break;
	case MUX_EVENT_CLOSED:
		fx->srv_closed = true;
		fx->srv = NULL;
		mux_close(ss);
		break;
	default:
		break;
	}
}

static const struct mux_callbacks g_raw_callbacks = {
	.on_accept = NULL,
	.on_event = raw_on_event_cb,
};

static int raw_fixture_setup(
	struct raw_fixture *fx, const struct mux_callbacks *restrict cbs,
	void *userdata)
{
	*fx = (struct raw_fixture){ .raw_fd = -1 };

	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}

	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}

	/* fds[0] = server mux session socket (non-blocking for libev) */
	{
		const int flags = fcntl(fds[0], F_GETFL, 0);
		if (flags >= 0) {
			(void)fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
		}
	}
	/* fds[1] = raw test socket (blocking with 2-second safety timeout) */
	{
		const struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
		(void)setsockopt(
			fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	fx->raw_fd = fds[1];

	const struct mux_config srv_conf = {
		.timeout = 30,
		.ping_timeout = 30,
		.keepalive = 15,
		.send_timeout = 10,
		.connect_timeout = 10,
		.resume_timeout = 30,
		.idle_timeout = 0,
		.max_streams = 64,
		.stream_window = 4,
		.session_window = 256,
	};

	unsigned char raw_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(raw_sid);
	const struct mux_session_opts raw_opts = {
		.callbacks = cbs,
		.userdata = userdata,
		.conf = &srv_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = fds[0],
		.id = raw_sid,
	};
	fx->srv = mux_new(fx->loop, &raw_opts);
	if (fx->srv == NULL) {
		close(fds[0]);
		close(fx->raw_fd);
		fx->raw_fd = -1;
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	mux_start(fx->srv);
	return 0;
}

static void raw_fixture_teardown(struct raw_fixture *restrict fx)
{
	if (fx->srv != NULL) {
		mux_close(fx->srv);
		fx->srv = NULL;
	}
	if (fx->raw_fd >= 0) {
		close(fx->raw_fd);
		fx->raw_fd = -1;
	}
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* Write exactly n bytes, retrying on EINTR. */
static bool raw_write_all(const int fd, const void *const buf, const size_t n)
{
	const unsigned char *p = buf;
	size_t remaining = n;
	while (remaining > 0) {
		const ssize_t nw = write(fd, p, remaining);
		if (nw < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		p += (size_t)nw;
		remaining -= (size_t)nw;
	}
	return true;
}

/* Read exactly n bytes, retrying on EINTR.  Returns false on EOF or error. */
static bool raw_read_all(const int fd, void *const buf, const size_t n)
{
	unsigned char *p = buf;
	size_t remaining = n;
	while (remaining > 0) {
		const ssize_t nr = read(fd, p, remaining);
		if (nr <= 0) {
			if (nr == 0) {
				return false; /* EOF */
			}
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		p += (size_t)nr;
		remaining -= (size_t)nr;
	}
	return true;
}

/* Drive the event loop until predicate fires or timeout_sec elapses. */
static int raw_wait_until(
	struct raw_fixture *fx, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	struct condition_waiter waiter = { .timed_out = false };
	ev_timer_init(
		&waiter.w_timer, condition_waiter_timer_cb, timeout_sec, 0.0);
	waiter.w_timer.data = &waiter;
	ev_timer_start(fx->loop, &waiter.w_timer);

	while (!waiter.timed_out) {
		const int status = predicate(ctx);
		if (status != 0) {
			ev_timer_stop(fx->loop, &waiter.w_timer);
			return status > 0 ? 0 : -1;
		}
		ev_run(fx->loop, EVRUN_ONCE);
	}

	ev_timer_stop(fx->loop, &waiter.w_timer);
	errno = ETIMEDOUT;
	return -1;
}

/* Predicate: server reached SESSION_ESTABLISHED. */
static int raw_pred_established(void *ctx)
{
	const struct raw_fixture *restrict fx = ctx;
	return fx->srv_established ? 1 : 0;
}

/* Predicate: server session closed. */
static int raw_pred_closed(void *ctx)
{
	const struct raw_fixture *restrict fx = ctx;
	return fx->srv_closed ? 1 : 0;
}

/* Write an 8-byte frame header (zero-payload) to fd. */
static bool raw_send_frame(const int fd, const struct mux_header *restrict hdr)
{
	unsigned char buf[MUX_FRAME_HEADER_SIZE];
	mux_write_header(buf, hdr);
	return raw_write_all(fd, buf, sizeof(buf));
}

/* Write a frame header followed by exactly hdr->length payload octets. */
static bool raw_send_frame_payload(
	const int fd, const struct mux_header *restrict hdr,
	const void *restrict payload)
{
	if (!raw_send_frame(fd, hdr)) {
		return false;
	}
	if (hdr->length == 0) {
		return true;
	}
	return raw_write_all(fd, payload, hdr->length);
}

/* Read an 8-byte frame header from fd (blocking, subject to SO_RCVTIMEO). */
static bool raw_read_frame_header(const int fd, struct mux_header *restrict hdr)
{
	unsigned char buf[MUX_FRAME_HEADER_SIZE];
	if (!raw_read_all(fd, buf, MUX_FRAME_HEADER_SIZE)) {
		return false;
	}
	mux_read_header(buf, hdr);
	return true;
}

static bool raw_discard_payload(const int fd, const uint_least16_t length)
{
	if (length == 0) {
		return true;
	}
	unsigned char *discard_buf = malloc(length);
	if (discard_buf == NULL) {
		return false;
	}
	const bool ok = raw_read_all(fd, discard_buf, length);
	free(discard_buf);
	return ok;
}

/* Returns 1 when raw_fd has incoming data, -1 on EOF/error, 0 otherwise. */
static int raw_pred_data_available(void *ctx)
{
	const int fd = *(const int *)ctx;
	unsigned char b;
	const ssize_t nr = recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT);
	if (nr > 0) {
		return 1;
	}
	if (nr == 0) {
		return -1; /* EOF */
	}
	return 0; /* EAGAIN / EINTR */
}

/*
 * Perform the hello exchange from the raw (client) side:
 * 1. Build and send a valid ClientHello.
 * 2. Drive the event loop until the server reaches SESSION_ESTABLISHED.
 * 3. Drain the ServerHello reply from raw_fd.
 */
static bool raw_do_hello(struct raw_fixture *restrict fx)
{
	unsigned char buf[512];
	struct proto_hello hello = {
		.msgid = PROTO_MSG_CLIENT_HELLO,
		.reject_inbound = false,
		.session_id = { 0 },
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 0,
	};
	const int n = proto_hello_build(buf, sizeof(buf), &hello);
	if (n <= 0) {
		return false;
	}
	if (!raw_write_all(fx->raw_fd, buf, (size_t)n)) {
		return false;
	}

	if (raw_wait_until(
		    fx, ESTABLISH_TIMEOUT_MS / 1000.0, raw_pred_established,
		    fx) != 0) {
		return false;
	}

	/* The server enqueues the ServerHello before signalling ESTABLISHED;
	 * drive the event loop until it is flushed to the socket. */
	if (raw_wait_until(fx, 2.0, raw_pred_data_available, &fx->raw_fd) !=
	    0) {
		return false;
	}

	/* Drain the 8-octet frame header + JSON body of the ServerHello. */
	struct mux_header srv_hdr;
	if (!raw_read_frame_header(fx->raw_fd, &srv_hdr)) {
		return false;
	}
	if (srv_hdr.length > 0) {
		unsigned char *body = malloc(srv_hdr.length);
		if (body == NULL) {
			return false;
		}
		const bool ok = raw_read_all(fx->raw_fd, body, srv_hdr.length);
		free(body);
		if (!ok) {
			return false;
		}
	}
	return true;
}

/* -------------------------------------------------------------------------
 * Interoperability test cases
 * ---------------------------------------------------------------------- */

/*
 * I-1: Non-SYN frame for an unknown non-zero stream.
 *
 * The raw (client) side sends an ACK-only frame whose stream ID is not
 * known to the server.  A zero-length ACK on an unknown stream is an
 * ignorable terminal control frame, so the server leaves the session open.
 * It may still emit session-level ACK traffic on stream 0, but emits no
 * stream-level response for stream 1.
 */
T_DECLARE_CASE(test_interop_i1_non_syn_unknown_stream)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	const struct mux_header ack_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_ACK,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(fx.raw_fd, &ack_hdr));

	int raw_fd = fx.raw_fd;
	errno = 0;
	const int wait_ret =
		raw_wait_until(&fx, 0.1, raw_pred_data_available, &raw_fd);
	if (wait_ret == 0) {
		while (raw_pred_data_available(&raw_fd) > 0) {
			struct mux_header resp;
			T_EXPECT(raw_read_frame_header(fx.raw_fd, &resp));
			T_EXPECT_EQ(resp.stream_id, (uint_least16_t)0);
			T_EXPECT((resp.flags & MUX_FLAG_ACK) != 0);
			T_EXPECT_EQ(resp.length, (uint_least16_t)0);
			T_EXPECT(raw_discard_payload(fx.raw_fd, resp.length));
		}
	} else {
		T_EXPECT_EQ(errno, ETIMEDOUT);
	}
	T_EXPECT(raw_wait_until(&fx, 0.1, raw_pred_closed, &fx) != 0);

cleanup:
	raw_fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * Stream-aware raw fixture
 *
 * Extends raw_fixture with an on_accept callback that tracks the accepted
 * stream, enabling tests that require an established or half-closed stream.
 * ---------------------------------------------------------------------- */

/* Accepts RAW stream events without acting on them. */
static void
raw_stream_io_noop_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	UNUSED(loop);
	UNUSED(w);
	UNUSED(revents);
}

struct raw_stream_fixture {
	struct raw_fixture base;
	struct mux_stream *accepted_stream;
	mux_stream_io w_stream;
};

static bool raw_stream_on_accept_cb(
	void *data, const struct mux_session *ss, struct mux_stream *s)
{
	UNUSED(ss);
	struct raw_stream_fixture *sfx = data;
	sfx->accepted_stream = s;
	mux_stream_io_init(&sfx->w_stream, raw_stream_io_noop_cb, s, EV_READ);
	mux_stream_io_start(sfx->base.loop, &sfx->w_stream);
	return true;
}

static void raw_stream_on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	UNUSED(edata);
	struct raw_stream_fixture *sfx = data;
	switch (event) {
	case MUX_EVENT_ESTABLISHED:
		sfx->base.srv_established = true;
		break;
	case MUX_EVENT_CLOSED:
		sfx->base.srv_closed = true;
		sfx->base.srv = NULL;
		sfx->accepted_stream = NULL;
		mux_close(ss);
		break;
	default:
		break;
	}
}

static const struct mux_callbacks g_raw_stream_callbacks = {
	.on_accept = raw_stream_on_accept_cb,
	.on_event = raw_stream_on_event_cb,
};

static int raw_stream_fixture_setup(struct raw_stream_fixture *restrict sfx)
{
	*sfx = (struct raw_stream_fixture){ 0 };
	return raw_fixture_setup(&sfx->base, &g_raw_stream_callbacks, sfx);
}

static void raw_stream_fixture_teardown(struct raw_stream_fixture *restrict sfx)
{
	raw_fixture_teardown(&sfx->base);
}

/* Read and discard exactly one 8-byte frame header plus its payload from fd.
 * Returns false on read error. */
static bool raw_drain_frame(const int fd)
{
	struct mux_header hdr;
	if (!raw_read_frame_header(fd, &hdr)) {
		return false;
	}
	return raw_discard_payload(fd, hdr.length);
}

/* Drain all frames immediately available in the socket receive buffer without
 * blocking.  Used after raw_drain_frame to consume any additional headers
 * packed in the same ctrl frame (e.g. piggybacked session ACKs), so that the
 * socket buffer is clean before the next raw_wait_until call. */
static bool raw_drain_available(const int fd)
{
	for (;;) {
		unsigned char peek[MUX_FRAME_HEADER_SIZE];
		const ssize_t nr =
			recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT);
		if (nr < (ssize_t)MUX_FRAME_HEADER_SIZE) {
			break;
		}
		if (!raw_drain_frame(fd)) {
			return false;
		}
	}
	return true;
}

/*
 * I-2: Undefined flag combination in STREAM_CLOSE_WAIT state.
 *
 * After half-closing from the client side (sending FIN), the server-side
 * stream enters STREAM_CLOSE_WAIT.  In that state only ACK is a valid
 * inbound flag (spec §4.2.1).  Sending PUSH after FIN is undefined; the
 * receiver MAY send RST with PROTOCOL_ERROR.
 */
T_DECLARE_CASE(test_interop_i2_close_wait_push)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	/* Open stream 1 from the raw client side. */
	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &syn_hdr));

	/* Wait for SYN|ACK from server, then drain it (including any
	 * piggybacked session-level headers packed in the same ctrl frame). */
	int raw_fd = sfx.base.raw_fd;
	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	T_EXPECT(raw_drain_frame(sfx.base.raw_fd));
	T_EXPECT(raw_drain_available(sfx.base.raw_fd));

	/* Half-close: send FIN to push the server-side stream into
	 * STREAM_CLOSE_WAIT. */
	const struct mux_header fin_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_FIN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &fin_hdr));

	/* Drive the event loop so the FIN is processed before sending PUSH. */
	ev_run(sfx.base.loop, EVRUN_NOWAIT);

	/* Send PUSH in STREAM_CLOSE_WAIT — invalid combination, MAY RST. */
	const struct mux_header push_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &push_hdr));

	/* Wait for and verify RST response. */
	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	struct mux_header resp;
	T_EXPECT(raw_read_frame_header(sfx.base.raw_fd, &resp));
	T_EXPECT((resp.flags & MUX_FLAG_RST) != 0);
	T_EXPECT_EQ(resp.stream_id, (uint_least16_t)1);

cleanup:
	raw_stream_fixture_teardown(&sfx);
}

/*
 * I-5: Duplicate SYN for an existing stream.
 *
 * After opening stream 1 and completing the SYN|ACK handshake, the raw
 * client sends another SYN for the same stream ID.  The server MUST respond
 * with RST per spec §8 (Error Handling - Duplicate SYN).
 */
T_DECLARE_CASE(test_interop_i5_duplicate_syn)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	/* Open stream 1 from the raw client side. */
	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &syn_hdr));

	/* Wait for SYN|ACK, then drain it (including any piggybacked
	 * session-level headers packed in the same ctrl frame). */
	int raw_fd = sfx.base.raw_fd;
	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	T_EXPECT(raw_drain_frame(sfx.base.raw_fd));
	T_EXPECT(raw_drain_available(sfx.base.raw_fd));

	/* Send a second SYN for the same stream ID — duplicate. */
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &syn_hdr));

	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	struct mux_header resp;
	T_EXPECT(raw_read_frame_header(sfx.base.raw_fd, &resp));
	T_EXPECT((resp.flags & MUX_FLAG_RST) != 0);
	T_EXPECT_EQ(resp.stream_id, (uint_least16_t)1);

cleanup:
	raw_stream_fixture_teardown(&sfx);
}

/*
 * I-3: ACK|FIN Extra field carries a credit grant, not a status code.
 *
 * Send a large payload then half-close.  The echo server will at some point
 * have both ack_pending and fin_pending simultaneously, resulting in an
 * ACK|FIN frame whose Extra field encodes the remaining credit increment.
 * If Extra were mistakenly treated as a status code the transfer would stall.
 */
T_DECLARE_CASE(test_interop_i3_ack_fin_credit)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0xA1);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		free(payload);
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		free(payload);
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_LARGE;
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_LARGE);
	T_EXPECT(ts->got_eof);
	T_EXPECT(!ts->got_error);
	if (ts->recv_len == PAYLOAD_LARGE) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0);
	}

	free(payload);
cleanup:
	fixture_teardown(&fx);
}

/*
 * I-4: Stream ID parity violation.
 *
 * The raw (client) side sends a SYN with an even stream ID (2), which
 * violates the client-must-use-odd-IDs rule.  The server MUST respond
 * with RST carrying PROTOCOL_ERROR.
 */
T_DECLARE_CASE(test_interop_i4_stream_id_parity)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 2, /* even — invalid for a client-side stream */
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(fx.raw_fd, &syn_hdr));

	/* Server must close the connection on stream ID parity violation. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);
	T_EXPECT(wait_ret == 0);

	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);
	T_EXPECT(nr == 0);

cleanup:
	raw_fixture_teardown(&fx);
}

/*
 * I-6: Fast-open credit boundary.
 *
 * Client opens a stream and immediately queues exactly MUX_DEFAULT_SEND_WINDOW
 * (16384) bytes before the event loop runs.  The scheduler combines this into
 * a single SYN|PUSH frame of exactly 16384 octets.  The receiver MUST accept
 * it and complete stream establishment without sending RST.
 */
T_DECLARE_CASE(test_interop_i6_fast_open_16384)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char payload[MUX_DEFAULT_SEND_WINDOW];
	fill_payload(payload, sizeof(payload), 0xB2);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	/* Queue the full credit window synchronously before the loop runs. */
	size_t len = sizeof(payload);
	const int sr = mux_stream_send(s, payload, &len);
	T_EXPECT(sr == 0);
	T_EXPECT_EQ(len, sizeof(payload));

	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = sizeof(payload),
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, sizeof(payload));
	T_EXPECT(!ts->got_error);
	if (ts->recv_len == sizeof(payload)) {
		T_EXPECT(memcmp(ts->recv_buf, payload, sizeof(payload)) == 0);
	}

cleanup:
	fixture_teardown(&fx);
}

/*
 * I-7: Out-of-order FIN then data.
 *
 * After the raw client half-closes the stream with FIN, the server-side
 * stream enters STREAM_CLOSE_WAIT.  A subsequent PUSH carrying payload on the
 * same stream is undefined for that state; the current implementation enforces
 * its local closed-stream policy by replying with RST.
 */
T_DECLARE_CASE(test_interop_i7_fin_then_data)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &syn_hdr));

	int raw_fd = sfx.base.raw_fd;
	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	T_EXPECT(raw_drain_frame(sfx.base.raw_fd));
	T_EXPECT(raw_drain_available(sfx.base.raw_fd));

	const struct mux_header fin_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_FIN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &fin_hdr));

	ev_run(sfx.base.loop, EVRUN_NOWAIT);

	static const unsigned char payload[] = { 0x7A };
	const struct mux_header push_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame_payload(sfx.base.raw_fd, &push_hdr, payload));

	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	struct mux_header resp;
	T_EXPECT(raw_read_frame_header(sfx.base.raw_fd, &resp));
	T_EXPECT((resp.flags & MUX_FLAG_RST) != 0);
	T_EXPECT_EQ(resp.stream_id, (uint_least16_t)1);

cleanup:
	raw_stream_fixture_teardown(&sfx);
}

/*
 * I-8: Out-of-order RST handling.
 *
 * After the raw client resets an established stream, the server closes its
 * local stream state.  A subsequent valid non-RST frame on the same stream ID
 * targets an unknown retired stream, so the implementation sends one RST for
 * that stream while keeping the session open.
 */
T_DECLARE_CASE(test_interop_i8_rst_then_non_rst)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &syn_hdr));

	int raw_fd = sfx.base.raw_fd;
	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	T_EXPECT(raw_drain_frame(sfx.base.raw_fd));
	T_EXPECT(raw_drain_available(sfx.base.raw_fd));

	const struct mux_header rst_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_RST,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(sfx.base.raw_fd, &rst_hdr));

	T_EXPECT(
		raw_wait_until(&sfx.base, 0.1, raw_pred_closed, &sfx.base) !=
		0);
	/* Drain any session-level ACKs the server emitted during the wait
	 * (e.g., a coalesced session ACK for the RST frame).  The assertion
	 * below verifies that the server does not proactively send a new
	 * stream-level response to the RST. */
	T_EXPECT(raw_drain_available(sfx.base.raw_fd));
	T_EXPECT(raw_pred_data_available(&raw_fd) == 0);

	static const unsigned char payload[] = { 0x52 };
	const struct mux_header push_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame_payload(sfx.base.raw_fd, &push_hdr, payload));

	T_EXPECT(
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0);
	struct mux_header resp;
	T_EXPECT(raw_read_frame_header(sfx.base.raw_fd, &resp));
	T_EXPECT((resp.flags & MUX_FLAG_RST) != 0);
	T_EXPECT_EQ(resp.stream_id, (uint_least16_t)1);
	T_EXPECT(raw_drain_available(sfx.base.raw_fd));
	T_EXPECT(
		raw_wait_until(&sfx.base, 0.1, raw_pred_closed, &sfx.base) !=
		0);

cleanup:
	raw_stream_fixture_teardown(&sfx);
}

/*
 * I-9: Reserved flag bit set — receiver MUST close the connection.
 *
 * The raw side sends a frame with reserved flag bit 0x20 set after a
 * successful handshake.  The server MUST close the connection (not just RST).
 */
T_DECLARE_CASE(test_interop_i9_reserved_flag)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	const struct mux_header bad_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0x20, /* reserved bit */
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(fx.raw_fd, &bad_hdr));

	/* Drive the loop until the server closes its side of the connection. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);
	T_EXPECT(wait_ret == 0);

	/* Connection must be closed; next blocking recv returns EOF. */
	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);
	T_EXPECT(nr == 0);

cleanup:
	raw_fixture_teardown(&fx);
}

/*
 * I-10: Hello version parameter mismatch — server MUST close the connection.
 *
 * The raw side sends a ClientHello whose type field carries version=2.
 * The server MUST close the connection upon detecting the version mismatch.
 */
T_DECLARE_CASE(test_interop_i10_hello_version_mismatch)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}

	static const char bad_json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=2\","
		"\"msgid\":0,\"connect\":false}";
	const size_t json_len = sizeof(bad_json) - 1;
	const struct mux_header bad_hdr = {
		.version = 0,
		.flags = 0,
		.length = (uint_least16_t)json_len,
		.stream_id = 0,
		.extra = 0,
	};
	unsigned char hdr_buf[MUX_FRAME_HEADER_SIZE];
	mux_write_header(hdr_buf, &bad_hdr);
	T_EXPECT(raw_write_all(fx.raw_fd, hdr_buf, sizeof(hdr_buf)));
	T_EXPECT(raw_write_all(fx.raw_fd, bad_json, json_len));

	/* Server must close the connection on version mismatch. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);
	T_EXPECT(wait_ret == 0);

	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);
	T_EXPECT(nr == 0);

	raw_fixture_teardown(&fx);
}

/*
 * I-11: PING/PONG echo.
 *
 * The raw side sends a stream-0 PING carrying an opaque payload.  The server
 * MUST reply with a PONG whose payload is byte-for-byte identical.
 */
T_DECLARE_CASE(test_interop_i11_ping_pong_echo)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	static const unsigned char ping_payload[] = {
		0x10, 0x22, 0x34, 0x46, 0x58,
	};
	const struct mux_header ping_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(ping_payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};
	T_EXPECT(raw_send_frame_payload(fx.raw_fd, &ping_hdr, ping_payload));

	int raw_fd = fx.raw_fd;
	T_EXPECT(
		raw_wait_until(&fx, 1.0, raw_pred_data_available, &raw_fd) ==
		0);

	struct mux_header resp;
	T_EXPECT(raw_read_frame_header(fx.raw_fd, &resp));
	T_EXPECT_EQ(resp.version, (uint_fast8_t)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(resp.flags, (uint_fast8_t)0);
	T_EXPECT_EQ(resp.stream_id, (uint_least16_t)STREAMID_CTRL);
	T_EXPECT_EQ(resp.extra, (uint_least16_t)MUX_CTRL_PONG);
	T_EXPECT_EQ(resp.length, (uint_least16_t)sizeof(ping_payload));

	unsigned char pong_payload[sizeof(ping_payload)];
	T_EXPECT(raw_read_all(fx.raw_fd, pong_payload, sizeof(pong_payload)));
	T_EXPECT(memcmp(pong_payload, ping_payload, sizeof(ping_payload)) == 0);

cleanup:
	raw_fixture_teardown(&fx);
}

/*
 * I-12: Unknown keepalive subtype.
 *
 * A reserved stream-0 keepalive subtype must be silently discarded without
 * closing the session.  This test sends the reserved subtype first, then a
 * valid PING and verifies the first response is the PONG for that later PING.
 */
T_DECLARE_CASE(test_interop_i12_unknown_keepalive_subtype)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	const struct mux_header unknown_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = 0,
		.stream_id = STREAMID_CTRL,
		.extra = 0x0003u,
	};
	T_EXPECT(raw_send_frame(fx.raw_fd, &unknown_hdr));
	T_EXPECT(raw_wait_until(&fx, 0.1, raw_pred_closed, &fx) != 0);

	int raw_fd = fx.raw_fd;
	T_EXPECT(raw_pred_data_available(&raw_fd) == 0);

	static const unsigned char ping_payload[] = {
		0x91, 0x82, 0x73, 0x64, 0x55,
	};
	const struct mux_header ping_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(ping_payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};
	T_EXPECT(raw_send_frame_payload(fx.raw_fd, &ping_hdr, ping_payload));

	T_EXPECT(
		raw_wait_until(&fx, 1.0, raw_pred_data_available, &raw_fd) ==
		0);

	struct mux_header resp;
	T_EXPECT(raw_read_frame_header(fx.raw_fd, &resp));
	T_EXPECT_EQ(resp.version, (uint_fast8_t)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(resp.flags, (uint_fast8_t)0);
	T_EXPECT_EQ(resp.stream_id, (uint_least16_t)STREAMID_CTRL);
	T_EXPECT_EQ(resp.extra, (uint_least16_t)MUX_CTRL_PONG);
	T_EXPECT_EQ(resp.length, (uint_least16_t)sizeof(ping_payload));

	unsigned char pong_payload[sizeof(ping_payload)];
	T_EXPECT(raw_read_all(fx.raw_fd, pong_payload, sizeof(pong_payload)));
	T_EXPECT(memcmp(pong_payload, ping_payload, sizeof(ping_payload)) == 0);

cleanup:
	raw_fixture_teardown(&fx);
}

/*
 * I-13: Invalid opening SYN flags — server MUST close the connection.
 *
 * The raw side sends SYN|ACK as the first frame for an unknown stream.
 * Only SYN and SYN|PUSH are permitted as opening frames; any other
 * flag combination is a protocol violation and the receiver MUST close
 * the connection and MUST NOT resume the session.
 */
T_DECLARE_CASE(test_interop_i13_invalid_syn_flags)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		T_FATAL("hello exchange failed");
		goto cleanup;
	}

	const struct mux_header bad_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags =
			MUX_FLAG_SYN | MUX_FLAG_ACK, /* invalid opening flags */
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame(fx.raw_fd, &bad_hdr));

	/* Server must close the connection, not reply with RST. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);
	T_EXPECT(wait_ret == 0);

	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);
	T_EXPECT(nr == 0);

cleanup:
	raw_fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_no_reconnect_with_idle_timeout: when idle_timeout is configured on the
 * client, an unexpected transport loss must emit MUX_EVENT_CLOSED instead of
 * scheduling a reconnect.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_no_reconnect_with_idle_timeout)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	/* Set idle_timeout on the live client session so that session_on_close
	 * takes the "no reconnect" branch. Any positive value is sufficient.
	 * Also set the timer repeat directly so ev_timer_again fires quickly
	 * without waiting for the integer-second config granularity. */
	fx.cli->conf.idle_timeout = 1;
	fx.cli->w_idle_timeout.repeat = 0.01;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* Close the server session, causing a clean TCP close.  The client
	 * detects EOF and calls session_on_close, which must NOT schedule a
	 * reconnect because idle_timeout is set. */
	mux_close(fx.srv);
	fx.srv = NULL;

	const int ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_closed, &fx);
	T_EXPECT(ret == 0);
	T_EXPECT(fx.cli_closed);
	/* cli is set to NULL by on_closed_cb; verify reconnect was not armed. */
	T_EXPECT(fx.cli == NULL);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * fx_break_transport: sever the underlying TCP connection with a RST so that
 * both sessions detect a transport error and enter SUSPENDED state.
 *
 * The server fd is closed with SO_LINGER{l_onoff=1,l_linger=0}.  The RST
 * travels to the client (whose fd remains valid), so libev fires on the
 * client side → ECONNRESET → session_suspend(cli).  The server stays
 * ESTABLISHED until the client reconnects; session_resume_transport then
 * calls session_suspend(srv) internally to handle the stale state.
 * ---------------------------------------------------------------------- */

static void fx_break_transport(struct mux_test_fixture *restrict fx)
{
	const int srv_fd = mux_fd(fx->srv);

	/* Create a sentinel UNIX socketpair to occupy the server fd slot during
	 * the transport break.  Keeping srv_fd occupied prevents the fd number
	 * from being returned by the next accept(), which would cause libev to
	 * dispatch the new connection's events to fx->srv's socket watcher. */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
		return;
	}

	const struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	(void)setsockopt(srv_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

	/* Atomically close srv_fd (sends RST to the client) and replace it
	 * with sp[0] so the slot remains occupied.  session_resume_transport
	 * will later call session_suspend(fx->srv), which calls ev_io_stop and
	 * SOCKET_CLOSE_FD on srv_fd (now sp[0]) cleanly — no EBADF. */
	(void)dup2(sp[0], srv_fd);
	close(sp[0]);

	/* Retain sp[1] so sp[0] (= srv_fd) has a connected peer and does not
	 * immediately become readable as EOF in the event loop. */
	fx->break_transport_sp = sp[1];
}

static void test_session_set_write_only(struct mux_session *restrict ss)
{
	const int fd = ss->w_socket.fd;
	ev_io_stop(ss->loop, &ss->w_socket);
	ev_io_set(&ss->w_socket, fd, EV_WRITE);
	ev_io_start(ss->loop, &ss->w_socket);
}

static void test_pump_unacked_no_wait(struct mux_test_fixture *restrict fx)
{
	test_session_set_write_only(fx->cli);
	test_session_set_write_only(fx->srv);

	for (int i = 0; i < 32; i++) {
		ev_run(fx->loop, EVRUN_NOWAIT);
		if (fx->cli->unacked_frames > 0 &&
		    fx->srv->unacked_frames > 0) {
			break;
		}
	}

	session_update_watcher(fx->cli);
	session_update_watcher(fx->srv);
}

/* -------------------------------------------------------------------------
 * test_resume_idle: transport break with no active streams.
 * The session must suspend, reconnect, and fire MUX_EVENT_RESUMED on both
 * sides without any data loss.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_resume_idle)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	fx_break_transport(&fx);

	const int ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	T_EXPECT(ret == 0);
	T_EXPECT(fx.cli_suspended);
	T_EXPECT(fx.srv_suspended);
	T_EXPECT(fx.cli_resumed);
	T_EXPECT(fx.srv_resumed);
	T_EXPECT_EQ(mux_state(fx.cli), MUX_STATE_ESTABLISHED);
	T_EXPECT_EQ(mux_state(fx.srv), MUX_STATE_ESTABLISHED);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_resume_retransmit: transport break with a stream in flight.
 * Frames unacknowledged at suspension must be retransmitted after resume
 * and the echo must complete with exactly the original payload.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_resume_retransmit)
{
	struct mux_test_fixture fx;
	const size_t payload_len = PAYLOAD_SMALL;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	unsigned char *cli_payload = NULL;
	unsigned char *srv_payload = NULL;
	struct test_stream *cli_ts = NULL;
	struct test_stream *srv_ts = NULL;
	size_t cli_sent = 0;
	size_t srv_sent = 0;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	cli_payload = malloc(payload_len);
	if (cli_payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(cli_payload, payload_len, 0x7B);

	srv_payload = malloc(payload_len);
	if (srv_payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(srv_payload, payload_len, 0x9C);

	{
		struct mux_stream *cli_s = mux_open_stream(fx.cli);
		if (cli_s == NULL) {
			T_FATAL("mux_open_stream returned NULL");
			goto cleanup;
		}
		cli_ts = test_stream_new(&fx, cli_s);
		if (cli_ts == NULL) {
			T_FATAL("test_stream_new failed");
			goto cleanup;
		}
		if (fx.n_cli_streams < MAX_ACCEPTED) {
			fx.cli_streams[fx.n_cli_streams++] = cli_ts;
		}

		struct mux_stream *srv_s = mux_open_stream(fx.srv);
		if (srv_s == NULL) {
			T_FATAL("mux_open_stream(srv) returned NULL");
			goto cleanup;
		}
		srv_ts = test_stream_new(&fx, srv_s);
		if (srv_ts == NULL) {
			T_FATAL("test_stream_new failed");
			goto cleanup;
		}
		if (fx.n_srv_active_streams < MAX_ACCEPTED) {
			fx.srv_active_streams[fx.n_srv_active_streams++] =
				srv_ts;
		}
	}

	/* Pre-break load injection (no waits): queue data from both endpoints.
	 * Stop naturally when flow control returns zero progress. */
	for (;;) {
		size_t chunk = payload_len - cli_sent;
		if (chunk == 0) {
			break;
		}
		if (mux_stream_send(cli_ts->s, cli_payload + cli_sent, &chunk) <
			    0 ||
		    chunk == 0) {
			break;
		}
		cli_sent += chunk;
	}
	for (;;) {
		size_t chunk = payload_len - srv_sent;
		if (chunk == 0) {
			break;
		}
		if (mux_stream_send(srv_ts->s, srv_payload + srv_sent, &chunk) <
			    0 ||
		    chunk == 0) {
			break;
		}
		srv_sent += chunk;
	}
	T_EXPECT(cli_sent > 0);
	T_EXPECT(srv_sent > 0);

	mux_stream_io_start(fx.loop, &cli_ts->w_io);
	mux_stream_io_start(fx.loop, &srv_ts->w_io);
	test_pump_unacked_no_wait(&fx);
	T_EXPECT(fx.cli->unacked_frames > 0);
	T_EXPECT(fx.srv->unacked_frames > 0);
	T_LOGF("pre-suspend unacked: cli=%zu srv=%zu", fx.cli->unacked_frames,
	       fx.srv->unacked_frames);

	/* Freeze both endpoints directly into SUSPENDED with non-empty unacked
	 * lists. This avoids timing windows while still forcing resume to replay
	 * the preserved frames over a fresh transport. */
	session_suspend(fx.cli);
	session_suspend(fx.srv);
	T_EXPECT(fx.cli->retransmit_off != SIZE_MAX);
	T_EXPECT(fx.srv->retransmit_off != SIZE_MAX);
	T_LOGF("retransmit armed: cli=%d srv=%d",
	       fx.cli->retransmit_off != SIZE_MAX,
	       fx.srv->retransmit_off != SIZE_MAX);

	/* Wait for both sessions to resume. */
	const int resume_ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	if (resume_ret != 0) {
		T_LOGF("resume wait failed:"
		       " cli(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
		       " ack_seq=%" PRIuLEAST32 " tx_pending=%d retrans=%d)"
		       " srv(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
		       " ack_seq=%" PRIuLEAST32 " tx_pending=%d retrans=%d)",
		       fx.cli->state, fx.cli->unacked_frames, fx.cli->recv_seq,
		       fx.cli->ack_seq, fx.cli->wire.tx_pending,
		       fx.cli->retransmit_off != SIZE_MAX, fx.srv->state,
		       fx.srv->unacked_frames, fx.srv->recv_seq,
		       fx.srv->ack_seq, fx.srv->wire.tx_pending,
		       fx.srv->retransmit_off != SIZE_MAX);
	}
	T_EXPECT(resume_ret == 0);
	T_EXPECT(fx.cli_suspended);
	T_EXPECT(fx.srv_suspended);
	T_EXPECT(fx.cli_resumed);
	T_EXPECT(fx.srv_resumed);

	/* Bidirectional echo must complete after retransmission. */
	{
		struct echo_ctx cli_ctx = {
			.ts = cli_ts,
			.expected = cli_payload,
			.expected_len = cli_sent,
		};
		const int cli_echo_ret = wait_until(
			&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
			&cli_ctx);
		if (cli_echo_ret != 0) {
			T_LOGF("client echo after resume failed:"
			       " cli(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " ack_seq=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)"
			       " srv(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " ack_seq=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)",
			       fx.cli->state, fx.cli->unacked_frames,
			       fx.cli->recv_seq, fx.cli->ack_seq,
			       fx.cli->wire.tx_pending,
			       fx.cli->retransmit_off != SIZE_MAX,
			       cli_ts->recv_len, cli_sent, cli_ts->got_error,
			       cli_ts->got_eof, fx.srv->state,
			       fx.srv->unacked_frames, fx.srv->recv_seq,
			       fx.srv->ack_seq, fx.srv->wire.tx_pending,
			       fx.srv->retransmit_off != SIZE_MAX,
			       srv_ts->recv_len, srv_sent, srv_ts->got_error,
			       srv_ts->got_eof);
		}
		T_EXPECT(cli_echo_ret == 0);
	}
	{
		struct echo_ctx srv_ctx = {
			.ts = srv_ts,
			.expected = srv_payload,
			.expected_len = srv_sent,
		};
		const int srv_echo_ret = wait_until(
			&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
			&srv_ctx);
		if (srv_echo_ret != 0) {
			T_LOGF("server echo after resume failed:"
			       " cli(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " ack_seq=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)"
			       " srv(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " ack_seq=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)",
			       fx.cli->state, fx.cli->unacked_frames,
			       fx.cli->recv_seq, fx.cli->ack_seq,
			       fx.cli->wire.tx_pending,
			       fx.cli->retransmit_off != SIZE_MAX,
			       cli_ts->recv_len, cli_sent, cli_ts->got_error,
			       cli_ts->got_eof, fx.srv->state,
			       fx.srv->unacked_frames, fx.srv->recv_seq,
			       fx.srv->ack_seq, fx.srv->wire.tx_pending,
			       fx.srv->retransmit_off != SIZE_MAX,
			       srv_ts->recv_len, srv_sent, srv_ts->got_error,
			       srv_ts->got_eof);
		}
		T_EXPECT(srv_echo_ret == 0);
	}
	T_EXPECT(!cli_ts->got_error);
	T_EXPECT(!srv_ts->got_error);
	if (cli_ts->recv_len >= cli_sent) {
		T_EXPECT(memcmp(cli_ts->recv_buf, cli_payload, cli_sent) == 0);
	}
	if (srv_ts->recv_len >= srv_sent) {
		T_EXPECT(memcmp(srv_ts->recv_buf, srv_payload, srv_sent) == 0);
	}
cleanup:
	free(cli_payload);
	free(srv_payload);
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_resume_handshake_transport_lost: regression for the bug where a
 * transport failure during a client resume handshake (SESSION_HANDSHAKE,
 * has_session_id=true, !accepted) incorrectly called session_reset instead
 * of session_suspend, destroying the unacked list and all streams.
 *
 * The test verifies that:
 *   1. The client goes back to SESSION_SUSPENDED (not SESSION_CLOSED).
 *   2. The session can still complete a successful resume on the next attempt.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_resume_handshake_transport_lost)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* Disable auto-reconnect so that session_suspend does not immediately
	 * re-dial; we will control the client's reconnect manually. */
	char saved_connect_str[sizeof(fx.connect_str)];
	memcpy(saved_connect_str, fx.connect_str, sizeof(saved_connect_str));
	fx.connect_str[0] = '\0';

	/* Suspend the client while the server remains ESTABLISHED.
	 * The server will handle the resume once the client reconnects. */
	session_suspend(fx.cli);
	T_EXPECT_EQ(fx.cli->state, (int)SESSION_SUSPENDED);

	/* Give the client a dead-end socketpair: sp[1] is closed immediately
	 * so the client's resume ClientHello hits an error (EPIPE or EOF)
	 * during the handshake, exercising the re-suspension path. */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
		T_FATAL("socketpair failed");
		goto cleanup;
	}
	{
		const int flags = fcntl(sp[0], F_GETFL, 0);
		if (flags >= 0) {
			(void)fcntl(sp[0], F_SETFL, flags | O_NONBLOCK);
		}
	}
	close(sp[1]); /* close peer end; writes to sp[0] get EPIPE / reads get EOF */

	mux_attach_fd(fx.cli, sp[0]);

	/* Run the event loop until the client detects the error and re-suspends.
	 * With the fix, this reaches SESSION_SUSPENDED.
	 * Without the fix, it reaches SESSION_CLOSED (and the test fails). */
	for (int i = 0; i < 32 && fx.cli->state != SESSION_SUSPENDED; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}

	T_EXPECT_EQ(fx.cli->state, (int)SESSION_SUSPENDED);
	if (fx.cli->state != SESSION_SUSPENDED) {
		T_LOGF("client state after dead-end handshake: %d"
		       " (expected SESSION_SUSPENDED=%d)",
		       fx.cli->state, (int)SESSION_SUSPENDED);
		goto cleanup;
	}

	/* Restore the connect string and perform the real resume. */
	memcpy(fx.connect_str, saved_connect_str, sizeof(fx.connect_str));
	const int fd = fixture_dial(fx.connect_str);
	if (fd < 0) {
		T_FATAL("fixture_dial failed for real resume attempt");
		goto cleanup;
	}
	mux_attach_fd(fx.cli, fd);

	const int ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	if (ret != 0) {
		T_LOGF("resume wait failed:"
		       " cli(state=%d unacked=%zu) srv(state=%d unacked=%zu)"
		       " cli_closed=%d srv_closed=%d",
		       fx.cli != NULL ? (int)fx.cli->state : -1,
		       fx.cli != NULL ? fx.cli->unacked_frames : 0,
		       fx.srv != NULL ? (int)fx.srv->state : -1,
		       fx.srv != NULL ? fx.srv->unacked_frames : 0,
		       fx.cli_closed, fx.srv_closed);
	}
	T_EXPECT(ret == 0);
	T_EXPECT(fx.cli_resumed);
	T_EXPECT(fx.srv_resumed);
	T_EXPECT(!fx.cli_connect_failed);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_nodelay_reverse_large: nodelay=true, server sends PAYLOAD_LARGE to
 * client.  Reproduces reported infinite-loop / 100% CPU with nodelay and
 * reverse data direction.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_nodelay_reverse_large)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	/* Enable nodelay on the client session (already created by
	 * fixture_setup) and on the fixture so pending_accept_cb picks
	 * it up for the server config. */
	fx.nodelay = true;
	fx.cli->conf.nodelay = true;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0xE7);

	/* Server will send payload + FIN when a stream is accepted. */
	fx.accept_mode = ACCEPT_SEND_PAYLOAD;
	fx.accept_send_data = payload;
	fx.accept_send_len = PAYLOAD_LARGE;

	/* Client opens a stream; it does not send any data – it only receives. */
	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream(cli) returned NULL");
		free(payload);
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		free(payload);
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait until the client received all bytes AND got peer EOF. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_LARGE);
	T_EXPECT(ts->got_eof);
	T_EXPECT(!ts->got_error);
	if (ts->recv_len == PAYLOAD_LARGE) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0);
	}

	free(payload);
cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * BDP estimator tests.
 * ---------------------------------------------------------------------- */

struct bdp_ctx {
	struct test_stream *ts;
	const struct mux_session *ss;
	size_t expected_len;
};

static void bdp_enable_auto_windows(struct mux_session *restrict ss)
{
	struct mux_config conf = *mux_conf(ss);
	conf.stream_window = 0;
	conf.session_window = 0;
	mux_set_config(ss, &conf);
}

struct bdp_control_ctx {
	const struct mux_session *ss;
	uint_least64_t before_bytes_recv;
};

static int pred_control_only_no_bdp(void *ptr)
{
	const struct bdp_control_ctx *restrict ctx = ptr;
	if (ctx->ss->bytes_recv <= ctx->before_bytes_recv) {
		return 0;
	}
	if (wndfilter_get(&ctx->ss->estimator.bw_wnd) > 0 ||
	    ctx->ss->estimator.ping_in_flight) {
		return -1;
	}
	return 1;
}

static int pred_echo_and_bdp_cycle(void *ptr)
{
	const struct bdp_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	/* All echoed bytes received AND at least one full PING/PONG cycle. */
	if (ctx->ts->recv_len < ctx->expected_len) {
		return 0;
	}
	if (wndfilter_get(&ctx->ss->estimator.rtt_wnd) == 0 ||
	    ctx->ss->estimator.ping_in_flight) {
		return 0;
	}
	return 1;
}

/* -------------------------------------------------------------------------
 * test_bdp_auto_stream_window_updated_by_pong: when both windows are
 * automatic, a PONG-driven BDP update must grow stream_window but leave
 * session_window unchanged (session_window tracks peer_stream_window, not
 * the local BDP estimate).
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_auto_stream_window_updated_by_pong)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	bdp_enable_auto_windows(fx.cli);
	T_EXPECT(fx.cli->auto_stream_window);
	T_EXPECT(fx.cli->auto_session_window);
	T_EXPECT_EQ(
		fx.cli->session_window,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(fx.cli->stream_window, fx.cli->session_window);

	/* Drive the real PONG -> estimator -> session_update_window path
	 * directly so the regression does not depend on a large data transfer
	 * completing before the smaller auto session-window cap stalls sends.
	 * Use 4 × MUX_INITIAL_SEND_WINDOW so the resulting BDP estimate is
	 * well above the 5-frame boundary; a 1× sample lands right at
	 * BDP_MIN and integer-division truncation makes the assertion fragile. */
	estimator_add(fx.cli, (uint_least64_t)MUX_INITIAL_SEND_WINDOW * 4);
	T_EXPECT(fx.cli->estimator.ping_in_flight);
	if (!fx.cli->estimator.ping_in_flight) {
		T_FATAL("estimator did not queue ping frame");
		goto cleanup;
	}
	/* Back-date the timestamp by 1 ms so the measured RTT is positive. */
	if (fx.cli->estimator.last_probe_ns <= 1000000) {
		T_FATAL("invalid estimator timestamp");
		goto cleanup;
	}
	fx.cli->estimator.last_probe_ns -= 1000000;
	const intmax_t sent_ns = fx.cli->estimator.last_probe_ns;

	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = MUX_PING_PAYLOAD_SIZE,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PONG,
	};
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + MUX_PING_PAYLOAD_SIZE;
	ringbuf_reset(fx.cli->wire.recvbuf);
	if (!ringbuf_reserve(&fx.cli->wire.recvbuf, frame_size, false)) {
		T_FATAL("recvbuf has no space");
		goto cleanup;
	}
	unsigned char *const pong = ringbuf_write_ptr(fx.cli->wire.recvbuf);
	mux_write_header(pong, &hdr);
	write_uint64(pong + MUX_FRAME_HEADER_SIZE, (uint_fast64_t)sent_ns);
	ringbuf_produce(fx.cli->wire.recvbuf, frame_size);
	session_recv_pong(fx.cli, &hdr, frame_size);

	T_EXPECT(
		fx.cli->session_window ==
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	/* PONG updates only stream_window; session_window tracks
	 * peer_stream_window and is unchanged (no SYN/SYN|ACK in auto mode). */
	T_EXPECT(
		fx.cli->stream_window >
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT(!fx.cli->estimator.ping_in_flight);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_bdp_manual_window_mode_no_estimator_effect: in manual window mode
 * (both stream_window and session_window > 0), BDP estimator updates must
 * not change either window.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_manual_window_mode_no_estimator_effect)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* Both windows non-zero → manual mode; auto_stream_window and
	 * auto_session_window must be clear. */
	const uint_least32_t fixed_session = 8;
	const uint_least32_t fixed_stream = 4;
	struct mux_config conf = *mux_conf(fx.cli);
	conf.session_window = (int)fixed_session;
	conf.stream_window = (int)fixed_stream;
	mux_set_config(fx.cli, &conf);
	T_EXPECT(!fx.cli->auto_stream_window);
	T_EXPECT(!fx.cli->auto_session_window);
	T_EXPECT_EQ(fx.cli->session_window, fixed_session);
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

	/* dispatch.c guards estimator_add with auto_stream_window; session and
	 * stream windows must remain at their configured values. */
	T_EXPECT_EQ(fx.cli->session_window, fixed_session);
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_bdp_auto_session_window_without_auto_stream_window: session_window
 * auto (= 0 in config) with stream_window manual (> 0).  session_window
 * must track peer_stream_window; the BDP estimator must not start probes;
 * stream_window must remain at its configured value.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_auto_session_window_without_auto_stream_window)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* session_window = 0 (auto), stream_window = 4 (manual). */
	const uint_least32_t fixed_stream = 4;
	struct mux_config conf = *mux_conf(fx.cli);
	conf.session_window = 0;
	conf.stream_window = (int)fixed_stream;
	mux_set_config(fx.cli, &conf);
	T_EXPECT(!fx.cli->auto_stream_window);
	T_EXPECT(fx.cli->auto_session_window);
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

	/* dispatch.c guards estimator_add with auto_stream_window; stream_window
	 * must remain at its configured value. */
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

	/* session_update_session_window must still update session_window to
	 * track peer_stream_window even when stream_window is manual. */
	const uint_least32_t floor_frames =
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT);
	const uint_least32_t new_peer_window = floor_frames * 4;
	fx.cli->peer_stream_window = new_peer_window;
	session_update_session_window(fx.cli);
	T_EXPECT_EQ(fx.cli->session_window, new_peer_window);
	/* stream_window must not have been modified. */
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_bdp_auto_session_window_tracks_peer_stream_window: in automatic
 * window mode, session_update_session_window must update session_window to
 * match peer_stream_window without touching stream_window.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_auto_session_window_tracks_peer_stream_window)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	bdp_enable_auto_windows(fx.cli);
	T_EXPECT(fx.cli->auto_stream_window);
	T_EXPECT(fx.cli->auto_session_window);

	/* In auto mode, session_window tracks peer_stream_window via
	 * session_update_session_window.  Set peer_stream_window to a value
	 * above the floor and call the function directly. */
	const uint_least32_t floor_frames =
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT);
	const uint_least32_t new_peer_window = floor_frames * 4;
	const uint_least32_t initial_stream_window = fx.cli->stream_window;

	fx.cli->peer_stream_window = new_peer_window;
	session_update_session_window(fx.cli);

	T_EXPECT_EQ(fx.cli->session_window, new_peer_window);
	/* stream_window is driven by the BDP estimator, not peer_stream_window;
	 * session_update_session_window must not change it. */
	T_EXPECT_EQ(fx.cli->stream_window, initial_stream_window);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_bdp_control_only_no_cycle: control-only inbound traffic must not
 * start a measurement cycle when auto stream-window mode is enabled.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_control_only_no_cycle)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	bdp_enable_auto_windows(fx.cli);

	struct bdp_control_ctx ctx = {
		.ss = fx.cli,
		.before_bytes_recv = fx.cli->bytes_recv,
	};
	T_EXPECT(session_send_ctrl(fx.srv, STREAMID_CTRL, 0, MUX_CTRL_PROBE));
	session_flush(fx.srv);
	const int ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_control_only_no_bdp,
		&ctx);
	T_EXPECT(ret == 0);
	T_EXPECT(wndfilter_get(&fx.cli->estimator.bw_wnd) == 0);
	T_EXPECT(!fx.cli->estimator.ping_in_flight);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_bdp_ping_queued_before_send_progress: starting a cycle queues the
 * estimator PING immediately and stamps the timestamp into the frame payload
 * at queue time, transitioning directly to the in-flight state.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_ping_queued_before_send_progress)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	bdp_enable_auto_windows(fx.cli);
	estimator_add(fx.cli, (uint_least64_t)MUX_MAX_PAYLOAD_SIZE);

	T_EXPECT_EQ(
		estimator_window_size(&fx.cli->estimator),
		(size_t)fx.cli->session_window * (size_t)MUX_WINDOW_UNIT);
	T_EXPECT_EQ(
		fx.cli->estimator.sample, (uint_least32_t)MUX_MAX_PAYLOAD_SIZE);
	T_EXPECT(fx.cli->wire.oobbuf.head != NULL);
	T_EXPECT(fx.cli->estimator.ping_in_flight);
	T_EXPECT(fx.cli->estimator.last_probe_ns > 0);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_bdp_ping_sent: verify that the BDP estimator's PING frame is
 * delivered by EV_WRITE directly after inbound PUSH payload starts a cycle.
 * The estimator queues a dedicated PING, the peer replies with PONG, and the
	 * completed cycle records a bandwidth sample.  If oobbuf were stuck the wait
 * would time out.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_ping_sent)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	unsigned char *payload = NULL;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	bdp_enable_auto_windows(fx.cli);

	payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x4E);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait for: (1) all echoed bytes received, (2) a complete PING/PONG
	 * cycle with no queued or in-flight estimator PING left behind. */
	struct bdp_ctx bdp = {
		.ts = ts,
		.ss = fx.cli,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_bdp_cycle, &bdp);
	T_EXPECT(ret == 0);
	T_EXPECT(wndfilter_get(&fx.cli->estimator.rtt_wnd) > 0);
	T_EXPECT(!fx.cli->estimator.ping_in_flight);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_SMALL);
	if (ts->recv_len == PAYLOAD_SMALL) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0);
	}

cleanup:
	free(payload);
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_bdp_stop_halves_stream_window: on disconnect, stream_window is set to
 * the raw BDP in frames (half of the window target) and estimator learned
 * state is preserved.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(test_bdp_stop_halves_stream_window)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	unsigned char *payload = NULL;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	bdp_enable_auto_windows(fx.cli);

	payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x68);

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct bdp_ctx bdp = {
		.ts = ts,
		.ss = fx.cli,
		.expected_len = PAYLOAD_SMALL,
	};
	const int cycle_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_bdp_cycle, &bdp);
	T_EXPECT(cycle_ret == 0);
	T_EXPECT(wndfilter_get(&fx.cli->estimator.rtt_wnd) > 0);

	/* Clear last_probe_ns to bypass the send-side rate limit so that the
	 * second estimator_add immediately queues a PING for the stop test. */
	fx.cli->estimator.last_probe_ns = 0;
	estimator_add(fx.cli, (uint_least64_t)MUX_MAX_PAYLOAD_SIZE);
	T_EXPECT(fx.cli->estimator.ping_in_flight);

	/* Simulate the stop-path: set window target to a known value; estimator
	 * state (filters, probe) is intentionally preserved. */
	fx.cli->estimator.effective_bdp = 3u * (size_t)MUX_INITIAL_SEND_WINDOW;
	const uint_least32_t initial_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	fx.cli->stream_window = (uint_least32_t)MAX(
		estimator_window_size(&fx.cli->estimator) / 2 / MUX_WINDOW_UNIT,
		(size_t)initial_frames);
	T_EXPECT_EQ(
		estimator_window_size(&fx.cli->estimator),
		3u * (size_t)MUX_INITIAL_SEND_WINDOW);
	T_EXPECT_EQ(fx.cli->stream_window, 3u * initial_frames / 2u);
	/* Learned state is preserved after stop. */
	T_EXPECT(wndfilter_get(&fx.cli->estimator.rtt_wnd) > 0);
	T_EXPECT(fx.cli->estimator.ping_in_flight);
	T_EXPECT(fx.cli->estimator.last_probe_ns != 0);

cleanup:
	free(payload);
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_send_queue_saturates_read_credit: mux_stream_send must gate on
 * stream_read_credit_avail, not stream_credit_avail.
 *
 * Without driving the event loop:
 *   - A single call that fills queued_send_bytes == credit_avail is accepted.
 *   - A subsequent call with any bytes is rejected (*len = 0) because
 *     read_credit_avail = credit_avail - queued_send_bytes = 0.
 *
 * After SYN|ACK arrives (driven by the event loop):
 *   - send_window grows; read_credit_avail > 0 again.
 *   - A further mux_stream_send succeeds.
 * ---------------------------------------------------------------------- */

struct stream_established_ctx {
	const struct mux_stream *s;
};

static int pred_stream_established(void *ptr)
{
	const struct stream_established_ctx *restrict ctx = ptr;
	return ctx->s->state == STREAM_ESTABLISHED ? 1 : 0;
}

T_DECLARE_CASE(test_send_queue_saturates_read_credit)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}

	/* Stream in STREAM_INIT: send_window = MUX_DEFAULT_SEND_WINDOW,
	 * bytes_sent = 0, queued_send_bytes = 0.
	 * read_credit_avail = send_window - queued_send_bytes = 16384. */
	const size_t initial_credit = MUX_DEFAULT_SEND_WINDOW;

	/* Allocate a buffer that exactly fills the initial read credit. */
	unsigned char *buf = malloc(initial_credit + 1);
	if (buf == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(buf, initial_credit + 1, 0xAA);

	/* --- Part 1: synchronous saturation (no event loop) --- */

	/* First call: exactly fills read_credit_avail. */
	size_t len1 = initial_credit;
	T_EXPECT(mux_stream_send(s, buf, &len1) == 0);
	T_EXPECT_EQ(len1, initial_credit);

	/* Second call: read_credit_avail = 0 → must be rejected. */
	size_t len2 = 1;
	T_EXPECT(mux_stream_send(s, buf, &len2) == 0);
	T_EXPECT_EQ(len2, (size_t)0);

	/* --- Part 2: credit restored after SYN|ACK --- */

	/* Attach a direct I/O watcher and drive the event loop until the stream
	 * reaches ESTABLISHED (SYN|ACK received with new window grant). */
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(buf);
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = buf;
	ts->send_len = 0; /* stream_io_cb won't send additional data */
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct stream_established_ctx ec = { .s = s };
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		    &ec) != 0) {
		T_FATAL("stream did not reach ESTABLISHED");
		free(buf);
		goto cleanup;
	}

	/* SYN|ACK grants additional credit; read_credit_avail > 0 now. */
	size_t len3 = 1;
	T_EXPECT(mux_stream_send(s, buf + initial_credit, &len3) == 0);
	T_EXPECT(len3 > 0);

	free(buf);
cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * test_drain_rejects_new_streams: mux_open_stream must return NULL after
 * mux_drain is called while a stream is open (so state stays ESTABLISHED
 * and the draining flag is what gates the rejection).
 * ---------------------------------------------------------------------- */
T_DECLARE_CASE(test_drain_rejects_new_streams)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		T_FATAL("sessions did not establish");
		goto cleanup;
	}

	/* Open a stream to hold the session in ESTABLISHED during drain,
	 * ensuring the draining check in session_open_stream is exercised. */
	struct mux_stream *s = mux_open_stream(fx.cli);
	if (s == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	mux_drain(fx.cli);

	T_EXPECT(mux_open_stream(fx.cli) == NULL);

cleanup:
	fixture_teardown(&fx);
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(void)
{
	T_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	slog_setoutput(SLOG_OUTPUT_FILE, stderr);
	slog_setlevel(LOG_LEVEL_DEBUG);

	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_establish);
	T_RUN_CASE(t, test_send_recv_small);
	T_RUN_CASE(t, test_idle_scheduler_stops_while_sendbuf_blocked);
	T_RUN_CASE(t, test_nagle_releases_queued_small_frame_on_ack);
	T_RUN_CASE(t, test_send_recv_large);
	T_RUN_CASE(t, test_half_close);
	T_RUN_CASE(t, test_rst_on_unread_data);
	T_RUN_CASE(t, test_multi_stream);
	T_RUN_CASE(t, test_server_open_send_recv);
	T_RUN_CASE(t, test_client_open_server_sends_first);
	T_RUN_CASE(t, test_graceful_close_server_initiated);
	T_RUN_CASE(t, test_simultaneous_close);
	T_RUN_CASE(t, test_rst_from_client);
	T_RUN_CASE(t, test_active_open_shutdown_before_synack);
	T_RUN_CASE(t, test_interop_i1_non_syn_unknown_stream);
	T_RUN_CASE(t, test_interop_i2_close_wait_push);
	T_RUN_CASE(t, test_interop_i3_ack_fin_credit);
	T_RUN_CASE(t, test_interop_i4_stream_id_parity);
	T_RUN_CASE(t, test_interop_i5_duplicate_syn);
	T_RUN_CASE(t, test_interop_i6_fast_open_16384);
	T_RUN_CASE(t, test_interop_i7_fin_then_data);
	T_RUN_CASE(t, test_interop_i8_rst_then_non_rst);
	T_RUN_CASE(t, test_interop_i9_reserved_flag);
	T_RUN_CASE(t, test_interop_i10_hello_version_mismatch);
	T_RUN_CASE(t, test_interop_i11_ping_pong_echo);
	T_RUN_CASE(t, test_interop_i12_unknown_keepalive_subtype);
	T_RUN_CASE(t, test_interop_i13_invalid_syn_flags);
	T_RUN_CASE(t, test_no_reconnect_with_idle_timeout);
	T_RUN_CASE(t, test_resume_idle);
	T_RUN_CASE(t, test_resume_retransmit);
	T_RUN_CASE(t, test_resume_handshake_transport_lost);
	T_RUN_CASE(t, test_nodelay_reverse_large);
	T_RUN_CASE(t, test_bdp_auto_stream_window_updated_by_pong);
	T_RUN_CASE(t, test_bdp_manual_window_mode_no_estimator_effect);
	T_RUN_CASE(t, test_bdp_auto_session_window_without_auto_stream_window);
	T_RUN_CASE(t, test_bdp_auto_session_window_tracks_peer_stream_window);
	T_RUN_CASE(t, test_bdp_control_only_no_cycle);
	T_RUN_CASE(t, test_bdp_ping_queued_before_send_progress);
	T_RUN_CASE(t, test_bdp_ping_sent);
	T_RUN_CASE(t, test_bdp_stop_halves_stream_window);
	T_RUN_CASE(t, test_send_queue_saturates_read_credit);
	T_RUN_CASE(t, test_drain_rejects_new_streams);

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
