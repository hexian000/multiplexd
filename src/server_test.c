/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* server_test.c - black-box tests for the server forwarding path; real
 * util/conf/listener/server/tunnel/api_server + mux library linked;
 * all waits are bounded. */

#include "server.h"

#include "conf.h"
#include "listener.h"
#include "mux/mux.h"
#include "mux/session.h"
#if WITH_TLS
#include "shim/tls.h"
#endif
#include "shim/util.h"
#include "tunnel.h"

#include "algo/hashtable.h"
#include "os/socket.h"
#include "sync/task.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
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
#include <time.h>
#include <unistd.h>

/* I/O wait timeouts, generous on purpose: the bound only bites on genuine
 * failure, with headroom for host clock anomalies (e.g. CLOCK_MONOTONIC stalls
 * under WSL2). */
enum {
	IO_WAIT_TIMEOUT_MS = 20000,
	SETUP_WAIT_TIMEOUT_MS = 20000,
	SESSION_WAIT_TIMEOUT_MS = 20000,
	STREAM_WAIT_TIMEOUT_MS = 20000,
	PEER_EOF_WAIT_TIMEOUT_MS = 20000,
	CONNECT_WAIT_TIMEOUT_MS = 20000,
	ECHO_WAIT_TIMEOUT_MS = 20000,
	WORKLOAD_ECHO_WAIT_TIMEOUT_MS = 20000,
	STREAM_CHURN_ROUNDS = 20,
	STREAM_CHURN_CONCURRENCY = 4,
	BUFFER_SIZE = 256,
	PAYLOAD_SMALL = 1024,
	PAYLOAD_MEDIUM = 16384,
	PAYLOAD_LARGE = 262144,
};

enum mock_mode {
	MOCK_ECHO = 0,
	MOCK_ECHO_HALF_CLOSE = 1,
	MOCK_ECHO_HALF_CLOSE_ON_EOF = 2,
};

struct mock_server {
	struct ev_loop *loop;
	int listen_fd;
	int port;
	bool running;
	enum mock_mode mode;
	ev_io w_accept;
	struct mock_conn *conns;
};

struct mock_conn {
	struct mock_server *mock;
	int fd;
	bool peer_eof;
	bool half_close_armed;
	bool write_shutdown;
	char *out_buf;
	size_t out_len;
	size_t out_off;
	ev_io w_io;
	struct mock_conn *next;
};

struct test_fixture {
	struct ev_loop *loop;

	struct server *srv_a;
	struct server *srv_b;
	struct config *conf_a;
	struct config *conf_b;

	int mux_port_a;
	int tcp_port_a;
	int tcp_port_b;

	struct mock_server backend_a;
	struct mock_server backend_b;
};

static const char *g_setup_stage = "init";

struct fd_waiter {
	bool done;
	bool timed_out;
	int revents;
	ev_io w_io;
	ev_timer w_timer;
};

typedef int (*wait_predicate_fn)(void *ctx);

struct condition_waiter {
	bool timed_out;
	ev_timer w_timer;
};

static void drive_loop_once(const struct test_fixture *restrict fx)
{
	ev_run(fx->loop, EVRUN_ONCE);
}

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

static void
condition_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)revents;
	struct condition_waiter *const restrict waiter = w->data;
	waiter->timed_out = true;
}

/* No-op: periodic wakeup so the predicate is re-checked while waiting for
 * worker-thread progress (e.g., stream establishment on a background thread). */
static void wait_poll_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

/* Monotonic clock, in seconds.  Test deadlines must use this, not ev_time()
 * (CLOCK_REALTIME), which can step forward and falsely blow a deadline. */
static ev_tstamp mono_now(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return ev_time();
	}
	return (ev_tstamp)ts.tv_sec + (ev_tstamp)ts.tv_nsec / 1e9;
}

static int wait_until(
	const struct test_fixture *restrict fx, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	struct condition_waiter waiter = {
		.timed_out = false,
	};

	ev_timer_init(
		&waiter.w_timer, condition_waiter_timer_cb, timeout_sec, 0.0);
	waiter.w_timer.data = &waiter;
	ev_timer_start(fx->loop, &waiter.w_timer);

	/* Poll every 10 ms so ev_run(EVRUN_ONCE) does not block until the
	 * timeout when awaiting worker-thread progress (e.g., stream
	 * establishment on a background worker). */
	ev_timer w_poll;
	ev_timer_init(&w_poll, wait_poll_cb, 0.01, 0.01);
	ev_timer_start(fx->loop, &w_poll);

	while (!waiter.timed_out) {
		const int status = predicate(ctx);
		if (status != 0) {
			ev_timer_stop(fx->loop, &waiter.w_timer);
			ev_timer_stop(fx->loop, &w_poll);
			return status > 0 ? 0 : -1;
		}
		ev_run(fx->loop, EVRUN_ONCE);
	}

	ev_timer_stop(fx->loop, &waiter.w_timer);
	ev_timer_stop(fx->loop, &w_poll);
	errno = ETIMEDOUT;
	return -1;
}

static int wait_fd_events(
	const struct test_fixture *restrict fx, const int fd, const int events,
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

static int get_listener_port(const struct listener *restrict listener)
{
	const int fd = listener->w_accept.fd;
	if (fd < 0) {
		return -1;
	}

	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	memset(&sa, 0, sizeof(sa));
	if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
		return -1;
	}
	return (int)ntohs(sa.sin_port);
}

static int write_full(
	struct test_fixture *restrict fx, const int fd, const void *buf,
	const size_t len)
{
	const char *const ptr = buf;
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
					return -1;
				}
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

/* Read exactly msg_len bytes from fd (pumping fx->loop while the socket blocks)
 * and verify they echo back msg. Called directly when the payload was already
 * written, or via send_and_expect_echo after it writes. */
static int expect_echo(
	struct test_fixture *restrict fx, const int fd,
	const char *const restrict msg, const size_t msg_len,
	const double timeout_sec)
{
	char *buf = malloc(msg_len);
	if (buf == NULL) {
		return -1;
	}
	size_t off = 0;
	const ev_tstamp deadline = mono_now() + timeout_sec;

	while (off < msg_len) {
		const ssize_t n = read(fd, buf + off, msg_len - off);
		if (n < 0) {
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				/* Register EV_READ on fx->loop so ev_run wakes when
				 * echo data arrives, driving the mock backend too. */
				const ev_tstamp remaining =
					deadline - mono_now();
				if (remaining <= 0.0 ||
				    (wait_fd_events(fx, fd, EV_READ, remaining) &
				     EV_READ) == 0) {
					(void)fprintf(
						stderr,
						"DBGFAIL: timeout/EAGAIN off=%zu/%zu remaining=%.3f\n",
						off, msg_len, remaining);
					free(buf);
					return -1;
				}
				continue;
			}
			(void)fprintf(
				stderr, "DBGFAIL: read err=%d off=%zu/%zu\n",
				err, off, msg_len);
			free(buf);
			return -1;
		}
		if (n == 0) {
			(void)fprintf(
				stderr, "DBGFAIL: EOF off=%zu/%zu\n", off,
				msg_len);
			free(buf);
			return -1;
		}
		off += (size_t)n;
	}

	const int ret = memcmp(buf, msg, msg_len) == 0 ? 0 : -1;
	if (ret != 0) {
		size_t mm = 0;
		while (mm < msg_len && buf[mm] == msg[mm]) {
			mm++;
		}
		(void)fprintf(
			stderr,
			"DBGFAIL: mismatch at byte %zu/%zu got=0x%02x want=0x%02x\n",
			mm, msg_len, (unsigned char)buf[mm],
			(unsigned char)msg[mm]);
	}
	free(buf);
	return ret;
}

static int send_and_expect_echo(
	struct test_fixture *restrict fx, const int fd,
	const char *const restrict msg, const size_t msg_len,
	const double timeout_sec)
{
	if (write_full(fx, fd, msg, msg_len) != 0) {
		return -1;
	}
	return expect_echo(fx, fd, msg, msg_len, timeout_sec);
}

static int wait_for_peer_eof(
	struct test_fixture *restrict fx, const int fd,
	const double timeout_sec)
{
	const ev_tstamp deadline = mono_now() + timeout_sec;
	for (;;) {
		char buf[BUFFER_SIZE];
		const ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				const ev_tstamp remaining =
					deadline - mono_now();
				if (remaining <= 0.0 ||
				    (wait_fd_events(fx, fd, EV_READ, remaining) &
				     EV_READ) == 0) {
					return -1;
				}
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return 0;
		}
		/* Discard unexpected data; keep reading to find EOF. */
	}
}

static int bind_listen_localhost(void)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		socket_close(fd);
		return -1;
	}

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		socket_close(fd);
		return -1;
	}
	if (listen(fd, 8) != 0) {
		socket_close(fd);
		return -1;
	}
	return fd;
}

static int listener_fd_port(const int fd)
{
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	memset(&sa, 0, sizeof(sa));
	if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
		return -1;
	}
	return (int)ntohs(sa.sin_port);
}

static void mock_conn_free(struct mock_conn *restrict conn)
{
	if (conn == NULL) {
		return;
	}
	if (ev_is_active(&conn->w_io)) {
		ev_io_stop(conn->mock->loop, &conn->w_io);
	}
	if (conn->fd >= 0) {
		socket_close(conn->fd);
		conn->fd = -1;
	}
	free(conn->out_buf);
	free(conn);
}

static void mock_server_drop_conn(struct mock_conn *restrict conn)
{
	struct mock_server *const restrict mock = conn->mock;
	for (struct mock_conn **p = &mock->conns; *p != NULL; p = &(*p)->next) {
		if (*p == conn) {
			*p = conn->next;
			mock_conn_free(conn);
			return;
		}
	}
}

static int mock_conn_queue(
	struct mock_conn *restrict conn, const char *const restrict data,
	const size_t len)
{
	char *const new_buf = realloc(conn->out_buf, conn->out_len + len);
	if (new_buf == NULL) {
		return -1;
	}
	conn->out_buf = new_buf;
	memcpy(conn->out_buf + conn->out_len, data, len);
	conn->out_len += len;
	return 0;
}

static int mock_conn_flush(struct mock_conn *restrict conn)
{
	while (conn->out_off < conn->out_len) {
		const size_t remain = conn->out_len - conn->out_off;
		const ssize_t n =
			send(conn->fd, conn->out_buf + conn->out_off, remain,
			     MSG_NOSIGNAL);
		if (n < 0) {
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				return 0; /* wait for EV_WRITE */
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		conn->out_off += (size_t)n;
	}

	conn->out_len = 0;
	conn->out_off = 0;
	free(conn->out_buf);
	conn->out_buf = NULL;

	if (conn->half_close_armed && !conn->write_shutdown) {
		(void)socket_shutdown(conn->fd, SHUT_WR);
		conn->write_shutdown = true;
	}
	return 0;
}

static void mock_conn_update_events(struct mock_conn *restrict conn)
{
	int events = EV_READ;
	if (conn->out_off < conn->out_len) {
		events |= EV_WRITE;
	}
	modify_io_events(conn->mock->loop, &conn->w_io, events);
}

static void mock_conn_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct mock_conn *restrict conn = w->data;

	if ((revents & EV_READ) != 0) {
		for (;;) {
			char buf[BUFFER_SIZE];
			const ssize_t n = read(conn->fd, buf, sizeof(buf));
			if (n < 0) {
				const int err = errno;
				if (err == EINTR) {
					continue;
				}
				if (err == EAGAIN || err == EWOULDBLOCK ||
				    err == ENOBUFS || err == ENOMEM) {
					break;
				}
				mock_server_drop_conn(conn);
				return;
			}
			if (n == 0) {
				conn->peer_eof = true;
				if (conn->mock->mode ==
				    MOCK_ECHO_HALF_CLOSE_ON_EOF) {
					conn->half_close_armed = true;
				}
				break;
			}
			if (mock_conn_queue(conn, buf, (size_t)n) != 0) {
				mock_server_drop_conn(conn);
				return;
			}
			if (conn->mock->mode == MOCK_ECHO_HALF_CLOSE) {
				conn->half_close_armed = true;
			}
		}
	}

	if ((revents & EV_WRITE) != 0 || conn->out_off < conn->out_len ||
	    (conn->half_close_armed && !conn->write_shutdown)) {
		if (mock_conn_flush(conn) != 0) {
			mock_server_drop_conn(conn);
			return;
		}
	}

	if (conn->peer_eof && conn->out_off == conn->out_len) {
		mock_server_drop_conn(conn);
		return;
	}

	mock_conn_update_events(conn);
	(void)loop;
}

static void
mock_server_accept_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct mock_server *const restrict mock = w->data;

	while (mock->running) {
		const int fd = accept(mock->listen_fd, NULL, NULL);
		if (fd < 0) {
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				break;
			}
			return;
		}
		if (socket_set_nonblock(fd) != 0) {
			socket_close(fd);
			continue;
		}

		struct mock_conn *const conn = calloc(1, sizeof(*conn));
		if (conn == NULL) {
			socket_close(fd);
			continue;
		}
		conn->mock = mock;
		conn->fd = fd;
		conn->next = mock->conns;
		mock->conns = conn;
		ev_io_init(&conn->w_io, mock_conn_io_cb, fd, EV_READ);
		conn->w_io.data = conn;
		ev_io_start(loop, &conn->w_io);
	}
}

static int mock_server_start(
	struct mock_server *restrict mock, struct ev_loop *restrict loop,
	const enum mock_mode mode)
{
	*mock = (struct mock_server){
		.loop = loop,
		.listen_fd = -1,
		.port = -1,
		.running = false,
		.mode = mode,
		.conns = NULL,
	};

	mock->listen_fd = bind_listen_localhost();
	if (mock->listen_fd < 0) {
		return -1;
	}
	mock->port = listener_fd_port(mock->listen_fd);
	if (mock->port <= 0) {
		socket_close(mock->listen_fd);
		mock->listen_fd = -1;
		return -1;
	}

	if (socket_set_nonblock(mock->listen_fd) != 0) {
		socket_close(mock->listen_fd);
		mock->listen_fd = -1;
		return -1;
	}

	ev_io_init(
		&mock->w_accept, mock_server_accept_cb, mock->listen_fd,
		EV_READ);
	mock->w_accept.data = mock;
	ev_io_start(loop, &mock->w_accept);
	mock->running = true;
	return 0;
}

/* Gate on `running`, not a listen_fd sentinel: every construction site would
 * otherwise need to remember to initialize listen_fd/port to -1 for an
 * unstarted mock to be recognized as such (a zero-initialized-by-omission
 * struct has listen_fd == 0, a value mock_server_accept_cb's own fd could
 * never legitimately reuse, but that mock_server_stop can't tell apart from
 * a real listener without this). `running` defaults to false on any
 * zero/partially-initialized struct, so no sentinel is needed at all. */
static void mock_server_stop(struct mock_server *restrict mock)
{
	if (mock == NULL) {
		return;
	}
	if (ev_is_active(&mock->w_accept)) {
		ev_io_stop(mock->loop, &mock->w_accept);
	}
	if (mock->running) {
		(void)socket_shutdown(mock->listen_fd, SHUT_RDWR);
		socket_close(mock->listen_fd);
		mock->listen_fd = -1;
	}
	mock->running = false;
	while (mock->conns != NULL) {
		struct mock_conn *conn = mock->conns;
		mock->conns = conn->next;
		mock_conn_free(conn);
	}
}

static struct config *make_config(
	const char *const restrict mux_listen,
	const char *const restrict mux_connect,
	const char *const restrict listen,
	const char *const restrict connect_to)
{
	struct config *const conf = malloc(sizeof(*conf));
	if (conf == NULL) {
		return NULL;
	}

	*conf = (struct config){
		.type = strdup("application/x-multiplexd-config; version=2"),
		.api_listen = NULL,
		.mux_listen = mux_listen ? strdup(mux_listen) : NULL,
		.mux_connect = mux_connect ? strdup(mux_connect) : NULL,
		.listen = listen ? strdup(listen) : NULL,
		.connect = connect_to ? strdup(connect_to) : NULL,
		.mux =
			{
				.timeout = 30,
				.keepalive = 1,
				.send_timeout = 1,
				.connect_timeout = 1,
				.idle_timeout = 0,
				.max_streams = 32,
				.stream_window = 2,
				.session_window = 256,
				.max_frame_payload = mux_session_config_default.max_frame_payload,
			},
		.mux_tcp =
			{
				.tcp_keepalive = true,
				.tcp_nodelay = true,
				.tcp_reuseport = false,
				.tcp_sndbuf = 0,
				.tcp_rcvbuf = 0,
				.backlog = 16,
			},
		.tcp =
			{
				.tcp_keepalive = true,
				.tcp_nodelay = true,
				.tcp_reuseport = false,
				.tcp_sndbuf = 0,
				.tcp_rcvbuf = 0,
				.backlog = 16,
			},
		.loglevel = LOG_LEVEL_WARNING,
		.max_sessions = 0,
		.startup_limit_start = 10,
		.startup_limit_rate = 30,
		.startup_limit_full = 100,
	};

	if (conf->type == NULL || (mux_listen && conf->mux_listen == NULL) ||
	    (mux_connect && conf->mux_connect == NULL) ||
	    (listen && conf->listen == NULL) ||
	    (connect_to && conf->connect == NULL)) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

struct listener_port_wait_ctx {
	const struct listener *listener;
	int *out_port;
};

/* Shared by streams_ready_wait_predicate (>= expected) and
 * streams_exact_wait_predicate (== expected). */
struct streams_wait_ctx {
	struct test_fixture *fx;
	size_t expected;
};

struct wait_stats {
	size_t num_streams;
	size_t num_halfopen_streams;
	size_t num_established_sessions;
	size_t num_halfopen_sessions;
};

static struct wait_stats wait_stats_snapshot(const struct server *restrict s)
{
	struct wait_stats st = { 0 };
#if WITH_THREADS
	const uint_least64_t session_connect = atomic_load_explicit(
		&s->counters.num_session_connect, memory_order_relaxed);
	const uint_least64_t session_connected = atomic_load_explicit(
		&s->counters.num_session_connected, memory_order_relaxed);
	const uint_least64_t session_disconnected = atomic_load_explicit(
		&s->counters.num_session_disconnected, memory_order_relaxed);
#else /* WITH_THREADS */
	const uint_least64_t session_connect = s->counters.num_session_connect;
	const uint_least64_t session_connected =
		s->counters.num_session_connected;
	const uint_least64_t session_disconnected =
		s->counters.num_session_disconnected;
#endif /* WITH_THREADS */
	st.num_established_sessions =
		(size_t)(session_connected - session_disconnected);
	st.num_halfopen_sessions =
		(size_t)(session_connect - session_connected);
	struct server_stats *const restrict snap = server_stats(s, true);
	if (snap != NULL) {
		st.num_streams = (size_t)((snap->num_stream_opened +
					   snap->num_stream_accepted) -
					  (snap->num_stream_succeeded +
					   snap->num_stream_failed));
		st.num_halfopen_streams =
			(size_t)((snap->num_stream_opened +
				  snap->num_stream_accepted) -
				 snap->num_stream_established);
		free(snap);
	}
	return st;
}

static void log_stream_wait_stats(
	struct test_fixture *restrict fx, const char *restrict wait_name,
	const size_t expected)
{
	const struct wait_stats sa = wait_stats_snapshot(fx->srv_a);
	const struct wait_stats sb = wait_stats_snapshot(fx->srv_b);
	(void)fprintf(
		stderr,
		"    %s:%d %s timed out: expected=%zu"
		" srv_a(streams=%zu halfopen_streams=%zu established_sessions=%zu"
		" halfopen_sessions=%zu)"
		" srv_b(streams=%zu halfopen_streams=%zu established_sessions=%zu"
		" halfopen_sessions=%zu)\n",
		__FILE__, __LINE__, wait_name, expected, sa.num_streams,
		sa.num_halfopen_streams, sa.num_established_sessions,
		sa.num_halfopen_sessions, sb.num_streams,
		sb.num_halfopen_streams, sb.num_established_sessions,
		sb.num_halfopen_sessions);
}

static int streams_ready_wait_predicate(void *ptr)
{
	struct streams_wait_ctx *const restrict ctx = ptr;
	const struct wait_stats sa = wait_stats_snapshot(ctx->fx->srv_a);
	const struct wait_stats sb = wait_stats_snapshot(ctx->fx->srv_b);
	if (sa.num_streams >= ctx->expected &&
	    sb.num_streams >= ctx->expected && sa.num_halfopen_streams == 0 &&
	    sb.num_halfopen_streams == 0) {
		return 1;
	}
	return 0;
}

static int sessions_ready_wait_predicate(void *ptr)
{
	struct test_fixture *const restrict ctx = ptr;
	const struct wait_stats sa = wait_stats_snapshot(ctx->srv_a);
	const struct wait_stats sb = wait_stats_snapshot(ctx->srv_b);
	if (sa.num_established_sessions >= 1 &&
	    sb.num_established_sessions >= 1 && sa.num_halfopen_sessions == 0 &&
	    sb.num_halfopen_sessions == 0) {
		return 1;
	}
	return 0;
}

static int streams_exact_wait_predicate(void *ptr)
{
	struct streams_wait_ctx *const restrict ctx = ptr;
	const struct wait_stats sa = wait_stats_snapshot(ctx->fx->srv_a);
	const struct wait_stats sb = wait_stats_snapshot(ctx->fx->srv_b);
	if (sa.num_streams == ctx->expected &&
	    sb.num_streams == ctx->expected && sa.num_halfopen_streams == 0 &&
	    sb.num_halfopen_streams == 0) {
		return 1;
	}
	return 0;
}

static int listener_port_wait_predicate(void *ptr)
{
	struct listener_port_wait_ctx *const restrict ctx = ptr;
	const int port = get_listener_port(ctx->listener);
	if (port <= 0) {
		return 0;
	}
	*ctx->out_port = port;
	return 1;
}

static int wait_for_listener_port(
	struct test_fixture *restrict fx,
	const struct listener *restrict listener, int *restrict out_port,
	const double timeout_sec)
{
	struct listener_port_wait_ctx ctx = {
		.listener = listener,
		.out_port = out_port,
	};
	return wait_until(fx, timeout_sec, listener_port_wait_predicate, &ctx);
}

static int
wait_for_streams_ready(struct test_fixture *restrict fx, const size_t expected)
{
	struct streams_wait_ctx ctx = {
		.fx = fx,
		.expected = expected,
	};
	const int ret = wait_until(
		fx, (double)STREAM_WAIT_TIMEOUT_MS / 1000.0,
		streams_ready_wait_predicate, &ctx);
	if (ret != 0) {
		log_stream_wait_stats(fx, "wait_for_streams_ready", expected);
	}
	return ret;
}

static int wait_for_sessions_ready(struct test_fixture *restrict fx)
{
	return wait_until(
		fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		sessions_ready_wait_predicate, fx);
}

static int connect_local(struct test_fixture *restrict fx, const int port)
{
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons((unsigned)port & 0xFFFFu);

	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	if (socket_set_nonblock(fd) != 0) {
		(void)close(fd);
		return -1;
	}

	if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) == 0) {
		return fd;
	}
	if (errno == EINPROGRESS) {
		const int revents = wait_fd_events(
			fx, fd, EV_WRITE, (double)IO_WAIT_TIMEOUT_MS / 1000.0);
		if ((revents & EV_WRITE) != 0 && socket_get_error(fd) == 0) {
			return fd;
		}
	}
	(void)close(fd);
	return -1;
}

static int
wait_for_streams_exact(struct test_fixture *restrict fx, const size_t expected)
{
	struct streams_wait_ctx ctx = {
		.fx = fx,
		.expected = expected,
	};
	const int ret = wait_until(
		fx, (double)STREAM_WAIT_TIMEOUT_MS / 1000.0,
		streams_exact_wait_predicate, &ctx);
	if (ret != 0) {
		log_stream_wait_stats(fx, "wait_for_streams_exact", expected);
	}
	return ret;
}

static int
fixture_setup(struct test_fixture *restrict fx, const enum mock_mode mode)
{
	g_setup_stage = "fixture_init";
	*fx = (struct test_fixture){
		.loop = NULL,
		.srv_a = NULL,
		.srv_b = NULL,
		.conf_a = NULL,
		.conf_b = NULL,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};
	g_setup_stage = "ev_loop_new";
	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}

	g_setup_stage = "mock_server_a_start";
	if (mock_server_start(&fx->backend_a, fx->loop, mode) != 0) {
		return -1;
	}
	g_setup_stage = "mock_server_b_start";
	if (mock_server_start(&fx->backend_b, fx->loop, mode) != 0) {
		return -1;
	}

	char connect_a[64];
	(void)snprintf(
		connect_a, sizeof(connect_a), "127.0.0.1:%d",
		fx->backend_a.port);
	g_setup_stage = "conf_a_create";
	fx->conf_a = make_config("127.0.0.1:0", NULL, "127.0.0.1:0", connect_a);
	if (fx->conf_a == NULL) {
		return -1;
	}
	g_setup_stage = "server_a_create";
	fx->srv_a = server_new(fx->loop, fx->conf_a);
	if (fx->srv_a == NULL) {
		return -1;
	}
	g_setup_stage = "server_a_start";
	if (!server_start(fx->srv_a)) {
		return -1;
	}
	g_setup_stage = "server_a_mux_port";
	if (wait_for_listener_port(
		    fx, &fx->srv_a->mux_listener, &fx->mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		return -1;
	}

	char connect_b[64];
	char mux_connect_b[64];
	(void)snprintf(
		connect_b, sizeof(connect_b), "127.0.0.1:%d",
		fx->backend_b.port);
	(void)snprintf(
		mux_connect_b, sizeof(mux_connect_b), "127.0.0.1:%d",
		fx->mux_port_a);
	g_setup_stage = "conf_b_create";
	fx->conf_b = make_config(NULL, mux_connect_b, "127.0.0.1:0", connect_b);
	if (fx->conf_b == NULL) {
		return -1;
	}
	g_setup_stage = "server_b_create";
	fx->srv_b = server_new(fx->loop, fx->conf_b);
	if (fx->srv_b == NULL) {
		return -1;
	}
	g_setup_stage = "server_b_start";
	if (!server_start(fx->srv_b)) {
		return -1;
	}

	g_setup_stage = "server_a_tcp_port";
	if (wait_for_listener_port(
		    fx, &fx->srv_a->local_listener, &fx->tcp_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		return -1;
	}
	g_setup_stage = "server_b_tcp_port";
	if (wait_for_listener_port(
		    fx, &fx->srv_b->local_listener, &fx->tcp_port_b,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		return -1;
	}
	g_setup_stage = "sessions_ready";
	if (wait_for_sessions_ready(fx) != 0) {
		return -1;
	}
	g_setup_stage = "ok";
	return 0;
}

static int connect_and_wait_echo(
	struct test_fixture *restrict fx, const int port,
	const char *const restrict msg, int *restrict out_fd)
{
	const size_t msg_len = strlen(msg);
	struct condition_waiter waiter = {
		.timed_out = false,
	};
	ev_timer_init(
		&waiter.w_timer, condition_waiter_timer_cb,
		(double)CONNECT_WAIT_TIMEOUT_MS / 1000.0, 0.0);
	waiter.w_timer.data = &waiter;
	ev_timer_start(fx->loop, &waiter.w_timer);

	while (!waiter.timed_out) {
		const int fd = connect_local(fx, port);
		if (fd < 0) {
			drive_loop_once(fx);
			continue;
		}
		if (send_and_expect_echo(
			    fx, fd, msg, msg_len,
			    (double)ECHO_WAIT_TIMEOUT_MS / 1000.0) == 0) {
			ev_timer_stop(fx->loop, &waiter.w_timer);
			*out_fd = fd;
			return 0;
		}
		(void)close(fd);
		drive_loop_once(fx);
	}

	ev_timer_stop(fx->loop, &waiter.w_timer);
	errno = ETIMEDOUT;
	return -1;
}

static void
fill_payload(char *restrict buf, const size_t len, const uint_fast8_t seed)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (char)('a' + ((seed + i) % 26u));
	}
}

static void fixture_teardown(struct test_fixture *restrict fx)
{
	if (fx == NULL) {
		return;
	}

	if (fx->srv_b != NULL) {
		server_stop(fx->srv_b);
		server_free(fx->srv_b);
		fx->srv_b = NULL;
	}
	if (fx->srv_a != NULL) {
		server_stop(fx->srv_a);
		server_free(fx->srv_a);
		fx->srv_a = NULL;
	}
	if (fx->conf_b != NULL) {
		conf_free(fx->conf_b);
		fx->conf_b = NULL;
	}
	if (fx->conf_a != NULL) {
		conf_free(fx->conf_a);
		fx->conf_a = NULL;
	}

	mock_server_stop(&fx->backend_b);
	mock_server_stop(&fx->backend_a);

	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* Keep a teardown-then-fail pair atomic: every T_FATAL after the fixture has
 * live resources must tear it down first, or the loop/servers/mocks leak. */
#define FIXTURE_FATAL(fx_, msg_)                                               \
	do {                                                                   \
		fixture_teardown(fx_);                                         \
		T_FATAL(msg_);                                                 \
	} while (0)

/* Minimal established-tunnel builder for the identity-listener offline check
 * below (server_offline_listeners reads only tunnel_state via
 * listener_has_live_tunnel). Mirrors api_server_test's helper. */
static bool ol_verify_peer(void *user, const char *peer_id)
{
	(void)user;
	(void)peer_id;
	return false;
}
static uint_least64_t ol_alloc_index(void *user)
{
	return ++((struct server *)user)->next_tunnel_index;
}
#if WITH_THREADS
static bool ol_post_task(void *user, struct task task)
{
	(void)user;
	(void)task;
	return false;
}
static void ol_flush_tasks(void *user)
{
	(void)user;
}
#endif /* WITH_THREADS */

static struct tunnel *
ol_make_established_tunnel(struct server *restrict srv, const char *peer_id)
{
	static const struct tunnel_callbacks cb = { 0 };
	static const unsigned char session_id[MUX_SESSION_ID_LEN] = { 0 };
	const struct mux_session_config mux_cfg = conf_get_mux(srv->conf);
	const struct tunnel_session_counters cnts = {
		.num_session_created = &srv->counters.num_session_created,
		.num_session_connect = &srv->counters.num_session_connect,
		.num_session_connected = &srv->counters.num_session_connected,
		.num_session_disconnected =
			&srv->counters.num_session_disconnected,
		.num_session_finalized = &srv->counters.num_session_finalized,
		.num_sessions = &srv->counters.num_sessions,
		.num_session_halfopen = &srv->counters.num_session_halfopen,
	};
	const struct tunnel_context ctx = {
#if WITH_THREADS
		.post_task = ol_post_task,
		.flush_tasks = ol_flush_tasks,
#endif
		.verify_peer = ol_verify_peer,
		.alloc_index = ol_alloc_index,
		.user = srv,
#if !WITH_THREADS
		.loop = srv->loop,
#endif
	};
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
	ss->state = SESSION_ESTABLISHED;
	PUB_STORE(ss->_pub_state, SESSION_ESTABLISHED);
	return t;
}

/* Records identities reported offline by server_offline_listeners. */
struct offline_capture {
	size_t count;
	char names[4][64];
};
static void offline_capture_cb(void *data, const char *identifier)
{
	struct offline_capture *const c = data;
	if (c->count < 4) {
		(void)snprintf(
			c->names[c->count], sizeof(c->names[0]), "%s",
			identifier != NULL ? identifier : "(null)");
	}
	c->count++;
}

/* server_offline_listeners' identity-listener branch (idle_timeout == 0 &&
 * identities != NULL): an identity pool with a live tunnel is not reported
 * offline, while one with no live tunnel is -- exercising both sides of
 * listener_has_live_tunnel, which the conf->listen-only test below never does. */
T_DECLARE_CASE(test_server_offline_listeners_identity_branch)
{
	struct config conf = {
		.listen = NULL,
		.mux = {
			.idle_timeout = 0, /* selects the identity-listener branch */
			.timeout = 600,
			.keepalive = 25,
			.send_timeout = 15,
			.connect_timeout = 15,
			.stream_window = 2,
			.session_window = 128,
			.max_streams = 32,
			.max_halfopen = 16,
			.nodelay = true,
		},
	};
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	struct server srv = { .conf = &conf, .loop = loop };
	srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(srv.identities != NULL);

	struct tunnel *const live =
		ol_make_established_tunnel(&srv, "peer-live");
	T_CHECK(live != NULL);
	struct tunnel *live_arr[1] = { live };
	struct identity_listener sl_live = {
		.peer_identity = "peer-live",
		.tunnels = live_arr,
		.num_tunnels = 1,
	};
	struct identity_listener sl_off = {
		.peer_identity = "peer-off",
		.tunnels = NULL,
		.num_tunnels = 0,
	};
	{
		void *slot = &sl_live;
		srv.identities =
			table_set(srv.identities, sl_live.peer_identity, &slot);
		T_CHECK(slot == NULL);
	}
	{
		void *slot = &sl_off;
		srv.identities =
			table_set(srv.identities, sl_off.peer_identity, &slot);
		T_CHECK(slot == NULL);
	}

	struct offline_capture cap = { 0 };
	const size_t offline =
		server_offline_listeners(&srv, offline_capture_cb, &cap);

	/* Teardown before asserting so a failing T_EXPECT can't skip it; offline
	 * and cap are stack-resident and independent of the freed resources. */
	tunnel_close(live);
	table_free(srv.identities);
	ev_loop_destroy(loop);

	T_EXPECT_EQ(offline, (size_t)1);
	T_EXPECT_EQ(cap.count, (size_t)1);
	T_EXPECT_STREQ(cap.names[0], "peer-off");
}

/* The idle_timeout exemption for conf->listen must only apply when it is
 * actually backed by an on-demand mux_tunnel (mux_connect != NULL) -- not
 * unconditionally, which would also silence a genuinely dead
 * accepted-tunnel-only listener (mux_listen server mode) on a mixed
 * deployment where idle_timeout is set for unrelated identity.mux_connect
 * peers. No real tunnels are needed: with mux_tunnel/accepted_tunnels/
 * identities all NULL, conf->listen has nothing live either way, so the
 * result depends entirely on which branch of the exemption fires. */
T_DECLARE_CASE(test_server_offline_listeners_idle_timeout_scoped_to_mux_connect)
{
	struct config conf = {
		.listen = "127.0.0.1:0",
		.mux_connect = NULL,
		.mux = { .idle_timeout = 60 },
	};
	struct server srv = {
		.conf = &conf,
		.mux_tunnel = NULL,
		.accepted_tunnels = NULL,
		.identities = NULL,
	};

	/* mux_connect unset: conf->listen is accepted-tunnel-only: a dead
	 * listener here is a real problem idle_timeout must not silence. */
	T_EXPECT_EQ(server_offline_listeners(&srv, NULL, NULL), (size_t)1);

	/* mux_connect set: conf->listen may legitimately be backed by an
	 * on-demand tunnel that has intentionally disconnected while idle. */
	conf.mux_connect = "127.0.0.1:1";
	T_EXPECT_EQ(server_offline_listeners(&srv, NULL, NULL), (size_t)0);

	/* idle_timeout == 0: exemption never applies regardless of
	 * mux_connect, matching the pre-existing (unchanged) behavior. */
	conf.mux.idle_timeout = 0;
	T_EXPECT_EQ(server_offline_listeners(&srv, NULL, NULL), (size_t)1);
}

T_DECLARE_CASE(test_bidirectional_stream_and_forward)
{
	struct test_fixture fx;
	int cl_a = -1;
	int cl_b = -1;

	T_LOG("forward: fixture_setup begin");
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}
	T_LOGF("forward: fixture_setup ok mux=%d tcp_a=%d tcp_b=%d",
	       fx.mux_port_a, fx.tcp_port_a, fx.tcp_port_b);

	cl_b = -1;
	T_LOG("forward: connect_and_wait_echo tcp_b begin");
	if (connect_and_wait_echo(&fx, fx.tcp_port_b, "b-to-a-data", &cl_b) !=
	    0) {
		T_LOG("connect_and_wait_echo tcp_port_b failed");
		T_FAIL();
		goto cleanup;
	}
	T_LOG("forward: tcp_b echo ok");

	cl_a = -1;
	T_LOG("forward: connect_and_wait_echo tcp_a begin");
	if (connect_and_wait_echo(&fx, fx.tcp_port_a, "a-to-b-data", &cl_a) !=
	    0) {
		T_LOG("connect_and_wait_echo tcp_port_a failed");
		T_FAIL();
		goto cleanup;
	}
	T_LOG("forward: tcp_a echo ok");

	if (wait_for_streams_ready(&fx, 1) != 0) {
		T_LOG("wait_for_streams_ready failed");
		T_FAIL();
		goto cleanup;
	}
	T_LOG("forward: stream_ready ok");

cleanup:
	if (cl_b >= 0) {
		(void)close(cl_b);
	}
	if (cl_a >= 0) {
		(void)close(cl_a);
	}
	T_LOG("forward: teardown begin");
	fixture_teardown(&fx);
	T_LOG("forward: teardown done");
}

/* Regression: server_stop()'s force-close sweep must fold a still-open tunnel's
 * monotonic counters into server_counters.closed before tunnel_close() frees it,
 * so a force-closed session's traffic and stream history survive in the /stats
 * and /metrics totals instead of being silently dropped. Drive traffic over the
 * client mux link (srv_b dials srv_a, so its mux_tunnel carries the wire bytes),
 * snapshot the live totals, force-close srv_b, then confirm the post-stop
 * snapshot still accounts for them -- they now live in srv->counters, not in any
 * live tunnel. Without the fold the totals would read back as zero. The buffer
 * gauges must go the other way and reach zero, since the closing session drains
 * them and they are deliberately excluded from the fold. */
T_DECLARE_CASE(test_server_force_close_folds_tunnel_counters)
{
	struct test_fixture fx;
	int cl = -1;

	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	if (connect_and_wait_echo(&fx, fx.tcp_port_b, "fold-traffic", &cl) !=
	    0) {
		FIXTURE_FATAL(&fx, "connect_and_wait_echo failed");
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		(void)close(cl);
		FIXTURE_FATAL(&fx, "wait_for_streams_ready failed");
	}

	struct server_stats *const before = server_stats(fx.srv_b, true);
	if (before == NULL) {
		(void)close(cl);
		FIXTURE_FATAL(&fx, "server_stats(before, true) OOM");
	}
	const uint_least64_t live_mux_recv = before->traffic_byt_mux_recv;
	const uint_least64_t live_mux_sent = before->traffic_byt_mux_sent;
	const uint_least64_t live_stream_opened = before->num_stream_opened;
	/* Streams still open at force-close, and the outcomes recorded so far:
	 * tearing the session down must give every one of them an outcome. */
	const size_t live_streams = before->num_streams;
	const uint_least64_t live_outcomes =
		before->num_stream_succeeded + before->num_stream_failed;
	const size_t live_buffered = before->send_buffered_frames +
				     before->recv_buffered_bytes +
				     before->unacked_frames;
	free(before);

	/* Force-close srv_b; its mux_tunnel is swept and its bytes folded. */
	server_stop(fx.srv_b);
	struct server_stats *const after = server_stats(fx.srv_b, true);
	if (after == NULL) {
		(void)close(cl);
		FIXTURE_FATAL(&fx, "server_stats(after, true) OOM");
	}
	const uint_least64_t folded_mux_recv = after->traffic_byt_mux_recv;
	const uint_least64_t folded_mux_sent = after->traffic_byt_mux_sent;
	const uint_least64_t folded_stream_opened = after->num_stream_opened;
	const uint_least64_t folded_outcomes =
		after->num_stream_succeeded + after->num_stream_failed;
	const size_t folded_buffered = after->send_buffered_frames +
				       after->recv_buffered_bytes +
				       after->unacked_frames;
	free(after);

	/* srv_b is already stopped; free it here and let teardown skip it. */
	server_free(fx.srv_b);
	fx.srv_b = NULL;
	(void)close(cl);
	fixture_teardown(&fx);

	/* Live totals were nonzero, and the fold preserved them (the sweep may
	 * add a few close-handshake bytes, hence >=); without the fold the
	 * post-stop totals would collapse to zero. */
	T_EXPECT(live_mux_recv > 0);
	T_EXPECT(live_mux_sent > 0);
	T_EXPECT(folded_mux_recv >= live_mux_recv);
	T_EXPECT(folded_mux_sent >= live_mux_sent);
	/* Stream lifecycle counters are folded too, not just traffic bytes. */
	T_EXPECT(live_stream_opened > 0);
	T_EXPECT(folded_stream_opened >= live_stream_opened);
	/* The sweep tore down a session with live_streams still open, and the
	 * fold happens after the tunnel thread is joined, so mux_close()'s own
	 * per-stream outcome counting is included: every stream that was open
	 * must now be accounted for as succeeded or failed. Folding a snapshot
	 * taken before the close instead drops all of them. */
	T_EXPECT(live_streams > 0);
	T_EXPECT(folded_outcomes >= live_outcomes + live_streams);
	/* Gauges are deliberately not folded -- server_counters.closed has no
	 * gauge fields at all -- so a closing session cannot leave the totals
	 * permanently overstated the way a folded gauge would. */
	T_EXPECT(live_buffered >= folded_buffered);
}

/* Regression: the live tunnel count is unbounded (max_sessions defaults to
 * unlimited and accepts values above any fixed cap), so server_snapshot_cap()
 * must size the force-close snapshot from the real count rather than assert an
 * arbitrary 65536 ceiling. Grow identity_tunnels[] with NULL slots so the cap
 * exceeds that bound (tunnel_iter_next skips NULL slots, so the snapshot still
 * yields only the real tunnels); pre-fix, server_stop()'s snapshot aborted the
 * debug build here. */
T_DECLARE_CASE(test_server_snapshot_cap_allows_many_tunnels)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	/* Push num_identity_tunnels past the old assertion's 65536 bound with
	 * NULL slots; server_stop() frees this array, taking ownership. */
	const size_t pad = 65537;
	const size_t old_n = fx.srv_b->num_identity_tunnels;
	const size_t new_n = old_n + pad;
	struct tunnel **const grown = (struct tunnel **)realloc(
		(void *)fx.srv_b->identity_tunnels,
		new_n * sizeof(struct tunnel *));
	if (grown == NULL) {
		FIXTURE_FATAL(&fx, "realloc identity_tunnels failed");
	}
	for (size_t i = old_n; i < new_n; i++) {
		grown[i] = NULL;
	}
	fx.srv_b->identity_tunnels = grown;
	fx.srv_b->num_identity_tunnels = new_n;

	/* Pre-fix this aborts inside server_snapshot_cap (ASSERT n <= 65536);
	 * with the fix the snapshot is sized from the real count and returns. */
	server_stop(fx.srv_b);
	server_free(fx.srv_b);
	fx.srv_b = NULL;

	fixture_teardown(&fx);
	/* Reaching here (no abort) with a cap past the old bound is the check. */
	T_EXPECT(new_n > 65536);
}

T_DECLARE_CASE(test_half_close_b_to_a)
{
	struct test_fixture fx;
	int cl = -1;

	if (fixture_setup(&fx, MOCK_ECHO_HALF_CLOSE_ON_EOF) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	if (connect_and_wait_echo(&fx, fx.tcp_port_b, "halfclose-b", &cl) !=
	    0) {
		T_LOG("connect_and_wait_echo tcp_port_b failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		T_LOG("wait_for_streams_ready failed");
		T_FAIL();
		goto cleanup;
	}
	if (shutdown(cl, SHUT_WR) != 0) {
		T_LOG("shutdown(SHUT_WR) failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_peer_eof(
		    &fx, cl, (double)PEER_EOF_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("wait_for_peer_eof failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl >= 0) {
		(void)close(cl);
	}
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_half_close_a_to_b)
{
	struct test_fixture fx;
	int cl = -1;
	int prime = -1;

	if (fixture_setup(&fx, MOCK_ECHO_HALF_CLOSE_ON_EOF) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	if (connect_and_wait_echo(&fx, fx.tcp_port_b, "prime-a-to-b", &prime) !=
	    0) {
		T_LOG("connect_and_wait_echo prime tcp_port_b failed");
		T_FAIL();
		goto cleanup;
	}
	(void)close(prime);
	prime = -1;

	if (connect_and_wait_echo(&fx, fx.tcp_port_a, "halfclose-a", &cl) !=
	    0) {
		T_LOG("connect_and_wait_echo tcp_port_a failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		T_LOG("wait_for_streams_ready failed");
		T_FAIL();
		goto cleanup;
	}
	if (shutdown(cl, SHUT_WR) != 0) {
		T_LOG("shutdown(SHUT_WR) failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_peer_eof(
		    &fx, cl, (double)PEER_EOF_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("wait_for_peer_eof failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (prime >= 0) {
		(void)close(prime);
	}
	if (cl >= 0) {
		(void)close(cl);
	}
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_multi_stream_churn_and_workload)
{
	struct test_fixture fx;
	int clients[STREAM_CHURN_CONCURRENCY] = { -1, -1, -1, -1 };
	const size_t payload_sizes[3] = {
		PAYLOAD_SMALL,
		PAYLOAD_MEDIUM,
		PAYLOAD_LARGE,
	};
	char *payload = NULL;

	payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		T_FAIL();
		return;
	}

	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	for (uint_fast32_t round = 0; round < STREAM_CHURN_ROUNDS; round++) {
		for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
			const int port = ((round + i) % 2u == 0u) ?
						 fx.tcp_port_a :
						 fx.tcp_port_b;
			clients[i] = connect_local(&fx, port);
			if (clients[i] < 0) {
				T_LOGF("round %u connect failed at slot %u",
				       (unsigned)round, (unsigned)i);
				T_FAIL();
				goto cleanup;
			}
		}

		if (wait_for_streams_ready(&fx, STREAM_CHURN_CONCURRENCY) !=
		    0) {
			T_LOGF("round %u wait_for_streams_ready failed",
			       (unsigned)round);
			T_FAIL();
			goto cleanup;
		}

		for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
			const size_t len = payload_sizes[(round + i) % 3u];
			fill_payload(payload, len, (uint_fast8_t)(round + i));
			if (send_and_expect_echo(
				    &fx, clients[i], payload, len,
				    (double)WORKLOAD_ECHO_WAIT_TIMEOUT_MS /
					    1000.0) != 0) {
				T_LOGF("round %u slot %u payload %zu echo failed",
				       (unsigned)round, (unsigned)i, len);
				T_FAIL();
				goto cleanup;
			}
		}

		for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
			if (clients[i] >= 0) {
				socket_close(clients[i]);
				clients[i] = -1;
			}
		}

		if (wait_for_streams_exact(&fx, 0) != 0) {
			T_LOGF("round %u wait_for_streams_exact(0) failed",
			       (unsigned)round);
			T_FAIL();
			goto cleanup;
		}
	}

cleanup:
	for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
		if (clients[i] >= 0) {
			socket_close(clients[i]);
			clients[i] = -1;
		}
	}
	if (payload != NULL) {
		free(payload);
		payload = NULL;
	}
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_backend_close_after_echo)
{
	struct test_fixture fx;
	int cl = -1;

	if (fixture_setup(&fx, MOCK_ECHO_HALF_CLOSE) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	cl = connect_local(&fx, fx.tcp_port_b);
	if (cl < 0) {
		T_LOG("connect_local failed");
		T_FAIL();
		goto cleanup;
	}
	if (send_and_expect_echo(
		    &fx, cl, "backend-close", strlen("backend-close"),
		    (double)ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("send_and_expect_echo failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_peer_eof(
		    &fx, cl, (double)PEER_EOF_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("wait_for_peer_eof failed");
		T_FAIL();
		goto cleanup;
	}
	socket_close(cl);
	cl = -1;
	if (wait_for_streams_exact(&fx, 0) != 0) {
		T_LOG("wait_for_streams_exact(0) failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl >= 0) {
		socket_close(cl);
	}
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_client_abort_mid_payload)
{
	struct test_fixture fx;
	int cl = -1;
	char *payload = NULL;
	ssize_t nsend = 0;

	payload = malloc(PAYLOAD_MEDIUM);
	if (payload == NULL) {
		T_FAIL();
		return;
	}

	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	cl = connect_local(&fx, fx.tcp_port_a);
	if (cl < 0) {
		T_LOG("connect_local failed");
		T_FAIL();
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_MEDIUM, 3);
	nsend = send(cl, payload, PAYLOAD_MEDIUM, MSG_NOSIGNAL);
	if (nsend <= 0) {
		T_LOG("send failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		T_LOG("wait_for_streams_ready failed");
		T_FAIL();
		goto cleanup;
	}
	socket_close(cl);
	cl = -1;
	if (wait_for_streams_exact(&fx, 0) != 0) {
		T_LOG("wait_for_streams_exact(0) failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl >= 0) {
		socket_close(cl);
	}
	free(payload);
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_listener_reuse_after_stream_churn)
{
	struct test_fixture fx;
	int clients[STREAM_CHURN_CONCURRENCY] = { -1, -1, -1, -1 };
	char payload[PAYLOAD_SMALL];

	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	for (uint_fast32_t round = 0; round < 4; round++) {
		for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
			const int port = ((round + i) % 2u == 0u) ?
						 fx.tcp_port_a :
						 fx.tcp_port_b;
			clients[i] = connect_local(&fx, port);
			if (clients[i] < 0) {
				T_LOGF("round %u connect failed at slot %u",
				       (unsigned)round, (unsigned)i);
				T_FAIL();
				goto cleanup;
			}
		}
		if (wait_for_streams_ready(&fx, STREAM_CHURN_CONCURRENCY) !=
		    0) {
			T_LOG("wait_for_streams_ready failed");
			T_FAIL();
			goto cleanup;
		}
		for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
			fill_payload(
				payload, sizeof(payload),
				(uint_fast8_t)(round + i));
			if (send_and_expect_echo(
				    &fx, clients[i], payload, sizeof(payload),
				    (double)WORKLOAD_ECHO_WAIT_TIMEOUT_MS /
					    1000.0) != 0) {
				T_LOGF("round %u slot %u echo failed",
				       (unsigned)round, (unsigned)i);
				T_FAIL();
				goto cleanup;
			}
		}
		for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
			if (clients[i] >= 0) {
				socket_close(clients[i]);
				clients[i] = -1;
			}
		}
		if (wait_for_streams_exact(&fx, 0) != 0) {
			T_LOG("wait_for_streams_exact(0) failed");
			T_FAIL();
			goto cleanup;
		}
	}

	for (uint_fast32_t i = 0; i < 3; i++) {
		int cl = -1;
		char msg[32];
		(void)snprintf(msg, sizeof(msg), "reuse-%u", (unsigned)i);
		if (connect_and_wait_echo(&fx, fx.tcp_port_a, msg, &cl) != 0) {
			T_LOG("connect_and_wait_echo reuse failed");
			T_FAIL();
			goto cleanup;
		}
		socket_close(cl);
		if (wait_for_streams_exact(&fx, 0) != 0) {
			T_LOG("wait_for_streams_exact(0) failed after reuse");
			T_FAIL();
			goto cleanup;
		}
	}

cleanup:
	for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
		if (clients[i] >= 0) {
			socket_close(clients[i]);
			clients[i] = -1;
		}
	}
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_cross_direction_overlap)
{
	struct test_fixture fx;
	int cl_a = -1;
	int cl_b = -1;
	char payload_a[PAYLOAD_MEDIUM];
	char payload_b[PAYLOAD_MEDIUM];

	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	cl_a = connect_local(&fx, fx.tcp_port_a);
	cl_b = connect_local(&fx, fx.tcp_port_b);
	if (cl_a < 0 || cl_b < 0) {
		T_LOG("connect_local failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		T_LOG("wait_for_streams_ready failed");
		T_FAIL();
		goto cleanup;
	}
	fill_payload(payload_a, sizeof(payload_a), 7);
	fill_payload(payload_b, sizeof(payload_b), 13);
	if (write_full(&fx, cl_a, payload_a, sizeof(payload_a)) != 0 ||
	    write_full(&fx, cl_b, payload_b, sizeof(payload_b)) != 0) {
		T_LOG("write_full failed");
		T_FAIL();
		goto cleanup;
	}
	if (expect_echo(
		    &fx, cl_a, payload_a, sizeof(payload_a),
		    (double)WORKLOAD_ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0 ||
	    expect_echo(
		    &fx, cl_b, payload_b, sizeof(payload_b),
		    (double)WORKLOAD_ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("expect_echo failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl_b >= 0) {
		socket_close(cl_b);
	}
	if (cl_a >= 0) {
		socket_close(cl_a);
	}
	fixture_teardown(&fx);
}

T_DECLARE_CASE(test_large_payload_then_half_close)
{
	struct test_fixture fx;
	int cl = -1;
	char *payload = NULL;

	payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		T_FAIL();
		return;
	}

	if (fixture_setup(&fx, MOCK_ECHO_HALF_CLOSE_ON_EOF) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FAIL();
		goto cleanup;
	}

	cl = connect_local(&fx, fx.tcp_port_b);
	if (cl < 0) {
		T_LOG("connect_local failed");
		T_FAIL();
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_LARGE, 19);
	if (send_and_expect_echo(
		    &fx, cl, payload, PAYLOAD_LARGE,
		    (double)WORKLOAD_ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("send_and_expect_echo failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		T_LOG("wait_for_streams_ready failed");
		T_FAIL();
		goto cleanup;
	}
	if (shutdown(cl, SHUT_WR) != 0) {
		T_LOG("shutdown(SHUT_WR) failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_peer_eof(
		    &fx, cl, (double)PEER_EOF_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("wait_for_peer_eof failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl >= 0) {
		socket_close(cl);
	}
	free(payload);
	fixture_teardown(&fx);
}

/* Predicate: srv_b's mux session has fully idle-closed (no established or
 * half-open sessions left). */
static int session_b_idle_closed_predicate(void *ptr)
{
	struct test_fixture *const restrict fx = ptr;
	const struct wait_stats sb = wait_stats_snapshot(fx->srv_b);
	return sb.num_established_sessions == 0 &&
			       sb.num_halfopen_sessions == 0 ?
		       1 :
		       0;
}

/* Regression for an on-demand tunnel (idle_timeout > 0) never reconnecting
 * after its first idle-close: handle_closed() used to relay the idle-closed
 * session's CLOSED event to the server exactly like a give-up case, which
 * tore the tunnel down permanently; nothing ever recreated it, so every
 * later connection to the forwarding listener failed until a config
 * reload. This exercises the full path: forward once, let the session
 * idle-close, then forward again through the same listener. */
T_DECLARE_CASE(test_on_demand_tunnel_reconnects_after_idle_close)
{
	struct test_fixture fx = {
		.loop = NULL,
		.srv_a = NULL,
		.srv_b = NULL,
		.conf_a = NULL,
		.conf_b = NULL,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};
	int cl1 = -1;
	int cl2 = -1;

	g_setup_stage = "ev_loop_new";
	fx.loop = ev_loop_new(EVFLAG_AUTO);
	if (fx.loop == NULL) {
		T_LOG("ev_loop_new failed");
		T_FAIL();
		return;
	}

	g_setup_stage = "mock_server_a_start";
	if (mock_server_start(&fx.backend_a, fx.loop, MOCK_ECHO) != 0) {
		T_LOG("mock_server_a_start failed");
		T_FAIL();
		goto cleanup;
	}
	g_setup_stage = "mock_server_b_start";
	if (mock_server_start(&fx.backend_b, fx.loop, MOCK_ECHO) != 0) {
		T_LOG("mock_server_b_start failed");
		T_FAIL();
		goto cleanup;
	}

	char connect_a[64];
	(void)snprintf(
		connect_a, sizeof(connect_a), "127.0.0.1:%d",
		fx.backend_a.port);
	fx.conf_a = make_config("127.0.0.1:0", NULL, "127.0.0.1:0", connect_a);
	if (fx.conf_a == NULL) {
		T_LOG("conf_a create failed");
		T_FAIL();
		goto cleanup;
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		T_LOG("server_a start failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_listener_port(
		    &fx, &fx.srv_a->mux_listener, &fx.mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("server_a mux port wait failed");
		T_FAIL();
		goto cleanup;
	}

	char connect_b[64];
	char mux_connect_b[64];
	(void)snprintf(
		connect_b, sizeof(connect_b), "127.0.0.1:%d",
		fx.backend_b.port);
	(void)snprintf(
		mux_connect_b, sizeof(mux_connect_b), "127.0.0.1:%d",
		fx.mux_port_a);
	fx.conf_b = make_config(NULL, mux_connect_b, "127.0.0.1:0", connect_b);
	if (fx.conf_b == NULL) {
		T_LOG("conf_b create failed");
		T_FAIL();
		goto cleanup;
	}
	/* On-demand tunnel: reconnects only when a new local connection
	 * arrives, never on a timer. */
	fx.conf_b->mux.idle_timeout = 1;
	fx.srv_b = server_new(fx.loop, fx.conf_b);
	if (fx.srv_b == NULL || !server_start(fx.srv_b)) {
		T_LOG("server_b start failed");
		T_FAIL();
		goto cleanup;
	}

	if (wait_for_listener_port(
		    &fx, &fx.srv_a->local_listener, &fx.tcp_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("server_a local port wait failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_listener_port(
		    &fx, &fx.srv_b->local_listener, &fx.tcp_port_b,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("server_b local port wait failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_sessions_ready(&fx) != 0) {
		T_LOG("initial session establishment failed");
		T_FAIL();
		goto cleanup;
	}

	/* Forward once before any idle-close, to prove the tunnel works. */
	if (connect_and_wait_echo(&fx, fx.tcp_port_b, "before-idle", &cl1) !=
	    0) {
		T_LOG("echo before idle-close failed");
		T_FAIL();
		goto cleanup;
	}
	(void)close(cl1);
	cl1 = -1;

	/* Wait for the session to self-close from idle_timeout. */
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    session_b_idle_closed_predicate, &fx) != 0) {
		T_LOG("session did not idle-close as expected");
		T_FAIL();
		goto cleanup;
	}

	/* The actual regression check: a new local connection after the
	 * idle-close must still be forwarded, via a demand-triggered
	 * reconnect. Before the fix this always timed out. */
	if (connect_and_wait_echo(&fx, fx.tcp_port_b, "after-idle", &cl2) !=
	    0) {
		T_LOG("echo after idle-close failed"
		      " -- tunnel did not reconnect on demand");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl2 >= 0) {
		(void)close(cl2);
	}
	if (cl1 >= 0) {
		(void)close(cl1);
	}
	fixture_teardown(&fx);
}

/* Predicate: srv_a's config pointer has been replaced (reload completed). */
struct reload_wait_ctx {
	const struct test_fixture *fx;
	const struct config *old_conf;
};

static int reload_done_predicate(void *ptr)
{
	const struct reload_wait_ctx *const restrict ctx = ptr;
	return ctx->fx->srv_a->conf != ctx->old_conf ? 1 : 0;
}

/* test_server_config_reload: exercises SIGHUP server_reload() — drains
 * tunnels, swaps config, waits for srv_b to reconnect, then verifies
 * echo still works. */
T_DECLARE_CASE(test_server_config_reload)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	/* Pre-reload echo sanity check. */
	const int fd_before = connect_local(&fx, fx.tcp_port_a);
	if (fd_before < 0) {
		FIXTURE_FATAL(&fx, "connect_local failed before reload");
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		(void)close(fd_before);
		FIXTURE_FATAL(&fx, "streams not ready before reload");
	}
	T_CHECK(send_and_expect_echo(
			&fx, fd_before, "pre", 3,
			(double)ECHO_WAIT_TIMEOUT_MS / 1000.0) == 0);
	(void)close(fd_before);

	/* Wait for the stream to close so the session is idle before drain. */
	if (wait_for_streams_exact(&fx, 0) != 0) {
		FIXTURE_FATAL(&fx, "stream not drained before reload");
	}

	/* Write the config to a tempfile.  The test config carries
	 * type="...version=2" which conf_parsefile rejects; temporarily clear
	 * it so conf_dumpfile emits the canonical CONF_TYPE ("version=1"). */
	char tmp_path[] = "/tmp/server_reload_XXXXXX";
	const int tmp_fd = mkstemp(tmp_path);
	if (tmp_fd < 0) {
		FIXTURE_FATAL(&fx, "mkstemp failed");
	}
	(void)close(tmp_fd);

	char *const saved_type = fx.conf_a->type;
	fx.conf_a->type = NULL;
	size_t dump_len;
	char *const dump_json = conf_dump(fx.conf_a, &dump_len, NULL);
	fx.conf_a->type = saved_type;
	bool dump_ok = false;
	if (dump_json != NULL) {
		FILE *const dump_fp = fopen(tmp_path, "w");
		if (dump_fp != NULL) {
			dump_ok = fwrite(dump_json, 1, dump_len, dump_fp) ==
				  dump_len;
			(void)fclose(dump_fp);
		}
		free(dump_json);
	}
	if (!dump_ok) {
		(void)unlink(tmp_path);
		FIXTURE_FATAL(&fx, "conf_dumpfile failed");
	}

	/* Trigger reload: point srv_a at the tempfile and invoke its SIGHUP
	 * watcher directly.  ev_feed_signal_event would fire srv_b's watcher
	 * too, causing a noisy "failed to reload config: (null)" error. */
	fx.srv_a->conf_path = tmp_path;
	ev_invoke(fx.loop, &fx.srv_a->w_sighup, EV_SIGNAL);

	/* Wait for signal_cb to run and server_reload() to swap the config.
	 * After this point fx.conf_a is a dangling pointer (freed by reload). */
	struct reload_wait_ctx reload_ctx = {
		.fx = &fx,
		.old_conf = fx.conf_a,
	};
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    reload_done_predicate, &reload_ctx) != 0) {
		(void)unlink(tmp_path);
		FIXTURE_FATAL(
			&fx,
			"server_reload did not swap config within timeout");
	}
	/* Update tracked pointer so fixture_teardown frees the new config. */
	fx.conf_a = fx.srv_a->conf;

	/* Wait for the session to be re-established after the drain. */
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    sessions_ready_wait_predicate, &fx) != 0) {
		(void)unlink(tmp_path);
		FIXTURE_FATAL(&fx, "session not re-established after reload");
	}

	/* Post-reload echo: server must still forward traffic.
	 * connect_and_wait_echo retries if the session is not yet ready
	 * to accept streams (accepted_tunnels may not yet be populated). */
	int fd_after;
	if (connect_and_wait_echo(&fx, fx.tcp_port_a, "post", &fd_after) != 0) {
		(void)unlink(tmp_path);
		FIXTURE_FATAL(&fx, "connect_and_wait_echo failed after reload");
	}
	(void)close(fd_after);

	(void)unlink(tmp_path);
	fixture_teardown(&fx);
}

/* Regression for "server_reload_identities_changed leaks tunnels for a peer
 * removed entirely from config": an identity.peers entry dropped by a reload
 * (not merely changed) must have its pooled tunnel actually closed, not just
 * detached. Builds its own two-server setup (skipping the mock-backend halves
 * of test_fixture, unused here) since make_config does not expose identity
 * fields. */
T_DECLARE_CASE(test_server_reload_removes_identity_peer_closes_tunnel)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct test_fixture fx = {
		.loop = loop,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};

	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_a) failed");
	}
	fx.conf_a->identity.claim = strdup("server-a");
	fx.conf_a->identity.peers = malloc(sizeof(*fx.conf_a->identity.peers));
	if (fx.conf_a->identity.claim == NULL ||
	    fx.conf_a->identity.peers == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf_a identity fields");
	}
	fx.conf_a->identity.peers[0] = (struct identity_peer){
		.id = strdup("peer1"),
		.listen = strdup("127.0.0.1:0"),
	};
	fx.conf_a->identity.peers_count = 1;
	if (fx.conf_a->identity.peers[0].id == NULL ||
	    fx.conf_a->identity.peers[0].listen == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf_a peer id/listen");
	}

	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}
	if (wait_for_listener_port(
		    &fx, &fx.srv_a->mux_listener, &fx.mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		FIXTURE_FATAL(&fx, "srv_a mux port wait failed");
	}

	char mux_connect_b[64];
	(void)snprintf(
		mux_connect_b, sizeof(mux_connect_b), "127.0.0.1:%d",
		fx.mux_port_a);
	fx.conf_b = make_config(NULL, mux_connect_b, NULL, NULL);
	if (fx.conf_b == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_b) failed");
	}
	fx.conf_b->identity.claim = strdup("peer1");
	if (fx.conf_b->identity.claim == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf_b identity fields");
	}

	fx.srv_b = server_new(fx.loop, fx.conf_b);
	if (fx.srv_b == NULL || !server_start(fx.srv_b)) {
		FIXTURE_FATAL(&fx, "srv_b start failed");
	}

	if (wait_for_sessions_ready(&fx) != 0) {
		FIXTURE_FATAL(&fx, "sessions not ready");
	}

	/* Defer assertions until after teardown; failing early would leak the
	 * loop's signal watchers and corrupt later tests in this process. */
	struct server_stats *const before = server_stats(fx.srv_a, true);
	bool found_before = false;
	if (before != NULL) {
		for (size_t i = 0; i < before->num_tunnels; i++) {
			if (before->tunnels[i].peer_identity != NULL &&
			    strcmp(before->tunnels[i].peer_identity, "peer1") ==
				    0) {
				found_before = true;
				break;
			}
		}
		free(before);
	}

	/* Reload srv_a with an otherwise-identical config that drops "peer1"
	 * entirely (not just changes it) -- server_apply_config takes ownership
	 * of new_conf, including on failure. */
	struct config *const new_conf =
		make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (new_conf == NULL) {
		FIXTURE_FATAL(&fx, "make_config(new_conf) failed");
	}
	new_conf->identity.claim = strdup("server-a");
	if (new_conf->identity.claim == NULL) {
		conf_free(new_conf);
		FIXTURE_FATAL(&fx, "OOM building new_conf identity fields");
	}
	const bool applied = server_apply_config(fx.srv_a, new_conf);
	fx.conf_a =
		fx.srv_a->conf; /* old conf_a was freed by server_apply_config */

	/* No loop iteration has run since reload, so disappearance here comes
	 * from identity_listener_discard(), not asynchronous drain dispatch. */
	struct server_stats *const after = server_stats(fx.srv_a, true);
	const size_t num_tunnels_after =
		after != NULL ? after->num_tunnels : SIZE_MAX;
	free(after);

	fixture_teardown(&fx);

	T_EXPECT(found_before);
	T_EXPECT(applied);
	T_EXPECT_EQ(num_tunnels_after, (size_t)0);
}

struct identity_pool_wait_ctx {
	const struct server *srv_a;
	const char *peer_identity;
	size_t expected;
};

/* Polls server_stats() directly for the condition under test (>= expected
 * tunnels sharing peer_identity) instead of srv_a's aggregate session
 * counters: those are independent relaxed atomics racing two concurrent
 * connect attempts, so a snapshot can transiently read a count that does not
 * yet match server_stats()'s own tunnels[] walk -- the actual thing this test
 * asserts on -- causing a flaky "expect 2, got 1" observed empirically when
 * this originally polled wait_stats_snapshot() instead. */
static int identity_pool_wait_predicate(void *ptr)
{
	struct identity_pool_wait_ctx *const restrict ctx = ptr;
	struct server_stats *const stats = server_stats(ctx->srv_a, true);
	if (stats == NULL) {
		return 0;
	}
	size_t count = 0;
	for (size_t i = 0; i < stats->num_tunnels; i++) {
		if (stats->tunnels[i].peer_identity != NULL &&
		    strcmp(stats->tunnels[i].peer_identity,
			   ctx->peer_identity) == 0) {
			count++;
		}
	}
	free(stats);
	return count >= ctx->expected ? 1 : 0;
}

/* Covers one identity_listener holding multiple live tunnels for the same
 * plaintext peer identity. cd8259d's exact pre-fix formula is unreachable
 * here, but the multi-tunnel pool state itself was previously untested. */
T_DECLARE_CASE(test_server_identity_pool_holds_concurrent_tunnels_same_peer)
{
	/* All locals are declared up front and NULL/sentinel-initialized so the
	 * single null-safe cleanup block below handles a T_FAIL at any setup
	 * stage -- including a partial conf_c[]/srv_c[] loop iteration -- without
	 * leaking the loop, servers, or configs. */
	struct ev_loop *loop = NULL;
	struct config *conf_a = NULL;
	struct server *srv_a = NULL;
	struct config *conf_c[2] = { NULL, NULL };
	struct server *srv_c[2] = { NULL, NULL };
	struct test_fixture fx = { 0 };
	int mux_port_a = -1;
	char mux_connect_a[64];
	int wait_rc = -1;
	size_t shared_count = 0;
	size_t reported_pool_size = 0;
	bool setup_ok = false;

	loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.loop = loop;

	conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf_a == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.claim = strdup("server-a");
	conf_a->identity.peers = malloc(sizeof(*conf_a->identity.peers));
	if (conf_a->identity.claim == NULL || conf_a->identity.peers == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.peers[0] = (struct identity_peer){
		.id = strdup("shared-peer"),
		.listen = strdup("127.0.0.1:0"),
	};
	conf_a->identity.peers_count = 1;
	if (conf_a->identity.peers[0].id == NULL ||
	    conf_a->identity.peers[0].listen == NULL) {
		T_FAIL();
		goto cleanup;
	}

	srv_a = server_new(loop, conf_a);
	if (srv_a == NULL || !server_start(srv_a)) {
		T_FAIL();
		goto cleanup;
	}
	fx.srv_a = srv_a;

	if (wait_for_listener_port(
		    &fx, &srv_a->mux_listener, &mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_FAIL();
		goto cleanup;
	}
	(void)snprintf(
		mux_connect_a, sizeof(mux_connect_a), "127.0.0.1:%d",
		mux_port_a);

	/* Two independent dialers, both claiming "shared-peer". */
	for (size_t i = 0; i < 2; i++) {
		conf_c[i] = make_config(NULL, mux_connect_a, NULL, NULL);
		if (conf_c[i] == NULL) {
			T_FAIL();
			goto cleanup;
		}
		conf_c[i]->identity.claim = strdup("shared-peer");
		if (conf_c[i]->identity.claim == NULL) {
			T_FAIL();
			goto cleanup;
		}
		srv_c[i] = server_new(loop, conf_c[i]);
		if (srv_c[i] == NULL || !server_start(srv_c[i])) {
			T_FAIL();
			goto cleanup;
		}
	}

	struct identity_pool_wait_ctx wait_ctx = {
		.srv_a = srv_a,
		.peer_identity = "shared-peer",
		.expected = 2,
	};
	wait_rc = wait_until(
		&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		identity_pool_wait_predicate, &wait_ctx);

	/* Snapshot the pool state (whatever it is, even after a wait timeout)
	 * before any cleanup runs below. */
	struct server_stats *const stats = server_stats(srv_a, true);
	if (stats != NULL) {
		for (size_t i = 0; i < stats->num_tunnels; i++) {
			if (stats->tunnels[i].peer_identity != NULL &&
			    strcmp(stats->tunnels[i].peer_identity,
				   "shared-peer") == 0) {
				shared_count++;
				reported_pool_size =
					stats->tunnels[i].num_tunnels;
			}
		}
		free(stats);
	}
	setup_ok = true;

cleanup:
	/* Teardown drives server_stop(srv_a), whose force-close sweep sizes a
	 * heap snapshot from the sum of every identity pool's num_tunnels
	 * (cd8259d); with 2 tunnels pooled under one peer, a reintroduced
	 * table_size(identities)-based undercount would trip
	 * ASSERT(count < cap) in server_snapshot_tunnels (this is a debug/
	 * ASSERT-enabled build), not pass quietly. */
	for (size_t i = 0; i < 2; i++) {
		if (srv_c[i] != NULL) {
			server_stop(srv_c[i]);
			server_free(srv_c[i]);
		}
	}
	if (srv_a != NULL) {
		server_stop(srv_a);
		server_free(srv_a);
	}
	for (size_t i = 0; i < 2; i++) {
		if (conf_c[i] != NULL) {
			conf_free(conf_c[i]);
		}
	}
	if (conf_a != NULL) {
		conf_free(conf_a);
	}
	if (loop != NULL) {
		ev_loop_destroy(loop);
	}

	/* All assertions are deferred past cleanup: reaching them before the
	 * servers/loop are torn down would leak a live ev_loop with registered
	 * SIGHUP/SIGINT/SIGTERM watchers, wedging libev's per-signal loop
	 * registry ("a signal must not be attached to two different loops") for
	 * every later test in this process. */
	if (setup_ok) {
		T_EXPECT_EQ(wait_rc, 0);
		T_EXPECT_EQ(shared_count, (size_t)2);
		T_EXPECT_EQ(reported_pool_size, (size_t)2);
	}
}

/* Regression: reloading away two identity peers that each hold a pooled tunnel
 * must not free a listener while it is still reachable through s->identities.
 * In the discard loop, closing the second peer's tunnel calls
 * server_tunnel_is_registered(), whose tunnel_iter_next() walks s->identities
 * and dereferences the first, already-freed listener -- a heap-use-after-free
 * this ASan build catches. Two peers each with a live tunnel guarantee the
 * ordering that triggers it, regardless of the hash-table iteration order. */
T_DECLARE_CASE(test_server_reload_drops_two_identity_peers_no_uaf)
{
	struct ev_loop *loop = NULL;
	struct config *conf_a = NULL;
	struct server *srv_a = NULL;
	struct config *conf_c[2] = { NULL, NULL };
	struct server *srv_c[2] = { NULL, NULL };
	struct test_fixture fx = { 0 };
	int mux_port_a = -1;
	char mux_connect_a[64];
	bool applied = false;
	size_t num_tunnels_after = SIZE_MAX;
	bool setup_ok = false;
	static const char *const peer_ids[2] = { "peer-a", "peer-b" };

	loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.loop = loop;

	conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf_a == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.claim = strdup("server-a");
	conf_a->identity.peers = malloc(2 * sizeof(*conf_a->identity.peers));
	if (conf_a->identity.claim == NULL || conf_a->identity.peers == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.peers_count = 2;
	for (size_t i = 0; i < 2; i++) {
		conf_a->identity.peers[i] = (struct identity_peer){
			.id = strdup(peer_ids[i]),
			.listen = strdup("127.0.0.1:0"),
		};
		if (conf_a->identity.peers[i].id == NULL ||
		    conf_a->identity.peers[i].listen == NULL) {
			T_FAIL();
			goto cleanup;
		}
	}

	srv_a = server_new(loop, conf_a);
	if (srv_a == NULL || !server_start(srv_a)) {
		T_FAIL();
		goto cleanup;
	}
	fx.srv_a = srv_a;

	if (wait_for_listener_port(
		    &fx, &srv_a->mux_listener, &mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_FAIL();
		goto cleanup;
	}
	(void)snprintf(
		mux_connect_a, sizeof(mux_connect_a), "127.0.0.1:%d",
		mux_port_a);

	/* One dialer per peer: each lands in a distinct identity pool. */
	for (size_t i = 0; i < 2; i++) {
		conf_c[i] = make_config(NULL, mux_connect_a, NULL, NULL);
		if (conf_c[i] == NULL) {
			T_FAIL();
			goto cleanup;
		}
		conf_c[i]->identity.claim = strdup(peer_ids[i]);
		if (conf_c[i]->identity.claim == NULL) {
			T_FAIL();
			goto cleanup;
		}
		srv_c[i] = server_new(loop, conf_c[i]);
		if (srv_c[i] == NULL || !server_start(srv_c[i])) {
			T_FAIL();
			goto cleanup;
		}
	}

	/* Wait until srv_a has pooled a tunnel for BOTH peers. */
	bool pooled = true;
	for (size_t i = 0; i < 2 && pooled; i++) {
		struct identity_pool_wait_ctx wait_ctx = {
			.srv_a = srv_a,
			.peer_identity = peer_ids[i],
			.expected = 1,
		};
		pooled = wait_until(
				 &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
				 identity_pool_wait_predicate, &wait_ctx) == 0;
	}
	if (!pooled) {
		T_FAIL();
		goto cleanup;
	}

	/* Reload srv_a with a config that drops both peers. The discard loop
	 * frees both listeners; pre-fix, the second discard reads the first
	 * (freed) listener while walking s->identities. server_apply_config
	 * owns new_conf (including on failure), and srv_a->conf is the survivor
	 * afterward -- so the cleanup block frees exactly one config for srv_a. */
	{
		struct config *const new_conf =
			make_config("127.0.0.1:0", NULL, NULL, NULL);
		if (new_conf == NULL) {
			T_FAIL();
			goto cleanup;
		}
		new_conf->identity.claim = strdup("server-a");
		if (new_conf->identity.claim == NULL) {
			conf_free(new_conf);
			T_FAIL();
			goto cleanup;
		}
		applied = server_apply_config(srv_a, new_conf);
		conf_a = srv_a->conf;
	}

	/* Sampled with no loop iteration in between: the discard ran
	 * synchronously inside server_apply_config. */
	{
		struct server_stats *const after = server_stats(srv_a, true);
		num_tunnels_after =
			after != NULL ? after->num_tunnels : SIZE_MAX;
		free(after);
	}
	setup_ok = true;

cleanup:
	for (size_t i = 0; i < 2; i++) {
		if (srv_c[i] != NULL) {
			server_stop(srv_c[i]);
			server_free(srv_c[i]);
		}
	}
	if (srv_a != NULL) {
		server_stop(srv_a);
		server_free(srv_a);
	}
	for (size_t i = 0; i < 2; i++) {
		if (conf_c[i] != NULL) {
			conf_free(conf_c[i]);
		}
	}
	if (conf_a != NULL) {
		conf_free(conf_a);
	}
	if (loop != NULL) {
		ev_loop_destroy(loop);
	}

	if (setup_ok) {
		T_EXPECT(applied);
		T_EXPECT_EQ(num_tunnels_after, (size_t)0);
	}
}

/* Populate conf as an identity dialer: claim "node-b", dial one
 * identity.mux_connect address, and pool the response under a routing-only
 * "node-a" identity (listen == NULL, so no extra TCP listener) so the
 * established dial-out lands in an identity pool. Returns false on OOM; the
 * caller's conf_free() cleans up any partial fields (counts are set right
 * after each array allocation). */
static bool build_identity_dialer_conf(
	struct config *restrict conf, const char *restrict connect_addr)
{
	conf->identity.claim = strdup("node-b");
	if (conf->identity.claim == NULL) {
		return false;
	}
	conf->identity.mux_connect =
		(char **)malloc(sizeof(*conf->identity.mux_connect));
	if (conf->identity.mux_connect == NULL) {
		return false;
	}
	conf->identity.mux_connect_count = 1;
	conf->identity.mux_connect[0] = strdup(connect_addr);
	if (conf->identity.mux_connect[0] == NULL) {
		return false;
	}
	conf->identity.peers = malloc(sizeof(*conf->identity.peers));
	if (conf->identity.peers == NULL) {
		return false;
	}
	conf->identity.peers_count = 1;
	conf->identity.peers[0] = (struct identity_peer){
		.id = strdup("node-a"),
		.listen = NULL,
	};
	return conf->identity.peers[0].id != NULL;
}

/* Regression: a config reload while an identity.mux_connect dial-out is
 * established must not spawn a duplicate. Establishment pools the dialed tunnel;
 * it previously also nulled the tunnel's identity_tunnels[] staging slot, and
 * reload then read the NULL slot as "closed" and dialed a fresh tunnel on every
 * reload -- growing the pool without bound. The fix keeps the slot pointing at
 * the live tunnel, so reload recognizes it and re-dials nothing. */
T_DECLARE_CASE(test_server_reload_keeps_established_identity_mux_connect_tunnel)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct test_fixture fx = {
		.loop = loop,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};

	/* srv_a: mux listener announcing identity "node-a"; accepts srv_b. */
	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_a) failed");
	}
	fx.conf_a->identity.claim = strdup("node-a");
	if (fx.conf_a->identity.claim == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf_a identity");
	}

	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}
	if (wait_for_listener_port(
		    &fx, &fx.srv_a->mux_listener, &fx.mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		FIXTURE_FATAL(&fx, "srv_a mux port wait failed");
	}

	char mux_connect_a[64];
	(void)snprintf(
		mux_connect_a, sizeof(mux_connect_a), "127.0.0.1:%d",
		fx.mux_port_a);

	/* srv_b: dials srv_a via identity.mux_connect. */
	fx.conf_b = make_config(NULL, NULL, NULL, NULL);
	if (fx.conf_b == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_b) failed");
	}
	if (!build_identity_dialer_conf(fx.conf_b, mux_connect_a)) {
		FIXTURE_FATAL(&fx, "OOM building conf_b identity");
	}

	fx.srv_b = server_new(fx.loop, fx.conf_b);
	if (fx.srv_b == NULL || !server_start(fx.srv_b)) {
		FIXTURE_FATAL(&fx, "srv_b start failed");
	}

	/* Wait for srv_b's dial-out to establish and land in the "node-a" pool. */
	struct identity_pool_wait_ctx wait_ctx = {
		.srv_a = fx.srv_b,
		.peer_identity = "node-a",
		.expected = 1,
	};
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    identity_pool_wait_predicate, &wait_ctx) != 0) {
		FIXTURE_FATAL(
			&fx, "identity.mux_connect dial-out did not establish");
	}

	/* The established dial-out must still be reachable through its staging
	 * slot (the core of the fix); capture it for the post-reload compare. */
	struct tunnel *const slot_after_established =
		fx.srv_b->num_identity_tunnels == 1 ?
			fx.srv_b->identity_tunnels[0] :
			NULL;

	/* Reload srv_b with an identical config. */
	struct config *const new_conf = make_config(NULL, NULL, NULL, NULL);
	if (new_conf == NULL) {
		FIXTURE_FATAL(&fx, "make_config(new_conf) failed");
	}
	if (!build_identity_dialer_conf(new_conf, mux_connect_a)) {
		conf_free(new_conf);
		FIXTURE_FATAL(&fx, "OOM building new_conf identity");
	}
	const bool applied = server_apply_config(fx.srv_b, new_conf);
	fx.conf_b =
		fx.srv_b->conf; /* old conf_b freed by server_apply_config */

	/* No loop iteration has run since reload, so the slot/pool state is
	 * exactly what server_reload_identity_tunnels left. */
	const size_t slots_after_reload = fx.srv_b->num_identity_tunnels;
	struct tunnel *const slot_after_reload =
		slots_after_reload == 1 ? fx.srv_b->identity_tunnels[0] : NULL;

	fixture_teardown(&fx);

	T_EXPECT(applied);
	/* Establishment leaves the slot pointing at the live tunnel. */
	T_EXPECT(slot_after_established != NULL);
	/* Reload re-dials nothing: the slot still holds the same tunnel (before
	 * the fix it held a freshly-dialed duplicate, or NULL). */
	T_EXPECT_EQ(slots_after_reload, (size_t)1);
	T_EXPECT(slot_after_reload == slot_after_established);
}

#if WITH_TLS
/* Two distinct 32-octet keys as hex; only their labels have to differ. */
#define RELOAD_PSK_HEX_A                                                       \
	"0101010101010101010101010101010101010101010101010101010101010101"
#define RELOAD_PSK_HEX_B                                                       \
	"0202020202020202020202020202020202020202020202020202020202020202"
#define RELOAD_PSK_ID "psk-peer"

/* make_config() plus a single tls.psk entry, laid out the way conf.c's parser
 * leaves one: the identity as the map key, the key itself hex-encoded. */
static struct config *make_psk_config(
	const char *const restrict mux_listen,
	const char *const restrict mux_connect, const char *const restrict hex)
{
	struct config *const conf =
		make_config(mux_listen, mux_connect, NULL, NULL);
	if (conf == NULL) {
		return NULL;
	}
	conf->tls_psk = malloc(sizeof(*conf->tls_psk));
	if (conf->tls_psk == NULL) {
		conf_free(conf);
		return NULL;
	}
	conf->tls_psk_cap = 1;
	/* Count first, so conf_free() reclaims the entry even half-built. */
	conf->tls_psk_count = 1;
	conf->tls_psk[0] = (struct psk_entry){
		.id = strdup(RELOAD_PSK_ID),
		.id_len = strlen(RELOAD_PSK_ID),
		.hex = strdup(hex),
	};
	if (conf->tls_psk[0].id == NULL || conf->tls_psk[0].hex == NULL) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

struct psk_retire_wait_ctx {
	const struct server *srv;
	const struct tunnel *t;
};

/* Predicate: the tunnel resolves through the current table and the barrier has
 * let go of everything the reload retired. */
static int psk_retired_released_predicate(void *ptr)
{
	const struct psk_retire_wait_ctx *const restrict ctx = ptr;
	return tunnel_psk_ctx(ctx->t) == ctx->srv->psk &&
			       ctx->srv->retired_psk == NULL ?
		       1 :
		       0;
}

/* Regression: server_apply_config() freed the outgoing PSK table as soon as it
 * had *queued* a reload to every tunnel.  A tunnel only stops resolving labels
 * through that table when the queued task runs on its own thread -- or never,
 * when the queue was full or the reload argument could not be allocated -- so
 * the free raced, and could permanently outlive, the readers.
 *
 * Reading the outgoing table after the reload is exactly what
 * tunnel_on_verify_identity() does for a hello arriving in that window, so
 * against the pre-fix server.c this lands on the freed block and the sanitizer
 * build reports a heap-use-after-free.  The tail of the case then holds the
 * fix to the other half of its bargain: the retirement is a barrier, not a
 * retention leak, and the maintenance tick must release the table once the
 * tunnel reports the new one. */
T_DECLARE_CASE(test_server_reload_retires_psk_table_for_live_tunnels)
{
	struct test_fixture fx = { 0 };
	fx.loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(fx.loop != NULL);
	/* mux_connect gives server_start() a dialed tunnel that borrows the
	 * table; it never has to reach a peer to be a reader of it. */
	struct config *const conf =
		make_psk_config("127.0.0.1:0", "127.0.0.1:1", RELOAD_PSK_HEX_A);
	T_CHECK(conf != NULL);
	struct server *const srv = server_new(fx.loop, conf);
	T_CHECK(srv != NULL);
	T_CHECK(server_start(srv));

	struct tunnel *const t = srv->mux_tunnel;
	T_CHECK(t != NULL);
	struct psk_table *const old_psk = srv->psk;
	T_CHECK(old_psk != NULL);
	/* Copied out before the reload: after it, reading the table is the very
	 * thing under test and must not be needed to set the test up. */
	char label[sizeof(old_psk->entries[0].label)];
	(void)snprintf(label, sizeof(label), "%s", old_psk->entries[0].label);

	struct config *const new_conf =
		make_psk_config("127.0.0.1:0", "127.0.0.1:1", RELOAD_PSK_HEX_B);
	T_CHECK(new_conf != NULL);
	const bool applied = server_apply_config(srv, new_conf);
	T_CHECK(applied);
	T_CHECK(srv->psk != old_psk);

	/* The defect, read back at the surface a tunnel meets it on.  Reduced to
	 * a verdict here rather than carried to the assertions below: the result
	 * points *into* the table, which the barrier is expected to release
	 * before this case ends. */
	const char *const owner = server_psk_identity_of(old_psk, label);
	const bool owner_ok =
		owner != NULL && strcmp(owner, RELOAD_PSK_ID) == 0;
	/* Whichever table the tunnel reports -- the reload is asynchronous, so
	 * either is legal -- resolving through it must not touch freed memory.
	 * NULL is a legal answer once it holds the new table, whose label
	 * differs; what matters is that the lookup stayed in bounds. */
	const void *const held = tunnel_psk_ctx(t);
	const bool held_live = (held == old_psk || held == srv->psk);
	const char *const held_owner = server_psk_identity_of(held, label);
	const bool held_owner_ok =
		held_owner == NULL || strcmp(held_owner, RELOAD_PSK_ID) == 0;

	struct psk_retire_wait_ctx wait_ctx = { .srv = srv, .t = t };
	const int released_rc =
		wait_until(&fx, 5.0, psk_retired_released_predicate, &wait_ctx);

	server_stop(srv);
	struct config *const final_conf = srv->conf;
	server_free(srv);
	conf_free(final_conf);
	ev_loop_destroy(fx.loop);

	T_EXPECT(owner_ok);
	T_EXPECT(held_live);
	T_EXPECT(held_owner_ok);
	T_EXPECT_EQ(released_rc, 0);
}

/* Predicate: the tunnel resolves through the current table. */
static int psk_repointed_predicate(void *ptr)
{
	const struct psk_retire_wait_ctx *const restrict ctx = ptr;
	return tunnel_psk_ctx(ctx->t) == ctx->srv->psk ? 1 : 0;
}

struct psk_tick_wait_ctx {
	const struct server *srv;
	uint_least64_t before;
};

/* Predicate: a maintenance tick has run since @c before was sampled, so the
 * retired-table sweep it carries has had its turn. */
static int psk_maintenance_ticked_predicate(void *ptr)
{
	const struct psk_tick_wait_ctx *const restrict ctx = ptr;
	return ctx->srv->maintenance_passes != ctx->before ? 1 : 0;
}

/* Regression: the barrier decided a retired table had no reader left from what
 * the live tunnels report, which covers only the pointer a tunnel has already
 * adopted.  A server TLS context registered with that table as its PSK lookup
 * context is a reader too, and the reload freeing the context handle does not
 * end it: SSL_new() (and the mbedTLS backend's per-connection reference) keeps
 * the parsed context alive, so a connection accepted before the reload can
 * still reach the lookup afterwards.  The sweep swept right past that holder.
 *
 * tls_ctx_ref() stands in for such a connection here -- it takes the same
 * reference on the parsed context that an accepted one does -- and the table is
 * then read at the surface the lookup meets it on, which lands on the freed
 * block against the pre-fix server.c.  The tail holds the fix to the other half
 * of its bargain: dropping the last reference must let the next tick go through
 * with the release. */
T_DECLARE_CASE(test_server_psk_retirement_waits_for_live_tls_context)
{
	struct test_fixture fx = { 0 };
	fx.loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(fx.loop != NULL);
	/* mux_listen builds the server-role context that registers the table;
	 * mux_connect gives the barrier a live tunnel to ask about. */
	struct config *const conf =
		make_psk_config("127.0.0.1:0", "127.0.0.1:1", RELOAD_PSK_HEX_A);
	T_CHECK(conf != NULL);
	struct server *const srv = server_new(fx.loop, conf);
	T_CHECK(srv != NULL);
	T_CHECK(server_start(srv));

	struct tunnel *const t = srv->mux_tunnel;
	T_CHECK(t != NULL);
	struct psk_table *const old_psk = srv->psk;
	T_CHECK(old_psk != NULL);
	char label[sizeof(old_psk->entries[0].label)];
	(void)snprintf(label, sizeof(label), "%s", old_psk->entries[0].label);

	/* The connection that outlives the reload: same reference an accepted one
	 * holds, taken while the context is still the server's. */
	T_CHECK(srv->server_tlsctx != NULL);
	struct tls_context *const accepted_ctx =
		tls_ctx_ref(srv->server_tlsctx);
	T_CHECK(accepted_ctx != NULL);

	struct config *const new_conf =
		make_psk_config("127.0.0.1:0", "127.0.0.1:1", RELOAD_PSK_HEX_B);
	T_CHECK(new_conf != NULL);
	const bool applied = server_apply_config(srv, new_conf);
	T_CHECK(applied);
	T_CHECK(srv->psk != old_psk);

	/* The barrier's own criterion, satisfied: every live tunnel reports the
	 * new table.  The sweep that follows is the one that used to free the
	 * table accepted_ctx still resolves through. */
	struct psk_retire_wait_ctx wait_ctx = { .srv = srv, .t = t };
	const int repointed_rc =
		wait_until(&fx, 5.0, psk_repointed_predicate, &wait_ctx);
	struct psk_tick_wait_ctx tick_ctx = {
		.srv = srv,
		.before = srv->maintenance_passes,
	};
	const int ticked_rc = wait_until(
		&fx, 5.0, psk_maintenance_ticked_predicate, &tick_ctx);

	/* Reduced to verdicts here, as in the case above: the reads point into a
	 * table the fix must have kept, and it is released before the case ends. */
	const bool still_retired = srv->retired_psk == old_psk;
	const char *const owner = server_psk_identity_of(old_psk, label);
	const bool owner_ok =
		owner != NULL && strcmp(owner, RELOAD_PSK_ID) == 0;

	/* The connection ends; nothing names the table any more. */
	tls_ctx_free(accepted_ctx);
	const int released_rc =
		wait_until(&fx, 5.0, psk_retired_released_predicate, &wait_ctx);

	server_stop(srv);
	struct config *const final_conf = srv->conf;
	server_free(srv);
	conf_free(final_conf);
	ev_loop_destroy(fx.loop);

	T_EXPECT(applied);
	T_EXPECT_EQ(repointed_rc, 0);
	T_EXPECT_EQ(ticked_rc, 0);
	/* The sweep ran with the tunnel already repointed and must still have
	 * kept the table: the context is a reader it cannot see. */
	T_EXPECT(still_retired);
	T_EXPECT(owner_ok);
	/* ...and kept it no longer than that. */
	T_EXPECT_EQ(released_rc, 0);
}
#endif /* WITH_TLS */

/* Like build_identity_dialer_conf, but registers both peer identities the
 * dialer is pointed at in turn, so a pool exists for each. */
static bool build_two_peer_dialer_conf(
	struct config *restrict conf, const char *restrict connect_addr)
{
	conf->identity.claim = strdup("node-b");
	if (conf->identity.claim == NULL) {
		return false;
	}
	conf->identity.mux_connect =
		(char **)malloc(sizeof(*conf->identity.mux_connect));
	if (conf->identity.mux_connect == NULL) {
		return false;
	}
	conf->identity.mux_connect_count = 1;
	conf->identity.mux_connect[0] = strdup(connect_addr);
	if (conf->identity.mux_connect[0] == NULL) {
		return false;
	}
	conf->identity.peers = malloc(2 * sizeof(*conf->identity.peers));
	if (conf->identity.peers == NULL) {
		return false;
	}
	conf->identity.peers_count = 2;
	conf->identity.peers[0] = (struct identity_peer){
		.id = strdup("node-a"),
		.listen = NULL,
	};
	conf->identity.peers[1] = (struct identity_peer){
		.id = strdup("node-c"),
		.listen = NULL,
	};
	return conf->identity.peers[0].id != NULL &&
	       conf->identity.peers[1].id != NULL;
}

/* Tunnels pooled under peer_identity, or SIZE_MAX when no such pool exists.
 * Pools are only mutated on the server loop thread, which is the thread
 * wait_until drives, so reading them between iterations races nothing. */
static size_t identity_pool_size(
	const struct server *restrict srv, const char *restrict peer_identity)
{
	void *elem = NULL;
	if (!table_find(srv->identities, peer_identity, &elem)) {
		return SIZE_MAX;
	}
	return ((const struct identity_listener *)elem)->num_tunnels;
}

/* Pool memberships summed over every identity pool. The single-pool invariant
 * makes this the tunnel count; a double-pooled tunnel counts twice. */
static size_t identity_pool_total(const struct server *restrict srv)
{
	size_t total = 0;
	size_t cursor = 0;
	void *elem;
	while (table_next(srv->identities, &cursor, NULL, &elem)) {
		total += ((const struct identity_listener *)elem)->num_tunnels;
	}
	return total;
}

struct pool_size_wait_ctx {
	const struct server *srv;
	const char *peer_identity;
	size_t expected;
};

static int pool_size_wait_predicate(void *ptr)
{
	const struct pool_size_wait_ctx *const restrict ctx = ptr;
	return identity_pool_size(ctx->srv, ctx->peer_identity) ==
			       ctx->expected ?
		       1 :
		       0;
}

/* Regression (#248): a tunnel belongs to at most one identity pool, even when
 * the identity its peer announces changes across a fresh re-establishment.
 *
 * A dialed tunnel re-enters MUX_EVENT_ESTABLISHED on every non-resumed
 * reconnect, and whoever answers then may claim a different identity. Drive
 * exactly that: a reload repoints srv_b's single identity.mux_connect slot from
 * srv_a ("node-a") to srv_c ("node-c"). tunnel_set_reload_connect() retargets
 * the *same* struct tunnel rather than dialing a new one, and srv_c holds no
 * matching session, so the resume is refused and the handshake falls back to
 * fresh -- running establishment a second time on that tunnel under a different
 * peer identity.
 *
 * The pooling pass previously consulted only the pool it was about to add to,
 * and nothing dropped the earlier membership, so the tunnel stayed in
 * "node-a"'s pool as well: identity_listener_pick() would forward "node-a"
 * traffic over a peer that now claims "node-c", and the close path -- which
 * stopped at the first pool holding the tunnel -- left the other pool pointing
 * at freed memory. */
T_DECLARE_CASE(test_server_identity_pool_single_membership_across_reclaim)
{
	struct ev_loop *loop = NULL;
	struct config *conf_a = NULL;
	struct config *conf_c = NULL;
	struct config *conf_b = NULL;
	struct server *srv_a = NULL;
	struct server *srv_c = NULL;
	struct server *srv_b = NULL;
	struct test_fixture fx = { 0 };
	int mux_port_a = -1;
	int mux_port_c = -1;
	char mux_connect_a[64];
	char mux_connect_c[64];
	struct tunnel *tunnel_on_a = NULL;
	struct tunnel *tunnel_on_c = NULL;
	int wait_a_rc = -1;
	int wait_c_rc = -1;
	size_t pool_a_after = SIZE_MAX;
	size_t pool_c_after = SIZE_MAX;
	size_t total_after = SIZE_MAX;
	bool applied = false;
	bool setup_ok = false;

	loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.loop = loop;

	/* Two peers with distinct claims, each accepting mux connections. */
	conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	conf_c = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf_a == NULL || conf_c == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.claim = strdup("node-a");
	conf_c->identity.claim = strdup("node-c");
	if (conf_a->identity.claim == NULL || conf_c->identity.claim == NULL) {
		T_FAIL();
		goto cleanup;
	}

	srv_a = server_new(loop, conf_a);
	if (srv_a == NULL || !server_start(srv_a)) {
		T_FAIL();
		goto cleanup;
	}
	srv_c = server_new(loop, conf_c);
	if (srv_c == NULL || !server_start(srv_c)) {
		T_FAIL();
		goto cleanup;
	}
	if (wait_for_listener_port(
		    &fx, &srv_a->mux_listener, &mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0 ||
	    wait_for_listener_port(
		    &fx, &srv_c->mux_listener, &mux_port_c,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_FAIL();
		goto cleanup;
	}
	(void)snprintf(
		mux_connect_a, sizeof(mux_connect_a), "127.0.0.1:%d",
		mux_port_a);
	(void)snprintf(
		mux_connect_c, sizeof(mux_connect_c), "127.0.0.1:%d",
		mux_port_c);

	/* srv_b dials srv_a and knows a pool for both identities. */
	conf_b = make_config(NULL, NULL, NULL, NULL);
	if (conf_b == NULL) {
		T_FAIL();
		goto cleanup;
	}
	if (!build_two_peer_dialer_conf(conf_b, mux_connect_a)) {
		T_FAIL();
		goto cleanup;
	}
	srv_b = server_new(loop, conf_b);
	if (srv_b == NULL || !server_start(srv_b)) {
		T_FAIL();
		goto cleanup;
	}
	conf_b = NULL; /* owned by srv_b from here; freed via srv_b->conf */

	struct pool_size_wait_ctx wait_a = {
		.srv = srv_b,
		.peer_identity = "node-a",
		.expected = 1,
	};
	wait_a_rc = wait_until(
		&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		pool_size_wait_predicate, &wait_a);
	if (wait_a_rc != 0) {
		T_FAIL();
		goto cleanup;
	}
	tunnel_on_a = srv_b->num_identity_tunnels == 1 ?
			      srv_b->identity_tunnels[0] :
			      NULL;

	/* Repoint the slot at the other peer: same tunnel, new claim. */
	struct config *const new_conf = make_config(NULL, NULL, NULL, NULL);
	if (new_conf == NULL) {
		T_FAIL();
		goto cleanup;
	}
	if (!build_two_peer_dialer_conf(new_conf, mux_connect_c)) {
		conf_free(new_conf);
		T_FAIL();
		goto cleanup;
	}
	applied = server_apply_config(srv_b, new_conf);
	if (!applied) {
		T_FAIL();
		goto cleanup;
	}

	struct pool_size_wait_ctx wait_c = {
		.srv = srv_b,
		.peer_identity = "node-c",
		.expected = 1,
	};
	wait_c_rc = wait_until(
		&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		pool_size_wait_predicate, &wait_c);
	if (wait_c_rc != 0) {
		T_FAIL();
		goto cleanup;
	}

	/* The state under test, sampled with no loop iteration in between. */
	pool_a_after = identity_pool_size(srv_b, "node-a");
	pool_c_after = identity_pool_size(srv_b, "node-c");
	total_after = identity_pool_total(srv_b);
	tunnel_on_c = srv_b->num_identity_tunnels == 1 ?
			      srv_b->identity_tunnels[0] :
			      NULL;
	setup_ok = true;

cleanup:
	if (srv_b != NULL) {
		server_stop(srv_b);
		struct config *const final_conf_b = srv_b->conf;
		server_free(srv_b);
		conf_free(final_conf_b);
	}
	if (srv_c != NULL) {
		server_stop(srv_c);
		server_free(srv_c);
	}
	if (srv_a != NULL) {
		server_stop(srv_a);
		server_free(srv_a);
	}
	if (conf_b != NULL) {
		conf_free(conf_b);
	}
	if (conf_c != NULL) {
		conf_free(conf_c);
	}
	if (conf_a != NULL) {
		conf_free(conf_a);
	}
	if (loop != NULL) {
		ev_loop_destroy(loop);
	}

	/* Assertions deferred past teardown: a fatal T_EXPECT before the
	 * servers/loop are freed would leak a live ev_loop with registered signal
	 * watchers and wedge later tests in this process. */
	if (setup_ok) {
		T_EXPECT(applied);
		/* Re-establishment reused the tunnel instead of dialing a new
		 * one -- otherwise the double-pooling this guards never arises. */
		T_EXPECT(tunnel_on_a != NULL);
		T_EXPECT(tunnel_on_c == tunnel_on_a);
		/* The whole point: it left the pool it no longer belongs to. */
		T_EXPECT_EQ(pool_a_after, (size_t)0);
		T_EXPECT_EQ(pool_c_after, (size_t)1);
		T_EXPECT_EQ(total_after, (size_t)1);
	}
}

/* Regression: once an identity.mux_connect slot is freed -- e.g. a draining
 * orphan that had shadowed a reconfigured target finally closes -- maintenance_cb
 * must re-dial the slot from the current config instead of leaving it empty until
 * the next reload. server_reload_identity_tunnels only ever dials a NULL slot, so
 * a slot still held by an orphan at reload time is otherwise never revisited. The
 * freed slot is simulated by nulling it directly (handle_closed does exactly this
 * when the tunnel closes), which keeps the test deterministic; a single
 * maintenance tick must then re-populate it with a fresh tunnel. */
T_DECLARE_CASE(test_server_maintenance_redials_emptied_identity_slot)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct test_fixture fx = {
		.loop = loop,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};

	/* srv_a: mux listener announcing identity "node-a"; accepts srv_b. */
	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_a) failed");
	}
	fx.conf_a->identity.claim = strdup("node-a");
	if (fx.conf_a->identity.claim == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf_a identity");
	}

	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}
	if (wait_for_listener_port(
		    &fx, &fx.srv_a->mux_listener, &fx.mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		FIXTURE_FATAL(&fx, "srv_a mux port wait failed");
	}

	char mux_connect_a[64];
	(void)snprintf(
		mux_connect_a, sizeof(mux_connect_a), "127.0.0.1:%d",
		fx.mux_port_a);

	/* srv_b: dials srv_a via identity.mux_connect. */
	fx.conf_b = make_config(NULL, NULL, NULL, NULL);
	if (fx.conf_b == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_b) failed");
	}
	if (!build_identity_dialer_conf(fx.conf_b, mux_connect_a)) {
		FIXTURE_FATAL(&fx, "OOM building conf_b identity");
	}

	fx.srv_b = server_new(fx.loop, fx.conf_b);
	if (fx.srv_b == NULL || !server_start(fx.srv_b)) {
		FIXTURE_FATAL(&fx, "srv_b start failed");
	}

	/* Wait for srv_b's dial-out to establish and land in the "node-a" pool. */
	struct identity_pool_wait_ctx wait_ctx = {
		.srv_a = fx.srv_b,
		.peer_identity = "node-a",
		.expected = 1,
	};
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    identity_pool_wait_predicate, &wait_ctx) != 0) {
		FIXTURE_FATAL(
			&fx, "identity.mux_connect dial-out did not establish");
	}
	if (fx.srv_b->num_identity_tunnels != 1) {
		FIXTURE_FATAL(&fx, "expected exactly one identity slot");
	}

	/* Free the slot (the tunnel stays alive in the "node-a" pool, so nothing
	 * leaks), then drive one maintenance tick synchronously. */
	struct tunnel *const orphan = fx.srv_b->identity_tunnels[0];
	fx.srv_b->identity_tunnels[0] = NULL;
	ev_invoke(fx.loop, &fx.srv_b->w_maintenance, EV_TIMER);
	struct tunnel *const redialed = fx.srv_b->identity_tunnels[0];

	fixture_teardown(&fx);

	/* The freed slot was re-dialed with a fresh tunnel on the maintenance
	 * tick, not left empty until a later reload. */
	T_EXPECT(orphan != NULL);
	T_EXPECT(redialed != NULL);
	T_EXPECT(redialed != orphan);
}

/* The maintenance tick is deferred work, not a heartbeat: it must be disarmed
 * on a freshly started server with nothing outstanding, and a pass that finds
 * no work must stop it rather than leave a standing wakeup behind. */
T_DECLARE_CASE(test_server_maintenance_timer_stops_when_idle)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct config *conf = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf == NULL) {
		ev_loop_destroy(loop);
		T_FATAL("make_config failed");
	}
	struct server *const srv = server_new(loop, conf);
	if (srv == NULL || !server_start(srv)) {
		if (srv != NULL) {
			server_stop(srv);
			server_free(srv);
		}
		conf_free(conf);
		ev_loop_destroy(loop);
		T_FATAL("server_start failed");
	}

	/* Nothing is outstanding, so starting the server must not arm it. */
	const bool idle_after_start = !ev_is_active(&srv->w_maintenance);

	/* Armed with no work behind it, the pass it runs must disarm it again. */
	ev_timer_again(loop, &srv->w_maintenance);
	const bool armed = ev_is_active(&srv->w_maintenance);
	const uint_least64_t before = srv->maintenance_passes;
	ev_invoke(loop, &srv->w_maintenance, EV_TIMER);
	const bool stopped_itself = !ev_is_active(&srv->w_maintenance);
	const uint_least64_t after = srv->maintenance_passes;

	server_stop(srv);
	server_free(srv);
	conf_free(conf);
	ev_loop_destroy(loop);

	T_EXPECT(idle_after_start);
	T_EXPECT(armed);
	T_EXPECT(stopped_itself);
	T_EXPECT(after == before + 1);
}

/* Regression for "server_start_identity_listeners crashes on a NULL
 * identity.peers[].listen": an identity used only for routing/pooling, with
 * no per-peer TCP forward port, must start cleanly instead of dereferencing
 * NULL in resolve_bindaddr/split_addr. */
T_DECLARE_CASE(test_server_start_identity_peer_with_null_listen)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct test_fixture fx = {
		.loop = loop,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};

	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	fx.conf_a->identity.claim = strdup("server-a");
	fx.conf_a->identity.peers = malloc(sizeof(*fx.conf_a->identity.peers));
	if (fx.conf_a->identity.claim == NULL ||
	    fx.conf_a->identity.peers == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf identity fields");
	}
	fx.conf_a->identity.peers[0] = (struct identity_peer){
		.id = strdup("routing-only-peer"),
		.listen = NULL,
	};
	fx.conf_a->identity.peers_count = 1;
	if (fx.conf_a->identity.peers[0].id == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf peer id");
	}

	fx.srv_a = server_new(fx.loop, fx.conf_a);
	const bool started = fx.srv_a != NULL && server_start(fx.srv_a);

	fixture_teardown(&fx);

	T_EXPECT(started);
}

/* test_server_max_sessions_rejects: exercises max_sessions via
 * is_startup_limited(). Lowers limit and fakes num_sessions; the next
 * inbound connection must be closed immediately. */
T_DECLARE_CASE(test_server_max_sessions_rejects)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	/* Clamp the limit below the faked session count. */
	fx.srv_a->conf->max_sessions = 1;

	/* Fake num_sessions == 2 so the check (2 > 1) fires. */
#if WITH_THREADS
	atomic_store_explicit(
		&fx.srv_a->counters.num_sessions, 2, memory_order_relaxed);
#else
	fx.srv_a->counters.num_sessions = 2;
#endif

	/* Open a raw TCP connection to the mux listener; expect immediate
	 * close (server rejects it via is_startup_limited). */
	const int raw = connect_local(&fx, fx.mux_port_a);
	if (raw < 0) {
		FIXTURE_FATAL(&fx, "connect_local to mux port failed");
	}

	/* Drive until the connection is rejected and closed; server closes
	 * the fd synchronously in mux_serve, so one event-loop iteration
	 * is sufficient. */
	const int revents = wait_fd_events(
		&fx, raw, EV_READ, (double)CONNECT_WAIT_TIMEOUT_MS / 1000.0);
	T_CHECK((revents & EV_READ) != 0);

	char buf[1];
	const ssize_t n = read(raw, buf, sizeof(buf));
	(void)close(raw);

	/* Defer assertions until after teardown; failing early would leak the
	 * loop's signal watchers and corrupt later tests in this process. */
	const bool rejected = fx.srv_a->counters.num_rejected > 0;

	/* Restore the faked counter so the fixture tears down cleanly. */
#if WITH_THREADS
	atomic_store_explicit(
		&fx.srv_a->counters.num_sessions, 1, memory_order_relaxed);
#else
	fx.srv_a->counters.num_sessions = 1;
#endif
	fx.srv_a->conf->max_sessions = 0;

	fixture_teardown(&fx);

	T_EXPECT_EQ(n, (ssize_t)0); /* peer closed the connection */
	T_EXPECT(rejected);
}

/* is_startup_limited() must reject once the existing count already equals
 * the configured limit, not only once it exceeds it -- the check runs
 * before this connection is counted, so count == limit already means
 * admitting this one would make limit + 1. Distinguishes >= from the
 * pre-fix strict >, which test_server_max_sessions_rejects above (count one
 * past the limit) cannot: that case rejects under either operator. */
T_DECLARE_CASE(test_server_max_sessions_rejects_at_exact_limit)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	fx.srv_a->conf->max_sessions = 2;
#if WITH_THREADS
	atomic_store_explicit(
		&fx.srv_a->counters.num_sessions, 2, memory_order_relaxed);
#else
	fx.srv_a->counters.num_sessions = 2;
#endif

	const int raw = connect_local(&fx, fx.mux_port_a);
	if (raw < 0) {
		FIXTURE_FATAL(&fx, "connect_local to mux port failed");
	}

	const int revents = wait_fd_events(
		&fx, raw, EV_READ, (double)CONNECT_WAIT_TIMEOUT_MS / 1000.0);
	T_CHECK((revents & EV_READ) != 0);

	char buf[1];
	const ssize_t n = read(raw, buf, sizeof(buf));
	(void)close(raw);

	/* Defer assertions until after teardown; failing early would leak the
	 * loop's signal watchers and corrupt later tests in this process. */
	const bool rejected = fx.srv_a->counters.num_rejected > 0;

#if WITH_THREADS
	atomic_store_explicit(
		&fx.srv_a->counters.num_sessions, 1, memory_order_relaxed);
#else
	fx.srv_a->counters.num_sessions = 1;
#endif
	fx.srv_a->conf->max_sessions = 0;

	fixture_teardown(&fx);

	T_EXPECT_EQ(n, (ssize_t)0);
	T_EXPECT(rejected);
}

/* startup_limit_start == 0 is a valid, explicit "throttle from the first
 * connection" configuration, not "disabled". rate=100 makes the
 * probabilistic reject deterministic (frand() in [0,1), so frand()*100
 * < 100 always holds). */
T_DECLARE_CASE(test_server_startup_limit_zero_start_throttles_first_connection)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	fx.srv_a->conf->startup_limit_start = 0;
	fx.srv_a->conf->startup_limit_rate = 100;
	fx.srv_a->conf->startup_limit_full = 100;

	const int raw = connect_local(&fx, fx.mux_port_a);
	if (raw < 0) {
		FIXTURE_FATAL(&fx, "connect_local to mux port failed");
	}

	const int revents = wait_fd_events(
		&fx, raw, EV_READ, (double)CONNECT_WAIT_TIMEOUT_MS / 1000.0);
	T_CHECK((revents & EV_READ) != 0);

	char buf[1];
	const ssize_t n = read(raw, buf, sizeof(buf));
	(void)close(raw);

	/* Defer assertions until after teardown; failing early would leak the
	 * loop's signal watchers and corrupt later tests in this process. */
	const bool rejected = fx.srv_a->counters.num_rejected > 0;

	fx.srv_a->conf->startup_limit_start = 0;
	fx.srv_a->conf->startup_limit_rate = 0;
	fx.srv_a->conf->startup_limit_full = 0;

	fixture_teardown(&fx);

	T_EXPECT_EQ(n, (ssize_t)0);
	T_EXPECT(rejected);
}

struct establish_count_ctx {
	const struct server *srv;
};

/* Predicate: srv has published at least one stream-establish sample. */
static int stream_establish_recorded_predicate(void *ptr)
{
	const struct establish_count_ctx *const restrict ctx = ptr;
	struct server_stats *const st = server_stats(ctx->srv, true);
	if (st == NULL) {
		return 0;
	}
	const bool ok = st->stream_establish_count > 0;
	free(st);
	return ok ? 1 : 0;
}

/* Count the snapshot's tunnels that hold ring samples, and how many of those
 * carry derived percentiles.  With want_tunnel_latency the two must agree;
 * without it the second must be zero. */
static void count_tunnel_percentiles(
	const struct server_stats *restrict st, size_t *restrict sampled,
	size_t *restrict derived)
{
	*sampled = 0;
	*derived = 0;
	for (size_t i = 0; i < st->num_tunnels; i++) {
		const struct tunnel_stats *const restrict ts = &st->tunnels[i];
		if (ts->stream_establish_count > 0) {
			(*sampled)++;
		}
		if (ts->stream_establish_p50 != 0 ||
		    ts->stream_establish_p90 != 0 ||
		    ts->stream_establish_p99 != 0) {
			(*derived)++;
		}
	}
}

/* calc_stream_percentiles (ring-merge -> qsort -> percentile-index selection)
 * runs whenever the dialing side records SYN->SYN|ACK samples, but no test ever
 * asserted its output. Open several streams from srv_b (which dials srv_a) and
 * check the reported count and percentile ordering. */
T_DECLARE_CASE(test_server_stream_establish_percentiles)
{
	struct test_fixture fx;
	int cls[4] = { -1, -1, -1, -1 };
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	for (size_t i = 0; i < 4; i++) {
		if (connect_and_wait_echo(
			    &fx, fx.tcp_port_b, "estab", &cls[i]) != 0) {
			FIXTURE_FATAL(&fx, "connect_and_wait_echo failed");
		}
	}
	/* Wait until srv_b has published at least one establish sample. */
	struct establish_count_ctx ctx = { .srv = fx.srv_b };
	const int waited = wait_until(
		&fx, (double)STREAM_WAIT_TIMEOUT_MS / 1000.0,
		stream_establish_recorded_predicate, &ctx);

	struct server_stats *const st = server_stats(fx.srv_b, true);
	size_t count = 0;
	int_least64_t p50 = 0, p90 = 0, p99 = 0, pmax = 0;
	/* Per-tunnel percentiles are derived only when asked for. */
	size_t sampled = 0, derived = 0, unasked_derived = 0;
	if (st != NULL) {
		count = st->stream_establish_count;
		p50 = st->stream_establish_p50;
		p90 = st->stream_establish_p90;
		p99 = st->stream_establish_p99;
		pmax = st->stream_establish_pmax;
		count_tunnel_percentiles(st, &sampled, &derived);
		free(st);
	}
	/* The same snapshot without want_tunnel_latency must leave them zero --
	 * every route but GET /metrics discards them, so none should pay the
	 * per-tunnel sort. */
	struct server_stats *const st_plain = server_stats(fx.srv_b, false);
	if (st_plain != NULL) {
		size_t ignored = 0;
		count_tunnel_percentiles(st_plain, &ignored, &unasked_derived);
		free(st_plain);
	}
	for (size_t i = 0; i < 4; i++) {
		if (cls[i] >= 0) {
			(void)close(cls[i]);
		}
	}
	fixture_teardown(&fx);

	T_EXPECT_EQ(waited, 0);
	T_EXPECT(count > 0);
	T_EXPECT(p50 <= p90);
	T_EXPECT(p90 <= p99);
	T_EXPECT(p99 <= pmax);
	/* Asked for: every tunnel holding samples gets its own percentiles. */
	T_EXPECT(sampled > 0);
	T_EXPECT_EQ(derived, sampled);
	/* Not asked for: none does. */
	T_EXPECT_EQ(unasked_derived, (size_t)0);
}

/* The sibling case above drives the dialing side only, which is what let
 * tunnel.h claim the ring is "populated only for dialed tunnels" and server.c
 * claim the merge covers "all dialed tunnels". Neither is true: the ring is fed
 * by every active open regardless of session role, and srv_a -- which accepted
 * srv_b's connection -- round-robins its own local connections over
 * accepted_tunnels. A reader trusting those comments could drop accepted
 * tunnels from the /stats percentiles, so pin that they contribute. */
T_DECLARE_CASE(test_server_stream_establish_percentiles_accepted_side)
{
	struct test_fixture fx;
	int cls[4] = { -1, -1, -1, -1 };
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	/* srv_a accepted the session; these open streams over that accepted
	 * tunnel. */
	for (size_t i = 0; i < 4; i++) {
		if (connect_and_wait_echo(
			    &fx, fx.tcp_port_a, "estab-accepted", &cls[i]) !=
		    0) {
			FIXTURE_FATAL(&fx, "connect_and_wait_echo failed");
		}
	}
	struct establish_count_ctx ctx = { .srv = fx.srv_a };
	const int waited = wait_until(
		&fx, (double)STREAM_WAIT_TIMEOUT_MS / 1000.0,
		stream_establish_recorded_predicate, &ctx);

	struct server_stats *const st = server_stats(fx.srv_a, true);
	size_t count = 0;
	size_t sampled = 0, derived = 0;
	if (st != NULL) {
		count = st->stream_establish_count;
		count_tunnel_percentiles(st, &sampled, &derived);
		free(st);
	}
	for (size_t i = 0; i < 4; i++) {
		if (cls[i] >= 0) {
			(void)close(cls[i]);
		}
	}
	fixture_teardown(&fx);

	T_EXPECT_EQ(waited, 0);
	/* The accepted side's samples reach the merged percentiles. */
	T_EXPECT(count > 0);
	T_EXPECT(sampled > 0);
	T_EXPECT_EQ(derived, sampled);
}

/* server_evlog is a documented diagnostic ring, but no test read it. Two
 * consecutive reloads with no active sessions emit two identical "config
 * reloaded" messages, which must dedup into one entry with occurrence count 2. */
T_DECLARE_CASE(test_server_evlog_dedups_consecutive_reload_events)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct test_fixture fx = {
		.loop = loop,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};

	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_a) failed");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}

	for (int i = 0; i < 2; i++) {
		struct config *const nc =
			make_config("127.0.0.1:0", NULL, NULL, NULL);
		if (nc == NULL) {
			FIXTURE_FATAL(&fx, "make_config(reload) failed");
		}
		if (!server_apply_config(fx.srv_a, nc)) {
			FIXTURE_FATAL(&fx, "server_apply_config failed");
		}
		fx.conf_a = fx.srv_a->conf; /* old conf freed by apply */
	}

	struct server_stats *const st = server_stats(fx.srv_a, true);
	size_t len = 0;
	size_t last_count = 0;
	char last_msg[256] = { 0 };
	if (st != NULL && st->evlog != NULL) {
		const struct server_evlog *const el = st->evlog;
		len = el->len;
		if (el->len > 0) {
			const size_t cap =
				sizeof(el->entries) / sizeof(el->entries[0]);
			const size_t last = (el->pos + cap - 1) % cap;
			last_count = el->entries[last].count;
			(void)snprintf(
				last_msg, sizeof(last_msg), "%s",
				el->entries[last].message);
		}
		free(st);
	}
	fixture_teardown(&fx);

	T_EXPECT(len >= 1);
	T_EXPECT_STREQ(last_msg, "config reloaded");
	T_EXPECT_EQ(last_count, (size_t)2);
}

/* Predicate: srv_a's graceful shutdown has drained every session. */
static int srv_a_sessions_drained_predicate(void *ptr)
{
	const struct test_fixture *const restrict fx = ptr;
	struct server_stats *const st = server_stats(fx->srv_a, true);
	if (st == NULL) {
		return 0;
	}
	const bool drained = st->num_tunnels == 0;
	free(st);
	return drained ? 1 : 0;
}

/* test_server_graceful_shutdown_via_signal: fires srv_a's SIGTERM watcher
 * directly (bypassing srv_b), drives the loop until listeners stop, and
 * verifies teardown stays clean. */
T_DECLARE_CASE(test_server_graceful_shutdown_via_signal)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	/* Invoke srv_a's SIGTERM watcher directly; using ev_feed_signal_event
	 * would also fire srv_b's watcher and complicate teardown ordering. */
	ev_invoke(fx.loop, &fx.srv_a->w_sigterm, EV_SIGNAL);

	/* Drive until signal_cb has stopped the mux listener (synchronous
	 * side-effect of the signal handler). */
	const ev_tstamp deadline =
		mono_now() + (double)SETUP_WAIT_TIMEOUT_MS / 1000.0;
	while (fx.srv_a->mux_listener.w_accept.fd != -1 &&
	       mono_now() < deadline) {
		drive_loop_once(&fx);
	}
	T_CHECK(fx.srv_a->mux_listener.w_accept.fd == -1);
	T_CHECK(fx.srv_a->local_listener.w_accept.fd == -1);

	/* Drive the graceful shutdown until it has actually drained srv_a's
	 * sessions, rather than a fixed settle count; bounded, and teardown
	 * force-closes anything still lingering if the drain does not complete. */
	(void)wait_until(
		&fx, (double)SETUP_WAIT_TIMEOUT_MS / 1000.0,
		srv_a_sessions_drained_predicate, &fx);

	fixture_teardown(&fx);
}

/* server_apply_config()'s SIGHUP reload path must honor an explicit --loglevel
 * (server->loglevel_override): with no override the reloaded config's level
 * takes effect, but a set override wins -- matching main()'s boot-path choice
 * so `systemctl reload` cannot silently revert the operator's --loglevel. Uses
 * an unstarted server with identical listen addresses so the reload touches no
 * listeners/identities/tunnels. */
T_DECLARE_CASE(test_server_apply_config_honors_cli_loglevel_override)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	struct config *const conf =
		make_config("127.0.0.1:0", NULL, NULL, NULL);
	T_CHECK(conf != NULL);
	struct server *const srv = server_new(loop, conf);
	T_CHECK(srv != NULL);

	const int saved_level = slog_level_;

	/* No CLI override: the reloaded config's loglevel takes effect. */
	srv->loglevel_override = -1;
	struct config *const nc1 = make_config("127.0.0.1:0", NULL, NULL, NULL);
	T_CHECK(nc1 != NULL);
	nc1->loglevel = LOG_LEVEL_ERROR;
	const bool applied_no_override = server_apply_config(srv, nc1);
	const int level_no_override = slog_level_;

	/* CLI override in effect: it wins over the reloaded config's loglevel. */
	srv->loglevel_override = LOG_LEVEL_DEBUG;
	struct config *const nc2 = make_config("127.0.0.1:0", NULL, NULL, NULL);
	T_CHECK(nc2 != NULL);
	nc2->loglevel = LOG_LEVEL_WARNING;
	const bool applied_override = server_apply_config(srv, nc2);
	const int level_override = slog_level_;

	slog_setlevel(saved_level);
	/* server_free() does not free srv->conf (main() frees the final config
	 * separately); reclaim the last-applied config here to match. */
	struct config *const final_conf = srv->conf;
	server_free(srv);
	conf_free(final_conf);
	ev_loop_destroy(loop);

	T_EXPECT(applied_no_override);
	T_EXPECT_EQ(level_no_override, LOG_LEVEL_ERROR);
	T_EXPECT(applied_override);
	T_EXPECT_EQ(level_override, LOG_LEVEL_DEBUG);
}

/* Read srv's client-mode reconnect total: the counter is per-tunnel, so this
 * goes through the same aggregate the /stats page reports.  Returns 0 if the
 * snapshot cannot be allocated. */
static uint_least64_t server_num_reconnects(const struct server *restrict s)
{
	struct server_stats *const restrict stats = server_stats(s, true);
	if (stats == NULL) {
		return 0;
	}
	const uint_least64_t n = stats->num_reconnects;
	free(stats);
	return n;
}

struct reconnect_wait_ctx {
	const struct server *srv;
	uint_least64_t baseline;
};

/* Predicate: srv's reconnect counter has advanced past the recorded baseline. */
static int reconnect_moved_predicate(void *ptr)
{
	const struct reconnect_wait_ctx *const restrict ctx = ptr;
	return server_num_reconnects(ctx->srv) > ctx->baseline ? 1 : 0;
}

/* suspend_cb(): a suspend-clock advance that the monotonic clock did not match,
 * larger than SUSPEND_JUMP_S, is read as a resume-from-suspend and drops every
 * transport, so each dialed tunnel reconnects. Back-date srv_b's suspend-clock
 * baseline by an hour, fire the check watcher, and assert its mux dial-out's
 * transport was dropped and reconnected (the counter moved). */
T_DECLARE_CASE(test_server_maintenance_suspend_drops_transports_and_reconnects)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	/* srv_b is the dialer; its mux_tunnel holds a client transport that the
	 * suspend handler must drop and reconnect. */
	const uint_least64_t before = server_num_reconnects(fx.srv_b);

	/* Make the next suspend check observe an hour the monotonic clock did
	 * not see, and clear the throttle so the check actually runs. */
	fx.srv_b->last_check_at = 0.0;
	fx.srv_b->last_check_elapsed_ns -=
		(int_least64_t)3600 * INT64_C(1000000000);
	ev_invoke(fx.loop, &fx.srv_b->w_suspend, EV_CHECK);

	struct reconnect_wait_ctx ctx = {
		.srv = fx.srv_b,
		.baseline = before,
	};
	const int waited = wait_until(
		&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		reconnect_moved_predicate, &ctx);
	const uint_least64_t after = server_num_reconnects(fx.srv_b);

	fixture_teardown(&fx);

	T_EXPECT_EQ(waited, 0);
	T_EXPECT(after > before);
}

/* Safety net for the shutdown-deadline test: records that it fired and breaks
 * the loop, so a maintenance_cb that fails to force the exit cannot hang. */
static void maintenance_safety_break_cb(
	struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)revents;
	*(bool *)w->data = true;
	ev_break(loop, EVBREAK_ALL);
}

/* maintenance_cb()'s highest-priority task: while shutting_down, once the
 * force-exit deadline (2s past shutdown_start_ns) has elapsed it must break the
 * event loop. Enter shutdown with an already-expired deadline, drive the
 * maintenance timer promptly, and assert the loop broke via maintenance_cb --
 * not via the safety net that bounds the run. */
T_DECLARE_CASE(test_server_maintenance_shutdown_deadline_breaks_loop)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct config *conf = NULL;
	struct server *srv = NULL;
	ev_timer w_safety;
	bool have_safety = false;
	bool safety_fired = false;
	bool started = false;

	conf = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf == NULL) {
		T_FAIL();
		goto cleanup;
	}
	srv = server_new(loop, conf);
	if (srv == NULL || !server_start(srv)) {
		T_FAIL();
		goto cleanup;
	}
	started = true;

	/* Bound the run: if maintenance_cb fails to break, the safety timer breaks
	 * it after a fixed delay and records that it had to. */
	ev_timer_init(&w_safety, maintenance_safety_break_cb, 2.0, 0.0);
	w_safety.data = &safety_fired;
	ev_timer_start(loop, &w_safety);
	have_safety = true;

	/* Enter shutdown: from here the watcher IS the force-exit deadline, so
	 * reaching it must break the loop. */
	srv->shutting_down = true;

	/* Re-arm the deadline to fire almost immediately rather than after its
	 * full 2s period, then let the loop run it. */
	srv->w_maintenance.repeat = 0.01;
	ev_timer_again(loop, &srv->w_maintenance);
	ev_run(loop, 0);

cleanup:
	if (have_safety) {
		ev_timer_stop(loop, &w_safety);
	}
	if (srv != NULL) {
		server_stop(srv);
		struct config *const final_conf = srv->conf;
		server_free(srv);
		conf_free(final_conf);
	} else if (conf != NULL) {
		conf_free(conf);
	}
	ev_loop_destroy(loop);

	T_EXPECT(started);
	/* The loop broke on maintenance_cb's deadline, before the safety net. */
	T_EXPECT(!safety_fired);
}

#if WITH_THREADS
/* server_apply_config() creates and starts tunnels on its own, so threads that
 * signal srv->w_async through server_post_task() can exist before (or without)
 * server_start() ever running. ev_async_start() is also what makes libev arm the
 * loop's internal pipe watcher, so arming w_async only in server_start() left
 * that send writing a pipe nothing watched, aborting the next ev_run() from
 * inside libev. Drive exactly that sequence deterministically -- no threads: a
 * server that was never started, one send, one loop iteration. */
T_DECLARE_CASE(test_server_new_arms_async_before_start)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct config *const conf =
		make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf == NULL) {
		T_FAIL();
		ev_loop_destroy(loop);
		return;
	}
	struct server *const srv = server_new(loop, conf);
	if (srv == NULL) {
		T_FAIL();
		conf_free(conf);
		ev_loop_destroy(loop);
		return;
	}

	/* The deterministic check: the armed watcher is what makes the send below
	 * safe, and it is what regressed. */
	T_EXPECT(ev_is_active(&srv->w_async));
	/* Exactly what server_post_task() does from a tunnel thread, followed by
	 * one loop iteration. Reproducing the abort itself needs a loop carrying
	 * other active watchers, which is what the real failure had; here this
	 * just walks the path. */
	ev_async_send(loop, &srv->w_async);
	ev_run(loop, EVRUN_NOWAIT);

	server_stop(srv);
	struct config *const final_conf = srv->conf;
	server_free(srv);
	conf_free(final_conf);
	ev_loop_destroy(loop);
}

/* w_async stays armed for the object's whole lifetime, so the destructor -- not
 * only server_stop() -- has to hand its loop registration back; otherwise a
 * server freed without a stop leaves a dangling entry in the loop's async array.
 * Send before freeing so the ev_run() below actually walks that array, which is
 * where the stale entry gets dereferenced. */
T_DECLARE_CASE(test_server_free_releases_async_without_stop)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct config *const conf =
		make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf == NULL) {
		T_FAIL();
		ev_loop_destroy(loop);
		return;
	}
	struct server *const srv = server_new(loop, conf);
	if (srv == NULL) {
		T_FAIL();
		conf_free(conf);
		ev_loop_destroy(loop);
		return;
	}
	/* Precondition: without an armed watcher the free below releases nothing
	 * and the case would pass vacuously. */
	T_EXPECT(ev_is_active(&srv->w_async));

	ev_async_send(loop, &srv->w_async);
	/* Deliberately no server_stop(): the destructor alone must release it. */
	server_free(srv);
	conf_free(conf);

	ev_run(loop, EVRUN_NOWAIT);
	ev_loop_destroy(loop);
}
#endif /* WITH_THREADS */

struct pool_used_wait_ctx {
	const struct server *srv;
	const char *peer_identity;
};

/* Predicate: at least two tunnels pooled under peer_identity have each had a
 * stream actively opened on them (num_stream_opened > 0), i.e. round-robin has
 * dispatched across both. */
static int pool_both_tunnels_used_predicate(void *ptr)
{
	const struct pool_used_wait_ctx *const restrict ctx = ptr;
	struct server_stats *const stats = server_stats(ctx->srv, true);
	if (stats == NULL) {
		return 0;
	}
	size_t pooled = 0;
	size_t used = 0;
	for (size_t i = 0; i < stats->num_tunnels; i++) {
		const struct tunnel_stats *const ts = &stats->tunnels[i];
		if (ts->peer_identity == NULL ||
		    strcmp(ts->peer_identity, ctx->peer_identity) != 0) {
			continue;
		}
		pooled++;
		if (ts->num_stream_opened > 0) {
			used++;
		}
	}
	free(stats);
	return (pooled >= 2 && used >= 2) ? 1 : 0;
}

/* Covers identity_tcp_serve()'s pick->tunnel_open_stream branch and
 * identity_listener_pick()'s round-robin dispatch. srv_a runs an identity
 * listener for "peer-x" whose pool holds two dialed-in tunnels (srv_c[0] and
 * srv_c[1], both claiming "peer-x" and forwarding to a shared echo backend).
 * Driving several TCP connections through the identity listener's port must
 * echo end-to-end and, by round-robin, open a stream on each pooled tunnel, so
 * both report a nonzero opened-stream count. */
T_DECLARE_CASE(test_server_identity_listener_forwards_over_pool)
{
	/* All resources are declared up front and NULL/sentinel-initialized so
	 * the single cleanup block handles a T_FAIL at any setup stage without
	 * leaking the loop, backend, servers, or configs. */
	struct ev_loop *loop = NULL;
	struct config *conf_a = NULL;
	struct server *srv_a = NULL;
	struct config *conf_c[2] = { NULL, NULL };
	struct server *srv_c[2] = { NULL, NULL };
	struct mock_server backend = { .listen_fd = -1, .port = -1 };
	struct test_fixture fx = { 0 };
	int mux_port_a = -1;
	int id_port = -1;
	char mux_connect_a[64];
	char connect_backend[64];
	int wait_pool_rc = -1;
	int echo_rc = 0;
	int both_used_rc = -1;
	bool setup_ok = false;

	loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.loop = loop;

	if (mock_server_start(&backend, loop, MOCK_ECHO) != 0) {
		T_FAIL();
		goto cleanup;
	}
	(void)snprintf(
		connect_backend, sizeof(connect_backend), "127.0.0.1:%d",
		backend.port);

	conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf_a == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.claim = strdup("server-a");
	conf_a->identity.peers = malloc(sizeof(*conf_a->identity.peers));
	if (conf_a->identity.claim == NULL || conf_a->identity.peers == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.peers[0] = (struct identity_peer){
		.id = strdup("peer-x"),
		.listen = strdup("127.0.0.1:0"),
	};
	conf_a->identity.peers_count = 1;
	if (conf_a->identity.peers[0].id == NULL ||
	    conf_a->identity.peers[0].listen == NULL) {
		T_FAIL();
		goto cleanup;
	}

	srv_a = server_new(loop, conf_a);
	if (srv_a == NULL || !server_start(srv_a)) {
		T_FAIL();
		goto cleanup;
	}
	fx.srv_a = srv_a;

	if (wait_for_listener_port(
		    &fx, &srv_a->mux_listener, &mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_FAIL();
		goto cleanup;
	}
	(void)snprintf(
		mux_connect_a, sizeof(mux_connect_a), "127.0.0.1:%d",
		mux_port_a);

	/* Two independent dialers, both claiming "peer-x", each forwarding
	 * inbound streams to the shared echo backend. */
	for (size_t i = 0; i < 2; i++) {
		conf_c[i] =
			make_config(NULL, mux_connect_a, NULL, connect_backend);
		if (conf_c[i] == NULL) {
			T_FAIL();
			goto cleanup;
		}
		conf_c[i]->identity.claim = strdup("peer-x");
		if (conf_c[i]->identity.claim == NULL) {
			T_FAIL();
			goto cleanup;
		}
		srv_c[i] = server_new(loop, conf_c[i]);
		if (srv_c[i] == NULL || !server_start(srv_c[i])) {
			T_FAIL();
			goto cleanup;
		}
	}
	setup_ok = true;

	/* Wait for both dial-outs to establish and land in srv_a's "peer-x" pool. */
	struct identity_pool_wait_ctx pool_ctx = {
		.srv_a = srv_a,
		.peer_identity = "peer-x",
		.expected = 2,
	};
	wait_pool_rc = wait_until(
		&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		identity_pool_wait_predicate, &pool_ctx);
	if (wait_pool_rc != 0) {
		goto cleanup;
	}

	/* Resolve the identity listener's TCP port from srv_a's (single-entry)
	 * identity table. */
	{
		size_t cursor = 0;
		void *elem = NULL;
		if (table_next(srv_a->identities, &cursor, NULL, &elem)) {
			struct identity_listener *const restrict sl = elem;
			id_port = get_listener_port(&sl->listener);
		}
	}
	if (id_port <= 0) {
		echo_rc = -1;
		goto cleanup;
	}

	/* Drive several connections through the identity listener; round-robin
	 * must spread them across both pooled tunnels. */
	for (int i = 0; i < 4; i++) {
		const int cl = connect_local(&fx, id_port);
		if (cl < 0) {
			echo_rc = -1;
			break;
		}
		if (send_and_expect_echo(
			    &fx, cl, "id-echo", strlen("id-echo"),
			    (double)ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0) {
			echo_rc = -1;
			(void)close(cl);
			break;
		}
		(void)close(cl);
	}

	struct pool_used_wait_ctx used_ctx = {
		.srv = srv_a,
		.peer_identity = "peer-x",
	};
	both_used_rc = wait_until(
		&fx, (double)STREAM_WAIT_TIMEOUT_MS / 1000.0,
		pool_both_tunnels_used_predicate, &used_ctx);

cleanup:
	for (size_t i = 0; i < 2; i++) {
		if (srv_c[i] != NULL) {
			server_stop(srv_c[i]);
			server_free(srv_c[i]);
		}
	}
	if (srv_a != NULL) {
		server_stop(srv_a);
		server_free(srv_a);
	}
	for (size_t i = 0; i < 2; i++) {
		if (conf_c[i] != NULL) {
			conf_free(conf_c[i]);
		}
	}
	if (conf_a != NULL) {
		conf_free(conf_a);
	}
	mock_server_stop(&backend);
	if (loop != NULL) {
		ev_loop_destroy(loop);
	}

	/* Assertions deferred past teardown: reaching a fatal T_EXPECT before the
	 * servers/loop are freed would leak a live ev_loop with registered signal
	 * watchers and wedge later tests in this process. */
	if (setup_ok) {
		T_EXPECT_EQ(wait_pool_rc, 0);
		T_EXPECT_EQ(echo_rc, 0);
		T_EXPECT_EQ(both_used_rc, 0);
	}
}

/* Covers identity_tcp_serve()'s empty-pool branch: with no dialed-in tunnels,
 * identity_listener_pick() returns NULL and the accepted connection is closed
 * immediately. srv_a's "peer-x" identity listener is started but no peer ever
 * connects, so a TCP client on its port must observe an immediate EOF. */
T_DECLARE_CASE(test_server_identity_listener_empty_pool_closes_conn)
{
	struct ev_loop *loop = NULL;
	struct config *conf_a = NULL;
	struct server *srv_a = NULL;
	struct test_fixture fx = { 0 };
	int id_port = -1;
	int cl = -1;
	int eof_rc = -1;
	bool setup_ok = false;

	loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.loop = loop;

	conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf_a == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.claim = strdup("server-a");
	conf_a->identity.peers = malloc(sizeof(*conf_a->identity.peers));
	if (conf_a->identity.claim == NULL || conf_a->identity.peers == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_a->identity.peers[0] = (struct identity_peer){
		.id = strdup("peer-x"),
		.listen = strdup("127.0.0.1:0"),
	};
	conf_a->identity.peers_count = 1;
	if (conf_a->identity.peers[0].id == NULL ||
	    conf_a->identity.peers[0].listen == NULL) {
		T_FAIL();
		goto cleanup;
	}

	srv_a = server_new(loop, conf_a);
	if (srv_a == NULL || !server_start(srv_a)) {
		T_FAIL();
		goto cleanup;
	}
	fx.srv_a = srv_a;

	{
		size_t cursor = 0;
		void *elem = NULL;
		if (table_next(srv_a->identities, &cursor, NULL, &elem)) {
			struct identity_listener *const restrict sl = elem;
			id_port = get_listener_port(&sl->listener);
		}
	}
	if (id_port <= 0) {
		T_FAIL();
		goto cleanup;
	}
	setup_ok = true;

	/* Connect (but never send): the server has no pooled tunnel to forward
	 * over, so identity_tcp_serve closes the accepted fd and the client sees
	 * an orderly EOF. */
	cl = connect_local(&fx, id_port);
	if (cl < 0) {
		goto cleanup;
	}
	eof_rc = wait_for_peer_eof(
		&fx, cl, (double)PEER_EOF_WAIT_TIMEOUT_MS / 1000.0);

cleanup:
	if (cl >= 0) {
		(void)close(cl);
	}
	if (srv_a != NULL) {
		server_stop(srv_a);
		server_free(srv_a);
	}
	if (conf_a != NULL) {
		conf_free(conf_a);
	}
	if (loop != NULL) {
		ev_loop_destroy(loop);
	}

	if (setup_ok) {
		T_EXPECT_EQ(eof_rc, 0);
	}
}

/* Regression: an API connection still mid-request when the server stops must be
 * reclaimed by server_stop(), not left behind with its context and open fd. The
 * client sends a request whose body it withholds under Expect: 100-continue; the
 * interim response proves the server parsed the headers and is now waiting, and
 * that it consumed every byte sent, so the close that follows is an orderly FIN
 * the client reads as EOF. Untracked contexts outlived the server, and no EOF
 * ever arrived. */
T_DECLARE_CASE(test_server_stop_frees_inflight_api_connection)
{
	static const char req[] = "POST /config HTTP/1.1\r\n"
				  "Content-Length: 4\r\n"
				  "Expect: 100-continue\r\n"
				  "\r\n";
	static const char interim[] = "HTTP/1.1 100 Continue\r\n\r\n";

	struct ev_loop *loop = NULL;
	struct config *conf = NULL;
	struct server *srv = NULL;
	struct test_fixture fx = { 0 };
	int api_port = -1;
	int cl = -1;
	int interim_rc = -1;
	int eof_rc = -1;
	bool setup_ok = false;

	loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.loop = loop;

	conf = make_config(NULL, NULL, NULL, NULL);
	if (conf == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf->api_listen = strdup("127.0.0.1:0");
	if (conf->api_listen == NULL) {
		T_FAIL();
		goto cleanup;
	}

	srv = server_new(loop, conf);
	if (srv == NULL || !server_start(srv)) {
		T_FAIL();
		goto cleanup;
	}
	api_port = get_listener_port(&srv->api_listener);
	if (api_port <= 0) {
		T_FAIL();
		goto cleanup;
	}

	cl = connect_local(&fx, api_port);
	if (cl < 0) {
		T_FAIL();
		goto cleanup;
	}
	if (write_full(&fx, cl, req, sizeof(req) - 1) != 0) {
		T_FAIL();
		goto cleanup;
	}
	setup_ok = true;

	/* expect_echo() reads exactly this many bytes and compares them. */
	interim_rc = expect_echo(
		&fx, cl, interim, sizeof(interim) - 1,
		(double)IO_WAIT_TIMEOUT_MS / 1000.0);
	if (interim_rc != 0) {
		goto cleanup;
	}

	server_stop(srv);
	server_free(srv);
	srv = NULL;
	eof_rc = wait_for_peer_eof(
		&fx, cl, (double)PEER_EOF_WAIT_TIMEOUT_MS / 1000.0);

cleanup:
	if (cl >= 0) {
		(void)close(cl);
	}
	if (srv != NULL) {
		server_stop(srv);
		server_free(srv);
	}
	if (conf != NULL) {
		conf_free(conf);
	}
	if (loop != NULL) {
		ev_loop_destroy(loop);
	}

	if (setup_ok) {
		T_EXPECT_EQ(interim_rc, 0);
		T_EXPECT_EQ(eof_rc, 0);
	}
}

/* Collects every log record slog emits while registered as its writer sink. */
struct log_capture {
	size_t len;
	bool overflow;
	char buf[8192];
};

static void
log_capture_write(void *ud, const unsigned char *buf, const size_t len)
{
	struct log_capture *const restrict cap = ud;
	/* One byte is reserved for the NUL the string searches below need. */
	if (cap->len + len >= sizeof(cap->buf)) {
		cap->overflow = true;
		return;
	}
	memcpy(cap->buf + cap->len, buf, len);
	cap->len += len;
	cap->buf[cap->len] = '\0';
}

static int evlog_nonempty_predicate(void *ctx)
{
	const struct server_evlog *const restrict evlog = ctx;
	return evlog->len > 0 ? 1 : 0;
}

/* Regression: an identity is peer-supplied and, per doc/spec.md 5.2.3.2, only
 * NUL-excluded, so a claim carrying CR/LF or ESC would forge whole log records
 * and drive the terminal of whoever reads the log or GET /stats (CWE-117/150).
 * srv_a claims such an identity and srv_b dials it while pooling nothing under
 * it, which drives both output paths at once: the "matches no configured
 * identity.listen entry" warning, and the session event log that the /stats body
 * renders verbatim. Neither may carry a raw control byte, and the escaped
 * spelling must appear in its place. */
T_DECLARE_CASE(test_server_escapes_peer_identity_in_output)
{
	static const char crafted[] = "a\r\nE forged\x1b[31m";

	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct test_fixture fx = {
		.loop = loop,
		.mux_port_a = -1,
		.tcp_port_a = -1,
		.tcp_port_b = -1,
		.backend_a = { .listen_fd = -1, .port = -1 },
		.backend_b = { .listen_fd = -1, .port = -1 },
	};

	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_a) failed");
	}
	fx.conf_a->identity.claim = strdup(crafted);
	if (fx.conf_a->identity.claim == NULL) {
		FIXTURE_FATAL(&fx, "OOM building conf_a identity");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}
	if (wait_for_listener_port(
		    &fx, &fx.srv_a->mux_listener, &fx.mux_port_a,
		    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		FIXTURE_FATAL(&fx, "srv_a mux port wait failed");
	}

	char mux_connect_a[64];
	(void)snprintf(
		mux_connect_a, sizeof(mux_connect_a), "127.0.0.1:%d",
		fx.mux_port_a);
	fx.conf_b = make_config(NULL, NULL, NULL, NULL);
	if (fx.conf_b == NULL) {
		FIXTURE_FATAL(&fx, "make_config(conf_b) failed");
	}
	if (!build_identity_dialer_conf(fx.conf_b, mux_connect_a)) {
		FIXTURE_FATAL(&fx, "OOM building conf_b identity");
	}

	/* The suite runs at LOG_LEVEL_SILENCE with no sink; both are put back
	 * that way once the exchange is over. */
	struct log_capture cap = { 0 };
	slog_setoutput(SLOG_OUTPUT_WRITER, log_capture_write, &cap);
	/* NOTICE, not WARNING: the mux layer prefixes every record with the
	 * session tag, which carries the claim too, and its establishment record
	 * is a NOTICE. */
	slog_setlevel(LOG_LEVEL_NOTICE);

	fx.srv_b = server_new(fx.loop, fx.conf_b);
	if (fx.srv_b == NULL || !server_start(fx.srv_b)) {
		slog_setlevel(LOG_LEVEL_SILENCE);
		slog_setoutput(SLOG_OUTPUT_DISCARD);
		FIXTURE_FATAL(&fx, "srv_b start failed");
	}
	const int wait_rc = wait_until(
		&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		evlog_nonempty_predicate, &fx.srv_b->evlog);

	char evmsg[sizeof(fx.srv_b->evlog.entries[0].message)] = { 0 };
	for (size_t i = 0; i < fx.srv_b->evlog.len; i++) {
		const char *const msg = fx.srv_b->evlog.entries[i].message;
		if (strstr(msg, "session established") != NULL) {
			memcpy(evmsg, msg, sizeof(evmsg));
			break;
		}
	}

	/* Teardown joins every tunnel thread, so no further record can reach
	 * cap once the sink is dropped right after it. */
	fixture_teardown(&fx);
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);

	T_EXPECT_EQ(wait_rc, 0);
	T_EXPECT(!cap.overflow);
	/* The warning that names the claimed identity was emitted, as was a
	 * record carrying the session tag the claim also feeds... */
	T_EXPECT(strstr(cap.buf, "dialed session identity") != NULL);
	T_EXPECT(strstr(cap.buf, "node-b => a\\r\\n") != NULL);
	/* ...carrying the escaped spelling and no byte the peer could have used
	 * to end the record early or move the reader's cursor. */
	T_EXPECT(strstr(cap.buf, "\\r\\n") != NULL);
	T_EXPECT(strstr(cap.buf, "\\x1b") != NULL);
	T_EXPECT(memchr(cap.buf, '\r', cap.len) == NULL);
	T_EXPECT(memchr(cap.buf, '\x1b', cap.len) == NULL);
	/* The event log GET /stats renders verbatim holds the same. */
	T_EXPECT(strstr(evmsg, "session established") != NULL);
	T_EXPECT(strstr(evmsg, "\\r\\n") != NULL);
	T_EXPECT(strchr(evmsg, '\r') == NULL);
	T_EXPECT(strchr(evmsg, '\x1b') == NULL);
}

static const struct testing_suite suite[] = {
	T_CASE(test_server_apply_config_honors_cli_loglevel_override),
	T_CASE(test_server_offline_listeners_idle_timeout_scoped_to_mux_connect),
	T_CASE(test_server_offline_listeners_identity_branch),
	T_CASE(test_bidirectional_stream_and_forward),
	T_CASE(test_server_force_close_folds_tunnel_counters),
	T_CASE(test_server_snapshot_cap_allows_many_tunnels),
	T_CASE(test_half_close_b_to_a),
	T_CASE(test_half_close_a_to_b),
	T_CASE(test_multi_stream_churn_and_workload),
	T_CASE(test_backend_close_after_echo),
	T_CASE(test_client_abort_mid_payload),
	T_CASE(test_listener_reuse_after_stream_churn),
	T_CASE(test_cross_direction_overlap),
	T_CASE(test_large_payload_then_half_close),
	T_CASE(test_on_demand_tunnel_reconnects_after_idle_close),
	T_CASE(test_server_config_reload),
	T_CASE(test_server_reload_removes_identity_peer_closes_tunnel),
	T_CASE(test_server_identity_pool_holds_concurrent_tunnels_same_peer),
	T_CASE(test_server_reload_drops_two_identity_peers_no_uaf),
	T_CASE(test_server_reload_keeps_established_identity_mux_connect_tunnel),
#if WITH_TLS
	T_CASE(test_server_reload_retires_psk_table_for_live_tunnels),
	T_CASE(test_server_psk_retirement_waits_for_live_tls_context),
#endif
	T_CASE(test_server_maintenance_redials_emptied_identity_slot),
	T_CASE(test_server_maintenance_timer_stops_when_idle),
	T_CASE(test_server_start_identity_peer_with_null_listen),
	T_CASE(test_server_max_sessions_rejects),
	T_CASE(test_server_max_sessions_rejects_at_exact_limit),
	T_CASE(test_server_startup_limit_zero_start_throttles_first_connection),
	T_CASE(test_server_stream_establish_percentiles),
	T_CASE(test_server_stream_establish_percentiles_accepted_side),
	T_CASE(test_server_evlog_dedups_consecutive_reload_events),
	T_CASE(test_server_graceful_shutdown_via_signal),
	T_CASE(test_server_maintenance_suspend_drops_transports_and_reconnects),
	T_CASE(test_server_maintenance_shutdown_deadline_breaks_loop),
#if WITH_THREADS
	T_CASE(test_server_new_arms_async_before_start),
	T_CASE(test_server_free_releases_async_without_stop),
#endif
	T_CASE(test_server_identity_pool_single_membership_across_reclaim),
	T_CASE(test_server_identity_listener_forwards_over_pool),
	T_CASE(test_server_identity_listener_empty_pool_closes_conn),
	T_CASE(test_server_stop_frees_inflight_api_connection),
	T_CASE(test_server_escapes_peer_identity_in_output),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* The real socket_send() path (mux/wire.c, api_server.c) writes with no
	 * MSG_NOSIGNAL; a peer closing mid-forward raises SIGPIPE by default, and
	 * this suite drives that real stack, so the test process must survive it. */
	T_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	return testing_main(argc, argv, suite);
}
