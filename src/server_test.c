/* server_test.c - robust server forwarding tests with bounded waits */

#include "conf.h"
#include "listener.h"
#include "server.h"
#include "util.h"

#include "os/socket.h"
#include "utils/minmax.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
	IO_WAIT_TIMEOUT_MS = 50,
	SETUP_WAIT_TIMEOUT_MS = 500,
	SESSION_WAIT_TIMEOUT_MS = 500,
	STREAM_WAIT_TIMEOUT_MS = 500,
	PEER_EOF_WAIT_TIMEOUT_MS = 500,
	CONNECT_WAIT_TIMEOUT_MS = 500,
	ECHO_WAIT_TIMEOUT_MS = 1000,
	WORKLOAD_ECHO_WAIT_TIMEOUT_MS = 2000,
	STREAM_CHURN_ROUNDS = 20,
	STREAM_CHURN_CONCURRENCY = 4,
	BUFFER_SIZE = 256,
	PAYLOAD_SMALL = 1024,
	PAYLOAD_MEDIUM = 16384,
	PAYLOAD_LARGE = 262144,
};

int exitcode = EXIT_SUCCESS;

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
	struct fd_waiter *restrict waiter = w->data;
	waiter->revents = revents;
	waiter->done = true;
	ev_io_stop(loop, &waiter->w_io);
	ev_timer_stop(loop, &waiter->w_timer);
}

static void
fd_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	UNUSED(revents);
	struct fd_waiter *restrict waiter = w->data;
	waiter->timed_out = true;
	waiter->done = true;
	ev_timer_stop(loop, &waiter->w_timer);
	ev_io_stop(loop, &waiter->w_io);
}

static void
condition_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	UNUSED(loop);
	UNUSED(revents);
	struct condition_waiter *restrict waiter = w->data;
	waiter->timed_out = true;
}

/* No-op: periodic wakeup so the predicate is re-checked while waiting for
 * worker-thread progress (e.g., stream establishment on a background thread). */
static void wait_poll_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	UNUSED(loop);
	UNUSED(w);
	UNUSED(revents);
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

	if (waiter.timed_out) {
		return 0;
	}
	return waiter.revents;
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
	const char *ptr = buf;
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

static int send_and_expect_echo(
	struct test_fixture *restrict fx, const int fd,
	const char *const restrict msg, const size_t msg_len,
	const double timeout_sec)
{
	if (write_full(fx, fd, msg, msg_len) != 0) {
		return -1;
	}

	char *buf = malloc(msg_len);
	if (buf == NULL) {
		return -1;
	}
	size_t off = 0;
	const ev_tstamp deadline = ev_time() + timeout_sec;

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
					deadline - ev_time();
				if (remaining <= 0.0 ||
				    (wait_fd_events(fx, fd, EV_READ, remaining) &
				     EV_READ) == 0) {
					free(buf);
					return -1;
				}
				continue;
			}
			free(buf);
			return -1;
		}
		if (n == 0) {
			free(buf);
			return -1;
		}
		off += (size_t)n;
	}

	const int ret = memcmp(buf, msg, msg_len) == 0 ? 0 : -1;
	free(buf);
	return ret;
}

static int read_and_expect_echo(
	struct test_fixture *restrict fx, const int fd,
	const char *const restrict msg, const size_t msg_len,
	const double timeout_sec)
{
	char *buf = malloc(msg_len);
	if (buf == NULL) {
		return -1;
	}
	size_t off = 0;
	const ev_tstamp deadline = ev_time() + timeout_sec;

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
					deadline - ev_time();
				if (remaining <= 0.0 ||
				    (wait_fd_events(fx, fd, EV_READ, remaining) &
				     EV_READ) == 0) {
					free(buf);
					return -1;
				}
				continue;
			}
			free(buf);
			return -1;
		}
		if (n == 0) {
			free(buf);
			return -1;
		}
		off += (size_t)n;
	}

	const int ret = memcmp(buf, msg, msg_len) == 0 ? 0 : -1;
	free(buf);
	return ret;
}

static int wait_for_peer_eof(
	struct test_fixture *restrict fx, const int fd,
	const double timeout_sec)
{
	const ev_tstamp deadline = ev_time() + timeout_sec;
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
					deadline - ev_time();
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
		SOCKET_CLOSE_FD(fd);
		return -1;
	}

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		SOCKET_CLOSE_FD(fd);
		return -1;
	}
	if (listen(fd, 8) != 0) {
		SOCKET_CLOSE_FD(fd);
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
		SOCKET_CLOSE_FD(conn->fd);
		conn->fd = -1;
	}
	free(conn->out_buf);
	free(conn);
}

static void mock_server_drop_conn(struct mock_conn *restrict conn)
{
	struct mock_server *restrict mock = conn->mock;
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
	char *new_buf = realloc(conn->out_buf, conn->out_len + len);
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
		size_t remain = conn->out_len - conn->out_off;
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
		SOCKET_SHUTDOWN_FD(conn->fd, WR);
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
		while (true) {
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
	UNUSED(loop);
}

static void
mock_server_accept_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct mock_server *restrict mock = w->data;

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
			SOCKET_CLOSE_FD(fd);
			continue;
		}

		struct mock_conn *conn = calloc(1, sizeof(*conn));
		if (conn == NULL) {
			SOCKET_CLOSE_FD(fd);
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
		.running = true,
		.mode = mode,
		.conns = NULL,
	};

	mock->listen_fd = bind_listen_localhost();
	if (mock->listen_fd < 0) {
		return -1;
	}
	mock->port = listener_fd_port(mock->listen_fd);
	if (mock->port <= 0) {
		close(mock->listen_fd);
		mock->listen_fd = -1;
		return -1;
	}

	if (socket_set_nonblock(mock->listen_fd) != 0) {
		close(mock->listen_fd);
		mock->listen_fd = -1;
		return -1;
	}

	ev_io_init(
		&mock->w_accept, mock_server_accept_cb, mock->listen_fd,
		EV_READ);
	mock->w_accept.data = mock;
	ev_io_start(loop, &mock->w_accept);
	return 0;
}

static void mock_server_stop(struct mock_server *restrict mock)
{
	if (mock == NULL) {
		return;
	}
	mock->running = false;
	if (ev_is_active(&mock->w_accept)) {
		ev_io_stop(mock->loop, &mock->w_accept);
	}
	if (mock->listen_fd >= 0) {
		SOCKET_SHUTDOWN_FD(mock->listen_fd, RDWR);
		SOCKET_CLOSE_FD(mock->listen_fd);
		mock->listen_fd = -1;
	}
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
	struct config *conf = malloc(sizeof(*conf));
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
				.ping_timeout = 5,
				.keepalive = 1,
				.send_timeout = 1,
				.connect_timeout = 1,
				.idle_timeout = 0,
				.max_streams = 32,
				.stream_window = 2,
				.session_window = 256,
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

struct streams_ready_wait_ctx {
	struct test_fixture *fx;
	size_t expected;
};

struct streams_exact_wait_ctx {
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
#else
	const uint_least64_t session_connect = s->counters.num_session_connect;
	const uint_least64_t session_connected =
		s->counters.num_session_connected;
	const uint_least64_t session_disconnected =
		s->counters.num_session_disconnected;
#endif
	st.num_established_sessions =
		(size_t)(session_connected - session_disconnected);
	st.num_halfopen_sessions =
		(size_t)(session_connect - session_connected);
	struct server_stats *restrict snap = server_stats(s);
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
	struct streams_ready_wait_ctx *restrict ctx = ptr;
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
	struct test_fixture *restrict ctx = ptr;
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
	struct streams_exact_wait_ctx *restrict ctx = ptr;
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
	struct listener_port_wait_ctx *restrict ctx = ptr;
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
	struct streams_ready_wait_ctx ctx = {
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
		close(fd);
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
	close(fd);
	return -1;
}

static int
wait_for_streams_exact(struct test_fixture *restrict fx, const size_t expected)
{
	struct streams_exact_wait_ctx ctx = {
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
		close(fd);
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
		close(cl_b);
	}
	if (cl_a >= 0) {
		close(cl_a);
	}
	T_LOG("forward: teardown begin");
	fixture_teardown(&fx);
	T_LOG("forward: teardown done");
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
		close(cl);
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
	close(prime);
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
		close(prime);
	}
	if (cl >= 0) {
		close(cl);
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
				SOCKET_CLOSE_FD(clients[i]);
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
			SOCKET_CLOSE_FD(clients[i]);
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
	SOCKET_CLOSE_FD(cl);
	cl = -1;
	if (wait_for_streams_exact(&fx, 0) != 0) {
		T_LOG("wait_for_streams_exact(0) failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl >= 0) {
		SOCKET_CLOSE_FD(cl);
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
	SOCKET_CLOSE_FD(cl);
	cl = -1;
	if (wait_for_streams_exact(&fx, 0) != 0) {
		T_LOG("wait_for_streams_exact(0) failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl >= 0) {
		SOCKET_CLOSE_FD(cl);
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
				SOCKET_CLOSE_FD(clients[i]);
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
		SOCKET_CLOSE_FD(cl);
		if (wait_for_streams_exact(&fx, 0) != 0) {
			T_LOG("wait_for_streams_exact(0) failed after reuse");
			T_FAIL();
			goto cleanup;
		}
	}

cleanup:
	for (uint_fast32_t i = 0; i < STREAM_CHURN_CONCURRENCY; i++) {
		if (clients[i] >= 0) {
			SOCKET_CLOSE_FD(clients[i]);
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
	if (read_and_expect_echo(
		    &fx, cl_a, payload_a, sizeof(payload_a),
		    (double)WORKLOAD_ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0 ||
	    read_and_expect_echo(
		    &fx, cl_b, payload_b, sizeof(payload_b),
		    (double)WORKLOAD_ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("read_and_expect_echo failed");
		T_FAIL();
		goto cleanup;
	}

cleanup:
	if (cl_b >= 0) {
		SOCKET_CLOSE_FD(cl_b);
	}
	if (cl_a >= 0) {
		SOCKET_CLOSE_FD(cl_a);
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
		SOCKET_CLOSE_FD(cl);
	}
	free(payload);
	fixture_teardown(&fx);
}

/* Predicate: srv_a's config pointer has been replaced (reload completed). */
struct reload_wait_ctx {
	const struct test_fixture *fx;
	const struct config *old_conf;
};

static int reload_done_predicate(void *ptr)
{
	const struct reload_wait_ctx *restrict ctx = ptr;
	return ctx->fx->srv_a->conf != ctx->old_conf ? 1 : 0;
}

/*
 * test_server_config_reload – exercises server_reload() (the SIGHUP path),
 * server_drain_tunnels(), server_reload_listeners(), server_reload_mux_tunnel(),
 * and server_reload_identity_tunnels().
 *
 * Steps:
 *   1. Establish a two-server pair and verify echo works.
 *   2. Dump srv_a's config to a tempfile (clearing the "version=2" type tag
 *      so conf_parsefile accepts it as "version=1").
 *   3. Invoke srv_a's SIGHUP watcher via ev_invoke so signal_cb runs
 *      synchronously before ev_run processes any other event.
 *   4. Update fx.conf_a to the new config to avoid a double-free on teardown.
 *   5. Wait for the session to be re-established (srv_b reconnects after drain).
 *   6. Verify echo still works after the reload.
 */
T_DECLARE_CASE(test_server_config_reload)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FATAL("fixture_setup failed");
	}

	/* Pre-reload echo sanity check. */
	const int fd_before = connect_local(&fx, fx.tcp_port_a);
	if (fd_before < 0) {
		fixture_teardown(&fx);
		T_FATAL("connect_local failed before reload");
	}
	if (wait_for_streams_ready(&fx, 1) != 0) {
		close(fd_before);
		fixture_teardown(&fx);
		T_FATAL("streams not ready before reload");
	}
	T_CHECK(send_and_expect_echo(
			&fx, fd_before, "pre", 3,
			(double)ECHO_WAIT_TIMEOUT_MS / 1000.0) == 0);
	close(fd_before);

	/* Wait for the stream to close so the session is idle before drain. */
	if (wait_for_streams_exact(&fx, 0) != 0) {
		fixture_teardown(&fx);
		T_FATAL("stream not drained before reload");
	}

	/* Write the config to a tempfile.  The test config carries
	 * type="...version=2" which conf_parsefile rejects; temporarily clear
	 * it so conf_dumpfile emits the canonical CONF_TYPE ("version=1"). */
	char tmp_path[] = "/tmp/server_reload_XXXXXX";
	const int tmp_fd = mkstemp(tmp_path);
	if (tmp_fd < 0) {
		fixture_teardown(&fx);
		T_FATAL("mkstemp failed");
	}
	close(tmp_fd);

	char *const saved_type = fx.conf_a->type;
	fx.conf_a->type = NULL;
	size_t dump_len;
	char *dump_json = conf_dump(fx.conf_a, &dump_len);
	fx.conf_a->type = saved_type;
	bool dump_ok = false;
	if (dump_json != NULL) {
		FILE *dump_fp = fopen(tmp_path, "w");
		if (dump_fp != NULL) {
			dump_ok = fwrite(dump_json, 1, dump_len, dump_fp) ==
				  dump_len;
			(void)fclose(dump_fp);
		}
		free(dump_json);
	}
	if (!dump_ok) {
		(void)unlink(tmp_path);
		fixture_teardown(&fx);
		T_FATAL("conf_dumpfile failed");
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
	if (wait_until(&fx, 1.0, reload_done_predicate, &reload_ctx) != 0) {
		(void)unlink(tmp_path);
		fixture_teardown(&fx);
		T_FATAL("server_reload did not swap config within timeout");
	}
	/* Update tracked pointer so fixture_teardown frees the new config. */
	fx.conf_a = fx.srv_a->conf;

	/* Wait for the session to be re-established after the drain. */
	if (wait_until(&fx, 2.0, sessions_ready_wait_predicate, &fx) != 0) {
		(void)unlink(tmp_path);
		fixture_teardown(&fx);
		T_FATAL("session not re-established after reload");
	}

	/* Post-reload echo – the server must still forward traffic.
	 * Use connect_and_wait_echo which retries if the session is not
	 * yet ready to accept streams (e.g. accepted_tunnels not yet
	 * populated). */
	int fd_after;
	if (connect_and_wait_echo(&fx, fx.tcp_port_a, "post", &fd_after) != 0) {
		(void)unlink(tmp_path);
		fixture_teardown(&fx);
		T_FATAL("connect_and_wait_echo failed after reload");
	}
	close(fd_after);

	(void)unlink(tmp_path);
	fixture_teardown(&fx);
}

/*
 * test_server_max_sessions_rejects – exercises the max_sessions branch of
 * is_startup_limited(), which rejects new mux connections when the number of
 * established sessions already exceeds the configured maximum.
 *
 * Approach: after the fixture establishes one real session (num_sessions==1),
 * lower max_sessions to 1 and artificially bump the counter to 2 so the guard
 * fires on the next inbound mux connection.  The raw TCP connection is then
 * expected to be closed immediately by the server (read() returns 0).
 */
T_DECLARE_CASE(test_server_max_sessions_rejects)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FATAL("fixture_setup failed");
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
		fixture_teardown(&fx);
		T_FATAL("connect_local to mux port failed");
	}

	/* Drive until the connection is rejected and closed.  The server
	 * increments num_rejected and closes the fd synchronously inside
	 * mux_serve, so the rejection should appear within one event-loop
	 * iteration. */
	const int revents = wait_fd_events(
		&fx, raw, EV_READ, (double)CONNECT_WAIT_TIMEOUT_MS / 1000.0);
	T_CHECK((revents & EV_READ) != 0);

	char buf[1];
	const ssize_t n = read(raw, buf, sizeof(buf));
	T_EXPECT_EQ(n, (ssize_t)0); /* peer closed the connection */
	close(raw);

	/* Verify the rejection counter was incremented. */
	T_EXPECT(fx.srv_a->counters.num_rejected > 0);

	/* Restore the faked counter so the fixture tears down cleanly. */
#if WITH_THREADS
	atomic_store_explicit(
		&fx.srv_a->counters.num_sessions, 1, memory_order_relaxed);
#else
	fx.srv_a->counters.num_sessions = 1;
#endif
	fx.srv_a->conf->max_sessions = 0;

	fixture_teardown(&fx);
}

/*
 * test_server_graceful_shutdown_via_signal – exercises the SIGTERM branch of
 * signal_cb(), which stops all listeners, initiates graceful session shutdown,
 * and starts a two-second deadline timer.
 *
 * Steps:
 *   1. Establish a two-server pair.
 *   2. Invoke srv_a's SIGTERM watcher via ev_invoke so only srv_a's
 *      signal_cb fires (avoids disturbing srv_b's watcher).
 *   3. Drive the event loop until the listeners on srv_a are stopped.
 *   4. Verify that fixture_teardown completes cleanly (server_stop +
 *      server_free are safe after the signal handler ran).
 */
T_DECLARE_CASE(test_server_graceful_shutdown_via_signal)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		T_FATAL("fixture_setup failed");
	}

	/* Invoke srv_a's SIGTERM watcher directly; using ev_feed_signal_event
	 * would also fire srv_b's watcher and complicate teardown ordering. */
	ev_invoke(fx.loop, &fx.srv_a->w_sigterm, EV_SIGNAL);

	/* Drive until signal_cb has stopped the mux listener (synchronous
	 * side-effect of the signal handler). */
	const ev_tstamp deadline =
		ev_time() + (double)SETUP_WAIT_TIMEOUT_MS / 1000.0;
	while (fx.srv_a->mux_listener.w_accept.fd != -1 &&
	       ev_time() < deadline) {
		drive_loop_once(&fx);
	}
	T_CHECK(fx.srv_a->mux_listener.w_accept.fd == -1);
	T_CHECK(fx.srv_a->local_listener.w_accept.fd == -1);

	/* Let any pending shutdown tasks settle before tearing down. */
	drive_loop_once(&fx);
	drive_loop_once(&fx);

	fixture_teardown(&fx);
}

int main(void)
{
	init(0, NULL);
	loadlibs();

	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_bidirectional_stream_and_forward);
	T_RUN_CASE(t, test_half_close_b_to_a);
	T_RUN_CASE(t, test_half_close_a_to_b);
	T_RUN_CASE(t, test_multi_stream_churn_and_workload);
	T_RUN_CASE(t, test_backend_close_after_echo);
	T_RUN_CASE(t, test_client_abort_mid_payload);
	T_RUN_CASE(t, test_listener_reuse_after_stream_churn);
	T_RUN_CASE(t, test_cross_direction_overlap);
	T_RUN_CASE(t, test_large_payload_then_half_close);
	T_RUN_CASE(t, test_server_config_reload);
	T_RUN_CASE(t, test_server_max_sessions_rejects);
	T_RUN_CASE(t, test_server_graceful_shutdown_via_signal);

	unloadlibs();
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
