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
#include "sync/shared_mutex.h"
#include "sync/task.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#if WITH_THREADS || defined(SERVER_TEST_WRAP_REALLOC)
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#if WITH_THREADS
#include <threads.h>
#endif
#include <time.h>
#include <unistd.h>

#ifdef SERVER_TEST_WRAP_REALLOC
/* Fail only growth of the armed array, once. Tunnel-thread allocations cannot
 * consume this injection, and the cleanup prevents it reaching a later case. */
static atomic_uintptr_t fail_realloc_ptr;
void *__real_realloc(void *ptr, size_t size);
void *__wrap_realloc(void *ptr, size_t size);

void *__wrap_realloc(void *ptr, size_t size)
{
	uintptr_t expected = (uintptr_t)ptr;
	if (expected != 0 &&
	    atomic_compare_exchange_strong_explicit(
		    &fail_realloc_ptr, &expected, 0, memory_order_relaxed,
		    memory_order_relaxed)) {
		errno = ENOMEM;
		return NULL;
	}
	return __real_realloc(ptr, size);
}

static void clear_realloc_failure(void *data)
{
	(void)data;
	atomic_store_explicit(&fail_realloc_ptr, 0, memory_order_relaxed);
}
#endif /* SERVER_TEST_WRAP_REALLOC */

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
	/* lossymux: UDP echo backends on each TCP backend's port (the connect
	 * address serves both protocols); fd -1 when not set up. */
	ev_io udp_echo_a;
	ev_io udp_echo_b;
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
				.lossymux_idle_timeout =
					mux_session_config_default
						.lossymux_idle_timeout,
				.lossymux_queue =
					mux_session_config_default
						.lossymux_queue,
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
	struct server_stats *const restrict snap = server_stats(s, false);
	if (snap != NULL) {
		st.num_established_sessions = snap->num_sessions;
		st.num_halfopen_sessions = snap->num_session_halfopen;
		/* Logical completion precedes tombstone reclamation; this wait
		 * counts unfinished streams, not still-allocated stream objects. */
		st.num_streams = (size_t)((snap->num_stream_opened +
					   snap->num_stream_accepted) -
					  (snap->num_stream_succeeded +
					   snap->num_stream_failed));
		st.num_halfopen_streams = snap->num_stream_halfopen;
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

/* Echo every datagram back to its sender. */
static void udp_echo_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)revents;
	for (;;) {
		unsigned char buf[2048];
		union sockaddr_max from;
		socklen_t from_len = sizeof(from);
		const ssize_t n = recvfrom(
			w->fd, buf, sizeof(buf), MSG_DONTWAIT, &from.sa,
			&from_len);
		if (n < 0) {
			return;
		}
		(void)sendto(w->fd, buf, (size_t)n, 0, &from.sa, from_len);
	}
}

/* Bind a UDP echo on 127.0.0.1:port, watched by w on loop. */
static int udp_echo_start(ev_io *w, struct ev_loop *loop, const int port)
{
	const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons((uint16_t)port),
	};
	if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		(void)close(fd);
		return -1;
	}
	ev_io_init(w, udp_echo_cb, fd, EV_READ);
	ev_io_start(loop, w);
	return 0;
}

static void udp_echo_stop(ev_io *w, struct ev_loop *loop)
{
	if (w->fd < 0) {
		return;
	}
	ev_io_stop(loop, w);
	(void)close(w->fd);
	ev_io_set(w, -1, EV_READ);
}

static int fixture_setup_ex(
	struct test_fixture *restrict fx, const enum mock_mode mode,
	const bool lossymux)
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
	ev_io_init(&fx->udp_echo_a, udp_echo_cb, -1, EV_READ);
	ev_io_init(&fx->udp_echo_b, udp_echo_cb, -1, EV_READ);
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
	if (lossymux) {
		g_setup_stage = "udp_echo_start";
		if (udp_echo_start(
			    &fx->udp_echo_a, fx->loop, fx->backend_a.port) !=
			    0 ||
		    udp_echo_start(
			    &fx->udp_echo_b, fx->loop, fx->backend_b.port) !=
			    0) {
			return -1;
		}
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
	fx->conf_a->mux.lossymux = lossymux;
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
	fx->conf_b->mux.lossymux = lossymux;
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

static int
fixture_setup(struct test_fixture *restrict fx, const enum mock_mode mode)
{
	return fixture_setup_ex(fx, mode, false);
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
		udp_echo_stop(&fx->udp_echo_b, fx->loop);
		udp_echo_stop(&fx->udp_echo_a, fx->loop);
	}

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
static bool ol_verify_peer(void *user, const char *peer_identity)
{
	(void)user;
	(void)peer_identity;
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

/* A dialed tunnel that is never started: its session stays in INIT, which
 * reads as MUX_STATE_CONNECT -- a pool member that cannot carry a stream. */
static struct tunnel *ol_make_tunnel(struct server *restrict srv)
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
		.cnt = &cnts,
	};
	return tunnel_new(&ctx, &opts);
}

static struct tunnel *ol_make_established_tunnel(struct server *restrict srv)
{
	struct tunnel *const t = ol_make_tunnel(srv);
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
	struct identity_peer peers[] = {
		{ .id = "peer-live", .listen = "127.0.0.1:1" },
		{ .id = "peer-off", .listen = "127.0.0.1:2" },
	};
	conf.identity.peers = peers;
	conf.identity.peers_count = 2;
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	struct server srv = { .conf = &conf, .loop = loop };
	srv.identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(srv.identities != NULL);

	struct tunnel *const live = ol_make_established_tunnel(&srv);
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

/* Historical failed negotiations and streams must not look half-open once
 * their gauges return to zero. Both readiness predicates consume this view. */
T_DECLARE_CASE(test_server_wait_stats_ignores_historical_failures)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	fx.srv_a->counters.num_session_connect++;
	fx.srv_b->counters.num_session_connect++;
	fx.srv_a->counters.closed.num_stream_opened++;
	fx.srv_a->counters.closed.num_stream_failed++;
	fx.srv_b->counters.closed.num_stream_opened++;
	fx.srv_b->counters.closed.num_stream_failed++;
	const struct wait_stats st = wait_stats_snapshot(fx.srv_a);
	const int sessions_ready = sessions_ready_wait_predicate(&fx);
	struct streams_wait_ctx ctx = { .fx = &fx, .expected = 0 };
	const int streams_ready = streams_exact_wait_predicate(&ctx);
	fixture_teardown(&fx);
	T_EXPECT_EQ(st.num_halfopen_sessions, (size_t)0);
	T_EXPECT_EQ(st.num_halfopen_streams, (size_t)0);
	T_EXPECT_EQ(sessions_ready, 1);
	T_EXPECT_EQ(streams_ready, 1);
}

/* A global idle timeout does not make passive identity routes dialable.
 * The exemption follows a configured dial-out in that exact pool. */
T_DECLARE_CASE(test_server_offline_ignores_routing_only_peer)
{
	struct config *const conf =
		make_config("127.0.0.1:0", NULL, NULL, NULL);
	T_CHECK(conf != NULL);
	conf->identity.peers = calloc(1, sizeof(conf->identity.peers[0]));
	T_CHECK(conf->identity.peers != NULL);
	conf->identity.peers_count = 1;
	conf->identity.peers[0].id = strdup("routing-only");
	T_CHECK(conf->identity.peers[0].id != NULL);
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	struct server *const srv = server_new(loop, conf);
	T_CHECK(srv != NULL);
	const bool started = server_start(srv);
	const size_t offline = server_offline_listeners(srv, NULL, NULL);
	server_stop(srv);
	server_free(srv);
	conf_free(conf);
	ev_loop_destroy(loop);
	T_EXPECT(started);
	T_EXPECT_EQ(offline, (size_t)0);
}

T_DECLARE_CASE(test_server_offline_passive_identity_with_idle_timeout)
{
	struct config *const conf = make_config(NULL, NULL, NULL, NULL);
	T_CHECK(conf != NULL);
	conf->mux.idle_timeout = 60;
	struct identity_peer peers[] = {
		{ .id = "passive", .listen = "127.0.0.1:1" },
		{ .id = "outbound", .listen = "127.0.0.1:2" },
	};
	conf->identity.peers = peers;
	conf->identity.peers_count = 2;
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	struct server srv = { .conf = conf, .loop = loop };
	srv.identities = table_new(&TABLE_OPTS_STR);
	T_CHECK(srv.identities != NULL);
	struct tunnel *const dialed = ol_make_tunnel(&srv);
	T_CHECK(dialed != NULL);
	struct tunnel *members[] = { dialed };
	struct identity_listener passive = { .peer_identity = "passive" };
	struct identity_listener outbound = {
		.peer_identity = "outbound",
		.tunnels = members,
		.num_tunnels = 1,
	};
	void *slot = &passive;
	srv.identities =
		table_set(srv.identities, passive.peer_identity, &slot);
	T_CHECK(slot == NULL);
	slot = &outbound;
	srv.identities =
		table_set(srv.identities, outbound.peer_identity, &slot);
	T_CHECK(slot == NULL);
	const size_t passive_only = server_offline_listeners(&srv, NULL, NULL);
	char *destinations[] = { "127.0.0.1:1" };
	conf->identity.mux_connect = destinations;
	conf->identity.mux_connect_count = 1;
	srv.identity_tunnels = members;
	srv.num_identity_tunnels = 1;
	struct offline_capture cap = { 0 };
	const size_t mixed =
		server_offline_listeners(&srv, offline_capture_cb, &cap);
	/* Removing the destination also removes the idle exemption. */
	conf->identity.mux_connect_count = 0;
	const size_t removed = server_offline_listeners(&srv, NULL, NULL);
	peers[0].listen = NULL;
	peers[1].listen = NULL;
	const size_t routing_only = server_offline_listeners(&srv, NULL, NULL);
	conf->identity.mux_connect = NULL;
	conf->identity.peers = NULL;
	conf->identity.peers_count = 0;
	tunnel_close(dialed);
	table_free(srv.identities);
	ev_loop_destroy(loop);
	conf_free(conf);
	T_EXPECT_EQ(passive_only, (size_t)2);
	T_EXPECT_EQ(mixed, (size_t)1);
	T_EXPECT_EQ(cap.count, (size_t)1);
	T_EXPECT_STREQ(cap.names[0], "passive");
	T_EXPECT_EQ(removed, (size_t)2);
	T_EXPECT_EQ(routing_only, (size_t)0);
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

/* A UDP client of one server's listen address and the reply it waits for.
 * The datagram is re-sent every few polls: best effort, it is dropped while
 * lossymux is not yet ready on the session carrying it. */
struct udp_echo_wait {
	int fd;
	struct sockaddr_in to;
	const char *msg;
	int polls;
	ssize_t received_len;
	char got[64];
};

static int udp_echo_wait_predicate(void *ptr)
{
	struct udp_echo_wait *const restrict w = ptr;
	struct pollfd pfd = { .fd = w->fd, .events = POLLIN };
	if (poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN)) {
		const ssize_t n =
			recv(w->fd, w->got, sizeof(w->got) - 1, MSG_DONTWAIT);
		if (n >= 0) {
			w->received_len = n;
			w->got[n] = '\0';
			return 1;
		}
	}
	if (w->polls++ % 20 == 0) {
		(void)sendto(
			w->fd, w->msg, strlen(w->msg), 0,
			(const struct sockaddr *)&w->to, sizeof(w->to));
	}
	return 0;
}

/* Send msg to 127.0.0.1:port over UDP and wait for its echo. */
static bool
udp_roundtrip(struct test_fixture *restrict fx, const int port, const char *msg)
{
	struct udp_echo_wait w = {
		.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP),
		.to = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = htons((uint16_t)port),
		},
		.msg = msg,
		.received_len = -1,
	};
	if (w.fd < 0) {
		return false;
	}
	const int ret = wait_until(
		fx, (double)ECHO_WAIT_TIMEOUT_MS / 1000.0,
		udp_echo_wait_predicate, &w);
	(void)close(w.fd);
	return ret == 0 && w.received_len == (ssize_t)strlen(msg) &&
	       strcmp(w.got, msg) == 0;
}

/* lossymux end to end, both directions over one session: a datagram to the
 * dialing server's listen address is relayed to the accepting server's
 * connect target and the echo comes back to the client (forward), and the
 * same from the accepting side (reverse).  Each side's datagram counters
 * account for it. */
T_DECLARE_CASE(test_server_lossymux_udp_roundtrip)
{
	struct test_fixture fx;
	if (fixture_setup_ex(&fx, MOCK_ECHO, true) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	/* The UDP sockets share their TCP listeners' (port-0) ports. */
	const bool forward = udp_roundtrip(&fx, fx.tcp_port_b, "forward");
	const bool reverse = udp_roundtrip(&fx, fx.tcp_port_a, "reverse");

	struct server_stats *const sa = server_stats(fx.srv_a, false);
	struct server_stats *const sb = server_stats(fx.srv_b, false);
	T_CHECK(sa != NULL && sb != NULL);
	const uint_least64_t a_sent = sa->pkt_dgram_sent;
	const uint_least64_t a_recv = sa->pkt_dgram_recv;
	const uint_least64_t b_sent = sb->pkt_dgram_sent;
	const uint_least64_t b_recv = sb->pkt_dgram_recv;
	const size_t a_flows = sa->num_flows;
	const size_t b_flows = sb->num_flows;
	free(sa);
	free(sb);
	fixture_teardown(&fx);

	T_EXPECT(forward);
	T_EXPECT(reverse);
	/* One flow each way per side: an active one and a passive one. */
	T_EXPECT_EQ(a_flows, (size_t)2);
	T_EXPECT_EQ(b_flows, (size_t)2);
	T_EXPECT(a_sent >= 2 && a_recv >= 2);
	T_EXPECT(b_sent >= 2 && b_recv >= 2);
}

/* Empty datagrams traverse the socket/mux/socket relay in each direction.
 * Packet counters advance while payload-byte counters remain zero. */
T_DECLARE_CASE(test_server_lossymux_udp_empty_roundtrip)
{
	struct test_fixture fx;
	if (fixture_setup_ex(&fx, MOCK_ECHO, true) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	const bool forward = udp_roundtrip(&fx, fx.tcp_port_b, "");
	const bool reverse = udp_roundtrip(&fx, fx.tcp_port_a, "");
	struct server_stats *const sa = server_stats(fx.srv_a, false);
	struct server_stats *const sb = server_stats(fx.srv_b, false);
	T_CHECK(sa != NULL && sb != NULL);
	const uint_least64_t a_sent = sa->pkt_dgram_sent;
	const uint_least64_t a_recv = sa->pkt_dgram_recv;
	const uint_least64_t b_sent = sb->pkt_dgram_sent;
	const uint_least64_t b_recv = sb->pkt_dgram_recv;
	const uint_least64_t a_bytes_sent = sa->byt_dgram_sent;
	const uint_least64_t a_bytes_recv = sa->byt_dgram_recv;
	const uint_least64_t b_bytes_sent = sb->byt_dgram_sent;
	const uint_least64_t b_bytes_recv = sb->byt_dgram_recv;
	const size_t a_flows = sa->num_flows;
	const size_t b_flows = sb->num_flows;
	free(sa);
	free(sb);
	fixture_teardown(&fx);

	T_EXPECT(forward);
	T_EXPECT(reverse);
	T_EXPECT_EQ(a_flows, (size_t)2);
	T_EXPECT_EQ(b_flows, (size_t)2);
	T_EXPECT(a_sent >= 2 && a_recv >= 2);
	T_EXPECT(b_sent >= 2 && b_recv >= 2);
	T_EXPECT_EQ(a_bytes_sent, (uint_least64_t)0);
	T_EXPECT_EQ(a_bytes_recv, (uint_least64_t)0);
	T_EXPECT_EQ(b_bytes_sent, (uint_least64_t)0);
	T_EXPECT_EQ(b_bytes_recv, (uint_least64_t)0);
}

/* Without lossymux no UDP socket is bound beside the listen address. */
T_DECLARE_CASE(test_server_lossymux_disabled_binds_no_udp)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	const bool none_a = fx.srv_a->udp_local == NULL;
	const bool none_b = fx.srv_b->udp_local == NULL;
	fixture_teardown(&fx);

	T_EXPECT(none_a);
	T_EXPECT(none_b);
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

	/* The actual regression check: the first local connection after the
	 * idle-close must itself be forwarded -- it triggers the demand
	 * reconnect and waits for it, rather than being closed while the
	 * session comes back up. One attempt only: a retry would hide exactly
	 * that dropped first connection. */
	cl2 = connect_local(&fx, fx.tcp_port_b);
	if (cl2 < 0 || send_and_expect_echo(
			       &fx, cl2, "after-idle", strlen("after-idle"),
			       (double)ECHO_WAIT_TIMEOUT_MS / 1000.0) != 0) {
		T_LOG("first connection after idle-close was not forwarded");
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

/* A listener bind failure during reload must be reported before the active
 * configuration is replaced, leaving the previous listener serving traffic. */
T_DECLARE_CASE(test_server_reload_rejects_listener_bind_failure)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	char occupied[64];
	(void)snprintf(
		occupied, sizeof(occupied), "127.0.0.1:%d", fx.tcp_port_b);
	struct config *const new_conf = make_config(
		fx.conf_a->mux_listen, fx.conf_a->mux_connect, occupied,
		fx.conf_a->connect);
	if (new_conf == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	struct config *const old_conf = fx.srv_a->conf;
	const int old_port = fx.tcp_port_a;
	const bool applied = server_apply_config(fx.srv_a, new_conf);

	fx.conf_a = fx.srv_a->conf;
	const bool kept_conf = fx.srv_a->conf == old_conf;
	const int port_after = get_listener_port(&fx.srv_a->local_listener);
	const int fd = connect_local(&fx, old_port);
	if (fd >= 0) {
		(void)close(fd);
	}

	fixture_teardown(&fx);

	T_EXPECT(!applied);
	T_EXPECT(kept_conf);
	T_EXPECT_EQ(port_after, old_port);
	T_EXPECT(fd >= 0);
}

/* The API control socket carries a dedicated profile, not the application's
 * tcp{} tuning: server_new() binds api_listener with a fixed socket_opts that
 * server_apply_config never repoints (unlike the local and mux listeners), so a
 * reload that moves api_listen must bind the replacement with those same
 * options.  Preparing it from new_conf->tcp instead leaks the user's buffer
 * hints, keepalive, reuseport and fastopen settings onto the control socket and
 * leaves api_listener.socket_opts describing a socket that does not exist. */
T_DECLARE_CASE(test_server_reload_api_listener_keeps_dedicated_socket_opts)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	struct config *const new_conf = make_config(
		fx.conf_a->mux_listen, fx.conf_a->mux_connect,
		fx.conf_a->listen, fx.conf_a->connect);
	if (new_conf == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	/* Only api_listen changes, so the reload rebinds that listener alone. */
	new_conf->api_listen = strdup("127.0.0.1:0");
	if (new_conf->api_listen == NULL) {
		conf_free(new_conf);
		FIXTURE_FATAL(&fx, "strdup failed");
	}
	/* Each option the API profile pins, requested the other way round here, so
	 * a socket bound from tcp{} is distinguishable from one bound from the
	 * profile. */
	new_conf->tcp.tcp_nodelay = false;
	new_conf->tcp.tcp_keepalive = true;
	new_conf->tcp.tcp_reuseport = true;

	const bool applied = server_apply_config(fx.srv_a, new_conf);
	if (applied) {
		/* Track the new config so teardown frees it, not the freed old one. */
		fx.conf_a = fx.srv_a->conf;
	}

	const int api_fd = fx.srv_a->api_listener.w_accept.fd;
	int nodelay = -1;
	int keepalive = -1;
	int reuseport = 0;
	if (api_fd >= 0) {
		socklen_t len = sizeof(nodelay);
		(void)getsockopt(
			api_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, &len);
		len = sizeof(keepalive);
		(void)getsockopt(
			api_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, &len);
#ifdef SO_REUSEPORT
		len = sizeof(reuseport);
		(void)getsockopt(
			api_fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, &len);
#endif
	}

	fixture_teardown(&fx);

	T_EXPECT(applied);
	T_EXPECT(api_fd >= 0);
	/* api_socket_opts: nodelay on, keepalive off, reuseport off. */
	T_EXPECT(nodelay != 0);
	T_EXPECT_EQ(keepalive, 0);
	T_EXPECT_EQ(reuseport, 0);
}

/* Reload fx->srv_a with fx->conf_a's addresses except listen, which becomes
 * @p listen, and track the config srv_a runs afterwards. On success the old
 * config was freed by server_apply_config; on failure it is still in force. */
static bool reload_local_listen(
	struct test_fixture *restrict fx, const char *restrict listen)
{
	struct config *const new_conf = make_config(
		fx->conf_a->mux_listen, fx->conf_a->mux_connect, listen,
		fx->conf_a->connect);
	if (new_conf == NULL) {
		return false;
	}
	const bool applied = server_apply_config(fx->srv_a, new_conf);
	fx->conf_a = fx->srv_a->conf;
	return applied;
}

/* True if @p l is bound to the IPv4 address @p ip (host byte order) on
 * @p port. */
static bool listener_bound_to(
	const struct listener *restrict l, const uint32_t ip, const int port)
{
	union sockaddr_max sa;
	return listener_get_addr(l, &sa) && sa.sa.sa_family == AF_INET &&
	       sa.in.sin_addr.s_addr == htonl(ip) &&
	       (int)ntohs(sa.in.sin_port) == port;
}

/* True if connecting to 127.0.0.1:@p port succeeds. */
static bool can_connect_local(struct test_fixture *restrict fx, const int port)
{
	const int fd = connect_local(fx, port);
	if (fd < 0) {
		return false;
	}
	(void)close(fd);
	return true;
}

/* Regression: a reload that moves a listener to another address on the port
 * it already holds must succeed. Linux refuses to bind an address:port that
 * overlaps a listening socket even with SO_REUSEADDR, so binding the
 * replacement beside the live socket failed every such reload: a respelling
 * of the bound address, widening to the wildcard, and narrowing back. */
T_DECLARE_CASE(test_server_reload_moves_listener_within_port)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	const int port = fx.tcp_port_a;
	char addr[64];

	/* "127.0.0.1:0" respelled as the address it is bound to: the live
	 * socket is kept, not rebound. */
	const int old_fd = fx.srv_a->local_listener.w_accept.fd;
	(void)snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
	const bool respelled = reload_local_listen(&fx, addr);
	const int respelled_fd = fx.srv_a->local_listener.w_accept.fd;

	(void)snprintf(addr, sizeof(addr), "0.0.0.0:%d", port);
	const bool widened = reload_local_listen(&fx, addr);
	const bool widened_bound =
		listener_bound_to(&fx.srv_a->local_listener, INADDR_ANY, port);
	const bool widened_serves = can_connect_local(&fx, port);

	(void)snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
	const bool narrowed = reload_local_listen(&fx, addr);
	const bool narrowed_bound = listener_bound_to(
		&fx.srv_a->local_listener, INADDR_LOOPBACK, port);
	const bool narrowed_serves = can_connect_local(&fx, port);

	/* Asserted only after teardown: a failing assertion longjmps out of the
	 * case, which would leak the fixture's loop and servers. */
	fixture_teardown(&fx);

	T_EXPECT(respelled);
	T_EXPECT_EQ(respelled_fd, old_fd);
	T_EXPECT(widened);
	T_EXPECT(widened_bound);
	T_EXPECT(widened_serves);
	T_EXPECT(narrowed);
	T_EXPECT(narrowed_bound);
	T_EXPECT(narrowed_serves);
}

/* True if this host refuses to bind @p ip (host byte order), e.g. because it
 * is not one of its addresses and non-local binds are off. */
static bool host_refuses_bind(const uint32_t ip)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return false;
	}
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(ip);
	const bool refused =
		bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0;
	(void)close(fd);
	return refused;
}

/* Build fx->conf_a with listen replaced by @p listen and one identity peer
 * listening on 127.0.0.1:@p occupied_port. Returns NULL on allocation failure,
 * having freed whatever it built. */
static struct config *make_listen_with_occupied_peer(
	const struct test_fixture *restrict fx, const char *restrict listen,
	const int occupied_port)
{
	struct config *const conf = make_config(
		fx->conf_a->mux_listen, fx->conf_a->mux_connect, listen,
		fx->conf_a->connect);
	if (conf == NULL) {
		return NULL;
	}
	char occupied[64];
	(void)snprintf(
		occupied, sizeof(occupied), "127.0.0.1:%d", occupied_port);
	conf->identity.peers = malloc(sizeof(*conf->identity.peers));
	if (conf->identity.peers == NULL) {
		conf_free(conf);
		return NULL;
	}
	conf->identity.peers[0] = (struct identity_peer){
		.id = strdup("peer1"),
		.listen = strdup(occupied),
	};
	conf->identity.peers_count = 1;
	if (conf->identity.peers[0].id == NULL ||
	    conf->identity.peers[0].listen == NULL) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

/* A reload that released the live listener to move it within its port, and
 * then cannot bind the new address, must bind the listener back on its old
 * address before reporting the failure. */
T_DECLARE_CASE(test_server_reload_restores_listener_after_failed_bind)
{
	/* 192.0.2.1 is TEST-NET-1: unbindable unless non-local binds are on. */
	if (!host_refuses_bind(UINT32_C(0xC0000201))) {
		T_LOG("host binds 192.0.2.1; nothing to fail the reload with");
		return;
	}
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	const int port = fx.tcp_port_a;
	struct config *const old_conf = fx.srv_a->conf;

	char addr[64];
	(void)snprintf(addr, sizeof(addr), "192.0.2.1:%d", port);
	const bool applied = reload_local_listen(&fx, addr);
	const bool kept_conf = fx.srv_a->conf == old_conf;
	const bool bound = listener_bound_to(
		&fx.srv_a->local_listener, INADDR_LOOPBACK, port);
	const bool serves = can_connect_local(&fx, port);

	/* Asserted only after teardown, as above. */
	fixture_teardown(&fx);

	T_EXPECT(!applied);
	T_EXPECT(kept_conf);
	T_EXPECT(bound);
	T_EXPECT(serves);
}

/* Likewise when the new address binds but a later step of the reload fails:
 * here the identity listener, whose address is srv_b's live TCP listener. */
T_DECLARE_CASE(test_server_reload_restores_listener_after_later_failure)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	const int port = fx.tcp_port_a;
	struct config *const old_conf = fx.srv_a->conf;

	char addr[64];
	(void)snprintf(addr, sizeof(addr), "0.0.0.0:%d", port);
	struct config *const new_conf =
		make_listen_with_occupied_peer(&fx, addr, fx.tcp_port_b);
	if (new_conf == NULL) {
		FIXTURE_FATAL(&fx, "make_listen_with_occupied_peer failed");
	}
	const bool applied = server_apply_config(fx.srv_a, new_conf);
	const bool kept_conf = fx.srv_a->conf == old_conf;
	const bool bound = listener_bound_to(
		&fx.srv_a->local_listener, INADDR_LOOPBACK, port);
	const bool serves = can_connect_local(&fx, port);

	/* Asserted only after teardown, as above. */
	fixture_teardown(&fx);

	T_EXPECT(!applied);
	T_EXPECT(kept_conf);
	T_EXPECT(bound);
	T_EXPECT(serves);
}

/* Every listening role can inherit a port the previous role relinquishes. */
T_DECLARE_CASE(test_server_reload_transfers_listener_between_roles)
{
	struct test_fixture fx = {
		.loop = ev_loop_new(EVFLAG_AUTO),
		.backend_a = { .listen_fd = -1 },
		.backend_b = { .listen_fd = -1 },
		.udp_echo_a = { .fd = -1 },
		.udp_echo_b = { .fd = -1 },
	};
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	fx.conf_a = make_config(NULL, NULL, "127.0.0.1:0", NULL);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "server_start failed");
	}
	const int port = get_listener_port(&fx.srv_a->local_listener);
	char addr[64];
	(void)snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
	bool applied[4] = { false };
	int ports[4] = { -1, -1, -1, -1 };
	for (size_t role = 0; role < 4; role++) {
		struct config *const nc = make_config(
			role == 0 ? addr : NULL, NULL, role == 3 ? addr : NULL,
			NULL);
		if (nc == NULL) {
			FIXTURE_FATAL(&fx, "make_config failed");
		}
		if (role == 1) {
			nc->api_listen = strdup(addr);
			if (nc->api_listen == NULL) {
				conf_free(nc);
				FIXTURE_FATAL(&fx, "strdup failed");
			}
		}
		if (role == 2) {
			nc->identity.peers =
				calloc(1, sizeof(nc->identity.peers[0]));
			if (nc->identity.peers == NULL) {
				conf_free(nc);
				FIXTURE_FATAL(&fx, "calloc failed");
			}
			nc->identity.peers_count = 1;
			nc->identity.peers[0].id = strdup("peer");
			nc->identity.peers[0].listen = strdup(addr);
			if (nc->identity.peers[0].id == NULL ||
			    nc->identity.peers[0].listen == NULL) {
				conf_free(nc);
				FIXTURE_FATAL(&fx, "strdup failed");
			}
		}
		applied[role] = server_apply_config(fx.srv_a, nc);
		fx.conf_a = fx.srv_a->conf;
		struct listener *l = role == 0 ? &fx.srv_a->mux_listener :
				     role == 1 ? &fx.srv_a->api_listener :
						 &fx.srv_a->local_listener;
		void *elem;
		if (role == 2 &&
		    table_find(fx.srv_a->identities, "peer", &elem)) {
			l = &((struct identity_listener *)elem)->listener;
		}
		ports[role] = get_listener_port(l);
	}
	fixture_teardown(&fx);
	for (size_t i = 0; i < 4; i++) {
		T_EXPECT(applied[i]);
		T_EXPECT_EQ(ports[i], port);
	}
}

/* Two roles can swap ports; a later identity-bind failure must restore both. */
T_DECLARE_CASE(test_server_reload_swaps_roles_and_rolls_back)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	char local[64];
	char mux[64];
	(void)snprintf(local, sizeof(local), "127.0.0.1:%d", fx.mux_port_a);
	(void)snprintf(mux, sizeof(mux), "127.0.0.1:%d", fx.tcp_port_a);
	struct config *const nc =
		make_config(mux, NULL, local, fx.conf_a->connect);
	if (nc == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	const bool applied = server_apply_config(fx.srv_a, nc);
	fx.conf_a = fx.srv_a->conf;
	const bool swapped =
		get_listener_port(&fx.srv_a->local_listener) == fx.mux_port_a &&
		get_listener_port(&fx.srv_a->mux_listener) == fx.tcp_port_a;
	struct config *const rejected =
		make_listen_with_occupied_peer(&fx, mux, fx.tcp_port_b);
	if (rejected == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	free(rejected->mux_listen);
	rejected->mux_listen = strdup(local);
	if (rejected->mux_listen == NULL) {
		conf_free(rejected);
		FIXTURE_FATAL(&fx, "strdup failed");
	}
	const bool rejected_applied = server_apply_config(fx.srv_a, rejected);
	fx.conf_a = fx.srv_a->conf;
	const bool restored =
		get_listener_port(&fx.srv_a->local_listener) == fx.mux_port_a &&
		get_listener_port(&fx.srv_a->mux_listener) == fx.tcp_port_a;
	fixture_teardown(&fx);
	T_EXPECT(applied);
	T_EXPECT(swapped);
	T_EXPECT(!rejected_applied);
	T_EXPECT(restored);
}

/* A routing-only retained peer can acquire a listener before a later bind
 * fails. Rollback must stop that new socket and restore its old option owner. */
T_DECLARE_CASE(test_server_reload_rolls_back_new_listener_on_retained_peer)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	struct config *const route = make_config(
		fx.conf_a->mux_listen, NULL, fx.conf_a->listen,
		fx.conf_a->connect);
	if (route == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	route->identity.peers = calloc(1, sizeof(route->identity.peers[0]));
	if (route->identity.peers == NULL) {
		conf_free(route);
		FIXTURE_FATAL(&fx, "calloc failed");
	}
	route->identity.peers_count = 1;
	route->identity.peers[0].id = strdup("retained");
	if (route->identity.peers[0].id == NULL) {
		conf_free(route);
		FIXTURE_FATAL(&fx, "strdup failed");
	}
	const bool prepared = server_apply_config(fx.srv_a, route);
	fx.conf_a = fx.srv_a->conf;
	if (!prepared) {
		FIXTURE_FATAL(&fx, "routing-only reload failed");
	}
	struct config *const nc =
		make_listen_with_occupied_peer(&fx, NULL, fx.tcp_port_b);
	if (nc == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	struct identity_peer *const peers = (struct identity_peer *)realloc(
		(void *)nc->identity.peers, 2 * sizeof(peers[0]));
	if (peers == NULL) {
		conf_free(nc);
		FIXTURE_FATAL(&fx, "realloc failed");
	}
	nc->identity.peers = peers;
	peers[1] = peers[0];
	char addr[64];
	(void)snprintf(addr, sizeof(addr), "127.0.0.1:%d", fx.tcp_port_a);
	peers[0] = (struct identity_peer){ .id = strdup("retained"),
					   .listen = strdup(addr) };
	nc->identity.peers_count = 2;
	if (peers[0].id == NULL || peers[0].listen == NULL) {
		conf_free(nc);
		FIXTURE_FATAL(&fx, "strdup failed");
	}
	const bool applied = server_apply_config(fx.srv_a, nc);
	fx.conf_a = fx.srv_a->conf;
	void *elem;
	const bool found = table_find(fx.srv_a->identities, "retained", &elem);
	const bool peer_stopped =
		found &&
		((struct identity_listener *)elem)->listener.w_accept.fd == -1;
	const bool owner_restored =
		found &&
		((struct identity_listener *)elem)->listener.socket_opts ==
			&fx.conf_a->tcp;
	const bool local_restored =
		get_listener_port(&fx.srv_a->local_listener) == fx.tcp_port_a;
	fixture_teardown(&fx);
	T_EXPECT(!applied);
	T_EXPECT(peer_stopped);
	T_EXPECT(owner_restored);
	T_EXPECT(local_restored);
}

/* Count the live tunnels s currently pools under the peer identity id, or
 * SIZE_MAX if the stats snapshot could not be taken. */
static size_t
count_pooled_tunnels(const struct server *restrict s, const char *restrict id)
{
	struct server_stats *const stats = server_stats(s, true);
	if (stats == NULL) {
		return SIZE_MAX;
	}
	size_t count = 0;
	for (size_t i = 0; i < stats->num_tunnels; i++) {
		if (stats->tunnels[i].peer_identity != NULL &&
		    strcmp(stats->tunnels[i].peer_identity, id) == 0) {
			count++;
		}
	}
	free(stats);
	return count;
}

struct identity_pool_wait_ctx {
	const struct server *srv_a;
	const char *peer_identity;
	size_t expected;
};

/* Polls server_stats() for the condition under test (>= expected tunnels
 * pooled under peer_identity) instead of the session counters: a session is
 * counted established on its tunnel's thread before the server loop pools the
 * tunnel, and two concurrent connects bump independent relaxed atomics, so a
 * counter-based wait can pass while server_stats()'s own tunnels[] walk -- the
 * thing these tests assert on -- does not match it yet. */
static int identity_pool_wait_predicate(void *ptr)
{
	const struct identity_pool_wait_ctx *const restrict ctx = ptr;
	const size_t count =
		count_pooled_tunnels(ctx->srv_a, ctx->peer_identity);
	return count != SIZE_MAX && count >= ctx->expected ? 1 : 0;
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
	/* The session counts as established before srv_a pools its tunnel. */
	struct identity_pool_wait_ctx pool_ctx = {
		.srv_a = fx.srv_a,
		.peer_identity = "peer1",
		.expected = 1,
	};
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    identity_pool_wait_predicate, &pool_ctx) != 0) {
		FIXTURE_FATAL(&fx, "peer1 tunnel not pooled");
	}

	/* Reload srv_a with an otherwise-identical config that drops "peer1"
	 * entirely (not just changes it) -- server_apply_config takes ownership
	 * of new_conf, including on failure. Assertions are deferred until after
	 * teardown; failing early would leak the loop's signal watchers and
	 * corrupt later tests in this process. */
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

	T_EXPECT(applied);
	T_EXPECT_EQ(num_tunnels_after, (size_t)0);
}

/* Build the config this case reloads: mux_listen on an ephemeral port, an
 * identity claim of "server-a", and num_peers peers named peer1..peerN, each
 * listening on an ephemeral port. Returns NULL on allocation failure, having
 * freed whatever it built. */
static struct config *make_identity_peers_config(const size_t num_peers)
{
	struct config *const conf =
		make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf == NULL) {
		return NULL;
	}
	conf->identity.claim = strdup("server-a");
	conf->identity.peers = calloc(num_peers, sizeof(*conf->identity.peers));
	if (conf->identity.claim == NULL || conf->identity.peers == NULL) {
		conf_free(conf);
		return NULL;
	}
	conf->identity.peers_count = num_peers;
	for (size_t i = 0; i < num_peers; i++) {
		char id[32];
		(void)snprintf(id, sizeof(id), "peer%zu", i + 1);
		conf->identity.peers[i] = (struct identity_peer){
			.id = strdup(id),
			.listen = strdup("127.0.0.1:0"),
		};
		if (conf->identity.peers[i].id == NULL ||
		    conf->identity.peers[i].listen == NULL) {
			conf_free(conf);
			return NULL;
		}
	}
	return conf;
}

/* Regression: a reload that keeps an identity peer must keep that peer's
 * listener and its pooled tunnels reachable. The rebuild locates the retained
 * peer with a table lookup that cannot miss, and once made that lookup the
 * operand of ASSERT() -- which expands to `((void)(0))` under NDEBUG, so in a
 * release build the call never runs, the out-param stays NULL, and the very
 * next store dereferences it. Reloads twice: first with an unchanged peer
 * table, then with a peer added, which must still carry the retained peer's
 * live pool over. Both crashed a release build before that fix; a debug build
 * never did, because ASSERT() is live there. */
T_DECLARE_CASE(test_server_reload_retains_identity_peer)
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

	fx.conf_a = make_identity_peers_config(1);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "make_identity_peers_config(conf_a) failed");
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
	/* The session counts as established before srv_a pools its tunnel. */
	struct identity_pool_wait_ctx pool_ctx = {
		.srv_a = fx.srv_a,
		.peer_identity = "peer1",
		.expected = 1,
	};
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    identity_pool_wait_predicate, &pool_ctx) != 0) {
		FIXTURE_FATAL(&fx, "peer1 tunnel not pooled");
	}

	/* Defer assertions until after teardown; failing early would leak the
	 * loop's signal watchers and corrupt later tests in this process. */
	const size_t pooled_before = count_pooled_tunnels(fx.srv_a, "peer1");

	/* Reload with an identical peer table: the rebuild only repoints each
	 * retained listener at the new config. */
	struct config *const new_conf = make_identity_peers_config(1);
	if (new_conf == NULL) {
		FIXTURE_FATAL(
			&fx, "make_identity_peers_config(new_conf) failed");
	}
	const bool applied_unchanged = server_apply_config(fx.srv_a, new_conf);
	fx.conf_a =
		fx.srv_a->conf; /* old conf_a was freed by server_apply_config */
	const size_t pooled_unchanged = count_pooled_tunnels(fx.srv_a, "peer1");
	/* The retained listener must now name the peer through the new config's
	 * own string: the old one is freed the moment this reload returns. */
	void *elem = NULL;
	const bool repointed =
		table_find(fx.srv_a->identities, "peer1", &elem) &&
		((const struct identity_listener *)elem)->peer_identity ==
			fx.conf_a->identity.peers[0].id;

	/* Reload with a peer added: peer1's listener, pool included, has to
	 * carry over into the rebuilt table. */
	struct config *const new_conf2 = make_identity_peers_config(2);
	if (new_conf2 == NULL) {
		FIXTURE_FATAL(
			&fx, "make_identity_peers_config(new_conf2) failed");
	}
	const bool applied_changed = server_apply_config(fx.srv_a, new_conf2);
	fx.conf_a = fx.srv_a->conf;
	const size_t pooled_changed = count_pooled_tunnels(fx.srv_a, "peer1");

	fixture_teardown(&fx);

	T_EXPECT_EQ(pooled_before, (size_t)1);
	/* Unchanged peer table: reload applies and the pooled tunnel stays. */
	T_EXPECT(applied_unchanged);
	T_EXPECT_EQ(pooled_unchanged, (size_t)1);
	/* The retained listener adopted the new config's own id pointer. */
	T_EXPECT(repointed);
	/* Changed peer table: the retained peer keeps its pool. */
	T_EXPECT(applied_changed);
	T_EXPECT_EQ(pooled_changed, (size_t)1);
}

/* The listener s serves peer id through, or NULL when s has no such peer. */
static const struct identity_listener *
find_identity_listener(const struct server *restrict s, const char *restrict id)
{
	void *elem = NULL;
	if (!table_find(s->identities, id, &elem)) {
		return NULL;
	}
	return elem;
}

/* The fd and the port of the socket s listens on for peer id; -1 each when s
 * has no such peer or the peer has no socket. */
static int identity_listener_fd(const struct server *restrict s, const char *id)
{
	const struct identity_listener *const sl =
		find_identity_listener(s, id);
	return sl != NULL ? sl->listener.w_accept.fd : -1;
}

static int
identity_listener_port(const struct server *restrict s, const char *id)
{
	const struct identity_listener *const sl =
		find_identity_listener(s, id);
	return sl != NULL ? get_listener_port(&sl->listener) : -1;
}

/* Replace peer i's listen address in conf with 127.0.0.1:port (port 0 picks an
 * ephemeral one). False on OOM. The cases below only ever name a port srv_a
 * already listens on: one picked free and released up front could be taken by
 * any ephemeral bind, the server's own included, before srv_a binds it. */
static bool set_identity_peer_port(
	struct config *restrict conf, const size_t i, const int port)
{
	char addr[64];
	(void)snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
	char *const listen = strdup(addr);
	if (listen == NULL) {
		return false;
	}
	free(conf->identity.peers[i].listen);
	conf->identity.peers[i].listen = listen;
	return true;
}

/* A blocking connect to 127.0.0.1:port that never runs the event loop, so the
 * connection completes into the listener's accept queue and stays there
 * unaccepted. -1 on failure. */
static int connect_unaccepted(const int port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons((unsigned)port & 0xFFFFu);
	if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		(void)close(fd);
		return -1;
	}
	return fd;
}

/* True while fd's connection is open with nothing to read: neither reset nor
 * closed by the other end. */
static bool connection_still_open(const int fd)
{
	char byte;
	const ssize_t n = recv(fd, &byte, 1, MSG_DONTWAIT);
	return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

/* Regression: a reload that changes the identity peer set must leave the
 * listening socket of every peer whose listen address is unchanged alone. It
 * once stopped and rebound every identity listener, so an unchanged peer on an
 * ephemeral port moved to another port, and a connection waiting in its accept
 * queue was reset. The same reload also moves two peers onto each other's
 * port and adds a peer, which the rebound listeners must still accommodate. */
T_DECLARE_CASE(test_server_reload_keeps_unchanged_identity_listener)
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

	fx.conf_a = make_identity_peers_config(3);
	if (fx.conf_a == NULL) {
		FIXTURE_FATAL(&fx, "building conf_a failed");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}

	const int fd1_before = identity_listener_fd(fx.srv_a, "peer1");
	const int port1_before = identity_listener_port(fx.srv_a, "peer1");
	const int port2 = identity_listener_port(fx.srv_a, "peer2");
	const int port3 = identity_listener_port(fx.srv_a, "peer3");
	if (port2 <= 0 || port3 <= 0) {
		FIXTURE_FATAL(&fx, "reading peer ports failed");
	}
	/* Waits in peer1's accept queue across the reload. */
	const int pending =
		port1_before > 0 ? connect_unaccepted(port1_before) : -1;

	/* peer1 unchanged, peer2 and peer3 trade ports on fixed addresses, peer4
	 * is new. */
	struct config *const new_conf = make_identity_peers_config(4);
	if (new_conf == NULL || !set_identity_peer_port(new_conf, 1, port3) ||
	    !set_identity_peer_port(new_conf, 2, port2)) {
		if (new_conf != NULL) {
			conf_free(new_conf);
		}
		if (pending >= 0) {
			(void)close(pending);
		}
		FIXTURE_FATAL(&fx, "building new_conf failed");
	}
	const bool applied = server_apply_config(fx.srv_a, new_conf);
	fx.conf_a = fx.srv_a->conf;

	const int fd1_after = identity_listener_fd(fx.srv_a, "peer1");
	const int port1_after = identity_listener_port(fx.srv_a, "peer1");
	const int port2_after = identity_listener_port(fx.srv_a, "peer2");
	const int port3_after = identity_listener_port(fx.srv_a, "peer3");
	const int port4_after = identity_listener_port(fx.srv_a, "peer4");
	const bool pending_open =
		pending >= 0 && connection_still_open(pending);
	/* Every listener names its peer through the new config's own string. */
	bool repointed = applied;
	for (size_t i = 0; applied && i < fx.conf_a->identity.peers_count;
	     i++) {
		const struct identity_peer *const p =
			&fx.conf_a->identity.peers[i];
		const struct identity_listener *const sl =
			find_identity_listener(fx.srv_a, p->id);
		if (sl == NULL || sl->peer_identity != p->id ||
		    sl->listener.socket_opts != &fx.conf_a->tcp) {
			repointed = false;
		}
	}
	if (pending >= 0) {
		(void)close(pending);
	}

	fixture_teardown(&fx);

	T_EXPECT(fd1_before >= 0);
	T_EXPECT(port1_before > 0);
	T_EXPECT(pending >= 0);
	T_EXPECT(applied);
	/* peer1 keeps its very socket, and with it the queued connection. */
	T_EXPECT_EQ(fd1_after, fd1_before);
	T_EXPECT_EQ(port1_after, port1_before);
	T_EXPECT(pending_open);
	T_EXPECT_EQ(port2_after, port3);
	T_EXPECT_EQ(port3_after, port2);
	T_EXPECT(port4_after > 0);
	T_EXPECT(repointed);
}

/* A reload whose new identity listener cannot be bound is rejected with the
 * running identity table intact: the unchanged peer's socket untouched, the
 * changed and the removed peer's listeners bound back on their old ports, and
 * the new peer's listener gone. */
T_DECLARE_CASE(test_server_reload_restores_identity_listeners_on_bind_failure)
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

	const int occupied_fd = bind_listen_localhost();
	const int occupied_port =
		occupied_fd >= 0 ? listener_fd_port(occupied_fd) : -1;
	if (occupied_port <= 0) {
		if (occupied_fd >= 0) {
			socket_close(occupied_fd);
		}
		FIXTURE_FATAL(&fx, "occupying a port failed");
	}
	fx.conf_a = make_identity_peers_config(3);
	if (fx.conf_a == NULL) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "building conf_a failed");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}
	struct config *const old_conf = fx.srv_a->conf;
	const struct hashtable *const old_tbl = fx.srv_a->identities;
	const struct identity_listener *const sl1 =
		find_identity_listener(fx.srv_a, "peer1");
	const int fd1_before = identity_listener_fd(fx.srv_a, "peer1");
	const int port1_before = identity_listener_port(fx.srv_a, "peer1");
	const int port2 = identity_listener_port(fx.srv_a, "peer2");
	const int port3 = identity_listener_port(fx.srv_a, "peer3");
	if (port2 <= 0 || port3 <= 0) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "reading peer ports failed");
	}

	/* peer1 unchanged, peer2 moved to the port of peer3, which is removed,
	 * and peer4 new on the occupied port -- the bind that fails. */
	struct config *const new_conf = make_identity_peers_config(3);
	char *const peer4 = strdup("peer4");
	if (new_conf == NULL || peer4 == NULL ||
	    !set_identity_peer_port(new_conf, 1, port3) ||
	    !set_identity_peer_port(new_conf, 2, occupied_port)) {
		free(peer4);
		if (new_conf != NULL) {
			conf_free(new_conf);
		}
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "building new_conf failed");
	}
	free(new_conf->identity.peers[2].id);
	new_conf->identity.peers[2].id = peer4;
	new_conf->identity.peers[2].id_len = strlen(peer4);

	const bool applied = server_apply_config(fx.srv_a, new_conf);
	const bool conf_kept = fx.srv_a->conf == old_conf;
	const bool table_kept = fx.srv_a->identities == old_tbl;

	const struct identity_listener *const sl1_after =
		find_identity_listener(fx.srv_a, "peer1");
	const struct identity_listener *const sl2_after =
		find_identity_listener(fx.srv_a, "peer2");
	const struct identity_listener *const sl3_after =
		find_identity_listener(fx.srv_a, "peer3");
	const int fd1_after = identity_listener_fd(fx.srv_a, "peer1");
	const int port1_after = identity_listener_port(fx.srv_a, "peer1");
	const int port2_after = identity_listener_port(fx.srv_a, "peer2");
	const int port3_after = identity_listener_port(fx.srv_a, "peer3");
	const bool peer4_absent =
		find_identity_listener(fx.srv_a, "peer4") == NULL;
	const size_t num_peers = table_size(fx.srv_a->identities);
	/* The restored listeners still take the running config's options. */
	const bool opts_kept =
		sl2_after != NULL &&
		sl2_after->listener.socket_opts == &old_conf->tcp &&
		sl3_after != NULL &&
		sl3_after->listener.socket_opts == &old_conf->tcp;
	/* Each old port accepts again. */
	int accepted = 0;
	const int ports[] = { port1_before, port2, port3 };
	for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
		const int fd = connect_unaccepted(ports[i]);
		if (fd >= 0) {
			accepted++;
			(void)close(fd);
		}
	}
	socket_close(occupied_fd);

	fixture_teardown(&fx);

	T_EXPECT(fd1_before >= 0);
	T_EXPECT(!applied);
	T_EXPECT(conf_kept);
	T_EXPECT(table_kept);
	T_EXPECT(sl1_after == sl1);
	T_EXPECT_EQ(fd1_after, fd1_before);
	T_EXPECT_EQ(port1_after, port1_before);
	T_EXPECT_EQ(port2_after, port2);
	T_EXPECT_EQ(port3_after, port3);
	T_EXPECT(peer4_absent);
	T_EXPECT_EQ(num_peers, (size_t)3);
	T_EXPECT(opts_kept);
	T_EXPECT_EQ(accepted, 3);
}

/* Regression: a rejected reload restores peers that traded addresses. peer1
 * and peer2 swap ports and are both rebound before peer3's bind fails. The
 * restore once stopped and rebound one peer at a time, so peer1 went back to
 * its old port while peer2 still held it and was left with no listener. */
T_DECLARE_CASE(test_server_reload_restores_traded_identity_listeners)
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

	const int occupied_fd = bind_listen_localhost();
	const int occupied_port =
		occupied_fd >= 0 ? listener_fd_port(occupied_fd) : -1;
	if (occupied_port <= 0) {
		if (occupied_fd >= 0) {
			socket_close(occupied_fd);
		}
		FIXTURE_FATAL(&fx, "occupying a port failed");
	}
	fx.conf_a = make_identity_peers_config(3);
	if (fx.conf_a == NULL) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "building conf_a failed");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}
	struct config *const old_conf = fx.srv_a->conf;
	const int port1 = identity_listener_port(fx.srv_a, "peer1");
	const int port2 = identity_listener_port(fx.srv_a, "peer2");
	const int port3 = identity_listener_port(fx.srv_a, "peer3");
	if (port1 <= 0 || port2 <= 0 || port3 <= 0) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "reading peer ports failed");
	}

	/* peer1 and peer2 trade ports; peer3 moves to the occupied port. */
	struct config *const new_conf = make_identity_peers_config(3);
	if (new_conf == NULL || !set_identity_peer_port(new_conf, 0, port2) ||
	    !set_identity_peer_port(new_conf, 1, port1) ||
	    !set_identity_peer_port(new_conf, 2, occupied_port)) {
		if (new_conf != NULL) {
			conf_free(new_conf);
		}
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "building new_conf failed");
	}

	const bool applied = server_apply_config(fx.srv_a, new_conf);
	const bool conf_kept = fx.srv_a->conf == old_conf;
	const int port1_after = identity_listener_port(fx.srv_a, "peer1");
	const int port2_after = identity_listener_port(fx.srv_a, "peer2");
	const int port3_after = identity_listener_port(fx.srv_a, "peer3");
	int accepted = 0;
	const int ports[] = { port1, port2, port3 };
	for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
		const int fd = connect_unaccepted(ports[i]);
		if (fd >= 0) {
			accepted++;
			(void)close(fd);
		}
	}
	socket_close(occupied_fd);

	fixture_teardown(&fx);

	T_EXPECT(!applied);
	T_EXPECT(conf_kept);
	T_EXPECT_EQ(port1_after, port1);
	T_EXPECT_EQ(port2_after, port2);
	T_EXPECT_EQ(port3_after, port3);
	T_EXPECT_EQ(accepted, 3);
}

/* Regression: a rejected reload binds each released identity listener back on
 * the address its socket held, not on its old listen string resolved anew.
 * peer1 and peer2 listen on ephemeral ports; the reload moves peer1 to peer2's
 * port as a fixed one, drops peer2, and fails on new peer3's occupied port. The
 * restore once resolved "127.0.0.1:0" again, so both came back on fresh
 * ephemeral ports. */
T_DECLARE_CASE(test_server_reload_restores_identity_listener_bound_port)
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

	const int occupied_fd = bind_listen_localhost();
	const int occupied_port =
		occupied_fd >= 0 ? listener_fd_port(occupied_fd) : -1;
	if (occupied_port <= 0) {
		if (occupied_fd >= 0) {
			socket_close(occupied_fd);
		}
		FIXTURE_FATAL(&fx, "occupying a port failed");
	}
	fx.conf_a = make_identity_peers_config(2);
	if (fx.conf_a == NULL) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "building conf_a failed");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "srv_a start failed");
	}
	const int port1_before = identity_listener_port(fx.srv_a, "peer1");
	const int port2_before = identity_listener_port(fx.srv_a, "peer2");
	if (port1_before <= 0 || port2_before <= 0) {
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "reading peer ports failed");
	}

	/* peer1 moved to the fixed port of peer2, which is removed, and peer3 new
	 * on the occupied port -- the bind that fails. */
	struct config *const new_conf = make_identity_peers_config(2);
	char *const peer3 = strdup("peer3");
	if (new_conf == NULL || peer3 == NULL ||
	    !set_identity_peer_port(new_conf, 0, port2_before) ||
	    !set_identity_peer_port(new_conf, 1, occupied_port)) {
		free(peer3);
		if (new_conf != NULL) {
			conf_free(new_conf);
		}
		socket_close(occupied_fd);
		FIXTURE_FATAL(&fx, "building new_conf failed");
	}
	free(new_conf->identity.peers[1].id);
	new_conf->identity.peers[1].id = peer3;
	new_conf->identity.peers[1].id_len = strlen(peer3);

	const bool applied = server_apply_config(fx.srv_a, new_conf);
	const int port1_after = identity_listener_port(fx.srv_a, "peer1");
	const int port2_after = identity_listener_port(fx.srv_a, "peer2");
	int accepted = 0;
	const int ports[] = { port1_before, port2_before };
	for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
		const int fd = connect_unaccepted(ports[i]);
		if (fd >= 0) {
			accepted++;
			(void)close(fd);
		}
	}
	socket_close(occupied_fd);

	fixture_teardown(&fx);

	T_EXPECT(!applied);
	T_EXPECT_EQ(port1_after, port1_before);
	T_EXPECT_EQ(port2_after, port2_before);
	T_EXPECT_EQ(accepted, 2);
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

static struct mux_frame *resume_peer_alloc(void *data, size_t size)
{
	(void)data;
	return malloc(size);
}

static void resume_peer_free(void *data, struct mux_frame *frame)
{
	(void)data;
	free(frame);
}

static size_t server_capacity_used(struct server *srv)
{
#if WITH_THREADS
	T_CHECK(smtx_sharedlock(&srv->accepted_mu) == thrd_success);
#endif
	const size_t used = srv->session_slots;
#if WITH_THREADS
	T_CHECK(smtx_sharedunlock(&srv->accepted_mu) == thrd_success);
#endif
	return used;
}

struct resume_peer_wait_ctx {
	struct mux_session *peer;
	struct tunnel *accepted;
	const struct server *server;
};

static int resume_peer_suspended_predicate(void *data)
{
	const struct resume_peer_wait_ctx *const ctx = data;
	return mux_state(ctx->peer) == MUX_STATE_SUSPENDED &&
			       tunnel_state(ctx->accepted) ==
				       MUX_STATE_SUSPENDED ?
		       1 :
		       0;
}

static int resume_peer_completed_predicate(void *data)
{
	const struct resume_peer_wait_ctx *const ctx = data;
	return mux_state(ctx->peer) == MUX_STATE_ESTABLISHED &&
			       table_size(ctx->server->accepted_tunnels) == 1 ?
		       1 :
		       0;
}

/* The unbound peer may change its non-NULL hello claim on successful resume.
 * Drive a real resume, then check both routing pools and unique stats entries. */
T_DECLARE_CASE(test_server_resume_reconciles_changed_identity)
{
	struct test_fixture fx = {
		.loop = ev_loop_new(EVFLAG_AUTO),
		.backend_a = { .listen_fd = -1 },
		.backend_b = { .listen_fd = -1 },
		.udp_echo_a = { .fd = -1 },
		.udp_echo_b = { .fd = -1 },
	};
	struct mux_session *peer = NULL;
	bool resumed = false;
	size_t suspended_usage = SIZE_MAX;
	size_t resumed_usage = SIZE_MAX;
	size_t alice_count = SIZE_MAX;
	size_t bob_count = SIZE_MAX;
	size_t stats_count = SIZE_MAX;
	uint_least64_t initial_index = 0;
	uint_least64_t resumed_index = 0;
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.conf_a->max_sessions = 1;
	fx.conf_a->identity.peers =
		calloc(2, sizeof(fx.conf_a->identity.peers[0]));
	if (fx.conf_a->identity.peers == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.conf_a->identity.peers_count = 2;
	fx.conf_a->identity.peers[0].id = strdup("alice");
	fx.conf_a->identity.peers[1].id = strdup("bob");
	if (fx.conf_a->identity.peers[0].id == NULL ||
	    fx.conf_a->identity.peers[1].id == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		T_FAIL();
		goto cleanup;
	}
	const int port = get_listener_port(&fx.srv_a->mux_listener);
	static const struct mux_callbacks callbacks = { 0 };
	static const unsigned char id[MUX_SESSION_ID_LEN] = { 1 };
	const struct mux_session_config conf = conf_get_mux(fx.conf_a);
	const struct mux_session_opts opts = {
		.callbacks = &callbacks,
		.conf = &conf,
		.fd = -1,
		.id = id,
		.identity = "alice",
		.pool = { resume_peer_alloc, resume_peer_free, NULL },
	};
	peer = mux_new(fx.loop, &opts);
	if (peer == NULL) {
		T_FAIL();
		goto cleanup;
	}
	int fd = connect_local(&fx, port);
	if (fd < 0) {
		T_FAIL();
		goto cleanup;
	}
	mux_attach_fd(peer, fd);
	struct pool_size_wait_ctx wait = {
		.srv = fx.srv_a,
		.peer_identity = "alice",
		.expected = 1,
	};
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    pool_size_wait_predicate, &wait) != 0) {
		T_LOG("initial alice handshake failed");
		T_FAIL();
		goto cleanup;
	}
	void *elem;
	(void)table_find(fx.srv_a->identities, "alice", &elem);
	struct tunnel *const accepted =
		((struct identity_listener *)elem)->tunnels[0];
	initial_index = tunnel_index(accepted);
	struct resume_peer_wait_ctx suspended = { .peer = peer,
						  .accepted = accepted,
						  .server = fx.srv_a };
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    resume_peer_completed_predicate, &suspended) != 0) {
		T_LOG("initial client handshake failed");
		T_FAIL();
		goto cleanup;
	}
	(void)shutdown(mux_fd(peer), SHUT_RDWR);
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    resume_peer_suspended_predicate, &suspended) != 0) {
		T_LOG("transport did not suspend");
		T_FAIL();
		goto cleanup;
	}
	suspended_usage = server_capacity_used(fx.srv_a);
	/* This client session runs on the test loop, so its hello claim can be
	 * changed without racing a tunnel worker. Its session ID is preserved. */
	char *const claim = strdup("bob");
	if (claim == NULL) {
		T_FAIL();
		goto cleanup;
	}
	free(peer->handshake.identity);
	peer->handshake.identity = claim;
	fd = connect_local(&fx, port);
	if (fd < 0) {
		T_FAIL();
		goto cleanup;
	}
	mux_attach_fd(peer, fd);
	suspended.server = fx.srv_a;
	resumed = wait_until(
			  &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
			  resume_peer_completed_predicate, &suspended) == 0;
	alice_count = identity_pool_size(fx.srv_a, "alice");
	bob_count = identity_pool_size(fx.srv_a, "bob");
	struct server_stats *const stats = server_stats(fx.srv_a, false);
	if (stats != NULL) {
		stats_count = stats->num_tunnels;
		if (stats_count > 0) {
			resumed_index = stats->tunnels[0].tunnel_index;
		}
		free(stats);
	}
	resumed_usage = server_capacity_used(fx.srv_a);
cleanup:
	if (peer != NULL) {
		mux_close(peer);
	}
	fixture_teardown(&fx);
	T_EXPECT_EQ(suspended_usage, (size_t)1);
	T_EXPECT_EQ(resumed_usage, (size_t)1);
	T_EXPECT(resumed);
	T_EXPECT_EQ(alice_count, (size_t)0);
	T_EXPECT_EQ(bob_count, (size_t)1);
	T_EXPECT_EQ(stats_count, (size_t)1);
	T_EXPECT(initial_index != 0);
	T_EXPECT_EQ(resumed_index, initial_index);
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

#ifdef SERVER_TEST_WRAP_REALLOC
T_DECLARE_CASE(test_server_maintenance_retries_identity_array_growth)
{
	struct test_fixture fx = {
		.loop = ev_loop_new(EVFLAG_AUTO),
		.backend_a = { .listen_fd = -1 },
		.backend_b = { .listen_fd = -1 },
		.udp_echo_a = { .fd = -1 },
		.udp_echo_b = { .fd = -1 },
	};
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	fx.conf_a = make_config(NULL, NULL, NULL, NULL);
	if (fx.conf_a == NULL ||
	    !build_identity_dialer_conf(fx.conf_a, "127.0.0.1:1")) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		FIXTURE_FATAL(&fx, "server_start failed");
	}
	struct config *const nc = make_config(NULL, NULL, NULL, NULL);
	if (nc == NULL || !build_identity_dialer_conf(nc, "127.0.0.1:1")) {
		conf_free(nc);
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	char **const addresses = (char **)realloc(
		(void *)nc->identity.mux_connect, 2 * sizeof(*addresses));
	if (addresses == NULL) {
		conf_free(nc);
		FIXTURE_FATAL(&fx, "realloc failed");
	}
	nc->identity.mux_connect = addresses;
	addresses[1] = strdup("127.0.0.1:2");
	if (addresses[1] == NULL) {
		conf_free(nc);
		FIXTURE_FATAL(&fx, "strdup failed");
	}
	nc->identity.mux_connect_count = 2;
	atomic_store_explicit(
		&fail_realloc_ptr, (uintptr_t)fx.srv_a->identity_tunnels,
		memory_order_relaxed);
	T_CLEANUP(clear_realloc_failure, NULL);
	const bool applied = server_apply_config(fx.srv_a, nc);
	fx.conf_a = fx.srv_a->conf;
	const bool failed_growth =
		atomic_load_explicit(&fail_realloc_ptr, memory_order_relaxed) ==
			0 &&
		fx.srv_a->num_identity_tunnels == 1;
	const bool retry_armed = ev_is_active(&fx.srv_a->w_maintenance);
	clear_realloc_failure(NULL);
	ev_invoke(fx.loop, &fx.srv_a->w_maintenance, EV_TIMER);
	const bool grew = fx.srv_a->num_identity_tunnels == 2 &&
			  fx.srv_a->identity_tunnels[1] != NULL;
	fixture_teardown(&fx);
	T_EXPECT(applied);
	T_EXPECT(failed_growth);
	T_EXPECT(retry_armed);
	T_EXPECT(grew);
}
#endif /* SERVER_TEST_WRAP_REALLOC */

struct slot_closed_wait_ctx {
	const struct server *srv;
};

static int slot_closed_predicate(void *ptr)
{
	const struct slot_closed_wait_ctx *const restrict ctx = ptr;
	const struct tunnel *const t = ctx->srv->identity_tunnels[0];
	return t != NULL && tunnel_state(t) == MUX_STATE_CLOSED ? 1 : 0;
}

/* An on-demand identity tunnel (mux.idle_timeout > 0) whose dial failed is
 * CLOSED, and it waits in its slot for the local connection that redials it:
 * the tunnel keeps that CLOSED to itself.  A maintenance pass must leave it
 * there.  It must not take the CLOSED state for a lost close notification,
 * tear the tunnel down and dial a replacement nobody asked for. */
T_DECLARE_CASE(test_server_maintenance_keeps_idle_on_demand_identity_tunnel)
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

	/* A bound socket that never listens: every dial to it is refused. */
	const int refuse_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (refuse_fd < 0) {
		FIXTURE_FATAL(&fx, "socket failed");
	}
	struct sockaddr_in refuse_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t refuse_len = sizeof(refuse_sa);
	if (bind(refuse_fd, (struct sockaddr *)&refuse_sa, sizeof(refuse_sa)) !=
		    0 ||
	    getsockname(refuse_fd, (struct sockaddr *)&refuse_sa, &refuse_len) !=
		    0) {
		(void)close(refuse_fd);
		FIXTURE_FATAL(&fx, "bind failed");
	}
	char mux_connect[64];
	(void)snprintf(
		mux_connect, sizeof(mux_connect), "127.0.0.1:%d",
		(int)ntohs(refuse_sa.sin_port));

	fx.conf_b = make_config(NULL, NULL, NULL, NULL);
	if (fx.conf_b == NULL ||
	    !build_identity_dialer_conf(fx.conf_b, mux_connect)) {
		(void)close(refuse_fd);
		FIXTURE_FATAL(&fx, "building conf_b failed");
	}
	fx.conf_b->mux.idle_timeout = 60;
	fx.srv_b = server_new(fx.loop, fx.conf_b);
	if (fx.srv_b == NULL || !server_start(fx.srv_b)) {
		(void)close(refuse_fd);
		FIXTURE_FATAL(&fx, "srv_b start failed");
	}

	struct slot_closed_wait_ctx wait_ctx = { .srv = fx.srv_b };
	const bool closed =
		wait_until(
			&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
			slot_closed_predicate, &wait_ctx) == 0;
	const struct tunnel *const before = fx.srv_b->identity_tunnels[0];
	const uint_least64_t index_before = fx.srv_b->next_tunnel_index;
	ev_invoke(fx.loop, &fx.srv_b->w_maintenance, EV_TIMER);
	const struct tunnel *const after = fx.srv_b->identity_tunnels[0];
	/* A replacement tunnel takes a fresh index even if the allocator hands
	 * it the old tunnel's address. */
	const uint_least64_t index_after = fx.srv_b->next_tunnel_index;

	fixture_teardown(&fx);
	(void)close(refuse_fd);

	T_EXPECT(closed);
	T_EXPECT(before != NULL);
	T_EXPECT(after == before);
	T_EXPECT_EQ(index_after, index_before);
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

struct capacity_peer_wait {
	struct mux_session **peers;
	size_t count;
};

static int capacity_peers_settled(void *data)
{
	const struct capacity_peer_wait *const wait = data;
	for (size_t i = 0; i < wait->count; i++) {
		const enum mux_state state = mux_state(wait->peers[i]);
		if (state != MUX_STATE_ESTABLISHED &&
		    state != MUX_STATE_CLOSED && state != MUX_STATE_SUSPENDED) {
			return 0;
		}
	}
	return 1;
}

static struct mux_session *capacity_peer_new(struct test_fixture *fx)
{
	static const struct mux_callbacks callbacks = { 0 };
	static const unsigned char id[MUX_SESSION_ID_LEN] = { 42 };
	const struct mux_session_config conf = conf_get_mux(fx->srv_a->conf);
	const struct mux_session_opts opts = {
		.callbacks = &callbacks,
		.conf = &conf,
		.fd = -1,
		.id = id,
		.pool = { resume_peer_alloc, resume_peer_free, NULL },
	};
	return mux_new(fx->loop, &opts);
}

struct capacity_accept_wait {
	struct server *srv;
	size_t count;
};

static int capacity_accepted(void *data)
{
	const struct capacity_accept_wait *const wait = data;
	return table_size(wait->srv->accepted_tunnels) == wait->count;
}

/* Queue every TCP transport before any hello, then drive all client hellos
 * together. The tunnel workers compete for one shared capacity reservation. */
T_DECLARE_CASE(test_server_capacity_simultaneous_inbound)
{
	struct test_fixture fx = {
		.loop = ev_loop_new(EVFLAG_AUTO),
		.backend_a = { .listen_fd = -1 },
		.backend_b = { .listen_fd = -1 },
		.udp_echo_a = { .fd = -1 },
		.udp_echo_b = { .fd = -1 },
	};
	enum { N = 4 };
	struct mux_session *peers[N] = { 0 };
	int fds[N] = { -1, -1, -1, -1 };
	size_t established = 0;
	bool settled = false;
	size_t halfopen_used = SIZE_MAX;
	size_t established_used = SIZE_MAX;
	size_t stopped_used = SIZE_MAX;
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	fx.conf_a = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (fx.conf_a == NULL) {
		T_FAIL();
		goto cleanup;
	}
	fx.conf_a->max_sessions = 1;
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL || !server_start(fx.srv_a)) {
		T_FAIL();
		goto cleanup;
	}
	fx.mux_port_a = get_listener_port(&fx.srv_a->mux_listener);
	for (size_t i = 0; i < N; i++) {
		fds[i] = connect_local(&fx, fx.mux_port_a);
		peers[i] = capacity_peer_new(&fx);
		if (fds[i] < 0 || peers[i] == NULL) {
			T_FAIL();
			goto cleanup;
		}
	}
	struct capacity_accept_wait admitted = { fx.srv_a, N };
	if (wait_until(&fx, 2.0, capacity_accepted, &admitted) != 0) {
		T_FAIL();
		goto cleanup;
	}
	halfopen_used = server_capacity_used(fx.srv_a);
	for (size_t i = 0; i < N; i++) {
		mux_attach_fd(peers[i], fds[i]);
		fds[i] = -1;
	}
	struct capacity_peer_wait wait = { peers, N };
	settled = wait_until(&fx, 2.0, capacity_peers_settled, &wait) == 0;
	for (size_t i = 0; i < N; i++) {
		established += mux_state(peers[i]) == MUX_STATE_ESTABLISHED;
	}
	established_used = server_capacity_used(fx.srv_a);
cleanup:
	for (size_t i = 0; i < N; i++) {
		if (peers[i] != NULL) {
			mux_close(peers[i]);
		}
		if (fds[i] >= 0) {
			socket_close(fds[i]);
		}
	}
	if (fx.srv_a != NULL) {
		server_stop(fx.srv_a);
		stopped_used = server_capacity_used(fx.srv_a);
	}
	fixture_teardown(&fx);
	T_EXPECT_EQ(halfopen_used, (size_t)0);
	T_EXPECT(settled);
	T_EXPECT_EQ(established, (size_t)1);
	T_EXPECT_EQ(established_used, (size_t)1);
	T_EXPECT_EQ(stopped_used, (size_t)0);
}

/* Lowering the budget preserves both the established tunnel and its slot.
 * Temporary transports remain admitted, but neither fresh nor unmatched resume
 * hellos can establish. Removing the cap admits fresh sessions again. */
T_DECLARE_CASE(test_server_capacity_reload_and_unmatched_resume)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	struct mux_session *existing = capacity_peer_new(&fx);
	const int existing_fd = connect_local(&fx, fx.mux_port_a);
	if (existing == NULL || existing_fd < 0) {
		if (existing != NULL) {
			mux_close(existing);
		}
		if (existing_fd >= 0) {
			socket_close(existing_fd);
		}
		FIXTURE_FATAL(&fx, "second established peer setup failed");
	}
	mux_attach_fd(existing, existing_fd);
	struct capacity_peer_wait initial = { &existing, 1 };
	if (wait_until(&fx, 2.0, capacity_peers_settled, &initial) != 0 ||
	    mux_state(existing) != MUX_STATE_ESTABLISHED) {
		mux_close(existing);
		FIXTURE_FATAL(&fx, "second peer handshake failed");
	}
	struct config *conf = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	conf->max_sessions = 1;
	if (!server_apply_config(fx.srv_a, conf)) {
		FIXTURE_FATAL(&fx, "capacity reload failed");
	}
	fx.conf_a = conf;
	fx.mux_port_a = get_listener_port(&fx.srv_a->mux_listener);
	const size_t lowered_usage = server_capacity_used(fx.srv_a);
	bool rejects[2] = { false, false };
	size_t retained[2] = { SIZE_MAX, SIZE_MAX };
	for (size_t attempt = 0; attempt < 2; attempt++) {
		struct mux_session *peer = capacity_peer_new(&fx);
		if (peer == NULL) {
			FIXTURE_FATAL(&fx, "mux_new failed");
		}
		if (attempt != 0) {
			peer->handshake.has_session_id = true;
			memset(peer->handshake.session_id, 77,
			       MUX_SESSION_ID_LEN);
		}
		const int fd = connect_local(&fx, fx.mux_port_a);
		if (fd < 0) {
			mux_close(peer);
			FIXTURE_FATAL(&fx, "connect_local failed");
		}
		mux_attach_fd(peer, fd);
		struct capacity_peer_wait wait = { &peer, 1 };
		const bool settled =
			wait_until(&fx, 2.0, capacity_peers_settled, &wait) ==
			0;
		const bool rejected = mux_state(peer) == MUX_STATE_CLOSED ||
				      mux_state(peer) == MUX_STATE_SUSPENDED;
		mux_close(peer);
		rejects[attempt] = settled && rejected;
		retained[attempt] = server_capacity_used(fx.srv_a);
	}
	conf = make_config("127.0.0.1:0", NULL, NULL, NULL);
	if (conf == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	if (!server_apply_config(fx.srv_a, conf)) {
		FIXTURE_FATAL(&fx, "unlimited reload failed");
	}
	fx.conf_a = conf;
	fx.mux_port_a = get_listener_port(&fx.srv_a->mux_listener);
	struct mux_session *peer = capacity_peer_new(&fx);
	const int fd = connect_local(&fx, fx.mux_port_a);
	if (peer == NULL || fd < 0) {
		if (peer != NULL) {
			mux_close(peer);
		}
		if (fd >= 0) {
			socket_close(fd);
		}
		FIXTURE_FATAL(&fx, "unlimited peer setup failed");
	}
	mux_attach_fd(peer, fd);
	struct capacity_peer_wait wait = { &peer, 1 };
	const bool settled =
		wait_until(&fx, 2.0, capacity_peers_settled, &wait) == 0;
	const bool established = mux_state(peer) == MUX_STATE_ESTABLISHED;

	mux_close(existing);
	mux_close(peer);
	fixture_teardown(&fx);
	T_EXPECT_EQ(lowered_usage, (size_t)2);
	T_EXPECT(rejects[0]);
	T_EXPECT(rejects[1]);
	T_EXPECT_EQ(retained[0], (size_t)2);
	T_EXPECT_EQ(retained[1], (size_t)2);
	T_EXPECT(settled);
	T_EXPECT(established);
}

static int capacity_removed_outbound_closed(void *data)
{
	const struct server *const srv = data;
	return srv->mux_tunnel == NULL;
}

/* Capacity reduction preserves retained sessions, but removing a configured
 * outbound tunnel in the same reload must still drain and release its slot. */
T_DECLARE_CASE(test_server_capacity_reduction_drains_removed_outbound)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}
	const int fd = connect_local(&fx, fx.tcp_port_b);
	if (fd < 0) {
		FIXTURE_FATAL(&fx, "connect_local failed");
	}
	if (wait_for_streams_ready(&fx, 1) != 0 ||
	    send_and_expect_echo(&fx, fd, "before", 6, 2.0) != 0) {
		(void)close(fd);
		FIXTURE_FATAL(&fx, "stream setup failed");
	}
	const size_t before = server_capacity_used(fx.srv_b);
	struct config *const conf =
		make_config(NULL, NULL, "127.0.0.1:0", fx.conf_b->connect);
	if (conf == NULL) {
		(void)close(fd);
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	conf->max_sessions = 1;
	if (!server_apply_config(fx.srv_b, conf)) {
		(void)close(fd);
		FIXTURE_FATAL(&fx, "capacity reload failed");
	}
	fx.conf_b = conf;
	/* The active stream keeps the retired tunnel alive until its own close. */
	const bool echoed = send_and_expect_echo(&fx, fd, "after", 5, 2.0) == 0;
	const size_t draining = server_capacity_used(fx.srv_b);
	(void)close(fd);
	const bool closed = wait_until(
				    &fx, 2.0, capacity_removed_outbound_closed,
				    fx.srv_b) == 0;
	const size_t after = server_capacity_used(fx.srv_b);
	fixture_teardown(&fx);
	T_EXPECT(echoed);
	T_EXPECT(closed);
	T_EXPECT_EQ(before, (size_t)1);
	T_EXPECT_EQ(draining, (size_t)1);
	T_EXPECT_EQ(after, (size_t)0);
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

struct admission_wait_ctx {
	const struct server *srv;
	uint_least64_t served0;
	uint_least64_t rejected0;
};

/* Predicate: srv has either admitted or rejected one more mux connection. */
static int admission_decided_predicate(void *ptr)
{
	const struct admission_wait_ctx *const restrict ctx = ptr;
	return ctx->srv->counters.num_served != ctx->served0 ||
	       ctx->srv->counters.num_rejected != ctx->rejected0;
}

static void fake_halfopen_add(struct server *restrict srv, const size_t n)
{
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(
		&srv->counters.num_session_halfopen, n, memory_order_relaxed);
#else
	srv->counters.num_session_halfopen += n;
#endif
}

static void fake_halfopen_sub(struct server *restrict srv, const size_t n)
{
#if WITH_THREADS
	(void)atomic_fetch_sub_explicit(
		&srv->counters.num_session_halfopen, n, memory_order_relaxed);
#else
	srv->counters.num_session_halfopen -= n;
#endif
}

/* Connects to srv_a's mux port and drives the loop until the listener has
 * admitted or rejected it; returns whether it was rejected, or -1 when no
 * decision was observed. */
static int probe_admission(struct test_fixture *restrict fx)
{
	struct admission_wait_ctx ctx = {
		.srv = fx->srv_a,
		.served0 = fx->srv_a->counters.num_served,
		.rejected0 = fx->srv_a->counters.num_rejected,
	};
	const int raw = connect_local(fx, fx->mux_port_a);
	if (raw < 0) {
		return -1;
	}
	const int rc = wait_until(
		fx, (double)CONNECT_WAIT_TIMEOUT_MS / 1000.0,
		admission_decided_predicate, &ctx);
	(void)close(raw);
	if (rc != 0) {
		return -1;
	}
	return fx->srv_a->counters.num_rejected != ctx.rejected0;
}

/* The startup_limit_full hard cap rejects once the half-open count already
 * equals it -- the check runs before this connection is
 * counted -- and admits one below it. rate=0 disables the probabilistic
 * branch, so the cap is the only thing that can reject here. */
T_DECLARE_CASE(test_server_startup_limit_full_rejects_at_exact_limit)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	const int full = 3;
	fx.srv_a->conf->max_sessions = 0;
	fx.srv_a->conf->startup_limit_start = 0;
	fx.srv_a->conf->startup_limit_rate = 0;
	fx.srv_a->conf->startup_limit_full = full;

	/* Rejected connections never touch the half-open count, so the fake
	 * offset stays exact across the first probe. */
	fake_halfopen_add(fx.srv_a, (size_t)full);
	const int at_limit = probe_admission(&fx);
	fake_halfopen_sub(fx.srv_a, 1);
	const int below_limit = probe_admission(&fx);
	fake_halfopen_sub(fx.srv_a, (size_t)full - 1);

	/* Defer assertions until after teardown; failing early would leak the
	 * loop's signal watchers and corrupt later tests in this process. */
	fx.srv_a->conf->startup_limit_full = 0;

	fixture_teardown(&fx);

	T_EXPECT_EQ(at_limit, 1);
	T_EXPECT_EQ(below_limit, 0);
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

/* Records, through w->data, that the timer fired, and breaks the loop: the
 * shutdown tests' safety net, and a stand-in for the force-exit deadline that
 * makes reaching it observable. */
static void
shutdown_safety_break_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)revents;
	*(bool *)w->data = true;
	ev_break(loop, EVBREAK_ALL);
}

/* Bound on a shutdown test's ev_run, well past signal_cb's 2 s force-exit
 * deadline so that the deadline, not this, ends a shutdown that fails to
 * drain. */
static const double SHUTDOWN_SAFETY_S = 10.0;

/* test_server_graceful_shutdown_via_signal: delivers SIGTERM to srv_a (the
 * accepting side) and runs the loop until something breaks it.  The graceful
 * drain must be what ends it -- handle_closed() stops the force-exit deadline
 * and breaks the loop the moment the last session closes -- so the deadline
 * is swapped for a marker that would record it being reached instead. */
T_DECLARE_CASE(test_server_graceful_shutdown_via_signal)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	/* Precondition: there is a session to drain, or the case is vacuous. */
	const bool had_session = srv_a_sessions_drained_predicate(&fx) == 0;

	/* Invoke srv_a's SIGTERM watcher directly; ev_feed_signal_event would
	 * also fire srv_b's watcher and complicate teardown ordering. */
	ev_invoke(fx.loop, &fx.srv_a->w_sigterm, EV_SIGNAL);
	const bool listeners_stopped =
		fx.srv_a->mux_listener.w_accept.fd == -1 &&
		fx.srv_a->local_listener.w_accept.fd == -1;
	/* With a session left to drain, signal_cb armed the deadline. */
	const bool shutting_down = fx.srv_a->shutting_down;
	const bool deadline_armed = ev_is_active(&fx.srv_a->w_maintenance);

	bool deadline_reached = false;
	ev_timer *const w_deadline = &fx.srv_a->w_maintenance;
	void (*const saved_cb)(struct ev_loop *, ev_timer *, int) =
		ev_cb(w_deadline);
	void *const saved_data = w_deadline->data;
	ev_set_cb(w_deadline, shutdown_safety_break_cb);
	w_deadline->data = &deadline_reached;
	/* Bounds a drain that ends neither way, e.g. with the deadline
	 * stopped but the loop never broken. */
	bool safety_fired = false;
	ev_timer w_safety;
	ev_timer_init(
		&w_safety, shutdown_safety_break_cb, SHUTDOWN_SAFETY_S, 0.0);
	w_safety.data = &safety_fired;
	ev_timer_start(fx.loop, &w_safety);
	ev_run(fx.loop, 0);
	ev_timer_stop(fx.loop, &w_safety);
	const bool drained = srv_a_sessions_drained_predicate(&fx) == 1;
	ev_timer_stop(fx.loop, w_deadline);
	ev_set_cb(w_deadline, saved_cb);
	w_deadline->data = saved_data;

	fixture_teardown(&fx);

	T_EXPECT(had_session);
	T_EXPECT(shutting_down);
	T_EXPECT(deadline_armed);
	T_EXPECT(listeners_stopped);
	T_EXPECT(!deadline_reached);
	T_EXPECT(!safety_fired);
	T_EXPECT(drained);
}

/* A graceful shutdown leaves the API connections open, so a PUT /config can
 * still reach server_apply_config() after SIGTERM.  It must be refused: a
 * reload would rebind the listeners signal_cb just stopped and dial tunnels
 * that were never told to shut down, so shutdown could only end at the
 * force-exit deadline. */
T_DECLARE_CASE(test_server_apply_config_rejected_while_shutting_down)
{
	struct test_fixture fx;
	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture_setup failed at stage: %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup failed");
	}

	ev_invoke(fx.loop, &fx.srv_a->w_sigterm, EV_SIGNAL);
	const bool initially_stopped =
		fx.srv_a->local_listener.w_accept.fd == -1 &&
		fx.srv_a->mux_listener.w_accept.fd == -1;
	struct tunnel *const old_mux_tunnel = fx.srv_a->mux_tunnel;

	/* Name the ports signal_cb just released explicitly: the strings differ
	 * from the configured "127.0.0.1:0", so an applied reload would rebind
	 * both listeners. */
	char mux_listen[64];
	char listen[64];
	(void)snprintf(
		mux_listen, sizeof(mux_listen), "127.0.0.1:%d", fx.mux_port_a);
	(void)snprintf(listen, sizeof(listen), "127.0.0.1:%d", fx.tcp_port_a);
	struct config *const new_conf = make_config(
		mux_listen, fx.conf_a->mux_connect, listen, fx.conf_a->connect);
	if (new_conf == NULL) {
		FIXTURE_FATAL(&fx, "make_config failed");
	}
	struct config *const old_conf = fx.srv_a->conf;
	const bool applied = server_apply_config(fx.srv_a, new_conf);
	if (applied) {
		/* Track the new config so teardown frees it, not the freed old one. */
		fx.conf_a = fx.srv_a->conf;
	}

	const bool kept_conf = fx.srv_a->conf == old_conf;
	const bool still_stopped = fx.srv_a->local_listener.w_accept.fd == -1 &&
				   fx.srv_a->mux_listener.w_accept.fd == -1;
	const bool kept_tunnel = fx.srv_a->mux_tunnel == old_mux_tunnel;
	fixture_teardown(&fx);

	T_EXPECT(initially_stopped);
	T_EXPECT(!applied);
	T_EXPECT(kept_conf);
	T_EXPECT(still_stopped);
	T_EXPECT(kept_tunnel);
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

	/* Both peers are already using their single slot. A real outbound
	 * reconnect must reuse it, and the inbound resume must use its old slot. */
	struct server *const servers[] = { fx.srv_a, fx.srv_b };
	for (size_t i = 0; i < 2; i++) {
		struct server *const srv = servers[i];
		struct config *const conf = make_config(
			srv->conf->mux_listen, srv->conf->mux_connect,
			srv->conf->listen, srv->conf->connect);
		if (conf == NULL) {
			FIXTURE_FATAL(&fx, "capacity config failed");
		}
		conf->max_sessions = 1;
		const bool applied = server_apply_config(srv, conf);
		fx.conf_a = fx.srv_a->conf;
		fx.conf_b = fx.srv_b->conf;
		if (!applied) {
			FIXTURE_FATAL(&fx, "capacity reload failed");
		}
	}
	const uint_least64_t dialed_index = tunnel_index(fx.srv_b->mux_tunnel);
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

	const int established = wait_for_sessions_ready(&fx);
	const size_t inbound_usage = server_capacity_used(fx.srv_a);
	const size_t outbound_usage = server_capacity_used(fx.srv_b);
	const uint_least64_t reconnected_index =
		tunnel_index(fx.srv_b->mux_tunnel);
	fixture_teardown(&fx);

	T_EXPECT_EQ(waited, 0);
	T_EXPECT(after > before);
	T_EXPECT_EQ(established, 0);
	T_EXPECT_EQ(inbound_usage, (size_t)1);
	T_EXPECT_EQ(outbound_usage, (size_t)1);
	T_EXPECT_EQ(reconnected_index, dialed_index);
}

/* Start a server whose only session is a mux_connect dial-out to
 * 127.0.0.1:@p port; NULL on failure.  Release it with dialer_server_free(). */
static struct server *dialer_server_start(
	struct ev_loop *loop, const int port, const int idle_timeout)
{
	char mux_connect[64];
	(void)snprintf(mux_connect, sizeof(mux_connect), "127.0.0.1:%d", port);
	struct config *const conf = make_config(NULL, mux_connect, NULL, NULL);
	if (conf == NULL) {
		return NULL;
	}
	conf->mux.idle_timeout = idle_timeout;
	/* No handshake or close timeout: a session stalled on a silent peer
	 * stays stalled, rather than closing on its own mid-test. */
	conf->mux.connect_timeout = 0;
	struct server *const srv = server_new(loop, conf);
	if (srv == NULL) {
		conf_free(conf);
		return NULL;
	}
	if (!server_start(srv)) {
		server_stop(srv);
		server_free(srv);
		conf_free(conf);
		return NULL;
	}
	return srv;
}

static void dialer_server_free(struct server *restrict srv)
{
	if (srv == NULL) {
		return;
	}
	server_stop(srv);
	struct config *const conf = srv->conf;
	server_free(srv);
	conf_free(conf);
}

/* A loopback port that refuses connections: bound, then released again. */
static int refused_port(void)
{
	const int fd = bind_listen_localhost();
	if (fd < 0) {
		return -1;
	}
	const int port = listener_fd_port(fd);
	socket_close(fd);
	return port;
}

/* Predicate: srv's dial-out is resting in CLOSED after a failed redial.  The
 * counter moves where a redial is made, so a nonzero count with the session
 * CLOSED means that redial has failed too, putting the next attempt on the
 * 2 s backoff rung: long enough for a shutdown to find the session there. */
static int dialer_in_backoff_predicate(void *ptr)
{
	const struct server *const restrict srv = ptr;
	if (server_num_reconnects(srv) == 0 || srv->mux_tunnel == NULL) {
		return 0;
	}
	return tunnel_state(srv->mux_tunnel) == MUX_STATE_CLOSED ? 1 : 0;
}

/* Predicate: srv's dial-out has closed and is kept for an on-demand redial. */
static int dialer_closed_predicate(void *ptr)
{
	const struct server *const restrict srv = ptr;
	return srv->mux_tunnel != NULL && tunnel_state(srv->mux_tunnel) ==
						  MUX_STATE_CLOSED ?
		       1 :
		       0;
}

/* SIGTERM a server whose dial-out session is already CLOSED -- between
 * reconnect attempts, or resting as an on-demand tunnel -- and run its loop
 * until something breaks it.  Shutting such a session down is no transition,
 * so the tunnel has to report the close itself; handle_closed() then drops the
 * tunnel and ends the loop.  Returns NULL if that happened, else what went
 * wrong: had the loop run out to the force-exit deadline instead, the tunnel
 * would still be there. */
static const char *dialer_shutdown_failure(
	const int idle_timeout, wait_predicate_fn closed_predicate)
{
	struct test_fixture fx = { .loop = ev_loop_new(EVFLAG_AUTO) };
	if (fx.loop == NULL) {
		return "ev_loop_new failed";
	}
	const char *failure = NULL;
	const int port = refused_port();
	struct server *const srv =
		port < 0 ? NULL :
			   dialer_server_start(fx.loop, port, idle_timeout);
	if (srv == NULL) {
		failure = "dialer start failed";
		goto cleanup;
	}
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    closed_predicate, srv) != 0) {
		failure = "dial-out never came to rest in CLOSED";
		goto cleanup;
	}

	bool safety_fired = false;
	ev_timer w_safety;
	ev_timer_init(
		&w_safety, shutdown_safety_break_cb, SHUTDOWN_SAFETY_S, 0.0);
	w_safety.data = &safety_fired;
	ev_timer_start(fx.loop, &w_safety);
	/* Run signal_cb inside ev_run, as a real signal does. */
	ev_feed_event(fx.loop, &srv->w_sigterm, EV_SIGNAL);
	ev_run(fx.loop, 0);
	ev_timer_stop(fx.loop, &w_safety);

	if (safety_fired) {
		failure = "shutdown never ended";
	} else if (srv->mux_tunnel != NULL) {
		failure = "loop ended at the force-exit deadline, tunnel live";
	}

cleanup:
	dialer_server_free(srv);
	ev_loop_destroy(fx.loop);
	return failure;
}

T_DECLARE_CASE(test_server_graceful_shutdown_dialer_in_reconnect_backoff)
{
	const char *const failure =
		dialer_shutdown_failure(0, dialer_in_backoff_predicate);
	if (failure != NULL) {
		T_LOG(failure);
	}
	T_EXPECT(failure == NULL);
}

T_DECLARE_CASE(test_server_graceful_shutdown_idle_on_demand_dialer)
{
	const char *const failure =
		dialer_shutdown_failure(1, dialer_closed_predicate);
	if (failure != NULL) {
		T_LOG(failure);
	}
	T_EXPECT(failure == NULL);
}

/* signal_cb()'s force-exit deadline: with a session that cannot finish its
 * close -- a dial-out stalled in the handshake against a peer that accepts but
 * never answers, with no connect_timeout to end it -- SIGTERM must arm
 * w_maintenance as a one-shot at the deadline, and reaching it must break the
 * loop through maintenance_cb.  The arming is checked as signal_cb left it,
 * then the deadline is pulled in to fire at once rather than after 2 s. */
T_DECLARE_CASE(test_server_maintenance_shutdown_deadline_breaks_loop)
{
	struct test_fixture fx = { .loop = ev_loop_new(EVFLAG_AUTO) };
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	int conn_fd = -1;
	struct server *srv = NULL;
	bool armed_one_shot = false;
	bool armed_at_deadline = false;
	bool safety_fired = false;
	bool still_closing = false;

	const int peer_fd = bind_listen_localhost();
	const int port = peer_fd < 0 ? -1 : listener_fd_port(peer_fd);
	srv = port < 0 ? NULL : dialer_server_start(fx.loop, port, 0);
	if (srv == NULL) {
		T_LOG("dialer start failed");
		T_FAIL();
		goto cleanup;
	}
	/* The hello's arrival means the dialer is in the handshake, where a
	 * shutdown starts a close exchange this peer never finishes. */
	if ((wait_fd_events(
		     &fx, peer_fd, EV_READ,
		     (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) &
	     EV_READ) == 0) {
		T_LOG("dialer never connected");
		T_FAIL();
		goto cleanup;
	}
	conn_fd = accept(peer_fd, NULL, NULL);
	if (conn_fd < 0 || (wait_fd_events(
				    &fx, conn_fd, EV_READ,
				    (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) &
			    EV_READ) == 0) {
		T_LOG("dialer never sent its hello");
		T_FAIL();
		goto cleanup;
	}

	ev_invoke(fx.loop, &srv->w_sigterm, EV_SIGNAL);
	T_CHECK(srv->shutting_down);
	T_CHECK(ev_is_active(&srv->w_maintenance));
	armed_one_shot = srv->w_maintenance.repeat == 0.0;
	/* The 2 s deadline, not the 1 s maintenance period. */
	const ev_tstamp remaining =
		ev_timer_remaining(fx.loop, &srv->w_maintenance);
	armed_at_deadline = remaining > 1.5 && remaining <= 2.0;

	ev_timer_stop(fx.loop, &srv->w_maintenance);
	ev_timer_set(&srv->w_maintenance, 0.01, 0.0);
	ev_timer_start(fx.loop, &srv->w_maintenance);

	ev_timer w_safety;
	ev_timer_init(
		&w_safety, shutdown_safety_break_cb, SHUTDOWN_SAFETY_S, 0.0);
	w_safety.data = &safety_fired;
	ev_timer_start(fx.loop, &w_safety);
	ev_run(fx.loop, 0);
	ev_timer_stop(fx.loop, &w_safety);
	/* Still mid-close: the deadline, not a drain, ended the loop. */
	still_closing = srv->mux_tunnel != NULL &&
			tunnel_state(srv->mux_tunnel) == MUX_STATE_CLOSING;

cleanup:
	dialer_server_free(srv);
	if (conn_fd >= 0) {
		socket_close(conn_fd);
	}
	if (peer_fd >= 0) {
		socket_close(peer_fd);
	}
	ev_loop_destroy(fx.loop);

	T_EXPECT(armed_one_shot);
	T_EXPECT(armed_at_deadline);
	T_EXPECT(!safety_fired);
	T_EXPECT(still_closing);
}

/* A config for dialer_server_start()'s server, with mux_connect to
 * 127.0.0.1:@p port, or none when @p port is negative; NULL on OOM. */
static struct config *dialer_reload_config(const int port)
{
	char mux_connect[64];
	(void)snprintf(mux_connect, sizeof(mux_connect), "127.0.0.1:%d", port);
	struct config *const conf =
		make_config(NULL, port < 0 ? NULL : mux_connect, NULL, NULL);
	if (conf == NULL) {
		return NULL;
	}
	conf->mux.connect_timeout = 0;
	return conf;
}

struct mux_tunnel_changed_ctx {
	const struct server *srv;
	const struct tunnel *old;
};

/* Predicate: srv's mux_connect slot no longer holds the given tunnel. */
static int mux_tunnel_changed_predicate(void *ptr)
{
	const struct mux_tunnel_changed_ctx *const restrict ctx = ptr;
	return ctx->srv->mux_tunnel != ctx->old ? 1 : 0;
}

/* A reload that removes mux_connect retires the dial-out, which keeps its slot
 * while its session winds down -- here a dial stalled against a peer that
 * never answers.  A reload that re-adds mux_connect meanwhile finds the slot
 * held and dials nothing, and must not hand the address back to the retired
 * tunnel either: it stays retired.  So once it closes and frees the slot,
 * maintenance must dial a fresh tunnel for the re-added mux_connect, as it
 * does for an emptied identity slot.  Pre-fix nothing did, and the configured
 * mux_connect stayed down until yet another reload changed it. */
T_DECLARE_CASE(test_server_maintenance_redials_mux_connect_readded_while_retired)
{
	struct test_fixture fx = { .loop = ev_loop_new(EVFLAG_AUTO) };
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	int conn_fd = -1;
	struct server *srv = NULL;
	bool setup_ok = false;
	bool removed_kept = false;
	bool readded_kept = false;
	bool freed = false;
	bool fresh = false;
	bool redialed = false;

	const int peer_fd = bind_listen_localhost();
	const int port = peer_fd < 0 ? -1 : listener_fd_port(peer_fd);
	srv = port < 0 ? NULL : dialer_server_start(fx.loop, port, 0);
	if (srv == NULL) {
		T_LOG("dialer start failed");
		goto cleanup;
	}
	if ((wait_fd_events(
		     &fx, peer_fd, EV_READ,
		     (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) &
	     EV_READ) == 0) {
		T_LOG("dialer never connected");
		goto cleanup;
	}
	conn_fd = accept(peer_fd, NULL, NULL);
	if (conn_fd < 0) {
		T_LOG("accept failed");
		goto cleanup;
	}
	const struct tunnel *const old = srv->mux_tunnel;

	/* Its dial is still live, so the retired tunnel keeps the slot. */
	struct config *conf = dialer_reload_config(-1);
	if (conf == NULL || !server_apply_config(srv, conf)) {
		T_LOG("reload removing mux_connect failed");
		goto cleanup;
	}
	removed_kept = srv->mux_tunnel == old;
	conf = dialer_reload_config(port);
	if (conf == NULL || !server_apply_config(srv, conf)) {
		T_LOG("reload re-adding mux_connect failed");
		goto cleanup;
	}
	readded_kept = srv->mux_tunnel == old;

	/* The peer drops the stalled dial, and the retired tunnel closes. */
	socket_close(conn_fd);
	conn_fd = -1;
	struct mux_tunnel_changed_ctx wait_ctx = { .srv = srv, .old = old };
	freed = wait_until(
			&fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
			mux_tunnel_changed_predicate, &wait_ctx) == 0;
	ev_invoke(fx.loop, &srv->w_maintenance, EV_TIMER);
	fresh = srv->mux_tunnel != NULL;
	/* And the fresh tunnel dials the re-added address. */
	redialed = fresh && (wait_fd_events(
				     &fx, peer_fd, EV_READ,
				     (double)SETUP_WAIT_TIMEOUT_MS / 1000.0) &
			     EV_READ) != 0;
	setup_ok = true;

cleanup:
	dialer_server_free(srv);
	if (conn_fd >= 0) {
		socket_close(conn_fd);
	}
	if (peer_fd >= 0) {
		socket_close(peer_fd);
	}
	ev_loop_destroy(fx.loop);

	T_EXPECT(setup_ok);
	T_EXPECT(removed_kept);
	T_EXPECT(readded_kept);
	T_EXPECT(freed);
	T_EXPECT(fresh);
	T_EXPECT(redialed);
}

/* Invoke-pending hook that runs nothing: it only records, in the loop's
 * userdata, how many watchers came due. */
static void count_pending_cb(struct ev_loop *loop)
{
	*(unsigned int *)ev_userdata(loop) = ev_pending_count(loop);
}

/* server_free() must stop the maintenance tick whatever armed it: the timer
 * lives in the server, so leaving it in the loop hands the loop freed memory.
 * Arm it as a maintenance kick would (due in 10 ms rather than a full period),
 * free the server, and run one loop iteration that counts what comes due
 * without invoking it -- a stale timer would call maintenance_cb on the freed
 * server.  With nothing left active the iteration returns at once. */
T_DECLARE_CASE(test_server_free_stops_maintenance_timer)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	struct config *const conf =
		make_config("127.0.0.1:0", NULL, NULL, NULL);
	struct server *const srv = conf == NULL ? NULL : server_new(loop, conf);
	if (srv == NULL) {
		T_FAIL();
		conf_free(conf);
		ev_loop_destroy(loop);
		return;
	}
	srv->w_maintenance.repeat = 0.01;
	ev_timer_again(loop, &srv->w_maintenance);
	T_EXPECT(ev_is_active(&srv->w_maintenance));
	server_free(srv);
	conf_free(conf);

	unsigned int came_due = 0;
	ev_set_userdata(loop, &came_due);
	ev_set_invoke_pending_cb(loop, count_pending_cb);
	ev_run(loop, EVRUN_ONCE);
	ev_loop_destroy(loop);
	T_EXPECT_EQ(came_due, 0u);
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

/* A CLOSED event still queued when server_stop() runs is handled there, by its
 * dispatcher flush -- and must not re-arm the maintenance tick on the server
 * being torn down.  Queue one deterministically: shut down a dial-out resting
 * in reconnect backoff, whose tunnel then relays its CLOSED, and wait for the
 * relay's wakeup without running the loop. */
T_DECLARE_CASE(test_server_stop_leaves_maintenance_disarmed)
{
	struct test_fixture fx = { .loop = ev_loop_new(EVFLAG_AUTO) };
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	bool queued = false;
	bool armed_after_stop = true;
	const int port = refused_port();
	struct server *srv =
		port < 0 ? NULL : dialer_server_start(fx.loop, port, 0);
	if (srv == NULL) {
		T_LOG("dialer start failed");
		T_FAIL();
		goto cleanup;
	}
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    dialer_in_backoff_predicate, srv) != 0) {
		T_LOG("dial-out never came to rest in CLOSED");
		T_FAIL();
		goto cleanup;
	}
	/* Consume any wakeup already pending, so the next one is the CLOSED. */
	ev_run(fx.loop, EVRUN_NOWAIT);

	tunnel_shutdown(srv->mux_tunnel);
	const ev_tstamp deadline =
		mono_now() + (double)SETUP_WAIT_TIMEOUT_MS / 1000.0;
	while (!(queued = ev_async_pending(&srv->w_async)) &&
	       mono_now() < deadline) {
		const struct timespec ts = { .tv_nsec = 1000000 };
		(void)nanosleep(&ts, NULL);
	}

	server_stop(srv);
	armed_after_stop = ev_is_active(&srv->w_maintenance);
	struct config *const conf = srv->conf;
	server_free(srv);
	conf_free(conf);
	srv = NULL;

cleanup:
	dialer_server_free(srv);
	ev_loop_destroy(fx.loop);

	T_EXPECT(queued);
	T_EXPECT(!armed_after_stop);
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

/* Drive n fresh connections to port, one at a time; each must echo on its own
 * first attempt. Returns 0 when all did. */
static int
echo_each_connection(struct test_fixture *restrict fx, const int port, int n)
{
	for (; n > 0; n--) {
		const int cl = connect_local(fx, port);
		if (cl < 0) {
			return -1;
		}
		const int rc = send_and_expect_echo(
			fx, cl, "rr-echo", strlen("rr-echo"),
			(double)ECHO_WAIT_TIMEOUT_MS / 1000.0);
		(void)close(cl);
		if (rc != 0) {
			return -1;
		}
	}
	return 0;
}

/* Regression: identity_listener_pick() must skip a pooled tunnel that is not
 * established. srv_a's "peer-x" pool holds one real dialed-in tunnel plus a
 * never-started one (its session stuck short of ESTABLISHED, as a pooled
 * tunnel is through reconnect backoff or suspension). Plain round-robin handed
 * every other connection to the dead member, which closed it; every connection
 * must now be forwarded over the live one. */
T_DECLARE_CASE(test_server_identity_listener_skips_non_established_tunnel)
{
	struct ev_loop *loop = NULL;
	struct config *conf_a = NULL;
	struct server *srv_a = NULL;
	struct config *conf_c = NULL;
	struct server *srv_c = NULL;
	struct tunnel *dead = NULL;
	struct identity_listener *sl = NULL;
	struct mock_server backend = { .listen_fd = -1, .port = -1 };
	struct test_fixture fx = { 0 };
	int mux_port_a = -1;
	int id_port = -1;
	char mux_connect_a[64];
	char connect_backend[64];
	int echo_rc = -1;
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

	conf_c = make_config(NULL, mux_connect_a, NULL, connect_backend);
	if (conf_c == NULL) {
		T_FAIL();
		goto cleanup;
	}
	conf_c->identity.claim = strdup("peer-x");
	if (conf_c->identity.claim == NULL) {
		T_FAIL();
		goto cleanup;
	}
	srv_c = server_new(loop, conf_c);
	if (srv_c == NULL || !server_start(srv_c)) {
		T_FAIL();
		goto cleanup;
	}

	struct identity_pool_wait_ctx pool_ctx = {
		.srv_a = srv_a,
		.peer_identity = "peer-x",
		.expected = 1,
	};
	if (wait_until(
		    &fx, (double)SESSION_WAIT_TIMEOUT_MS / 1000.0,
		    identity_pool_wait_predicate, &pool_ctx) != 0) {
		T_FAIL();
		goto cleanup;
	}
	{
		size_t cursor = 0;
		void *elem = NULL;
		if (table_next(srv_a->identities, &cursor, NULL, &elem)) {
			sl = elem;
			id_port = get_listener_port(&sl->listener);
		}
	}
	/* Append the dead member in place: the pool's first growth leaves room
	 * for four, so no reallocation is needed. */
	if (sl == NULL || id_port <= 0 || sl->num_tunnels != 1 ||
	    sl->cap_tunnels < 2) {
		T_FAIL();
		goto cleanup;
	}
	dead = ol_make_tunnel(srv_a);
	if (dead == NULL) {
		T_FAIL();
		goto cleanup;
	}
	sl->tunnels[sl->num_tunnels++] = dead;
	setup_ok = true;

	/* Four picks walk the two-member pool twice over. */
	echo_rc = echo_each_connection(&fx, id_port, 4);

cleanup:
	if (dead != NULL) {
		for (size_t i = 0; sl != NULL && i < sl->num_tunnels; i++) {
			if (sl->tunnels[i] == dead) {
				sl->tunnels[i] = sl->tunnels[--sl->num_tunnels];
				sl->rr_next = 0;
				break;
			}
		}
		tunnel_close(dead);
	}
	if (srv_c != NULL) {
		server_stop(srv_c);
		server_free(srv_c);
	}
	if (srv_a != NULL) {
		server_stop(srv_a);
		server_free(srv_a);
	}
	if (conf_c != NULL) {
		conf_free(conf_c);
	}
	if (conf_a != NULL) {
		conf_free(conf_a);
	}
	mock_server_stop(&backend);
	if (loop != NULL) {
		ev_loop_destroy(loop);
	}

	if (setup_ok) {
		T_EXPECT_EQ(echo_rc, 0);
	}
}

/* Regression: tcp_serve()'s accepted-tunnel fallback (no mux_connect) must skip
 * an accepted tunnel that is not established -- every accepted connection is
 * registered before its handshake, so a peer holding half-open connections
 * used to take a share of the local connections, each closed. A never-started
 * tunnel stands in for such a half-open entry beside srv_b's real one. */
T_DECLARE_CASE(test_server_accepted_fallback_skips_non_established_tunnel)
{
	struct test_fixture fx;
	struct tunnel *dead = NULL;
	bool registered = false;
	int echo_rc = -1;

	if (fixture_setup(&fx, MOCK_ECHO) != 0) {
		T_LOGF("fixture setup failed at %s", g_setup_stage);
		FIXTURE_FATAL(&fx, "fixture_setup");
	}
	struct server *const srv = fx.srv_a;
	dead = ol_make_tunnel(srv);
	if (dead == NULL) {
		FIXTURE_FATAL(&fx, "ol_make_tunnel");
	}
	{
		void *elem = dead;
#if WITH_THREADS
		THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
		srv->accepted_tunnels = table_set(
			srv->accepted_tunnels, tunnel_session_id(dead), &elem);
#if WITH_THREADS
		THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
		registered = (elem == NULL);
	}
	if (registered && table_size(srv->accepted_tunnels) == 2) {
		/* Four picks walk the two-entry table twice over. */
		echo_rc = echo_each_connection(&fx, fx.tcp_port_a, 4);
	}

	if (registered) {
#if WITH_THREADS
		THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
		srv->accepted_tunnels = table_del(
			srv->accepted_tunnels, tunnel_session_id(dead), NULL);
		srv->accepted_rr_cursor = 0;
#if WITH_THREADS
		THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
	}
	tunnel_close(dead);
	fixture_teardown(&fx);

	T_EXPECT(registered);
	T_EXPECT_EQ(echo_rc, 0);
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
				  "Host: test\r\n"
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

static int capacity_outbound_retried(void *data)
{
	const struct server *const srv = data;
	return srv->mux_tunnel == NULL && srv->num_identity_tunnels == 1 &&
	       srv->identity_tunnels[0] != NULL;
}

T_DECLARE_CASE(test_server_capacity_defers_outbound_and_retries)
{
	struct test_fixture fx = {
		.loop = ev_loop_new(EVFLAG_AUTO),
		.backend_a = { .listen_fd = -1 },
		.backend_b = { .listen_fd = -1 },
		.udp_echo_a = { .fd = -1 },
		.udp_echo_b = { .fd = -1 },
	};
	if (fx.loop == NULL) {
		T_FATAL("ev_loop_new failed");
	}
	const int listener = bind_listen_localhost();
	if (listener < 0) {
		fixture_teardown(&fx);
		T_FATAL("bind_listen_localhost failed");
	}
	char address[64];
	(void)snprintf(
		address, sizeof(address), "127.0.0.1:%d",
		listener_fd_port(listener));
	fx.conf_a = make_config(NULL, address, NULL, NULL);
	if (fx.conf_a == NULL ||
	    !build_identity_dialer_conf(fx.conf_a, address)) {
		socket_close(listener);
		FIXTURE_FATAL(&fx, "dialer config failed");
	}
	fx.conf_a->max_sessions = 1;
	fx.conf_a->mux.connect_timeout = 0;
	fx.srv_a = server_new(fx.loop, fx.conf_a);
	if (fx.srv_a == NULL) {
		socket_close(listener);
		FIXTURE_FATAL(&fx, "server_new failed");
	}
	struct log_capture cap = { 0 };
	slog_setoutput(SLOG_OUTPUT_WRITER, log_capture_write, &cap);
	slog_setlevel(LOG_LEVEL_WARNING);
	const bool started = server_start(fx.srv_a);
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
	const bool deferred = started && fx.srv_a->mux_tunnel != NULL &&
			      fx.srv_a->num_identity_tunnels == 1 &&
			      fx.srv_a->identity_tunnels[0] == NULL;
	const size_t initial_usage = server_capacity_used(fx.srv_a);
	const bool warning =
		strstr(cap.buf, "session capacity exhausted;") != NULL;
	bool retried = false;
	if (deferred) {
		/* Retire the half-open mux session; its destruction frees capacity.
		 * The still configured identity tunnel is then created by maintenance. */
		struct config *const conf = make_config(NULL, NULL, NULL, NULL);
		if (conf != NULL && build_identity_dialer_conf(conf, address)) {
			conf->max_sessions = 1;
			conf->mux.connect_timeout = 0;
			if (server_apply_config(fx.srv_a, conf)) {
				fx.conf_a = conf;
				if ((wait_fd_events(
					     &fx, listener, EV_READ, 2.0) &
				     EV_READ) != 0) {
					const int fd =
						accept(listener, NULL, NULL);
					if (fd >= 0) {
						socket_close(fd);
					}
				}
				ev_invoke(
					fx.loop, &fx.srv_a->w_maintenance,
					EV_TIMER);
				retried = wait_until(
						  &fx, 2.0,
						  capacity_outbound_retried,
						  fx.srv_a) == 0;
			} else {
				T_FAIL();
			}
		} else {
			conf_free(conf);
			T_FAIL();
		}
	}
	const size_t retry_usage = server_capacity_used(fx.srv_a);
	socket_close(listener);
	server_stop(fx.srv_a);
	const size_t stopped_usage = server_capacity_used(fx.srv_a);
	fixture_teardown(&fx);
	T_EXPECT_EQ(initial_usage, (size_t)1);
	T_EXPECT_EQ(retry_usage, (size_t)1);
	T_EXPECT_EQ(stopped_usage, (size_t)0);
	T_EXPECT(started);
	T_EXPECT(deferred);
	T_EXPECT(warning);
	T_EXPECT(retried);
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

#if WITH_TLS
/* Builds a PSK server's TLS context from a config carrying mux.readahead's
 * schema default and returns what slog emitted at WARNING while doing so. */
static bool build_tls_ctx_capture_log(
	const bool socket_offload, struct log_capture *restrict cap)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	if (loop == NULL) {
		return false;
	}
	struct config *const conf =
		make_psk_config("127.0.0.1:0", NULL, RELOAD_PSK_HEX_A);
	if (conf == NULL) {
		ev_loop_destroy(loop);
		return false;
	}
	conf->mux.readahead = 131072;
	conf->tls_socket_offload = socket_offload;

	/* The suite runs at LOG_LEVEL_SILENCE with no sink; both are put back
	 * that way before returning. */
	slog_setoutput(SLOG_OUTPUT_WRITER, log_capture_write, cap);
	slog_setlevel(LOG_LEVEL_WARNING);
	struct server *const srv = server_new(loop, conf);
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);

	const bool ok = srv != NULL && srv->server_tlsctx != NULL;
	server_free(srv);
	conf_free(conf);
	ev_loop_destroy(loop);
	return ok;
}

/* Regression: mux.readahead reached the TLS context as a request for library
 * read-ahead even in memory-BIO mode, where it only sizes the session receive
 * ring.  Its schema default is non-zero, so the mbedTLS backend, which has no
 * read-ahead to enable, warned "mux.readahead ... ignored" on every context
 * built from an untouched config.  The request belongs to socket offload
 * alone, as tls.kernel_offload's does. */
T_DECLARE_CASE(test_server_tls_readahead_only_under_socket_offload)
{
	struct log_capture mem_cap = { 0 };
	T_CHECK(build_tls_ctx_capture_log(false, &mem_cap));
	T_EXPECT(!mem_cap.overflow);
	T_EXPECT(strstr(mem_cap.buf, "mux.readahead") == NULL);

	/* Under socket offload the request is real: the mbedTLS backend still
	 * says it cannot honor it, and OpenSSL enables it silently. */
	struct log_capture fd_cap = { 0 };
	T_CHECK(build_tls_ctx_capture_log(true, &fd_cap));
	T_EXPECT(!fd_cap.overflow);
#if WITH_MBEDTLS
	T_EXPECT(strstr(fd_cap.buf, "mux.readahead") != NULL);
#else
	T_EXPECT(strstr(fd_cap.buf, "mux.readahead") == NULL);
#endif
}
#endif /* WITH_TLS */

static const struct testing_suite suite[] = {
	T_CASE(test_server_apply_config_honors_cli_loglevel_override),
	T_CASE(test_server_offline_listeners_idle_timeout_scoped_to_mux_connect),
	T_CASE(test_server_offline_listeners_identity_branch),
	T_CASE(test_server_offline_passive_identity_with_idle_timeout),
	T_CASE(test_server_offline_ignores_routing_only_peer),
	T_CASE(test_server_wait_stats_ignores_historical_failures),
	T_CASE(test_server_reload_transfers_listener_between_roles),
	T_CASE(test_server_reload_swaps_roles_and_rolls_back),
	T_CASE(test_server_reload_rolls_back_new_listener_on_retained_peer),
	T_CASE(test_bidirectional_stream_and_forward),
	T_CASE(test_server_lossymux_udp_roundtrip),
	T_CASE(test_server_lossymux_udp_empty_roundtrip),
	T_CASE(test_server_lossymux_disabled_binds_no_udp),
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
	T_CASE(test_server_reload_rejects_listener_bind_failure),
	T_CASE(test_server_reload_moves_listener_within_port),
	T_CASE(test_server_reload_restores_listener_after_failed_bind),
	T_CASE(test_server_reload_restores_listener_after_later_failure),
	T_CASE(test_server_apply_config_rejected_while_shutting_down),
	T_CASE(test_server_reload_api_listener_keeps_dedicated_socket_opts),
	T_CASE(test_server_reload_removes_identity_peer_closes_tunnel),
	T_CASE(test_server_reload_retains_identity_peer),
	T_CASE(test_server_reload_keeps_unchanged_identity_listener),
	T_CASE(test_server_reload_restores_identity_listeners_on_bind_failure),
	T_CASE(test_server_reload_restores_traded_identity_listeners),
	T_CASE(test_server_reload_restores_identity_listener_bound_port),
	T_CASE(test_server_identity_pool_holds_concurrent_tunnels_same_peer),
	T_CASE(test_server_reload_drops_two_identity_peers_no_uaf),
	T_CASE(test_server_reload_keeps_established_identity_mux_connect_tunnel),
#if WITH_TLS
	T_CASE(test_server_reload_retires_psk_table_for_live_tunnels),
	T_CASE(test_server_psk_retirement_waits_for_live_tls_context),
#endif
	T_CASE(test_server_maintenance_redials_emptied_identity_slot),
#ifdef SERVER_TEST_WRAP_REALLOC
	T_CASE(test_server_maintenance_retries_identity_array_growth),
#endif
	T_CASE(test_server_maintenance_keeps_idle_on_demand_identity_tunnel),
	T_CASE(test_server_maintenance_timer_stops_when_idle),
	T_CASE(test_server_start_identity_peer_with_null_listen),
	T_CASE(test_server_capacity_simultaneous_inbound),
	T_CASE(test_server_capacity_defers_outbound_and_retries),
	T_CASE(test_server_capacity_reload_and_unmatched_resume),
	T_CASE(test_server_capacity_reduction_drains_removed_outbound),
	T_CASE(test_server_startup_limit_zero_start_throttles_first_connection),
	T_CASE(test_server_startup_limit_full_rejects_at_exact_limit),
	T_CASE(test_server_stream_establish_percentiles),
	T_CASE(test_server_stream_establish_percentiles_accepted_side),
	T_CASE(test_server_evlog_dedups_consecutive_reload_events),
	T_CASE(test_server_graceful_shutdown_via_signal),
	T_CASE(test_server_maintenance_suspend_drops_transports_and_reconnects),
	T_CASE(test_server_graceful_shutdown_dialer_in_reconnect_backoff),
	T_CASE(test_server_graceful_shutdown_idle_on_demand_dialer),
	T_CASE(test_server_maintenance_shutdown_deadline_breaks_loop),
	T_CASE(test_server_maintenance_redials_mux_connect_readded_while_retired),
	T_CASE(test_server_free_stops_maintenance_timer),
#if WITH_THREADS
	T_CASE(test_server_stop_leaves_maintenance_disarmed),
	T_CASE(test_server_new_arms_async_before_start),
	T_CASE(test_server_free_releases_async_without_stop),
#endif
	T_CASE(test_server_identity_pool_single_membership_across_reclaim),
	T_CASE(test_server_resume_reconciles_changed_identity),
	T_CASE(test_server_identity_listener_forwards_over_pool),
	T_CASE(test_server_identity_listener_empty_pool_closes_conn),
	T_CASE(test_server_identity_listener_skips_non_established_tunnel),
	T_CASE(test_server_accepted_fallback_skips_non_established_tunnel),
	T_CASE(test_server_stop_frees_inflight_api_connection),
	T_CASE(test_server_escapes_peer_identity_in_output),
#if WITH_TLS
	T_CASE(test_server_tls_readahead_only_under_socket_offload),
#endif
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
