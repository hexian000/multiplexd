/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* mux_test.c - integration tests for the mux protocol stack (no mocks).
 * Uses the public mux API; local proto_hello_build crafts raw hello bytes
 * for the raw-peer driver. */

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/proto_schema.gen.h"
#include "mux/recv.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"
#if WITH_TLS
#include "tlsutil.h"
#endif

#include "algo/hashtable.h"
#include "algo/wndfilter.h"
#include "codec/base64.h"
#include "math/rand.h"
#include "os/clock.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

/* Constants */

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
	/* Two window units (2 × MUX_WINDOW_UNIT = 32768) match the immediate-ACK
	 * threshold so each drain triggers an immediate ACK and avoids the
	 * 1-tick (40 ms) delayed-ACK timer on the fast path. */
	CHUNK_SIZE = 32768,
};

/* Forward declarations */

struct mux_test_fixture;
struct test_stream;
struct pending_accept;

static void stream_io_cb(struct ev_loop *loop, mux_stream_io *w, int revents);
static bool raw_drain_available(int fd);

/* Fixture types */

enum accept_mode {
	ACCEPT_ECHO = 0, /* echo all data, mirror FIN */
	ACCEPT_CLOSE_IMMEDIATE, /* close immediately (triggers RST) */
	/* send payload from fx->accept_send_data and FIN, do not echo */
	ACCEPT_SEND_PAYLOAD,
	/* drain and discard all received data, counting recv_total; used by
	 * the throughput benchmark to measure one-directional stream rate. */
	ACCEPT_DRAIN,
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
	bool send_shutdown_on_drain;
	/* Throughput bench: cyclic sender.  Repeatedly transmit the fixed
	 * send_data[0, send_len) buffer until send_remaining bytes have been
	 * queued, then (with send_shutdown_on_drain) half-close. */
	bool send_cyclic;
	uint_fast64_t send_remaining;

	/* Throughput bench: receiver discards every byte into recv_buf (without
	 * advancing recv_len) and only accumulates the running total. */
	bool is_drain;
	uint_fast64_t recv_total;

	/* echo: reflect all received bytes back to the sender */
	bool is_echo;
	/* Echo backpressure: bytes of recv_buf already echoed back.  The
	 * un-echoed region [echo_off, recv_len) is re-driven from both EV_READ
	 * and EV_WRITE so a full send window does not drop data. */
	size_t echo_off;
	bool echo_fin_seen;
	bool echo_shutdown_done;
	/* close_on_readable: close the stream as soon as EV_READ fires
	 * (without consuming data), triggering RST due to unread data */
	bool close_on_readable;

	bool got_eof;
	bool got_error;
	bool closed;
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

/* wait_until helpers */

typedef int (*wait_predicate_fn)(void *ctx);

struct condition_waiter {
	bool timed_out;
	ev_timer w_timer;
};

static void
condition_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)revents;
	struct condition_waiter *const restrict waiter = w->data;
	waiter->timed_out = true;
}

static int loop_wait_until(
	struct ev_loop *loop, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	struct condition_waiter waiter = {
		.timed_out = false,
	};
	ev_timer_init(
		&waiter.w_timer, condition_waiter_timer_cb, timeout_sec, 0.0);
	waiter.w_timer.data = &waiter;
	ev_timer_start(loop, &waiter.w_timer);

	/* The predicate inspects state mutated by mux callbacks dispatched inside
	 * ev_run().  Route the call through a volatile pointer so the optimizer
	 * cannot cache the polled flag across ev_run(). */
	wait_predicate_fn volatile vpredicate = predicate;
	while (!waiter.timed_out) {
		const int status = vpredicate(ctx);
		if (status != 0) {
			ev_timer_stop(loop, &waiter.w_timer);
			return status > 0 ? 0 : -1;
		}
		ev_run(loop, EVRUN_ONCE);
	}

	ev_timer_stop(loop, &waiter.w_timer);
	errno = ETIMEDOUT;
	return -1;
}

static int wait_until(
	struct mux_test_fixture *fx, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	return loop_wait_until(fx->loop, timeout_sec, predicate, ctx);
}

/* test_stream helpers */

static struct test_stream *test_stream_new(
	struct mux_test_fixture *restrict fx, struct mux_stream *restrict s)
{
	struct test_stream *const ts = malloc(sizeof(struct test_stream));
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
		unsigned char *const buf = malloc(PAYLOAD_LARGE + CHUNK_SIZE);
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
	if (ts->send_cyclic) {
		/* Push as much as the send window allows, recycling the fixed
		 * send_data buffer; content is irrelevant for throughput. */
		while (ts->send_remaining > 0) {
			size_t chunk =
				ts->send_remaining < (uint_fast64_t)CHUNK_SIZE ?
					(size_t)ts->send_remaining :
					(size_t)CHUNK_SIZE;
			const int ret =
				mux_stream_send(ts->s, ts->send_data, &chunk);
			if (ret < 0) {
				return false; /* pool exhausted; resume on EV_WRITE */
			}
			if (chunk == 0) {
				return false; /* window full; resume on EV_WRITE */
			}
			ts->send_remaining -= chunk;
		}
		return true;
	}
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

/* Echo backpressure pump: flush un-echoed recv_buf[echo_off, recv_len).
 * Stops on full send window; after peer FIN, mirrors the shutdown once
 * the backlog drains. */
static void test_stream_pump_echo(struct test_stream *restrict ts)
{
	while (ts->echo_off < ts->recv_len) {
		size_t chunk = ts->recv_len - ts->echo_off;
		const int r = mux_stream_send(
			ts->s, ts->recv_buf + ts->echo_off, &chunk);
		if (r < 0 || chunk == 0) {
			break;
		}
		ts->echo_off += chunk;
	}
	if (ts->echo_fin_seen && ts->echo_off >= ts->recv_len &&
	    !ts->echo_shutdown_done) {
		ts->echo_shutdown_done = true;
		mux_stream_shutdown(ts->s);
	}
}

/* Echo I/O callback (used by both server-accepted and client-opened streams) */

static void
stream_io_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	struct test_stream *const restrict ts = (struct test_stream *)w;

	if (revents & EV_ERROR) {
		ts->got_error = true;
		if (!ts->closed) {
			ts->closed = true;
			mux_stream_close(ts->s);
		}
		return;
	}

	if (revents & EV_READ) {
		if (ts->is_drain) {
			/* Throughput sink: read and discard, counting bytes. */
			for (;;) {
				size_t cap = ts->recv_cap;
				const int ret = mux_stream_recv(
					ts->s, ts->recv_buf, &cap);
				if (ret < 0) {
					if (errno == EAGAIN) {
						break;
					}
					ts->got_error = true;
					if (!ts->closed) {
						ts->closed = true;
						mux_stream_close(ts->s);
					}
					return;
				}
				if (cap == 0) {
					/* Peer FIN: the count is final.  Mirror the
					 * shutdown to release the half-closed stream. */
					ts->got_eof = true;
					mux_stream_shutdown(ts->s);
					return;
				}
				ts->recv_total += cap;
			}
			return;
		}
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
					/* Echo server: drain the backlog, then
					 * mirror the FIN once it is empty. */
					ts->echo_fin_seen = true;
					test_stream_pump_echo(ts);
				}
				return;
			}
			ts->recv_len += cap;
		}

		/* Echo server: reflect everything received so far, honouring send
		 * backpressure (EV_WRITE resumes a window-blocked backlog). */
		if (ts->is_echo) {
			test_stream_pump_echo(ts);
		}
	}

	if (revents & EV_WRITE) {
		if (ts->is_echo) {
			test_stream_pump_echo(ts);
		} else if (ts->send_data != NULL) {
			const bool done = test_stream_flush_send(ts);
			if (done && ts->send_shutdown_on_drain) {
				mux_stream_shutdown(ts->s);
			}
		}
	}
}

/* Session callbacks */

static bool
on_accept_cb(void *data, const struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	struct mux_test_fixture *const restrict fx = data;
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

	if (fx->accept_mode == ACCEPT_DRAIN) {
		/* Throughput sink: drain and discard, no echo. */
		ts->is_drain = true;
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
		(void)close(fd);
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
		(void)close(fd);
		return -1;
	}
	return fd;
}

static void on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	(void)edata;
	struct mux_test_fixture *const restrict fx = data;
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
		 * closed event after the resume handoff resets them; they match
		 * neither fx->srv nor fx->cli.  mux_close is always required. */
		mux_close(ss);
		break;
	default:
		break;
	}
}

/* TCP loopback listen helper: bind, listen, return fd and port */

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
		(void)close(fd);
		return -1;
	}
	if (listen(fd, 4) != 0) {
		(void)close(fd);
		return -1;
	}
	socklen_t len = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
		(void)close(fd);
		return -1;
	}
	*port_out = (int)ntohs(sa.sin_port);
	return fd;
}

/* Forward declaration needed by pending_accept_cb below */
static const struct mux_callbacks g_srv_callbacks;

static struct mux_frame *test_frame_alloc(void *data, const size_t size)
{
	(void)data;
	return malloc(size);
}

static void test_frame_free(void *data, struct mux_frame *frame)
{
	(void)data;
	free(frame);
}

static void proto_session_id_new(unsigned char *const id)
{
	write_uint64(id, rand64());
	write_uint64(id + sizeof(uint64_t), rand64());
}

/* Build a hello frame into buf, mirroring the on-wire format.  Local copy
 * for the raw-peer driver (no handshake.c link needed).
 * Returns total frame length, or -1 on failure. */
static int mux_test_proto_hello_build(
	unsigned char *const buf, const size_t buf_size,
	const struct proto_hello *const msg)
{
	enum { SESSION_ID_B64 = 24 };
	static const char proto_type[] =
		"application/x-multiplexd-proto; version=1";
	char id_b64[SESSION_ID_B64 + 1];
	if (msg->has_session_id) {
		size_t len = SESSION_ID_B64;
		(void)base64_encode(
			(unsigned char *)id_b64, &len, msg->session_id,
			MUX_SESSION_ID_LEN);
		id_b64[SESSION_ID_B64] = '\0';
	}
	/* Strings in raw are borrowed; do not call json_free_proto(). */
	const struct json_proto raw = {
		.type = { .str = (char *)proto_type,
			  .len = sizeof(proto_type) - 1 },
		.msgid = msg->msgid,
		.session_id = {
			.str = msg->has_session_id ? id_b64 : NULL,
			.len = msg->has_session_id ? SESSION_ID_B64 : 0,
		},
		.resume_seq = msg->has_resume_seq ? (unsigned)msg->resume_seq : 0,
		.extensions = {
			.reject_inbound = msg->reject_inbound,
			.identity = {
				.str = msg->has_identity
					? (char *)msg->identity
					: NULL,
				.len = msg->has_identity
					? strlen(msg->identity)
					: 0,
			},
		},
	};
	const int json_sz = json_marshal_proto(NULL, 0, &raw, NULL);
	if (json_sz <= 0 || (size_t)json_sz > MUX_MAX_PAYLOAD_SIZE) {
		return -1;
	}
	const size_t total = MUX_FRAME_HEADER_SIZE + (size_t)json_sz;
	if (total <= buf_size) {
		char json_buf[(size_t)json_sz + 1];
		(void)json_marshal_proto(
			json_buf, (size_t)json_sz + 1, &raw, NULL);
		const struct mux_header hdr = {
			.version = 0,
			.flags = 0,
			.length = (uint_least16_t)json_sz,
			.stream_id = 0,
			.extra = 0,
		};
		mux_write_header(buf, &hdr);
		memcpy(buf + MUX_FRAME_HEADER_SIZE, json_buf, (size_t)json_sz);
	}
	return (int)total;
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
	(void)revents;
	struct pending_accept *const restrict pa = w->data;

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

	struct mux_test_fixture *const restrict fx = pa->fx;
	const struct mux_config srv_conf = {
		.timeout = 30,
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
			(void)close(srv_fd);
			return;
		}
		mux_start(fx->srv);
	} else {
		/* Subsequent accept (resume path): create a transient session.
		 * on_resume_cb detaches its transport onto fx->srv via
		 * mux_transport_detach + mux_resume_attach, then resets it. */
		struct mux_session *const transient = mux_new(loop, &srv_opts);
		if (transient == NULL) {
			(void)close(srv_fd);
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

/* Fixture setup / teardown */

static bool on_resume_cb(
	void *data, struct mux_session *new_ss, const unsigned char *session_id,
	const uint_least32_t resume_seq)
{
	const struct mux_test_fixture *restrict fx = data;
	if (fx->srv != NULL && memcmp(session_id, mux_session_id(fx->srv),
				      MUX_SESSION_ID_LEN) == 0) {
		/* Single test loop: move the transient transport onto fx->srv and
		 * resume inline (the tunnel layer would post this to srv's loop). */
		struct mux_transport transport;
		mux_transport_detach(new_ss, &transport);
		mux_resume_attach(fx->srv, &transport, resume_seq);
		return true;
	}
	return false;
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

	/* Create a TCP listen socket on loopback.  The client connects via
	 * session_connect (real TCP, EV_WRITE on completion), exercising
	 * the normal handshake path without socketpair tricks. */
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
		(void)close(listen_fd);
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
		(void)close(listen_fd);
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
		struct pending_accept *const restrict pa = fx->pending_accept;
		if (fx->loop != NULL) {
			ev_io_stop(fx->loop, &pa->w_accept);
		}
		(void)close(pa->listen_fd);
		free(pa);
		fx->pending_accept = NULL;
	}

	if (fx->break_transport_sp >= 0) {
		(void)close(fx->break_transport_sp);
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

/* Predicates */

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

/* Throughput bench: tracks the byte count the server-side drain stream must
 * reach.  See pred_drain_total near the benchmark itself. */
struct drain_done_ctx {
	const struct mux_test_fixture *fx;
	uint_fast64_t expected_total;
};

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

/* Helper: fill buffer with deterministic pseudo-random content */

static void fill_payload(
	unsigned char *restrict buf, const size_t len, const uint_fast8_t seed)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (unsigned char)((seed + i * 31u + i * i * 7u) & 0xFFu);
	}
}

/* Test cases */

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

/* test_idle_scheduler_stops_while_sendbuf_blocked: INIT stream on a full
 * sendbuf must stay queued without marking lp_pending; session_on_send
 * re-arms the drain once the sendbuf clears. */

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

	frame = mux_frame_get(&fx.cli->pool, fx.cli->max_payload);
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
	/* The INIT stream is parked on the low-priority queue while the sendbuf
	 * is occupied; the lifecycle drain is NOT scheduled (an active idle watcher
	 * would keep libev from sleeping and spin until the transport drains). */
	T_EXPECT(!fx.cli->sched.lp_pending);
	T_EXPECT(fx.cli->sched.lp_head != NULL);
	T_EXPECT(fx.cli->wire.tx_pending);

	/* Stop the socket watcher so EVRUN_NOWAIT cannot flush the sendbuf:
	 * opening the stream re-armed EV_WRITE via session_notify, so stop it here
	 * to confirm the lifecycle drain stays parked while the sendbuf is busy. */
	ev_io_stop(fx.loop, &fx.cli->w_socket);

	ev_run(fx.loop, EVRUN_NOWAIT);

	T_EXPECT(!fx.cli->sched.lp_pending);
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
		session_notify(fx.cli);
	}
	if (fx.srv != NULL) {
		session_notify(fx.srv);
	}
	fixture_teardown(&fx);
}

/* test_retransmit_excludes_lifecycle_drain: while replay is in flight
 * (retransmit_off != SIZE_MAX), session_on_send must NOT drain the
 * lifecycle queue; the drain stays pending until replay completes. */
T_DECLARE_CASE(test_retransmit_excludes_lifecycle_drain)
{
	struct mux_test_fixture fx;
	struct mux_frame *u = NULL;
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

	/* Drive session_on_send by hand; stop the watcher so the loop cannot
	 * drain in the background. */
	ev_io_stop(fx.loop, &fx.cli->w_socket);

	/* A fresh INIT stream parked on the lifecycle (lp) queue, drain armed. */
	struct mux_stream *b = mux_open_stream(fx.cli);
	if (b == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	T_EXPECT_EQ(b->state, STREAM_INIT);
	T_EXPECT(fx.cli->sched.lp_head == b);
	fx.cli->sched.lp_pending = true;

	/* One unacked entry with the replay cursor at its head makes resume
	 * replay "in flight" for this send pass. */
	u = mux_frame_get(&fx.cli->pool, fx.cli->max_payload);
	if (u == NULL) {
		T_FATAL("mux_frame_get failed");
		goto cleanup;
	}
	u->pos = 0;
	u->len = MUX_FRAME_HEADER_SIZE;
	const struct mux_header uh = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 0,
		.stream_id = 2, /* any non-control id */
		.extra = 0,
	};
	mux_write_header(u->data, &uh);
	unacked_track_sent(fx.cli, u); /* takes ownership; ring count -> 1 */
	u = NULL;
	if (fx.cli->unacked.ring == NULL || fx.cli->unacked.ring->count == 0) {
		T_FATAL("unacked ring not populated");
		goto cleanup;
	}
	fx.cli->unacked.retransmit_off = 0;

	session_on_send(fx.cli);

	/* Exclusivity: the lifecycle SYN must not have been staged ahead of the
	 * replay; the drain stays pending for after replay completes. */
	T_EXPECT_EQ(b->state, STREAM_INIT);
	T_EXPECT(fx.cli->sched.lp_pending);

cleanup:
	if (u != NULL) {
		mux_frame_put(&fx.cli->pool, u);
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

/* server actively opens a stream and sends a
 * payload first; the client-side (echo) sends it back.  Verifies that the
 * server-side initiator correctly receives the echoed data. */

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

/* client opens a stream but sends no data; the server sends a payload
 * and immediately half-closes.  Verifies the client receives data and
 * peer EOF. */

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

/* server actively opens a stream, sends a payload, then half-closes.
 * The client-side echo mirrors data and FIN back; verifies the server
 * observes clean EOF without errors. */

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

/* test_simultaneous_close: both ends half-close independently, exercising
 * FIN_WAIT->CLOSING (active opener) and CLOSE_WAIT->CLOSING (passive opener)
 * with distinct payloads. */

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

/* server opens a stream and sends a payload; the client closes without
 * reading, triggering RST (non-empty recv buffer).  Verifies the server
 * observes ECONNRESET via got_error. */

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

	/* Half-close before SYN|ACK: must not emit FIN ahead of the SYN. */
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

/* Raw interoperability test infrastructure: a minimal wire-level fixture where
 * a mux server session holds one end of a socketpair and raw_fd is driven
 * manually to inject or inspect frames. */

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
	(void)edata;
	struct raw_fixture *const fx = data;
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
		(void)close(fds[0]);
		(void)close(fx->raw_fd);
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
		(void)close(fx->raw_fd);
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

static int raw_wait_until(
	struct raw_fixture *fx, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	return loop_wait_until(fx->loop, timeout_sec, predicate, ctx);
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

/* Perform the hello exchange from the raw (client) side:
 * send a ClientHello, drive the loop until SESSION_ESTABLISHED,
 * then drain the ServerHello reply from raw_fd. */
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
	const int n = mux_test_proto_hello_build(buf, sizeof(buf), &hello);
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

/* Interoperability test cases */

/* I-1: non-SYN frame for an unknown stream.  A zero-length ACK is an ignorable
 * terminal control frame, so the server keeps the session open and sends no
 * stream-level response (session-level ACK on stream 0 may still occur). */
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

/* Stream-aware raw fixture: extends raw_fixture with an on_accept callback
 * that tracks the accepted stream, enabling tests requiring an established
 * or half-closed stream. */

/* Accepts RAW stream events without acting on them. */
static void
raw_stream_io_noop_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

struct raw_stream_fixture {
	struct raw_fixture base;
	struct mux_stream *accepted_stream;
	mux_stream_io w_stream;
};

static bool raw_stream_on_accept_cb(
	void *data, const struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	struct raw_stream_fixture *const sfx = data;
	sfx->accepted_stream = s;
	mux_stream_io_init(&sfx->w_stream, raw_stream_io_noop_cb, s, EV_READ);
	mux_stream_io_start(sfx->base.loop, &sfx->w_stream);
	return true;
}

static void raw_stream_on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	(void)edata;
	struct raw_stream_fixture *const sfx = data;
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

/* Drain all frames immediately available without blocking.  Used after
 * raw_drain_frame to consume piggybacked session ACKs so the socket
 * buffer is clean before the next raw_wait_until call. */
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

/* I-2: undefined flags in CLOSE_WAIT.  After the client FIN the server stream
 * is CLOSE_WAIT, where only ACK is valid (spec §4.2.1); PUSH after FIN is
 * undefined and MAY draw RST with PROTOCOL_ERROR. */
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

/* I-5: duplicate SYN for an existing stream.  After the SYN|ACK handshake the
 * client re-sends SYN for the same ID; the server MUST reply RST (spec §8). */
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

/* I-3: ACK|FIN Extra carries a credit grant, not a status code.  A large
 * payload then half-close makes the echo server emit ACK|FIN with a credit
 * increment in Extra; treating it as a status code would stall the transfer. */
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

/* I-4: stream ID parity violation.  A client SYN with an even ID (2) breaks
 * the odd-ID rule; the server MUST reply RST with PROTOCOL_ERROR. */
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

/* I-6: fast-open credit boundary.  The client queues exactly
 * MUX_DEFAULT_SEND_WINDOW (16384) bytes before the loop runs, yielding one
 * SYN|PUSH of 16384 octets the receiver MUST accept without RST. */
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

/* I-7: out-of-order FIN then data.  After the client FIN the server stream is
 * CLOSE_WAIT; a later PUSH there is undefined and draws RST. */
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

/* I-8: out-of-order RST.  After the client RSTs an established stream the
 * server closes it; a later non-RST frame on that retired ID draws one RST
 * while the session stays open. */
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
	/* Drain any session-level ACKs emitted during the wait; verifies that
	 * the server does not proactively send a stream-level reply to the
	 * RST. */
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

/* I-9: Reserved flag bit set — receiver MUST close the connection.
 * The raw side sends a frame with reserved bit 0x20 after handshake;
 * the server MUST close (not just RST). */
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

/* I-10: Hello version parameter mismatch — server MUST close the connection.
 * The raw side sends a ClientHello with version=2; the server MUST close
 * upon detecting the mismatch. */
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

/* I-11: PING/PONG echo.  The raw side sends a stream-0 PING with an
 * opaque payload; the server MUST reply with a PONG whose payload is
 * byte-for-byte identical. */
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

/* I-12: unknown keepalive subtype.  A reserved stream-0 subtype is silently
 * discarded; sent before a valid PING, the first response is that PING's PONG. */
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

/* I-13: invalid opening SYN flags.  SYN|ACK as the first frame for an unknown
 * stream is a violation (only SYN/SYN|PUSH open); the server MUST close the
 * connection and MUST NOT resume. */
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

/* I-14: reserved stream-0 frame type (spec §4.1).  A stream-0 frame
 * with non-zero non-ACK flags MUST be silently discarded; a subsequent
 * PING confirms the session survived and drew no reply. */
T_DECLARE_CASE(test_interop_i14_reserved_stream0_frame)
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

	/* PUSH on stream 0: non-zero, non-ACK flags -> reserved frame type. */
	static const unsigned char reserved_payload[] = {
		0xDE,
		0xAD,
		0xBE,
		0xEF,
	};
	const struct mux_header reserved_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = (uint_least16_t)sizeof(reserved_payload),
		.stream_id = STREAMID_CTRL,
		.extra = 0,
	};
	T_EXPECT(raw_send_frame_payload(
		fx.raw_fd, &reserved_hdr, reserved_payload));
	T_EXPECT(raw_wait_until(&fx, 0.1, raw_pred_closed, &fx) != 0);

	int raw_fd = fx.raw_fd;
	T_EXPECT(raw_pred_data_available(&raw_fd) == 0);

	/* The session must still answer a valid PING with a matching PONG. */
	static const unsigned char ping_payload[] = {
		0xA5, 0xB6, 0xC7, 0xD8, 0xE9,
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

/* when idle_timeout is configured on the
 * client, an unexpected transport loss must emit MUX_EVENT_CLOSED instead of
 * scheduling a reconnect. */

T_DECLARE_CASE(test_no_reconnect_with_idle_timeout)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	/* Set idle_timeout (any positive value) so session_on_close takes the
	 * no-reconnect branch; reduce w_idle_timeout.repeat so ev_timer_again
	 * fires quickly without the integer-second config granularity. */
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

/* fx_break_transport: RST the TCP connection so both sessions suspend.
 * SO_LINGER{1,0} sends RST to the client; the server stays ESTABLISHED
 * until reconnect, when mux_resume_attach suspends it. */

static void fx_break_transport(struct mux_test_fixture *restrict fx)
{
	const int srv_fd = mux_fd(fx->srv);

	/* Sentinel socketpair: keeps srv_fd occupied so the next accept()
	 * does not reuse it and cause libev to dispatch new-connection
	 * events to fx->srv's socket watcher. */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
		return;
	}

	const struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	(void)setsockopt(srv_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

	/* dup2 atomically sends RST (SO_LINGER) and puts sp[0] in the slot.
	 * mux_resume_attach later calls session_suspend which closes sp[0]
	 * cleanly — no EBADF. */
	(void)dup2(sp[0], srv_fd);
	(void)close(sp[0]);

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
		if (fx->cli->unacked.frames > 0 &&
		    fx->srv->unacked.frames > 0) {
			break;
		}
	}

	session_notify(fx->cli);
	session_notify(fx->srv);
}

/* transport break with no active streams.
 * The session must suspend, reconnect, and fire MUX_EVENT_RESUMED on both
 * sides without any data loss. */

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

/* transport break with a stream in flight.
 * Frames unacknowledged at suspension must be retransmitted after resume
 * and the echo must complete with exactly the original payload. */

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
	T_EXPECT(fx.cli->unacked.frames > 0);
	T_EXPECT(fx.srv->unacked.frames > 0);
	T_LOGF("pre-suspend unacked: cli=%zu srv=%zu", fx.cli->unacked.frames,
	       fx.srv->unacked.frames);

	/* Freeze both endpoints directly into SUSPENDED with non-empty unacked
	 * lists. This avoids timing windows while still forcing resume to replay
	 * the preserved frames over a fresh transport. */
	session_suspend(fx.cli);
	session_suspend(fx.srv);
	T_EXPECT(fx.cli->unacked.retransmit_off != SIZE_MAX);
	T_EXPECT(fx.srv->unacked.retransmit_off != SIZE_MAX);
	T_LOGF("retransmit armed: cli=%d srv=%d",
	       fx.cli->unacked.retransmit_off != SIZE_MAX,
	       fx.srv->unacked.retransmit_off != SIZE_MAX);

	/* Wait for both sessions to resume. */
	const int resume_ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	if (resume_ret != 0) {
		T_LOGF("resume wait failed:"
		       " cli(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
		       " ack_seq=%" PRIuLEAST32 " tx_pending=%d retrans=%d)"
		       " srv(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
		       " ack_seq=%" PRIuLEAST32 " tx_pending=%d retrans=%d)",
		       fx.cli->state, fx.cli->unacked.frames,
		       fx.cli->unacked.recv_seq, fx.cli->unacked.ack_seq,
		       fx.cli->wire.tx_pending,
		       fx.cli->unacked.retransmit_off != SIZE_MAX,
		       fx.srv->state, fx.srv->unacked.frames,
		       fx.srv->unacked.recv_seq, fx.srv->unacked.ack_seq,
		       fx.srv->wire.tx_pending,
		       fx.srv->unacked.retransmit_off != SIZE_MAX);
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
			       fx.cli->state, fx.cli->unacked.frames,
			       fx.cli->unacked.recv_seq,
			       fx.cli->unacked.ack_seq, fx.cli->wire.tx_pending,
			       fx.cli->unacked.retransmit_off != SIZE_MAX,
			       cli_ts->recv_len, cli_sent, cli_ts->got_error,
			       cli_ts->got_eof, fx.srv->state,
			       fx.srv->unacked.frames, fx.srv->unacked.recv_seq,
			       fx.srv->unacked.ack_seq, fx.srv->wire.tx_pending,
			       fx.srv->unacked.retransmit_off != SIZE_MAX,
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
			       fx.cli->state, fx.cli->unacked.frames,
			       fx.cli->unacked.recv_seq,
			       fx.cli->unacked.ack_seq, fx.cli->wire.tx_pending,
			       fx.cli->unacked.retransmit_off != SIZE_MAX,
			       cli_ts->recv_len, cli_sent, cli_ts->got_error,
			       cli_ts->got_eof, fx.srv->state,
			       fx.srv->unacked.frames, fx.srv->unacked.recv_seq,
			       fx.srv->unacked.ack_seq, fx.srv->wire.tx_pending,
			       fx.srv->unacked.retransmit_off != SIZE_MAX,
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

/* a stream mid-transfer across a real RST break must deliver its full
 * payload without error or premature EOF; the suspend→reconnect→resume
 * path is transparent to the stream. */

T_DECLARE_CASE(test_resume_stream_transparent)
{
	struct mux_test_fixture fx;
	unsigned char *payload = NULL;
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

	payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x5A);

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
	ts->send_len = PAYLOAD_LARGE;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Let the transfer get underway, then sever the transport mid-flight so
	 * the resume happens while data is still in transit on this stream. */
	struct echo_ctx partial_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE / 4,
	};
	if (wait_until(
		    &fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
		    &partial_ctx) != 0) {
		T_FATAL("echo transfer did not get underway");
		goto cleanup;
	}
	T_EXPECT(ts->recv_len < (size_t)PAYLOAD_LARGE); /* still in flight */
	T_EXPECT(!ts->got_eof);
	T_EXPECT(!ts->got_error);

	fx_break_transport(&fx);

	/* The remaining payload must echo back without the stream ever observing
	 * an error (pred_echo_received returns -1 on got_error): the session
	 * resume is transparent to the stream. */
	struct echo_ctx full_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, (RESUME_TIMEOUT_MS + ECHO_TIMEOUT_MS) / 1000.0,
		pred_echo_received, &full_ctx);
	T_EXPECT(ret == 0);
	T_EXPECT(!ts->got_error);
	T_EXPECT(!ts->got_eof);
	/* A real resume must have occurred on both sides. */
	T_EXPECT(fx.cli_suspended);
	T_EXPECT(fx.srv_suspended);
	T_EXPECT(fx.cli_resumed);
	T_EXPECT(fx.srv_resumed);
	T_EXPECT_EQ(mux_state(fx.cli), MUX_STATE_ESTABLISHED);
	T_EXPECT_EQ(mux_state(fx.srv), MUX_STATE_ESTABLISHED);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_LARGE);
	if (ts->recv_len == PAYLOAD_LARGE) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0);
	}

cleanup:
	free(payload);
	fixture_teardown(&fx);
}

/* like test_resume_stream_transparent, but deterministically forces
 * frames into the unacked ring (write-only sockets + session_suspend)
 * so the resume path MUST retransmit; transparent to the stream. */

T_DECLARE_CASE(test_resume_stream_unacked_retransmit)
{
	struct mux_test_fixture fx;
	unsigned char *payload = NULL;
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

	payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		T_FATAL("malloc failed");
		goto cleanup;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x3C);

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
	ts->send_len = PAYLOAD_LARGE;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Let the transfer get underway so the stream straddles the break. */
	struct echo_ctx partial_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE / 4,
	};
	if (wait_until(
		    &fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
		    &partial_ctx) != 0) {
		T_FATAL("echo transfer did not get underway");
		goto cleanup;
	}
	T_EXPECT(!ts->got_error);

	/* Force a non-empty unacked ring: stop processing ACKs and pump the send
	 * side so sent frames stay pending replay. */
	test_pump_unacked_no_wait(&fx);
	T_EXPECT(fx.cli->unacked.frames > 0);

	/* Freeze straight into SUSPENDED with the ring populated; resume must
	 * replay the preserved frames over the fresh transport. */
	session_suspend(fx.cli);
	session_suspend(fx.srv);
	T_EXPECT(fx.cli->unacked.retransmit_off != SIZE_MAX);

	const int resume_ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	T_EXPECT(resume_ret == 0);
	T_EXPECT(fx.cli_suspended);
	T_EXPECT(fx.srv_suspended);
	T_EXPECT(fx.cli_resumed);
	T_EXPECT(fx.srv_resumed);

	/* The full payload must echo back intact, with the stream never observing
	 * an error or premature EOF: the retransmission is transparent. */
	struct echo_ctx full_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, (RESUME_TIMEOUT_MS + ECHO_TIMEOUT_MS) / 1000.0,
		pred_echo_received, &full_ctx);
	T_EXPECT(ret == 0);
	T_EXPECT(!ts->got_error);
	T_EXPECT(!ts->got_eof);
	T_EXPECT_EQ(ts->recv_len, (size_t)PAYLOAD_LARGE);
	if (ts->recv_len == PAYLOAD_LARGE) {
		T_EXPECT(memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0);
	}

cleanup:
	free(payload);
	fixture_teardown(&fx);
}

/* test_resume_handshake_transport_lost: transport failure during a client
 * resume handshake must re-suspend (not reset/close) so the session can
 * resume on the next attempt. */

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
	(void)close(
		sp[1]); /* close peer end; writes to sp[0] get EPIPE / reads get EOF */

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
		       fx.cli != NULL ? fx.cli->unacked.frames : 0,
		       fx.srv != NULL ? (int)fx.srv->state : -1,
		       fx.srv != NULL ? fx.srv->unacked.frames : 0,
		       fx.cli_closed, fx.srv_closed);
	}
	T_EXPECT(ret == 0);
	T_EXPECT(fx.cli_resumed);
	T_EXPECT(fx.srv_resumed);
	T_EXPECT(!fx.cli_connect_failed);

cleanup:
	fixture_teardown(&fx);
}

/* nodelay=true, server sends PAYLOAD_LARGE to
 * client.  Reproduces reported infinite-loop / 100% CPU with nodelay and
 * reverse data direction. */

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

/* BDP estimator tests. */

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
	if (wndfilter_get(&ctx->ss->estimator.rx.bw_wnd) > 0 ||
	    wndfilter_get(&ctx->ss->estimator.tx.bw_wnd) > 0 ||
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

/* when both windows are automatic, a PONG-driven BDP update from inbound
 * PUSH bytes must grow stream_window while session_window (tx estimate)
 * stays at its floor. */

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

	/* Drive the PONG -> estimator -> session_update_window path directly.
	 * Use 4 × MUX_INITIAL_SEND_WINDOW: a 1× sample lands at BDP_MIN
	 * where integer-division truncation makes the assertion fragile. */
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
	const int_fast64_t sent_ns = fx.cli->estimator.last_probe_ns;

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

	/* PONG grows stream_window from the rx estimate; the idle tx
	 * direction leaves session_window at its floor. */
	T_EXPECT(
		fx.cli->stream_window >
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(
		fx.cli->session_window,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT(!fx.cli->estimator.ping_in_flight);

cleanup:
	fixture_teardown(&fx);
}

/* test_bdp_session_window_grows_from_ack_sample_only: a pure sender (no inbound
 * PUSH, hence no rx sample) must still grow session_window from the tx ack-clock
 * (estimator_add_acked) while stream_window stays at its rx-driven floor. */

T_DECLARE_CASE(test_bdp_session_window_grows_from_ack_sample_only)
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
	T_EXPECT_EQ(
		fx.cli->session_window,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(fx.cli->stream_window, fx.cli->session_window);

	/* Mirror test_bdp_auto_stream_window_updated_by_pong, but drive the
	 * cycle via estimator_add_acked only: sample stays 0 throughout. */
	estimator_add_acked(
		fx.cli, (uint_least64_t)MUX_INITIAL_SEND_WINDOW * 4);
	T_EXPECT(fx.cli->estimator.ping_in_flight);
	T_EXPECT_EQ(fx.cli->estimator.rx.sample, (size_t)0);
	T_EXPECT(fx.cli->estimator.tx.sample > 0);
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
	const int_fast64_t sent_ns = fx.cli->estimator.last_probe_ns;

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

	/* PONG grows session_window from the tx ack-clock estimate; the idle
	 * rx direction leaves stream_window at its floor. */
	T_EXPECT(
		fx.cli->session_window >
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(
		fx.cli->stream_window,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT(!fx.cli->estimator.ping_in_flight);
	T_EXPECT_EQ(fx.cli->estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(fx.cli->estimator.tx.sample, (size_t)0);

cleanup:
	fixture_teardown(&fx);
}

/* in manual window mode
 * (both stream_window and session_window > 0), BDP estimator updates must
 * not change either window. */

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

	/* recv.c guards estimator_add with auto_stream_window; session and
	 * stream windows must remain at their configured values. */
	T_EXPECT_EQ(fx.cli->session_window, fixed_session);
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

cleanup:
	fixture_teardown(&fx);
}

/* session_window auto (= 0), stream_window manual (> 0):
 * session_window must track peer_stream_window; estimator must not probe;
 * stream_window must stay at its configured value. */

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

	/* recv.c guards estimator_add with auto_stream_window; stream_window
	 * must remain at its configured value. */
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

	/* session_update_session_window must still update session_window to
	 * track peer_stream_window even when stream_window is manual. */
	const uint_least32_t floor_frames =
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT);
	const uint_least32_t new_peer_window = floor_frames * 4;
	fx.cli->peer_stream_window = new_peer_window;
	session_update_session_window(
		fx.cli, estimator_tx_window_size(&fx.cli->estimator));
	T_EXPECT_EQ(fx.cli->session_window, new_peer_window);
	/* stream_window must not have been modified. */
	T_EXPECT_EQ(fx.cli->stream_window, fixed_stream);

cleanup:
	fixture_teardown(&fx);
}

/* in automatic
 * window mode, session_update_session_window must update session_window to
 * match peer_stream_window without touching stream_window. */

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
	session_update_session_window(
		fx.cli, estimator_tx_window_size(&fx.cli->estimator));

	T_EXPECT_EQ(fx.cli->session_window, new_peer_window);
	/* stream_window is driven by the BDP estimator, not peer_stream_window;
	 * session_update_session_window must not change it. */
	T_EXPECT_EQ(fx.cli->stream_window, initial_stream_window);

cleanup:
	fixture_teardown(&fx);
}

/* test_bdp_control_only_no_cycle: control-only inbound traffic must not
 * start a measurement cycle when auto stream-window mode is enabled. */

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
	T_EXPECT(wndfilter_get(&fx.cli->estimator.rx.bw_wnd) == 0);
	T_EXPECT(wndfilter_get(&fx.cli->estimator.tx.bw_wnd) == 0);
	T_EXPECT(!fx.cli->estimator.ping_in_flight);

cleanup:
	fixture_teardown(&fx);
}

/* starting a cycle queues the
 * estimator PING immediately and stamps the timestamp into the frame payload
 * at queue time, transitioning directly to the in-flight state. */

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
		estimator_tx_window_size(&fx.cli->estimator),
		(size_t)fx.cli->session_window * (size_t)MUX_WINDOW_UNIT);
	T_EXPECT_EQ(
		fx.cli->estimator.rx.sample,
		(uint_least32_t)MUX_MAX_PAYLOAD_SIZE);
	T_EXPECT(fx.cli->wire.oobbuf.head != NULL);
	T_EXPECT(fx.cli->estimator.ping_in_flight);
	T_EXPECT(fx.cli->estimator.last_probe_ns > 0);

cleanup:
	fixture_teardown(&fx);
}

/* test_bdp_ping_sent: inbound PUSH starts an estimator cycle; the queued PING
 * is delivered by EV_WRITE, the peer PONGs, and the cycle records a bandwidth
 * sample.  A stuck oobbuf would time out the wait. */

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

/* on disconnect, stream_window is set to
 * the raw BDP in frames (half of the window target) and estimator learned
 * state is preserved. */

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
	fx.cli->estimator.rx.effective_bdp =
		3u * (size_t)MUX_INITIAL_SEND_WINDOW;
	const uint_least32_t initial_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	fx.cli->stream_window = (uint_least32_t)MAX(
		estimator_rx_window_size(&fx.cli->estimator) / 2 /
			MUX_WINDOW_UNIT,
		(size_t)initial_frames);
	T_EXPECT_EQ(
		estimator_rx_window_size(&fx.cli->estimator),
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

/* test_send_queue_saturates_read_credit: mux_stream_send must gate on
 * stream_read_credit_avail; a call that fills it is accepted, the next
 * is rejected (== 0), and SYN|ACK credit growth re-enables sends. */

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

/* mux_open_stream must return NULL after
 * mux_drain is called while a stream is open (so state stays ESTABLISHED
 * and the draining flag is what gates the rejection). */
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

/* a draining session must refuse inbound
 * streams opened by the peer with RST (REFUSED_STREAM) so the drain can
 * converge; streams opened before the drain remain in the session table. */
T_DECLARE_CASE(test_drain_refuses_peer_syn)
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

	/* Open a stream and wait until the server accepts it, holding the
	 * server session in ESTABLISHED during the drain. */
	struct mux_stream *s1 = mux_open_stream(fx.cli);
	if (s1 == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts1 = test_stream_new(&fx, s1);
	if (ts1 == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts1;
	mux_stream_io_start(fx.loop, &ts1->w_io);
	struct accepted_count_ctx acc_ctx = { .fx = &fx, .min_accepted = 1 };
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_accepted_count,
		    &acc_ctx) != 0) {
		T_FATAL("server did not accept the first stream");
		goto cleanup;
	}

	mux_drain(fx.srv);

	/* A stream opened by the peer after the drain must be refused:
	 * the client observes RST (delivered as a recv error) and the
	 * server never surfaces the stream to on_accept. */
	struct mux_stream *s2 = mux_open_stream(fx.cli);
	if (s2 == NULL) {
		T_FATAL("mux_open_stream returned NULL");
		goto cleanup;
	}
	struct test_stream *ts2 = test_stream_new(&fx, s2);
	if (ts2 == NULL) {
		T_FATAL("test_stream_new failed");
		goto cleanup;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts2;
	mux_stream_io_start(fx.loop, &ts2->w_io);

	const int ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts2);
	T_EXPECT(ret == 0);
	T_EXPECT(ts2->got_error);
	T_EXPECT(fx.n_accepted == 1);

cleanup:
	fixture_teardown(&fx);
}

/* Public API tests (mux_state / accessors / mux_stream_send / mux_stream_recv).
 * These drive the public mux API directly without the two-session harness. */

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static struct mux_frame *mux_api_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void mux_api_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = mux_api_test_alloc,
		.free = mux_api_test_free,
		.data = ctx,
	};
}

static void
mux_api_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void mux_api_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static struct mux_session make_session(struct frame_pool_ctx *restrict pool_ctx)
{
	return (struct mux_session){
		.pool = make_pool(pool_ctx),
		.max_payload =
			(uint_least32_t)mux_conf_default.max_frame_payload,
		.state = SESSION_ESTABLISHED,
		/* Seed the stats mirrors that mux_state()/mux_session_stats() read. */
		._pub_state = SESSION_ESTABLISHED,
		.stream_window = 3,
		._pub_stream_window = 3,
		.peer_stream_window = 5,
		._pub_peer_stream_window = 5,
	};
}

T_DECLARE_CASE(test_mux_state_maps_internal_states)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);

	/* mux_state() reads the published mirror, so drive it via PUB_STORE. */
	PUB_STORE(ss._pub_state, SESSION_ESTABLISHED);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_ESTABLISHED);
	PUB_STORE(ss._pub_state, SESSION_SUSPENDED);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_SUSPENDED);
	PUB_STORE(ss._pub_state, SESSION_HANDSHAKE);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_CONNECT);
	PUB_STORE(ss._pub_state, SESSION_CLOSED);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_CLOSED);
}

T_DECLARE_CASE(test_mux_peer_addr_and_window_accessors)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);

	memset(&ss.peer_addr, 0, sizeof(ss.peer_addr));
	T_EXPECT(mux_peer_addr(&ss) == NULL);
	ss.peer_addr.sa.sa_family = AF_UNIX;
	T_EXPECT(mux_peer_addr(&ss) != NULL);
	{
		struct mux_session_stats st = { 0 };
		mux_session_stats(&ss, &st);
		T_EXPECT_EQ(st.rx_window, (size_t)(3 * MUX_WINDOW_UNIT));
		T_EXPECT_EQ(st.tx_window, (size_t)(5 * MUX_WINDOW_UNIT));
	}
}

T_DECLARE_CASE(test_mux_stream_send_rejects_invalid_state)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct mux_stream s = {
		.state = STREAM_SYN_SENT,
		.session = &ss,
	};
	unsigned char payload[] = { 1, 2, 3 };
	size_t len = sizeof(payload);

	errno = 0;
	T_EXPECT(mux_stream_send(&s, payload, &len) < 0);
	T_EXPECT_EQ(errno, EINVAL);
}

T_DECLARE_CASE(test_mux_stream_send_queues_payload)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct ev_loop *loop = NULL;
	int fds[2] = { -1, -1 };
	struct mux_stream s = {
		.state = STREAM_INIT,
		.session = &ss,
		.send_window = 64,
	};
	unsigned char payload[20];
	size_t len = sizeof(payload);

	memset(payload, 0xA5, sizeof(payload));
	loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	ss.loop = loop;
	ss.wire.rx_open = true;
	ev_io_init(&ss.w_socket, mux_api_io_cb, fds[0], EV_READ);
	ss.w_socket.data = &ss;
	sched_init(&ss);
	T_EXPECT(mux_stream_send(&s, payload, &len) == 0);
	T_EXPECT_EQ(len, sizeof(payload));
	T_EXPECT(s.send_queue.head != NULL);
	mux_frame_list_clear(&s.send_queue, &ss.pool);
	(void)close(fds[0]);
	(void)close(fds[1]);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_mux_stream_recv_reports_eagain_and_reset)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct mux_stream s = {
		.state = STREAM_ESTABLISHED,
		.session = &ss,
	};
	s.recvbuf = ringbuf_new(MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(s.recvbuf != NULL);
	unsigned char buf[16];
	size_t len = sizeof(buf);

	errno = 0;
	T_EXPECT(mux_stream_recv(&s, buf, &len) < 0);
	T_EXPECT_EQ(errno, EAGAIN);

	s.rst_received = true;
	errno = 0;
	T_EXPECT(mux_stream_recv(&s, buf, &len) < 0);
	T_EXPECT_EQ(errno, ECONNRESET);
	ringbuf_free(s.recvbuf);
}

T_DECLARE_CASE(test_mux_stream_io_stop_clears_stream_binding)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct mux_stream s = {
		.state = STREAM_ESTABLISHED,
		.session = &ss,
	};
	mux_stream_io watcher;

	T_CHECK(loop != NULL);
	mux_stream_io_init(&watcher, mux_api_cb, &s, EV_READ | EV_WRITE);
	watcher.loop = loop;
	watcher.active = 1;
	s.direct.w_io = &watcher;

	mux_stream_io_stop(loop, &watcher);
	T_EXPECT(watcher.stream == NULL);
	T_EXPECT(s.direct.w_io == NULL);
	T_EXPECT_EQ(watcher.active, 0);

	ev_loop_destroy(loop);
}

/* main */

/* Cross-module cases against the real assembled stack; exercise behavior
 * the mock-isolated white-box tests cannot.  A self-contained xs_-prefixed
 * fixture keeps them independent of the integration harness. */

struct xs_pool_ctx {
	int alloc_calls;
	int free_calls;
};

struct xs_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
	struct xs_pool_ctx pool_ctx;
	int fds[2];
};

static struct mux_frame *xs_alloc(void *data, const size_t size)
{
	struct xs_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void xs_free(void *data, struct mux_frame *frame)
{
	struct xs_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator xs_make_pool(struct xs_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = xs_alloc,
		.free = xs_free,
		.data = ctx,
	};
}

static void xs_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void xs_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static int xs_setup(struct xs_fixture *restrict fx)
{
	*fx = (struct xs_fixture){
		.fds = { -1, -1 },
	};
	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fx->fds) != 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	fx->ss = (struct mux_session){
		.loop = fx->loop,
		.state = SESSION_ESTABLISHED,
		.pool = xs_make_pool(&fx->pool_ctx),
		.max_payload = (uint_least32_t)mux_conf_default.max_frame_payload,
		.session_window = 8,
		.stream_window = 4,
		.wire = {
			.rx_open = true,
		},
	};
	fx->ss.sched.streams = table_new(&mux_stream_table_opts);
	if (fx->ss.sched.streams == NULL) {
		(void)close(fx->fds[0]);
		(void)close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	ev_io_init(&fx->ss.w_socket, xs_io_cb, fx->fds[0], EV_READ);
	fx->ss.w_socket.data = &fx->ss;
	ev_timer_init(&fx->ss.w_idle_timeout, xs_timer_cb, 1.0, 0.0);
	fx->ss.w_idle_timeout.data = &fx->ss;
	sched_init(&fx->ss);
	fx->ss.wire.recvbuf = ringbuf_new(4u * (size_t)MUX_MAX_FRAME_SIZE);
	if (fx->ss.wire.recvbuf == NULL) {
		table_free(fx->ss.sched.streams);
		(void)close(fx->fds[0]);
		(void)close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	fx->ss.unacked.ring = mux_frame_ring_new(MUX_FRAME_RING_MIN);
	if (fx->ss.unacked.ring == NULL) {
		ringbuf_free(fx->ss.wire.recvbuf);
		fx->ss.wire.recvbuf = NULL;
		table_free(fx->ss.sched.streams);
		(void)close(fx->fds[0]);
		(void)close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	return 0;
}

static void xs_teardown(struct xs_fixture *restrict fx)
{
	if (fx->ss.sched.streams != NULL) {
		sched_free_streams(&fx->ss);
	}
	if (fx->ss.wire.oobbuf.head != NULL ||
	    ringbuf_readable(fx->ss.wire.recvbuf) > 0 ||
	    fx->ss.wire.sendbuf.head != NULL) {
		wire_discard_buffers(&fx->ss);
	}
	ringbuf_free(fx->ss.wire.recvbuf);
	fx->ss.wire.recvbuf = NULL;
	mux_frame_ring_free(&fx->ss.unacked.ring, &fx->ss.pool);
	fx->ss.unacked.frames = 0;
	fx->ss.unacked.retransmit_off = SIZE_MAX;
	if (fx->fds[0] >= 0) {
		(void)close(fx->fds[0]);
		fx->fds[0] = -1;
	}
	if (fx->fds[1] >= 0) {
		(void)close(fx->fds[1]);
		fx->fds[1] = -1;
	}
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

static struct mux_frame *xs_make_frame(
	const struct mux_frame_allocator *restrict pool,
	const uint_least16_t stream_id, const uint_least8_t flags,
	const uint_least16_t extra, const void *restrict payload,
	const size_t payload_len)
{
	struct mux_frame *const frame =
		mux_frame_get(pool, MUX_MAX_PAYLOAD_SIZE);
	if (frame == NULL) {
		return NULL;
	}
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = flags,
		.length = (uint_least16_t)payload_len,
		.stream_id = stream_id,
		.extra = extra,
	};
	mux_write_header(frame->data, &hdr);
	if (payload_len > 0 && payload != NULL) {
		memcpy(frame->data + MUX_FRAME_HEADER_SIZE, payload,
		       payload_len);
	}
	frame->len = MUX_FRAME_HEADER_SIZE + payload_len;
	frame->pos = 0;
	return frame;
}

/* unacked_ack_trim reports the trimmed payload bytes so the caller can feed
 * estimator_add_acked; the trim itself no longer touches the estimator (the
 * auto/manual gating now lives in the receive dispatch caller). */
T_DECLARE_CASE(test_session_ack_trim_acks_feed_estimator)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	static const unsigned char payload[100] = { 0 };

	struct mux_frame *const frame = xs_make_frame(
		&fx.ss.pool, 1, MUX_FLAG_PUSH, 0, payload, sizeof(payload));
	T_CHECK(frame != NULL);
	frame->unacked_count = 1;
	T_CHECK(mux_frame_ring_push(&fx.ss.unacked.ring, frame));
	fx.ss.unacked.frames = 1;
	fx.ss.unacked.bytes = sizeof(payload);
	fx.ss.unacked.last_ack_recv = 0;

	const struct unacked_ack_result r = unacked_ack_trim(&fx.ss, 1);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)0);
	T_EXPECT_EQ(r.trimmed_bytes, sizeof(payload));
	/* unacked stays decoupled from the estimator: no probe is started here. */
	T_EXPECT_EQ(fx.ss.estimator.tx.sample, (size_t)0);
	T_EXPECT(!fx.ss.estimator.ping_in_flight);

	xs_teardown(&fx);
}

/* Manual mode (default: both auto_*_window flags false) must not probe the
 * estimator on session ACKs. */
T_DECLARE_CASE(test_session_ack_trim_manual_mode_skips_estimator)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	static const unsigned char payload[100] = { 0 };

	struct mux_frame *const frame = xs_make_frame(
		&fx.ss.pool, 1, MUX_FLAG_PUSH, 0, payload, sizeof(payload));
	T_CHECK(frame != NULL);
	frame->unacked_count = 1;
	T_CHECK(mux_frame_ring_push(&fx.ss.unacked.ring, frame));
	fx.ss.unacked.frames = 1;
	fx.ss.unacked.bytes = sizeof(payload);
	fx.ss.unacked.last_ack_recv = 0;

	T_EXPECT(unacked_ack_trim(&fx.ss, 1).ok);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)0);
	T_EXPECT_EQ(fx.ss.estimator.tx.sample, (size_t)0);
	T_EXPECT(!fx.ss.estimator.ping_in_flight);

	xs_teardown(&fx);
}

T_DECLARE_CASE(test_session_open_stream_enforces_limits)
{
	struct xs_fixture fx;
	struct mux_stream *existing = NULL;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	fx.ss.conf.max_halfopen = 1;
	fx.ss.num_halfopen = 1;
	T_EXPECT(session_open_stream(&fx.ss) == NULL);

	fx.ss.num_halfopen = 0;
	fx.ss.conf.max_halfopen = 0;
	fx.ss.conf.max_streams = 1;
	existing = stream_new(&fx.ss, 3, true);
	T_CHECK(existing != NULL);
	T_EXPECT(sched_add_stream(&fx.ss, existing));
	T_EXPECT(session_open_stream(&fx.ss) == NULL);

	xs_teardown(&fx);
}

T_DECLARE_CASE(test_session_open_stream_success_sets_default_send_window)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	struct mux_stream *const s = session_open_stream(&fx.ss);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(s->id, (uint_least16_t)1);
	T_EXPECT_EQ(s->send_window, (uint_least32_t)MUX_DEFAULT_SEND_WINDOW);
	T_EXPECT(sched_find_stream(&fx.ss, s->id) == s);

	xs_teardown(&fx);
}

/* Regression: a received PONG must clear the estimator's ping_in_flight token
 * (the data path drives BDP PINGs) and reset w_keepalive.repeat to the full
 * keepalive interval (jittered). */
T_DECLARE_CASE(test_session_recv_pong_clears_ping_in_flight)
{
	struct xs_fixture fx;
	static const unsigned char payload[MUX_PING_PAYLOAD_SIZE] = { 0 };
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	/* Simulate a probe in flight (sent by keepalive or data path):
	 * payload is all-zero so sent_ns == 0, which matches last_probe_ns. */
	fx.ss.conf.keepalive = 60;
	ev_timer_init(&fx.ss.w_keepalive, xs_timer_cb, 0.0, 15.0);
	fx.ss.w_keepalive.data = &fx.ss;
	fx.ss.estimator.ping_in_flight = true;
	fx.ss.estimator.last_probe_ns = 0;

	/* Build a minimal PONG frame in recvbuf. */
	struct mux_frame *const frame = xs_make_frame(
		&fx.ss.pool, STREAMID_CTRL, 0, MUX_CTRL_PONG, payload,
		sizeof(payload));
	T_CHECK(frame != NULL);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PONG,
	};
	ringbuf_reset(fx.ss.wire.recvbuf);
	memcpy(ringbuf_write_ptr(fx.ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(fx.ss.wire.recvbuf, frame->len);

	session_recv_pong(&fx.ss, &hdr, frame->len);

	T_EXPECT(!fx.ss.estimator.ping_in_flight);
	/* Timer repeat must be restored to the keepalive interval, jittered
	 * down into (keepalive * (1 - jitter), keepalive]. */
	T_EXPECT(
		fx.ss.w_keepalive.repeat > 48.0 &&
		fx.ss.w_keepalive.repeat <= 60.0);

	mux_frame_put(&fx.ss.pool, frame);
	xs_teardown(&fx);
}

/* Any received PONG resets w_keepalive.repeat to the keepalive interval,
 * jittered down, regardless of whether a probe was outstanding. */
T_DECLARE_CASE(test_session_recv_pong_resets_keepalive_interval)
{
	struct xs_fixture fx;
	static const unsigned char payload[MUX_PING_PAYLOAD_SIZE] = { 0 };
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	fx.ss.conf.keepalive = 60;
	ev_timer_init(&fx.ss.w_keepalive, xs_timer_cb, 0.0, 60.0);
	fx.ss.w_keepalive.data = &fx.ss;
	fx.ss.estimator.ping_in_flight = false;

	struct mux_frame *const frame = xs_make_frame(
		&fx.ss.pool, STREAMID_CTRL, 0, MUX_CTRL_PONG, payload,
		sizeof(payload));
	T_CHECK(frame != NULL);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PONG,
	};
	ringbuf_reset(fx.ss.wire.recvbuf);
	memcpy(ringbuf_write_ptr(fx.ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(fx.ss.wire.recvbuf, frame->len);

	session_recv_pong(&fx.ss, &hdr, frame->len);

	T_EXPECT(!fx.ss.estimator.ping_in_flight);
	/* Timer repeat must be set to the keepalive interval, jittered down
	 * into (keepalive * (1 - jitter), keepalive]. */
	T_EXPECT(
		fx.ss.w_keepalive.repeat > 48.0 &&
		fx.ss.w_keepalive.repeat <= 60.0);

	mux_frame_put(&fx.ss.pool, frame);
	xs_teardown(&fx);
}

/* The sendbuf head is in-flight while send_blocked (TLS WANT_WRITE);
 * discarding it caused SSL bad-length on retry (bench.py -P 10 --bidir).
 * The blocked head must survive a discard call. */
T_DECLARE_CASE(test_session_discard_keeps_blocked_inflight_head)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	T_CHECK(session_send_ctrl(&fx.ss, 5, MUX_FLAG_ACK, 0));
	T_CHECK(fx.ss.wire.sendbuf.head != NULL);

	/* Mark the head as in flight; it must survive the discard. */
	fx.ss.wire.send_blocked = true;
	session_discard_stream_frames(&fx.ss, 5);
	T_EXPECT(fx.ss.wire.sendbuf.head != NULL);

	fx.ss.wire.send_blocked = false;
	xs_teardown(&fx);
}

/* Throughput benchmark */

#if WITH_TLS
/* Self-signed RSA-4096 cert (CN=test.example) + key, in-memory for all
 * TLS backends.  Also the authorized peer cert (mutual auth).  Same as
 * tlsutil_test so the benches share an apples-to-apples TLS setup. */
static char bench_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFKjCCAxKgAwIBAgIUM70vOlOUSVk9dQ7tbW/ih/8sKCwwDQYJKoZIhvcNAQEL\n"
	"BQAwFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCAXDTI2MDYwOTAyNDQ0NVoYDzIx\n"
	"MjYwNTE2MDI0NDQ1WjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwggIiMA0GCSqG\n"
	"SIb3DQEBAQUAA4ICDwAwggIKAoICAQC+SzjGbGTgjqsKQCEGYS3hFnO1hBoy1VQ8\n"
	"zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uceOaVYLXIe3f96+TucfBJw\n"
	"Wh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXkaxOOVaayRJx79cPxqqLFr\n"
	"rDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW9tNYRrZWVoTe21m2apl6\n"
	"/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGmRNzcAnguhIIe3z8qbwDH\n"
	"1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVpmL6QLpMolNS0cznJgVo2\n"
	"eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV08tZNLeNoN3ezRXsEYE2\n"
	"/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baozaQwoGNzDO/QXffAADp/W\n"
	"F2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus2IBTNFZp+mW8mCliYWop\n"
	"zfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi0omuKHTR326KPLkG7IpW\n"
	"agolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6Rn0bwaeCR6t0or8ru7Dxs\n"
	"dq/TW93U5wIDAQABo2wwajAdBgNVHQ4EFgQU3hgHVZAn/Lh/xbRhabVaEGQbxc8w\n"
	"HwYDVR0jBBgwFoAU3hgHVZAn/Lh/xbRhabVaEGQbxc8wDwYDVR0TAQH/BAUwAwEB\n"
	"/zAXBgNVHREEEDAOggx0ZXN0LmV4YW1wbGUwDQYJKoZIhvcNAQELBQADggIBAIWF\n"
	"in4MUtRj4R6GYGtjjnWt1m9aN4I/w22kdD183G07uTJZ+i545DdFNglt8ZIO1f2F\n"
	"eQ67wQfxIeFeZrr4x6wA7B+RVwX/mRuj3aby5QXhNDVkjAp2su9GRPyIe3jXPDv/\n"
	"/quE4Oufa0kE8HuvqPIOSO6UYWkNAP81LDoyDhyoadB5+mIuxpM3+NyKh6AK2g8n\n"
	"Ran7GYKtMUrL7ryRoJyPcpFk/QyrWAMCbmO3p2Rxx5sj3RtL+6HNYTqNij5qsB+S\n"
	"zmdmX8XyAW5Bgog3hrnrTn1j1AaxNgEczsjdDmaGQiYKscyLwMe38DI8NP/rPP4X\n"
	"rMH8B/TLl+uRwY1THRtkyHI6y4ZnGzmdEBf001J/KUfBFnLxHZBrJwMYbgqLWjba\n"
	"nVXS5GXAtt7Mmz2tKQo7gCHUjgByWcnun3qMGcEoCkkTaqi0pxf2844BYyy73VRT\n"
	"XdPJnfOOHDhuwkkeOfVJbPnfYFAAd8qMpmzBQvz4Clz2q4plB7odyWPSGwvLbFYs\n"
	"sdwuTXnyLqCrB3K0uMBlKr7xeWiVHUfe5oGCwgp7TjV/2AmKUxNzdg41d3Fn7TPK\n"
	"CncDeSmMy1elKbutfBvWvl8d7C0A9viO49Vy0CVR41uQnF09bzdFTYoaOrX8c+w4\n"
	"VtiUoGP5D91X1vhTixpq4BqoHRkKVQpZ0Z/9386J\n"
	"-----END CERTIFICATE-----\n";

static char bench_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQC+SzjGbGTgjqsK\n"
	"QCEGYS3hFnO1hBoy1VQ8zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uce\n"
	"OaVYLXIe3f96+TucfBJwWh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXka\n"
	"xOOVaayRJx79cPxqqLFrrDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW\n"
	"9tNYRrZWVoTe21m2apl6/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGm\n"
	"RNzcAnguhIIe3z8qbwDH1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVp\n"
	"mL6QLpMolNS0cznJgVo2eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV\n"
	"08tZNLeNoN3ezRXsEYE2/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baoz\n"
	"aQwoGNzDO/QXffAADp/WF2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus\n"
	"2IBTNFZp+mW8mCliYWopzfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi\n"
	"0omuKHTR326KPLkG7IpWagolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6R\n"
	"n0bwaeCR6t0or8ru7Dxsdq/TW93U5wIDAQABAoICAAorHteLh0BwnzcnAhzDKJ50\n"
	"gq5aZsP8nkm5kDqWre2s3IMqSJlVtKQg+GddTv/SyY5nzWt7tWjC0qLM1ccGdqir\n"
	"mDFMDCFqh9m1FwgPjEG+8lDWFpK8bc+fHluVbGDx21+UyOsI6c6WB+ikSLz9Lpl7\n"
	"C67jULmqVgC47NwoLpHpAoedu+/Pb89CDbzKqdfziAlT/NZmS3TaIA2KFvUKokeu\n"
	"y97UvdB/lb/617jVneXEMXr92ZfuCqqq0Wi0Dt8Egrdx29NoUhUwwcDuwRaIkz95\n"
	"GTLpHwj3cYU8G9BRheNkW6ddSzfvVy+E48mR0jJJItu7zOABucekSmaAIP63Xmmf\n"
	"ISujhU7P1LVLClj/T9c1AJ5EPCdZIbnooe3I1nEppGsKQZ6HP7YOPiWolDjJm2Z2\n"
	"nDQ/y/Ez3z44rywiY3slmypMDmbg96OBStHvfeBedDm18yRZu973QIJJ3kjrMBh9\n"
	"MitVVc/8q6WuTIgPnSfMLVYkSQv5AMrOntXcYMzxyiWHui3+lbT0JrL9knJVrNoi\n"
	"iT1NfSsbWaTxpOZgH0n07na9IDDvsENDy1uoE3wHVBGdHOKb+0bdauIHg4L2Vuaq\n"
	"9fEXHYnIfmXoPs2pAu+ijP2ZwAwBZpCQrs9wd5p5RAuCPnuQCnKhGZ2087/XZqGR\n"
	"e1sYrreurkSaZci1DbMxAoIBAQDjNLoiq/ckjuC4eBLr5ubgliKmQxGdXdwJJG/j\n"
	"udJfRWYY7yaRSSUWomin0jj35Ilmt5idzawSouDZVZz5LP7zPUvt78DtQSVFLazV\n"
	"vYyaKbPhRcVnt/y1nwbMIOCWPrNEE6smvQyjrANS9mAfPFUteDG7jH9qRxEOB6HT\n"
	"B3u0JinhbhP0sHyuju1bqzNLCS+Hqyv1re9eYATRMzsy+0vCnIZglojm9/Nfbu6F\n"
	"VNOaOmmpYn5+gfp3xepfa3CqRO/SdVWAwbgpYi000lWLQK1KarDad/UERwWjE96/\n"
	"cFStLkwK2IAGJ4K7hXFIcw5oWBanybyVg0SZp6d2X3ZHp6/lAoIBAQDWaPMZqLLY\n"
	"hDLTAi2FihBnva9zYd7BBkaGDiDas/HzTPfhSW2skCfFJbOf65NPq67YJTAbrVlN\n"
	"WLNsBFvaKgxAqJtmrgpcCrAW7L5x6hEPKNp4dBGaNOEVzDHZQjZMAobh5fCwl0uK\n"
	"2et6wda1BNat9ckYtSdYOZNoKSK2FCKzj2xGoboez8ndpq3sbQkYSsG62igMAXkd\n"
	"TRVlTdvIo5Tgjl6tFPPmppUi5hEJx0K6sD3v+vKK+kCoHU40blL+2t2sulXYSIfH\n"
	"YiyGBBAljA6AE2KKuz9YoRQ2+Erla2tPQMkC+LgJujEaCZaTP7jWzrvgB4mh+BrL\n"
	"yU73qOGfgyzbAoIBAESC98XQuRuLAfReMMZ1wBTk8NnVy4/6Z4lSNXMj623TDXBj\n"
	"XOvedJKYspo4Z/lILq6MmjareEG+X7LpgAYbLV3HlAfRjgl85XIwzbc+CxHJlXZO\n"
	"hbI65rcVlwUivNZRXdkfXTK3OwJ3siDoLh/9H2ownj6BpUI0382tO3zY+tJd168k\n"
	"dFwKg+5XJvfHbhYoVO7CDOVuZ4m7xngWzLkY0cWDUXn6qpmLFxYl60LFS3FsP8RV\n"
	"8PLQ2ugXBA915GlTlEWQIBJNV+0Sr7MH4ce13wtblKysE3QQvoBoU3jCtKXsGf4D\n"
	"PsecTm2hVYGVQDjypxI9YOJszNjQl0y4iIAe7okCggEBALhVkmtE9j3fqjJvdOOS\n"
	"R3hpRCZWxkP9OTSXgPeGLUWXrqUpk/kAFrEQMNYUmpmsaK27ixjAeD5fPCJpvO5b\n"
	"qB0O2Ev25UEsjyemcjVNn00BOpLEdz20qK8s1s6KdlPy+DPOlJe9+1xs7l6juAv5\n"
	"FPiKj1GGrUTUez7Z3tXbidoGPHidIn7K9ipx2qWhOGiCHPygAj4QJihi1To7LfHZ\n"
	"cW19+TelA+wQ27cdRRi7D0uhqh5gCZYigOQIDexVzVT+pgaSTKud794jMVQmuhsN\n"
	"xommINpVEakJE3APF5UWPTPt5uN/Ifp68SwJgkMmTaugITYCRPnTbHY3pISX1SJm\n"
	"jHECggEBAI7oDbmegf1H4KFbAn2ZCRJuMQg2SgtXb4gKbvrnvd/SAQoFkIth0VZ2\n"
	"9IccGPbgaEYxLXGDhY4oiibtRX5cCwB0uOYbb495SUuJRyA0bMJVHqtcRo3zX5df\n"
	"PNM+lny+hwzm3VziNfgGqNjAbOK5ukXrtaDMP1J2KyIbfC8A0eP+lUYnd/oJTRQN\n"
	"rJvfapSR/TGwsz0A4BtKCRJ5zlMvNm87soACzZBV9Es0ROf3683v/e1kMhffcvbS\n"
	"MKCbHGB5/oKk/I0aaRsNvyU0+TPSXEBu3HzAmmCns1p7MJYfghjg2H3f9nhE5smE\n"
	"NL+YLwobqSZhkl4iZWt2wGODitzp/aQ=\n"
	"-----END PRIVATE KEY-----\n";

static struct tls_context *bench_srv_tlsctx;
static struct tls_context *bench_cli_tlsctx;
#endif /* WITH_TLS */

enum {
	/* Per-round drain timeout.  The bench runner caps each calibration round
	 * at roughly one second of transfer, so 60s is ample headroom. */
	BENCH_STREAM_TIMEOUT_MS = 60000,
};

/* Establish a TCP pair over loopback (matching the tlsutil benches).
 * Returns two connected blocking fds (out[0]=accepted, out[1]=connected)
 * with TCP_NODELAY, or false on failure. */
static bool bench_loopback_pair(int out[2])
{
	out[0] = out[1] = -1;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		return false;
	}
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	socklen_t salen = sizeof(sa);
	if (bind(lfd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(lfd, 1) != 0 ||
	    getsockname(lfd, (struct sockaddr *)&sa, &salen) != 0) {
		(void)close(lfd);
		return false;
	}
	const int cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		(void)close(lfd);
		return false;
	}
	const int one = 1;
	(void)setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (connect(cfd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		(void)close(cfd);
		(void)close(lfd);
		return false;
	}
	const int afd = accept(lfd, NULL, NULL);
	(void)close(lfd);
	if (afd < 0) {
		(void)close(cfd);
		return false;
	}
	(void)setsockopt(afd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	out[0] = afd;
	out[1] = cfd;
	return true;
}

/* Connect two mux sessions over loopback TCP with TLS (AES-128-GCM) when
 * WITH_TLS.  Transport and cipher match the tlsutil benches for comparable
 * GiB/s figures; teardown via fixture_teardown, TLS contexts freed after. */
static int bench_fixture_setup(struct mux_test_fixture *restrict fx)
{
	*fx = (struct mux_test_fixture){ 0 };
	fx->listen_fd_cleanup = -1;
	fx->break_transport_sp = -1;

	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}

	int fds[2] = { -1, -1 };
#if WITH_TLS
	struct tls_connection *srv_conn = NULL;
#endif
	if (!bench_loopback_pair(fds)) {
		goto fail;
	}
	if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
		goto fail;
	}

#if WITH_TLS
	{
		char *authcerts[] = { bench_cert_pem };
		const struct tls_config tls_conf = {
			.cert = bench_cert_pem,
			.key = bench_key_pem,
			.authcerts = authcerts,
			.authcerts_count = 1,
#if WITH_OPENSSL
			.ciphersuites = "TLS_AES_128_GCM_SHA256",
#else
			.ciphersuites = "TLS1-3-AES-128-GCM-SHA256",
#endif
		};
		bench_srv_tlsctx = tls_ctx_server(&tls_conf);
		bench_cli_tlsctx = tls_ctx_client(&tls_conf);
		if (bench_srv_tlsctx == NULL || bench_cli_tlsctx == NULL) {
			goto fail;
		}
		/* tls_server wraps the server fd; the server session takes
		 * ownership of both the fd and this connection below. */
		srv_conn = tls_server(bench_srv_tlsctx, fds[0]);
		if (srv_conn == NULL) {
			goto fail;
		}
	}
#endif /* WITH_TLS */

	/* Throughput config: nodelay (iperf-style) + large stream_window to
	 * keep grants above the 2-frame immediate-ACK threshold and avoid
	 * deferring window updates to the coalescing timer. */
	struct mux_config conf = make_cli_conf(true);
	conf.stream_window = 256;
#if WITH_TLS
	/* Socket-offloaded TLS on both ends (the production default): the
	 * pre-wrapped server connection owns fds[0] and the client's tlsctx is
	 * offloaded onto fds[1], so the mux wire must not also do buffered I/O on
	 * those fds (doing so steals handshake bytes from the TLS library). */
	conf.tls_socket_offload = true;
#endif
	unsigned char srv_sid[MUX_SESSION_ID_LEN];
	unsigned char cli_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(srv_sid);
	proto_session_id_new(cli_sid);

	/* Server: inbound session on fds[0]; mux_start begins the handshake. */
	const struct mux_session_opts srv_opts = {
		.callbacks = &g_srv_callbacks,
		.userdata = fx,
		.conf = &conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = fds[0],
		.id = srv_sid,
#if WITH_TLS
		.conn = srv_conn,
#endif
	};
	fx->srv = mux_new(fx->loop, &srv_opts);
	if (fx->srv == NULL) {
		goto fail;
	}
	fds[0] = -1; /* owned by fx->srv (which now also owns srv_conn) */
	mux_start(fx->srv);

	/* Client: outbound session (fd=-1) with the peer end attached, which
	 * sends the hello and drives the handshake to completion. */
	const struct mux_session_opts cli_opts = {
		.callbacks = &g_cli_callbacks,
		.userdata = fx,
		.conf = &conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = -1,
		.id = cli_sid,
#if WITH_TLS
		.tlsctx = bench_cli_tlsctx,
#endif
	};
	fx->cli = mux_new(fx->loop, &cli_opts);
	if (fx->cli == NULL) {
		goto fail;
	}
	mux_start(fx->cli);
	mux_attach_fd(fx->cli, fds[1]);
	fds[1] = -1; /* owned by fx->cli */
	return 0;

fail:
	if (fds[0] >= 0) {
		(void)close(fds[0]);
	}
	if (fds[1] >= 0) {
		(void)close(fds[1]);
	}
#if WITH_TLS
	/* srv_conn is owned by fx->srv once it exists; otherwise free it here. */
	if (fx->srv == NULL && srv_conn != NULL) {
		tls_conn_free(srv_conn);
	}
#endif
	if (fx->srv != NULL) {
		mux_close(fx->srv);
		fx->srv = NULL;
	}
#if WITH_TLS
	tls_ctx_free(bench_srv_tlsctx);
	bench_srv_tlsctx = NULL;
	tls_ctx_free(bench_cli_tlsctx);
	bench_cli_tlsctx = NULL;
#endif
	ev_loop_destroy(fx->loop);
	fx->loop = NULL;
	return -1;
}

/* Cumulative-drain predicate for the throughput bench's persistent stream.
 * Unlike pred_drain_done it does not wait for a FIN: the stream is reused across
 * calibration rounds and stays open, so the sink only ever counts recv_total. */
static int pred_drain_total(void *ptr)
{
	const struct drain_done_ctx *restrict ctx = ptr;
	if (ctx->fx->n_accepted < 1) {
		return 0;
	}
	const struct test_stream *restrict ts = ctx->fx->accepted[0];
	if (ts->got_error) {
		return -1;
	}
	return ts->recv_total >= ctx->expected_total ? 1 : 0;
}

/* Persistent state for bench_mux_stream_throughput.  The fixture, the single
 * client stream and its send buffer are created once (bench_mux_setup) and
 * reused across calibration rounds, then reclaimed at process exit. */
static struct mux_test_fixture bench_mux_fx;
static struct test_stream *bench_mux_ts;
static unsigned char *bench_mux_send_buf;
static uint_fast64_t bench_mux_expected;

static void bench_mux_teardown(void)
{
	free(bench_mux_send_buf);
	bench_mux_send_buf = NULL;
	fixture_teardown(&bench_mux_fx);
#if WITH_TLS
	/* fixture_teardown closed the sessions (and their TLS connections); the
	 * contexts those connections referenced are freed last. */
	tls_ctx_free(bench_srv_tlsctx);
	bench_srv_tlsctx = NULL;
	tls_ctx_free(bench_cli_tlsctx);
	bench_cli_tlsctx = NULL;
#endif
	slog_setlevel(LOG_LEVEL_DEBUG);
}

static void bench_mux_setup(void)
{
	/* Silence setup and per-frame logging so it neither clutters the bench
	 * output nor dominates the measured transfer. */
	slog_setlevel(LOG_LEVEL_SILENCE);
	T_CHECK(bench_fixture_setup(&bench_mux_fx) == 0);
	T_CHECK(wait_until(
			&bench_mux_fx, ESTABLISH_TIMEOUT_MS / 1000.0,
			pred_established, &bench_mux_fx) == 0);

	/* Server accepts the stream as a discard sink. */
	bench_mux_fx.accept_mode = ACCEPT_DRAIN;

	bench_mux_send_buf = malloc(CHUNK_SIZE);
	T_CHECK(bench_mux_send_buf != NULL);
	fill_payload(bench_mux_send_buf, CHUNK_SIZE, 0x5A);

	struct mux_stream *const s = mux_open_stream(bench_mux_fx.cli);
	T_CHECK(s != NULL);
	bench_mux_ts = test_stream_new(&bench_mux_fx, s);
	T_CHECK(bench_mux_ts != NULL);
	bench_mux_fx.cli_streams[bench_mux_fx.n_cli_streams++] = bench_mux_ts;
	bench_mux_ts->send_data = bench_mux_send_buf;
	bench_mux_ts->send_len = CHUNK_SIZE;
	bench_mux_ts->send_cyclic = true;
	/* The stream is reused across rounds: never half-close, so the server's
	 * drain sink keeps counting into recv_total without a FIN. */
	bench_mux_ts->send_shutdown_on_drain = false;

	T_CHECK(atexit(bench_mux_teardown) == 0);
}

/* One-directional single-stream throughput over mux-over-TLS (loopback NIC),
 * matching the tlsutil benches' transport and cipher so the figures are
 * directly comparable.  Each op streams one CHUNK_SIZE payload that the server
 * drains and discards (set via T_BENCH_SET_BYTES for the throughput column). */
T_DECLARE_BENCH(bench_mux_stream_throughput)
{
	static bool ready = false;
	if (!ready) {
		bench_mux_setup();
		ready = true;
	}
	T_BENCH_SET_BYTES(CHUNK_SIZE);

	/* Queue N more chunks onto the persistent stream and wait for the server
	 * to drain them all.  send_remaining and the expected total accumulate, so
	 * the cyclic sender simply resumes where the previous round left off. */
	const uint_fast64_t round_bytes = _b_->N * (uint_fast64_t)CHUNK_SIZE;
	bench_mux_expected += round_bytes;
	bench_mux_ts->send_remaining += round_bytes;
	struct drain_done_ctx ctx = {
		.fx = &bench_mux_fx,
		.expected_total = bench_mux_expected,
	};
	mux_stream_io_start(bench_mux_fx.loop, &bench_mux_ts->w_io);
	T_CHECK(wait_until(
			&bench_mux_fx, BENCH_STREAM_TIMEOUT_MS / 1000.0,
			pred_drain_total, &ctx) == 0);
}

static const struct testing_suite suite[] = {
	T_CASE(test_establish),
	T_CASE(test_send_recv_small),
	T_CASE(test_idle_scheduler_stops_while_sendbuf_blocked),
	T_CASE(test_retransmit_excludes_lifecycle_drain),
	T_CASE(test_nagle_releases_queued_small_frame_on_ack),
	T_CASE(test_send_recv_large),
	T_CASE(test_half_close),
	T_CASE(test_rst_on_unread_data),
	T_CASE(test_multi_stream),
	T_CASE(test_server_open_send_recv),
	T_CASE(test_client_open_server_sends_first),
	T_CASE(test_graceful_close_server_initiated),
	T_CASE(test_simultaneous_close),
	T_CASE(test_rst_from_client),
	T_CASE(test_active_open_shutdown_before_synack),
	T_CASE(test_interop_i1_non_syn_unknown_stream),
	T_CASE(test_interop_i2_close_wait_push),
	T_CASE(test_interop_i3_ack_fin_credit),
	T_CASE(test_interop_i4_stream_id_parity),
	T_CASE(test_interop_i5_duplicate_syn),
	T_CASE(test_interop_i6_fast_open_16384),
	T_CASE(test_interop_i7_fin_then_data),
	T_CASE(test_interop_i8_rst_then_non_rst),
	T_CASE(test_interop_i9_reserved_flag),
	T_CASE(test_interop_i10_hello_version_mismatch),
	T_CASE(test_interop_i11_ping_pong_echo),
	T_CASE(test_interop_i12_unknown_keepalive_subtype),
	T_CASE(test_interop_i13_invalid_syn_flags),
	T_CASE(test_interop_i14_reserved_stream0_frame),
	T_CASE(test_no_reconnect_with_idle_timeout),
	T_CASE(test_resume_idle),
	T_CASE(test_resume_retransmit),
	T_CASE(test_resume_stream_transparent),
	T_CASE(test_resume_stream_unacked_retransmit),
	T_CASE(test_resume_handshake_transport_lost),
	T_CASE(test_nodelay_reverse_large),
	T_CASE(test_bdp_auto_stream_window_updated_by_pong),
	T_CASE(test_bdp_session_window_grows_from_ack_sample_only),
	T_CASE(test_bdp_manual_window_mode_no_estimator_effect),
	T_CASE(test_bdp_auto_session_window_without_auto_stream_window),
	T_CASE(test_bdp_auto_session_window_tracks_peer_stream_window),
	T_CASE(test_bdp_control_only_no_cycle),
	T_CASE(test_bdp_ping_queued_before_send_progress),
	T_CASE(test_bdp_ping_sent),
	T_CASE(test_bdp_stop_halves_stream_window),
	T_CASE(test_send_queue_saturates_read_credit),
	T_CASE(test_drain_rejects_new_streams),
	T_CASE(test_drain_refuses_peer_syn),

	T_CASE(test_mux_state_maps_internal_states),
	T_CASE(test_mux_peer_addr_and_window_accessors),
	T_CASE(test_mux_stream_send_rejects_invalid_state),
	T_CASE(test_mux_stream_send_queues_payload),
	T_CASE(test_mux_stream_recv_reports_eagain_and_reset),
	T_CASE(test_mux_stream_io_stop_clears_stream_binding),
	T_CASE(test_session_ack_trim_acks_feed_estimator),
	T_CASE(test_session_ack_trim_manual_mode_skips_estimator),
	T_CASE(test_session_open_stream_enforces_limits),
	T_CASE(test_session_open_stream_success_sets_default_send_window),
	T_CASE(test_session_recv_pong_clears_ping_in_flight),
	T_CASE(test_session_recv_pong_resets_keepalive_interval),
	T_CASE(test_session_discard_keeps_blocked_inflight_head),
	/* Opt-in throughput benchmark (mux-over-TLS, loopback NIC); skipped by the
	 * default run.  Select with `--run <ere>` or TESTING_FILTER. */
	T_BENCH(bench_mux_stream_throughput),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	T_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	slog_setoutput(SLOG_OUTPUT_FILE, stderr);
	slog_setlevel(LOG_LEVEL_DEBUG);

	return testing_main(argc, argv, suite);
}
