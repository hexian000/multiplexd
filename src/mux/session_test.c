/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* session_test.c - white-box tests for session.c (lifecycle: handshake-done
 * re-arming, graceful/forced shutdown, drain, socket-option helper);
 * session.c #included; all sibling-module collaborators mocked below. */

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/recv.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <netinet/tcp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mux/session.c"

/* Configurable mock results: each test sets these before driving the code under
 * test, then restores the inert default.  Declared here so the mock bodies
 * below can read them. */
static bool g_session_send_oob_result = true;
static enum wire_shutdown_state g_wire_shutdown_result = WIRE_SHUTDOWN_DONE;
static bool g_wire_wait_eof_result = true;
static bool g_wire_tls_start_result = true;
static uint_least16_t g_alloc_stream_id_result = STREAMID_CTRL;
static struct mux_stream *g_stream_new_result = NULL;
static bool g_sched_add_stream_result = true;

/* mock - collaborator stubs for session.c's sibling-module calls; most are
 * inert, a few reproduce minimal behavior for lifecycle decisions under test
 * (e.g. sched_coalesce_arm actually arms the timer). */

static void st_coalesce_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

void sched_init(struct mux_session *restrict ss)
{
	ev_timer_init(&ss->sched.w_coalesce, st_coalesce_cb, 0.0, 1.0);
	ss->sched.w_coalesce.data = ss;
}

void sched_coalesce_arm(struct mux_session *ss)
{
	if (!ev_is_active(&ss->sched.w_coalesce)) {
		ev_timer_start(ss->loop, &ss->sched.w_coalesce);
	}
}

void sched_schedule(struct mux_session *ss)
{
	(void)ss;
}

void sched_wake(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
}

bool sched_add_stream(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
	return g_sched_add_stream_result;
}

uint_least16_t sched_alloc_stream_id(struct mux_session *ss)
{
	(void)ss;
	return g_alloc_stream_id_result;
}

void sched_free_streams(struct mux_session *restrict ss)
{
	ss->sched.sched_head = NULL;
	ss->sched.sched_tail = NULL;
	ss->sched.drr_active = NULL;
	ss->sched.lp_head = NULL;
	ss->sched.lp_tail = NULL;
	ss->sched.delay_head = NULL;
	ss->unacked.stalled = false;
	ss->sched.num_tombstones = 0;
	ss->sched.next_stream_id = 0;
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
}

void wire_discard_buffers(struct mux_session *restrict ss)
{
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	ss->wire.sendbuf_staging = false;
	if (ss->wire.recvbuf != NULL) {
		ringbuf_reset(ss->wire.recvbuf);
	}
}

void unacked_free_all(struct mux_session *ss)
{
	mux_frame_ring_free(&ss->unacked.ring, &ss->pool);
	ss->unacked.frames = 0;
	ss->unacked.bytes = 0;
	ss->unacked.partial_offset = 0;
	ss->unacked.retransmit_off = SIZE_MAX;
}

void wire_conn_free(struct mux_session *ss)
{
	(void)ss;
}

/* Inert sibling entry points: not exercised by the lifecycle cases below. */

void estimator_init(struct mux_session *restrict ss, size_t bdp)
{
	(void)ss;
	(void)bdp;
}

size_t estimator_rx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return 0;
}

bool handshake_enqueue_hello(
	struct mux_session *ss, int msgid, bool include_resume_seq)
{
	(void)ss;
	(void)msgid;
	(void)include_resume_seq;
	return true;
}

void session_flush_oob(struct mux_session *ss)
{
	(void)ss;
}

void session_on_recv(struct mux_session *ss)
{
	(void)ss;
}

void session_on_send(struct mux_session *ss)
{
	(void)ss;
}

bool session_send_oob(
	struct mux_session *ss, uint_fast8_t extra,
	const unsigned char *payload, size_t payload_len)
{
	(void)ss;
	(void)extra;
	(void)payload;
	(void)payload_len;
	return g_session_send_oob_result;
}

struct mux_stream *
stream_new(struct mux_session *restrict ss, uint_fast16_t id, bool active_open)
{
	(void)ss;
	(void)id;
	(void)active_open;
	return g_stream_new_result;
}

void stream_free(struct mux_stream *s)
{
	(void)s;
}

bool unacked_resume_ack_recv(struct mux_session *ss, uint_least32_t peer_ack)
{
	(void)ss;
	(void)peer_ack;
	return true;
}

void unacked_track_sent(struct mux_session *ss, struct mux_frame *frame)
{
	/* Real unacked_track_sent takes ownership; reclaim here to avoid leaks
	 * when a test routes a captured sendbuf frame through this path. */
	mux_frame_put(&ss->pool, frame);
}

void wire_adopt_tlsconn(
	struct mux_session *restrict ss, struct tls_connection *restrict conn)
{
	(void)ss;
	(void)conn;
}

void wire_tlsconn_free(struct tls_connection *conn)
{
	(void)conn;
}

enum wire_shutdown_state wire_shutdown(struct mux_session *ss)
{
	(void)ss;
	return g_wire_shutdown_result;
}

void wire_tls_log_status(struct mux_session *ss)
{
	(void)ss;
}

bool wire_tls_start(struct mux_session *ss)
{
	(void)ss;
	return g_wire_tls_start_result;
}

bool wire_wait_eof(struct mux_session *ss)
{
	(void)ss;
	return g_wire_wait_eof_result;
}

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

struct session_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
	struct frame_pool_ctx pool_ctx;
	int fds[2];
};

static struct mux_frame *session_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void session_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = session_test_alloc,
		.free = session_test_free,
		.data = ctx,
	};
}

static void
session_test_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void
session_test_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static int setup_fixture(struct session_fixture *restrict fx)
{
	*fx = (struct session_fixture){
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
		.pool = make_pool(&fx->pool_ctx),
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
	ev_io_init(&fx->ss.w_socket, session_test_io_cb, fx->fds[0], EV_READ);
	fx->ss.w_socket.data = &fx->ss;
	ev_timer_init(&fx->ss.w_idle_timeout, session_test_timer_cb, 1.0, 0.0);
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

static int setup_handshake_fixture(struct session_fixture *restrict fx)
{
	if (setup_fixture(fx) != 0) {
		return -1;
	}
	fx->ss.state = SESSION_HANDSHAKE;
	/* session_handshake_done calls ev_timer_stop(&w_connect_timeout) and
	 * ev_timer_again on w_keepalive; the repeat interval must
	 * be > 0 for ev_timer_again to actually start the watcher. */
	ev_timer_init(
		&fx->ss.w_connect_timeout, session_test_timer_cb, 0.0, 0.0);
	fx->ss.w_connect_timeout.data = &fx->ss;
	ev_timer_init(&fx->ss.w_timeout, session_test_timer_cb, 0.0, 5.0);
	fx->ss.w_timeout.data = &fx->ss;
	ev_timer_init(&fx->ss.w_keepalive, session_test_timer_cb, 0.0, 5.0);
	fx->ss.w_keepalive.data = &fx->ss;
	ev_timer_init(&fx->ss.w_send_timeout, session_test_timer_cb, 0.0, 5.0);
	fx->ss.w_send_timeout.data = &fx->ss;
	return 0;
}

static void teardown_fixture(struct session_fixture *restrict fx)
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

/* regression - targeted cases for one session-lifecycle decision each */

T_DECLARE_CASE(test_session_handshake_done_rearms_coalesce_for_delay_list)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}

	struct mux_stream s = {
		.id = 1,
		.delay_pending = true,
		.delay_ticks = 2,
	};
	fx.ss.sched.delay_head = &s;
	T_EXPECT(!ev_is_active(&fx.ss.sched.w_coalesce));

	session_handshake_done(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_ESTABLISHED);
	T_EXPECT(ev_is_active(&fx.ss.sched.w_coalesce));

	/* Remove the on-stack stream from the delay list before teardown. */
	fx.ss.sched.delay_head = NULL;
	teardown_fixture(&fx);
}

/* Regression: after session_handshake_done, w_coalesce must be re-armed when
 * recv_seq != ack_seq (session-level ACK backlog preserved across the
 * transport break), even when the delay list is empty. */
T_DECLARE_CASE(test_session_handshake_done_rearms_coalesce_for_ack_backlog)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}

	fx.ss.unacked.recv_seq = 5;
	fx.ss.unacked.ack_seq = 3;
	T_EXPECT(!ev_is_active(&fx.ss.sched.w_coalesce));

	session_handshake_done(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_ESTABLISHED);
	T_EXPECT(ev_is_active(&fx.ss.sched.w_coalesce));

	teardown_fixture(&fx);
}

/* Regression: after session_handshake_done on a fresh establish (no backlog),
 * w_coalesce must NOT be started. */
T_DECLARE_CASE(test_session_handshake_done_no_coalesce_without_backlog)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}

	/* No delay_head and recv_seq == ack_seq: no backlog. */
	T_EXPECT(!ev_is_active(&fx.ss.sched.w_coalesce));

	session_handshake_done(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_ESTABLISHED);
	T_EXPECT(!ev_is_active(&fx.ss.sched.w_coalesce));

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_initiate_shutdown_transitions_to_closed)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	/* SESSION_INIT takes the force-close path: no timer init required;
	 * session_cleanup closes w_socket.fd (== fds[0]), so clear it in
	 * the fixture to prevent double-close in teardown_fixture. */
	fx.ss.state = SESSION_INIT;
	session_initiate_shutdown(&fx.ss);
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_drain_sets_draining_flag)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	/* Use SESSION_INIT so that session_drain does not trigger an
	 * immediate session_initiate_shutdown (which would require timer
	 * initialisation and leave the session CLOSED). */
	fx.ss.state = SESSION_INIT;
	session_drain(&fx.ss);
	T_EXPECT(fx.ss.draining);
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_INIT);

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_socket_user_timeout_sets_option)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);
#if WITH_TCP_USER_TIMEOUT
	T_EXPECT_EQ(socket_user_timeout(fd, 5000), 0);
	int val = 0;
	socklen_t len = sizeof(val);
	T_CHECK(getsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &val, &len) == 0);
	T_EXPECT_EQ(val, 5000);
#else
	/* Platform lacks TCP_USER_TIMEOUT; function must return -1. */
	T_EXPECT_EQ(socket_user_timeout(fd, 5000), -1);
#endif /* WITH_TCP_USER_TIMEOUT */
	(void)close(fd);
}

/* session_log_frame_header / format_frame_flags: VERYVERBOSE-gated diagnostic.
 * Exercises the flag-name join, the unknown-bit branch, and the NONE branch. */
T_DECLARE_CASE(test_session_log_frame_header_formats_flags)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	unsigned char raw[MUX_FRAME_HEADER_SIZE] = { 0 };
	/* Multiple known flags: exercises the "|" separator join. */
	struct mux_header hdr = {
		.flags = MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_FIN |
			 MUX_FLAG_RST | MUX_FLAG_PUSH,
	};
	session_log_frame_header(&fx.ss, "all-flags", raw, &hdr);
	/* Known flag plus unknown bits: exercises the UNKNOWN(...) branch. */
	hdr.flags = MUX_FLAG_SYN | (uint_least8_t)(~MUX_FLAG_MASK);
	session_log_frame_header(&fx.ss, "unknown", raw, &hdr);
	/* No flags: exercises the NONE branch. */
	hdr.flags = 0;
	session_log_frame_header(&fx.ss, "none", raw, &hdr);

	teardown_fixture(&fx);
}

/* closing_cb dispatch on the transport-shutdown state machine: PENDING returns
 * without a state change; ERROR resets the session. */
T_DECLARE_CASE(test_closing_cb_pending_then_error)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_CLOSING;

	g_wire_shutdown_result = WIRE_SHUTDOWN_PENDING;
	closing_cb(&fx.ss);
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSING);

	g_wire_shutdown_result = WIRE_SHUTDOWN_ERROR;
	closing_cb(&fx.ss);
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	g_wire_shutdown_result = WIRE_SHUTDOWN_DONE;

	fx.fds[0] = -1; /* session_cleanup closed it */
	teardown_fixture(&fx);
}

/* close_wait_cb logs and resets when wire_wait_eof reports unexpected state. */
T_DECLARE_CASE(test_close_wait_cb_unexpected)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_CLOSE_WAIT;

	g_wire_wait_eof_result = false;
	close_wait_cb(&fx.ss);
	g_wire_wait_eof_result = true;
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* connect_cb after TCP connect: TLS start failure resets; a live TLS connection
 * advances to the mux handshake. */
T_DECLARE_CASE(test_connect_cb_tls_paths)
{
#if WITH_TLS
	{
		struct session_fixture fx;
		if (setup_fixture(&fx) != 0) {
			T_FATAL("setup_fixture failed");
			return;
		}
		fx.ss.state = SESSION_CONNECT;
		g_wire_tls_start_result = false;
		connect_cb(&fx.ss);
		g_wire_tls_start_result = true;
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
		fx.fds[0] = -1;
		teardown_fixture(&fx);
	}
	{
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.state = SESSION_CONNECT;
		/* Opaque non-NULL: connect_cb only tests tlsconn for NULL, and the
		 * mocked wire/handshake paths never dereference it. */
		fx.ss.wire.tlsconn = (struct tls_connection *)(uintptr_t)1;
		connect_cb(&fx.ss);
		fx.ss.wire.tlsconn = NULL;
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_HANDSHAKE);
		teardown_fixture(&fx);
	}
#else
	T_SKIP();
#endif /* WITH_TLS */
}

/* session_on_dead_link: a negotiated session id suspends for resume; without
 * one the session is closed.  The suspend path also captures a sendbuf with one
 * frame equal to retransmit_copy (reclaimed) and one tracked for replay. */
T_DECLARE_CASE(test_dead_link_suspend_for_resume)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.handshake.has_session_id = true;

	struct mux_frame *const copy =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	struct mux_frame *const tracked =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	if (copy == NULL || tracked == NULL) {
		T_FATAL("frame alloc failed");
		teardown_fixture(&fx);
		return;
	}
	copy->len = tracked->len = MUX_FRAME_HEADER_SIZE;
	copy->pos = tracked->pos = 0;
	mux_frame_list_push(&fx.ss.wire.sendbuf, copy);
	mux_frame_list_push(&fx.ss.wire.sendbuf, tracked);
	fx.ss.unacked.retransmit_copy = copy;

	session_on_dead_link(&fx.ss, "send timeout");
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_SUSPENDED);

	fx.fds[0] = -1; /* session_suspend closed it */
	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_dead_link_close_without_session_id)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.handshake.has_session_id = false;

	session_on_dead_link(&fx.ss, "send timeout");
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* Liveness timer callbacks all funnel into session_on_dead_link. */
T_DECLARE_CASE(test_timeout_and_send_timeout_callbacks)
{
	{
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.state = SESSION_ESTABLISHED;
		fx.ss.handshake.has_session_id = false;
		timeout_cb(fx.ss.loop, &fx.ss.w_timeout, EV_TIMER);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
		fx.fds[0] = -1;
		teardown_fixture(&fx);
	}
	{
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.state = SESSION_ESTABLISHED;
		fx.ss.handshake.has_session_id = false;
		send_timeout_cb(fx.ss.loop, &fx.ss.w_send_timeout, EV_TIMER);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
		fx.fds[0] = -1;
		teardown_fixture(&fx);
	}
}

/* keepalive_cb emits a PROBE (or logs and skips on pool exhaustion) and re-arms
 * the keepalive timer; the session stays ESTABLISHED either way. */
T_DECLARE_CASE(test_keepalive_cb_emits_and_rearms)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.conf.keepalive = 5;

	g_session_send_oob_result = false; /* exhausted-pool skip branch */
	keepalive_cb(fx.ss.loop, &fx.ss.w_keepalive, EV_TIMER);
	g_session_send_oob_result = true; /* normal PROBE branch */
	keepalive_cb(fx.ss.loop, &fx.ss.w_keepalive, EV_TIMER);
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_ESTABLISHED);

	teardown_fixture(&fx);
}

/* connect_timeout_cb covers the resume-timeout (SUSPENDED) and close-timeout
 * (CLOSING) arms; both close the session. */
T_DECLARE_CASE(test_connect_timeout_cb_states)
{
	{
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.state = SESSION_SUSPENDED;
		connect_timeout_cb(
			fx.ss.loop, &fx.ss.w_connect_timeout, EV_TIMER);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
		fx.fds[0] = -1;
		teardown_fixture(&fx);
	}
	{
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.state = SESSION_CLOSING;
		connect_timeout_cb(
			fx.ss.loop, &fx.ss.w_connect_timeout, EV_TIMER);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
		fx.fds[0] = -1;
		teardown_fixture(&fx);
	}
}

/* session_open_stream rejection paths: closed, not-established, peer rejects
 * inbound, stream-id exhaustion, stream_new OOM, and sched_add failure. */
T_DECLARE_CASE(test_open_stream_rejections)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	fx.ss.state = SESSION_CLOSED;
	T_EXPECT(session_open_stream(&fx.ss) == NULL);

	fx.ss.state = SESSION_HANDSHAKE;
	T_EXPECT(session_open_stream(&fx.ss) == NULL);

	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.handshake.peer_rejects_inbound_streams = true;
	T_EXPECT(session_open_stream(&fx.ss) == NULL);
	fx.ss.handshake.peer_rejects_inbound_streams = false;

	/* sched_alloc_stream_id returns STREAMID_CTRL: IDs exhausted. */
	g_alloc_stream_id_result = STREAMID_CTRL;
	T_EXPECT(session_open_stream(&fx.ss) == NULL);

	/* A valid id, but stream_new fails (OOM). */
	g_alloc_stream_id_result = 5;
	g_stream_new_result = NULL;
	T_EXPECT(session_open_stream(&fx.ss) == NULL);

	/* stream_new succeeds, but sched_add_stream fails. */
	struct mux_stream dummy = { .id = 5 };
	g_stream_new_result = &dummy;
	g_sched_add_stream_result = false;
	T_EXPECT(session_open_stream(&fx.ss) == NULL);
	g_stream_new_result = NULL;
	g_sched_add_stream_result = true;
	g_alloc_stream_id_result = STREAMID_CTRL;

	teardown_fixture(&fx);
}

/* session_set_config on a live session: auto session-window floor, timer
 * stop/restart for timeout/keepalive/send/connect/idle. */
T_DECLARE_CASE(test_set_config_live_session_branches)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.auto_session_window = true;
	fx.ss.session_window = 1; /* below the initial floor */

	/* Arm the timers whose "active -> ev_timer_again" arms we want to hit. */
	ev_timer_set(&fx.ss.w_send_timeout, 0.0, 5.0);
	ev_timer_again(fx.ss.loop, &fx.ss.w_send_timeout);
	ev_timer_set(&fx.ss.w_connect_timeout, 0.0, 5.0);
	ev_timer_again(fx.ss.loop, &fx.ss.w_connect_timeout);
	ev_timer_set(&fx.ss.w_idle_timeout, 0.0, 5.0);
	ev_timer_again(fx.ss.loop, &fx.ss.w_idle_timeout);

	struct mux_config conf = fx.ss.conf;
	conf.session_window =
		0; /* auto: enforce floor (covers the floor branch) */
	conf.stream_window = 4; /* manual */
	conf.timeout = 0; /* established: stop w_timeout */
	conf.keepalive = 0; /* established: stop w_keepalive */
	conf.send_timeout =
		5; /* AF_UNIX: TCP_USER_TIMEOUT fails, repeat kept */
	conf.connect_timeout = 5;
	conf.idle_timeout = 5;
	session_set_config(&fx.ss, &conf);

	T_EXPECT(
		fx.ss.session_window >=
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT);

	ev_timer_stop(fx.ss.loop, &fx.ss.w_send_timeout);
	ev_timer_stop(fx.ss.loop, &fx.ss.w_connect_timeout);
	ev_timer_stop(fx.ss.loop, &fx.ss.w_idle_timeout);
	teardown_fixture(&fx);
}

/* session_start aborts and resets when the TLS layer fails to start. */
T_DECLARE_CASE(test_session_start_tls_failed)
{
#if WITH_TLS
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_INIT;
	g_wire_tls_start_result = false;
	session_start(&fx.ss);
	g_wire_tls_start_result = true;
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	fx.fds[0] = -1;
	teardown_fixture(&fx);
#else
	T_SKIP();
#endif /* WITH_TLS */
}

/* session_handshake_done: pending egress arms tx_pending; a drain request with
 * no active streams initiates an immediate graceful shutdown. */
T_DECLARE_CASE(test_handshake_done_sched_head_and_drain)
{
	{
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		struct mux_stream s = { .id = 1 };
		fx.ss.sched.sched_head = &s;
		session_handshake_done(&fx.ss);
		T_EXPECT(fx.ss.wire.tx_pending);
		fx.ss.sched.sched_head = NULL;
		teardown_fixture(&fx);
	}
	{
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.draining =
			true; /* no active streams -> graceful shutdown */
		session_handshake_done(&fx.ss);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSING);
		teardown_fixture(&fx);
	}
}

static const struct testing_suite suite[] = {
	T_CASE(test_session_handshake_done_rearms_coalesce_for_delay_list),
	T_CASE(test_session_handshake_done_rearms_coalesce_for_ack_backlog),
	T_CASE(test_session_handshake_done_no_coalesce_without_backlog),
	T_CASE(test_session_initiate_shutdown_transitions_to_closed),
	T_CASE(test_session_drain_sets_draining_flag),
	T_CASE(test_socket_user_timeout_sets_option),
	T_CASE(test_session_log_frame_header_formats_flags),
	T_CASE(test_closing_cb_pending_then_error),
	T_CASE(test_close_wait_cb_unexpected),
	T_CASE(test_connect_cb_tls_paths),
	T_CASE(test_dead_link_suspend_for_resume),
	T_CASE(test_dead_link_close_without_session_id),
	T_CASE(test_timeout_and_send_timeout_callbacks),
	T_CASE(test_keepalive_cb_emits_and_rearms),
	T_CASE(test_connect_timeout_cb_states),
	T_CASE(test_open_stream_rejections),
	T_CASE(test_set_config_live_session_branches),
	T_CASE(test_session_start_tls_failed),
	T_CASE(test_handshake_done_sched_head_and_drain),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	slog_level_ = LOG_LEVEL_VERYVERBOSE;

	return testing_main(argc, argv, suite);
}
