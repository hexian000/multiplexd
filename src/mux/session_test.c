/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* session_test.c - white-box tests for session.c (lifecycle: handshake-done
 * re-arming, graceful/forced shutdown, drain, socket-option helper);
 * session.c #included; all sibling-module collaborators mocked below. */

#include "mux/session.h"

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/recv.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/session.c"
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Configurable mock results: each test sets these before driving the code under
 * test, then restores the inert default.  Declared here so the mock bodies
 * below can read them. */
static bool g_session_send_oob_result = true;
static int g_session_send_oob_calls;
static uint_fast8_t g_last_send_oob_extra;
static enum wire_shutdown_state g_wire_shutdown_result = WIRE_SHUTDOWN_DONE;
static enum wire_eof_result g_wire_wait_eof_result = WIRE_EOF_CONFIRMED;
static bool g_wire_tls_start_result = true;
static uint_least16_t g_alloc_stream_id_result = STREAMID_CTRL;
static struct mux_stream *g_stream_new_result = NULL;
static bool g_sched_add_stream_result = true;

/* mock - collaborator stubs for session.c's sibling-module calls; most are
 * inert, a few reproduce minimal behavior for lifecycle decisions under test
 * (e.g. mux_sched_coalesce_arm actually arms the timer). */

static void st_coalesce_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

void mux_sched_init(struct mux_session *restrict ss)
{
	ev_timer_init(&ss->sched.w_coalesce, st_coalesce_cb, 0.0, 1.0);
	ss->sched.w_coalesce.data = ss;
}

void mux_sched_coalesce_arm(struct mux_session *restrict ss)
{
	if (!ev_is_active(&ss->sched.w_coalesce)) {
		ev_timer_start(ss->loop, &ss->sched.w_coalesce);
	}
}

void mux_sched_schedule(struct mux_session *restrict ss)
{
	(void)ss;
}

void mux_sched_wake(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	(void)ss;
	(void)s;
}

bool mux_sched_add_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	(void)ss;
	(void)s;
	return g_sched_add_stream_result;
}

uint_least16_t mux_sched_alloc_stream_id(struct mux_session *restrict ss)
{
	(void)ss;
	return g_alloc_stream_id_result;
}

void mux_sched_free_streams(struct mux_session *restrict ss)
{
	ss->sched.sched_head = NULL;
	ss->sched.sched_tail = NULL;
	ss->sched.drr_active = NULL;
	ss->sched.lp_head = NULL;
	ss->sched.lp_tail = NULL;
	ss->sched.delay_head = NULL;
	ss->sched.num_tombstones = 0;
	ss->sched.next_stream_id = 0;
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
}

/* Mirror the real sched.c helper (mux_session_initiate_shutdown is the linked
 * session.c one) so the handshake_done drain/idle-arm cases keep observing its
 * effect without pulling in the rest of sched.c. */
void mux_sched_check_no_active_streams(struct mux_session *restrict ss)
{
	if (table_size(ss->sched.streams) != ss->sched.num_tombstones) {
		return;
	}
	if (ss->state != SESSION_ESTABLISHED) {
		return;
	}
	if (ss->draining) {
		mux_session_initiate_shutdown(ss);
		return;
	}
	if (!ss->accepted && ss->conf.idle_timeout > 0) {
		ev_timer_again(ss->loop, &ss->w_idle_timeout);
	}
}

void mux_wire_discard_buffers(struct mux_session *restrict ss)
{
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	ss->wire.sendbuf_staging = false;
	if (ss->wire.recvbuf != NULL) {
		bytebuf_reset(ss->wire.recvbuf);
	}
}

void mux_unacked_free_all(struct mux_session *restrict ss)
{
	mux_frame_ring_free(&ss->unacked.ring, &ss->pool);
	ss->unacked.frames = 0;
	ss->unacked.bytes = 0;
	ss->unacked.partial_offset = 0;
	ss->unacked.retransmit_off = SIZE_MAX;
	/* The real one owns clearing these two (unacked.c); session_cleanup and
	 * mux_session_initiate_shutdown rely on it rather than doing it themselves, so
	 * a double that skipped them would model the pre-fix contract. */
	ss->unacked.retransmit_copy = NULL;
	ss->unacked.stalled = false;
}

void mux_wire_conn_free(struct mux_session *restrict ss)
{
	(void)ss;
}

/* Inert sibling entry points: not exercised by the lifecycle cases below. */

void mux_estimator_init(struct mux_session *restrict ss, size_t bdp)
{
	(void)ss;
	(void)bdp;
}

static int g_estimator_suspend_calls = 0;

void mux_estimator_suspend(struct mux_session *restrict ss)
{
	(void)ss;
	g_estimator_suspend_calls++;
}

size_t mux_estimator_rx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return 0;
}

bool mux_handshake_enqueue_hello(
	struct mux_session *ss, int msgid, bool include_resume_seq)
{
	(void)ss;
	(void)msgid;
	(void)include_resume_seq;
	return true;
}

void mux_session_flush_oob(struct mux_session *restrict ss)
{
	(void)ss;
}

void mux_session_on_recv(struct mux_session *restrict ss)
{
	(void)ss;
}

void mux_session_on_send(struct mux_session *restrict ss)
{
	(void)ss;
}

bool mux_session_send_oob(
	struct mux_session *restrict ss, uint_fast8_t extra,
	const unsigned char *restrict payload, size_t payload_len)
{
	(void)ss;
	(void)payload;
	(void)payload_len;
	g_session_send_oob_calls++;
	g_last_send_oob_extra = extra;
	return g_session_send_oob_result;
}

struct mux_stream *mux_stream_new(
	struct mux_session *restrict ss, uint_fast16_t id, bool active_open)
{
	(void)ss;
	(void)id;
	(void)active_open;
	return g_stream_new_result;
}

void mux_stream_free(struct mux_stream *s)
{
	(void)s;
}

bool mux_unacked_resume_ack_recv(
	struct mux_session *restrict ss, uint_least32_t peer_ack)
{
	(void)ss;
	(void)peer_ack;
	return true;
}

static int g_unacked_track_sent_calls = 0;
static const struct mux_frame *g_last_track_sent_frame;

void mux_unacked_track_sent(
	struct mux_session *restrict ss, struct mux_frame *restrict frame)
{
	/* Real mux_unacked_track_sent takes ownership; reclaim here to avoid leaks
	 * when a test routes a captured sendbuf frame through this path. Record
	 * the frame: the count alone cannot tell which one was tracked. */
	g_unacked_track_sent_calls++;
	g_last_track_sent_frame = frame;
	mux_frame_put(&ss->pool, frame);
}

void mux_wire_adopt_tlsconn(
	struct mux_session *restrict ss, struct tls_connection *restrict conn)
{
	(void)ss;
	(void)conn;
}

void mux_wire_tlsconn_free(struct tls_connection *restrict conn)
{
	(void)conn;
}

enum wire_shutdown_state mux_wire_shutdown(struct mux_session *restrict ss)
{
	(void)ss;
	return g_wire_shutdown_result;
}

void mux_wire_tls_log_status(struct mux_session *restrict ss)
{
	(void)ss;
}

bool mux_wire_tls_start(struct mux_session *restrict ss)
{
	(void)ss;
	return g_wire_tls_start_result;
}

enum wire_eof_result mux_wire_wait_eof(struct mux_session *restrict ss)
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

static int g_closed_event_count = 0;
static bool g_last_closed_clean;
static int g_last_closed_err;

static void session_test_on_event(
	void *data, struct mux_session *ss, const enum mux_event event,
	const union mux_event_data edata)
{
	(void)data;
	(void)ss;
	if (event == MUX_EVENT_CLOSED) {
		g_closed_event_count++;
		g_last_closed_clean = edata.closed.clean;
		g_last_closed_err = edata.closed.err;
	}
}

/* fd used by session_test_on_event_reentrant_reconnect's nested
 * mux_session_attach_fd() call, and counters for the events it observes. */
static int g_reentrant_attach_fd = -1;
static int g_suspended_event_count = 0;
static int g_connect_event_count = 0;

/* Mimics tunnel_on_event reconnecting synchronously on MUX_EVENT_SUSPENDED
 * (handle_transport_lost -> tunnel_do_connect): reenters mux_session_attach_fd
 * from inside mux_session_suspend's own emit; only on the first SUSPENDED. */
static void session_test_on_event_reentrant_reconnect(
	void *data, struct mux_session *ss, const enum mux_event event,
	const union mux_event_data edata)
{
	(void)data;
	(void)edata;
	switch (event) {
	case MUX_EVENT_SUSPENDED:
		g_suspended_event_count++;
		if (g_suspended_event_count == 1) {
			mux_session_attach_fd(ss, g_reentrant_attach_fd);
		}
		break;
	case MUX_EVENT_CONNECT:
		g_connect_event_count++;
		break;
	case MUX_EVENT_CLOSED:
		g_closed_event_count++;
		break;
	default:
		break;
	}
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
		.max_payload = (uint_least32_t)mux_session_config_default.max_frame_payload,
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
	mux_sched_init(&fx->ss);
	fx->ss.wire.recvbuf = bytebuf_new(4u * (size_t)MUX_MAX_FRAME_SIZE);
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
		bytebuf_free(fx->ss.wire.recvbuf);
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
	/* mux_session_handshake_done calls ev_timer_stop(&w_connect_timeout) and
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
		mux_sched_free_streams(&fx->ss);
	}
	if (fx->ss.wire.oobbuf.head != NULL ||
	    bytebuf_readable(fx->ss.wire.recvbuf) > 0 ||
	    fx->ss.wire.sendbuf.head != NULL) {
		mux_wire_discard_buffers(&fx->ss);
	}
	bytebuf_free(fx->ss.wire.recvbuf);
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

	mux_session_handshake_done(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_ESTABLISHED);
	T_EXPECT(ev_is_active(&fx.ss.sched.w_coalesce));

	/* Remove the on-stack stream from the delay list before teardown. */
	fx.ss.sched.delay_head = NULL;
	teardown_fixture(&fx);
}

/* Regression: after mux_session_handshake_done, w_coalesce must be re-armed when
 * unreported > 0 (session-level ACK backlog preserved across the transport
 * break), even when the delay list is empty. */
T_DECLARE_CASE(test_session_handshake_done_rearms_coalesce_for_ack_backlog)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}

	fx.ss.unacked.unreported = 2;
	T_EXPECT(!ev_is_active(&fx.ss.sched.w_coalesce));

	mux_session_handshake_done(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_ESTABLISHED);
	T_EXPECT(ev_is_active(&fx.ss.sched.w_coalesce));

	teardown_fixture(&fx);
}

/* Regression: after mux_session_handshake_done on a fresh establish (no backlog),
 * w_coalesce must NOT be started. */
T_DECLARE_CASE(test_session_handshake_done_no_coalesce_without_backlog)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}

	/* No delay_head and unreported == 0: no backlog. */
	T_EXPECT(!ev_is_active(&fx.ss.sched.w_coalesce));

	mux_session_handshake_done(&fx.ss);

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
	mux_session_initiate_shutdown(&fx.ss);
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* The force-close path must apply the same peer_addr/num_halfopen reset as
 * mux_session_reset() for an outbound session, not just transition the state. */
T_DECLARE_CASE(test_session_initiate_shutdown_force_close_resets_outbound_state)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	fx.ss.state = SESSION_INIT;
	fx.ss.accepted = false;
	fx.ss.peer_addr.sa.sa_family = AF_INET;
	fx.ss.num_halfopen = 3;

	mux_session_initiate_shutdown(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	T_EXPECT_EQ(fx.ss.peer_addr.sa.sa_family, (sa_family_t)AF_UNSPEC);
	T_EXPECT_EQ(fx.ss.num_halfopen, (size_t)0);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* The force-close branch must not re-emit MUX_EVENT_CLOSED for a session that is
 * already CLOSED (reachable when the async shutdown task runs after the session
 * independently closed); mux_session_notify_closed's was_closed guard suppresses it. */
T_DECLARE_CASE(test_session_initiate_shutdown_no_reemit_when_closed)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	/* Drive to CLOSED first (session_cleanup closes w_socket.fd). */
	fx.ss.state = SESSION_INIT;
	mux_session_reset(&fx.ss);
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	fx.ss.callbacks.on_event = session_test_on_event;
	g_closed_event_count = 0;

	mux_session_initiate_shutdown(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	T_EXPECT_EQ(g_closed_event_count, 0);

	fx.ss.callbacks.on_event = NULL;
	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* A config reload while SUSPENDED must not disturb w_connect_timeout, which is
 * repurposed as the one-shot resume deadline (repeat 0.0, armed by
 * mux_session_suspend). The unguarded old code reset repeat to connect_timeout and
 * would restart or (with connect_timeout == 0) cancel the resume deadline. */
T_DECLARE_CASE(test_session_set_config_preserves_suspended_resume_deadline)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_SUSPENDED;
	/* Arm w_connect_timeout as mux_session_suspend does: one-shot at the resume
	 * deadline (repeat 0.0). */
	ev_timer_init(
		&fx.ss.w_connect_timeout, session_test_timer_cb, 0.0, 0.0);
	fx.ss.w_connect_timeout.data = &fx.ss;
	ev_timer_set(&fx.ss.w_connect_timeout, 30.0, 0.0);
	ev_timer_start(fx.ss.loop, &fx.ss.w_connect_timeout);

	const struct mux_session_config conf = {
		.timeout = 30,
		.keepalive = 15,
		.send_timeout = 10,
		.connect_timeout = 10, /* differs from the resume deadline */
		.resume_timeout = 30,
	};
	mux_session_set_config(&fx.ss, &conf);

	/* Untouched: still a one-shot (repeat 0.0) and still active. */
	T_EXPECT_EQ(fx.ss.w_connect_timeout.repeat, 0.0);
	T_EXPECT(ev_is_active(&fx.ss.w_connect_timeout));

	ev_timer_stop(fx.ss.loop, &fx.ss.w_connect_timeout);
	teardown_fixture(&fx);
}

/* A config reload during a graceful close (CLOSING or CLOSE_WAIT) must not
 * disturb w_connect_timeout, repurposed as the one-shot close deadline (repeat
 * 0.0, armed by mux_session_initiate_shutdown and left running across the
 * CLOSING->CLOSE_WAIT transition). The old guard skipped only SUSPENDED, so a
 * reload here ran ev_timer_again with repeat = connect_timeout: a schema-legal
 * connect_timeout of 0 stops the timer, cancelling the close watchdog so a peer
 * that never finishes the close handshake wedges the session in CLOSING/
 * CLOSE_WAIT forever (never freed); a nonzero value turns the one-shot into a
 * periodic timer and resets the elapsed deadline. Covers both states and both
 * reload values. */
T_DECLARE_CASE(test_session_set_config_preserves_graceful_close_deadline)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	const enum session_state states[2] = { SESSION_CLOSING,
					       SESSION_CLOSE_WAIT };
	/* 0 = disabled (old code stopped the timer); 5 = enabled (old code
	 * turned the one-shot periodic and reset the deadline). */
	const int timeouts[2] = { 0, 5 };
	enum { NCASES = 4 };
	bool active[NCASES];
	double repeat[NCASES];
	size_t k = 0;
	for (size_t i = 0; i < 2; i++) {
		for (size_t j = 0; j < 2; j++) {
			fx.ss.state = states[i];
			/* Arm as mux_session_initiate_shutdown does: a one-shot at
			 * the close deadline (repeat 0.0). */
			ev_timer_init(
				&fx.ss.w_connect_timeout, session_test_timer_cb,
				0.0, 0.0);
			fx.ss.w_connect_timeout.data = &fx.ss;
			ev_timer_set(&fx.ss.w_connect_timeout, 30.0, 0.0);
			ev_timer_start(fx.ss.loop, &fx.ss.w_connect_timeout);

			const struct mux_session_config conf = {
				.timeout = 30,
				.keepalive = 15,
				.send_timeout = 10,
				.connect_timeout = timeouts[j],
				.resume_timeout = 30,
			};
			mux_session_set_config(&fx.ss, &conf);

			active[k] = ev_is_active(&fx.ss.w_connect_timeout);
			repeat[k] = fx.ss.w_connect_timeout.repeat;
			k++;
			ev_timer_stop(fx.ss.loop, &fx.ss.w_connect_timeout);
		}
	}
	teardown_fixture(&fx);

	/* In every case the close deadline is untouched: still armed (not
	 * cancelled) and still a one-shot (repeat 0.0, not turned periodic). */
	for (size_t i = 0; i < NCASES; i++) {
		T_EXPECT(active[i]);
		T_EXPECT_EQ(repeat[i], 0.0);
	}
}

/* connect_timeout == 0 means disabled. The graceful-shutdown path's
 * close-deadline arm is ev_timer_set+ev_timer_start with an explicit at-delay,
 * not ev_timer_again -- an unconditional arm with at=0 would fire immediately
 * (the opposite of "never") instead of not arming at all. */
T_DECLARE_CASE(test_session_initiate_shutdown_skips_close_deadline_when_disabled)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.conf.connect_timeout = 0;

	mux_session_initiate_shutdown(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSING);
	T_EXPECT(!ev_is_active(&fx.ss.w_connect_timeout));

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_drain_sets_draining_flag)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	/* Use SESSION_INIT so that mux_session_drain does not trigger an
	 * immediate mux_session_initiate_shutdown (which would require timer
	 * initialisation and leave the session CLOSED). */
	fx.ss.state = SESSION_INIT;
	mux_session_drain(&fx.ss);
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
#else /* WITH_TCP_USER_TIMEOUT */
	/* Platform lacks TCP_USER_TIMEOUT; function must return -1. */
	T_EXPECT_EQ(socket_user_timeout(fd, 5000), -1);
#endif /* WITH_TCP_USER_TIMEOUT */
	(void)close(fd);
}

/* mux_session_log_frame_header / format_frame_flags: VERYVERBOSE-gated diagnostic.
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
	mux_session_log_frame_header(&fx.ss, "all-flags", raw, &hdr);
	/* Known flag plus unknown bits: exercises the UNKNOWN(...) branch. */
	hdr.flags = MUX_FLAG_SYN | (uint_least8_t)(~MUX_FLAG_MASK);
	mux_session_log_frame_header(&fx.ss, "unknown", raw, &hdr);
	/* No flags: exercises the NONE branch. */
	hdr.flags = 0;
	mux_session_log_frame_header(&fx.ss, "none", raw, &hdr);

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

/* close_wait_cb logs and resets when mux_wire_wait_eof reports unexpected state. */
T_DECLARE_CASE(test_close_wait_cb_unexpected)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_CLOSE_WAIT;

	g_wire_wait_eof_result = WIRE_EOF_ERROR;
	close_wait_cb(&fx.ss);
	g_wire_wait_eof_result = WIRE_EOF_CONFIRMED;
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* MUX_EVENT_CLOSED's `clean` flag means "peer FIN or TLS close_notify". On a
 * locally-initiated graceful close, close_wait_cb's WIRE_EOF_CONFIRMED arm is
 * the only place that observation is made, so a completed close handshake must
 * report clean -- it reported false for every such close before. */
T_DECLARE_CASE(test_close_wait_cb_confirmed_reports_clean)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_CLOSE_WAIT;
	fx.ss.wire.rx_eof =
		false; /* locally-initiated close: no inbound EOF yet */
	fx.ss.callbacks.on_event = session_test_on_event;
	g_closed_event_count = 0;
	g_last_closed_clean = false;

	g_wire_wait_eof_result = WIRE_EOF_CONFIRMED;
	/* Drive the ev_io callback, not close_wait_cb directly: socket_cb is
	 * where the CLOSED event is emitted from wire.rx_eof. */
	fx.ss.w_socket.data = &fx.ss;
	socket_cb(fx.ss.loop, &fx.ss.w_socket, EV_READ);

	const int closed_events = g_closed_event_count;
	const bool clean = g_last_closed_clean;
	fx.ss.callbacks.on_event = NULL;

	fx.fds[0] = -1;
	teardown_fixture(&fx);

	T_EXPECT_EQ(closed_events, 1);
	T_EXPECT(clean);
}

/* WIRE_EOF_PENDING (a spurious wakeup with nothing confirmed yet, e.g. EAGAIN)
 * is a distinct outcome from WIRE_EOF_CONFIRMED and WIRE_EOF_ERROR, newly
 * reachable now that mux_wire_wait_eof no longer conflates it into a single
 * boolean. Teardown still runs unconditionally either way -- CLOSE_WAIT's own
 * close-timeout watchdog is what actually backstops a peer that never confirms
 * -- so this only exercises that the new state is reachable and handled, not a
 * change in when mux_session_reset runs. */
T_DECLARE_CASE(test_close_wait_cb_pending)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_CLOSE_WAIT;

	g_wire_wait_eof_result = WIRE_EOF_PENDING;
	close_wait_cb(&fx.ss);
	g_wire_wait_eof_result = WIRE_EOF_CONFIRMED;
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
		connect_cb(&fx.ss);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_HANDSHAKE);
		teardown_fixture(&fx);
	}
#else /* WITH_TLS */
	T_SKIP();
#endif /* WITH_TLS */
}

/* A connect that fails after the SYN is out reports its errno only through
 * SO_ERROR at connect completion; connect_cb used to log it and drop it, so the
 * CLOSED event told the owner nothing about why the transport never came up and
 * its reconnect policy could not tell an unreachable path from a peer that
 * declined.  Drive socket_cb (where the CLOSED emit lives) over a non-socket
 * fd: getsockopt(SO_ERROR) fails on one, so socket_get_error reports a
 * deterministic ENOTSOCK in place of a routing-dependent errno. */
T_DECLARE_CASE(test_connect_cb_reports_socket_error_on_closed)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	int pipefd[2];
	if (pipe(pipefd) != 0) {
		teardown_fixture(&fx);
		T_FATAL("pipe failed");
		return;
	}
	fx.ss.state = SESSION_CONNECT;
	ev_io_set(&fx.ss.w_socket, pipefd[0], EV_READ);
	fx.ss.callbacks.on_event = session_test_on_event;
	g_closed_event_count = 0;
	g_last_closed_err = 0;

	socket_cb(fx.ss.loop, &fx.ss.w_socket, EV_WRITE);

	const int recorded = fx.ss.wire.err;
	const int closed_events = g_closed_event_count;
	const int reported = g_last_closed_err;
	const enum session_state state = fx.ss.state;
	fx.ss.callbacks.on_event = NULL;

	/* mux_session_reset closed pipefd[0] with the rest of the transport. */
	(void)close(pipefd[1]);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum session_state)SESSION_CLOSED);
	T_EXPECT_EQ(closed_events, 1);
	/* Kept on the session... */
	T_EXPECT_EQ(recorded, ENOTSOCK);
	/* ...and handed to the owner with the close. */
	T_EXPECT_EQ(reported, ENOTSOCK);
}

/* A stale transport errno must not outlive its transport: every attach clears
 * it, or the next close of a session that dialed successfully would report the
 * previous attempt's failure and mis-pace the retry after it. */
T_DECLARE_CASE(test_attach_fd_clears_stale_transport_error)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		teardown_fixture(&fx);
		T_FATAL("socketpair failed");
		return;
	}
	fx.ss.state = SESSION_CLOSED;
	fx.ss.wire.err = EHOSTUNREACH;

	mux_session_attach_fd(&fx.ss, fds[0]);

	const int after_attach = fx.ss.wire.err;
	const union mux_event_data data = session_closed_data(&fx.ss, false);

	(void)close(fds[1]);
	teardown_fixture(&fx);

	T_EXPECT_EQ(after_attach, 0);
	T_EXPECT_EQ(data.closed.err, 0);
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
	g_unacked_track_sent_calls = 0;
	g_last_track_sent_frame = NULL;
	const int frees_before = fx.pool_ctx.free_calls;

	session_on_dead_link(&fx.ss, "send timeout");
	const int track_calls = g_unacked_track_sent_calls;
	const struct mux_frame *const tracked_frame = g_last_track_sent_frame;
	const int frees_after = fx.pool_ctx.free_calls;

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_SUSPENDED);
	/* Only `tracked` enters the resume ring: `copy` is already the replay
	 * copy, so re-tracking it would double-enter it. */
	T_EXPECT_EQ(track_calls, 1);
	T_EXPECT(tracked_frame == tracked);
	/* Both frames released exactly once -- `copy` straight back to the pool,
	 * `tracked` through the mock that stands in for the ring. */
	T_EXPECT_EQ(frees_after - frees_before, 2);

	fx.fds[0] = -1; /* mux_session_suspend closed it */
	teardown_fixture(&fx);
}

/* mux_unacked_track_sent (via unacked_push) can itself reset ss on a ring-push
 * OOM; session_capture_frame_list must stop feeding it further frames once
 * that happens instead of resurrecting the ring it just freed (or, on a
 * multi-frame capture, injecting a stale frame into a later session). A real
 * ring-push OOM isn't reliably injectable in this project's test style
 * (matching unacked_test.c's own documented constraint on this ring), so
 * this drives the same guard via the mocked mux_unacked_track_sent above:
 * simulating "closed underneath us" directly and checking the mock is
 * never called for a frame captured after that point. */
T_DECLARE_CASE(test_capture_frame_list_skips_frames_once_session_closed)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_frame *const frame =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_CHECK(frame != NULL);
	mux_write_header(
		frame->data,
		&(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
				      .stream_id = 33 });
	frame->len = MUX_FRAME_HEADER_SIZE;
	mux_frame_list_push(&fx.ss.wire.sendbuf, frame);

	g_unacked_track_sent_calls = 0;
	fx.ss.state = SESSION_CLOSED;
	session_capture_sendbuf(&fx.ss);

	T_EXPECT(fx.ss.wire.sendbuf.head == NULL);
	T_EXPECT_EQ(g_unacked_track_sent_calls, 0);

	fx.fds[0] = -1;
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

/* mux_session_reset on a client (!accepted) session must clear has_session_id,
 * mirroring send.c's send_handle_rx_closed. A full reset destroys streams and
 * the unacked ring, so there is nothing left locally to resume; leaving
 * has_session_id set would make the next connect attempt request resume with a
 * stale id, which a still-suspended server session could accept as a ghost
 * resume. */
T_DECLARE_CASE(test_session_reset_clears_has_session_id_for_client)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;

	mux_session_reset(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	T_EXPECT(!fx.ss.handshake.has_session_id);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* mux_session_reset on a server (accepted) session must leave has_session_id
 * alone: the client, not this struct, decides whether to request resume
 * on its own next connect. */
T_DECLARE_CASE(test_session_reset_preserves_has_session_id_for_server)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.accepted = true;
	fx.ss.handshake.has_session_id = true;

	mux_session_reset(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	T_EXPECT(fx.ss.handshake.has_session_id);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* mux_session_notify_closed on an already-CLOSED session (mux_session_reset is a
 * documented no-op there) must not re-emit MUX_EVENT_CLOSED: the event
 * signals a real transition, and a spurious repeat would make
 * tunnel_on_event's handle_closed double-schedule a reconnect. Exercises
 * the same no-op path mux_session_attach_fd's reconnect-retry OOM branch
 * hits when a dialed session is already closed. */
T_DECLARE_CASE(test_notify_closed_on_already_closed_session_does_not_reemit)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.callbacks.on_event = session_test_on_event;
	g_closed_event_count = 0;

	fx.ss.state = SESSION_CLOSED;
	mux_session_notify_closed(&fx.ss, false);
	T_EXPECT_EQ(g_closed_event_count, 0);

	/* Contrast: a real ESTABLISHED -> CLOSED transition must still emit. */
	fx.ss.state = SESSION_ESTABLISHED;
	mux_session_notify_closed(&fx.ss, false);
	T_EXPECT_EQ(g_closed_event_count, 1);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* Leaving ESTABLISHED must clear the estimator's in-flight probe/sample
 * state, else a stale pre-outage byte count could pair with a post-resume
 * RTT and produce a bogus bandwidth sample. */
T_DECLARE_CASE(test_established_exit_suspends_estimator)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.handshake.has_session_id = false;

	g_estimator_suspend_calls = 0;
	session_on_dead_link(&fx.ss, "send timeout");
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	T_EXPECT_EQ(g_estimator_suspend_calls, 1);

	fx.fds[0] = -1;
	teardown_fixture(&fx);
}

/* Leaving ESTABLISHED must stop w_idle_timeout together with the other liveness
 * timers.  Regression: send.c's send_handle_rx_closed moves ESTABLISHED ->
 * CLOSING directly and stops nothing itself, so a still-armed idle deadline
 * firing in CLOSING would abort() on idle_cb's ESTABLISHED precondition. */
T_DECLARE_CASE(test_established_exit_stops_idle_timeout)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	ev_timer_start(fx.ss.loop, &fx.ss.w_idle_timeout);
	const bool idle_armed_before = ev_is_active(&fx.ss.w_idle_timeout);

	/* CLOSING keeps the socket, so the fd is not closed here; teardown owns it. */
	mux_session_set_state(&fx.ss, SESSION_CLOSING);

	const bool state_closing = (fx.ss.state == SESSION_CLOSING);
	const bool idle_active_after = ev_is_active(&fx.ss.w_idle_timeout);
	teardown_fixture(&fx);
	T_EXPECT(idle_armed_before);
	T_EXPECT(state_closing);
	T_EXPECT(!idle_active_after);
}

/* session_reset_stream_window_floor re-probes only in auto mode: a manually
 * configured mux.stream_window must survive an ESTABLISHED exit unchanged (only
 * mux_session_set_config, which runs on reload, would ever restore it), while an
 * auto window is floored back down.  mux_estimator_rx_window_size is mocked to 0
 * here, so the auto floor is exactly MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT. */
T_DECLARE_CASE(test_established_exit_stream_window_floor_respects_mode)
{
	const uint_least32_t floor_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	/* Manual mode: the configured value is preserved. */
	{
		struct session_fixture fx;
		if (setup_fixture(&fx) != 0) {
			T_FATAL("setup_fixture failed");
			return;
		}
		fx.ss.state = SESSION_ESTABLISHED;
		fx.ss.auto_stream_window = false;
		session_set_stream_window(&fx.ss, floor_frames + 100u);
		mux_session_set_state(&fx.ss, SESSION_CLOSING);
		const uint_least32_t window_after = fx.ss.stream_window;
		teardown_fixture(&fx);
		T_EXPECT_EQ(window_after, floor_frames + 100u);
	}
	/* Auto mode: the window is re-floored on exit. */
	{
		struct session_fixture fx;
		if (setup_fixture(&fx) != 0) {
			T_FATAL("setup_fixture failed");
			return;
		}
		fx.ss.state = SESSION_ESTABLISHED;
		fx.ss.auto_stream_window = true;
		session_set_stream_window(&fx.ss, floor_frames + 100u);
		mux_session_set_state(&fx.ss, SESSION_CLOSING);
		const uint_least32_t window_after = fx.ss.stream_window;
		teardown_fixture(&fx);
		T_EXPECT_EQ(window_after, floor_frames);
	}
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
	/* mux_keepalive_interval jitters the base down by up to
	 * MUX_KEEPALIVE_JITTER, so the re-armed period is bounded, not exact. */
	const double lo = 5.0 * (1.0 - MUX_KEEPALIVE_JITTER);
	g_session_send_oob_calls = 0;

	g_session_send_oob_result = false; /* exhausted-pool skip branch */
	keepalive_cb(fx.ss.loop, &fx.ss.w_keepalive, EV_TIMER);
	const int calls_after_skip = g_session_send_oob_calls;
	const bool armed_after_skip = ev_is_active(&fx.ss.w_keepalive);
	const double repeat_after_skip = fx.ss.w_keepalive.repeat;

	g_session_send_oob_result = true; /* normal PROBE branch */
	keepalive_cb(fx.ss.loop, &fx.ss.w_keepalive, EV_TIMER);
	const int calls_after_probe = g_session_send_oob_calls;
	const uint_fast8_t probe_extra = g_last_send_oob_extra;
	const bool armed_after_probe = ev_is_active(&fx.ss.w_keepalive);
	const double repeat_after_probe = fx.ss.w_keepalive.repeat;

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_ESTABLISHED);
	/* A PROBE is emitted on both branches; only the pool result differs. */
	T_EXPECT_EQ(calls_after_skip, 1);
	T_EXPECT_EQ(calls_after_probe, 2);
	T_EXPECT_EQ(probe_extra, (uint_fast8_t)MUX_CTRL_PROBE);
	/* Re-armed for the next cycle on both branches -- a skipped PROBE must
	 * not stop keepalive. */
	T_EXPECT(armed_after_skip);
	T_EXPECT(armed_after_probe);
	T_EXPECT(repeat_after_skip > lo && repeat_after_skip <= 5.0);
	T_EXPECT(repeat_after_probe > lo && repeat_after_probe <= 5.0);

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
	{
		/* A resumable (has_session_id, dialed) session whose resume
		 * attempt is merely slow -- not dead -- must suspend rather
		 * than being destroyed, mirroring session_on_dead_link() and
		 * the send.c I/O-error paths for the same HANDSHAKE state. */
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.accepted = false;
		fx.ss.handshake.has_session_id = true;
		connect_timeout_cb(
			fx.ss.loop, &fx.ss.w_connect_timeout, EV_TIMER);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_SUSPENDED);
		teardown_fixture(&fx);
	}
	{
		/* mux_session_suspend()'s own precondition excludes SESSION_CONNECT
		 * (transport not up yet), so a resumable session timing out
		 * there must still fall through to the ordinary close path,
		 * not attempt to suspend. */
		struct session_fixture fx;
		if (setup_handshake_fixture(&fx) != 0) {
			T_FATAL("setup_handshake_fixture failed");
			return;
		}
		fx.ss.state = SESSION_CONNECT;
		fx.ss.accepted = false;
		fx.ss.handshake.has_session_id = true;
		connect_timeout_cb(
			fx.ss.loop, &fx.ss.w_connect_timeout, EV_TIMER);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
		fx.fds[0] = -1;
		teardown_fixture(&fx);
	}
}

/* mux_session_suspend() must pay back the num_session_halfopen increment when
 * suspending out of SESSION_HANDSHAKE, since mux_session_set_state()'s own
 * accounting deliberately excludes SUSPENDED from that payback (a suspended
 * resume attempt is still "pending") -- and if this session is later torn
 * down straight from SUSPENDED, oldstate is SUSPENDED then too, so nothing
 * else pays the debt. */
T_DECLARE_CASE(test_session_suspend_pays_back_halfopen_from_handshake)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	/* num_session_halfopen is a mux_gauge* (atomic_size_t), not mux_counter*;
	 * declare the backing storage with the matching type. */
	mux_gauge halfopen = 1; /* simulates the earlier CONNECT-entry +1 */
	fx.ss.cnt.session.num_session_halfopen = &halfopen;
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;

	mux_session_suspend(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_SUSPENDED);
	const uint_least64_t halfopen_after = halfopen;
	T_EXPECT_EQ(halfopen_after, (uint_least64_t)0);

	fx.fds[0] = -1; /* mux_session_suspend closed it */
	teardown_fixture(&fx);
}

/* resume_timeout == 0 means disabled (held suspended indefinitely). The
 * resume-deadline arm is ev_timer_set+ev_timer_start with an explicit at-delay,
 * not ev_timer_again -- an unconditional arm with at=0 would fire immediately
 * (the opposite of "never") instead of not arming at all. */
T_DECLARE_CASE(test_session_suspend_skips_resume_deadline_when_disabled)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;
	fx.ss.conf.resume_timeout = 0;

	mux_session_suspend(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_SUSPENDED);
	T_EXPECT(!ev_is_active(&fx.ss.w_connect_timeout));

	fx.fds[0] = -1; /* mux_session_suspend closed it */
	teardown_fixture(&fx);
}

/* A real-stream-id control frame mux_session_send_ctrl deferred in wire.oobbuf
 * behind an in-progress replay must survive a second suspend intervening before
 * it flushes — migrated into the resume log via mux_unacked_track_sent, not
 * silently freed like genuine OOB traffic (PING/PONG/PROBE) still is. */
T_DECLARE_CASE(test_session_suspend_migrates_pending_oobbuf_frame)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_frame *const deferred =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_CHECK(deferred != NULL);
	mux_write_header(
		deferred->data,
		&(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
				      .flags = MUX_FLAG_RST,
				      .stream_id = 33 });
	deferred->len = MUX_FRAME_HEADER_SIZE;
	mux_frame_list_push(&fx.ss.wire.oobbuf, deferred);

	g_unacked_track_sent_calls = 0;
	mux_session_suspend(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_SUSPENDED);
	T_EXPECT(fx.ss.wire.oobbuf.head == NULL);
	/* The mock frees the frame it receives, so a leak-free teardown below
	 * is itself proof the deferred frame reached mux_unacked_track_sent rather
	 * than being dropped by some other path. */
	T_EXPECT_EQ(g_unacked_track_sent_calls, 1);

	fx.fds[0] = -1; /* mux_session_suspend closed it */
	teardown_fixture(&fx);
}

/* session_resume_attach must clear wire.rx_eof the way the fresh-attach path
 * does: the FIN that suspended the session belongs to the transport that just
 * died, so carrying it across makes every later teardown of the resumed session
 * report MUX_EVENT_CLOSED with clean=true. */
T_DECLARE_CASE(test_resume_attach_clears_stale_rx_eof)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.handshake.has_session_id = true;
	mux_session_suspend(&fx.ss);
	fx.fds[0] = -1; /* mux_session_suspend closed it */
	T_CHECK(fx.ss.state == SESSION_SUSPENDED);
	/* Suspended by a peer FIN: send_handle_rx_closed left rx_eof set. */
	fx.ss.wire.rx_eof = true;

	struct mux_transport t = { .fd = fx.fds[1] };
	session_resume_attach(&fx.ss, &t, 0);

	const bool rx_eof = fx.ss.wire.rx_eof;
	const enum session_state state = fx.ss.state;

	fx.fds[1] = -1; /* the resumed session owns it now */
	teardown_fixture(&fx);

	T_EXPECT(state != (enum session_state)SESSION_SUSPENDED);
	T_EXPECT(!rx_eof);
}

/* Spec §5.2.2 defines the active extension set from the hello exchange, and a
 * resume is one. The resume ClientHello's extensions are parsed into the
 * transient session that mux_transport_detach then discards, so they ride
 * across on the transport: otherwise a client toggling reject_inbound or
 * changing its claim across a reconnect is silently ignored, and the resumed
 * session keeps reporting the original hello's identity. */
T_DECLARE_CASE(test_resume_attach_adopts_hello_extensions)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.handshake.has_session_id = true;
	fx.ss.handshake.peer_rejects_inbound_streams = false;
	fx.ss.handshake.peer_identity = strdup("old-peer");
	T_CHECK(fx.ss.handshake.peer_identity != NULL);
	mux_session_suspend(&fx.ss);
	fx.fds[0] = -1; /* mux_session_suspend closed it */
	T_CHECK(fx.ss.state == SESSION_SUSPENDED);

	char *const fresh = strdup("new-peer");
	T_CHECK(fresh != NULL);
	struct mux_transport t = {
		.fd = fx.fds[1],
		.peer_identity = fresh,
		.reject_inbound = true,
	};
	session_resume_attach(&fx.ss, &t, 0);

	const bool rejects = fx.ss.handshake.peer_rejects_inbound_streams;
	char identity[32] = { 0 };
	if (fx.ss.handshake.peer_identity != NULL) {
		(void)snprintf(
			identity, sizeof(identity), "%s",
			fx.ss.handshake.peer_identity);
	}
	/* Ownership moved to the session, so the transport must not free it. */
	const bool transport_consumed = (t.peer_identity == NULL);

	fx.fds[1] = -1; /* the resumed session owns it now */
	free(fx.ss.handshake.peer_identity);
	fx.ss.handshake.peer_identity = NULL;
	mux_transport_discard(&t);
	teardown_fixture(&fx);

	T_EXPECT(rejects);
	T_EXPECT_STREQ(identity, "new-peer");
	T_EXPECT(transport_consumed);
}

/* A stream can independently abort/close while a session is SUSPENDED, queuing
 * a fresh frame into wire.sendbuf via mux_session_send_ctrl. mux_session_attach_fd (the
 * client-side re-dial path) must capture it into the retransmit ring the same
 * way session_resume_attach (server-side) already does, instead of leaving it
 * to trip mux_handshake_enqueue_hello's ASSERT(sendbuf.head == NULL) on the next
 * handshake. */
T_DECLARE_CASE(test_session_attach_fd_captures_pending_sendbuf_frame)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_SUSPENDED;

	struct mux_frame *const deferred =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_CHECK(deferred != NULL);
	mux_write_header(
		deferred->data,
		&(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
				      .flags = MUX_FLAG_RST,
				      .stream_id = 33 });
	deferred->len = MUX_FRAME_HEADER_SIZE;
	mux_frame_list_push(&fx.ss.wire.sendbuf, deferred);

	g_unacked_track_sent_calls = 0;
	mux_session_attach_fd(&fx.ss, fx.fds[1]);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CONNECT);
	T_EXPECT(fx.ss.wire.sendbuf.head == NULL);
	/* The mock frees the frame it receives, so a leak-free teardown below
	 * is itself proof the deferred frame reached mux_unacked_track_sent rather
	 * than being dropped or left dangling in sendbuf. */
	T_EXPECT_EQ(g_unacked_track_sent_calls, 1);

	teardown_fixture(&fx);
}

/* The sibling of the case above for wire.oobbuf: a stream RST that aborts during
 * the suspension window lands in wire.oobbuf rather than wire.sendbuf once a
 * replay is pending (mux_session_send_ctrl routes real-stream-id frames there). The
 * re-attach path must capture that list too, or mux_wire_discard_buffers silently
 * frees the RST -- and with rst_sent already latched, the stream never re-emits
 * it, stranding the peer's half-open stream. */
T_DECLARE_CASE(test_session_attach_fd_captures_pending_oobbuf_frame)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_SUSPENDED;

	struct mux_frame *const deferred =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_CHECK(deferred != NULL);
	mux_write_header(
		deferred->data,
		&(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
				      .flags = MUX_FLAG_RST,
				      .stream_id = 33 });
	deferred->len = MUX_FRAME_HEADER_SIZE;
	mux_frame_list_push(&fx.ss.wire.oobbuf, deferred);

	g_unacked_track_sent_calls = 0;
	mux_session_attach_fd(&fx.ss, fx.fds[1]);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CONNECT);
	T_EXPECT(fx.ss.wire.oobbuf.head == NULL);
	/* Captured into the retransmit ring (mock frees it), not dropped by
	 * mux_wire_discard_buffers: without the oobbuf capture this stays 0. */
	T_EXPECT_EQ(g_unacked_track_sent_calls, 1);

	teardown_fixture(&fx);
}

/* Regression (commit 2c397eb): session_on_dead_link's post-mux_session_suspend
 * check must be `== SESSION_CLOSED`, not `!= SESSION_SUSPENDED` -- a
 * successful reentrant reconnect (below) legitimately lands on CONNECT,
 * neither of those states. */
T_DECLARE_CASE(test_dead_link_reentrant_reconnect_reaches_connect)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;
	fx.ss.callbacks.on_event = session_test_on_event_reentrant_reconnect;

	g_reentrant_attach_fd = fx.fds[1];
	g_suspended_event_count = 0;
	g_connect_event_count = 0;
	g_closed_event_count = 0;

	session_on_dead_link(&fx.ss, "test reentrant reconnect");

	/* Reentrant mux_session_attach_fd already ran inside mux_session_suspend's own
	 * SUSPENDED emit, landing on CONNECT before this call returns. */
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CONNECT);
	T_EXPECT_EQ(fx.ss.w_socket.fd, fx.fds[1]);
	T_EXPECT_EQ(g_suspended_event_count, 1);
	T_EXPECT_EQ(g_connect_event_count, 1);
	/* Must not mistake SESSION_CONNECT for closed and double-emit. */
	T_EXPECT_EQ(g_closed_event_count, 0);

	fx.ss.callbacks.on_event = NULL;
	fx.fds[0] = -1; /* mux_session_suspend closed it */
	teardown_fixture(&fx);
}

/* Same scenario as above, through connect_timeout_cb's SESSION_HANDSHAKE
 * case -- the other caller commit 2c397eb's reentrancy fix touched. */
T_DECLARE_CASE(test_connect_timeout_cb_reentrant_reconnect_reaches_connect)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;
	fx.ss.callbacks.on_event = session_test_on_event_reentrant_reconnect;

	g_reentrant_attach_fd = fx.fds[1];
	g_suspended_event_count = 0;
	g_connect_event_count = 0;
	g_closed_event_count = 0;

	connect_timeout_cb(fx.ss.loop, &fx.ss.w_connect_timeout, EV_TIMER);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CONNECT);
	T_EXPECT_EQ(fx.ss.w_socket.fd, fx.fds[1]);
	T_EXPECT_EQ(g_suspended_event_count, 1);
	T_EXPECT_EQ(g_connect_event_count, 1);
	T_EXPECT_EQ(g_closed_event_count, 0);

	fx.ss.callbacks.on_event = NULL;
	fx.fds[0] = -1; /* mux_session_suspend closed it */
	teardown_fixture(&fx);
}

/* mux_session_open_stream rejection paths: closed, not-established, draining,
 * peer rejects inbound, halfopen backlog full, max_streams cap, stream-id
 * exhaustion, mux_stream_new OOM, and sched_add failure. */
T_DECLARE_CASE(test_open_stream_rejections)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	/* Open the success path first -- a valid stream id, a stream that
	 * allocates, a sched_add that succeeds -- so each gate below is the sole
	 * cause of the NULL it returns; g_alloc_stream_id_result's inert default
	 * would otherwise short-circuit every one of them into ID exhaustion. */
	struct mux_stream dummy = { .id = 5 };
	g_alloc_stream_id_result = 5;
	g_stream_new_result = &dummy;
	g_sched_add_stream_result = true;

	fx.ss.state = SESSION_CLOSED;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);

	fx.ss.state = SESSION_HANDSHAKE;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);

	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.draining = true;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);
	fx.ss.draining = false;

	fx.ss.handshake.peer_rejects_inbound_streams = true;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);
	fx.ss.handshake.peer_rejects_inbound_streams = false;

	fx.ss.conf.max_halfopen = 1;
	fx.ss.num_halfopen = 1;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);
	fx.ss.conf.max_halfopen = 0;
	fx.ss.num_halfopen = 0;

	/* One live stream in the table, no tombstone: the max_streams cap bites. */
	void *elem = (void *)(uintptr_t)1;
	fx.ss.sched.streams = table_set(
		fx.ss.sched.streams, (const void *)(uintptr_t)7, &elem);
	T_CHECK(fx.ss.sched.streams != NULL);
	fx.ss.conf.max_streams = 1;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);
	fx.ss.conf.max_streams = 0;

	/* Positive control: every gate clear now yields a stream, so each NULL
	 * above was its gate rather than a fixture that can never succeed. */
	T_EXPECT(mux_session_open_stream(&fx.ss) == &dummy);

	/* mux_sched_alloc_stream_id returns STREAMID_CTRL: IDs exhausted. */
	g_alloc_stream_id_result = STREAMID_CTRL;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);

	/* A valid id, but mux_stream_new fails (OOM). */
	g_alloc_stream_id_result = 5;
	g_stream_new_result = NULL;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);

	/* mux_stream_new succeeds, but mux_sched_add_stream fails. */
	g_stream_new_result = &dummy;
	g_sched_add_stream_result = false;
	T_EXPECT(mux_session_open_stream(&fx.ss) == NULL);
	g_stream_new_result = NULL;
	g_sched_add_stream_result = true;
	g_alloc_stream_id_result = STREAMID_CTRL;

	teardown_fixture(&fx);
}

/* mux_session_set_config on a live session: auto session-window floor, timer
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

	struct mux_session_config conf = fx.ss.conf;
	conf.session_window =
		0; /* auto: enforce floor (covers the floor branch) */
	conf.stream_window = 4; /* manual */
	conf.timeout = 0; /* established: stop w_timeout */
	conf.keepalive = 0; /* established: stop w_keepalive */
	conf.send_timeout =
		5; /* AF_UNIX: TCP_USER_TIMEOUT fails, repeat kept */
	conf.connect_timeout = 5;
	conf.idle_timeout = 5;
	mux_session_set_config(&fx.ss, &conf);

	T_EXPECT(
		fx.ss.session_window >=
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT);

	ev_timer_stop(fx.ss.loop, &fx.ss.w_send_timeout);
	ev_timer_stop(fx.ss.loop, &fx.ss.w_connect_timeout);
	ev_timer_stop(fx.ss.loop, &fx.ss.w_idle_timeout);
	teardown_fixture(&fx);
}

/* mux_session_start aborts and resets when the TLS layer fails to start. */
T_DECLARE_CASE(test_session_start_tls_failed)
{
#if WITH_TLS
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	fx.ss.state = SESSION_INIT;
	fx.ss.callbacks.on_event = session_test_on_event;
	g_closed_event_count = 0;
	g_wire_tls_start_result = false;
	mux_session_start(&fx.ss);
	g_wire_tls_start_result = true;
	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSED);
	/* The owner (mux_start) is not inside socket_cb's dispatch, so nothing
	 * catches a bare reset from SESSION_INIT; mux_session_start must emit
	 * MUX_EVENT_CLOSED itself or the owning tunnel leaks. */
	T_EXPECT_EQ(g_closed_event_count, 1);
	fx.ss.callbacks.on_event = NULL;
	fx.fds[0] = -1;
	teardown_fixture(&fx);
#else /* WITH_TLS */
	T_SKIP();
#endif /* WITH_TLS */
}

/* mux_session_handshake_done: pending egress arms tx_pending; a drain request with
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
		mux_session_handshake_done(&fx.ss);
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
		mux_session_handshake_done(&fx.ss);
		T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSING);
		teardown_fixture(&fx);
	}
}

/* The drain arm in mux_session_handshake_done must subtract tombstones like the
 * idle arm ten lines above it already does -- a resume completing with one
 * lingering (CLOSED-but-not-yet-swept) tombstone must still initiate shutdown
 * immediately, not wait up to MUX_TOMBSTONE_PERIOD_S for it to expire and be
 * swept. */
T_DECLARE_CASE(test_handshake_done_drain_subtracts_tombstones)
{
	struct session_fixture fx;
	if (setup_handshake_fixture(&fx) != 0) {
		T_FATAL("setup_handshake_fixture failed");
		return;
	}
	void *elem = (void *)(uintptr_t)1;
	fx.ss.sched.streams = table_set(
		fx.ss.sched.streams, (const void *)(uintptr_t)7, &elem);
	T_CHECK(fx.ss.sched.streams != NULL);
	fx.ss.sched.num_tombstones = 1;
	fx.ss.draining = true;

	mux_session_handshake_done(&fx.ss);

	T_EXPECT_EQ(fx.ss.state, (enum session_state)SESSION_CLOSING);
	teardown_fixture(&fx);
}

static const struct testing_suite suite[] = {
	T_CASE(test_session_handshake_done_rearms_coalesce_for_delay_list),
	T_CASE(test_session_handshake_done_rearms_coalesce_for_ack_backlog),
	T_CASE(test_session_handshake_done_no_coalesce_without_backlog),
	T_CASE(test_session_initiate_shutdown_transitions_to_closed),
	T_CASE(test_session_initiate_shutdown_force_close_resets_outbound_state),
	T_CASE(test_session_initiate_shutdown_no_reemit_when_closed),
	T_CASE(test_session_set_config_preserves_suspended_resume_deadline),
	T_CASE(test_session_set_config_preserves_graceful_close_deadline),
	T_CASE(test_session_initiate_shutdown_skips_close_deadline_when_disabled),
	T_CASE(test_session_drain_sets_draining_flag),
	T_CASE(test_socket_user_timeout_sets_option),
	T_CASE(test_session_log_frame_header_formats_flags),
	T_CASE(test_closing_cb_pending_then_error),
	T_CASE(test_close_wait_cb_unexpected),
	T_CASE(test_close_wait_cb_confirmed_reports_clean),
	T_CASE(test_close_wait_cb_pending),
	T_CASE(test_connect_cb_tls_paths),
	T_CASE(test_connect_cb_reports_socket_error_on_closed),
	T_CASE(test_attach_fd_clears_stale_transport_error),
	T_CASE(test_dead_link_suspend_for_resume),
	T_CASE(test_capture_frame_list_skips_frames_once_session_closed),
	T_CASE(test_dead_link_close_without_session_id),
	T_CASE(test_session_reset_clears_has_session_id_for_client),
	T_CASE(test_session_reset_preserves_has_session_id_for_server),
	T_CASE(test_notify_closed_on_already_closed_session_does_not_reemit),
	T_CASE(test_established_exit_suspends_estimator),
	T_CASE(test_established_exit_stops_idle_timeout),
	T_CASE(test_established_exit_stream_window_floor_respects_mode),
	T_CASE(test_timeout_and_send_timeout_callbacks),
	T_CASE(test_keepalive_cb_emits_and_rearms),
	T_CASE(test_connect_timeout_cb_states),
	T_CASE(test_session_suspend_pays_back_halfopen_from_handshake),
	T_CASE(test_session_suspend_skips_resume_deadline_when_disabled),
	T_CASE(test_session_suspend_migrates_pending_oobbuf_frame),
	T_CASE(test_resume_attach_clears_stale_rx_eof),
	T_CASE(test_resume_attach_adopts_hello_extensions),
	T_CASE(test_session_attach_fd_captures_pending_sendbuf_frame),
	T_CASE(test_session_attach_fd_captures_pending_oobbuf_frame),
	T_CASE(test_dead_link_reentrant_reconnect_reaches_connect),
	T_CASE(test_connect_timeout_cb_reentrant_reconnect_reaches_connect),
	T_CASE(test_open_stream_rejections),
	T_CASE(test_set_config_live_session_branches),
	T_CASE(test_session_start_tls_failed),
	T_CASE(test_handshake_done_sched_head_and_drain),
	T_CASE(test_handshake_done_drain_subtracts_tombstones),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	slog_level_ = LOG_LEVEL_VERYVERBOSE;

	return testing_main(argc, argv, suite);
}
