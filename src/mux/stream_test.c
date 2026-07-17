/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* stream_test.c - white-box tests for stream.c (per-stream state machine,
 * window/credit accounting, half-close/RST); stream.c #included, sched/send
 * collaborators mocked below. */

#include "mux/stream.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/stream.c"

#include "algo/hashtable.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* mock - collaborator mocks, frame pool, session/stream fixtures */

/* sched.c: the scheduler is not under test; sched_add_stream/sched_free_streams
 * keep the stream table coherent (the fixture relies on them), the queue
 * arming/coalescing entry points are inert. */

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

bool sched_add_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	/* Mirror production sched.c: reject a duplicate ID *before* touching the
	 * table. table_set would otherwise replace the existing mapping with s and
	 * return the prior stream, orphaning it -- the caller responds to a false
	 * return with stream_free(s), which would then leave the table holding a
	 * freed pointer. */
	if (ss->sched.streams != NULL) {
		void *found = NULL;
		if (table_find(
			    ss->sched.streams, (const void *)(uintptr_t)s->id,
			    &found)) {
			return false;
		}
	}
	void *elem = s;
	ss->sched.streams = table_set(
		ss->sched.streams, (const void *)(uintptr_t)s->id, &elem);
	/* elem is NULL on a fresh insert; it stays == s only on a table-NULL/grow
	 * failure now that a duplicate is rejected above. */
	if (ss->sched.streams == NULL || elem != NULL) {
		return false;
	}
	ev_timer_stop(ss->loop, &ss->w_idle_timeout);
	return true;
}

static bool st_free_stream_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	(void)data;
	stream_free(element);
	return true;
}

void sched_free_streams(struct mux_session *restrict ss)
{
	ss->sched.sched_head = NULL;
	ss->sched.sched_tail = NULL;
	ss->sched.drr_active = NULL;
	ss->sched.lp_head = NULL;
	ss->sched.lp_tail = NULL;
	for (struct mux_stream *d = ss->sched.delay_head; d != NULL;
	     d = d->delay_next) {
		d->delay_pending = false;
	}
	ss->sched.delay_head = NULL;
	ss->sched.num_tombstones = 0;
	ss->sched.next_stream_id = 0;
	if (ss->sched.streams != NULL) {
		table_iterate(ss->sched.streams, st_free_stream_cb, ss);
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
}

void sched_delay(
	struct mux_session *restrict ss, struct mux_stream *restrict s,
	const uint_fast8_t ticks)
{
	(void)ss;
	(void)s;
	(void)ticks;
}

void sched_delay_remove(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
}

void sched_wake(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
}

static int g_sched_check_no_active_streams_calls;
/* Opt-in cascade used to reproduce last-stream drain teardown with this
 * file's sched_free_streams() mock. */
static bool g_free_streams_on_check;

void sched_check_no_active_streams(struct mux_session *ss)
{
	g_sched_check_no_active_streams_calls++;
	if (g_free_streams_on_check) {
		g_free_streams_on_check = false;
		sched_free_streams(ss);
	}
}

/* send.c: control-frame emission is reproduced just enough for callers that
 * inspect the resulting wire frame (e.g. the close-sends-RST case); the flush
 * entry points are inert. */
static bool g_session_send_ctrl_fail = false;

bool session_send_ctrl(
	struct mux_session *ss, uint_fast16_t stream_id, uint_fast8_t flags,
	uint_fast32_t extra)
{
	if (g_session_send_ctrl_fail) {
		return false;
	}
	struct mux_frame *const frame =
		mux_frame_get(&ss->pool, ss->max_payload);
	if (frame == NULL) {
		return false;
	}
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = (uint_least8_t)flags,
		.length = 0,
		.stream_id = (uint_least16_t)stream_id,
		.extra = (uint_least16_t)extra,
	};
	mux_write_header(frame->data, &hdr);
	frame->len = MUX_FRAME_HEADER_SIZE;
	frame->pos = 0;
	mux_frame_list_push(&ss->wire.sendbuf, frame);
	return true;
}

void session_discard_stream_frames(
	struct mux_session *ss, uint_fast16_t stream_id)
{
	(void)ss;
	(void)stream_id;
}

void session_flush(struct mux_session *ss)
{
	(void)ss;
}

void session_eager_flush(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
}

/* wire.c: mirror the real buffer-reset path so teardown reclaims frames. */
void wire_discard_buffers(struct mux_session *restrict ss)
{
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	ss->wire.sendbuf_staging = false;
	bytebuf_reset(ss->wire.recvbuf);
}

struct frame_pool_ctx {
	uint_least32_t alloc_calls;
	uint_least32_t free_calls;
};

struct stream_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
	struct frame_pool_ctx pool_ctx;
	int fds[2];
};

static struct mux_frame *stream_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void stream_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = stream_test_alloc,
		.free = stream_test_free,
		.data = ctx,
	};
}

static void
stream_test_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void stream_test_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static int setup_fixture(struct stream_fixture *restrict fx)
{
	/* Reset collaborator-mock globals so no case's opt-in state (notably the
	 * g_free_streams_on_check cascade, which self-clears only inside
	 * sched_check_no_active_streams and so survives a case that never reaches
	 * it) can bleed into the next case. */
	g_free_streams_on_check = false;
	g_sched_check_no_active_streams_calls = 0;
	g_session_send_ctrl_fail = false;

	*fx = (struct stream_fixture){
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
	ev_io_init(&fx->ss.w_socket, stream_test_io_cb, fx->fds[0], EV_READ);
	fx->ss.w_socket.data = &fx->ss;
	ev_timer_init(&fx->ss.w_idle_timeout, stream_test_timer_cb, 1.0, 0.0);
	fx->ss.w_idle_timeout.data = &fx->ss;
	sched_init(&fx->ss);
	fx->ss.wire.recvbuf = bytebuf_new(4u * (size_t)MUX_MAX_FRAME_SIZE);
	if (fx->ss.wire.recvbuf == NULL) {
		table_free(fx->ss.sched.streams);
		(void)close(fx->fds[0]);
		(void)close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	return 0;
}

static void teardown_fixture(struct stream_fixture *restrict fx)
{
	if (fx->ss.sched.streams != NULL) {
		sched_free_streams(&fx->ss);
	}
	if (fx->ss.wire.oobbuf.head != NULL ||
	    bytebuf_readable(fx->ss.wire.recvbuf) > 0 ||
	    fx->ss.wire.sendbuf.head != NULL) {
		wire_discard_buffers(&fx->ss);
	}
	bytebuf_free(fx->ss.wire.recvbuf);
	fx->ss.wire.recvbuf = NULL;
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

static struct mux_stream *
make_stream(struct stream_fixture *restrict fx, const uint_fast16_t id)
{
	struct mux_stream *const s = stream_new(&fx->ss, id, true);
	if (s != NULL) {
		s->state = STREAM_ESTABLISHED;
	}
	return s;
}

static struct mux_frame *make_payload_frame(
	const struct mux_frame_allocator *restrict pool,
	const size_t payload_len)
{
	struct mux_frame *const frame =
		mux_frame_get(pool, MUX_MAX_PAYLOAD_SIZE);
	if (frame == NULL) {
		return NULL;
	}
	memset(frame->data, 0, MUX_FRAME_HEADER_SIZE + payload_len);
	frame->len = MUX_FRAME_HEADER_SIZE + payload_len;
	frame->pos = 0;
	return frame;
}

/* regression - targeted cases for one stream behavior each */

T_DECLARE_CASE(test_stream_grant_inc_uses_available_window)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->grant_sent = 0;
	const uint_fast32_t grant = stream_grant_inc(s);

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(grant, (uint_fast32_t)4);
}

T_DECLARE_CASE(test_stream_grant_inc_scales_under_pressure)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	fx.ss.conf.mem_pressure_lo = 2 * (int)MUX_MAX_FRAME_SIZE;
	fx.ss.conf.mem_pressure_hi = 4 * (int)MUX_MAX_FRAME_SIZE;
	fx.ss.recv_buffered_bytes = 4 * (size_t)MUX_MAX_FRAME_SIZE;
	fx.ss.stream_window = 8;

	struct mux_stream *const s = stream_new(&fx.ss, 1, true);
	T_CHECK(s != NULL);
	s->state = STREAM_ESTABLISHED;
	s->grant_sent = 0;
	const uint_fast32_t grant = stream_grant_inc(s);

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(grant, (uint_fast32_t)1);
}

T_DECLARE_CASE(test_stream_dequeue_send_updates_queue_counters)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	struct mux_frame *frame;
	T_CHECK(s != NULL);
	frame = make_payload_frame(&fx.ss.pool, 32);
	T_CHECK(frame != NULL);
	mux_frame_list_push(&s->send_queue, frame);
	s->queued_send_bytes = 32;
	fx.ss.send_buffered_frames = 1;

	frame = stream_dequeue_send(s);
	const bool dequeued = (frame != NULL);
	const bool head_null = (s->send_queue.head == NULL);
	const uint_least32_t queued = s->queued_send_bytes;
	const size_t buffered_frames = fx.ss.send_buffered_frames;
	if (frame != NULL) {
		mux_frame_put(&fx.ss.pool, frame);
	}

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(dequeued);
	T_EXPECT(head_null);
	T_EXPECT_EQ(queued, (uint_least32_t)0);
	T_EXPECT_EQ(buffered_frames, (size_t)0);
}

T_DECLARE_CASE(test_stream_recv_window_grows_send_credit)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = true;
	s->send_window = 0;
	s->bytes_sent = 0;

	stream_recv_window(s, 2);
	const uint_least32_t send_window = s->send_window;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(send_window, (uint_least32_t)(2 * MUX_WINDOW_UNIT));
}

static int g_notify_write_revents;
static void
stream_test_notify_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	(void)w;
	g_notify_write_revents |= revents;
}

/* A WINDOW/ACK grant feeds the direct-mode EV_WRITE only while the stream is
 * still in a sendable state. The same grant arriving after the local FIN
 * (STREAM_CLOSING) must not feed a spurious EV_WRITE -- stream_recv_window's
 * notify must apply the stream_can_send_data() gate that stream_io_start() and
 * mux_stream_io_modify() apply to the same feed. */
T_DECLARE_CASE(test_stream_recv_window_gates_ev_write_on_sendable_state)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	mux_stream_io w;
	mux_stream_io_init(&w, stream_test_notify_cb, s, EV_WRITE);
	w.loop = fx.loop;
	s->is_direct = true;
	s->direct.w_io = &w;

	/* Sendable (ESTABLISHED): the grant restores credit and feeds EV_WRITE. */
	s->send_window = 0;
	s->bytes_sent = 0;
	g_notify_write_revents = 0;
	stream_recv_window(s, 2);
	ev_invoke_pending(fx.loop);
	const int established_revents = g_notify_write_revents;

	/* Non-sendable (CLOSING, local FIN already sent): the grant must not
	 * feed EV_WRITE even though credit is restored. */
	s->state = STREAM_CLOSING;
	s->send_window = 0;
	s->bytes_sent = 0;
	g_notify_write_revents = 0;
	stream_recv_window(s, 2);
	ev_invoke_pending(fx.loop);
	const int closing_revents = g_notify_write_revents;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(established_revents & EV_WRITE);
	T_EXPECT(!(closing_revents & EV_WRITE));
}

T_DECLARE_CASE(test_stream_recv_fin_advances_state)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);

	s->state = STREAM_ESTABLISHED;
	stream_recv_fin(s);
	const enum stream_state after_established = s->state;

	s->state = STREAM_FIN_WAIT;
	stream_recv_fin(s);
	const enum stream_state after_fin_wait = s->state;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(after_established, (enum stream_state)STREAM_CLOSE_WAIT);
	T_EXPECT_EQ(after_fin_wait, (enum stream_state)STREAM_CLOSING);
}

T_DECLARE_CASE(test_stream_recv_rst_discards_buffered_data)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	unsigned char payload[16] = { 0 };
	T_CHECK(s != NULL);
	s->is_direct = true;
	stream_recv_copy(s, payload, sizeof(payload));
	const uint_least32_t buffered_before = s->buffered_bytes;

	stream_recv_rst(s, MUX_STATUS_NO_ERROR);
	const bool rst_received = s->rst_received;
	const enum stream_state state = s->state;
	const uint_least32_t buffered_after = s->buffered_bytes;
	const size_t recvbuf_readable = bytebuf_readable(s->recvbuf);

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(buffered_before, (uint_least32_t)sizeof(payload));
	T_EXPECT(rst_received);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT_EQ(buffered_after, (uint_least32_t)0);
	T_EXPECT_EQ(recvbuf_readable, (size_t)0);
}

/* Flow control (spec §6.5/§6.6): a PUSH pushing cumulative bytes_received past
 * grant_sent must abort the stream. recv_window does not enforce this -- a
 * promptly-draining app keeps buffered_bytes low, so a peer could over-send and
 * wrap stream_grantable_bytes' credit subtraction, freezing the loop. A payload
 * within the grant must not abort. */
T_DECLARE_CASE(test_stream_recv_copy_aborts_over_granted_credit)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = true;
	s->grant_sent = 16; /* only 16 bytes granted so far */
	s->recv_window = 65536; /* large so recv_window does not trip first */
	unsigned char payload[64] = { 0 };

	/* Within the grant: buffered, not aborted. */
	stream_recv_copy(s, payload, 8);
	const bool within_ok = (s->state == STREAM_ESTABLISHED);
	const uint_least32_t received = s->bytes_received;

	/* 8 + 16 > 16 granted: flow-control abort. */
	stream_recv_copy(s, payload, 16);
	const bool aborted = (s->state == STREAM_CLOSED);

	stream_free(s);
	teardown_fixture(&fx);
	T_EXPECT(within_ok);
	T_EXPECT_EQ(received, (uint_least32_t)8);
	T_EXPECT(aborted);
}

/* Wrap-boundary regression for the cumulative-credit check: bytes_received and
 * grant_sent both wrap at 2^32, so an in-credit PUSH arriving while the pair
 * straddles the boundary (grant_sent already wrapped small, bytes_received still
 * near 2^32) must not abort. A plain-magnitude compare aborted a conforming bulk
 * stream every ~4 GiB here; the wrap-safe (grant_sent - bytes_received) idiom
 * must not. */
T_DECLARE_CASE(test_stream_recv_copy_credit_check_survives_counter_wrap)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = true;
	/* 32 bytes of outstanding credit straddling the wrap: grant_sent leads
	 * bytes_received by 32 but has already wrapped past 2^32 to zero. */
	s->bytes_received = UINT32_MAX - 31u; /* 2^32 - 32 */
	s->grant_sent = 0u; /* bytes_received + 32, wrapped */
	s->recv_window = 65536; /* large so recv_window does not trip */
	unsigned char payload[8] = { 0 };

	/* 8 bytes, within the 32-byte outstanding credit: buffered, not aborted. */
	stream_recv_copy(s, payload, sizeof(payload));
	const bool not_aborted = (s->state == STREAM_ESTABLISHED);
	const uint_least32_t received = s->bytes_received;

	stream_free(s);
	teardown_fixture(&fx);
	T_EXPECT(not_aborted);
	T_EXPECT_EQ(received, (uint_least32_t)((UINT32_MAX - 31u) + 8u));
}

/* A direct-mode stream fully closed by the application (user_closed) while
 * already in CLOSING (both FINs exchanged, empty recvbuf) must be completed by
 * stream_shutdown, not stranded: no mux_stream_recv caller remains to finish
 * it, so it would otherwise sit in CLOSING for the session's life. */
/* A direct-mode stream already in CLOSING (both FINs exchanged) that the app has
 * closed has no mux_stream_recv caller left, so stream_shutdown must complete the
 * close itself rather than strand it in CLOSING for the session's life. A
 * still-owned direct stream (no user_closed) must keep deferring -- the library
 * may not free a stream the app still holds (a half-close via mux_stream_shutdown
 * never sets user_closed, so it must not complete here). */
T_DECLARE_CASE(test_stream_shutdown_completes_user_closed_closing_direct)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const owned = make_stream(&fx, 1);
	T_CHECK(owned != NULL);
	owned->is_direct = true;
	owned->state = STREAM_CLOSING; /* both FINs already exchanged */
	stream_shutdown(owned);
	const enum stream_state owned_state = owned->state;

	struct mux_stream *const closed = make_stream(&fx, 3);
	T_CHECK(closed != NULL);
	closed->is_direct = true;
	closed->user_closed = true;
	closed->state = STREAM_CLOSING; /* both FINs already exchanged */
	stream_shutdown(closed);
	const enum stream_state closed_state = closed->state;

	stream_free(owned);
	stream_free(closed);
	teardown_fixture(&fx);

	T_EXPECT_EQ(owned_state, (enum stream_state)STREAM_CLOSING);
	T_EXPECT_EQ(closed_state, (enum stream_state)STREAM_CLOSED);
}

/* A stream torn down while it holds the DRR round budget (drr_active) must not
 * leave a stale self-reference behind, or the tombstone-driven sched_wake 10s
 * later silently no-ops (sched_lp_enqueue treats "s == drr_active" as "already
 * owned") and the stream is never freed. */
T_DECLARE_CASE(test_stream_recv_rst_clears_stale_drr_active)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	fx.ss.sched.drr_active = s;

	stream_recv_rst(s, MUX_STATUS_NO_ERROR);
	const enum stream_state state = s->state;
	const bool drr_cleared = (fx.ss.sched.drr_active == NULL);

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(drr_cleared);
}

/* Socket-mode local write path: a hard write error (send(-1) -> EBADF) makes
 * stream_local_write abort the stream (STREAM_CLOSED, send timer stopped), and
 * stream_flush_local must NOT re-arm the send timeout on the torn-down stream.
 * Regression for the timer re-arm bug in the nwrite==0 branch. */
T_DECLARE_CASE(test_stream_flush_local_hard_error_leaves_timer_stopped)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	/* Socket mode, a write-failing fd, and a configured send timeout. */
	s->is_direct = false;
	s->socket.w_io.fd = -1;
	s->socket.w_timeout.repeat = 5.0;
	/* Buffer some recv data (with matching accounting for stream_free). */
	unsigned char payload[16] = { 0 };
	memcpy(bytebuf_write_ptr(s->recvbuf), payload, sizeof(payload));
	bytebuf_produce(s->recvbuf, sizeof(payload));
	s->buffered_bytes = (uint_least32_t)sizeof(payload);
	s->session->recv_buffered_bytes = sizeof(payload);

	stream_flush_local(s);

	const enum stream_state state = s->state;
	/* The abort stopped the send timer; the buggy path re-armed it here. */
	const bool timer_stopped = !ev_is_active(&s->socket.w_timeout);

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(timer_stopped);
}

T_DECLARE_CASE(test_stream_abort_clears_stale_drr_active)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	fx.ss.sched.drr_active = s;

	stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
	const enum stream_state state = s->state;
	const bool drr_cleared = (fx.ss.sched.drr_active == NULL);

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(drr_cleared);
}

T_DECLARE_CASE(test_stream_close_with_unread_data_sends_rst)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	unsigned char payload[8] = { 0 };
	T_CHECK(s != NULL);
	s->is_direct = true;
	stream_recv_copy(s, payload, sizeof(payload));
	const uint_least32_t buffered_before = s->buffered_bytes;

	stream_close(s);
	const bool sent_frame = (fx.ss.wire.sendbuf.head != NULL);
	const enum stream_state state = s->state;
	struct mux_header hdr = { 0 };
	if (sent_frame) {
		mux_read_header(fx.ss.wire.sendbuf.head->data, &hdr);
	}

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(buffered_before, (uint_least32_t)sizeof(payload));
	T_CHECK(sent_frame);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(hdr.flags & MUX_FLAG_RST);
	T_EXPECT_EQ(hdr.extra, (uint_least16_t)MUX_STATUS_CANCEL);
}

/* Spec §4.3.4: a receiver of RST goes to CLOSED and sends no response frame.
 * stream_recv_rst fires the direct-mode EV_READ notify while the pre-RST
 * payload is still buffered, and mux.c invites the app to call
 * mux_stream_close() from that callback -- which reaches stream_close with
 * unread data and rst_received set. The unread-data branch must not answer the
 * peer's RST with one of its own. */
T_DECLARE_CASE(test_stream_close_after_peer_rst_sends_no_rst)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	unsigned char payload[8] = { 0 };
	T_CHECK(s != NULL);
	s->is_direct = true;
	stream_recv_copy(s, payload, sizeof(payload));
	T_CHECK(s->buffered_bytes == (uint_least32_t)sizeof(payload));
	/* As stream_recv_rst leaves it when it notifies the app. */
	s->rst_received = true;

	stream_close(s);

	const bool sent_frame = fx.ss.wire.sendbuf.head != NULL;
	const enum stream_state state = s->state;
	const bool rst_sent = s->rst_sent;
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(!sent_frame);
	T_EXPECT(!rst_sent);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
}

/* stream_close's abortive path (unread data -> RST) whose RST enqueue OOMs must
 * still count the stream failed, not succeeded. rst_sent is latched only on a
 * successful enqueue (retryable on OOM), so the close marks the stream aborted
 * to keep the count correct -- mirroring stream_abort's aborted latch. */
T_DECLARE_CASE(test_stream_close_oom_abortive_rst_counts_failed)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	mux_counter failed = 0, succeeded = 0;
	fx.ss.cnt.num_stream_failed = &failed;
	fx.ss.cnt.num_stream_succeeded = &succeeded;

	struct mux_stream *const s = make_stream(&fx, 1); /* ESTABLISHED */
	unsigned char payload[8] = { 0 };
	T_CHECK(s != NULL);
	/* Direct mode so stream_recv_copy buffers rather than fast-pathing the
	 * payload to a connected socket, leaving unread data at close. */
	s->is_direct = true;
	stream_recv_copy(s, payload, sizeof(payload));
	T_CHECK(bytebuf_readable(s->recvbuf) > 0);

	g_session_send_ctrl_fail = true; /* the abortive RST enqueue OOMs */
	stream_close(s);
	g_session_send_ctrl_fail = false;

	const bool aborted = s->aborted;
	const bool rst_sent = s->rst_sent;
	/* Read the (atomic under threads) counters directly rather than via
	 * COUNTER_LOAD, whose NULL check trips -Waddress on a stack address. */
	const uint_least64_t n_failed = failed;
	const uint_least64_t n_succeeded = succeeded;
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(!rst_sent); /* OOM left the RST retryable */
	T_EXPECT(aborted); /* the abortive close is marked... */
	T_EXPECT_EQ(n_failed, (uint_least64_t)1); /* ...so counted failed */
	T_EXPECT_EQ(n_succeeded, (uint_least64_t)0);
}

/* A direct-mode stream the app has closed has no mux_stream_recv caller left,
 * so stream_mark_fin_sent must complete the close itself instead of deferring
 * to one: otherwise the stream sits in CLOSING for the session's life, holding
 * its scheduler slot and max_streams quota. A still-owned direct stream (no
 * user_closed) must keep deferring -- the library may not free a stream the
 * app still holds. */
T_DECLARE_CASE(test_stream_mark_fin_sent_closes_user_closed_direct_stream)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const owned = make_stream(&fx, 1);
	T_CHECK(owned != NULL);
	owned->is_direct = true;
	stream_set_state(owned, STREAM_CLOSE_WAIT);
	stream_mark_fin_sent(owned);
	const enum stream_state owned_state = owned->state;

	struct mux_stream *const closed = make_stream(&fx, 3);
	T_CHECK(closed != NULL);
	closed->is_direct = true;
	closed->user_closed = true;
	stream_set_state(closed, STREAM_CLOSE_WAIT);
	stream_mark_fin_sent(closed);
	const enum stream_state closed_state = closed->state;

	stream_free(owned);
	stream_free(closed);
	teardown_fixture(&fx);

	T_EXPECT_EQ(owned_state, (enum stream_state)STREAM_CLOSING);
	T_EXPECT_EQ(closed_state, (enum stream_state)STREAM_CLOSED);
}

/* The mirror image on the receive side: the peer's FIN arriving after the app
 * closed a direct-mode stream must complete the close, without touching the
 * socket half of the I/O union (there is no local socket in this mode). */
T_DECLARE_CASE(test_stream_recv_fin_closes_user_closed_direct_stream)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const owned = make_stream(&fx, 1);
	T_CHECK(owned != NULL);
	owned->is_direct = true;
	stream_set_state(owned, STREAM_FIN_WAIT);
	stream_recv_fin(owned);
	const enum stream_state owned_state = owned->state;

	struct mux_stream *const closed = make_stream(&fx, 3);
	T_CHECK(closed != NULL);
	closed->is_direct = true;
	closed->user_closed = true;
	stream_set_state(closed, STREAM_FIN_WAIT);
	stream_recv_fin(closed);
	const enum stream_state closed_state = closed->state;

	stream_free(owned);
	stream_free(closed);
	teardown_fixture(&fx);

	T_EXPECT_EQ(owned_state, (enum stream_state)STREAM_CLOSING);
	T_EXPECT_EQ(closed_state, (enum stream_state)STREAM_CLOSED);
}

/* Regression (#1): a user-closed direct-mode stream that received data after
 * our FIN -- buffered with no reader -- must not strand when the peer's FIN then
 * arrives. Both completion sites once required an empty recv buffer and left the
 * stream in CLOSING for the session's life otherwise. It now completes via
 * stream_close's close(fd) semantics (the same mux_stream_close applies to
 * unread data): the buffered data is discarded, an RST is sent, and the stream
 * reaches CLOSED. This is the receive-side path (peer FIN in FIN_WAIT). */
T_DECLARE_CASE(test_stream_recv_fin_user_closed_direct_rsts_buffered_data)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = true;
	/* Data the peer sent after our FIN, buffered with no reader left. */
	unsigned char payload[8] = { 0 };
	stream_recv_copy(s, payload, sizeof(payload));
	/* The application has closed the stream and our FIN has left (FIN_WAIT). */
	s->user_closed = true;
	stream_set_state(s, STREAM_FIN_WAIT);

	/* The peer's FIN arrives: FIN_WAIT -> CLOSING with data still buffered. */
	stream_recv_fin(s);

	const enum stream_state state = s->state;
	const bool rst_sent = s->rst_sent;
	const size_t readable = bytebuf_readable(s->recvbuf);
	const uint_least32_t buffered = s->buffered_bytes;
	const bool frame_out = fx.ss.wire.sendbuf.head != NULL;
	struct mux_header hdr = { 0 };
	if (frame_out) {
		mux_read_header(fx.ss.wire.sendbuf.head->data, &hdr);
	}

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED); /* not stranded */
	T_EXPECT(rst_sent);
	T_CHECK(frame_out);
	T_EXPECT(hdr.flags & MUX_FLAG_RST);
	T_EXPECT_EQ(readable, (size_t)0); /* discarded */
	T_EXPECT_EQ(buffered, (uint_least32_t)0);
}

/* The send-side mirror of the case above: a user-closed direct-mode stream with
 * data the peer sent after its FIN (we are in CLOSE_WAIT) must complete when our
 * FIN leaves, discarding the buffered data with an RST rather than stranding in
 * CLOSING. */
T_DECLARE_CASE(test_stream_mark_fin_sent_user_closed_direct_rsts_buffered_data)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = true;
	unsigned char payload[8] = { 0 };
	stream_recv_copy(s, payload, sizeof(payload));
	/* Peer FIN already arrived (CLOSE_WAIT) and the app has closed the stream;
	 * its data is buffered with no reader. */
	s->user_closed = true;
	stream_set_state(s, STREAM_CLOSE_WAIT);

	/* Our FIN leaves: CLOSE_WAIT -> CLOSING with data still buffered. */
	stream_mark_fin_sent(s);

	const enum stream_state state = s->state;
	const bool rst_sent = s->rst_sent;
	const size_t readable = bytebuf_readable(s->recvbuf);
	const uint_least32_t buffered = s->buffered_bytes;
	const bool frame_out = fx.ss.wire.sendbuf.head != NULL;
	struct mux_header hdr = { 0 };
	if (frame_out) {
		mux_read_header(fx.ss.wire.sendbuf.head->data, &hdr);
	}

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED); /* not stranded */
	T_EXPECT(rst_sent);
	T_CHECK(frame_out);
	T_EXPECT(hdr.flags & MUX_FLAG_RST);
	T_EXPECT_EQ(readable, (size_t)0);
	T_EXPECT_EQ(buffered, (uint_least32_t)0);
}

T_DECLARE_CASE(test_stream_shutdown_marks_rx_eof)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);

	stream_shutdown(s);
	const bool rx_eof = s->rx_eof;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(rx_eof);
}

/* Regression: when rx_eof is already set (local app finished sending)
 * and the peer FIN then arrives, stream_shutdown_local_write() must still call
 * shutdown(SHUT_WR) so the local TCP stack delivers EOF to the local app. */
T_DECLARE_CASE(test_stream_recv_fin_with_rx_eof_shuts_down_write)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);

	/* Simulate: local app already hit EOF; local FIN was sent; peer FIN
	 * has not yet arrived (FIN_WAIT state). */
	s->state = STREAM_FIN_WAIT;
	s->rx_eof = true;
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_NONE);
	s->socket.connected = true;

	/* Peer FIN arrives with no buffered recv data. */
	stream_recv_fin(s);

	const enum stream_state state = s->state;
	const bool tx_shutdown = s->tx_shutdown;
	/* The peer (fds[0]) must observe EOF on its read side, confirming
	 * that shutdown(SHUT_WR) was actually issued on fds[1]. */
	char buf[1];
	const ssize_t n = recv(fx.fds[0], buf, sizeof(buf), MSG_DONTWAIT);

	/* fds[1] was transferred to the stream; do not double-close it. */
	fx.fds[1] = -1;
	stream_free(s);
	teardown_fixture(&fx);

	/* Both half-closes exchanged: stream must be CLOSED. */
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	/* write-shutdown flag must be set regardless of rx_eof. */
	T_EXPECT(tx_shutdown);
	T_EXPECT_EQ(n, (ssize_t)0);
}

/* Regression: stream_recv_fin() must not touch s after stream_mark_closed()
 * because last-stream drain teardown can free it synchronously. */
T_DECLARE_CASE(test_stream_recv_fin_survives_last_stream_freed_by_scheduler)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	/* Production registers an open stream into the session's table (stream_new
	 * itself does not); sched_free_streams below only frees what is tracked. */
	T_CHECK(sched_add_stream(&fx.ss, s));

	/* Both FINs about to be exchanged, no buffered recv data, socket mode:
	 * the exact preconditions that lead stream_recv_fin into
	 * stream_mark_closed(). */
	s->state = STREAM_FIN_WAIT;
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_NONE);
	s->socket.connected = true;

	g_sched_check_no_active_streams_calls = 0;
	g_free_streams_on_check = true;
	/* stream_mark_closed() closes fds[1] itself before s is freed below. */
	fx.fds[1] = -1;

	/* must not dereference s past stream_mark_closed() */
	stream_recv_fin(s);

	const int calls = g_sched_check_no_active_streams_calls;
	/* sched_free_streams() ran and cleared the table; nothing left to free. */
	const bool freed = (fx.ss.sched.streams == NULL);

	teardown_fixture(&fx);

	T_EXPECT_EQ(calls, 1);
	T_EXPECT(freed);
}

/* Regression: local_cb() must not touch s after stream_on_send() closes the
 * last active stream of a draining session and the scheduler frees it. A
 * socket-mode stream in STREAM_CLOSING with queued recv data becomes writable;
 * local_cb -> stream_on_send -> stream_flush_local drains the tail, reaches
 * stream_mark_closed, and the drain cascade frees s -- the post-flush
 * update_watcher(s) would then dereference freed memory. */
T_DECLARE_CASE(test_local_cb_survives_last_stream_freed_on_flush)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	T_CHECK(sched_add_stream(&fx.ss, s));

	/* Socket mode, connected, both FINs exchanged (CLOSING), a small recv
	 * tail still queued to the local socket: the exact state that leads
	 * stream_flush_local into stream_mark_closed once the queue drains. */
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_WRITE);
	s->socket.connected = true;
	s->state = STREAM_CLOSING;
	unsigned char payload[8] = { 0 };
	memcpy(bytebuf_write_ptr(s->recvbuf), payload, sizeof(payload));
	bytebuf_produce(s->recvbuf, sizeof(payload));
	s->buffered_bytes = (uint_least32_t)sizeof(payload);
	s->session->recv_buffered_bytes = sizeof(payload);

	g_sched_check_no_active_streams_calls = 0;
	g_free_streams_on_check = true;
	/* stream_mark_closed() closes fds[1] before the stream is freed. */
	fx.fds[1] = -1;

	/* Drive local_cb for a writable socket; the flush frees s, and local_cb
	 * must not dereference it afterward. */
	ev_invoke(fx.loop, &s->socket.w_io, EV_WRITE);

	const int calls = g_sched_check_no_active_streams_calls;
	const bool freed = (fx.ss.sched.streams == NULL);

	teardown_fixture(&fx);

	T_EXPECT_EQ(calls, 1);
	T_EXPECT(freed);
}

/* stream_on_send(): a not-yet-connected socket stream whose local connect
 * fails is aborted by local_on_connected(); on the last active stream of a
 * draining session the abort frees s via the drain cascade, so stream_on_send()
 * must not read s->state (nor flush) afterward. */
T_DECLARE_CASE(test_stream_on_send_survives_last_stream_freed_on_connect_fail)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	T_CHECK(sched_add_stream(&fx.ss, s));

	/* Socket mode, EV_WRITE-armed, local connect still in progress. A
	 * non-socket fd makes socket_get_error() report a failure, so
	 * local_on_connected() aborts the stream. */
	int pfd[2];
	T_CHECK(pipe(pfd) == 0);
	ev_io_set(&s->socket.w_io, pfd[1], EV_WRITE);
	s->socket.connected = false;

	g_sched_check_no_active_streams_calls = 0;
	g_free_streams_on_check = true;
	/* stream_mark_closed() closes the watcher fd (the write end) before the
	 * stream is freed; the read end is ours to reclaim. */
	(void)close(pfd[0]);

	/* Drive local_cb for a writable socket; the connect-failure abort frees
	 * s, and stream_on_send()/local_cb must not dereference it afterward. */
	ev_invoke(fx.loop, &s->socket.w_io, EV_WRITE);

	const int calls = g_sched_check_no_active_streams_calls;
	const bool freed = (fx.ss.sched.streams == NULL);

	teardown_fixture(&fx);

	T_EXPECT_EQ(calls, 1);
	T_EXPECT(freed);
}

/* auto_stream_window: when stream_window is reduced below recv_window,
 * stream_check_ack must shrink recv_window once no outstanding peer credit
 * remains and all buffered bytes fit the new target. */
T_DECLARE_CASE(test_stream_check_ack_shrinks_recv_window_when_safe)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.auto_stream_window = true;
	/* New BDP target: 2 frames. */
	fx.ss.stream_window = 2;

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);

	/* Force recv_window to a larger old value. */
	const uint_fast32_t old_window = (uint_fast32_t)8u * MUX_WINDOW_UNIT;
	s->recv_window = old_window;
	/* No outstanding credit: grant_sent == bytes_received. */
	s->grant_sent = 0;
	s->bytes_received = 0;
	s->buffered_bytes = 0;

	stream_check_ack(s);

	const uint_fast32_t expected =
		(uint_fast32_t)fx.ss.stream_window * MUX_WINDOW_UNIT;
	const uint_least32_t recv_window = s->recv_window;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(recv_window, expected);
}

/* stream_check_ack must NOT shrink recv_window while there is still
 * outstanding credit the peer may spend (buffered + outstanding > target). */
T_DECLARE_CASE(test_stream_check_ack_does_not_shrink_while_outstanding)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.auto_stream_window = true;
	/* New BDP target: 2 frames. */
	fx.ss.stream_window = 2;

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);

	const uint_fast32_t old_window = (uint_fast32_t)8u * MUX_WINDOW_UNIT;
	s->recv_window = old_window;

	/* Peer still has three frames of outstanding credit, which exceeds the
	 * two-frame target: buffered(0) + outstanding(3) > target(2). */
	s->bytes_received = 0;
	s->grant_sent = 3u * (uint_least32_t)MUX_WINDOW_UNIT;
	s->buffered_bytes = 0;

	const uint_fast32_t target =
		(uint_fast32_t)fx.ss.stream_window * MUX_WINDOW_UNIT;
	/* outstanding > target so the shrink must be deferred. */
	const bool precondition =
		(uint_fast32_t)(s->grant_sent - s->bytes_received) > target;

	stream_check_ack(s);

	const uint_least32_t recv_window = s->recv_window;

	stream_free(s);
	teardown_fixture(&fx);

	T_CHECK(precondition);
	T_EXPECT_EQ(recv_window, old_window);
}

T_DECLARE_CASE(test_stream_format_tag_formats_id_string)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);

	char buf[256];
	const int ret = stream_format_tag(buf, sizeof(buf), s);
	const bool nonempty = (buf[0] != '\0');

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(ret > 0);
	T_EXPECT(nonempty);
}

T_DECLARE_CASE(test_stream_mark_syn_sent_advances_state)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	/* stream_new with active_open=true starts in STREAM_INIT. */
	struct mux_stream *const s = stream_new(&fx.ss, 1, true);
	T_CHECK(s != NULL);
	const enum stream_state init_state = s->state;

	stream_mark_syn_sent(s);
	const enum stream_state syn_state = s->state;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(init_state, (enum stream_state)STREAM_INIT);
	T_EXPECT_EQ(syn_state, (enum stream_state)STREAM_SYN_SENT);
}

/* Race condition tests */

T_DECLARE_CASE(test_syn_received_rst_before_attach)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = stream_new(&fx.ss, 2, false);
	T_CHECK(s != NULL);
	T_CHECK(sched_add_stream(&fx.ss, s));
	const enum stream_state state_before = s->state;
	const bool halfopen_before = s->halfopen_counted;
	stream_recv_rst(s, MUX_STATUS_NO_ERROR);
	const enum stream_state state_after = s->state;
	const bool rst_received = s->rst_received;
	const bool halfopen_after = s->halfopen_counted;
	/* stream is now owned by sched LP queue; teardown_fixture frees it. */
	teardown_fixture(&fx);

	T_EXPECT_EQ(state_before, (enum stream_state)STREAM_SYN_RECEIVED);
	T_EXPECT(halfopen_before);
	T_EXPECT_EQ(state_after, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(rst_received);
	T_EXPECT(!halfopen_after);
}

T_DECLARE_CASE(test_halfopen_release_before_free)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->halfopen_counted = true;
	fx.ss.num_halfopen = 1;
	const bool halfopen_set = s->halfopen_counted;
	const bool num_positive = (fx.ss.num_halfopen > 0);
	fx.ss.num_halfopen--;
	s->halfopen_counted = false;
	const size_t num_after = fx.ss.num_halfopen;
	const bool halfopen_clear = !s->halfopen_counted;
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(halfopen_set);
	T_CHECK(num_positive);
	T_EXPECT_EQ(num_after, (size_t)0);
	T_EXPECT(halfopen_clear);
}

/* stream_format_tag endpoint rendering: identity strings, peer_identity,
 * peer_id, and the fd-fallback when no address is available. */
T_DECLARE_CASE(test_stream_format_tag_endpoint_variants)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	char buf[256];

	char id_buf[] = "local-id";
	char peer_ident[] = "peer-ident";
	char peer_id_buf[] = "peer-id";

	/* identity set -> "%s" branch for the local endpoint. */
	fx.ss.handshake.identity = id_buf;
	fx.ss.handshake.peer_identity = peer_ident; /* peer_identity branch */
	const bool r1 = (stream_format_tag(buf, sizeof(buf), s) > 0);

	/* No identity and an unusable fd -> "[fd:%d]" local fallback; peer_id
	 * branch for the peer endpoint. */
	fx.ss.handshake.identity = NULL;
	fx.ss.handshake.peer_identity = NULL;
	fx.ss.handshake.peer_id = peer_id_buf;
	const int saved_fd = fx.ss.w_socket.fd;
	fx.ss.w_socket.fd = -1;
	const bool r2 = (stream_format_tag(buf, sizeof(buf), s) > 0);
	fx.ss.w_socket.fd = saved_fd;
	fx.ss.handshake.peer_id = NULL;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(r1);
	T_EXPECT(r2);
}

/* session_pressure_scale via stream_grant_inc: no buffering, below the low
 * watermark, and the linear-decay band between watermarks. */
T_DECLARE_CASE(test_stream_pressure_scale_branches)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	fx.ss.conf.mem_pressure_lo = 2 * (int)MUX_MAX_FRAME_SIZE;
	fx.ss.conf.mem_pressure_hi = 4 * (int)MUX_MAX_FRAME_SIZE;
	fx.ss.stream_window = 8;

	struct mux_stream *const s = stream_new(&fx.ss, 1, true);
	T_CHECK(s != NULL);
	s->state = STREAM_ESTABLISHED;
	s->grant_sent = 0;

	/* pressure enabled but nothing buffered -> scale 1.0 */
	fx.ss.recv_buffered_bytes = 0;
	const bool b1 = (stream_grant_inc(s) > 0);
	/* buffered below the low watermark -> scale 1.0 */
	fx.ss.recv_buffered_bytes = (size_t)MUX_MAX_FRAME_SIZE;
	const bool b2 = (stream_grant_inc(s) > 0);
	/* buffered in the linear-decay band -> 0 < scale < 1.0 */
	fx.ss.recv_buffered_bytes = 3 * (size_t)MUX_MAX_FRAME_SIZE;
	const bool b3 = (stream_grant_inc(s) > 0);

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(b1);
	T_EXPECT(b2);
	T_EXPECT(b3);
}

/* stream_recv_copy: discards data in CLOSED state, and aborts on a receive
 * window overflow. */
T_DECLARE_CASE(test_stream_recv_copy_closed_and_overflow)
{
	unsigned char payload[64] = { 0 };
	{
		struct stream_fixture fx;
		if (setup_fixture(&fx) != 0) {
			T_FATAL("setup_fixture failed");
			return;
		}
		struct mux_stream *const s = make_stream(&fx, 1);
		T_CHECK(s != NULL);
		s->state = STREAM_CLOSED;
		stream_recv_copy(s, payload, sizeof(payload));
		stream_free(s);
		teardown_fixture(&fx);
	}
	{
		struct stream_fixture fx;
		if (setup_fixture(&fx) != 0) {
			T_FATAL("setup_fixture failed");
			return;
		}
		struct mux_stream *const s = make_stream(&fx, 1);
		T_CHECK(s != NULL);
		s->state = STREAM_ESTABLISHED;
		s->recv_window = 16;
		s->buffered_bytes = 8;
		stream_recv_copy(s, payload, sizeof(payload)); /* 8+64 > 16 */
		const enum stream_state state = s->state;
		stream_free(s);
		teardown_fixture(&fx);
		T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	}
}

/* stream_recv_window: aborts on excessive credit and no-ops when both the
 * outstanding credit and the increment are zero. */
T_DECLARE_CASE(test_stream_recv_window_excessive_and_exhausted)
{
	{
		struct stream_fixture fx;
		if (setup_fixture(&fx) != 0) {
			T_FATAL("setup_fixture failed");
			return;
		}
		struct mux_stream *const s = make_stream(&fx, 1);
		T_CHECK(s != NULL);
		s->send_window = (uint_least32_t)INT32_MAX;
		s->bytes_sent = 0;
		stream_recv_window(s, 1); /* outstanding+inc > INT32_MAX */
		const enum stream_state state = s->state;
		stream_free(s);
		teardown_fixture(&fx);
		T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	}
	{
		struct stream_fixture fx;
		if (setup_fixture(&fx) != 0) {
			T_FATAL("setup_fixture failed");
			return;
		}
		struct mux_stream *const s = make_stream(&fx, 1);
		T_CHECK(s != NULL);
		s->send_window = 0;
		s->bytes_sent = 0;
		stream_recv_window(s, 0); /* outstanding == inc == 0 */
		const enum stream_state state = s->state;
		stream_free(s);
		teardown_fixture(&fx);
		T_EXPECT_EQ(state, (enum stream_state)STREAM_ESTABLISHED);
	}
}

/* stream_mark_fin_sent in an unexpected state logs a warning and is otherwise
 * inert. */
T_DECLARE_CASE(test_stream_mark_fin_sent_unexpected_state)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->state = STREAM_SYN_SENT; /* neither ESTABLISHED nor CLOSE_WAIT */
	stream_mark_fin_sent(s);
	const enum stream_state state = s->state;
	stream_free(s);
	teardown_fixture(&fx);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_SYN_SENT);
}

/* stream_check_ack early returns: CLOSED state and an already-pending ACK. */
T_DECLARE_CASE(test_stream_check_ack_early_returns)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);

	s->state = STREAM_CLOSED;
	stream_check_ack(s); /* returns immediately */

	s->state = STREAM_ESTABLISHED;
	s->ack_pending = true;
	stream_check_ack(s); /* returns after the shrink attempt */
	const bool ack_pending = s->ack_pending;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(ack_pending);
}

/* timeout_cb aborts the stream on a local-socket send timeout. */
T_DECLARE_CASE(test_stream_timeout_cb_aborts)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->state = STREAM_ESTABLISHED;
	timeout_cb(fx.ss.loop, &s->socket.w_timeout, EV_TIMER);
	const enum stream_state state = s->state;
	stream_free(s);
	teardown_fixture(&fx);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
}

/* tombstone_cb decrements the tombstone count and re-enters cleanup. */
T_DECLARE_CASE(test_stream_tombstone_cb_decrements)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->state = STREAM_CLOSED;
	fx.ss.sched.num_tombstones = 1;
	tombstone_cb(fx.ss.loop, &s->w_tombstone, EV_TIMER);
	const size_t num_tombstones = fx.ss.sched.num_tombstones;
	stream_free(s);
	teardown_fixture(&fx);
	T_EXPECT_EQ(num_tombstones, (size_t)0);
}

/* stream_close on an already-CLOSED stream is a no-op. */
T_DECLARE_CASE(test_stream_close_idempotent_when_closed)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->state = STREAM_CLOSED;
	stream_close(s);
	const enum stream_state state = s->state;
	stream_free(s);
	teardown_fixture(&fx);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
}

/* stream_attach_fd: a SYN|ACK send failure (simulated OOM) must not
 * transition to ESTABLISHED; the stream aborts locally and the fd (ownership
 * already transferred in) is still closed rather than leaked. */
T_DECLARE_CASE(test_stream_attach_fd_syn_ack_failure_aborts)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = stream_new(&fx.ss, 3, false);
	T_CHECK(s != NULL);
	const enum stream_state initial_state = s->state;

	int local_fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, local_fds) == 0);

	g_session_send_ctrl_fail = true;
	stream_attach_fd(s, local_fds[0]);
	g_session_send_ctrl_fail = false;

	const enum stream_state state = s->state;
	const bool aborted = s->aborted;
	/* stream_mark_closed() must have closed local_fds[0] already. */
	const bool fd_closed =
		(fcntl(local_fds[0], F_GETFD) == -1 && errno == EBADF);

	(void)close(local_fds[1]);
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(initial_state, (enum stream_state)STREAM_SYN_RECEIVED);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(aborted);
	T_EXPECT(fd_closed);
}

/* stream_mark_closed's tombstone branch must evaluate whether this was the last
 * active stream right away, instead of only when sched_remove_stream eventually
 * runs (previously up to MUX_TOMBSTONE_PERIOD_S later, at tombstone_cb). */
T_DECLARE_CASE(test_stream_close_checks_no_active_streams_immediately)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s =
		make_stream(&fx, 1); /* STREAM_ESTABLISHED */
	T_CHECK(s != NULL);
	g_sched_check_no_active_streams_calls = 0;

	stream_close(s);

	const enum stream_state state = s->state;
	const size_t num_tombstones = fx.ss.sched.num_tombstones;
	const int calls = g_sched_check_no_active_streams_calls;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT_EQ(num_tombstones, (size_t)1);
	T_EXPECT_EQ(calls, 1);
}

/* A stream that never left STREAM_INIT has no peer-visible state to linger
 * (no tombstone), so it takes the sched_wake path instead -- the immediate
 * check above does not apply and must not run. */
T_DECLARE_CASE(test_stream_close_from_init_skips_no_active_streams_check)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = stream_new(&fx.ss, 1, true);
	T_CHECK(s != NULL);
	const enum stream_state initial_state = s->state;
	g_sched_check_no_active_streams_calls = 0;

	stream_close(s);

	const enum stream_state state = s->state;
	const size_t num_tombstones = fx.ss.sched.num_tombstones;
	const int calls = g_sched_check_no_active_streams_calls;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(initial_state, (enum stream_state)STREAM_INIT);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT_EQ(num_tombstones, (size_t)0);
	T_EXPECT_EQ(calls, 0);
}

static int g_stream_io_test_events;

static void
stream_io_test_cb(struct ev_loop *loop, struct mux_stream_io *w, int revents)
{
	(void)loop;
	(void)w;
	g_stream_io_test_events |= revents;
}

/* stream_io_start: a SYN|ACK send failure (simulated OOM) must not
 * transition to ESTABLISHED; the watcher must still be notified (EV_READ)
 * and detached rather than left attached with no event ever delivered. Because
 * stream_abort severs the binding, it must also return false -- returning true
 * would contradict the "true => watcher bound" contract and leave the caller
 * waiting on a detached watcher. */
T_DECLARE_CASE(test_stream_io_start_syn_ack_failure_notifies_and_detaches)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = stream_new(&fx.ss, 3, false);
	T_CHECK(s != NULL);
	const enum stream_state initial_state = s->state;

	struct mux_stream_io w = { 0 };
	mux_stream_io_init(&w, stream_io_test_cb, s, EV_READ);

	g_stream_io_test_events = 0;
	g_session_send_ctrl_fail = true;
	const bool started = stream_io_start(fx.loop, &w);
	g_session_send_ctrl_fail = false;

	const enum stream_state state = s->state;
	const bool aborted = s->aborted;
	const bool notified = ((g_stream_io_test_events & EV_READ) != 0);
	const bool w_detached = (w.stream == NULL);
	const int w_active = w.active;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(initial_state, (enum stream_state)STREAM_SYN_RECEIVED);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(aborted);
	T_EXPECT(notified);
	T_EXPECT(w_detached);
	T_EXPECT_EQ(w_active, 0);
	T_EXPECT(!started);
}

/* An application that defers attaching (e.g. a local connect() still pending)
 * can find the stream already gone by the time it calls back -- a peer RST is
 * enough to leave it in a state neither stream_attach_fd nor stream_io_start
 * ever expected to see. Both must reject gracefully instead of asserting on a
 * peer-triggerable condition. */
T_DECLARE_CASE(test_stream_attach_fd_rejects_gracefully_after_close)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = stream_new(&fx.ss, 3, false);
	T_CHECK(s != NULL);
	s->state = STREAM_CLOSED; /* simulates a peer RST beating the attach */

	int local_fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, local_fds) == 0);

	stream_attach_fd(s, local_fds[0]);

	const enum stream_state state = s->state; /* untouched */
	/* Ownership of the fd was taken and it was closed, not leaked. */
	const bool fd_closed =
		(fcntl(local_fds[0], F_GETFD) == -1 && errno == EBADF);

	(void)close(local_fds[1]);
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(fd_closed);
}

T_DECLARE_CASE(test_stream_io_start_rejects_gracefully_after_close)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = stream_new(&fx.ss, 3, false);
	T_CHECK(s != NULL);
	s->state = STREAM_CLOSED; /* simulates a peer RST beating the attach */

	struct mux_stream_io w = { 0 };
	mux_stream_io_init(&w, stream_io_test_cb, s, EV_READ);

	g_stream_io_test_events = 0;
	stream_io_start(fx.loop, &w);

	const enum stream_state state = s->state; /* untouched */
	const bool not_direct = !s->is_direct; /* direct mode never activated */
	const int w_active = w.active;
	const int events = g_stream_io_test_events;

	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(not_direct);
	T_EXPECT_EQ(w_active, 0);
	T_EXPECT_EQ(events, 0);
}

/* Direct-mode user watcher callback that closes its stream, exercising the
 * re-entrant close the RST-notify sites explicitly sanction. The production
 * entry point is mux_stream_close() (mux.c, not linked into this white-box TU);
 * with unread data buffered it dispatches to stream_close(), the function that
 * actually reaches stream_mark_closed() and thus the drain cascade, so the
 * callback invokes stream_close() directly. */
static void
stream_io_close_cb(struct ev_loop *loop, struct mux_stream_io *w, int revents)
{
	(void)loop;
	(void)revents;
	stream_close(w->stream);
}

/* Wire a started direct-mode user watcher onto s, mirroring stream_io_start's
 * activation (loop/active set, s->direct.w_io pointed at w). */
static void attach_direct_io(
	struct stream_fixture *restrict fx, struct mux_stream *restrict s,
	struct mux_stream_io *restrict w)
{
	mux_stream_io_init(w, stream_io_close_cb, s, EV_READ);
	w->loop = fx->loop;
	w->active = 1;
	s->is_direct = true;
	s->direct.w_io = w;
}

/* Regression: for a direct-mode stream, stream_recv_rst() synchronously invokes
 * the user's EV_READ callback (stream_rst_notify_direct -> ev_invoke). That
 * callback may call mux_stream_close(); on the last active stream of a draining
 * session the resulting stream_mark_closed() cascades into
 * session_initiate_shutdown -> sched_free_streams and frees s. stream_recv_rst()
 * must not read s->state (nor run the recv-buffer bookkeeping) afterward. */
T_DECLARE_CASE(test_stream_recv_rst_survives_reentrant_close_freeing_stream)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	T_CHECK(sched_add_stream(&fx.ss, s));

	/* Buffer unread recv data so the re-entrant mux_stream_close() takes the
	 * stream_close() (RST) path -- which reaches stream_mark_closed() and thus
	 * the drain cascade -- rather than the graceful stream_shutdown() path. */
	unsigned char payload[16] = { 0 };
	struct mux_stream_io w = { 0 };
	attach_direct_io(&fx, s, &w);
	stream_recv_copy(s, payload, sizeof(payload));

	g_sched_check_no_active_streams_calls = 0;
	g_free_streams_on_check = true;

	/* The RST notify invokes stream_io_close_cb -> stream_close(); the drain
	 * cascade frees s, and stream_recv_rst() must not touch it after. */
	stream_recv_rst(s, MUX_STATUS_CANCEL);

	const int calls = g_sched_check_no_active_streams_calls;
	/* sched_free_streams() ran and cleared the table; s is gone. */
	const bool freed = (fx.ss.sched.streams == NULL);
	const int w_active = w.active; /* stream_close() detached the watcher */

	teardown_fixture(&fx);

	T_EXPECT_EQ(calls, 1);
	T_EXPECT(freed);
	T_EXPECT_EQ(w_active, 0);
}

/* Regression: same drain-cascade hazard for stream_abort(), which likewise
 * fires the direct-mode EV_READ callback (stream_rst_notify_direct) before
 * reading s->state. A re-entrant mux_stream_close() on the last active stream
 * of a draining session frees s; stream_abort() must not read s->state after. */
T_DECLARE_CASE(test_stream_abort_survives_reentrant_close_freeing_stream)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	T_CHECK(sched_add_stream(&fx.ss, s));

	unsigned char payload[16] = { 0 };
	struct mux_stream_io w = { 0 };
	attach_direct_io(&fx, s, &w);
	stream_recv_copy(s, payload, sizeof(payload));

	g_sched_check_no_active_streams_calls = 0;
	g_free_streams_on_check = true;

	/* The abort notify invokes stream_io_close_cb -> stream_close(); the drain
	 * cascade frees s, and stream_abort() must not touch it after. */
	stream_abort(s, MUX_STATUS_INTERNAL_ERROR);

	const int calls = g_sched_check_no_active_streams_calls;
	const bool freed = (fx.ss.sched.streams == NULL);
	const int w_active = w.active;

	teardown_fixture(&fx);

	T_EXPECT_EQ(calls, 1);
	T_EXPECT(freed);
	T_EXPECT_EQ(w_active, 0);
}

/* Socket-mode local read path -- the only mode the shipped daemon uses.
 * local_cb's EV_READ branch drives stream_on_recv, which reads the local fd,
 * clamps the read to stream_read_credit_avail(), and queues the payload as a
 * send frame. Credit (10) is smaller than both the 64 bytes available and the
 * frame capacity, so exactly 10 bytes are read and read-credit falls to 0. */
T_DECLARE_CASE(test_local_cb_ev_read_queues_frame_clamped_to_credit)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	/* Socket mode, connected, reading from fds[1]; the peer writes fds[0]. */
	s->is_direct = false;
	s->socket.connected = true;
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_READ);
	(void)fcntl(fx.fds[1], F_SETFL, O_NONBLOCK);
	/* Grant only 10 bytes of send credit so the read is clamped below both
	 * the 64 bytes available and the frame capacity. */
	s->send_window = 10;
	s->bytes_sent = 0;
	s->queued_send_bytes = 0;

	unsigned char payload[64] = { 0 };
	const ssize_t nw = write(fx.fds[0], payload, sizeof(payload));
	T_CHECK(nw == (ssize_t)sizeof(payload));

	const uint_fast32_t credit_before = stream_read_credit_avail(s);
	ev_invoke(fx.loop, &s->socket.w_io, EV_READ);

	const bool queued = (s->send_queue.head != NULL);
	const size_t payload_len =
		queued ? s->send_queue.head->len - MUX_FRAME_HEADER_SIZE : 0;
	const uint_least32_t queued_bytes = s->queued_send_bytes;
	const uint_fast32_t credit_after = stream_read_credit_avail(s);

	/* fds[1] was handed to the stream; do not double-close it. */
	fx.fds[1] = -1;
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(credit_before, (uint_fast32_t)10);
	T_EXPECT(queued);
	T_EXPECT_EQ(payload_len, (size_t)10);
	T_EXPECT_EQ(queued_bytes, (uint_least32_t)10);
	T_EXPECT_EQ(credit_after, (uint_fast32_t)0);
}

/* stream_on_recv's EOF branch: a zero-length read (peer closed the socket)
 * sets rx_eof and queues no frame. */
T_DECLARE_CASE(test_local_cb_ev_read_marks_rx_eof_on_peer_close)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = false;
	s->socket.connected = true;
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_READ);
	(void)fcntl(fx.fds[1], F_SETFL, O_NONBLOCK);
	/* Close the peer end so the stream's read observes EOF. */
	(void)close(fx.fds[0]);
	fx.fds[0] = -1;

	ev_invoke(fx.loop, &s->socket.w_io, EV_READ);

	const bool rx_eof = s->rx_eof;
	const bool queued = (s->send_queue.head != NULL);

	fx.fds[1] = -1;
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(rx_eof);
	T_EXPECT(!queued);
}

/* stream_on_recv pauses (reads nothing, queues nothing, no spurious EOF) when
 * send credit is exhausted, so the local socket stays readable for when credit
 * returns. */
T_DECLARE_CASE(test_local_cb_ev_read_pauses_on_zero_credit)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = false;
	s->socket.connected = true;
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_READ);
	(void)fcntl(fx.fds[1], F_SETFL, O_NONBLOCK);
	/* No send credit: outstanding == send_window. */
	s->send_window = 0;
	s->bytes_sent = 0;
	s->queued_send_bytes = 0;

	unsigned char payload[16] = { 0 };
	const ssize_t nw = write(fx.fds[0], payload, sizeof(payload));
	T_CHECK(nw == (ssize_t)sizeof(payload));

	ev_invoke(fx.loop, &s->socket.w_io, EV_READ);

	const bool queued = (s->send_queue.head != NULL);
	const bool rx_eof = s->rx_eof;

	fx.fds[1] = -1;
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT(!queued);
	T_EXPECT(!rx_eof);
}

/* Socket-mode fast path in stream_recv_copy: with an empty recvbuf and a
 * connected socket, the payload is written straight to the local fd, skipping
 * the recvbuf. EV_WRITE is armed so stream_notify_readable would NOT eager-
 * flush -- the bytes therefore reach the peer via the fast path, not a later
 * drain -- and buffered_bytes/recvbuf stay untouched. */
T_DECLARE_CASE(test_stream_recv_copy_socket_fast_path_writes_to_fd)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = false;
	s->socket.connected = true;
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_WRITE);
	s->recv_window = 65536;
	s->grant_sent = 65536;
	s->bytes_received = 0;

	unsigned char payload[16];
	for (size_t i = 0; i < sizeof(payload); i++) {
		payload[i] = (unsigned char)(i + 1);
	}
	stream_recv_copy(s, payload, sizeof(payload));

	const uint_least32_t received = s->bytes_received;
	const uint_least32_t buffered = s->buffered_bytes;
	const size_t recvbuf_readable = bytebuf_readable(s->recvbuf);
	unsigned char got[32] = { 0 };
	const ssize_t n = recv(fx.fds[0], got, sizeof(got), MSG_DONTWAIT);
	const bool payload_matches =
		(n == (ssize_t)sizeof(payload)) &&
		(memcmp(got, payload, sizeof(payload)) == 0);

	fx.fds[1] = -1;
	stream_free(s);
	teardown_fixture(&fx);

	T_EXPECT_EQ(received, (uint_least32_t)sizeof(payload));
	T_EXPECT_EQ(buffered, (uint_least32_t)0);
	T_EXPECT_EQ(recvbuf_readable, (size_t)0);
	T_EXPECT(payload_matches);
}

/* stream_notify_readable's socket branch, happy path: with the write watcher
 * idle and data freshly buffered (fast path skipped by a non-empty recvbuf), it
 * eager-flushes the recvbuf to the local fd so the peer receives it without
 * waiting for a coalesced EV_WRITE drain. */
T_DECLARE_CASE(test_stream_recv_copy_notify_readable_eager_flush)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	s->is_direct = false;
	s->socket.connected = true;
	/* Valid fd, write watcher idle (no EV_WRITE). */
	ev_io_set(&s->socket.w_io, fx.fds[1], EV_NONE);
	s->recv_window = 65536;
	s->grant_sent = 65536;
	/* Non-empty recvbuf so stream_recv_copy skips the fast path and reaches
	 * stream_notify_readable. */
	unsigned char seed[4] = { 0xAA, 0xAA, 0xAA, 0xAA };
	memcpy(bytebuf_write_ptr(s->recvbuf), seed, sizeof(seed));
	bytebuf_produce(s->recvbuf, sizeof(seed));
	s->buffered_bytes = (uint_least32_t)sizeof(seed);
	s->session->recv_buffered_bytes = sizeof(seed);

	unsigned char payload[4] = { 0xBB, 0xBB, 0xBB, 0xBB };
	stream_recv_copy(s, payload, sizeof(payload));

	const uint_least32_t buffered = s->buffered_bytes;
	const size_t recvbuf_readable = bytebuf_readable(s->recvbuf);
	unsigned char got[16] = { 0 };
	const ssize_t n = recv(fx.fds[0], got, sizeof(got), MSG_DONTWAIT);

	fx.fds[1] = -1;
	stream_free(s);
	teardown_fixture(&fx);

	/* Both the seeded and the new payload were flushed to the peer. */
	T_EXPECT_EQ(n, (ssize_t)8);
	T_EXPECT_EQ(buffered, (uint_least32_t)0);
	T_EXPECT_EQ(recvbuf_readable, (size_t)0);
}

/* Drain-cascade UAF guard in stream_recv_copy's fast path: stream_local_write
 * hits a hard error (fd == -1 -> EBADF) and stream_abort frees s via the
 * last-active-stream drain cascade; stream_recv_copy must not read s->state
 * (nor fall through to the recvbuf) afterward. Removing the guard trips ASan. */
T_DECLARE_CASE(test_stream_recv_copy_fast_path_survives_last_stream_freed)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	T_CHECK(sched_add_stream(&fx.ss, s));
	/* Socket mode, connected, empty recvbuf, but a write-failing fd so the
	 * fast-path write hard-errors and aborts the stream. */
	s->is_direct = false;
	s->socket.connected = true;
	s->socket.w_io.fd = -1;
	s->recv_window = 65536;
	s->grant_sent = 65536;

	g_sched_check_no_active_streams_calls = 0;
	g_free_streams_on_check = true;

	unsigned char payload[16] = { 0 };
	/* The fast-path write aborts the last active stream of the draining
	 * session; the cascade frees s. stream_recv_copy must not touch it after. */
	stream_recv_copy(s, payload, sizeof(payload));

	const int calls = g_sched_check_no_active_streams_calls;
	const bool freed = (fx.ss.sched.streams == NULL);

	teardown_fixture(&fx);

	T_EXPECT_EQ(calls, 1);
	T_EXPECT(freed);
}

/* Drain-cascade UAF guard in stream_notify_readable's socket branch: with data
 * already buffered (fast path skipped), the new payload lands in the recvbuf
 * and stream_notify_readable eager-flushes it; the write hard-errors (fd ==
 * -1), stream_abort frees the last active stream via the drain cascade, and
 * stream_notify_readable must not touch s (update_watcher/feed_user) after.
 * Removing the guard trips ASan. */
T_DECLARE_CASE(test_stream_notify_readable_survives_last_stream_freed)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = make_stream(&fx, 1);
	T_CHECK(s != NULL);
	T_CHECK(sched_add_stream(&fx.ss, s));
	s->is_direct = false;
	s->socket.connected = true;
	s->socket.w_io.fd = -1; /* hard write error on flush */
	s->recv_window = 65536;
	s->grant_sent = 65536;

	/* Pre-buffer recv data so stream_recv_copy takes the slow path (the fast
	 * path requires an empty recvbuf) and reaches stream_notify_readable. */
	unsigned char seed[8] = { 0 };
	memcpy(bytebuf_write_ptr(s->recvbuf), seed, sizeof(seed));
	bytebuf_produce(s->recvbuf, sizeof(seed));
	s->buffered_bytes = (uint_least32_t)sizeof(seed);
	s->session->recv_buffered_bytes = sizeof(seed);

	g_sched_check_no_active_streams_calls = 0;
	g_free_streams_on_check = true;

	unsigned char payload[8] = { 0 };
	stream_recv_copy(s, payload, sizeof(payload));

	const int calls = g_sched_check_no_active_streams_calls;
	const bool freed = (fx.ss.sched.streams == NULL);

	teardown_fixture(&fx);

	T_EXPECT_EQ(calls, 1);
	T_EXPECT(freed);
}

static const struct testing_suite suite[] = {
	T_CASE(test_stream_grant_inc_uses_available_window),
	T_CASE(test_stream_grant_inc_scales_under_pressure),
	T_CASE(test_stream_dequeue_send_updates_queue_counters),
	T_CASE(test_stream_recv_window_grows_send_credit),
	T_CASE(test_stream_recv_window_gates_ev_write_on_sendable_state),
	T_CASE(test_stream_close_oom_abortive_rst_counts_failed),
	T_CASE(test_stream_recv_fin_advances_state),
	T_CASE(test_stream_recv_rst_discards_buffered_data),
	T_CASE(test_stream_recv_copy_aborts_over_granted_credit),
	T_CASE(test_stream_recv_copy_credit_check_survives_counter_wrap),
	T_CASE(test_stream_shutdown_completes_user_closed_closing_direct),
	T_CASE(test_stream_recv_rst_clears_stale_drr_active),
	T_CASE(test_stream_flush_local_hard_error_leaves_timer_stopped),
	T_CASE(test_stream_abort_clears_stale_drr_active),
	T_CASE(test_stream_close_with_unread_data_sends_rst),
	T_CASE(test_stream_close_after_peer_rst_sends_no_rst),
	T_CASE(test_stream_mark_fin_sent_closes_user_closed_direct_stream),
	T_CASE(test_stream_recv_fin_closes_user_closed_direct_stream),
	T_CASE(test_stream_recv_fin_user_closed_direct_rsts_buffered_data),
	T_CASE(test_stream_mark_fin_sent_user_closed_direct_rsts_buffered_data),
	T_CASE(test_stream_shutdown_marks_rx_eof),
	T_CASE(test_stream_recv_fin_with_rx_eof_shuts_down_write),
	T_CASE(test_stream_recv_fin_survives_last_stream_freed_by_scheduler),
	T_CASE(test_local_cb_survives_last_stream_freed_on_flush),
	T_CASE(test_stream_on_send_survives_last_stream_freed_on_connect_fail),
	T_CASE(test_stream_check_ack_shrinks_recv_window_when_safe),
	T_CASE(test_stream_check_ack_does_not_shrink_while_outstanding),
	T_CASE(test_stream_format_tag_formats_id_string),
	T_CASE(test_stream_mark_syn_sent_advances_state),
	T_CASE(test_syn_received_rst_before_attach),
	T_CASE(test_halfopen_release_before_free),
	T_CASE(test_stream_format_tag_endpoint_variants),
	T_CASE(test_stream_pressure_scale_branches),
	T_CASE(test_stream_recv_copy_closed_and_overflow),
	T_CASE(test_stream_recv_window_excessive_and_exhausted),
	T_CASE(test_stream_mark_fin_sent_unexpected_state),
	T_CASE(test_stream_check_ack_early_returns),
	T_CASE(test_stream_timeout_cb_aborts),
	T_CASE(test_stream_tombstone_cb_decrements),
	T_CASE(test_stream_close_idempotent_when_closed),
	T_CASE(test_stream_attach_fd_syn_ack_failure_aborts),
	T_CASE(test_stream_close_checks_no_active_streams_immediately),
	T_CASE(test_stream_close_from_init_skips_no_active_streams_check),
	T_CASE(test_stream_io_start_syn_ack_failure_notifies_and_detaches),
	T_CASE(test_stream_attach_fd_rejects_gracefully_after_close),
	T_CASE(test_stream_io_start_rejects_gracefully_after_close),
	T_CASE(test_stream_recv_rst_survives_reentrant_close_freeing_stream),
	T_CASE(test_stream_abort_survives_reentrant_close_freeing_stream),
	T_CASE(test_local_cb_ev_read_queues_frame_clamped_to_credit),
	T_CASE(test_local_cb_ev_read_marks_rx_eof_on_peer_close),
	T_CASE(test_local_cb_ev_read_pauses_on_zero_credit),
	T_CASE(test_stream_recv_copy_socket_fast_path_writes_to_fd),
	T_CASE(test_stream_recv_copy_notify_readable_eager_flush),
	T_CASE(test_stream_recv_copy_fast_path_survives_last_stream_freed),
	T_CASE(test_stream_notify_readable_survives_last_stream_freed),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	slog_level_ = LOG_LEVEL_VERYVERBOSE;

	return testing_main(argc, argv, suite);
}
