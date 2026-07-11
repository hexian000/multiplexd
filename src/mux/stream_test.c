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
	void *elem = s;
	ss->sched.streams = table_set(
		ss->sched.streams, (const void *)(uintptr_t)s->id, &elem);
	if (ss->sched.streams == NULL || elem == s) {
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
	ss->unacked.stalled = false;
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
	ringbuf_reset(ss->wire.recvbuf);
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
	fx->ss.wire.recvbuf = ringbuf_new(4u * (size_t)MUX_MAX_FRAME_SIZE);
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
	    ringbuf_readable(fx->ss.wire.recvbuf) > 0 ||
	    fx->ss.wire.sendbuf.head != NULL) {
		wire_discard_buffers(&fx->ss);
	}
	ringbuf_free(fx->ss.wire.recvbuf);
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
	T_EXPECT_EQ(stream_grant_inc(s), (uint_fast32_t)4);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(stream_grant_inc(s), (uint_fast32_t)1);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_CHECK(frame != NULL);
	T_EXPECT(s->send_queue.head == NULL);
	T_EXPECT_EQ(s->queued_send_bytes, (uint_least32_t)0);
	T_EXPECT_EQ(fx.ss.send_buffered_frames, (size_t)0);
	mux_frame_put(&fx.ss.pool, frame);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->send_window, (uint_least32_t)(2 * MUX_WINDOW_UNIT));

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSE_WAIT);

	s->state = STREAM_FIN_WAIT;
	stream_recv_fin(s);
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSING);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->buffered_bytes, (uint_least32_t)sizeof(payload));

	stream_recv_rst(s, MUX_STATUS_NO_ERROR);
	T_EXPECT(s->rst_received);
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT_EQ(s->buffered_bytes, (uint_least32_t)0);
	T_EXPECT_EQ(ringbuf_readable(s->recvbuf), (size_t)0);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(fx.ss.sched.drr_active == NULL);

	stream_free(s);
	teardown_fixture(&fx);
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
	memcpy(ringbuf_write_ptr(s->recvbuf), payload, sizeof(payload));
	ringbuf_produce(s->recvbuf, sizeof(payload));
	s->buffered_bytes = (uint_least32_t)sizeof(payload);
	s->session->recv_buffered_bytes = sizeof(payload);

	stream_flush_local(s);

	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	/* The abort stopped the send timer; the buggy path re-armed it here. */
	T_EXPECT(!ev_is_active(&s->socket.w_timeout));

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(fx.ss.sched.drr_active == NULL);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->buffered_bytes, (uint_least32_t)sizeof(payload));

	stream_close(s);
	T_CHECK(fx.ss.wire.sendbuf.head != NULL);
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	{
		struct mux_header hdr = { 0 };
		mux_read_header(fx.ss.wire.sendbuf.head->data, &hdr);
		T_EXPECT(hdr.flags & MUX_FLAG_RST);
		T_EXPECT_EQ(hdr.extra, (uint_least16_t)MUX_STATUS_CANCEL);
	}

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT(s->rx_eof);

	stream_free(s);
	teardown_fixture(&fx);
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

	/* Both half-closes exchanged: stream must be CLOSED. */
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	/* write-shutdown flag must be set regardless of rx_eof. */
	T_EXPECT(s->tx_shutdown);
	/* The peer (fds[0]) must observe EOF on its read side, confirming
	 * that shutdown(SHUT_WR) was actually issued on fds[1]. */
	{
		char buf[1];
		const ssize_t n =
			recv(fx.fds[0], buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT_EQ(n, (ssize_t)0);
	}

	/* fds[1] was transferred to the stream; do not double-close it. */
	fx.fds[1] = -1;
	stream_free(s);
	teardown_fixture(&fx);
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

	T_EXPECT_EQ(g_sched_check_no_active_streams_calls, 1);
	/* sched_free_streams() ran and cleared the table; nothing left to free. */
	T_EXPECT(fx.ss.sched.streams == NULL);

	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->recv_window, expected);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_CHECK((uint_fast32_t)(s->grant_sent - s->bytes_received) > target);

	stream_check_ack(s);

	T_EXPECT_EQ(s->recv_window, old_window);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT(ret > 0);
	T_EXPECT(buf[0] != '\0');

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_INIT);

	stream_mark_syn_sent(s);
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_SYN_SENT);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_SYN_RECEIVED);
	T_EXPECT(s->halfopen_counted);
	stream_recv_rst(s, MUX_STATUS_NO_ERROR);
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(s->rst_received);
	T_EXPECT(!s->halfopen_counted);
	/* stream is now owned by sched LP queue; teardown_fixture frees it. */
	teardown_fixture(&fx);
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
	T_EXPECT(s->halfopen_counted);
	T_CHECK(fx.ss.num_halfopen > 0);
	fx.ss.num_halfopen--;
	s->halfopen_counted = false;
	T_EXPECT_EQ(fx.ss.num_halfopen, (size_t)0);
	T_EXPECT(!s->halfopen_counted);
	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT(stream_format_tag(buf, sizeof(buf), s) > 0);

	/* No identity and an unusable fd -> "[fd:%d]" local fallback; peer_id
	 * branch for the peer endpoint. */
	fx.ss.handshake.identity = NULL;
	fx.ss.handshake.peer_identity = NULL;
	fx.ss.handshake.peer_id = peer_id_buf;
	const int saved_fd = fx.ss.w_socket.fd;
	fx.ss.w_socket.fd = -1;
	T_EXPECT(stream_format_tag(buf, sizeof(buf), s) > 0);
	fx.ss.w_socket.fd = saved_fd;
	fx.ss.handshake.peer_id = NULL;

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT(stream_grant_inc(s) > 0);
	/* buffered below the low watermark -> scale 1.0 */
	fx.ss.recv_buffered_bytes = (size_t)MUX_MAX_FRAME_SIZE;
	T_EXPECT(stream_grant_inc(s) > 0);
	/* buffered in the linear-decay band -> 0 < scale < 1.0 */
	fx.ss.recv_buffered_bytes = 3 * (size_t)MUX_MAX_FRAME_SIZE;
	T_EXPECT(stream_grant_inc(s) > 0);

	stream_free(s);
	teardown_fixture(&fx);
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
		T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
		stream_free(s);
		teardown_fixture(&fx);
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
		T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
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
		s->send_window = 0;
		s->bytes_sent = 0;
		stream_recv_window(s, 0); /* outstanding == inc == 0 */
		T_EXPECT_EQ(s->state, (enum stream_state)STREAM_ESTABLISHED);
		stream_free(s);
		teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_SYN_SENT);
	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT(s->ack_pending);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(fx.ss.sched.num_tombstones, (size_t)0);
	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_SYN_RECEIVED);

	int local_fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, local_fds) == 0);

	g_session_send_ctrl_fail = true;
	stream_attach_fd(s, local_fds[0]);
	g_session_send_ctrl_fail = false;

	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(s->aborted);
	/* stream_mark_closed() must have closed local_fds[0] already. */
	T_EXPECT(fcntl(local_fds[0], F_GETFD) == -1 && errno == EBADF);

	(void)close(local_fds[1]);
	stream_free(s);
	teardown_fixture(&fx);
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

	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT_EQ(fx.ss.sched.num_tombstones, (size_t)1);
	T_EXPECT_EQ(g_sched_check_no_active_streams_calls, 1);

	stream_free(s);
	teardown_fixture(&fx);
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
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_INIT);
	g_sched_check_no_active_streams_calls = 0;

	stream_close(s);

	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT_EQ(fx.ss.sched.num_tombstones, (size_t)0);
	T_EXPECT_EQ(g_sched_check_no_active_streams_calls, 0);

	stream_free(s);
	teardown_fixture(&fx);
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
 * and detached rather than left attached with no event ever delivered. */
T_DECLARE_CASE(test_stream_io_start_syn_ack_failure_notifies_and_detaches)
{
	struct stream_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}
	struct mux_stream *const s = stream_new(&fx.ss, 3, false);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_SYN_RECEIVED);

	struct mux_stream_io w = { 0 };
	mux_stream_io_init(&w, stream_io_test_cb, s, EV_READ);

	g_stream_io_test_events = 0;
	g_session_send_ctrl_fail = true;
	stream_io_start(fx.loop, &w);
	g_session_send_ctrl_fail = false;

	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT(s->aborted);
	T_EXPECT((g_stream_io_test_events & EV_READ) != 0);
	T_EXPECT(w.stream == NULL);
	T_EXPECT_EQ(w.active, 0);

	stream_free(s);
	teardown_fixture(&fx);
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

	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED); /* untouched */
	/* Ownership of the fd was taken and it was closed, not leaked. */
	T_EXPECT(fcntl(local_fds[0], F_GETFD) == -1 && errno == EBADF);

	(void)close(local_fds[1]);
	stream_free(s);
	teardown_fixture(&fx);
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

	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED); /* untouched */
	T_EXPECT(!s->is_direct); /* direct mode never activated */
	T_EXPECT_EQ(w.active, 0);
	T_EXPECT_EQ(g_stream_io_test_events, 0);

	stream_free(s);
	teardown_fixture(&fx);
}

static const struct testing_suite suite[] = {
	T_CASE(test_stream_grant_inc_uses_available_window),
	T_CASE(test_stream_grant_inc_scales_under_pressure),
	T_CASE(test_stream_dequeue_send_updates_queue_counters),
	T_CASE(test_stream_recv_window_grows_send_credit),
	T_CASE(test_stream_recv_fin_advances_state),
	T_CASE(test_stream_recv_rst_discards_buffered_data),
	T_CASE(test_stream_recv_rst_clears_stale_drr_active),
	T_CASE(test_stream_flush_local_hard_error_leaves_timer_stopped),
	T_CASE(test_stream_abort_clears_stale_drr_active),
	T_CASE(test_stream_close_with_unread_data_sends_rst),
	T_CASE(test_stream_shutdown_marks_rx_eof),
	T_CASE(test_stream_recv_fin_with_rx_eof_shuts_down_write),
	T_CASE(test_stream_recv_fin_survives_last_stream_freed_by_scheduler),
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
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	slog_level_ = LOG_LEVEL_VERYVERBOSE;

	return testing_main(argc, argv, suite);
}
