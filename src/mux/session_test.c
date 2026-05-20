/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/session.h"
#include "mux/stream.h"

#include "algo/hashtable.h"

#include "utils/testing.h"

#include <ev.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static struct mux_frame *session_test_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(sizeof(*frame));
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
		.session_window = 8,
		.stream_window = 4,
		.wire = {
			.rx_open = true,
		},
	};
	fx->ss.sched.streams = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_PTR.hash,
		.eq = TABLE_OPTS_PTR.eq,
		.flags = TABLE_FAST,
	});
	if (fx->ss.sched.streams == NULL) {
		close(fx->fds[0]);
		close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	ev_io_init(&fx->ss.w_socket, session_test_io_cb, fx->fds[0], EV_READ);
	fx->ss.w_socket.data = &fx->ss;
	ev_timer_init(&fx->ss.w_idle_timeout, session_test_timer_cb, 1.0, 0.0);
	fx->ss.w_idle_timeout.data = &fx->ss;
	sched_init(&fx->ss);
	fx->ss.wire.recvbuf = ringbuf_new(4u * (size_t)MUX_FRAME_SIZE);
	if (fx->ss.wire.recvbuf == NULL) {
		table_free(fx->ss.sched.streams);
		close(fx->fds[0]);
		close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
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
	mux_frame_list_clear(&fx->ss.unacked, &fx->ss.pool);
	if (fx->fds[0] >= 0) {
		close(fx->fds[0]);
		fx->fds[0] = -1;
	}
	if (fx->fds[1] >= 0) {
		close(fx->fds[1]);
		fx->fds[1] = -1;
	}
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

static struct mux_frame *make_frame(
	const struct mux_frame_allocator *restrict pool,
	const uint_least16_t stream_id, const uint_least8_t flags,
	const uint_least16_t extra, const void *restrict payload,
	const size_t payload_len)
{
	struct mux_frame *const frame = mux_frame_get(pool);
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

T_DECLARE_CASE(test_session_send_ctrl_packs_header_and_clamps_extra)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	T_EXPECT(session_send_ctrl(&fx.ss, 7, MUX_FLAG_ACK, UINT32_MAX));
	T_CHECK(fx.ss.wire.sendbuf.head != NULL);
	T_EXPECT(fx.ss.wire.tx_pending);
	T_EXPECT_EQ(
		fx.ss.wire.sendbuf.head->len, (size_t)MUX_FRAME_HEADER_SIZE);
	{
		struct mux_header hdr = { 0 };
		mux_read_header(fx.ss.wire.sendbuf.head->data, &hdr);
		T_EXPECT_EQ(hdr.stream_id, (uint_least16_t)7);
		T_EXPECT_EQ(hdr.flags, (uint_least8_t)MUX_FLAG_ACK);
		T_EXPECT_EQ(hdr.extra, (uint_least16_t)UINT16_MAX);
	}

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_send_oob_packs_payload)
{
	struct session_fixture fx;
	static const unsigned char payload[] = { 1, 2, 3, 4 };
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	T_EXPECT(session_send_oob(
		&fx.ss, MUX_CTRL_PONG, payload, sizeof(payload)));
	T_CHECK(fx.ss.wire.oobbuf.head != NULL);
	T_EXPECT(fx.ss.wire.tx_pending);
	{
		struct mux_header hdr = { 0 };
		mux_read_header(fx.ss.wire.oobbuf.head->data, &hdr);
		T_EXPECT_EQ(hdr.stream_id, (uint_least16_t)STREAMID_CTRL);
		T_EXPECT_EQ(hdr.extra, (uint_least16_t)MUX_CTRL_PONG);
		T_EXPECT_EQ(hdr.length, (uint_least16_t)sizeof(payload));
		T_EXPECT(
			memcmp(fx.ss.wire.oobbuf.head->data +
				       MUX_FRAME_HEADER_SIZE,
			       payload, sizeof(payload)) == 0);
	}

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_ack_trim_releases_frames_and_clears_stall)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	for (int i = 0; i < 3; i++) {
		struct mux_frame *const frame = make_frame(
			&fx.ss.pool, (uint_least16_t)(i + 1), MUX_FLAG_PUSH, 0,
			NULL, 0);
		T_CHECK(frame != NULL);
		frame->unacked_count = 1;
		mux_frame_list_push(&fx.ss.unacked, frame);
	}
	fx.ss.unacked_frames = 3;
	fx.ss.last_ack_recv = 1;
	fx.ss.session_window = 2;
	fx.ss.send_stalled = true;

	T_EXPECT(session_ack_trim(&fx.ss, 2));
	T_EXPECT_EQ(fx.ss.unacked_frames, (size_t)1);
	T_EXPECT_EQ(fx.ss.last_ack_recv, (uint_least32_t)3);
	T_EXPECT(!fx.ss.send_stalled);
	T_EXPECT(fx.ss.wire.tx_pending);

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_ack_trim_overflow_returns_false)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_frame *const frame =
		make_frame(&fx.ss.pool, 1, MUX_FLAG_PUSH, 0, NULL, 0);
	T_CHECK(frame != NULL);
	frame->unacked_count = 1;
	mux_frame_list_push(&fx.ss.unacked, frame);
	fx.ss.unacked_frames = 1;
	fx.ss.last_ack_recv = 5;

	/* count=2 > unacked_frames=1: must return false, list unchanged. */
	T_EXPECT(!session_ack_trim(&fx.ss, 2));
	T_EXPECT_EQ(fx.ss.unacked_frames, (size_t)1);
	T_EXPECT_EQ(fx.ss.last_ack_recv, (uint_least32_t)5);
	T_EXPECT(fx.ss.unacked.head == frame);

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_resume_ack_recv_advances_cursor)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	for (int i = 0; i < 2; i++) {
		struct mux_frame *const frame = make_frame(
			&fx.ss.pool, (uint_least16_t)(i + 1), MUX_FLAG_PUSH, 0,
			NULL, 0);
		T_CHECK(frame != NULL);
		frame->unacked_count = 1;
		mux_frame_list_push(&fx.ss.unacked, frame);
	}
	fx.ss.unacked_frames = 2;
	fx.ss.last_ack_recv = 1;

	T_EXPECT(session_resume_ack_recv(&fx.ss, 2));
	T_EXPECT_EQ(fx.ss.last_ack_recv, (uint_least32_t)2);
	T_EXPECT_EQ(fx.ss.unacked_frames, (size_t)1);
	T_EXPECT(fx.ss.retransmit_cursor == fx.ss.unacked.head);

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_open_stream_enforces_limits)
{
	struct session_fixture fx;
	struct mux_stream *existing = NULL;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
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

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_open_stream_success_sets_default_send_window)
{
	struct session_fixture fx;
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_stream *const s = session_open_stream(&fx.ss);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(s->id, (uint_least16_t)1);
	T_EXPECT_EQ(s->send_window, (uint_least32_t)MUX_DEFAULT_SEND_WINDOW);
	T_EXPECT(sched_find_stream(&fx.ss, s->id) == s);

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_recv_ping_copies_payload_into_pong)
{
	struct session_fixture fx;
	static const unsigned char payload[] = { 9, 8, 7, 6, 5, 4, 3, 2 };
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_frame *const frame = make_frame(
		&fx.ss.pool, STREAMID_CTRL, 0, MUX_CTRL_PING, payload,
		sizeof(payload));
	struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};
	T_CHECK(frame != NULL);
	ringbuf_reset(fx.ss.wire.recvbuf);
	memcpy(ringbuf_write_ptr(fx.ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(fx.ss.wire.recvbuf, frame->len);

	session_recv_ping(&fx.ss, &hdr, frame->len);
	T_CHECK(fx.ss.wire.oobbuf.head != NULL);
	{
		struct mux_header pong_hdr = { 0 };
		mux_read_header(fx.ss.wire.oobbuf.head->data, &pong_hdr);
		T_EXPECT_EQ(pong_hdr.extra, (uint_least16_t)MUX_CTRL_PONG);
	}
	T_EXPECT(
		memcmp(fx.ss.wire.oobbuf.head->data + MUX_FRAME_HEADER_SIZE,
		       payload, sizeof(payload)) == 0);
	mux_frame_put(&fx.ss.pool, frame);

	teardown_fixture(&fx);
}

T_DECLARE_CASE(test_session_recv_ping_drops_when_pong_already_queued)
{
	struct session_fixture fx;
	static const unsigned char payload1[] = { 1, 2, 3, 4 };
	static const unsigned char payload2[] = { 5, 6, 7, 8 };
	if (setup_fixture(&fx) != 0) {
		T_FATAL("setup_fixture failed");
		return;
	}

	struct mux_frame *const frame1 = make_frame(
		&fx.ss.pool, STREAMID_CTRL, 0, MUX_CTRL_PING, payload1,
		sizeof(payload1));
	struct mux_frame *const frame2 = make_frame(
		&fx.ss.pool, STREAMID_CTRL, 0, MUX_CTRL_PING, payload2,
		sizeof(payload2));
	struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(payload1),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};
	T_CHECK(frame1 != NULL);
	T_CHECK(frame2 != NULL);

	ringbuf_reset(fx.ss.wire.recvbuf);
	memcpy(ringbuf_write_ptr(fx.ss.wire.recvbuf), frame1->data,
	       frame1->len);
	ringbuf_produce(fx.ss.wire.recvbuf, frame1->len);
	session_recv_ping(&fx.ss, &hdr, frame1->len);
	T_CHECK(fx.ss.wire.oobbuf.head != NULL);
	const struct mux_frame *const queued = fx.ss.wire.oobbuf.head;

	fx.ss.ping_recv_last_ns = -(intmax_t)MUX_PING_RATE_LIMIT_NS;
	hdr.length = (uint_least16_t)sizeof(payload2);
	ringbuf_reset(fx.ss.wire.recvbuf);
	memcpy(ringbuf_write_ptr(fx.ss.wire.recvbuf), frame2->data,
	       frame2->len);
	ringbuf_produce(fx.ss.wire.recvbuf, frame2->len);
	session_recv_ping(&fx.ss, &hdr, frame2->len);

	T_EXPECT(fx.ss.wire.oobbuf.head == queued);
	T_EXPECT(fx.ss.wire.oobbuf.tail == queued);
	T_EXPECT(fx.ss.wire.oobbuf.head->next == NULL);
	T_EXPECT(
		memcmp(fx.ss.wire.oobbuf.head->data + MUX_FRAME_HEADER_SIZE,
		       payload1, sizeof(payload1)) == 0);

	mux_frame_put(&fx.ss.pool, frame1);
	mux_frame_put(&fx.ss.pool, frame2);

	teardown_fixture(&fx);
}

/* Build a session in SESSION_HANDSHAKE state with all timers needed for
 * session_handshake_done initialised.  Reuses setup_fixture for the common
 * parts (socket pair, pool, streams table, sched_init). */
static int setup_handshake_fixture(struct session_fixture *restrict fx)
{
	if (setup_fixture(fx) != 0) {
		return -1;
	}
	fx->ss.state = SESSION_HANDSHAKE;
	/* session_handshake_done calls ev_timer_stop(&w_connect_timeout) and
	 * ev_timer_again on w_timeout and w_keepalive; the repeat interval must
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

/* Regression: after session_handshake_done, w_coalesce must be re-armed when
 * delay_head is non-NULL (streams held in the Nagle / ACK coalescing list
 * from before suspension). */
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

	fx.ss.recv_seq = 5;
	fx.ss.ack_seq = 3;
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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_session_send_ctrl_packs_header_and_clamps_extra);
	T_RUN_CASE(t, test_session_send_oob_packs_payload);
	T_RUN_CASE(t, test_session_ack_trim_releases_frames_and_clears_stall);
	T_RUN_CASE(t, test_session_ack_trim_overflow_returns_false);
	T_RUN_CASE(t, test_session_resume_ack_recv_advances_cursor);
	T_RUN_CASE(t, test_session_open_stream_enforces_limits);
	T_RUN_CASE(
		t, test_session_open_stream_success_sets_default_send_window);
	T_RUN_CASE(t, test_session_recv_ping_copies_payload_into_pong);
	T_RUN_CASE(t, test_session_recv_ping_drops_when_pong_already_queued);
	T_RUN_CASE(
		t, test_session_handshake_done_rearms_coalesce_for_delay_list);
	T_RUN_CASE(
		t, test_session_handshake_done_rearms_coalesce_for_ack_backlog);
	T_RUN_CASE(t, test_session_handshake_done_no_coalesce_without_backlog);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
