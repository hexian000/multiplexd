/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/frame.h"
#include "mux/session.h"
#include "mux/stream.h"

#include "algo/hashtable.h"
#include "utils/testing.h"

#include <ev.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

struct stream_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
	struct frame_pool_ctx pool_ctx;
	int fds[2];
};

static struct mux_frame *stream_test_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(sizeof(*frame));
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
		.stream_window = 4,
		.wire = {
			.rx_open = true,
		},
	};
	fx->ss.sched.streams = table_new(&mux_stream_table_opts);
	if (fx->ss.sched.streams == NULL) {
		close(fx->fds[0]);
		close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	ev_io_init(&fx->ss.w_socket, stream_test_io_cb, fx->fds[0], EV_READ);
	fx->ss.w_socket.data = &fx->ss;
	ev_timer_init(&fx->ss.w_idle_timeout, stream_test_timer_cb, 1.0, 0.0);
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
	struct mux_frame *const frame = mux_frame_get(pool);
	if (frame == NULL) {
		return NULL;
	}
	memset(frame->data, 0, MUX_FRAME_HEADER_SIZE + payload_len);
	frame->len = MUX_FRAME_HEADER_SIZE + payload_len;
	frame->pos = 0;
	return frame;
}

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

	fx.ss.conf.mem_pressure_lo = 2 * (int)MUX_FRAME_SIZE;
	fx.ss.conf.mem_pressure_hi = 4 * (int)MUX_FRAME_SIZE;
	fx.ss.recv_buffered_bytes = 4 * (size_t)MUX_FRAME_SIZE;
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

	stream_recv_rst(s);
	T_EXPECT(s->rst_received);
	T_EXPECT_EQ(s->state, (enum stream_state)STREAM_CLOSED);
	T_EXPECT_EQ(s->buffered_bytes, (uint_least32_t)0);
	T_EXPECT_EQ(ringbuf_readable(s->recvbuf), (size_t)0);

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

/* When auto_stream_window is enabled and the session stream_window has been
 * reduced below a stream's recv_window, stream_check_ack must shrink
 * recv_window as soon as no outstanding peer credit remains and all buffered
 * bytes fit within the new target. */
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
	const uint_fast32_t old_window = 8u * MUX_MAX_PAYLOAD_SIZE;
	s->recv_window = old_window;
	/* No outstanding credit: grant_sent == bytes_received. */
	s->grant_sent = 0;
	s->bytes_received = 0;
	s->buffered_bytes = 0;

	stream_check_ack(s);

	const uint_fast32_t expected =
		(uint_fast32_t)fx.ss.stream_window * MUX_MAX_PAYLOAD_SIZE;
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

	const uint_fast32_t old_window = 8u * MUX_MAX_PAYLOAD_SIZE;
	s->recv_window = old_window;

	/* Peer still has three frames of outstanding credit, which exceeds the
	 * two-frame target: buffered(0) + outstanding(3) > target(2). */
	s->bytes_received = 0;
	s->grant_sent = 3u * (uint_least32_t)MUX_MAX_PAYLOAD_SIZE;
	s->buffered_bytes = 0;

	const uint_fast32_t target =
		(uint_fast32_t)fx.ss.stream_window * MUX_MAX_PAYLOAD_SIZE;
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

/* -------------------------------------------------------------------------
 * Race condition tests
 * ---------------------------------------------------------------------- */

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
	stream_recv_rst(s);
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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_stream_grant_inc_uses_available_window);
	T_RUN_CASE(t, test_stream_grant_inc_scales_under_pressure);
	T_RUN_CASE(t, test_stream_dequeue_send_updates_queue_counters);
	T_RUN_CASE(t, test_stream_recv_window_grows_send_credit);
	T_RUN_CASE(t, test_stream_recv_fin_advances_state);
	T_RUN_CASE(t, test_stream_recv_rst_discards_buffered_data);
	T_RUN_CASE(t, test_stream_close_with_unread_data_sends_rst);
	T_RUN_CASE(t, test_stream_shutdown_marks_rx_eof);
	T_RUN_CASE(t, test_stream_recv_fin_with_rx_eof_shuts_down_write);
	T_RUN_CASE(t, test_stream_check_ack_shrinks_recv_window_when_safe);
	T_RUN_CASE(t, test_stream_check_ack_does_not_shrink_while_outstanding);
	T_RUN_CASE(t, test_stream_format_tag_formats_id_string);
	T_RUN_CASE(t, test_stream_mark_syn_sent_advances_state);
	T_RUN_CASE(t, test_syn_received_rst_before_attach);
	T_RUN_CASE(t, test_halfopen_release_before_free);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
