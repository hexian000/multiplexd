/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/mux.h"

#include "mux/frame.h"
#include "mux/session.h"
#include "mux/stream.h"

#include "utils/testing.h"

#include <errno.h>
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

static struct mux_frame *mux_api_test_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(sizeof(*frame));
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
		.state = SESSION_ESTABLISHED,
		.stream_window = 3,
		.peer_stream_window = 5,
	};
}

T_DECLARE_CASE(test_mux_state_maps_internal_states)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);

	ss.state = SESSION_ESTABLISHED;
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_ESTABLISHED);
	ss.state = SESSION_SUSPENDED;
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_SUSPENDED);
	ss.state = SESSION_HANDSHAKE;
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_CONNECT);
	ss.state = SESSION_CLOSED;
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
		size_t rx = 0;
		size_t tx = 0;
		mux_stream_window(&ss, &rx, &tx);
		T_EXPECT_EQ(rx, (size_t)(3 * MUX_WINDOW_UNIT));
		T_EXPECT_EQ(tx, (size_t)(5 * MUX_WINDOW_UNIT));
	}
}

T_DECLARE_CASE(test_mux_stream_send_rejects_invalid_state)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct stream s = {
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
	struct stream s = {
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
	close(fds[0]);
	close(fds[1]);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_mux_stream_recv_reports_eagain_and_reset)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct stream s = {
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
	struct stream s = {
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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_mux_state_maps_internal_states);
	T_RUN_CASE(t, test_mux_peer_addr_and_window_accessors);
	T_RUN_CASE(t, test_mux_stream_send_rejects_invalid_state);
	T_RUN_CASE(t, test_mux_stream_send_queues_payload);
	T_RUN_CASE(t, test_mux_stream_recv_reports_eagain_and_reset);
	T_RUN_CASE(t, test_mux_stream_io_stop_clears_stream_binding);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
