/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/frame.h"
#include "mux/session.h"
#include "mux/wire.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static struct mux_frame *wire_test_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(sizeof(*frame));
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void wire_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = wire_test_alloc,
		.free = wire_test_free,
		.data = ctx,
	};
}

static struct mux_session
make_session(struct frame_pool_ctx *restrict pool_ctx, const int fd)
{
	struct mux_session ss = {
		.pool = make_pool(pool_ctx),
	};
	ss.w_socket.fd = fd;
	return ss;
}

T_DECLARE_CASE(test_wire_send_plain_tcp_writes_bytes)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char payload[] = "hello";
	unsigned char recvbuf[sizeof(payload)] = { 0 };
	size_t len = sizeof(payload) - 1;

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);

	T_EXPECT(wire_send(&ss, payload, &len));
	T_EXPECT_EQ(len, sizeof(payload) - 1);
	T_EXPECT(
		read(fds[1], recvbuf, sizeof(payload) - 1) ==
		(ssize_t)(sizeof(payload) - 1));
	T_EXPECT(memcmp(recvbuf, payload, sizeof(payload) - 1) == 0);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_wire_recv_plain_tcp_reads_payload)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char sendbuf[] = "mux";
	unsigned char recvbuf[sizeof(sendbuf) - 1] = { 0 };
	size_t len = sizeof(sendbuf) - 1;

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(write(fds[1], sendbuf, sizeof(sendbuf) - 1) ==
		(ssize_t)(sizeof(sendbuf) - 1));

	T_EXPECT(wire_recv(&ss, recvbuf, &len));
	T_EXPECT_EQ(len, sizeof(sendbuf) - 1);
	T_EXPECT(memcmp(recvbuf, sendbuf, sizeof(sendbuf) - 1) == 0);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_wire_recv_eof_clears_rx_open_and_sets_tx_pending)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char recvbuf[8] = { 0 };
	size_t len = sizeof(recvbuf);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	ss.wire.rx_open = true;
	T_CHECK(shutdown(fds[1], SHUT_WR) == 0);

	T_EXPECT(wire_recv(&ss, recvbuf, &len));
	T_EXPECT_EQ(len, (size_t)0);
	T_EXPECT(!ss.wire.rx_open);
	T_EXPECT(ss.wire.tx_pending);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_ringbuf_consume_frame_preserves_remaining_bytes)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 1,
		.stream_id = 2,
		.extra = 0,
	};
	unsigned char bytes[2 * MUX_FRAME_HEADER_SIZE + 2] = { 0 };

	mux_write_header(bytes, &hdr);
	bytes[MUX_FRAME_HEADER_SIZE] = 'A';
	hdr.stream_id = 4;
	mux_write_header(bytes + MUX_FRAME_HEADER_SIZE + 1, &hdr);
	bytes[2 * MUX_FRAME_HEADER_SIZE + 1] = 'B';
	ss.wire.recvbuf = ringbuf_new(sizeof(bytes));
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), bytes, sizeof(bytes));
	ringbuf_produce(ss.wire.recvbuf, sizeof(bytes));

	ringbuf_consume(ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE + 1);
	T_EXPECT_EQ(
		ringbuf_readable(ss.wire.recvbuf),
		sizeof(bytes) - ((size_t)MUX_FRAME_HEADER_SIZE + 1));
	T_EXPECT(
		ringbuf_read_ptr(ss.wire.recvbuf)[MUX_FRAME_HEADER_SIZE] ==
		'B');
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_ringbuf_consume_advances_offset_without_copy)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	unsigned char bytes[2 * MUX_FRAME_HEADER_SIZE] = { 0 };

	ss.wire.recvbuf = ringbuf_new(sizeof(bytes));
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), bytes, sizeof(bytes));
	ringbuf_produce(ss.wire.recvbuf, sizeof(bytes));

	ringbuf_consume(ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE);
	T_EXPECT_EQ(ss.wire.recvbuf->off, (size_t)MUX_FRAME_HEADER_SIZE);
	T_EXPECT_EQ(
		ringbuf_readable(ss.wire.recvbuf),
		sizeof(bytes) - (size_t)MUX_FRAME_HEADER_SIZE);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_wire_discard_buffers_frees_all_pending_frames)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *const sb1 = mux_frame_get(&ss.pool);
	struct mux_frame *const sb2 = mux_frame_get(&ss.pool);
	struct mux_frame *const ob1 = mux_frame_get(&ss.pool);
	struct mux_frame *const ob2 = mux_frame_get(&ss.pool);
	ss.wire.recvbuf = ringbuf_new(32);
	T_CHECK(ss.wire.recvbuf != NULL);
	ss.wire.recvbuf->off = 7;
	ss.wire.recvbuf->len = 11;
	T_CHECK(sb1 != NULL);
	T_CHECK(sb2 != NULL);
	T_CHECK(ob1 != NULL);
	T_CHECK(ob2 != NULL);
	mux_frame_list_push(&ss.wire.sendbuf, sb1);
	mux_frame_list_push(&ss.wire.sendbuf, sb2);
	mux_frame_list_push(&ss.wire.oobbuf, ob1);
	mux_frame_list_push(&ss.wire.oobbuf, ob2);

	wire_discard_buffers(&ss);
	T_EXPECT_EQ(pool_ctx.free_calls, 4);
	T_EXPECT(ss.wire.sendbuf.head == NULL);
	T_EXPECT(ss.wire.sendbuf.tail == NULL);
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)0);
	T_EXPECT(ss.wire.oobbuf.head == NULL);
	T_EXPECT(ss.wire.oobbuf.tail == NULL);
	T_EXPECT_EQ(ss.wire.oobbuf.count, (size_t)0);
	T_EXPECT(ss.wire.recvbuf != NULL);
	T_EXPECT_EQ(ss.wire.recvbuf->cap, (size_t)32);
	T_EXPECT_EQ(ss.wire.recvbuf->len, (size_t)0);
	T_EXPECT_EQ(ss.wire.recvbuf->off, (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_wire_shutdown_plain_tcp_returns_done)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char recvbuf[1] = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);

	T_EXPECT_EQ(
		wire_shutdown(&ss),
		(enum wire_shutdown_state)WIRE_SHUTDOWN_DONE);
	T_EXPECT(read(fds[1], recvbuf, sizeof(recvbuf)) == 0);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_wire_wait_eof_returns_true_on_clean_peer_close)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(shutdown(fds[1], SHUT_WR) == 0);

	T_EXPECT(wire_wait_eof(&ss));

	close(fds[0]);
	close(fds[1]);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_wire_send_plain_tcp_writes_bytes);
	T_RUN_CASE(t, test_wire_recv_plain_tcp_reads_payload);
	T_RUN_CASE(t, test_wire_recv_eof_clears_rx_open_and_sets_tx_pending);
	T_RUN_CASE(t, test_ringbuf_consume_frame_preserves_remaining_bytes);
	T_RUN_CASE(t, test_ringbuf_consume_advances_offset_without_copy);
	T_RUN_CASE(t, test_wire_discard_buffers_frees_all_pending_frames);
	T_RUN_CASE(t, test_wire_shutdown_plain_tcp_returns_done);
	T_RUN_CASE(t, test_wire_wait_eof_returns_true_on_clean_peer_close);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
