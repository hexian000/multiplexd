/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/frame.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
	struct mux_frame *last_freed;
	bool poison_new_frame;
};

static struct mux_frame *frame_test_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(sizeof(*frame));
	if (frame == NULL) {
		return NULL;
	}
	ctx->alloc_calls++;
	if (ctx->poison_new_frame) {
		frame->pos = 99;
		frame->len = 77;
		frame->next = frame;
	}
	return frame;
}

static void frame_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	ctx->last_freed = frame;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = frame_test_alloc,
		.free = frame_test_free,
		.data = ctx,
	};
}

T_DECLARE_CASE(test_frame_get_resets_runtime_fields)
{
	struct frame_pool_ctx ctx = {
		.poison_new_frame = true,
	};
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame *const frame = mux_frame_get(&pool);
	T_CHECK(frame != NULL);
	T_EXPECT_EQ(ctx.alloc_calls, 1);
	T_EXPECT_EQ(frame->pos, (size_t)0);
	T_EXPECT_EQ(frame->len, (size_t)0);
	T_EXPECT(frame->next == NULL);

	mux_frame_put(&pool, frame);
}

T_DECLARE_CASE(test_frame_put_calls_allocator_free)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame *const frame = mux_frame_get(&pool);
	T_CHECK(frame != NULL);
	T_EXPECT_EQ(ctx.free_calls, 0);

	mux_frame_put(&pool, frame);
	T_EXPECT_EQ(ctx.free_calls, 1);
	T_EXPECT(ctx.last_freed == frame);
}

T_DECLARE_CASE(test_header_roundtrip_preserves_all_fields)
{
	const struct mux_header src = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_PUSH,
		.length = 4096,
		.stream_id = 321,
		.extra = 17,
	};
	unsigned char buf[MUX_FRAME_HEADER_SIZE];
	struct mux_header dst = { 0 };

	mux_write_header(buf, &src);
	mux_read_header(buf, &dst);

	T_EXPECT_EQ(dst.version, src.version);
	T_EXPECT_EQ(dst.flags, src.flags);
	T_EXPECT_EQ(dst.length, src.length);
	T_EXPECT_EQ(dst.stream_id, src.stream_id);
	T_EXPECT_EQ(dst.extra, src.extra);
}

T_DECLARE_CASE(test_header_roundtrip_with_flag_combinations)
{
	const struct mux_header headers[] = {
		{
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_FIN,
			.length = 0,
			.stream_id = 1,
			.extra = 0,
		},
		{
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_RST,
			.length = 0,
			.stream_id = 2,
			.extra = MUX_STATUS_CANCEL,
		},
		{
			.version = 0,
			.flags = 0,
			.length = MUX_MAX_PAYLOAD_SIZE,
			.stream_id = 0,
			.extra = MUX_CTRL_PING,
		},
	};

	for (size_t i = 0; i < sizeof(headers) / sizeof(headers[0]); i++) {
		unsigned char buf[MUX_FRAME_HEADER_SIZE];
		struct mux_header roundtrip = { 0 };

		mux_write_header(buf, &headers[i]);
		mux_read_header(buf, &roundtrip);

		T_EXPECT_EQ(roundtrip.version, headers[i].version);
		T_EXPECT_EQ(roundtrip.flags, headers[i].flags);
		T_EXPECT_EQ(roundtrip.length, headers[i].length);
		T_EXPECT_EQ(roundtrip.stream_id, headers[i].stream_id);
		T_EXPECT_EQ(roundtrip.extra, headers[i].extra);
	}
}

T_DECLARE_CASE(test_frame_list_push_pop_fifo)
{
	struct mux_frame_list list = { 0 };
	struct mux_frame first = { 0 };
	struct mux_frame second = { 0 };
	struct mux_frame third = { 0 };

	mux_frame_list_push(&list, &first);
	mux_frame_list_push(&list, &second);
	mux_frame_list_push(&list, &third);

	T_EXPECT_EQ(list.count, (size_t)3);
	T_EXPECT(list.head == &first);
	T_EXPECT(list.tail == &third);

	T_EXPECT(mux_frame_list_pop(&list) == &first);
	T_EXPECT(mux_frame_list_pop(&list) == &second);
	T_EXPECT(mux_frame_list_pop(&list) == &third);
	T_EXPECT(mux_frame_list_pop(&list) == NULL);
	T_EXPECT_EQ(list.count, (size_t)0);
	T_EXPECT(list.head == NULL);
	T_EXPECT(list.tail == NULL);
}

T_DECLARE_CASE(test_frame_list_drain_clears_head_tail_and_count)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);
	struct mux_frame_list list = { 0 };
	struct mux_frame *frames[3] = { 0 };

	for (size_t i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
		frames[i] = mux_frame_get(&pool);
		T_CHECK(frames[i] != NULL);
		mux_frame_list_push(&list, frames[i]);
	}

	T_EXPECT_EQ(list.count, (size_t)3);
	mux_frame_list_clear(&list, &pool);

	T_EXPECT_EQ(ctx.free_calls, 3);
	T_EXPECT_EQ(list.count, (size_t)0);
	T_EXPECT(list.head == NULL);
	T_EXPECT(list.tail == NULL);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_frame_get_resets_runtime_fields);
	T_RUN_CASE(t, test_frame_put_calls_allocator_free);
	T_RUN_CASE(t, test_header_roundtrip_preserves_all_fields);
	T_RUN_CASE(t, test_header_roundtrip_with_flag_combinations);
	T_RUN_CASE(t, test_frame_list_push_pop_fifo);
	T_RUN_CASE(t, test_frame_list_drain_clears_head_tail_and_count);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
