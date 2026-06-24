/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* frame_test.c - white-box tests for frame.c.
 * Dependencies: frame.c #included (leaf module, no collaborators to mock).
 * Benches (bench section) are opt-in: run with BENCH set in the env. */

#include "mux/frame.h"

#include "mux/mux.h"

/* Unlock the testing.h bench macros (need a monotonic clock from os/clock.h). */
#include "os/clock.h"
#define UTILS_MEASURE_H
#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mux/frame.c"

/* mock - the test frame allocator */

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
	struct mux_frame *last_freed;
	bool poison_new_frame;
};

static struct mux_frame *frame_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
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

/* regression - targeted cases for one container/codec behavior each */

T_DECLARE_CASE(test_frame_get_resets_runtime_fields)
{
	struct frame_pool_ctx ctx = {
		.poison_new_frame = true,
	};
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame *const frame =
		mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
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

	struct mux_frame *const frame =
		mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
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
		frames[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
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

T_DECLARE_CASE(test_frame_ring_null_and_empty_ops)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	/* NULL ring: size/peek/pop must not crash or lie. */
	T_EXPECT_EQ(mux_frame_ring_size(NULL), (size_t)0);
	T_EXPECT(mux_frame_ring_peek(NULL, 0) == NULL);
	T_EXPECT(mux_frame_ring_pop(NULL) == NULL);

	/* Empty ring: same expectations after allocation. */
	struct mux_frame_ring *r = mux_frame_ring_new(MUX_FRAME_RING_MIN);
	T_CHECK(r != NULL);
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)0);
	T_EXPECT(mux_frame_ring_peek(r, 0) == NULL);
	T_EXPECT(mux_frame_ring_pop(r) == NULL);

	mux_frame_ring_free(&r, &pool);
	T_EXPECT(r == NULL);
	T_EXPECT_EQ(ctx.free_calls, 0);
}

T_DECLARE_CASE(test_frame_ring_push_pop_fifo)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame_ring *r = NULL;
	const int n = 8;
	struct mux_frame *pushed[8];

	for (int i = 0; i < n; i++) {
		pushed[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(pushed[i] != NULL);
		T_CHECK(mux_frame_ring_push(&r, pushed[i]));
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)n);

	/* peek should return items in push order */
	for (int i = 0; i < n; i++) {
		T_EXPECT(mux_frame_ring_peek(r, (size_t)i) == pushed[i]);
	}

	/* pop should return items in FIFO order */
	for (int i = 0; i < n; i++) {
		T_EXPECT(mux_frame_ring_pop(r) == pushed[i]);
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)0);

	mux_frame_ring_free(&r, &pool);
	/* All frames were already popped; ring_free frees 0 more. */
	T_EXPECT_EQ(ctx.free_calls, 0);

	/* Free the popped frames manually. */
	for (int i = 0; i < n; i++) {
		mux_frame_put(&pool, pushed[i]);
	}
	T_EXPECT_EQ(ctx.free_calls, n);
}

T_DECLARE_CASE(test_frame_ring_grow_contiguous)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame_ring *r = NULL;
	/* Fill exactly MUX_FRAME_RING_MIN slots (head stays 0 — contiguous). */
	const int cap0 = MUX_FRAME_RING_MIN;
	struct mux_frame *frames[MUX_FRAME_RING_MIN + 1];

	for (int i = 0; i < cap0; i++) {
		frames[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(frames[i] != NULL);
		T_CHECK(mux_frame_ring_push(&r, frames[i]));
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)cap0);

	/* One more push must trigger grow to 2×MIN capacity. */
	frames[cap0] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(frames[cap0] != NULL);
	T_CHECK(mux_frame_ring_push(&r, frames[cap0]));
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)(cap0 + 1));
	T_EXPECT_EQ(r->capacity, (size_t)(cap0 * 2));

	/* FIFO order must be preserved across the grow. */
	for (int i = 0; i <= cap0; i++) {
		T_EXPECT(mux_frame_ring_pop(r) == frames[i]);
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)0);

	mux_frame_ring_free(&r, &pool);
	for (int i = 0; i <= cap0; i++) {
		mux_frame_put(&pool, frames[i]);
	}
	T_EXPECT_EQ(ctx.free_calls, cap0 + 1);
}

T_DECLARE_CASE(test_frame_ring_grow_wrapped)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame_ring *r = NULL;
	const int cap0 = MUX_FRAME_RING_MIN; /* 16 */
	const int pop_n = 10;
	const int push2 = 14; /* total after pop: 6 + 14 = 20 > 16 → grow */
	const int total = cap0 + push2;
	struct mux_frame *frames[MUX_FRAME_RING_MIN + 14]; /* 30 */

	/* Round 1: fill to capacity. */
	for (int i = 0; i < cap0; i++) {
		frames[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(frames[i] != NULL);
		T_CHECK(mux_frame_ring_push(&r, frames[i]));
	}
	/* Pop 10: head advances into the ring (head = 10). */
	for (int i = 0; i < pop_n; i++) {
		T_EXPECT(mux_frame_ring_pop(r) == frames[i]);
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)(cap0 - pop_n));

	/* Round 2: push 14 more; slots wrap around, then grow fires. */
	for (int i = cap0; i < total; i++) {
		frames[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(frames[i] != NULL);
		T_CHECK(mux_frame_ring_push(&r, frames[i]));
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)(total - pop_n));

	/* FIFO order must be fully intact after the wrapped grow. */
	for (int i = pop_n; i < total; i++) {
		T_EXPECT(mux_frame_ring_pop(r) == frames[i]);
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)0);

	mux_frame_ring_free(&r, &pool);
	/* Free frames[0..pop_n-1] that were already popped above. */
	for (int i = 0; i < pop_n; i++) {
		mux_frame_put(&pool, frames[i]);
	}
	for (int i = pop_n; i < total; i++) {
		mux_frame_put(&pool, frames[i]);
	}
}

T_DECLARE_CASE(test_frame_ring_free_releases_all_frames)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame_ring *r = NULL;
	const int n = 6;

	for (int i = 0; i < n; i++) {
		struct mux_frame *f =
			mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(f != NULL);
		T_CHECK(mux_frame_ring_push(&r, f));
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)n);
	T_EXPECT_EQ(ctx.alloc_calls, n);

	mux_frame_ring_free(&r, &pool);

	T_EXPECT(r == NULL);
	T_EXPECT_EQ(ctx.free_calls, n);
}

/* bench - per-frame hot-path micro-benchmarks (opt-in: run with BENCH set) */

/* Opaque source/sink (volatile) to keep the optimizer from constant-folding the
 * benched header round-trip; without it the loop folds to a closed form and
 * measures ~0 ns/op. */
static volatile uint_least16_t g_bench_len = 4096;
static volatile uint_least16_t g_bench_sink;

T_DECLARE_BENCH(bench_header_roundtrip)
{
	unsigned char buf[MUX_FRAME_HEADER_SIZE];
	struct mux_header src = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_PUSH,
		.length = 4096,
		.stream_id = 321,
		.extra = 17,
	};
	struct mux_header dst = { 0 };
	uint_least16_t acc = 0;
	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		src.length = g_bench_len;
		mux_write_header(buf, &src);
		mux_read_header(buf, &dst);
		acc = (uint_least16_t)(acc + dst.length +
				       *(const volatile unsigned char *)&buf[2]);
	}
	g_bench_sink = acc;
}

T_DECLARE_BENCH(bench_frame_ring_push_pop)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);
	struct mux_frame *const f = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame_ring *r = NULL;
	/* Prime the ring so the grow cost is excluded from the steady state. */
	if (mux_frame_ring_push(&r, f)) {
		(void)mux_frame_ring_pop(r);
	}
	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		(void)mux_frame_ring_push(&r, f);
		(void)mux_frame_ring_pop(r);
	}
	mux_frame_ring_free(&r, &pool);
	mux_frame_put(&pool, f);
}

T_DECLARE_BENCH(bench_frame_get_put)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);
	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		struct mux_frame *const f =
			mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		if (f != NULL) {
			mux_frame_put(&pool, f);
		}
	}
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
	T_RUN_CASE(t, test_frame_ring_null_and_empty_ops);
	T_RUN_CASE(t, test_frame_ring_push_pop_fifo);
	T_RUN_CASE(t, test_frame_ring_grow_contiguous);
	T_RUN_CASE(t, test_frame_ring_grow_wrapped);
	T_RUN_CASE(t, test_frame_ring_free_releases_all_frames);
	/* Opt-in micro-benchmarks: each runs ~1s, so keep them out of the
	 * default ctest run.  Enable with BENCH set in the environment. */
	if (getenv("BENCH") != NULL) {
		T_RUN_BENCH(t, bench_header_roundtrip);
		T_RUN_BENCH(t, bench_frame_ring_push_pop);
		T_RUN_BENCH(t, bench_frame_get_put);
	}
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
