/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* frame_test.c - white-box tests for frame.c.
 * Dependencies: frame.c #included (leaf module, no collaborators to mock).
 * Benches (bench section) are opt-in: run with TESTING_BENCH set in the env. */

#include "mux/frame.h"

#include "mux/frame.c"
#include "mux/mux.h"

#include "meta/arraysize.h"
#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
		frame->cap = 12345;
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
	/* cap must be stamped from the requested size: it bounds payload writes
	 * at mux.c/stream.c/handshake.c, so a dropped `frame->cap = cap;` would
	 * ship silently. */
	T_EXPECT_EQ(frame->cap, (size_t)MUX_MAX_PAYLOAD_SIZE);

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

/* push_front sets tail only when the list was previously empty; otherwise it
 * re-heads and leaves tail alone. */
T_DECLARE_CASE(test_frame_list_push_front_empty_and_nonempty)
{
	struct mux_frame_list list = { 0 };
	struct mux_frame a = { 0 };
	struct mux_frame b = { 0 };
	struct mux_frame c = { 0 };

	/* Into an empty list: head and tail both become the frame. */
	mux_frame_list_push_front(&list, &a);
	T_EXPECT_EQ(list.count, (size_t)1);
	T_EXPECT(list.head == &a);
	T_EXPECT(list.tail == &a);

	/* Into a non-empty list: head updates, tail unchanged. */
	mux_frame_list_push_front(&list, &b);
	T_EXPECT_EQ(list.count, (size_t)2);
	T_EXPECT(list.head == &b);
	T_EXPECT(list.tail == &a);

	mux_frame_list_push_front(&list, &c);
	T_EXPECT_EQ(list.count, (size_t)3);
	T_EXPECT(list.head == &c);
	T_EXPECT(list.tail == &a);

	/* Front insertions come back out head-first: c, b, a. */
	T_EXPECT(mux_frame_list_pop(&list) == &c);
	T_EXPECT(mux_frame_list_pop(&list) == &b);
	T_EXPECT(mux_frame_list_pop(&list) == &a);
	T_EXPECT_EQ(list.count, (size_t)0);
	T_EXPECT(list.head == NULL);
	T_EXPECT(list.tail == NULL);
}

/* remove_after must cover interior removal (head/tail untouched), tail removal
 * (list->tail reset to prev), and head removal of the sole element (prev NULL,
 * list empties and tail resets to NULL). */
T_DECLARE_CASE(test_frame_list_remove_after_head_interior_tail)
{
	struct mux_frame_list list = { 0 };
	struct mux_frame a = { 0 };
	struct mux_frame b = { 0 };
	struct mux_frame c = { 0 };

	mux_frame_list_push(&list, &a);
	mux_frame_list_push(&list, &b);
	mux_frame_list_push(&list, &c);
	/* list: a -> b -> c, head=a tail=c count=3 */

	/* Interior removal (prev=a removes b); head and tail unchanged. */
	T_EXPECT(mux_frame_list_remove_after(&list, &a) == &b);
	T_EXPECT_EQ(list.count, (size_t)2);
	T_EXPECT(list.head == &a);
	T_EXPECT(list.tail == &c);
	T_EXPECT(a.next == &c);

	/* Tail removal (prev=a removes c, the tail): tail resets to a. */
	T_EXPECT(mux_frame_list_remove_after(&list, &a) == &c);
	T_EXPECT_EQ(list.count, (size_t)1);
	T_EXPECT(list.head == &a);
	T_EXPECT(list.tail == &a);
	T_EXPECT(a.next == NULL);

	/* Head removal of the sole remaining element (prev=NULL): list empties
	 * and tail resets to NULL. */
	T_EXPECT(mux_frame_list_remove_after(&list, NULL) == &a);
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
	struct mux_frame *pushed[8];
	const size_t n = ARRAY_SIZE(pushed);

	for (size_t i = 0; i < n; i++) {
		pushed[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(pushed[i] != NULL);
		T_CHECK(mux_frame_ring_push(&r, pushed[i]));
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), n);

	/* peek should return items in push order */
	for (size_t i = 0; i < n; i++) {
		T_EXPECT(mux_frame_ring_peek(r, i) == pushed[i]);
	}

	/* pop should return items in FIFO order */
	for (size_t i = 0; i < n; i++) {
		T_EXPECT(mux_frame_ring_pop(r) == pushed[i]);
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)0);

	mux_frame_ring_free(&r, &pool);
	/* All frames were already popped; ring_free frees 0 more. */
	T_EXPECT_EQ(ctx.free_calls, 0);

	/* Free the popped frames manually. */
	for (size_t i = 0; i < n; i++) {
		mux_frame_put(&pool, pushed[i]);
	}
	T_EXPECT_EQ(ctx.free_calls, (int)n);
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

/* mux_frame_ring_peek and mux_frame_ring_free both re-implement the wrap
 * arithmetic (head + i) & (capacity - 1), yet every other ring case runs
 * against head == 0 (grow linearizes head, and grow_wrapped pops empty before
 * freeing). Push MIN, pop 10 so head advances to 10, then push 4 more (still
 * <= capacity, so no grow: the ring stays wrapped) and exercise peek over the
 * wrap and free with live entries. */
T_DECLARE_CASE(test_frame_ring_peek_and_free_wrapped)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame_ring *r = NULL;
	const int cap0 = MUX_FRAME_RING_MIN; /* 16 */
	const int pop_n = 10;
	const int push2 = 4; /* 6 + 4 = 10 <= 16: stays wrapped, no grow */
	const int held = cap0 - pop_n + push2; /* 10 */
	struct mux_frame *pushed[MUX_FRAME_RING_MIN + 4]; /* 20 */

	for (int i = 0; i < cap0; i++) {
		pushed[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(pushed[i] != NULL);
		T_CHECK(mux_frame_ring_push(&r, pushed[i]));
	}
	/* Pop 10 (head advances to 10); free the popped frames now. */
	for (int i = 0; i < pop_n; i++) {
		T_EXPECT(mux_frame_ring_pop(r) == pushed[i]);
		mux_frame_put(&pool, pushed[i]);
	}
	/* Push 4 more; they wrap into slots 0..3 while head stays at 10. */
	for (int i = cap0; i < cap0 + push2; i++) {
		pushed[i] = mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(pushed[i] != NULL);
		T_CHECK(mux_frame_ring_push(&r, pushed[i]));
	}
	T_EXPECT_EQ(mux_frame_ring_size(r), (size_t)held);

	/* Peek must walk the wrapped ring in FIFO order: pushed[10..19]. */
	for (int i = 0; i < held; i++) {
		T_EXPECT(
			mux_frame_ring_peek(r, (size_t)i) == pushed[pop_n + i]);
	}

	/* Free the wrapped ring holding 10 live entries: exactly those are freed. */
	const int freed_before = ctx.free_calls;
	mux_frame_ring_free(&r, &pool);
	T_EXPECT(r == NULL);
	T_EXPECT_EQ(ctx.free_calls - freed_before, held);
}

/* Slots past the live entries must read as NULL after a grow, exactly like a
 * freshly allocated ring (mux_frame_ring_new), not leftover malloc bytes. */
T_DECLARE_CASE(test_frame_ring_grow_zeroes_new_slots)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame_ring *r = NULL;
	const int cap0 = MUX_FRAME_RING_MIN;

	for (int i = 0; i < cap0; i++) {
		struct mux_frame *const f =
			mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
		T_CHECK(f != NULL);
		T_CHECK(mux_frame_ring_push(&r, f));
	}
	/* One more push fills the ring to capacity and forces the 2x grow. */
	struct mux_frame *const last =
		mux_frame_get(&pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(last != NULL);
	T_CHECK(mux_frame_ring_push(&r, last));
	T_EXPECT_EQ(r->capacity, (size_t)(cap0 * 2));
	T_EXPECT_EQ(r->count, (size_t)(cap0 + 1));

	for (size_t i = r->count; i < r->capacity; i++) {
		T_EXPECT(r->entries[i] == NULL);
	}
	/* The last live slot must still be the frame that triggered the grow. */
	T_EXPECT(mux_frame_ring_peek(r, r->count - 1) == last);

	mux_frame_ring_free(&r, &pool);
	T_EXPECT_EQ(ctx.free_calls, cap0 + 1);
}

T_DECLARE_CASE(test_frame_ring_free_releases_all_frames)
{
	struct frame_pool_ctx ctx = { 0 };
	const struct mux_frame_allocator pool = make_pool(&ctx);

	struct mux_frame_ring *r = NULL;
	const int n = 6;

	for (int i = 0; i < n; i++) {
		struct mux_frame *const f =
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

/* Direct coverage of mux_bytebuf_reserve's four decision points: fast-path (space
 * already available), compaction, doubling growth, and overflow rejection. */

T_DECLARE_CASE(test_bytebuf_reserve_noop_when_space_available)
{
	struct bytebuf *rb = bytebuf_new(16);
	T_CHECK(rb != NULL);
	bytebuf_produce(rb, 4);

	T_EXPECT(mux_bytebuf_reserve(&rb, 12, false));
	T_EXPECT_EQ(rb->cap, (size_t)16);
	T_EXPECT_EQ(rb->off, (size_t)0);

	/* need == 0 is always satisfied too, even with zero space left. */
	bytebuf_produce(rb, 12);
	T_EXPECT_EQ(bytebuf_write_space(rb), (size_t)0);
	T_EXPECT(mux_bytebuf_reserve(&rb, 0, false));

	bytebuf_free(rb);
}

/* A partially-consumed buffer (off > 0, len > 0) has write_space trapped
 * behind already-read bytes; compaction alone must recover it without
 * growing, proving can_grow=false does not spuriously fail here. */
T_DECLARE_CASE(test_bytebuf_reserve_compaction_recovers_space)
{
	struct bytebuf *rb = bytebuf_new(10);
	T_CHECK(rb != NULL);
	bytebuf_produce(rb, 8);
	bytebuf_consume(
		rb, 5); /* off=5, len=3: partial consume, no off reset */
	T_CHECK(rb->off == 5 && rb->len == 3);
	T_EXPECT_EQ(bytebuf_write_space(rb), (size_t)2);

	T_EXPECT(mux_bytebuf_reserve(&rb, 5, false));
	T_EXPECT_EQ(rb->off, (size_t)0);
	T_EXPECT_EQ(rb->len, (size_t)3);
	T_EXPECT_EQ(rb->cap, (size_t)10); /* compaction alone; no realloc */

	bytebuf_free(rb);
}

/* can_grow=false with neither immediate space nor anything to compact must
 * fail cleanly rather than attempt to grow. */
T_DECLARE_CASE(test_bytebuf_reserve_returns_false_when_cannot_grow)
{
	struct bytebuf *rb = bytebuf_new(4);
	T_CHECK(rb != NULL);
	bytebuf_produce(rb, 4); /* off=0 already: compact is a no-op */

	T_EXPECT(!mux_bytebuf_reserve(&rb, 1, false));
	T_EXPECT_EQ(rb->cap, (size_t)4);

	bytebuf_free(rb);
}

/* A request well beyond one doubling forces the growth loop to iterate
 * several times; cap must land on the first power-of-two multiple of the
 * original capacity that is >= len+need, not merely >= need. */
T_DECLARE_CASE(test_bytebuf_reserve_doubling_growth_loop)
{
	struct bytebuf *rb = bytebuf_new(4);
	T_CHECK(rb != NULL);
	bytebuf_produce(rb, 4);
	bytebuf_consume(rb, 4); /* fully drained: off resets to 0, len=0 */
	T_CHECK(rb->off == 0 && rb->len == 0);

	/* min_cap = 0 + 20 = 20; doubling from 4: 4, 8, 16, 32 (first >= 20). */
	T_EXPECT(mux_bytebuf_reserve(&rb, 20, true));
	T_EXPECT_EQ(rb->cap, (size_t)32);
	T_EXPECT(bytebuf_write_space(rb) >= (size_t)20);

	bytebuf_free(rb);
}

/* A need large enough that len+need lands exactly on SIZE_MAX forces the growth
 * loop's overflow guard (new_cap > SIZE_MAX/2) to clamp to min_cap instead of
 * doubling past it; the subsequent header-overflow check (sizeof(struct bytebuf)
 * pushes the true request past SIZE_MAX) must then reject it before allocating. */
T_DECLARE_CASE(test_bytebuf_reserve_overflow_clamp_rejects)
{
	struct bytebuf *rb = bytebuf_new(4);
	T_CHECK(rb != NULL);

	T_EXPECT(!mux_bytebuf_reserve(&rb, SIZE_MAX - rb->len, true));
	T_EXPECT_EQ(
		rb->cap, (size_t)4); /* untouched: rejected before realloc */

	bytebuf_free(rb);
}

/* The sibling above starts from len == 0, so `need > SIZE_MAX - rb->len` is
 * false and the later header-size guard rejects.  With a non-zero len the first
 * guard (len + need would overflow SIZE_MAX) is the one that must reject,
 * before any doubling or allocation. */
T_DECLARE_CASE(test_bytebuf_reserve_len_plus_need_overflow_rejects)
{
	struct bytebuf *rb = bytebuf_new(4);
	T_CHECK(rb != NULL);
	bytebuf_produce(rb, 4); /* len = 4 so len + need can overflow */
	T_CHECK(rb->len == 4);

	T_EXPECT(!mux_bytebuf_reserve(&rb, SIZE_MAX - 3, true));
	T_EXPECT_EQ(
		rb->cap, (size_t)4); /* untouched: rejected before realloc */

	bytebuf_free(rb);
}

/* bench - per-frame hot-path micro-benchmarks (opt-in: run with TESTING_BENCH set) */

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

/* mux_status_str must name every known code distinctly (a
 * peer's REFUSED_STREAM must not be reported the same as
 * FLOW_CONTROL_ERROR) and must not index by an untrusted, peer-controlled
 * value -- an unrecognized code (a future extension, or a hostile peer)
 * must name safely as "UNKNOWN" rather than reading out of bounds. */
T_DECLARE_CASE(test_mux_status_str_names_known_codes_distinctly)
{
	static const enum mux_status known[] = {
		MUX_STATUS_NO_ERROR,	       MUX_STATUS_PROTOCOL_ERROR,
		MUX_STATUS_FLOW_CONTROL_ERROR, MUX_STATUS_INTERNAL_ERROR,
		MUX_STATUS_REFUSED_STREAM,     MUX_STATUS_CANCEL,
	};
	for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
		const char *const name =
			mux_status_str((uint_fast16_t)known[i]);
		T_CHECK(name != NULL);
		T_EXPECT(strcmp(name, "UNKNOWN") != 0);
		for (size_t j = 0; j < i; j++) {
			const char *const other =
				mux_status_str((uint_fast16_t)known[j]);
			T_EXPECT(strcmp(name, other) != 0);
		}
	}

	T_EXPECT_STREQ(mux_status_str((uint_fast16_t)0xFFFF), "UNKNOWN");
}

static const struct testing_suite suite[] = {
	T_CASE(test_frame_get_resets_runtime_fields),
	T_CASE(test_frame_put_calls_allocator_free),
	T_CASE(test_header_roundtrip_preserves_all_fields),
	T_CASE(test_header_roundtrip_with_flag_combinations),
	T_CASE(test_frame_list_push_pop_fifo),
	T_CASE(test_frame_list_drain_clears_head_tail_and_count),
	T_CASE(test_frame_list_push_front_empty_and_nonempty),
	T_CASE(test_frame_list_remove_after_head_interior_tail),
	T_CASE(test_frame_ring_null_and_empty_ops),
	T_CASE(test_frame_ring_push_pop_fifo),
	T_CASE(test_frame_ring_grow_contiguous),
	T_CASE(test_frame_ring_grow_wrapped),
	T_CASE(test_frame_ring_peek_and_free_wrapped),
	T_CASE(test_frame_ring_grow_zeroes_new_slots),
	T_CASE(test_frame_ring_free_releases_all_frames),
	T_CASE(test_bytebuf_reserve_noop_when_space_available),
	T_CASE(test_bytebuf_reserve_compaction_recovers_space),
	T_CASE(test_bytebuf_reserve_returns_false_when_cannot_grow),
	T_CASE(test_bytebuf_reserve_doubling_growth_loop),
	T_CASE(test_bytebuf_reserve_overflow_clamp_rejects),
	T_CASE(test_bytebuf_reserve_len_plus_need_overflow_rejects),
	T_CASE(test_mux_status_str_names_known_codes_distinctly),
	/* Opt-in micro-benchmarks: each runs ~1s, so they are skipped by the
	 * default (unfiltered) run.  Select with `--bench <ere>` or TESTING_BENCH. */
	T_BENCH(bench_header_roundtrip),
	T_BENCH(bench_frame_ring_push_pop),
	T_BENCH(bench_frame_get_put),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
