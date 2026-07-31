/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* unacked_test.c - white-box tests for the session reliability ring (spec
 * §5.7); unacked.c #included, real frame.c linked; benches opt-in via
 * TESTING_BENCH env. */

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/unacked.c"
#include "mux/unacked.h"

#include "utils/slog.h"
#include "utils/testing.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* mock - the test frame allocator and session fixture
 * Fixture: a minimal session carrying only the fields unacked.c touches. */

struct frame_pool_ctx {
	uint_least32_t alloc_calls;
	uint_least32_t free_calls;
};

static struct mux_frame *unacked_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void unacked_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

/* session.c is not linked; mux_unacked_track_sent and unacked_push call
 * mux_session_reset directly on an unrecoverable desync, so stub it (counting
 * calls) to satisfy the link and let the malformed-layout tests assert it
 * fired. The unacked_push OOM path that also calls it is not exercised: forcing
 * mux_frame_ring_push's malloc to fail has no seam here (no fault-injection
 * allocator in this project's test style), and faking the ring's capacity to
 * force an oversized grow doesn't work under ASan either -- sizes near its
 * allocation ceiling abort instead of returning NULL, and smaller ones aren't
 * guaranteed to fail (overcommit). */
static int g_reset_calls;
void mux_session_reset(struct mux_session *ss)
{
	(void)ss;
	g_reset_calls++;
}

struct unacked_fixture {
	struct mux_session ss;
	struct frame_pool_ctx pool_ctx;
	/* Backs ss.cnt.unacked_frames so the frames <-> gauge mirror invariant
	 * (unacked.h) is observable; without it COUNTER_ADD/SUB are NULL no-ops
	 * and the mirror can drift undetected. */
	mux_gauge unacked_frames;
};

/* session_window is in MUX_WINDOW_UNIT units; 4 units = 65536 bytes keeps the
 * stall gate well clear of the small frames most cases push. */
static void uf_setup(struct unacked_fixture *restrict fx)
{
	*fx = (struct unacked_fixture){ 0 };
	fx->ss.pool = (struct mux_frame_allocator){
		.alloc = unacked_test_alloc,
		.free = unacked_test_free,
		.data = &fx->pool_ctx,
	};
	fx->ss.max_payload = MUX_MAX_PAYLOAD_SIZE;
	fx->ss.session_window = 4;
	fx->ss.unacked.retransmit_off = SIZE_MAX;
	fx->ss.cnt.unacked_frames = &fx->unacked_frames;
}

/* Drain any frames left in the ring; returns true when every allocation was
 * freed.  Callers wrap this in T_EXPECT so the leak check counts as the case's
 * final assertion (this helper has no testing context of its own). */
static bool uf_teardown(struct unacked_fixture *restrict fx)
{
	mux_unacked_free_all(&fx->ss);
	return fx->pool_ctx.alloc_calls == fx->pool_ctx.free_calls;
}

/* Build a frame holding @p n concatenated headers with the given payload
 * lengths, all on @p stream_id with the given protocol @p version.  Payload
 * bytes are left uninitialised: only the header length fields are parsed. */
static struct mux_frame *make_frame(
	struct unacked_fixture *restrict fx, const uint_least8_t version,
	const uint_least16_t stream_id, const uint_least16_t *restrict lengths,
	const size_t n)
{
	struct mux_frame *const f =
		mux_frame_get(&fx->ss.pool, fx->ss.max_payload);
	if (f == NULL) {
		return NULL;
	}
	size_t off = 0;
	for (size_t i = 0; i < n; i++) {
		const struct mux_header h = {
			.version = version,
			.flags = MUX_FLAG_PUSH,
			.length = lengths[i],
			.stream_id = stream_id,
			.extra = 0,
		};
		mux_write_header(f->data + off, &h);
		off += MUX_FRAME_HEADER_SIZE + lengths[i];
	}
	f->len = off;
	f->pos = 0;
	return f;
}

/* Convenience: a single-header data frame on stream 1 with @p payload bytes. */
static struct mux_frame *make_data_frame(
	struct unacked_fixture *restrict fx, const uint_least16_t payload)
{
	const uint_least16_t lengths[1] = { payload };
	return make_frame(fx, MUX_PROTOCOL_VERSION, 1, lengths, 1);
}

/* regression - targeted cases for one ring/counter behavior each */

/* mux_unacked_track_sent: classification of flushed frames. */

/* A hello frame (version 0) is handshake-only and must never enter the ring. */
T_DECLARE_CASE(test_track_sent_drops_hello)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	const uint_least16_t lengths[1] = { 16 };
	struct mux_frame *const f =
		make_frame(&fx, 0 /*version*/, 1, lengths, 1);
	T_EXPECT(f != NULL);

	mux_unacked_track_sent(&fx.ss, f);

	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 0);

	T_EXPECT(uf_teardown(&fx));
}

/* A lone stream-0 control frame is one-shot; the fast path drops it. */
T_DECLARE_CASE(test_track_sent_drops_single_ctrl)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	const uint_least16_t lengths[1] = { 0 };
	struct mux_frame *const f = make_frame(
		&fx, MUX_PROTOCOL_VERSION, STREAMID_CTRL, lengths, 1);
	T_EXPECT(f != NULL);

	mux_unacked_track_sent(&fx.ss, f);

	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 0);

	T_EXPECT(uf_teardown(&fx));
}

/* A single data frame takes the fast path: one ring entry, payload counted. */
T_DECLARE_CASE(test_track_sent_pushes_single_data)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));

	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)100);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 1);

	T_EXPECT(uf_teardown(&fx));
}

/* A coalesced frame mixing stream-0 controls and data: controls are stripped
 * (compacted out), only the data sub-frames are tracked. */
T_DECLARE_CASE(test_track_sent_strips_ctrl_from_mixed)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	/* Layout: ctrl(len 4) | data(len 50) | ctrl(len 0) | data(len 70). */
	struct mux_frame *const f =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_EXPECT(f != NULL);
	size_t off = 0;
	const struct {
		uint_least16_t sid, len;
	} parts[] = {
		{ STREAMID_CTRL, 4 }, { 1, 50 }, { STREAMID_CTRL, 0 }, { 1, 70 }
	};
	for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
		const struct mux_header h = {
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_PUSH,
			.length = parts[i].len,
			.stream_id = parts[i].sid,
		};
		mux_write_header(f->data + off, &h);
		off += MUX_FRAME_HEADER_SIZE + parts[i].len;
	}
	f->len = off;
	f->pos = 0;

	mux_unacked_track_sent(&fx.ss, f);

	/* Two data sub-frames survive as one ring entry (count 2). */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)2);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)(50 + 70));
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 1);

	T_EXPECT(uf_teardown(&fx));
}

/* A coalesced frame that is entirely stream-0 controls compacts to nothing and
 * is dropped without touching the ring. */
T_DECLARE_CASE(test_track_sent_drops_all_ctrl_mixed)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	const uint_least16_t lengths[2] = { 8, 0 };
	struct mux_frame *const f = make_frame(
		&fx, MUX_PROTOCOL_VERSION, STREAMID_CTRL, lengths, 2);
	T_EXPECT(f != NULL);

	mux_unacked_track_sent(&fx.ss, f);

	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 0);

	T_EXPECT(uf_teardown(&fx));
}

/* A retransmit copy (matched by pointer identity) advances the replay cursor
 * and is freed without re-entering the ring. */
T_DECLARE_CASE(test_track_sent_retransmit_copy_advances_cursor)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	/* One real entry so the cursor has somewhere to point. */
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	fx.ss.unacked.retransmit_off = 0;

	struct mux_frame *const copy = make_data_frame(&fx, 100);
	T_EXPECT(copy != NULL);
	fx.ss.unacked.retransmit_copy = copy;
	/* send_queue_retransmit captures the original entry's logical count here;
	 * mirror it so the retire branch advances retransmitted_frames. */
	fx.ss.unacked.retransmit_copy_count = 1;

	mux_unacked_track_sent(&fx.ss, copy);

	T_EXPECT(fx.ss.unacked.retransmit_copy == NULL);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)1);
	/* The single entry is now retransmitted: the counter folds in its count. */
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)1);
	/* The copy was freed, not tracked: ring still holds the single entry. */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);

	T_EXPECT(uf_teardown(&fx));
}

/* A malformed internal frame (trailing bytes shorter than a header) is freed
 * rather than mis-parsed, and -- since it was already flushed to the wire --
 * the session is reset instead of silently desyncing from the peer. */
T_DECLARE_CASE(test_track_sent_rejects_truncated_trailer)
{
	struct unacked_fixture fx;
	uf_setup(&fx);
	g_reset_calls = 0;

	/* First header (data, len 0) then 4 stray bytes: not a whole header. */
	struct mux_frame *const f =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_EXPECT(f != NULL);
	const struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 0,
		.stream_id = 1,
	};
	mux_write_header(f->data, &h);
	f->len = MUX_FRAME_HEADER_SIZE +
		 4; /* defeats the single-header fast path */
	f->pos = 0;

	mux_unacked_track_sent(&fx.ss, f);

	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 0);
	T_EXPECT_EQ(g_reset_calls, 1);

	T_EXPECT(uf_teardown(&fx));
}

/* A malformed internal frame whose header claims more payload than is present
 * is likewise freed and resets the session (already flushed to the wire). */
T_DECLARE_CASE(test_track_sent_rejects_overlong_header)
{
	struct unacked_fixture fx;
	uf_setup(&fx);
	g_reset_calls = 0;

	struct mux_frame *const f =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_EXPECT(f != NULL);
	const struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 4096, /* claims 4096 payload bytes ... */
		.stream_id = 1,
	};
	mux_write_header(f->data, &h);
	/* ... but the frame body is only 16 bytes, and the total length differs
	 * from the single-header size so the walk path runs. */
	f->len = MUX_FRAME_HEADER_SIZE + 16;
	f->pos = 0;

	mux_unacked_track_sent(&fx.ss, f);

	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 0);
	T_EXPECT_EQ(g_reset_calls, 1);

	T_EXPECT(uf_teardown(&fx));
}

/* Crossing session_window * MUX_WINDOW_UNIT payload bytes raises the stall
 * gate; a later ACK that drops back below the limit clears it. */
T_DECLARE_CASE(test_stall_gate_raise_and_clear)
{
	struct unacked_fixture fx;
	uf_setup(&fx);
	fx.ss.session_window = 1; /* limit = 16384 bytes */

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 10000));
	T_EXPECT(!fx.ss.unacked.stalled); /* 10000 < 16384 */

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 10000));
	T_EXPECT(fx.ss.unacked.stalled); /* 20000 >= 16384 */

	/* ACK one frame: 20000 - 10000 = 10000 < 16384 -> unstall. */
	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 1);
	T_EXPECT(r.ok);
	T_EXPECT(r.unstalled);
	T_EXPECT_EQ(r.trimmed_bytes, (size_t)10000);
	T_EXPECT(!fx.ss.unacked.stalled);

	T_EXPECT(uf_teardown(&fx));
}

/* mux_unacked_ack_trim: byte accounting, partial trims, error handling. */

/* Acking more frames than were ever sent is a peer protocol violation. */
T_DECLARE_CASE(test_ack_trim_overflow_rejected)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));

	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 5);
	T_EXPECT(!r.ok);
	/* Ring is untouched on rejection. */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);

	T_EXPECT(uf_teardown(&fx));
}

/* A zero-count ACK is a no-op that still reports success. */
T_DECLARE_CASE(test_ack_trim_zero_noop)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));

	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 0);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(r.trimmed_bytes, (size_t)0);
	T_EXPECT(!r.unstalled);
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);

	T_EXPECT(uf_teardown(&fx));
}

/* Full pop of several single-header entries: frames, bytes, and last_ack_recv
 * all advance, and every popped frame is freed. */
T_DECLARE_CASE(test_ack_trim_full_pop)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 200));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 300));
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)3);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)600);

	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 2);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(r.trimmed_bytes, (size_t)300); /* 100 + 200 */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)300);
	T_EXPECT_EQ(fx.ss.unacked.last_ack_recv, (uint_least32_t)2);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 1);
	/* The server-wide gauge tracks unacked.frames through push and trim. */
	T_EXPECT_EQ(
		COUNTER_LOAD(fx.ss.cnt.unacked_frames), fx.ss.unacked.frames);

	T_EXPECT(uf_teardown(&fx));
}

/* A coalesced multi-header entry can be acked across several calls: the first
 * call partial-trims in place (saving a byte offset), the second pops it. */
T_DECLARE_CASE(test_ack_trim_partial_then_complete)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	const uint_least16_t lengths[3] = { 100, 200, 300 };
	mux_unacked_track_sent(
		&fx.ss, make_frame(&fx, MUX_PROTOCOL_VERSION, 1, lengths, 3));
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)3);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)600);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 1);

	/* Partial: ack the first of the three sub-frames. */
	struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 1);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(r.trimmed_bytes, (size_t)100);
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)2);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)500);
	T_EXPECT_EQ(
		fx.ss.unacked.partial_offset,
		(uint_least32_t)(MUX_FRAME_HEADER_SIZE + 100));
	/* The entry is still in the ring, partially consumed. */
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 1);

	/* Complete: ack the remaining two sub-frames, resuming from the offset. */
	r = mux_unacked_ack_trim(&fx.ss, 2);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(r.trimmed_bytes, (size_t)500); /* 200 + 300 */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.partial_offset, (uint_least32_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 0);

	T_EXPECT(uf_teardown(&fx));
}

/* The defensive clamp: if the logical frame counter outruns the physical ring
 * (which should never happen), trim drains the ring and resets byte state
 * rather than reading past the end. */
T_DECLARE_CASE(test_ack_trim_clamps_when_ring_underflows)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	/* Corrupt the logical counter to exceed the one physical entry. */
	fx.ss.unacked.frames = 3;

	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 3);
	T_EXPECT(r.ok);
	/* One real frame popped; the phantom remainder is clamped back in. */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)2);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 0);

	/* Repair the counter so teardown's leak check is meaningful. */
	fx.ss.unacked.frames = 0;
	T_EXPECT(uf_teardown(&fx));
}

/* The in-flight retransmit cursor slides down by the number of popped entries
 * when it still points within the ring. */
T_DECLARE_CASE(test_ack_trim_shifts_retransmit_cursor)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	fx.ss.unacked.retransmit_off = 2;
	fx.ss.unacked.retransmitted_frames = 2; /* two entries retransmitted */

	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 1);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)1);
	/* Popping the head shifts the counter down in lockstep with the cursor. */
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)1);

	T_EXPECT(uf_teardown(&fx));
}

/* When the trim pops past the retransmit cursor and empties the ring, the
 * cursor floors at zero and is then invalidated (SIZE_MAX). */
T_DECLARE_CASE(test_ack_trim_invalidates_cursor_past_end)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	fx.ss.unacked.retransmit_off = 1;
	fx.ss.unacked.retransmitted_frames = 1; /* one entry retransmitted */

	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 2);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)SIZE_MAX);
	/* Draining the ring invalidates the cursor and zeroes the counter. */
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

/* mux_unacked_ack_recv: bounds a peer ACK received mid-replay by what has
 * actually been retransmitted, so a mux_session_send_ctrl frame deferred behind
 * replay can't be exploited by claiming credit for an entry still awaiting
 * retransmission. */

/* A count exceeding the retransmitted prefix is rejected even though it is
 * within the overall unacked total. */
T_DECLARE_CASE(test_ack_recv_rejects_past_retransmit_cursor)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	fx.ss.unacked.retransmit_off =
		1; /* only the first entry retransmitted */
	fx.ss.unacked.retransmitted_frames = 1;

	const struct unacked_ack_result r = mux_unacked_ack_recv(&fx.ss, 2);
	T_EXPECT(!r.ok);
	/* Rejected before any state changed. */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)3);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)1);
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)1);

	T_EXPECT(uf_teardown(&fx));
}

/* A count exactly matching the retransmitted prefix is accepted. */
T_DECLARE_CASE(test_ack_recv_accepts_within_retransmit_cursor)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	fx.ss.unacked.retransmit_off = 2; /* first two entries retransmitted */
	fx.ss.unacked.retransmitted_frames = 2;

	const struct unacked_ack_result r = mux_unacked_ack_recv(&fx.ss, 2);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);
	/* Both retransmitted entries popped: cursor and counter fall to zero. */
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

/* Outside replay (the common case) mux_unacked_ack_recv behaves exactly like
 * mux_unacked_ack_trim: bounded only by the overall unacked total. */
T_DECLARE_CASE(test_ack_recv_unbounded_when_not_replaying)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	T_CHECK(fx.ss.unacked.retransmit_off == SIZE_MAX);

	const struct unacked_ack_result r = mux_unacked_ack_recv(&fx.ss, 2);
	T_EXPECT(r.ok);
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

/* The replay bound is a sum of unacked_count across the retransmitted prefix, so
 * a single coalesced ring entry (3 logical sub-frames) that has been
 * retransmitted contributes 3 to the bound.  Prior bound cases used only
 * single-header entries, leaving the summation untested.  A count on the sum is
 * accepted; one past it is rejected with no state change. */
T_DECLARE_CASE(test_ack_recv_bounds_coalesced_prefix_accept)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	const uint_least16_t lengths[3] = { 100, 100, 100 };
	mux_unacked_track_sent(
		&fx.ss, make_frame(&fx, MUX_PROTOCOL_VERSION, 1, lengths, 3));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	/* Only the coalesced entry is retransmitted: bound = its 3 sub-frames. */
	fx.ss.unacked.retransmit_off = 1;
	fx.ss.unacked.retransmitted_frames = 3;

	const struct unacked_ack_result r = mux_unacked_ack_recv(&fx.ss, 3);
	T_EXPECT(r.ok);
	/* The coalesced entry is fully popped; the trailing data entry remains. */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

T_DECLARE_CASE(test_ack_recv_bounds_coalesced_prefix_reject)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	const uint_least16_t lengths[3] = { 100, 100, 100 };
	mux_unacked_track_sent(
		&fx.ss, make_frame(&fx, MUX_PROTOCOL_VERSION, 1, lengths, 3));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	fx.ss.unacked.retransmit_off = 1;
	fx.ss.unacked.retransmitted_frames = 3;

	/* count 4 is within the overall unacked total (3 + 1) but past the
	 * retransmitted sum of 3: rejected before any state changes. */
	const struct unacked_ack_result r = mux_unacked_ack_recv(&fx.ss, 4);
	T_EXPECT(!r.ok);
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)4);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)1);
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)3);

	T_EXPECT(uf_teardown(&fx));
}

/* Brute-force recompute of the retransmitted-prefix sum, independent of the
 * incrementally-maintained unacked.retransmitted_frames counter, for the stress
 * cross-check below. */
static size_t replay_prefix_sum(const struct unacked_fixture *restrict fx)
{
	if (fx->ss.unacked.retransmit_off == SIZE_MAX ||
	    fx->ss.unacked.ring == NULL) {
		return 0;
	}
	size_t total = 0;
	for (size_t i = 0; i < fx->ss.unacked.retransmit_off; i++) {
		total += mux_frame_ring_peek(fx->ss.unacked.ring, i)
				 ->unacked_count;
	}
	return total;
}

/* Resume-replay stress test (issue #45): drive a large ring of mixed-width
 * entries through a full replay, retiring copies one at a time and letting the
 * peer ACK small 2-8 frame batches -- the exact pattern whose per-ACK rescan was
 * O(n^2).  After every retire and every ACK the running counter must equal a
 * brute-force recompute, and the security bound must reject one frame past what
 * has actually been retransmitted while accepting the batch. */
T_DECLARE_CASE(test_replay_counter_consistency_stress)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	enum { N = 1500 };
	size_t pushed = 0;
	for (size_t i = 0; i < N; i++) {
		const uint_least16_t lengths[3] = { 40, 41, 42 };
		const size_t width =
			(i % 3) + 1; /* 1, 2, or 3 logical sub-frames */
		mux_unacked_track_sent(
			&fx.ss,
			make_frame(
				&fx, MUX_PROTOCOL_VERSION, 1, lengths, width));
		pushed += width;
	}
	T_EXPECT_EQ(fx.ss.unacked.frames, pushed);

	/* Arm replay from the head, as mux_session_suspend()/the resume handshake do. */
	unacked_set_replay_off(&fx.ss.unacked, 0);
	T_CHECK(fx.ss.unacked.retransmitted_frames == replay_prefix_sum(&fx));

	size_t ack_cycle = 2;
	while (fx.ss.unacked.retransmit_off != SIZE_MAX &&
	       fx.ss.unacked.ring != NULL && fx.ss.unacked.ring->count > 0) {
		/* Retransmit the entry at the cursor: mirror send_queue_retransmit's
		 * capture and the fully-flushed copy reaching mux_unacked_track_sent. */
		if (fx.ss.unacked.retransmit_off < fx.ss.unacked.ring->count) {
			const struct mux_frame *const orig =
				mux_frame_ring_peek(
					fx.ss.unacked.ring,
					fx.ss.unacked.retransmit_off);
			struct mux_frame *const copy = make_data_frame(&fx, 8);
			T_CHECK(copy != NULL);
			fx.ss.unacked.retransmit_copy = copy;
			fx.ss.unacked.retransmit_copy_count =
				orig->unacked_count;
			mux_unacked_track_sent(&fx.ss, copy);
			T_CHECK(fx.ss.unacked.retransmitted_frames ==
				replay_prefix_sum(&fx));
		}

		const size_t avail = fx.ss.unacked.retransmitted_frames;
		if (avail == 0) {
			continue; /* nothing retransmitted yet; keep advancing */
		}
		/* One past the retransmitted sum must be refused by the bound. */
		const size_t before = fx.ss.unacked.frames;
		const struct unacked_ack_result rej = mux_unacked_ack_recv(
			&fx.ss, (uint_fast32_t)(avail + 1));
		T_CHECK(!rej.ok);
		T_CHECK(fx.ss.unacked.frames == before);

		/* A conformant peer ACKs a small batch within the retransmitted sum. */
		const size_t batch = ack_cycle < avail ? ack_cycle : avail;
		const struct unacked_ack_result ok =
			mux_unacked_ack_recv(&fx.ss, (uint_fast32_t)batch);
		T_CHECK(ok.ok);
		T_CHECK(fx.ss.unacked.retransmit_off == SIZE_MAX ||
			fx.ss.unacked.retransmitted_frames ==
				replay_prefix_sum(&fx));
		ack_cycle = ack_cycle >= 8 ? 2 : ack_cycle + 1;
	}

	/* Replay ran to completion: ring drained, cursor invalidated, counter 0. */
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)SIZE_MAX);
	T_EXPECT_EQ(fx.ss.unacked.retransmitted_frames, (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

/* mux_unacked_resume_ack_recv: resume-time trim and cursor positioning. */

/* A resume hello acking some frames trims them and parks the replay cursor at
 * the first surviving entry. */
T_DECLARE_CASE(test_resume_ack_positions_cursor)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));

	T_EXPECT(mux_unacked_resume_ack_recv(&fx.ss, 2));
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)1);
	T_EXPECT_EQ(fx.ss.unacked.last_ack_recv, (uint_least32_t)2);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

/* A resume ack landing inside a coalesced entry trims the acked sub-frame(s) and
 * parks the replay cursor part-way into the surviving entry (partial_offset > 0)
 * — the `retransmit_off == 0 && partial_offset != 0` state send_queue_retransmit's
 * skip logic is built for, which the single-header cases never produce. */
T_DECLARE_CASE(test_resume_ack_trims_into_coalesced_entry)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	/* One ring entry coalescing three data sub-frames on stream 1. */
	const uint_least16_t lengths[3] = { 100, 200, 300 };
	struct mux_frame *const f =
		make_frame(&fx, MUX_PROTOCOL_VERSION, 1, lengths, 3);
	T_EXPECT(f != NULL);
	mux_unacked_track_sent(&fx.ss, f);
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)3);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 1);

	/* Ack the first sub-frame only: the coalesced entry survives, its cursor
	 * advanced past the first header + payload. */
	T_EXPECT(mux_unacked_resume_ack_recv(&fx.ss, 1));
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)2);
	T_EXPECT_EQ(
		fx.ss.unacked.partial_offset,
		(uint_least32_t)(MUX_FRAME_HEADER_SIZE + 100));
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)0);
	T_EXPECT(mux_frame_ring_size(fx.ss.unacked.ring) == 1);

	T_EXPECT(uf_teardown(&fx));
}

/* A resume hello acking everything leaves an empty ring and an invalid cursor. */
T_DECLARE_CASE(test_resume_ack_empties_ring)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));

	T_EXPECT(mux_unacked_resume_ack_recv(&fx.ss, 2));
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)SIZE_MAX);

	T_EXPECT(uf_teardown(&fx));
}

/* A peer_ack that regresses below what was already acked is a protocol error. */
T_DECLARE_CASE(test_resume_ack_regress_rejected)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	fx.ss.unacked.last_ack_recv = 5;

	T_EXPECT(!mux_unacked_resume_ack_recv(&fx.ss, 3));

	fx.ss.unacked.last_ack_recv =
		0; /* keep teardown's counters consistent */
	T_EXPECT(uf_teardown(&fx));
}

/* A peer_ack that is numerically below last_ack_recv but is ahead in 32-bit
 * serial space (wrapped past UINT32_MAX) must be accepted, not rejected. */
T_DECLARE_CASE(test_resume_ack_wrap_accepted)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	/* Wind last_ack_recv to the top of the 32-bit serial space, then track one
	 * outstanding frame, so a peer_ack of 0 sits just past it across the wrap. */
	fx.ss.unacked.last_ack_recv = UINT32_MAX;
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));

	/* peer_ack = 0: peer received the frame at seq UINT32_MAX (wrap).
	 * In raw uint32: 0 < UINT32_MAX → old code falsely rejects.
	 * serial_lt32(0, UINT32_MAX): d = UINT32_MAX > 2^31 → not lt → accepted. */
	T_EXPECT(mux_unacked_resume_ack_recv(&fx.ss, UINT32_C(0)));

	T_EXPECT(uf_teardown(&fx));
}

/* A resume ack covering more frames than are outstanding is rejected once the
 * ring runs dry; the frames it did cover stay trimmed (the caller must tear
 * the session down). */
T_DECLARE_CASE(test_resume_ack_overflow_rejected)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));

	T_EXPECT(!mux_unacked_resume_ack_recv(&fx.ss, 5));
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

/* Session-ACK accounting and teardown. */

/* ack_emitted subtracts the reported count and resets the emission timer. */
T_DECLARE_CASE(test_ack_emitted_clears_unreported)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	fx.ss.unacked.unreported = 3;
	fx.ss.unacked.ack_ticks = 3;

	mux_unacked_ack_emitted(&fx.ss, 3);
	T_EXPECT_EQ(fx.ss.unacked.unreported, (uint_least32_t)0);
	T_EXPECT_EQ(fx.ss.unacked.ack_ticks, 0);

	T_EXPECT(uf_teardown(&fx));
}

/* A partial emission (fewer reported than outstanding) subtracts only the
 * reported count, leaving the remainder for a later session ACK (spec §5.7.3).
 * The 16-bit Extra-field clamp that produces such a partial count lives in
 * send.c and is covered by send_test.c. */
T_DECLARE_CASE(test_ack_emitted_partial_keeps_remainder)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	fx.ss.unacked.unreported = 5;

	mux_unacked_ack_emitted(&fx.ss, 3);
	T_EXPECT_EQ(fx.ss.unacked.unreported, (uint_least32_t)2);

	T_EXPECT(uf_teardown(&fx));
}

/* free_all discards a non-empty ring and resets all derived state. */
T_DECLARE_CASE(test_free_all_resets_state)
{
	struct unacked_fixture fx;
	uf_setup(&fx);

	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
	mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 200));
	fx.ss.unacked.retransmit_off = 0;
	fx.ss.unacked.partial_offset = 7;
	/* A replay in flight: the copy tracks the ring entry about to be freed. */
	struct mux_frame *const copy = make_data_frame(&fx, 50);
	fx.ss.unacked.retransmit_copy = copy;
	fx.ss.unacked.stalled = true;

	mux_unacked_free_all(&fx.ss);

	T_EXPECT(fx.ss.unacked.ring == NULL);
	T_EXPECT_EQ(fx.ss.unacked.frames, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.bytes, (size_t)0);
	T_EXPECT_EQ(fx.ss.unacked.partial_offset, (uint_least32_t)0);
	T_EXPECT_EQ(fx.ss.unacked.retransmit_off, (size_t)SIZE_MAX);
	/* The copy must not outlive the ring it referred to: left set, a frame
	 * the pool later returns at the same address false-matches
	 * mux_unacked_track_sent's identity check, which then peeks the freed (NULL)
	 * ring with its ASSERT compiled out of every shipped build. */
	T_EXPECT(fx.ss.unacked.retransmit_copy == NULL);
	/* stalled is a pure function of bytes, so it falls with them here rather
	 * than depending on mux_sched_free_streams (another module) running first. */
	T_EXPECT(!fx.ss.unacked.stalled);
	/* The copy itself belongs to the send buffer that queued it (production
	 * frees it in mux_wire_discard_buffers); mux_unacked_free_all only drops the
	 * tracking pointer, so release it here to keep the pool balanced. */
	mux_frame_put(&fx.ss.pool, copy);
	/* mux_unacked_free_all must decrement the gauge by the frames it drops, not
	 * just zero the local mirror (regression: it left the server-wide gauge
	 * permanently inflated). */
	T_EXPECT_EQ(COUNTER_LOAD(fx.ss.cnt.unacked_frames), (size_t)0);

	T_EXPECT(uf_teardown(&fx));
}

/* bench - steady-state send/ack reliability cost (opt-in: run with TESTING_BENCH) */

/* Recycling allocator: hands frames back from a fixed pool so the bench
 * measures unacked's ring/classification cost, not malloc/free. */
enum { BENCH_POOL_N = 8 };
/* Frame objects are heap-allocated (the payload is a flexible array member, so
 * they cannot live in a static array); the bench recycles these pointers. */
static struct mux_frame *g_bench_free[BENCH_POOL_N];
static size_t g_bench_top;

static struct mux_frame *bench_pool_alloc(void *data, const size_t size)
{
	(void)data;
	(void)size;
	return g_bench_top > 0 ? g_bench_free[--g_bench_top] : NULL;
}

static void bench_pool_free(void *data, struct mux_frame *frame)
{
	(void)data;
	if (g_bench_top < BENCH_POOL_N) {
		g_bench_free[g_bench_top++] = frame;
	}
}

T_DECLARE_BENCH(bench_unacked_track_and_trim)
{
	g_bench_top = 0;
	for (size_t i = 0; i < BENCH_POOL_N; i++) {
		struct mux_frame *const frame =
			malloc(MUX_FRAME_OBJECT_SIZE(MUX_MAX_PAYLOAD_SIZE));
		T_CHECK(frame != NULL);
		g_bench_free[g_bench_top++] = frame;
	}
	struct unacked_fixture fx;
	uf_setup(&fx);
	fx.ss.pool = (struct mux_frame_allocator){
		.alloc = bench_pool_alloc,
		.free = bench_pool_free,
	};

	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		/* Track one sent data frame, then ack exactly it: ring stays
		 * bounded and the frame recycles through the pool. */
		mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 100));
		(void)mux_unacked_ack_trim(&fx.ss, 1);
	}
	mux_unacked_free_all(&fx.ss);
	for (size_t i = 0; i < g_bench_top; i++) {
		free(g_bench_free[i]);
	}
}

/* Dedicated recycling pool for the replay bench: it keeps a whole ring plus the
 * in-flight copy live at once, so it needs many more frames than the steady-state
 * bench above.  Small frames (REPLAY_CAP) keep the pool cheap. */
enum { REPLAY_RING = 256, REPLAY_CAP = 256, REPLAY_POOL_N = REPLAY_RING + 4 };
static struct mux_frame *g_replay_free[REPLAY_POOL_N];
static size_t g_replay_top;

static struct mux_frame *replay_pool_alloc(void *data, const size_t size)
{
	(void)data;
	(void)size;
	return g_replay_top > 0 ? g_replay_free[--g_replay_top] : NULL;
}

static void replay_pool_free(void *data, struct mux_frame *frame)
{
	(void)data;
	if (g_replay_top < REPLAY_POOL_N) {
		g_replay_free[g_replay_top++] = frame;
	}
}

/* Replay-accounting cost (issue #45): fill a ring, then run a full resume replay
 * -- retire every entry and ACK it back in small batches.  Retire folds one
 * entry's logical count into the running counter in O(1) and each ACK reconciles
 * only the popped prefix, so a whole replay is O(total frames) instead of the
 * O(n^2) the per-ACK rescan cost.  In shipped (NDEBUG) builds mux_unacked_ack_recv's
 * bound is a single field read; the O(n) cross-check verifier is compiled out,
 * so build Release to read the production replay cost from this bench. */
T_DECLARE_BENCH(bench_unacked_replay_accounting)
{
	g_replay_top = 0;
	for (size_t i = 0; i < REPLAY_POOL_N; i++) {
		struct mux_frame *const frame =
			malloc(MUX_FRAME_OBJECT_SIZE(REPLAY_CAP));
		T_CHECK(frame != NULL);
		g_replay_free[g_replay_top++] = frame;
	}
	struct unacked_fixture fx;
	uf_setup(&fx);
	fx.ss.max_payload = REPLAY_CAP;
	fx.ss.pool = (struct mux_frame_allocator){
		.alloc = replay_pool_alloc,
		.free = replay_pool_free,
	};

	for (uint_fast64_t it = 0; it < _b_->N; it++) {
		for (size_t i = 0; i < REPLAY_RING; i++) {
			mux_unacked_track_sent(&fx.ss, make_data_frame(&fx, 8));
		}
		unacked_set_replay_off(&fx.ss.unacked, 0);
		while (fx.ss.unacked.retransmit_off != SIZE_MAX &&
		       fx.ss.unacked.ring != NULL &&
		       fx.ss.unacked.ring->count > 0) {
			if (fx.ss.unacked.retransmit_off <
			    fx.ss.unacked.ring->count) {
				const struct mux_frame *const orig =
					mux_frame_ring_peek(
						fx.ss.unacked.ring,
						fx.ss.unacked.retransmit_off);
				struct mux_frame *const copy =
					make_data_frame(&fx, 8);
				fx.ss.unacked.retransmit_copy = copy;
				fx.ss.unacked.retransmit_copy_count =
					orig->unacked_count;
				mux_unacked_track_sent(&fx.ss, copy);
			}
			const size_t avail = fx.ss.unacked.retransmitted_frames;
			if (avail > 0) {
				const size_t batch = avail < 4 ? avail : 4;
				(void)mux_unacked_ack_recv(
					&fx.ss, (uint_fast32_t)batch);
			}
		}
	}
	mux_unacked_free_all(&fx.ss);
	for (size_t i = 0; i < g_replay_top; i++) {
		free(g_replay_free[i]);
	}
}

static const struct testing_suite suite[] = {
	T_CASE(test_track_sent_drops_hello),
	T_CASE(test_track_sent_drops_single_ctrl),
	T_CASE(test_track_sent_pushes_single_data),
	T_CASE(test_track_sent_strips_ctrl_from_mixed),
	T_CASE(test_track_sent_drops_all_ctrl_mixed),
	T_CASE(test_track_sent_retransmit_copy_advances_cursor),
	T_CASE(test_track_sent_rejects_truncated_trailer),
	T_CASE(test_track_sent_rejects_overlong_header),
	T_CASE(test_stall_gate_raise_and_clear),
	T_CASE(test_ack_trim_overflow_rejected),
	T_CASE(test_ack_trim_zero_noop),
	T_CASE(test_ack_trim_full_pop),
	T_CASE(test_ack_trim_partial_then_complete),
	T_CASE(test_ack_trim_clamps_when_ring_underflows),
	T_CASE(test_ack_trim_shifts_retransmit_cursor),
	T_CASE(test_ack_trim_invalidates_cursor_past_end),
	T_CASE(test_ack_recv_rejects_past_retransmit_cursor),
	T_CASE(test_ack_recv_accepts_within_retransmit_cursor),
	T_CASE(test_ack_recv_unbounded_when_not_replaying),
	T_CASE(test_ack_recv_bounds_coalesced_prefix_accept),
	T_CASE(test_ack_recv_bounds_coalesced_prefix_reject),
	T_CASE(test_replay_counter_consistency_stress),
	T_CASE(test_resume_ack_positions_cursor),
	T_CASE(test_resume_ack_trims_into_coalesced_entry),
	T_CASE(test_resume_ack_empties_ring),
	T_CASE(test_resume_ack_regress_rejected),
	T_CASE(test_resume_ack_wrap_accepted),
	T_CASE(test_resume_ack_overflow_rejected),
	T_CASE(test_ack_emitted_clears_unreported),
	T_CASE(test_ack_emitted_partial_keeps_remainder),
	T_CASE(test_free_all_resets_state),
	/* Opt-in micro-benchmark: ~1s, skipped by the default (unfiltered) run.
	 * Select with `--bench <ere>` or TESTING_BENCH. */
	T_BENCH(bench_unacked_track_and_trim),
	T_BENCH(bench_unacked_replay_accounting),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* Exercise the DEBUG-level stall/unstall diagnostics in unacked.c. */
	slog_level_ = LOG_LEVEL_DEBUG;

	return testing_main(argc, argv, suite);
}
