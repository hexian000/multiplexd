/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/session.h"
#include "mux/stream.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mux/sched.c"

static int g_update_watcher_calls;
static int g_send_ctrl_calls;
static uint_fast16_t g_last_ctrl_stream_id;
static uint_fast8_t g_last_ctrl_flags;
static uint_fast32_t g_last_ctrl_extra;
static uint_fast32_t g_stream_grant_inc;
static int g_mark_fin_sent_calls;
static int g_send_push_calls;
static struct mux_frame *g_last_sent_frame;
static int g_stream_on_send_calls;
static int g_flush_calls;
static int g_mark_syn_sent_calls;
static int g_stream_free_calls;
static int g_emit_ack_calls;
static int g_stream_check_ack_calls;
static int g_session_initiate_shutdown_calls;

static void sched_test_reset(void)
{
	g_update_watcher_calls = 0;
	g_send_ctrl_calls = 0;
	g_last_ctrl_stream_id = 0;
	g_last_ctrl_flags = 0;
	g_last_ctrl_extra = 0;
	g_stream_grant_inc = 0;
	g_mark_fin_sent_calls = 0;
	g_send_push_calls = 0;
	g_last_sent_frame = NULL;
	g_stream_on_send_calls = 0;
	g_flush_calls = 0;
	g_mark_syn_sent_calls = 0;
	g_stream_free_calls = 0;
	g_emit_ack_calls = 0;
	g_stream_check_ack_calls = 0;
	g_session_initiate_shutdown_calls = 0;
}

static void
sched_timer_noop_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

int stream_format_tag(
	char *restrict buf, const size_t buflen,
	const struct mux_stream *restrict s)
{
	(void)s;
	return snprintf(buf, buflen, "[stream]:");
}

void session_update_watcher(struct mux_session *ss)
{
	(void)ss;
	g_update_watcher_calls++;
}

bool session_send_ctrl(
	struct mux_session *restrict ss, const uint_fast16_t stream_id,
	const uint_fast8_t flags, const uint_fast32_t extra)
{
	(void)ss;
	g_send_ctrl_calls++;
	g_last_ctrl_stream_id = stream_id;
	g_last_ctrl_flags = flags;
	g_last_ctrl_extra = extra;
	return true;
}

uint_fast32_t stream_grant_inc(const struct mux_stream *s)
{
	(void)s;
	return g_stream_grant_inc;
}

void stream_mark_fin_sent(struct mux_stream *s)
{
	(void)s;
	g_mark_fin_sent_calls++;
}

bool session_send_push(
	struct mux_session *ss, struct mux_stream *s, struct mux_frame *frame)
{
	(void)ss;
	(void)s;
	g_send_push_calls++;
	g_last_sent_frame = frame;
	return true;
}

struct mux_frame *stream_dequeue_send(struct mux_stream *restrict s)
{
	return mux_frame_list_pop(&s->send_queue);
}

void stream_on_send(struct mux_stream *restrict s)
{
	(void)s;
	g_stream_on_send_calls++;
}

void session_flush(struct mux_session *ss)
{
	(void)ss;
	g_flush_calls++;
}

void stream_mark_syn_sent(struct mux_stream *s)
{
	g_mark_syn_sent_calls++;
	s->state = STREAM_SYN_SENT;
}

void stream_free(struct mux_stream *s)
{
	g_stream_free_calls++;
	free(s);
}

void session_emit_ack(struct mux_session *ss)
{
	(void)ss;
	g_emit_ack_calls++;
}

static int g_stream_check_ack_calls;

void stream_check_ack(struct mux_stream *s)
{
	(void)s;
	g_stream_check_ack_calls++;
}

void session_initiate_shutdown(struct mux_session *ss)
{
	(void)ss;
	g_session_initiate_shutdown_calls++;
}

static struct mux_session make_session(void)
{
	struct mux_session ss = {
		.loop = ev_loop_new(EVFLAG_AUTO),
		.state = SESSION_ESTABLISHED,
		.session_window = 8,
		.stream_window = 4,
		.tag = (char *)"[test]:",
	};
	T_CHECK(ss.loop != NULL);
	ss.sched.streams = table_new(TABLE_FAST);
	T_CHECK(ss.sched.streams != NULL);
	ss.w_socket.fd = -1;
	ev_timer_init(&ss.w_idle_timeout, sched_timer_noop_cb, 0.0, 1.0);
	ss.w_idle_timeout.data = &ss;
	sched_init(&ss);
	return ss;
}

static void sched_test_bind_watchers(struct mux_session *restrict ss)
{
	ss->w_idle_timeout.data = ss;
	ss->sched.w_sched.data = ss;
	ss->sched.w_coalesce.data = ss;
}

static void cleanup_session(struct mux_session *restrict ss)
{
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
	if (ss->loop != NULL) {
		ev_loop_destroy(ss->loop);
		ss->loop = NULL;
	}
}

T_DECLARE_CASE(test_sched_alloc_stream_id_bitmap_nearly_full)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);

	/* Server session: even IDs; bitmap index = id >> 1. */
	ss.accepted = true;
	/* Occupy all bitmap slots then free exactly one: index 32767 (ID 65534). */
	memset(ss.sched.id_bitmap, 0xFF, sizeof(ss.sched.id_bitmap));
	ss.sched.id_bitmap[32767 / BITMAP_WORD_BITS] &=
		~((uint_fast32_t)1 << (32767 % BITMAP_WORD_BITS));

	/* Allocator scans from index 1 (skipping STREAMID_CTRL at 0),
	 * finds all taken, then finds the free slot at 32767 → ID 65534. */
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)65534);

	/* Occupy the last slot; next call must report exhaustion. */
	ss.sched.id_bitmap[32767 / BITMAP_WORD_BITS] |=
		(uint_fast32_t)1 << (32767 % BITMAP_WORD_BITS);
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_alloc_stream_id_starts_at_minimum)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);

	/* Client (odd IDs): first allocation returns ID 1. */
	ss.accepted = false;
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)1);

	/* Server (even IDs): first allocation skips STREAMID_CTRL and returns ID 2. */
	ss.accepted = true;
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)2);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_add_remove_updates_table_and_idle_timeout)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = { .id = 3 };

	sched_test_reset();
	ss.conf.idle_timeout = 1;
	T_EXPECT(sched_add_stream(&ss, &stream));
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)1);
	T_EXPECT(!ev_is_active(&ss.w_idle_timeout));

	sched_remove_stream(&ss, &stream);
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)0);
	T_EXPECT(ev_is_active(&ss.w_idle_timeout));

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_free_streams_clears_stream_counter)
{
	struct mux_session ss = make_session();
	struct mux_stream *first = calloc(1, sizeof(*first));
	struct mux_stream *second = calloc(1, sizeof(*second));

	sched_test_bind_watchers(&ss);
	T_CHECK(first != NULL);
	T_CHECK(second != NULL);
	first->id = 3;
	second->id = 5;
	sched_test_reset();
	T_EXPECT(sched_add_stream(&ss, first));
	T_EXPECT(sched_add_stream(&ss, second));
	ss.send_stalled = true;

	sched_free_streams(&ss);
	T_EXPECT(ss.cnt.num_stream_failed == NULL);
	T_EXPECT_EQ(g_stream_free_calls, 2);
	T_EXPECT(ss.sched.streams == NULL);
	T_EXPECT(!ss.send_stalled);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_wake_enqueues_only_once)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = {
		.id = 5,
		.state = STREAM_ESTABLISHED,
	};

	sched_test_reset();
	sched_wake(&ss, &stream);
	sched_wake(&ss, &stream);
	T_EXPECT(ss.sched.sched_head == &stream);
	T_EXPECT(ss.sched.sched_tail == &stream);
	T_EXPECT(stream.is_ready);
	T_EXPECT(ss.wire.tx_pending);
	T_EXPECT_EQ(g_update_watcher_calls, 2);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_dequeue_preserves_fifo_order)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream first = { .id = 1 };
	struct mux_stream second = { .id = 3 };
	struct mux_stream third = { .id = 5 };

	sched_enqueue(&ss, &first);
	sched_enqueue(&ss, &second);
	sched_enqueue(&ss, &third);

	T_EXPECT(sched_dequeue(&ss) == &first);
	T_EXPECT(sched_dequeue(&ss) == &second);
	T_EXPECT(sched_dequeue(&ss) == &third);
	T_EXPECT(sched_dequeue(&ss) == NULL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_delay_remove_handles_head_middle_and_tail)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream first = { .id = 1, .delay_pending = true };
	struct mux_stream second = { .id = 3, .delay_pending = true };
	struct mux_stream third = { .id = 5, .delay_pending = true };

	ss.sched.delay_head = &first;
	first.delay_next = &second;
	second.delay_prev = &first;
	second.delay_next = &third;
	third.delay_prev = &second;

	sched_delay_remove(&ss, &second);
	T_EXPECT(first.delay_next == &third);
	T_EXPECT(third.delay_prev == &first);
	T_EXPECT(!second.delay_pending);

	sched_delay_remove(&ss, &first);
	T_EXPECT(ss.sched.delay_head == &third);
	T_EXPECT(third.delay_prev == NULL);

	sched_delay_remove(&ss, &third);
	T_EXPECT(ss.sched.delay_head == NULL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_send_ctrl_flags_emits_ack_and_fin)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = {
		.id = 7,
		.state = STREAM_ESTABLISHED,
		.ack_pending = true,
		.rx_eof = true,
		.recv_window = 4 * MUX_WINDOW_UNIT,
	};

	sched_test_reset();
	g_stream_grant_inc = 2;
	sched_send_ctrl_flags(&ss, &stream);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_stream_id, (uint_fast16_t)7);
	T_EXPECT_EQ(
		g_last_ctrl_flags, (uint_fast8_t)(MUX_FLAG_ACK | MUX_FLAG_FIN));
	T_EXPECT_EQ(g_last_ctrl_extra, (uint_fast32_t)2);
	T_EXPECT_EQ(stream.grant_sent, (uint_least32_t)(2 * MUX_WINDOW_UNIT));
	T_EXPECT(!stream.ack_pending);
	T_EXPECT(ss.ack_pending);
	T_EXPECT_EQ(g_mark_fin_sent_calls, 1);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_next_data_sends_frame_and_resets_deficit_on_drain)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = {
		.id = 9,
		.state = STREAM_ESTABLISHED,
	};
	struct mux_frame frame = {
		.len = MUX_FRAME_HEADER_SIZE + 16,
	};

	sched_test_reset();
	mux_frame_list_push(&stream.send_queue, &frame);
	sched_enqueue(&ss, &stream);
	T_EXPECT(sched_next_data(&ss));
	T_EXPECT_EQ(g_send_push_calls, 1);
	T_EXPECT(g_last_sent_frame == &frame);
	T_EXPECT_EQ(g_stream_on_send_calls, 1);
	T_EXPECT_EQ(stream.deficit, (uint_least32_t)0);
	T_EXPECT(ss.sched.drr_active == NULL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_cb_sends_syn_for_init_stream)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = {
		.id = 11,
		.state = STREAM_INIT,
	};

	sched_test_reset();
	g_stream_grant_inc = 3;
	sched_lp_enqueue(&ss, &stream);
	ev_idle_start(ss.loop, &ss.sched.w_sched);
	sched_cb(ss.loop, &ss.sched.w_sched, EV_IDLE);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_flags, (uint_fast8_t)MUX_FLAG_SYN);
	T_EXPECT_EQ(g_last_ctrl_extra, (uint_fast32_t)3);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 1);
	T_EXPECT_EQ(g_flush_calls, 1);
	T_EXPECT_EQ(stream.state, (enum stream_state)STREAM_SYN_SENT);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_coalesce_forces_session_ack_after_tick_budget)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);

	sched_test_reset();
	ss.recv_seq = 5;
	ss.ack_seq = 1;
	ss.session_ack_ticks = MUX_SESSION_ACK_MAX_TICKS - 1;
	sched_coalesce_cb(ss.loop, &ss.sched.w_coalesce, EV_TIMER);
	T_EXPECT_EQ(g_emit_ack_calls, 1);

	cleanup_session(&ss);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_sched_alloc_stream_id_bitmap_nearly_full);
	T_RUN_CASE(t, test_sched_alloc_stream_id_bitmap_nearly_full);
	T_RUN_CASE(t, test_sched_alloc_stream_id_starts_at_minimum);
	T_RUN_CASE(t, test_sched_add_remove_updates_table_and_idle_timeout);
	T_RUN_CASE(t, test_sched_free_streams_clears_stream_counter);
	T_RUN_CASE(t, test_sched_wake_enqueues_only_once);
	T_RUN_CASE(t, test_sched_dequeue_preserves_fifo_order);
	T_RUN_CASE(t, test_sched_delay_remove_handles_head_middle_and_tail);
	T_RUN_CASE(t, test_sched_send_ctrl_flags_emits_ack_and_fin);
	T_RUN_CASE(
		t,
		test_sched_next_data_sends_frame_and_resets_deficit_on_drain);
	T_RUN_CASE(t, test_sched_cb_sends_syn_for_init_stream);
	T_RUN_CASE(t, test_sched_coalesce_forces_session_ack_after_tick_budget);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
