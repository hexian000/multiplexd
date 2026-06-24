/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* sched_test.c - white-box tests for the stream scheduler in sched.c (DRR/LP
 * queues, stream-id allocation, coalescing, control-frame emission).
 * Dependencies: sched.c #included; its collaborators (update_watcher,
 * session_send_ctrl, ...) are mocked below; no sibling TUs linked.
 * Benches (bench section) are opt-in: run with BENCH set in the env. */

#include "mux/frame.h"
#include "algo/hashtable.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/stream.h"

/* Unlock the testing.h bench macros (need a monotonic clock from os/clock.h). */
#include "os/clock.h"

#include <ev.h>

#define UTILS_MEASURE_H
#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mux/sched.c"

/* frame.c data global the header-inline framing helpers reference; defined here
 * since this white-box TU does not link frame.c. */
const struct mux_config mux_conf_default = {
	.max_frame_payload = 65536 - MUX_FRAME_HEADER_SIZE,
};

/* mock - collaborator spies and reset helper */

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

void update_watcher(struct mux_session *ss)
{
	(void)ss;
	g_update_watcher_calls++;
}

void session_notify(struct mux_session *restrict ss)
{
	ss->wire.tx_pending = true;
	if (ss->w_socket.fd != -1) {
		update_watcher(ss);
	}
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

void stream_notify_recv(struct mux_stream *restrict s)
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
		.max_payload =
			(uint_least32_t)mux_conf_default.max_frame_payload,
		.session_window = 8,
		.stream_window = 4,
		.tag = (char *)"[test]:",
	};
	T_CHECK(ss.loop != NULL);
	ss.sched.streams = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_PTR.hash,
		.eq = TABLE_OPTS_PTR.eq,
		.flags = TABLE_FAST,
	});
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

/* regression - targeted cases for one scheduler behavior each */

T_DECLARE_CASE(test_sched_alloc_stream_id_nearly_full)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);

	/* Server session: even IDs.  Occupy all even IDs except 65534. */
	ss.accepted = true;
	/* Fill the table with all even IDs 2..65534 except 65534 itself. */
	for (unsigned i = 2; i < 65534; i += 2) {
		void *dummy = (void *)(uintptr_t)i;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)i, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	/* Fill 65536 (wraps; parity even) as well. */
	{
		void *dummy = (void *)(uintptr_t)65536;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)0, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}

	/* Only 65534 remains free. */
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)65534);

	/* Occupy the last slot; next call must report exhaustion. */
	{
		void *dummy = (void *)(uintptr_t)65534;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)65534,
			&elem);
		T_CHECK(ss.sched.streams != NULL);
	}
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
	ss.unacked.stalled = true;

	sched_free_streams(&ss);
	T_EXPECT(ss.cnt.num_stream_failed == NULL);
	T_EXPECT_EQ(g_stream_free_calls, 2);
	T_EXPECT(ss.sched.streams == NULL);
	T_EXPECT(!ss.unacked.stalled);

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
	ss.w_socket.fd = 3; /* live socket: session_notify arms EV_WRITE */
	sched_wake(&ss, &stream);
	sched_wake(&ss, &stream);
	T_EXPECT(ss.sched.sched_head == &stream);
	T_EXPECT(ss.sched.sched_tail == &stream);
	T_EXPECT(stream.sched_queue == SCHED_QUEUE_DRR);
	T_EXPECT(ss.wire.tx_pending);
	/* Waking a ready stream must notify the loop; the exact notify cadence
	 * (once per wake vs. coalesced) is an implementation detail, so assert it
	 * happened rather than pinning the count. */
	T_EXPECT(g_update_watcher_calls >= 1);
	ss.w_socket.fd = -1;

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
	T_EXPECT(ss.unacked.ack_pending);
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

/* A sole ready stream stays the active stream and drains its whole send queue in
 * one pass, never re-queuing onto sched_head between frames; it yields only when
 * the queue empties. */
T_DECLARE_CASE(test_sched_sole_stream_drains_without_requeue)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	sched_test_reset();
	struct mux_stream stream = {
		.id = 9,
		.state = STREAM_ESTABLISHED,
	};
	struct mux_frame f1 = { .len = MUX_FRAME_HEADER_SIZE + 16 };
	struct mux_frame f2 = { .len = MUX_FRAME_HEADER_SIZE + 16 };
	struct mux_frame f3 = { .len = MUX_FRAME_HEADER_SIZE + 16 };
	mux_frame_list_push(&stream.send_queue, &f1);
	mux_frame_list_push(&stream.send_queue, &f2);
	mux_frame_list_push(&stream.send_queue, &f3);
	sched_enqueue(&ss, &stream);

	/* First two frames keep the stream active without re-queuing. */
	T_EXPECT(sched_next_data(&ss));
	T_EXPECT(ss.sched.drr_active == &stream);
	T_EXPECT(ss.sched.sched_head == NULL);
	T_EXPECT(sched_next_data(&ss));
	T_EXPECT(ss.sched.drr_active == &stream);
	T_EXPECT(ss.sched.sched_head == NULL);
	/* Third drains the queue: the stream yields. */
	T_EXPECT(sched_next_data(&ss));
	T_EXPECT(ss.sched.drr_active == NULL);
	T_EXPECT_EQ(g_send_push_calls, 3);

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
	sched_drain_lp(&ss);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_flags, (uint_fast8_t)MUX_FLAG_SYN);
	T_EXPECT_EQ(g_last_ctrl_extra, (uint_fast32_t)3);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 1);
	T_EXPECT_EQ(stream.state, (enum stream_state)STREAM_SYN_SENT);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_coalesce_forces_session_ack_after_tick_budget)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);

	sched_test_reset();
	ss.unacked.recv_seq = 5;
	ss.unacked.ack_seq = 1;
	ss.unacked.ack_ticks = MUX_SESSION_ACK_MAX_TICKS - 1;
	sched_coalesce_cb(ss.loop, &ss.sched.w_coalesce, EV_TIMER);
	T_EXPECT_EQ(g_emit_ack_calls, 1);

	cleanup_session(&ss);
}

/* Stream ID boundary tests */

T_DECLARE_CASE(test_stream_id_exhaustion)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	ss.accepted = false;
	/* Fill all odd IDs. */
	for (unsigned i = 1; i <= 65535; i += 2) {
		void *dummy = (void *)(uintptr_t)i;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)i, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_stream_id_wraparound_client)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	ss.accepted = false;
	/* Fill all odd IDs except 65535. */
	for (unsigned i = 1; i <= 65533; i += 2) {
		void *dummy = (void *)(uintptr_t)i;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)i, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	/* Start scan near wrap: next_stream_id=65533; only 65535 free. */
	ss.sched.next_stream_id = 65533;
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)65535);
	/* Now all odd IDs occupied; next allocation fails. */
	{
		void *dummy = (void *)(uintptr_t)65535;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)65535,
			&elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);
	/* Remove ID 1; next allocation wraps back to 1. */
	{
		void *elem = NULL;
		ss.sched.streams = table_del(
			ss.sched.streams, (const void *)(uintptr_t)1, &elem);
	}
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)1);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_stream_id_wraparound_server)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	ss.accepted = true;
	/* Fill all even IDs except 65534. */
	for (unsigned i = 2; i <= 65532; i += 2) {
		void *dummy = (void *)(uintptr_t)i;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)i, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	/* Start scan near wrap: next_stream_id=65532; only 65534 free. */
	ss.sched.next_stream_id = 65532;
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)65534);
	/* Now all even IDs occupied; next allocation fails. */
	{
		void *dummy = (void *)(uintptr_t)65534;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)65534,
			&elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);
	/* Remove ID 2; next allocation wraps back to 2. */
	{
		void *elem = NULL;
		ss.sched.streams = table_del(
			ss.sched.streams, (const void *)(uintptr_t)2, &elem);
	}
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)2);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_tombstone_excluded_from_max_streams)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	ss.accepted = false;
	ss.conf.max_streams = 4;
	sched_test_reset();

	for (int i = 0; i < 4; i++) {
		struct mux_stream *s = calloc(1, sizeof(*s));
		T_CHECK(s != NULL);
		s->id = (uint_least16_t)(i * 2 + 1);
		s->state = STREAM_ESTABLISHED;
		T_EXPECT(sched_add_stream(&ss, s));
	}
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)4);
	ss.sched.num_tombstones = 2;
	/* Live count = 4 - 2 = 2 < max_streams(4), so admission OK. */
	{
		struct mux_stream *s = calloc(1, sizeof(*s));
		T_CHECK(s != NULL);
		s->id = 9;
		s->state = STREAM_INIT;
		T_EXPECT(sched_add_stream(&ss, s));
	}
	sched_free_streams(&ss);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_stream_id_collision_skip)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	ss.accepted = true;
	/* Occupy ID 2; allocator must skip to 4. */
	{
		void *dummy = (void *)(uintptr_t)2;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)2, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(sched_alloc_stream_id(&ss), (uint_least16_t)4);
	cleanup_session(&ss);
}

/* Scheduler race condition tests */

T_DECLARE_CASE(test_sched_wake_double_enqueue_idempotent)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	sched_test_reset();

	struct mux_stream *s = calloc(1, sizeof(*s));
	T_CHECK(s != NULL);
	s->id = 1;
	s->state = STREAM_ESTABLISHED;
	T_EXPECT(sched_add_stream(&ss, s));
	sched_wake(&ss, s);
	T_EXPECT(s->sched_queue == SCHED_QUEUE_DRR);
	T_EXPECT(ss.sched.sched_head == s);
	T_EXPECT(ss.sched.sched_tail == s);
	sched_wake(&ss, s);
	T_EXPECT(ss.sched.sched_head == s);
	T_EXPECT(ss.sched.sched_tail == s);
	T_EXPECT(s->next == NULL);
	sched_free_streams(&ss);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_lp_queue_double_enqueue_prevented)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	sched_test_reset();

	struct mux_stream *s = calloc(1, sizeof(*s));
	T_CHECK(s != NULL);
	s->id = 1;
	s->state = STREAM_INIT;
	T_EXPECT(sched_add_stream(&ss, s));
	sched_wake(&ss, s);
	T_EXPECT(ss.sched.lp_head == s);
	T_EXPECT(ss.sched.lp_tail == s);
	sched_wake(&ss, s);
	T_EXPECT(ss.sched.lp_head == s);
	T_EXPECT(ss.sched.lp_tail == s);
	T_EXPECT(s->next == NULL);
	sched_free_streams(&ss);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_next_data_skips_blocked_stream)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);

	/* Stream A: ESTABLISHED but no frame to produce (send_queue empty). */
	struct mux_stream stream_a = {
		.id = 13,
		.state = STREAM_ESTABLISHED,
	};
	/* Stream B: ESTABLISHED with a frame ready to send. */
	struct mux_stream stream_b = {
		.id = 15,
		.state = STREAM_ESTABLISHED,
	};
	struct mux_frame frame_b = {
		.len = MUX_FRAME_HEADER_SIZE + 32,
	};

	sched_test_reset();
	mux_frame_list_push(&stream_b.send_queue, &frame_b);

	/* Enqueue A first so it sits at the head. */
	sched_enqueue(&ss, &stream_a);
	sched_enqueue(&ss, &stream_b);

	/* Should skip A (no frame) and produce B's frame. */
	T_EXPECT(sched_next_data(&ss));
	T_EXPECT_EQ(g_send_push_calls, 1);
	T_EXPECT(g_last_sent_frame == &frame_b);
	T_EXPECT_EQ(g_stream_on_send_calls, 1);

	/* Queue must be empty: both streams were visited and dequeued. */
	T_EXPECT(ss.sched.sched_head == NULL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_next_data_exhausts_queue_returns_false)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);

	/* Two ESTABLISHED streams, neither can produce a frame. */
	struct mux_stream stream_a = {
		.id = 17,
		.state = STREAM_ESTABLISHED,
	};
	struct mux_stream stream_b = {
		.id = 19,
		.state = STREAM_ESTABLISHED,
	};

	sched_test_reset();
	sched_enqueue(&ss, &stream_a);
	sched_enqueue(&ss, &stream_b);

	/* Neither has data: must exhaust the queue and return false. */
	T_EXPECT(!sched_next_data(&ss));
	T_EXPECT_EQ(g_send_push_calls, 0);

	/* Queue must be empty after exhaustive scan. */
	T_EXPECT(ss.sched.sched_head == NULL);
	T_EXPECT(ss.sched.sched_tail == NULL);

	cleanup_session(&ss);
}

/* The lifecycle-drain request is self-guarding: callers invoke it
 * unconditionally and it must no-op on an empty queue or an occupied sendbuf
 * (which the session_on_send epilogue re-arms), only marking pending and arming EV_WRITE
 * (via session_notify) when there is queued work and the sendbuf is clear. */
T_DECLARE_CASE(test_sched_schedule_self_guards_on_queue_and_sendbuf)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = { .id = 1, .state = STREAM_INIT };
	struct mux_frame staged = { 0 };

	sched_test_reset();

	/* Empty lp queue: nothing to drain, must not mark pending. */
	ss.sched.lp_pending = false;
	sched_schedule(&ss);
	T_EXPECT(!ss.sched.lp_pending);
	T_EXPECT_EQ(g_update_watcher_calls, 0);

	/* Queued work but the sendbuf is occupied: defer (no-op). */
	sched_lp_enqueue(&ss, &stream);
	ss.wire.sendbuf.head = &staged;
	sched_schedule(&ss);
	T_EXPECT(!ss.sched.lp_pending);
	T_EXPECT_EQ(g_update_watcher_calls, 0);

	/* Queued work and the sendbuf clear, but no live socket (fd == -1):
	 * mark pending without arming the watcher. */
	ss.wire.sendbuf.head = NULL;
	sched_schedule(&ss);
	T_EXPECT(ss.sched.lp_pending);
	T_EXPECT_EQ(g_update_watcher_calls, 0);

	/* With a live socket the request arms EV_WRITE via session_notify. */
	ss.sched.lp_pending = false;
	ss.w_socket.fd = 3; /* any value != -1; only tested for liveness here */
	sched_schedule(&ss);
	T_EXPECT(ss.sched.lp_pending);
	T_EXPECT(g_update_watcher_calls >= 1);

	ss.w_socket.fd = -1;
	ss.wire.sendbuf.head = NULL;
	cleanup_session(&ss);
}

/* bench - DRR ready-queue churn (opt-in: run with BENCH set in the env) */

T_DECLARE_BENCH(bench_sched_enqueue_dequeue)
{
	sched_test_reset();
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream s = { .id = 1 };
	/* Steady-state churn: one stream cycles through the ready queue. */
	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		sched_enqueue(&ss, &s);
		(void)sched_dequeue(&ss);
	}
	cleanup_session(&ss);
}

/* sched_wake before SESSION_ESTABLISHED routes through the single pre-split
 * queue rather than the DRR/LP split. */
T_DECLARE_CASE(test_sched_wake_before_established_uses_single_queue)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	ss.state = SESSION_HANDSHAKE;
	struct mux_stream stream = { .id = 5, .state = STREAM_ESTABLISHED };

	sched_wake(&ss, &stream);
	T_EXPECT(ss.sched.sched_head == &stream);
	T_EXPECT(stream.sched_queue == SCHED_QUEUE_DRR);

	ss.sched.sched_head = ss.sched.sched_tail = NULL;
	cleanup_session(&ss);
}

/* sched_delay shortens the deadline when an earlier request arrives for a
 * stream already in the delay list. */
T_DECLARE_CASE(test_sched_delay_shortens_pending_deadline)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = {
		.id = 5,
		.delay_pending = true,
		.delay_ticks = 5,
	};
	ss.sched.delay_head = &stream;

	sched_delay(&ss, &stream, 2); /* sooner than 5 */
	T_EXPECT_EQ(stream.delay_ticks, (uint_fast8_t)2);
	sched_delay(&ss, &stream, 4); /* not sooner: unchanged */
	T_EXPECT_EQ(stream.delay_ticks, (uint_fast8_t)2);

	ss.sched.delay_head = NULL;
	cleanup_session(&ss);
}

/* sched_find_stream returns NULL when the stream table has not been created. */
T_DECLARE_CASE(test_sched_find_stream_null_table)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct hashtable *const saved = ss.sched.streams;
	ss.sched.streams = NULL;
	T_EXPECT(sched_find_stream(&ss, 1) == NULL);
	ss.sched.streams = saved;
	cleanup_session(&ss);
}

/* sched_send_ctrl_flags clears ack_pending when the grantable amount is
 * sub-unit (grant_inc == 0) and no FIN is pending. */
T_DECLARE_CASE(test_sched_send_ctrl_flags_subunit_clears_ack)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	sched_test_reset();
	struct mux_stream stream = {
		.id = 5,
		.state = STREAM_ESTABLISHED,
		.ack_pending = true,
	};
	g_stream_grant_inc = 0; /* sub-unit grantable */

	sched_send_ctrl_flags(&ss, &stream);
	T_EXPECT(!stream.ack_pending);
	T_EXPECT_EQ(g_send_ctrl_calls, 0);

	cleanup_session(&ss);
}

/* sched_remove_stream of the last live stream while draining triggers a
 * graceful shutdown; removing an absent stream is a no-op. */
T_DECLARE_CASE(test_sched_remove_stream_drain_and_absent)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	sched_test_reset();

	struct mux_stream stream = { .id = 5, .state = STREAM_ESTABLISHED };
	T_CHECK(sched_add_stream(&ss, &stream));
	ss.draining = true;
	ss.state = SESSION_ESTABLISHED;
	sched_remove_stream(&ss, &stream);
	T_EXPECT_EQ(g_session_initiate_shutdown_calls, 1);

	/* Removing a stream that is no longer present is inert. */
	sched_remove_stream(&ss, &stream);
	T_EXPECT_EQ(g_session_initiate_shutdown_calls, 1);

	cleanup_session(&ss);
}

/* sched_drain_lp frees a CLOSED stream parked on the low-priority queue. */
T_DECLARE_CASE(test_sched_drain_lp_frees_closed_stream)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	sched_test_reset();

	struct mux_stream *const s = malloc(sizeof(*s));
	T_CHECK(s != NULL);
	*s = (struct mux_stream){ .id = 7, .state = STREAM_CLOSED };
	s->sched_queue = SCHED_QUEUE_LP;
	ss.sched.lp_head = s;
	ss.sched.lp_tail = s;
	ss.state = SESSION_ESTABLISHED;

	sched_drain_lp(&ss);
	T_EXPECT_EQ(g_stream_free_calls, 1);
	T_EXPECT(ss.sched.lp_head == NULL);

	cleanup_session(&ss);
}

/* sched_coalesce_cb decrements a multi-tick delay without expiring it. */
T_DECLARE_CASE(test_sched_coalesce_cb_decrements_multi_tick)
{
	struct mux_session ss = make_session();
	sched_test_bind_watchers(&ss);
	struct mux_stream stream = {
		.id = 5,
		.delay_pending = true,
		.delay_ticks = 2,
	};
	ss.sched.delay_head = &stream;

	sched_coalesce_cb(ss.loop, &ss.sched.w_coalesce, EV_TIMER);
	T_EXPECT_EQ(stream.delay_ticks, (uint_fast8_t)1);
	T_EXPECT(ss.sched.delay_head == &stream);

	ss.sched.delay_head = NULL;
	cleanup_session(&ss);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_sched_alloc_stream_id_nearly_full);
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
	T_RUN_CASE(t, test_sched_sole_stream_drains_without_requeue);
	T_RUN_CASE(t, test_sched_cb_sends_syn_for_init_stream);
	T_RUN_CASE(t, test_sched_coalesce_forces_session_ack_after_tick_budget);
	T_RUN_CASE(t, test_sched_next_data_skips_blocked_stream);
	T_RUN_CASE(t, test_sched_next_data_exhausts_queue_returns_false);
	T_RUN_CASE(t, test_sched_schedule_self_guards_on_queue_and_sendbuf);
	T_RUN_CASE(t, test_stream_id_exhaustion);
	T_RUN_CASE(t, test_stream_id_wraparound_client);
	T_RUN_CASE(t, test_stream_id_wraparound_server);
	T_RUN_CASE(t, test_tombstone_excluded_from_max_streams);
	T_RUN_CASE(t, test_stream_id_collision_skip);
	T_RUN_CASE(t, test_sched_wake_double_enqueue_idempotent);
	T_RUN_CASE(t, test_lp_queue_double_enqueue_prevented);
	T_RUN_CASE(t, test_sched_wake_before_established_uses_single_queue);
	T_RUN_CASE(t, test_sched_delay_shortens_pending_deadline);
	T_RUN_CASE(t, test_sched_find_stream_null_table);
	T_RUN_CASE(t, test_sched_send_ctrl_flags_subunit_clears_ack);
	T_RUN_CASE(t, test_sched_remove_stream_drain_and_absent);
	T_RUN_CASE(t, test_sched_drain_lp_frees_closed_stream);
	T_RUN_CASE(t, test_sched_coalesce_cb_decrements_multi_tick);
	/* Opt-in micro-benchmark: ~1s, kept out of the default ctest run. */
	if (getenv("BENCH") != NULL) {
		T_RUN_BENCH(t, bench_sched_enqueue_dequeue);
	}
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
