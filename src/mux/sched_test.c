/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* sched_test.c - white-box tests for sched.c (DRR/LP queues, stream-id
 * allocation, coalescing, control-frame emission); sched.c #included, its
 * collaborators mocked; benches opt-in via TESTING_BENCH env. */

#include "frame.h"
#include "mux.h"
#include "sched.c"
#include "session.h"
#include "stream.h"

#include "algo/hashtable.h"
#include "meta/arraysize.h"
#include "utils/testing.h"

#include <ev.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* frame.c data global the header-inline framing helpers reference; defined here
 * since this white-box TU does not link frame.c. Keep max_frame_payload in step
 * with the real definition in frame.c (16384 - MUX_FRAME_HEADER_SIZE): it feeds
 * make_session's ss.max_payload, the DRR quantum, so the fairness tests must run
 * against the same quantum the daemon uses. */
const struct mux_session_config mux_session_config_default = {
	.max_frame_payload = 16384 - MUX_FRAME_HEADER_SIZE,
	.readahead = 128 * 1024,
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
static uint_least16_t g_last_push_stream_id;
/* When set, mux_stream_dequeue_send() returns NULL for this stream without
 * popping its queue: simulates a credit-exhausted or Nagle-held stream. */
static struct mux_stream *g_block_stream;
static int g_notify_recv_calls;
static int g_flush_calls;
static int g_mark_syn_sent_calls;
static int g_stream_free_calls;
static int g_stream_orphan_calls;
static int g_emit_ack_calls;
static int g_stream_check_ack_calls;
static int g_session_initiate_shutdown_calls;
/* When set, mux_session_send_ctrl() fails as on frame-pool OOM. */
static bool g_send_ctrl_fail;
static int g_abort_unopened_calls;
/* Stream ids in the order mux_stream_mark_syn_sent() saw them. */
static uint_least16_t g_syn_ids[4];

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
	g_last_push_stream_id = 0;
	g_block_stream = NULL;
	g_notify_recv_calls = 0;
	g_flush_calls = 0;
	g_mark_syn_sent_calls = 0;
	g_stream_free_calls = 0;
	g_stream_orphan_calls = 0;
	g_emit_ack_calls = 0;
	g_stream_check_ack_calls = 0;
	g_session_initiate_shutdown_calls = 0;
	g_send_ctrl_fail = false;
	g_abort_unopened_calls = 0;
	memset(g_syn_ids, 0, sizeof(g_syn_ids));
}

static void
sched_timer_noop_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

int mux_stream_format_tag(
	char *restrict buf, const size_t buflen,
	const struct mux_stream *restrict s)
{
	(void)s;
	return snprintf(buf, buflen, "[stream]:");
}

static void update_watcher(struct mux_session *ss)
{
	(void)ss;
	g_update_watcher_calls++;
}

void mux_session_notify(struct mux_session *restrict ss)
{
	ss->wire.tx_pending = true;
	if (ss->w_socket.fd != -1) {
		update_watcher(ss);
	}
}

/* Models mux_wire_sendbuf_push()'s effect on an occupied sendbuf without
 * materialising the frame: it packs onto the open staging tail or is appended
 * by reference as the new one, so the tail is open for packing either way. */
static void sched_test_model_sendbuf_push(struct mux_session *restrict ss)
{
	if (ss->wire.sendbuf.head != NULL) {
		ss->wire.sendbuf_staging = true;
	}
}

bool mux_session_send_ctrl(
	struct mux_session *restrict ss, const uint_fast16_t stream_id,
	const uint_fast8_t flags, const uint_fast32_t extra)
{
	g_send_ctrl_calls++;
	g_last_ctrl_stream_id = stream_id;
	g_last_ctrl_flags = flags;
	g_last_ctrl_extra = extra;
	if (g_send_ctrl_fail) {
		return false;
	}
	sched_test_model_sendbuf_push(ss);
	return true;
}

uint_fast32_t mux_stream_grant_inc(const struct mux_stream *restrict s)
{
	(void)s;
	return g_stream_grant_inc;
}

void mux_stream_mark_fin_sent(struct mux_stream *s)
{
	(void)s;
	g_mark_fin_sent_calls++;
}

void mux_session_send_push(
	struct mux_session *ss, struct mux_stream *s,
	struct mux_frame *restrict frame)
{
	sched_test_model_sendbuf_push(ss);
	g_send_push_calls++;
	g_last_sent_frame = frame;
	g_last_push_stream_id = s->id;
}

struct mux_frame *mux_stream_dequeue_send(struct mux_stream *restrict s)
{
	if (s == g_block_stream) {
		/* Blocked (credit exhausted / Nagle-held): queue is left
		 * untouched, unlike the queue-empty case. */
		return NULL;
	}
	return mux_frame_list_pop(&s->send_queue);
}

void mux_stream_notify_recv(struct mux_stream *restrict s)
{
	(void)s;
	g_notify_recv_calls++;
}

void mux_session_flush(struct mux_session *ss)
{
	(void)ss;
	g_flush_calls++;
}

void mux_stream_mark_syn_sent(struct mux_stream *s)
{
	const size_t n = (size_t)g_mark_syn_sent_calls;
	if (n < ARRAY_SIZE(g_syn_ids)) {
		g_syn_ids[n] = s->id;
	}
	g_mark_syn_sent_calls++;
	s->state = STREAM_SYN_SENT;
}

void mux_stream_free(struct mux_stream *s)
{
	g_stream_free_calls++;
	free(s);
}

void mux_stream_orphan(struct mux_stream *s)
{
	g_stream_orphan_calls++;
	s->state = STREAM_CLOSED;
	s->orphaned = true;
}

void mux_stream_abort_unopened(struct mux_stream *s)
{
	g_abort_unopened_calls++;
	s->state = STREAM_CLOSED;
	s->session->sched.num_closed++;
}

void mux_session_emit_ack(struct mux_session *restrict ss)
{
	(void)ss;
	g_emit_ack_calls++;
}

void mux_stream_check_ack(struct mux_stream *restrict s)
{
	(void)s;
	g_stream_check_ack_calls++;
}

void mux_session_initiate_shutdown(struct mux_session *ss)
{
	(void)ss;
	g_session_initiate_shutdown_calls++;
}

/* Initialise in place: mux_session embeds self-pointers (timer .data), so a
 * by-value return would leave them dangling at the caller's copy. */
static void make_session(struct mux_session *restrict ss)
{
	*ss = (struct mux_session){
		.loop = ev_loop_new(EVFLAG_AUTO),
		.state = SESSION_ESTABLISHED,
		.max_payload = (uint_least32_t)mux_session_config_default
				       .max_frame_payload,
		.session_window = 8,
		.stream_window = 4,
		.tag = "[test]:",
	};
	T_CHECK(ss->loop != NULL);
	ss->sched.streams = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_PTR.hash,
		.eq = TABLE_OPTS_PTR.eq,
		.flags = TABLE_FAST,
	});
	T_CHECK(ss->sched.streams != NULL);
	ss->w_socket.fd = -1;
	ev_timer_init(&ss->w_idle_timeout, sched_timer_noop_cb, 0.0, 1.0);
	ss->w_idle_timeout.data = ss;
	mux_sched_init(ss);
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

/* Adds the last-sent frame's payload to whichever accumulator (a, b, c)
 * matches g_last_push_stream_id, and returns the amount added. */
static size_t sched_test_tally_push(
	size_t *restrict a, const uint_least16_t id_a, size_t *restrict b,
	const uint_least16_t id_b, size_t *restrict c,
	const uint_least16_t id_c)
{
	const size_t n = g_last_sent_frame->len - MUX_FRAME_HEADER_SIZE;
	if (g_last_push_stream_id == id_a) {
		*a += n;
	} else if (g_last_push_stream_id == id_b) {
		*b += n;
	} else {
		T_CHECK(g_last_push_stream_id == id_c);
		*c += n;
	}
	return n;
}

/* Pushes @p n heap-allocated frames of @p payload bytes onto @p queue,
 * appending each pointer to @p out starting at *out_count. */
static void sched_test_push_frames(
	struct mux_frame_list *restrict queue, struct mux_frame **restrict out,
	size_t *restrict out_count, const size_t n, const size_t payload)
{
	for (size_t i = 0; i < n; i++) {
		struct mux_frame *const frame = malloc(sizeof(*frame));
		T_CHECK(frame != NULL);
		*frame = (struct mux_frame){
			.len = MUX_FRAME_HEADER_SIZE + payload,
		};
		mux_frame_list_push(queue, frame);
		out[(*out_count)++] = frame;
	}
}

/* regression - targeted cases for one scheduler behavior each */

T_DECLARE_CASE(test_sched_alloc_stream_id_nearly_full)
{
	struct mux_session ss;
	make_session(&ss);

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
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)65534);

	/* Occupy the last slot; next call must report exhaustion. */
	{
		void *dummy = (void *)(uintptr_t)65534;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)65534,
			&elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(
		mux_sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_alloc_stream_id_starts_at_minimum)
{
	struct mux_session ss;
	make_session(&ss);

	/* Client (odd IDs): first allocation returns ID 1. */
	ss.accepted = false;
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)1);

	/* Server (even IDs): first allocation skips STREAMID_CTRL and returns ID 2. */
	ss.accepted = true;
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)2);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_add_remove_updates_table_and_idle_timeout)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream = { .id = 3 };

	sched_test_reset();
	ss.conf.idle_timeout = 1;
	T_EXPECT(mux_sched_add_stream(&ss, &stream));
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)1);
	T_EXPECT(!ev_is_active(&ss.w_idle_timeout));

	sched_remove_stream(&ss, &stream);
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)0);
	T_EXPECT(ev_is_active(&ss.w_idle_timeout));

	cleanup_session(&ss);
}

/* A second, distinct stream at an ID already in the table must be rejected by
 * mux_sched_add_stream's self-check (the old `elem == s` check let a genuine
 * collision through, returning true and silently overwriting the mapping). */
T_DECLARE_CASE(test_sched_add_stream_rejects_duplicate_id)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream first = { .id = 7 };
	struct mux_stream second = { .id = 7 };

	sched_test_reset();
	T_EXPECT(mux_sched_add_stream(&ss, &first));
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)1);

	/* Same ID, different object: rejected, no new entry, and the table still
	 * maps the ID to the ORIGINAL stream -- a replace-then-free would have left
	 * it holding a dangling pointer to the caller-freed duplicate. */
	T_EXPECT(!mux_sched_add_stream(&ss, &second));
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)1);
	T_EXPECT(mux_sched_find_stream(&ss, 7) == &first);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_free_streams_clears_stream_counter)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream *const first = calloc(1, sizeof(*first));
	struct mux_stream *const second = calloc(1, sizeof(*second));

	T_CHECK(first != NULL);
	T_CHECK(second != NULL);
	first->id = 3;
	second->id = 5;
	sched_test_reset();
	T_EXPECT(mux_sched_add_stream(&ss, first));
	T_EXPECT(mux_sched_add_stream(&ss, second));
	ss.unacked.stalled = true;
	first->state = STREAM_CLOSED;
	ss.sched.num_closed = 1;

	mux_sched_free_streams(&ss);
	T_EXPECT(ss.cnt.stream.num_stream_failed == NULL);
	T_EXPECT_EQ(g_stream_free_calls, 2);
	T_EXPECT(ss.sched.streams == NULL);
	T_EXPECT_EQ(ss.sched.num_closed, (size_t)0);
	/* The send-stall gate is not the scheduler's to clear: it belongs to the
	 * reliability module and falls with the unacked bytes in
	 * mux_unacked_free_all(), which every teardown caller pairs with this. Assert
	 * the gate is left alone rather than merely saying so, since this suite
	 * compiles the real sched.c and would otherwise not notice the
	 * cross-module poke coming back. */
	T_EXPECT(ss.unacked.stalled);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_wake_enqueues_only_once)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream = {
		.id = 5,
		.state = STREAM_ESTABLISHED,
	};

	sched_test_reset();
	ss.w_socket.fd = 3; /* live socket: mux_session_notify arms EV_WRITE */
	mux_sched_wake(&ss, &stream);
	mux_sched_wake(&ss, &stream);
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
	struct mux_session ss;
	make_session(&ss);
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
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream first = { .id = 1, .delay_pending = true };
	struct mux_stream second = { .id = 3, .delay_pending = true };
	struct mux_stream third = { .id = 5, .delay_pending = true };

	ss.sched.delay_head = &first;
	first.delay_next = &second;
	second.delay_prev = &first;
	second.delay_next = &third;
	third.delay_prev = &second;

	mux_sched_delay_remove(&ss, &second);
	T_EXPECT(first.delay_next == &third);
	T_EXPECT(third.delay_prev == &first);
	T_EXPECT(!second.delay_pending);

	mux_sched_delay_remove(&ss, &first);
	T_EXPECT(ss.sched.delay_head == &third);
	T_EXPECT(third.delay_prev == NULL);

	mux_sched_delay_remove(&ss, &third);
	T_EXPECT(ss.sched.delay_head == NULL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_send_ctrl_flags_emits_ack_and_fin)
{
	struct mux_session ss;
	make_session(&ss);
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
	T_EXPECT_EQ(g_mark_fin_sent_calls, 1);

	cleanup_session(&ss);
}

/* drr_active is off-FIFO while spending its round budget (file
 * header note), so mux_sched_flush_ctrl must flush its pending ACK/FIN
 * explicitly -- sched_head's walk alone would skip it, which matters most
 * during a session stall (send_stage_next) when this is the only remaining
 * path for per-stream ACK/FIN to flow. Also covers a sched_head member in the
 * same call, since mux_sched_flush_ctrl previously had no test of its own. */
T_DECLARE_CASE(test_sched_flush_ctrl_includes_drr_active)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream active = {
		.id = 7,
		.state = STREAM_ESTABLISHED,
		.ack_pending = true,
		.rx_eof = true,
		.recv_window = 4 * MUX_WINDOW_UNIT,
	};
	struct mux_stream queued = {
		.id = 9,
		.state = STREAM_ESTABLISHED,
		.ack_pending = true,
		.rx_eof = true,
		.recv_window = 4 * MUX_WINDOW_UNIT,
	};
	ss.sched.drr_active = &active;
	ss.sched.sched_head = &queued;
	queued.next = NULL;

	sched_test_reset();
	g_stream_grant_inc = 2;
	mux_sched_flush_ctrl(&ss);
	T_EXPECT_EQ(g_send_ctrl_calls, 2);
	T_EXPECT(!active.ack_pending);
	T_EXPECT(!queued.ack_pending);

	cleanup_session(&ss);
}

/* mux_sched_flush_ctrl must skip CLOSED streams at both check points: the CLOSED
 * drr_active guard and the `state != STREAM_CLOSED` skip in the sched_head
 * walk. A CLOSED stream (tombstone) carrying stale ack_pending must not emit a
 * control frame. */
T_DECLARE_CASE(test_sched_flush_ctrl_skips_closed_streams)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream closed_active = {
		.id = 7,
		.state = STREAM_CLOSED,
		.ack_pending = true,
		.rx_eof = true,
		.recv_window = 4 * MUX_WINDOW_UNIT,
	};
	struct mux_stream live = {
		.id = 9,
		.state = STREAM_ESTABLISHED,
		.ack_pending = true,
		.rx_eof = true,
		.recv_window = 4 * MUX_WINDOW_UNIT,
	};
	struct mux_stream closed_queued = {
		.id = 11,
		.state = STREAM_CLOSED,
		.ack_pending = true,
		.rx_eof = true,
		.recv_window = 4 * MUX_WINDOW_UNIT,
	};
	ss.sched.drr_active = &closed_active;
	ss.sched.sched_head = &live;
	live.next = &closed_queued;
	closed_queued.next = NULL;

	sched_test_reset();
	g_stream_grant_inc = 2;
	mux_sched_flush_ctrl(&ss);
	/* Only the live stream emits; both CLOSED streams are skipped. */
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_stream_id, (uint_fast16_t)9);

	cleanup_session(&ss);
}

/* CLOSED entries remain inactive independently of tombstone timer ownership. */
T_DECLARE_CASE(test_sched_check_no_active_streams_subtracts_closed_entries)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream = { .id = 3, .state = STREAM_ESTABLISHED };

	sched_test_reset();
	ss.draining = true;
	T_EXPECT(mux_sched_add_stream(&ss, &stream));
	mux_sched_check_no_active_streams(&ss);
	T_EXPECT_EQ(g_session_initiate_shutdown_calls, 0);

	stream.state = STREAM_CLOSED;
	ss.sched.num_closed = 1;
	/* No timer is active: an application-held CLOSED entry still cannot
	 * block drain, and its removal balances the table count. */
	mux_sched_check_no_active_streams(&ss);
	T_EXPECT_EQ(g_session_initiate_shutdown_calls, 1);
	ss.draining = false;
	ss.conf.idle_timeout = 1;
	mux_sched_check_no_active_streams(&ss);
	T_EXPECT(ev_is_active(&ss.w_idle_timeout));
	sched_remove_stream(&ss, &stream);
	T_EXPECT_EQ(ss.sched.num_closed, (size_t)0);

	cleanup_session(&ss);
}

/* mux_sched_next_data pulls a CLOSED stream off the DRR ready queue and, while the
 * tombstone timer does not own it, reroutes it to the lp cleanup queue instead
 * of trying to send its data. */
T_DECLARE_CASE(test_sched_next_data_reroutes_closed_stream_to_lp)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream closed = { .id = 3, .state = STREAM_CLOSED };

	sched_test_reset();
	sched_enqueue(&ss, &closed);

	/* w_tombstone is inactive (zeroed): the CLOSED stream leaves the DRR
	 * queue, lands in the lp cleanup queue, and no data is staged. */
	T_EXPECT(!mux_sched_next_data(&ss));
	T_EXPECT(ss.sched.sched_head == NULL);
	T_EXPECT(ss.sched.lp_head == &closed);
	T_EXPECT(ss.sched.drr_active == NULL);
	T_EXPECT_EQ(g_send_push_calls, 0);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_next_data_sends_frame_and_resets_deficit_on_drain)
{
	struct mux_session ss;
	make_session(&ss);
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
	T_EXPECT(mux_sched_next_data(&ss));
	T_EXPECT_EQ(g_send_push_calls, 1);
	T_EXPECT(g_last_sent_frame == &frame);
	T_EXPECT_EQ(g_notify_recv_calls, 1);
	T_EXPECT_EQ(stream.deficit, (uint_least32_t)0);
	T_EXPECT(ss.sched.drr_active == NULL);

	cleanup_session(&ss);
}

/* A sole ready stream stays the active stream and drains its whole send queue in
 * one pass, never re-queuing onto sched_head between frames; it yields only when
 * the queue empties. */
T_DECLARE_CASE(test_sched_sole_stream_drains_without_requeue)
{
	struct mux_session ss;
	make_session(&ss);
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
	T_EXPECT(mux_sched_next_data(&ss));
	T_EXPECT(ss.sched.drr_active == &stream);
	T_EXPECT(ss.sched.sched_head == NULL);
	T_EXPECT(mux_sched_next_data(&ss));
	T_EXPECT(ss.sched.drr_active == &stream);
	T_EXPECT(ss.sched.sched_head == NULL);
	/* Third drains the queue: the stream yields. */
	T_EXPECT(mux_sched_next_data(&ss));
	T_EXPECT(ss.sched.drr_active == NULL);
	T_EXPECT_EQ(g_send_push_calls, 3);

	cleanup_session(&ss);
}

/* Drive one mux_sched_next_data pass over an ESTABLISHED stream with an ACK and
 * a FIN pending while mux_session_send_ctrl fails as on frame-pool OOM. */
static void sched_test_ctrl_oom_pass(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	*s = (struct mux_stream){
		.id = 7,
		.state = STREAM_ESTABLISHED,
		.ack_pending = true,
		.rx_eof = true,
		.recv_window = 4 * MUX_WINDOW_UNIT,
	};
	sched_test_reset();
	g_stream_grant_inc = 2;
	g_send_ctrl_fail = true;
	sched_enqueue(ss, s);
	T_CHECK(!mux_sched_next_data(ss));
	g_send_ctrl_fail = false;
}

/* A failed ACK|FIN send (frame-pool OOM) must re-arm the stream: it is already
 * dequeued and mux_stream_check_ack bails while ack_pending is set, so without
 * a retry a receive-only stream never grants credit again and its FIN never
 * leaves. */
T_DECLARE_CASE(test_sched_send_ctrl_flags_oom_rearms_stream)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream;
	sched_test_ctrl_oom_pass(&ss, &stream);

	const bool rearmed = stream.delay_pending &&
			     ss.sched.delay_head == &stream &&
			     stream.delay_ticks == 1;
	const bool coalesce_armed = ev_is_active(&ss.sched.w_coalesce);

	mux_sched_delay_remove(&ss, &stream);
	ev_timer_stop(ss.loop, &ss.sched.w_coalesce);
	cleanup_session(&ss);

	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT(rearmed);
	T_EXPECT(coalesce_armed);
	T_EXPECT(stream.ack_pending);
	T_EXPECT_EQ(g_mark_fin_sent_calls, 0);
}

/* Once the pool recovers, the coalescing tick re-wakes the stream and the
 * retried ACK|FIN goes out. */
T_DECLARE_CASE(test_sched_send_ctrl_flags_oom_retries_next_tick)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream;
	sched_test_ctrl_oom_pass(&ss, &stream);

	sched_coalesce_cb(ss.loop, &ss.sched.w_coalesce, EV_TIMER);
	const bool rewoken = ss.sched.sched_head == &stream;
	(void)mux_sched_next_data(&ss);

	ev_timer_stop(ss.loop, &ss.sched.w_coalesce);
	cleanup_session(&ss);

	T_EXPECT(rewoken);
	T_EXPECT_EQ(g_send_ctrl_calls, 2);
	T_EXPECT_EQ(
		g_last_ctrl_flags, (uint_fast8_t)(MUX_FLAG_ACK | MUX_FLAG_FIN));
	T_EXPECT(!stream.ack_pending);
	T_EXPECT_EQ(g_mark_fin_sent_calls, 1);
}

/* A SYN the frame pool cannot allocate aborts the stream as a failed open
 * (no RST: nothing reached the peer) rather than closing it gracefully. */
T_DECLARE_CASE(test_sched_drain_lp_syn_oom_aborts_unopened)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream = {
		.id = 11,
		.state = STREAM_INIT,
		.session = &ss,
	};

	sched_test_reset();
	g_stream_grant_inc = 3;
	g_send_ctrl_fail = true;
	sched_lp_enqueue(&ss, &stream);
	mux_sched_drain_lp(&ss);

	cleanup_session(&ss);

	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_flags, (uint_fast8_t)MUX_FLAG_SYN);
	T_EXPECT_EQ(g_abort_unopened_calls, 1);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 0);
	T_EXPECT_EQ(stream.state, (enum stream_state)STREAM_CLOSED);
}

T_DECLARE_CASE(test_sched_drain_lp_sends_syn_for_init_stream)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream = {
		.id = 11,
		.state = STREAM_INIT,
	};

	sched_test_reset();
	g_stream_grant_inc = 3;
	sched_lp_enqueue(&ss, &stream);
	mux_sched_drain_lp(&ss);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_flags, (uint_fast8_t)MUX_FLAG_SYN);
	T_EXPECT_EQ(g_last_ctrl_extra, (uint_fast32_t)3);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 1);
	T_EXPECT_EQ(stream.state, (enum stream_state)STREAM_SYN_SENT);

	cleanup_session(&ss);
}

/* A partially written frame at the sendbuf head defers the INIT SYN batch
 * without popping: the first-opened stream stays at lp_head across repeated
 * passes, and once the head drains the SYNs leave in open order. */
T_DECLARE_CASE(test_sched_drain_lp_defers_syn_behind_partial_write_in_order)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream s1 = { .id = 1, .state = STREAM_INIT };
	struct mux_stream s3 = { .id = 3, .state = STREAM_INIT };
	struct mux_frame inflight = {
		.pos = 5,
		.len = MUX_FRAME_HEADER_SIZE + 16,
	};

	sched_test_reset();
	sched_lp_enqueue(&ss, &s1);
	sched_lp_enqueue(&ss, &s3);
	/* A partial write freezes the head (flush_sendbuf_head closes staging). */
	mux_frame_list_push(&ss.wire.sendbuf, &inflight);
	ss.wire.sendbuf_staging = false;

	for (int pass = 0; pass < 2; pass++) {
		mux_sched_drain_lp(&ss);
		T_EXPECT(ss.sched.lp_head == &s1);
		T_EXPECT(s1.next == &s3);
		T_EXPECT(ss.sched.lp_tail == &s3);
		T_EXPECT(s1.sched_queue == SCHED_QUEUE_LP);
	}
	T_EXPECT_EQ(g_send_ctrl_calls, 0);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 0);

	/* The head is fully written and popped; the re-armed drain proceeds. */
	(void)mux_frame_list_pop(&ss.wire.sendbuf);
	mux_sched_drain_lp(&ss);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 2);
	T_EXPECT_EQ(g_syn_ids[0], (uint_least16_t)1);
	T_EXPECT_EQ(g_syn_ids[1], (uint_least16_t)3);
	T_EXPECT(ss.sched.lp_head == NULL);
	T_EXPECT(ss.sched.lp_tail == NULL);

	cleanup_session(&ss);
}

/* A frozen head that has not started writing (pos == 0, a blocked flush) does
 * not defer the batch, and a SYN|PUSH appended by reference behind it opens a
 * new staging tail, so the following SYN still joins the same batch. */
T_DECLARE_CASE(test_sched_drain_lp_batches_syn_after_by_reference_push)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream s1 = { .id = 1, .state = STREAM_INIT };
	struct mux_stream s3 = { .id = 3, .state = STREAM_INIT };
	struct mux_frame blocked = { .len = MUX_FRAME_HEADER_SIZE + 16 };
	struct mux_frame fastopen = { .len = MUX_FRAME_HEADER_SIZE + 32 };

	sched_test_reset();
	mux_frame_list_push(&s1.send_queue, &fastopen);
	sched_lp_enqueue(&ss, &s1);
	sched_lp_enqueue(&ss, &s3);
	mux_frame_list_push(&ss.wire.sendbuf, &blocked);
	ss.wire.sendbuf_staging = false;

	mux_sched_drain_lp(&ss);
	T_EXPECT_EQ(g_send_push_calls, 1);
	T_EXPECT(g_last_sent_frame == &fastopen);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_flags, (uint_fast8_t)MUX_FLAG_SYN);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 2);
	T_EXPECT_EQ(g_syn_ids[0], (uint_least16_t)1);
	T_EXPECT_EQ(g_syn_ids[1], (uint_least16_t)3);
	T_EXPECT(ss.sched.lp_head == NULL);

	ss.wire.sendbuf = (struct mux_frame_list){ 0 };
	cleanup_session(&ss);
}

/* A SYN that fails (frame-pool OOM) while the sendbuf tail is frozen leaves no
 * staging tail to pack into, so the batch stops there: the next INIT stream
 * stays queued for the drain the sendbuf's drain re-arms, rather than taking
 * its own SYN attempt into the same shortage. */
T_DECLARE_CASE(test_sched_drain_lp_failed_syn_behind_frozen_tail_stops_batch)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream s1 = { .id = 1,
				 .state = STREAM_INIT,
				 .session = &ss };
	struct mux_stream s3 = { .id = 3,
				 .state = STREAM_INIT,
				 .session = &ss };
	struct mux_frame blocked = { .len = MUX_FRAME_HEADER_SIZE + 16 };

	sched_test_reset();
	g_send_ctrl_fail = true;
	sched_lp_enqueue(&ss, &s1);
	sched_lp_enqueue(&ss, &s3);
	mux_frame_list_push(&ss.wire.sendbuf, &blocked);
	ss.wire.sendbuf_staging = false;

	mux_sched_drain_lp(&ss);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_stream_id, (uint_fast16_t)1);
	T_EXPECT_EQ(g_mark_syn_sent_calls, 0);
	T_EXPECT(ss.sched.lp_head == &s3);
	T_EXPECT(ss.sched.lp_tail == &s3);
	T_EXPECT_EQ(s3.state, (enum stream_state)STREAM_INIT);

	ss.wire.sendbuf = (struct mux_frame_list){ 0 };
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_coalesce_forces_session_ack_after_tick_budget)
{
	struct mux_session ss;
	make_session(&ss);

	sched_test_reset();
	ss.unacked.unreported = 4;
	ss.unacked.ack_ticks = MUX_SESSION_ACK_MAX_TICKS - 1;
	sched_coalesce_cb(ss.loop, &ss.sched.w_coalesce, EV_TIMER);
	T_EXPECT_EQ(g_emit_ack_calls, 1);

	cleanup_session(&ss);
}

/* Stream ID boundary tests */

T_DECLARE_CASE(test_stream_id_exhaustion)
{
	struct mux_session ss;
	make_session(&ss);
	ss.accepted = false;
	/* Fill all odd IDs. */
	for (unsigned i = 1; i <= 65535; i += 2) {
		void *dummy = (void *)(uintptr_t)i;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)i, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(
		mux_sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_stream_id_wraparound_client)
{
	struct mux_session ss;
	make_session(&ss);
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
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)65535);
	/* Now all odd IDs occupied; next allocation fails. */
	{
		void *dummy = (void *)(uintptr_t)65535;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)65535,
			&elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(
		mux_sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);
	/* Remove ID 1; next allocation wraps back to 1. */
	{
		void *elem = NULL;
		ss.sched.streams = table_del(
			ss.sched.streams, (const void *)(uintptr_t)1, &elem);
	}
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)1);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_stream_id_wraparound_server)
{
	struct mux_session ss;
	make_session(&ss);
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
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)65534);
	/* Now all even IDs occupied; next allocation fails. */
	{
		void *dummy = (void *)(uintptr_t)65534;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)65534,
			&elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(
		mux_sched_alloc_stream_id(&ss), (uint_least16_t)STREAMID_CTRL);
	/* Remove ID 2; next allocation wraps back to 2. */
	{
		void *elem = NULL;
		ss.sched.streams = table_del(
			ss.sched.streams, (const void *)(uintptr_t)2, &elem);
	}
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)2);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_tombstone_excluded_from_max_streams)
{
	struct mux_session ss;
	make_session(&ss);
	ss.accepted = false;
	ss.conf.max_streams = 4;
	sched_test_reset();

	for (int i = 0; i < 4; i++) {
		struct mux_stream *const s = calloc(1, sizeof(*s));
		T_CHECK(s != NULL);
		s->id = (uint_least16_t)(i * 2 + 1);
		s->state = STREAM_ESTABLISHED;
		T_EXPECT(mux_sched_add_stream(&ss, s));
	}
	T_EXPECT_EQ(table_size(ss.sched.streams), (size_t)4);
	ss.sched.num_tombstones = 2;
	ss.sched.num_closed = 2;
	/* Live count = 4 - 2 = 2 < max_streams(4), so admission OK. */
	{
		struct mux_stream *const s = calloc(1, sizeof(*s));
		T_CHECK(s != NULL);
		s->id = 9;
		s->state = STREAM_INIT;
		T_EXPECT(mux_sched_add_stream(&ss, s));
	}
	mux_sched_free_streams(&ss);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_stream_id_collision_skip)
{
	struct mux_session ss;
	make_session(&ss);
	ss.accepted = true;
	/* Occupy ID 2; allocator must skip to 4. */
	{
		void *dummy = (void *)(uintptr_t)2;
		void *elem = dummy;
		ss.sched.streams = table_set(
			ss.sched.streams, (const void *)(uintptr_t)2, &elem);
		T_CHECK(ss.sched.streams != NULL);
	}
	T_EXPECT_EQ(mux_sched_alloc_stream_id(&ss), (uint_least16_t)4);
	cleanup_session(&ss);
}

/* Scheduler race condition tests */

T_DECLARE_CASE(test_sched_wake_double_enqueue_idempotent)
{
	struct mux_session ss;
	make_session(&ss);
	sched_test_reset();

	struct mux_stream *const s = calloc(1, sizeof(*s));
	T_CHECK(s != NULL);
	s->id = 1;
	s->state = STREAM_ESTABLISHED;
	T_EXPECT(mux_sched_add_stream(&ss, s));
	mux_sched_wake(&ss, s);
	T_EXPECT(s->sched_queue == SCHED_QUEUE_DRR);
	T_EXPECT(ss.sched.sched_head == s);
	T_EXPECT(ss.sched.sched_tail == s);
	mux_sched_wake(&ss, s);
	T_EXPECT(ss.sched.sched_head == s);
	T_EXPECT(ss.sched.sched_tail == s);
	T_EXPECT(s->next == NULL);
	mux_sched_free_streams(&ss);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_lp_queue_double_enqueue_prevented)
{
	struct mux_session ss;
	make_session(&ss);
	sched_test_reset();

	struct mux_stream *const s = calloc(1, sizeof(*s));
	T_CHECK(s != NULL);
	s->id = 1;
	s->state = STREAM_INIT;
	T_EXPECT(mux_sched_add_stream(&ss, s));
	mux_sched_wake(&ss, s);
	T_EXPECT(ss.sched.lp_head == s);
	T_EXPECT(ss.sched.lp_tail == s);
	mux_sched_wake(&ss, s);
	T_EXPECT(ss.sched.lp_head == s);
	T_EXPECT(ss.sched.lp_tail == s);
	T_EXPECT(s->next == NULL);
	mux_sched_free_streams(&ss);
	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_next_data_skips_empty_queue_stream)
{
	struct mux_session ss;
	make_session(&ss);

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
	T_EXPECT(mux_sched_next_data(&ss));
	T_EXPECT_EQ(g_send_push_calls, 1);
	T_EXPECT(g_last_sent_frame == &frame_b);
	T_EXPECT_EQ(g_notify_recv_calls, 1);

	/* Queue must be empty: both streams were visited and dequeued. */
	T_EXPECT(ss.sched.sched_head == NULL);

	cleanup_session(&ss);
}

T_DECLARE_CASE(test_sched_next_data_exhausts_queue_returns_false)
{
	struct mux_session ss;
	make_session(&ss);

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
	T_EXPECT(!mux_sched_next_data(&ss));
	T_EXPECT_EQ(g_send_push_calls, 0);

	/* Queue must be empty after exhaustive scan. */
	T_EXPECT(ss.sched.sched_head == NULL);
	T_EXPECT(ss.sched.sched_tail == NULL);

	cleanup_session(&ss);
}

/* A stream that stalls mid-round without draining its queue must not bank
 * leftover deficit: once re-admitted, its next turn must fit the same
 * one-quantum-per-round budget as its still-backlogged peers. */
T_DECLARE_CASE(test_sched_next_data_blocked_stream_does_not_bank_deficit)
{
	struct mux_session ss;
	make_session(&ss);
	sched_test_reset();
	/* Small quantum so a handful of small frames cross round boundaries. */
	ss.max_payload = 30;

	struct mux_stream stream_a = { .id = 21, .state = STREAM_ESTABLISHED };
	struct mux_stream stream_b = { .id = 23, .state = STREAM_ESTABLISHED };
	struct mux_stream stream_c = { .id = 25, .state = STREAM_ESTABLISHED };

	/* A: a tiny opener frame, then a 40-byte backlog -- bigger than one
	 * quantum. B and C: 90 bytes each, so both stay ready throughout. */
	struct mux_frame *all_frames[6 + 9 + 9];
	size_t nframes = 0;
	sched_test_push_frames(
		&stream_a.send_queue, all_frames, &nframes, 1, 2);
	sched_test_push_frames(
		&stream_a.send_queue, all_frames, &nframes, 5, 8);
	sched_test_push_frames(
		&stream_b.send_queue, all_frames, &nframes, 9, 10);
	sched_test_push_frames(
		&stream_c.send_queue, all_frames, &nframes, 9, 10);

	sched_enqueue(&ss, &stream_a);
	sched_enqueue(&ss, &stream_b);
	sched_enqueue(&ss, &stream_c);

	size_t bytes_a = 0, bytes_b = 0, bytes_c = 0;

	/* A takes its first (small) turn and stays drr_active with leftover
	 * deficit, exactly like a stream that "gets a little credit, sends a
	 * little" before stalling. */
	T_EXPECT(mux_sched_next_data(&ss));
	T_EXPECT_EQ(g_last_push_stream_id, stream_a.id);
	sched_test_tally_push(
		&bytes_a, stream_a.id, &bytes_b, stream_b.id, &bytes_c,
		stream_c.id);
	T_EXPECT(ss.sched.drr_active == &stream_a);

	/* A stalls before it can send its next frame -- deliberately NOT
	 * drained to empty; the rest of its backlog is still queued. */
	g_block_stream = &stream_a;
	T_EXPECT(stream_a.send_queue.head != NULL);

	/* Drive the scheduler while A sits blocked: B and C must each be able
	 * to complete a full quantum's turn without interference from A. */
	int guard = 0;
	while ((bytes_b < (size_t)ss.max_payload ||
		bytes_c < (size_t)ss.max_payload) &&
	       guard++ < 50) {
		T_CHECK(mux_sched_next_data(&ss));
		T_CHECK(g_last_push_stream_id != stream_a.id);
		sched_test_tally_push(
			&bytes_a, stream_a.id, &bytes_b, stream_b.id, &bytes_c,
			stream_c.id);
	}
	T_CHECK(guard < 50);
	T_EXPECT_EQ(bytes_b, (size_t)ss.max_payload);
	T_EXPECT_EQ(bytes_c, (size_t)ss.max_payload);
	/* Both peers made exactly one quantum of progress but are still
	 * backlogged -- genuinely concurrent with the stalled stream. */
	T_EXPECT(stream_b.send_queue.head != NULL);
	T_EXPECT(stream_c.send_queue.head != NULL);
	/* A is parked: off both the ready queue and drr_active. */
	T_EXPECT(ss.sched.drr_active != &stream_a);
	T_EXPECT(stream_a.sched_queue == SCHED_QUEUE_NONE);

	/* Unblock A exactly as mux_stream_recv_window() or the coalescing timer
	 * would in production: clear the external stall and re-admit it. */
	g_block_stream = NULL;
	mux_sched_wake(&ss, &stream_a);

	/* Measure the uninterrupted burst A sends once rescheduled, stopping
	 * the instant another stream is served (A yielded). */
	size_t a_burst = 0;
	bool a_started = false;
	bool a_continuing = true;
	guard = 0;
	while (a_continuing && guard++ < 50) {
		T_CHECK(mux_sched_next_data(&ss));
		const bool was_a = (g_last_push_stream_id == stream_a.id);
		const size_t n = sched_test_tally_push(
			&bytes_a, stream_a.id, &bytes_b, stream_b.id, &bytes_c,
			stream_c.id);
		if (was_a) {
			a_started = true;
			a_burst += n;
		} else if (a_started) {
			a_continuing = false;
		}
	}
	T_CHECK(guard < 50);
	T_EXPECT(a_started);

	/* The regression check: a stream that stalled without draining must
	 * not have banked more than one quantum of deficit -- its first turn
	 * back must fit the same per-round byte budget as B and C above. */
	T_EXPECT(a_burst <= (size_t)ss.max_payload);

	/* Drain everything and confirm no bytes were lost or duplicated. */
	guard = 0;
	while (guard++ < 50 && mux_sched_next_data(&ss)) {
		sched_test_tally_push(
			&bytes_a, stream_a.id, &bytes_b, stream_b.id, &bytes_c,
			stream_c.id);
	}
	T_CHECK(guard < 50);
	T_EXPECT_EQ(bytes_a, (size_t)42);
	T_EXPECT_EQ(bytes_b, (size_t)90);
	T_EXPECT_EQ(bytes_c, (size_t)90);

	for (size_t i = 0; i < nframes; i++) {
		free(all_frames[i]);
	}
	cleanup_session(&ss);
}

/* The lifecycle-drain request is self-guarding: no-op on an empty queue or
 * occupied sendbuf; marks pending and arms EV_WRITE (via mux_session_notify) only
 * when there is queued work and the sendbuf is clear. */
T_DECLARE_CASE(test_sched_schedule_self_guards_on_queue_and_sendbuf)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream = { .id = 1, .state = STREAM_INIT };
	struct mux_frame staged = { 0 };

	sched_test_reset();

	/* Empty lp queue: nothing to drain, must not mark pending. */
	ss.sched.lp_pending = false;
	mux_sched_schedule(&ss);
	T_EXPECT(!ss.sched.lp_pending);
	T_EXPECT_EQ(g_update_watcher_calls, 0);

	/* Queued work but the sendbuf is occupied: defer (no-op). */
	sched_lp_enqueue(&ss, &stream);
	ss.wire.sendbuf.head = &staged;
	mux_sched_schedule(&ss);
	T_EXPECT(!ss.sched.lp_pending);
	T_EXPECT_EQ(g_update_watcher_calls, 0);

	/* Queued work and the sendbuf clear, but no live socket (fd == -1):
	 * mark pending without arming the watcher. */
	ss.wire.sendbuf.head = NULL;
	mux_sched_schedule(&ss);
	T_EXPECT(ss.sched.lp_pending);
	T_EXPECT_EQ(g_update_watcher_calls, 0);

	/* With a live socket the request arms EV_WRITE via mux_session_notify. */
	ss.sched.lp_pending = false;
	ss.w_socket.fd = 3; /* any value != -1; only tested for liveness here */
	mux_sched_schedule(&ss);
	T_EXPECT(ss.sched.lp_pending);
	T_EXPECT(g_update_watcher_calls >= 1);

	ss.w_socket.fd = -1;
	ss.wire.sendbuf.head = NULL;
	cleanup_session(&ss);
}

/* bench - DRR ready-queue churn (opt-in: run with TESTING_BENCH set in the env) */

T_DECLARE_BENCH(bench_sched_enqueue_dequeue)
{
	sched_test_reset();
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream s = { .id = 1 };
	/* Steady-state churn: one stream cycles through the ready queue. */
	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		sched_enqueue(&ss, &s);
		(void)sched_dequeue(&ss);
	}
	cleanup_session(&ss);
}

/* mux_sched_wake before SESSION_ESTABLISHED routes through the single pre-split
 * queue rather than the DRR/LP split. */
T_DECLARE_CASE(test_sched_wake_before_established_uses_single_queue)
{
	struct mux_session ss;
	make_session(&ss);
	ss.state = SESSION_HANDSHAKE;
	struct mux_stream stream = { .id = 5, .state = STREAM_ESTABLISHED };

	mux_sched_wake(&ss, &stream);
	T_EXPECT(ss.sched.sched_head == &stream);
	T_EXPECT(stream.sched_queue == SCHED_QUEUE_DRR);

	ss.sched.sched_head = ss.sched.sched_tail = NULL;
	cleanup_session(&ss);
}

/* mux_sched_delay shortens the deadline when an earlier request arrives for a
 * stream already in the delay list. */
T_DECLARE_CASE(test_sched_delay_shortens_pending_deadline)
{
	struct mux_session ss;
	make_session(&ss);
	struct mux_stream stream = {
		.id = 5,
		.delay_pending = true,
		.delay_ticks = 5,
	};
	ss.sched.delay_head = &stream;

	mux_sched_delay(&ss, &stream, 2); /* sooner than 5 */
	T_EXPECT_EQ(stream.delay_ticks, (uint_fast8_t)2);
	mux_sched_delay(&ss, &stream, 4); /* not sooner: unchanged */
	T_EXPECT_EQ(stream.delay_ticks, (uint_fast8_t)2);

	ss.sched.delay_head = NULL;
	cleanup_session(&ss);
}

/* mux_sched_find_stream returns NULL when the stream table has not been created. */
T_DECLARE_CASE(test_sched_find_stream_null_table)
{
	struct mux_session ss;
	make_session(&ss);
	struct hashtable *const saved = ss.sched.streams;
	ss.sched.streams = NULL;
	T_EXPECT(mux_sched_find_stream(&ss, 1) == NULL);
	ss.sched.streams = saved;
	cleanup_session(&ss);
}

/* sched_send_ctrl_flags clears ack_pending when the grantable amount is
 * sub-unit (grant_inc == 0) and no FIN is pending. */
T_DECLARE_CASE(test_sched_send_ctrl_flags_subunit_clears_ack)
{
	struct mux_session ss;
	make_session(&ss);
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
	struct mux_session ss;
	make_session(&ss);
	sched_test_reset();

	struct mux_stream stream = { .id = 5, .state = STREAM_ESTABLISHED };
	T_CHECK(mux_sched_add_stream(&ss, &stream));
	ss.draining = true;
	ss.state = SESSION_ESTABLISHED;
	sched_remove_stream(&ss, &stream);
	T_EXPECT_EQ(g_session_initiate_shutdown_calls, 1);

	/* Removing a stream that is no longer present is inert. */
	sched_remove_stream(&ss, &stream);
	T_EXPECT_EQ(g_session_initiate_shutdown_calls, 1);

	cleanup_session(&ss);
}

/* mux_sched_drain_lp frees a CLOSED stream parked on the low-priority queue. */
T_DECLARE_CASE(test_sched_drain_lp_frees_closed_stream)
{
	struct mux_session ss;
	make_session(&ss);
	sched_test_reset();

	struct mux_stream *const s = malloc(sizeof(*s));
	T_CHECK(s != NULL);
	*s = (struct mux_stream){ .id = 7, .state = STREAM_CLOSED };
	s->sched_queue = SCHED_QUEUE_LP;
	ss.sched.lp_head = s;
	ss.sched.lp_tail = s;
	ss.state = SESSION_ESTABLISHED;

	mux_sched_drain_lp(&ss);
	T_EXPECT_EQ(g_stream_free_calls, 1);
	T_EXPECT(ss.sched.lp_head == NULL);

	cleanup_session(&ss);
}

/* A CLOSED direct stream the application has not closed yet (a peer RST or
 * local abort closed it under the application) must not be freed when its
 * tombstone hands it to cleanup: the application still holds the pointer. It
 * stays in the stream table until mux_stream_close() releases it (user_closed)
 * and wakes it again, and is freed on that pass. */
T_DECLARE_CASE(test_sched_drain_lp_holds_unreleased_direct_stream)
{
	struct mux_session ss;
	make_session(&ss);
	sched_test_reset();

	struct mux_stream *const s = malloc(sizeof(*s));
	T_CHECK(s != NULL);
	*s = (struct mux_stream){
		.id = 7,
		.state = STREAM_CLOSED,
		.is_direct = true,
	};
	void *elem = s;
	ss.sched.streams = table_set(
		ss.sched.streams, (const void *)(uintptr_t)s->id, &elem);
	T_CHECK(ss.sched.streams != NULL);
	ss.sched.num_closed = 1;
	sched_lp_enqueue(&ss, s);

	mux_sched_drain_lp(&ss);
	const int held_free_calls = g_stream_free_calls;
	const size_t held_table_size = table_size(ss.sched.streams);
	bool held_dequeued = false;

	/* Reach the stream through the table, so it is touched again only if
	 * the first pass kept it allocated. */
	struct mux_stream *const held = mux_sched_find_stream(&ss, 7);
	if (held != NULL) {
		held_dequeued = ss.sched.lp_head == NULL &&
				held->sched_queue == SCHED_QUEUE_NONE;
		held->user_closed = true;
		mux_sched_wake(&ss, held);
		mux_sched_drain_lp(&ss);
	}
	const int released_free_calls = g_stream_free_calls;
	const size_t released_table_size = table_size(ss.sched.streams);
	const size_t released_closed = ss.sched.num_closed;

	cleanup_session(&ss);

	T_EXPECT_EQ(held_free_calls, 0);
	T_EXPECT_EQ(held_table_size, (size_t)1);
	T_EXPECT(held_dequeued);
	T_EXPECT_EQ(released_free_calls, 1);
	T_EXPECT_EQ(released_table_size, (size_t)0);
	T_EXPECT_EQ(released_closed, (size_t)0);
}

/* sched_coalesce_cb decrements a multi-tick delay without expiring it. */
T_DECLARE_CASE(test_sched_coalesce_cb_decrements_multi_tick)
{
	struct mux_session ss;
	make_session(&ss);
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

/* A delay entry re-arming the coalescing timer while SUSPENDED: once the entry
 * is released the timer stops, even though the session-ACK backlog is kept for
 * resume (it cannot be emitted until the session is ESTABLISHED again). */
T_DECLARE_CASE(test_sched_coalesce_stops_when_suspended_with_ack_backlog)
{
	struct mux_session ss;
	make_session(&ss);
	ss.state = SESSION_SUSPENDED;
	ss.unacked.unreported = 4;
	struct mux_stream stream = { .id = 5, .state = STREAM_ESTABLISHED };

	sched_test_reset();
	mux_sched_delay(&ss, &stream, 1);
	T_EXPECT(ev_is_active(&ss.sched.w_coalesce));

	sched_coalesce_cb(ss.loop, &ss.sched.w_coalesce, EV_TIMER);
	T_EXPECT(ss.sched.delay_head == NULL);
	T_EXPECT(ss.sched.sched_head == &stream);
	T_EXPECT(!ev_is_active(&ss.sched.w_coalesce));
	T_EXPECT_EQ(ss.unacked.unreported, (uint_least32_t)4);
	T_EXPECT_EQ(g_emit_ack_calls, 0);

	ss.sched.sched_head = ss.sched.sched_tail = NULL;
	cleanup_session(&ss);
}

/* While ESTABLISHED the timer keeps running for a pending session-ACK backlog
 * even with an empty delay list: it is what emits the deferred ACK. */
T_DECLARE_CASE(test_sched_coalesce_keeps_running_for_established_backlog)
{
	struct mux_session ss;
	make_session(&ss);
	ss.unacked.unreported = 1;

	sched_test_reset();
	mux_sched_coalesce_arm(&ss);
	sched_coalesce_cb(ss.loop, &ss.sched.w_coalesce, EV_TIMER);
	T_EXPECT(ev_is_active(&ss.sched.w_coalesce));
	T_EXPECT_EQ(ss.unacked.ack_ticks, (uint_least8_t)1);

	ev_timer_stop(ss.loop, &ss.sched.w_coalesce);
	cleanup_session(&ss);
}

static const struct testing_suite suite[] = {
	T_CASE(test_sched_alloc_stream_id_nearly_full),
	T_CASE(test_sched_alloc_stream_id_starts_at_minimum),
	T_CASE(test_sched_add_remove_updates_table_and_idle_timeout),
	T_CASE(test_sched_add_stream_rejects_duplicate_id),
	T_CASE(test_sched_free_streams_clears_stream_counter),
	T_CASE(test_sched_wake_enqueues_only_once),
	T_CASE(test_sched_dequeue_preserves_fifo_order),
	T_CASE(test_sched_delay_remove_handles_head_middle_and_tail),
	T_CASE(test_sched_send_ctrl_flags_emits_ack_and_fin),
	T_CASE(test_sched_flush_ctrl_includes_drr_active),
	T_CASE(test_sched_flush_ctrl_skips_closed_streams),
	T_CASE(test_sched_check_no_active_streams_subtracts_closed_entries),
	T_CASE(test_sched_next_data_reroutes_closed_stream_to_lp),
	T_CASE(test_sched_next_data_sends_frame_and_resets_deficit_on_drain),
	T_CASE(test_sched_sole_stream_drains_without_requeue),
	T_CASE(test_sched_send_ctrl_flags_oom_rearms_stream),
	T_CASE(test_sched_send_ctrl_flags_oom_retries_next_tick),
	T_CASE(test_sched_drain_lp_syn_oom_aborts_unopened),
	T_CASE(test_sched_drain_lp_sends_syn_for_init_stream),
	T_CASE(test_sched_drain_lp_defers_syn_behind_partial_write_in_order),
	T_CASE(test_sched_drain_lp_batches_syn_after_by_reference_push),
	T_CASE(test_sched_drain_lp_failed_syn_behind_frozen_tail_stops_batch),
	T_CASE(test_sched_coalesce_forces_session_ack_after_tick_budget),
	T_CASE(test_sched_next_data_skips_empty_queue_stream),
	T_CASE(test_sched_next_data_exhausts_queue_returns_false),
	T_CASE(test_sched_next_data_blocked_stream_does_not_bank_deficit),
	T_CASE(test_sched_schedule_self_guards_on_queue_and_sendbuf),
	T_CASE(test_stream_id_exhaustion),
	T_CASE(test_stream_id_wraparound_client),
	T_CASE(test_stream_id_wraparound_server),
	T_CASE(test_tombstone_excluded_from_max_streams),
	T_CASE(test_stream_id_collision_skip),
	T_CASE(test_sched_wake_double_enqueue_idempotent),
	T_CASE(test_lp_queue_double_enqueue_prevented),
	T_CASE(test_sched_wake_before_established_uses_single_queue),
	T_CASE(test_sched_delay_shortens_pending_deadline),
	T_CASE(test_sched_find_stream_null_table),
	T_CASE(test_sched_send_ctrl_flags_subunit_clears_ack),
	T_CASE(test_sched_remove_stream_drain_and_absent),
	T_CASE(test_sched_drain_lp_frees_closed_stream),
	T_CASE(test_sched_drain_lp_holds_unreleased_direct_stream),
	T_CASE(test_sched_coalesce_cb_decrements_multi_tick),
	T_CASE(test_sched_coalesce_stops_when_suspended_with_ack_backlog),
	T_CASE(test_sched_coalesce_keeps_running_for_established_backlog),
	/* Opt-in micro-benchmark: ~1s, skipped by the default (unfiltered) run.
	 * Select with `--bench <ere>` or TESTING_BENCH. */
	T_BENCH(bench_sched_enqueue_dequeue),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
