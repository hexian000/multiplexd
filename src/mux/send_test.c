/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* send_test.c - white-box tests for the egress-flush state machine in send.c.
 * Dependencies: send.c #included; all collaborators (sched/stream/wire/
 * estimator/unacked/dispatch) mocked below; no sibling TUs linked. */

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* mock - collaborator spies, frame pool, session fixture
 * Spies for the collaborators the barrier decisions hinge on. */

static int g_sched_schedule_calls;
static int g_sched_drain_lp_calls;
static int g_sched_flush_ctrl_calls;
static int g_sched_next_data_calls;

/* Controllable returns / recorders for the frame-producer tests below. */
static int g_notify_calls;
static int g_sendbuf_push_calls;
/* Makes the mux_wire_sendbuf_push spy destroy the frame it is handed, as the real
 * coalescing path does; off by default so the other cases can still inspect
 * the pushed frame. */
static bool g_push_frees_frame;
static int g_log_frame_calls;
static unsigned char g_last_logged_header[MUX_FRAME_HEADER_SIZE];
static uint_fast32_t g_grant_inc;
static int g_mark_fin_sent_calls;
static int g_delay_remove_calls;
static int g_ack_emitted_calls;
static uint_fast32_t g_ack_emitted_last;
static bool g_wire_send_ret;
static size_t g_wire_send_nsend; /* bytes accepted; SIZE_MAX = all requested */
static int g_wire_send_calls;
static int g_track_sent_calls;
static int g_suspend_calls;
static int g_reset_calls;
static int g_dispatch_pending_calls;
/* mux_wire_flush() return under test (default DONE, as production usually returns). */
static enum wire_flush_result g_wire_flush_result;
/* Number of data frames the mux_sched_next_data() spy still produces before it
 * reports "nothing more"; each staged frame drives one send_pump packing turn. */
static int g_sched_next_data_frames;
/* When true, the mux_sched_next_data() spy stages frames through the real
 * producer's staging/coalescing path (opening sendbuf_staging and packing into
 * the open tail) so several small logical frames share one physical sendbuf
 * entry, instead of pushing one standalone entry per frame. */
static bool g_sched_next_data_coalesce;

static void spies_reset(void)
{
	g_wire_flush_result = WIRE_FLUSH_DONE;
	g_sched_next_data_frames = 0;
	g_sched_next_data_coalesce = false;
	g_sched_schedule_calls = 0;
	g_sched_drain_lp_calls = 0;
	g_sched_flush_ctrl_calls = 0;
	g_sched_next_data_calls = 0;
	g_notify_calls = 0;
	g_sendbuf_push_calls = 0;
	g_push_frees_frame = false;
	g_log_frame_calls = 0;
	g_grant_inc = 0;
	g_mark_fin_sent_calls = 0;
	g_delay_remove_calls = 0;
	g_ack_emitted_calls = 0;
	g_ack_emitted_last = 0;
	g_wire_send_ret = true;
	g_wire_send_nsend = SIZE_MAX;
	g_wire_send_calls = 0;
	g_track_sent_calls = 0;
	g_suspend_calls = 0;
	g_reset_calls = 0;
	g_dispatch_pending_calls = 0;
}

void mux_sched_schedule(struct mux_session *ss)
{
	(void)ss;
	g_sched_schedule_calls++;
}

void mux_sched_drain_lp(struct mux_session *restrict ss)
{
	(void)ss;
	g_sched_drain_lp_calls++;
}

void mux_sched_flush_ctrl(struct mux_session *restrict ss)
{
	(void)ss;
	g_sched_flush_ctrl_calls++;
}

bool mux_sched_next_data(struct mux_session *restrict ss)
{
	g_sched_next_data_calls++;
	if (g_sched_next_data_frames <= 0) {
		return false; /* nothing more to produce: keep send_pump bounded */
	}
	/* Stage one minimal (header-only) data frame into the sendbuf, mirroring
	 * the real producer, so send_pump's stage-and-flush loop actually runs. */
	struct mux_frame *const f = mux_frame_get(&ss->pool, ss->max_payload);
	if (f == NULL) {
		return false;
	}
	f->pos = 0;
	f->len = MUX_FRAME_HEADER_SIZE;
	if (g_sched_next_data_coalesce && ss->wire.sendbuf_staging &&
	    ss->wire.sendbuf.tail != NULL) {
		/* Pack into the open staging tail, as mux_wire_sendbuf_push() does, so
		 * several logical frames share one physical sendbuf entry. */
		struct mux_frame *const tail = ss->wire.sendbuf.tail;
		memcpy(tail->data + tail->len, f->data, f->len);
		tail->len += f->len;
		mux_frame_put(&ss->pool, f);
	} else {
		mux_frame_list_push(&ss->wire.sendbuf, f);
		/* Open the staging tail so the following frames coalesce into it. */
		if (g_sched_next_data_coalesce) {
			ss->wire.sendbuf_staging = true;
		}
	}
	g_sched_next_data_frames--;
	return true;
}

/* Benign no-op stubs for the remaining session.c collaborators */

void mux_session_dispatch_pending(struct mux_session *ss)
{
	(void)ss;
	g_dispatch_pending_calls++;
}

void mux_estimator_add_acked(
	struct mux_session *restrict ss, uint_fast64_t bytes)
{
	(void)ss;
	(void)bytes;
}

void mux_estimator_calculate(
	struct mux_session *restrict ss, int_fast64_t sent_ns)
{
	(void)ss;
	(void)sent_ns;
}

void mux_estimator_init(struct mux_session *restrict ss, size_t bdp)
{
	(void)ss;
	(void)bdp;
}

size_t mux_estimator_rx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return 0;
}

size_t mux_estimator_tx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return 0;
}

bool mux_handshake_enqueue_hello(
	struct mux_session *ss, int msgid, bool include_resume_seq)
{
	(void)ss;
	(void)msgid;
	(void)include_resume_seq;
	return true;
}

bool mux_sched_add_stream(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
	return true;
}

uint_least16_t mux_sched_alloc_stream_id(struct mux_session *ss)
{
	(void)ss;
	return STREAMID_CTRL;
}

void mux_sched_coalesce_arm(struct mux_session *ss)
{
	(void)ss;
}

void mux_sched_delay_remove(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
	g_delay_remove_calls++;
}

void mux_sched_free_streams(struct mux_session *ss)
{
	(void)ss;
}

void mux_sched_init(struct mux_session *restrict ss)
{
	(void)ss;
}

void mux_sched_wake(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
}

void mux_stream_check_ack(struct mux_stream *restrict s)
{
	(void)s;
}

void mux_stream_free(struct mux_stream *s)
{
	(void)s;
}

uint_fast32_t mux_stream_grant_inc(const struct mux_stream *s)
{
	(void)s;
	return g_grant_inc;
}

void mux_stream_mark_fin_sent(struct mux_stream *s)
{
	(void)s;
	g_mark_fin_sent_calls++;
}

struct mux_stream *mux_stream_new(
	struct mux_session *restrict ss, uint_fast16_t id, bool active_open)
{
	(void)ss;
	(void)id;
	(void)active_open;
	return NULL;
}

void mux_wire_conn_free(struct mux_session *ss)
{
	(void)ss;
}

void mux_wire_discard_buffers(struct mux_session *ss)
{
	(void)ss;
}

bool mux_wire_has_pending(const struct mux_session *ss)
{
	(void)ss;
	return false;
}

bool mux_wire_recv(
	struct mux_session *restrict ss, unsigned char *restrict buf,
	size_t *restrict len)
{
	(void)ss;
	(void)buf;
	(void)len;
	return false;
}

bool mux_wire_send(struct mux_session *ss, const unsigned char *buf, size_t *len)
{
	(void)ss;
	(void)buf;
	g_wire_send_calls++;
	if (!g_wire_send_ret) {
		return false;
	}
	if (g_wire_send_nsend != SIZE_MAX && g_wire_send_nsend < *len) {
		*len = g_wire_send_nsend;
	}
	return true;
}

void mux_wire_sendbuf_push(struct mux_session *ss, struct mux_frame *frame)
{
	/* Functional enough for the producer tests: take ownership by appending
	 * to the real sendbuf list so the written header can be inspected and the
	 * frame freed at teardown. */
	g_sendbuf_push_calls++;
	if (g_push_frees_frame) {
		/* Emulate the real coalescing path (wire.c), which copies the
		 * frame into the open staging tail and returns it to the pool
		 * instead of keeping it -- so the caller must not read it after. */
		mux_frame_put(&ss->pool, frame);
		return;
	}
	mux_frame_list_push(&ss->wire.sendbuf, frame);
}

enum wire_flush_result mux_wire_flush(struct mux_session *ss)
{
	(void)ss;
	return g_wire_flush_result;
}

enum wire_shutdown_state mux_wire_shutdown(struct mux_session *ss)
{
	(void)ss;
	return WIRE_SHUTDOWN_DONE;
}

enum wire_eof_result mux_wire_wait_eof(struct mux_session *ss)
{
	(void)ss;
	return WIRE_EOF_ERROR;
}

#if WITH_TLS
bool mux_wire_tls_start(struct mux_session *ss)
{
	(void)ss;
	return true;
}

void mux_wire_adopt_tlsconn(
	struct mux_session *restrict ss, struct tls_connection *restrict conn)
{
	(void)ss;
	(void)conn;
}

void mux_wire_tls_log_status(struct mux_session *ss)
{
	(void)ss;
}
#endif /* WITH_TLS */

bool mux_bytebuf_reserve(
	struct bytebuf **restrict rbp, size_t need, bool can_grow)
{
	(void)rbp;
	(void)need;
	(void)can_grow;
	return true;
}

struct mux_frame_ring *mux_frame_ring_new(size_t cap)
{
	(void)cap;
	return NULL;
}

struct mux_frame_ring *mux_frame_ring_grow(struct mux_frame_ring *r)
{
	return r;
}

const struct table_opts mux_stream_table_opts = { 0 };

/* frame.c data global the header-inline framing helpers reference; stubbed here
 * since this white-box TU does not link frame.c. */
const struct mux_config mux_conf_default = {
	.max_frame_payload = 65536 - MUX_FRAME_HEADER_SIZE,
	.readahead = 128 * 1024,
};

/* Session-core collaborators: send.c calls back into these for watcher/state
 * updates; the egress-flush assertions below depend only on the sched spies, so
 * these are benign no-ops. */
void mux_session_update_watcher(struct mux_session *restrict ss)
{
	(void)ss;
}

void mux_session_set_state(struct mux_session *ss, enum session_state newstate)
{
	ss->state = newstate;
}

void mux_session_suspend(struct mux_session *ss)
{
	g_suspend_calls++;
	ss->state = SESSION_SUSPENDED;
}

void mux_session_reset(struct mux_session *ss)
{
	g_reset_calls++;
	ss->state = SESSION_CLOSED;
}

/* Mirrors production mux_session_suspend_or_reset so these white-box tests still
 * observe the suspend-vs-reset decision via the stubs above. */
void mux_session_suspend_or_reset(struct mux_session *ss)
{
	if (ss->handshake.has_session_id &&
	    (ss->state == SESSION_ESTABLISHED ||
	     (ss->state == SESSION_HANDSHAKE && !ss->accepted))) {
		mux_session_suspend(ss);
	} else {
		mux_session_reset(ss);
	}
}

void mux_session_notify(struct mux_session *restrict ss)
{
	(void)ss;
	g_notify_calls++;
}

void mux_session_log_frame_header(
	const struct mux_session *restrict ss, const char *restrict what,
	const unsigned char *restrict raw,
	const struct mux_header *restrict hdr)
{
	(void)ss;
	(void)what;
	(void)hdr;
	/* The real implementation (session.c) hexdumps `raw`, so read it here
	 * too: a spy that ignored it would hide a producer logging a frame it has
	 * already handed away -- exactly the use-after-free
	 * test_send_push_does_not_read_frame_after_push pins. */
	memcpy(g_last_logged_header, raw, MUX_FRAME_HEADER_SIZE);
	g_log_frame_calls++;
}

/* unacked collaborators referenced by the send pipeline (never reached in these
 * cases: no frame is produced, so the retransmit/track paths stay idle). */
void mux_unacked_track_sent(struct mux_session *ss, struct mux_frame *frame)
{
	/* The real implementation takes ownership; mirror that so the flush
	 * tests, which fully send a frame, do not leak it. */
	g_track_sent_calls++;
	mux_frame_put(&ss->pool, frame);
}

void mux_unacked_ack_emitted(struct mux_session *ss, uint_fast32_t emit)
{
	(void)ss;
	g_ack_emitted_calls++;
	g_ack_emitted_last = emit;
}

/* Mirror the real mux_unacked_free_all's teardown of the retransmit state so
 * test_send_handle_rx_closed_terminal can assert the branch dropped the
 * dangling replay pointer; the ring itself is mocked away in this TU. */
void mux_unacked_free_all(struct mux_session *ss)
{
	ss->unacked.retransmit_copy = NULL;
	ss->unacked.retransmit_off = SIZE_MAX;
	ss->unacked.frames = 0;
	ss->unacked.bytes = 0;
	ss->unacked.stalled = false;
}

/* Pull in the unit under test after the collaborator definitions so its
 * external references bind to the spies above.  mux_session_on_send / mux_session_flush /
 * session_flush_inline now live in send.c. */
#include "mux/send.c"

/* Fixture: a minimal session with a real loop and the mux socket watcher.
 * modify_io_events asserts a valid fd, so w_socket is bound to a live pipe end
 * that is never actually driven. */

static void si_noop_io_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void si_noop_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

struct si_pool_ctx {
	uint_least32_t alloc_calls;
	uint_least32_t free_calls;
	/* force allocation failure to exercise OOM paths */
	bool fail;
};

static struct mux_frame *si_pool_alloc(void *data, const size_t size)
{
	struct si_pool_ctx *const ctx = data;
	if (ctx->fail) {
		return NULL;
	}
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void si_pool_free(void *data, struct mux_frame *frame)
{
	struct si_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

struct si_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
	struct si_pool_ctx pool_ctx;
	int pipefd[2];
};

static int si_setup(struct si_fixture *restrict fx)
{
	*fx = (struct si_fixture){ .pipefd = { -1, -1 } };
	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}
	if (pipe(fx->pipefd) != 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	fx->ss = (struct mux_session){
		.loop = fx->loop,
		.state = SESSION_ESTABLISHED,
		.pool = {
			.alloc = si_pool_alloc,
			.free = si_pool_free,
			.data = &fx->pool_ctx,
		},
		.max_payload = MUX_MAX_PAYLOAD_SIZE,
		.wire = {
			.rx_open = true,
		},
		/* Matches mux_session_new()'s real default: SIZE_MAX means "no resume
		 * replay in progress", not the zero-init compound literal would
		 * otherwise leave here. */
		.unacked = {
			.retransmit_off = SIZE_MAX,
		},
	};
	ev_io_init(&fx->ss.w_socket, si_noop_io_cb, fx->pipefd[0], EV_READ);
	fx->ss.w_socket.data = &fx->ss;
	return 0;
}

static void si_teardown(struct si_fixture *restrict fx)
{
	/* Free any frames the producer tests left queued. */
	mux_frame_list_clear(&fx->ss.wire.sendbuf, &fx->ss.pool);
	mux_frame_list_clear(&fx->ss.wire.oobbuf, &fx->ss.pool);
	if (ev_is_active(&fx->ss.w_socket)) {
		ev_io_stop(fx->loop, &fx->ss.w_socket);
	}
	for (int i = 0; i < 2; i++) {
		if (fx->pipefd[i] >= 0) {
			(void)close(fx->pipefd[i]);
			fx->pipefd[i] = -1;
		}
	}
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* regression - targeted cases pinning one egress decision each */

/* mux_session_on_send: the low-priority lifecycle drain is gated on ESTABLISHED. */

/* Before ESTABLISHED, mux_sched_drain_lp is a no-op, so mux_session_on_send must leave
 * lp_pending set (not consume it) and not call the drain -- otherwise the
 * queued INIT/CLOSED streams are stranded until an unrelated re-arm. */
T_DECLARE_CASE(test_send_cb_defers_lp_drain_before_established)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_HANDSHAKE;
	fx.ss.unacked.retransmit_off = SIZE_MAX; /* no replay in progress */
	fx.ss.sched.lp_pending = true;
	fx.ss.wire.tx_pending = true;

	mux_session_on_send(&fx.ss);

	const bool lp_pending = fx.ss.sched.lp_pending;
	const int drain_lp = g_sched_drain_lp_calls;
	const int next_data = g_sched_next_data_calls;
	si_teardown(&fx);

	T_EXPECT(lp_pending); /* not consumed */
	T_EXPECT_EQ(drain_lp, 0);
	/* HANDSHAKE breaks out of send_pump before the data scheduler. */
	T_EXPECT_EQ(next_data, 0);
}

/* Once ESTABLISHED, mux_session_on_send consumes lp_pending and runs the drain at entry,
 * before pumping, so its SYN/cleanup frames coalesce into this write. */
T_DECLARE_CASE(test_send_cb_drains_lp_when_established)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.unacked.retransmit_off = SIZE_MAX; /* no replay in progress */
	fx.ss.sched.lp_pending = true;
	fx.ss.wire.tx_pending = true;

	mux_session_on_send(&fx.ss);

	const bool lp_pending = fx.ss.sched.lp_pending;
	const int drain_lp = g_sched_drain_lp_calls;
	const bool send_blocked = fx.ss.wire.send_blocked;
	si_teardown(&fx);

	T_EXPECT(!lp_pending); /* consumed */
	T_EXPECT_EQ(drain_lp, 1);
	T_EXPECT(!send_blocked); /* drained: no residue */
}

/* mux_session_flush: the low-load fast path flushes inline when the pipe is clear. */

/* sendbuf empty (transport idle) -> flush straight through mux_session_on_send instead of
 * deferring to EV_WRITE: the send pipeline is entered in this call. */
T_DECLARE_CASE(test_session_flush_inline_when_pipe_clear)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.unacked.retransmit_off = SIZE_MAX; /* no replay in progress */
	fx.ss.wire.tx_pending = true;
	/* sendbuf.head == NULL and tls_want == 0: the pipe is clear. */

	mux_session_flush(&fx.ss);

	const int next_data = g_sched_next_data_calls;
	const bool tx_pending = fx.ss.wire.tx_pending;
	si_teardown(&fx);

	/* Inline path ran mux_session_on_send -> send_pump reached the data scheduler. */
	T_EXPECT_EQ(next_data, 1);
	T_EXPECT(!tx_pending); /* mux_session_on_send cleared it (no residue) */
}

/* mux_session_on_send: the lifecycle drain is resumed unconditionally (mux_sched_schedule
 * self-guards on an occupied sendbuf), even with an empty lp queue. */

/* Regression for the centralised guard: mux_session_on_send must call mux_sched_schedule on
 * every drain, not only when lp_head is non-NULL and the sendbuf cleared.  With
 * an empty session (no residue, lp_head == NULL) the call must still happen. */
T_DECLARE_CASE(test_send_cb_resumes_lifecycle_drain_unconditionally)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.unacked.retransmit_off = SIZE_MAX; /* no replay in progress */
	fx.ss.wire.tx_pending = true;

	mux_session_on_send(&fx.ss);

	const int schedules = g_sched_schedule_calls;
	const bool send_blocked = fx.ss.wire.send_blocked;
	const bool tx_pending = fx.ss.wire.tx_pending;
	si_teardown(&fx);

	T_EXPECT_EQ(schedules, 1);
	T_EXPECT(!send_blocked); /* drained: no residue */
	T_EXPECT(!tx_pending);
}

/* mux_session_on_send epilogue: with no sendbuf residue, mux_wire_flush() drains the
 * cipher buffer. WIRE_FLUSH_BLOCKED must keep the write path armed (tx_pending)
 * without marking send_blocked (nothing is in flight in the sendbuf head). */
T_DECLARE_CASE(test_session_on_send_wire_flush_blocked_keeps_tx_pending)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_flush_result = WIRE_FLUSH_BLOCKED;

	mux_session_on_send(&fx.ss);

	const bool tx_pending = fx.ss.wire.tx_pending;
	const bool send_blocked = fx.ss.wire.send_blocked;
	const int suspends = g_suspend_calls;
	const int resets = g_reset_calls;
	si_teardown(&fx);

	T_EXPECT(tx_pending);
	T_EXPECT(!send_blocked);
	T_EXPECT_EQ(suspends, 0);
	T_EXPECT_EQ(resets, 0);
}

/* WIRE_FLUSH_ERROR on a resumable transport (session_id present, ESTABLISHED)
 * suspends the session; it must not reset. */
T_DECLARE_CASE(test_session_on_send_wire_flush_error_suspends_resumable)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_flush_result = WIRE_FLUSH_ERROR;
	fx.ss.handshake.has_session_id = true; /* resumable */

	mux_session_on_send(&fx.ss);

	const int suspends = g_suspend_calls;
	const int resets = g_reset_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(suspends, 1);
	T_EXPECT_EQ(resets, 0);
}

/* WIRE_FLUSH_ERROR with no resume state resets the session. */
T_DECLARE_CASE(test_session_on_send_wire_flush_error_resets_non_resumable)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_flush_result = WIRE_FLUSH_ERROR;
	fx.ss.handshake.has_session_id = false; /* not resumable */

	mux_session_on_send(&fx.ss);

	const int suspends = g_suspend_calls;
	const int resets = g_reset_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(suspends, 0);
	T_EXPECT_EQ(resets, 1);
}

/* send_pump's stage-and-flush loop: each staged data frame is transmitted at the
 * top of the next turn before the next is produced. Drive several frames through
 * it (the mux_sched_next_data spy stages one header-only frame per turn). */
T_DECLARE_CASE(test_send_pump_stages_and_flushes_multiple_frames)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_sched_next_data_frames = 3;

	mux_session_on_send(&fx.ss);

	const int produced = g_sched_next_data_calls;
	const int remaining = g_sched_next_data_frames;
	const int sent = g_wire_send_calls;
	const int tracked = g_track_sent_calls;
	const bool sendbuf_empty = fx.ss.wire.sendbuf.head == NULL;
	si_teardown(&fx);

	/* 3 frames produced (each staged then flushed) plus the final "no more". */
	T_EXPECT_EQ(produced, 4);
	T_EXPECT_EQ(remaining, 0);
	T_EXPECT_EQ(sent, 3); /* each frame flushed via mux_wire_send */
	T_EXPECT_EQ(tracked, 3); /* each fully-sent frame handed to unacked */
	T_EXPECT(sendbuf_empty);
}

/* send_pump's coalescing/packing path: when the producer opens the staging
 * tail (sendbuf_staging), send_head_must_flush() leaves that tail unflushed so
 * successive small frames pack into it -- several logical frames become ONE
 * physical sendbuf entry flushed once (fewer mux_wire_send() calls than frames).
 * Contrast test_send_pump_stages_and_flushes_multiple_frames, whose non-staging
 * producer flushes a standalone entry per frame. */
T_DECLARE_CASE(test_send_pump_coalesces_staged_frames_into_one_record)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_sched_next_data_frames = 3;
	g_sched_next_data_coalesce = true;

	mux_session_on_send(&fx.ss);

	const int produced = g_sched_next_data_calls;
	const int remaining = g_sched_next_data_frames;
	const int sent = g_wire_send_calls;
	const int tracked = g_track_sent_calls;
	const bool sendbuf_empty = fx.ss.wire.sendbuf.head == NULL;
	const bool staging_closed = !fx.ss.wire.sendbuf_staging;
	si_teardown(&fx);

	T_EXPECT_EQ(produced, 4); /* 3 produced + final "no more" */
	T_EXPECT_EQ(remaining, 0);
	/* The 3 logical frames packed into one physical entry flushed once: the
	 * central coalescing behavior, not one flush per frame. */
	T_EXPECT_EQ(sent, 1);
	T_EXPECT_EQ(tracked, 1); /* one physical entry handed to unacked */
	T_EXPECT(sendbuf_empty);
	T_EXPECT(staging_closed); /* the flushed staging tail closed staging */
}

/* Frame producers: mux_session_send_ctrl/_oob/_push, mux_session_emit_ack, and
 * mux_session_discard_stream_frames; mux_wire_sendbuf_push spy captures produced
 * frames so the encoded header and session accounting can be asserted. */

static struct mux_frame *
si_alloc_frame(struct si_fixture *restrict fx, const size_t payload_len)
{
	struct mux_frame *const f =
		mux_frame_get(&fx->ss.pool, fx->ss.max_payload);
	if (f != NULL) {
		f->pos = 0;
		f->len = MUX_FRAME_HEADER_SIZE + payload_len;
	}
	return f;
}

static void si_queue_ctrl(
	struct si_fixture *restrict fx, const uint_least16_t stream_id,
	const uint_least8_t flags)
{
	struct mux_frame *const f = si_alloc_frame(fx, 0);
	if (f == NULL) {
		/* No case currently forces pool_ctx.fail, so this never fires;
		 * guard the deref so a future OOM-path case queues nothing (its
		 * own assertions then fail) rather than dereferencing NULL. */
		return;
	}
	const struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = flags,
		.length = 0,
		.stream_id = stream_id,
	};
	mux_write_header(f->data, &h);
	mux_frame_list_push(&fx->ss.wire.sendbuf, f);
}

/* Build one physical sendbuf entry that coalesces @n zero-payload sub-frames
 * from the given (stream_id, flags) pairs -- mirroring mux_wire_sendbuf_push's
 * packing of multiple logical frames (possibly from different streams) into a
 * single node -- append it, and return it. */
static struct mux_frame *si_queue_coalesced(
	struct si_fixture *restrict fx, const uint_least16_t *restrict ids,
	const uint_least8_t *restrict flags, const size_t n)
{
	struct mux_frame *const f = si_alloc_frame(fx, 0);
	if (f == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < n; i++) {
		const struct mux_header h = {
			.version = MUX_PROTOCOL_VERSION,
			.flags = flags[i],
			.length = 0,
			.stream_id = ids[i],
		};
		mux_write_header(f->data + i * MUX_FRAME_HEADER_SIZE, &h);
	}
	f->len = n * MUX_FRAME_HEADER_SIZE;
	mux_frame_list_push(&fx->ss.wire.sendbuf, f);
	return f;
}

/* mux_session_send_ctrl encodes the header, clamps Extra to 16 bits, queues the
 * frame, and wakes the writer. */
T_DECLARE_CASE(test_send_ctrl_encodes_and_clamps)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();

	const bool ok = mux_session_send_ctrl(
		&fx.ss, 5, MUX_FLAG_ACK, 100000 /* > UINT16_MAX */);

	const int push_calls = g_sendbuf_push_calls;
	const bool tx_pending = fx.ss.wire.tx_pending;
	const bool has_head = fx.ss.wire.sendbuf.head != NULL;
	struct mux_header h = { 0 };
	if (has_head) {
		mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	}
	si_teardown(&fx);

	T_EXPECT(ok);
	T_EXPECT_EQ(push_calls, 1);
	T_EXPECT(tx_pending); /* mux_notify_write fired */
	T_EXPECT(has_head);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_ACK);
	T_EXPECT_EQ((int)h.stream_id, 5);
	T_EXPECT_EQ((int)h.length, 0);
	T_EXPECT_EQ((int)h.extra, (int)UINT16_MAX);
}

/* On allocation failure mux_session_send_ctrl reports failure and queues nothing. */
T_DECLARE_CASE(test_send_ctrl_oom)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.pool_ctx.fail = true;
	mux_counter rst_sent = 0;
	fx.ss.cnt.num_rst_sent = &rst_sent;

	const bool ok = mux_session_send_ctrl(&fx.ss, 5, MUX_FLAG_RST, 0);

	const int push_calls = g_sendbuf_push_calls;
	const bool sendbuf_empty = fx.ss.wire.sendbuf.head == NULL;
	const uint_least64_t rst_count = COUNTER_LOAD(fx.ss.cnt.num_rst_sent);
	si_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT_EQ(push_calls, 0);
	T_EXPECT(sendbuf_empty);
	/* The RST was never enqueued, so num_rst_sent must not have counted it. */
	T_EXPECT_EQ(rst_count, (uint_least64_t)0);
}

/* mux_session_send_oob copies the supplied payload into a stream-0 frame queued on
 * the OOB list. */
T_DECLARE_CASE(test_send_oob_copies_payload)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	const unsigned char payload[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	const bool ok = mux_session_send_oob(
		&fx.ss, MUX_CTRL_PONG, payload, sizeof(payload));

	const bool has_head = fx.ss.wire.oobbuf.head != NULL;
	const bool tx_pending = fx.ss.wire.tx_pending;
	struct mux_header h = { 0 };
	unsigned char body[sizeof(payload)] = { 0 };
	if (has_head) {
		mux_read_header(fx.ss.wire.oobbuf.head->data, &h);
		memcpy(body,
		       fx.ss.wire.oobbuf.head->data + MUX_FRAME_HEADER_SIZE,
		       sizeof(body));
	}
	si_teardown(&fx);

	T_EXPECT(ok);
	T_EXPECT(has_head);
	T_EXPECT_EQ((int)h.stream_id, STREAMID_CTRL);
	T_EXPECT_EQ((int)h.extra, MUX_CTRL_PONG);
	T_EXPECT_EQ((int)h.length, (int)sizeof(payload));
	T_EXPECT_MEMEQ(body, payload, sizeof(payload));
	T_EXPECT(tx_pending);
}

/* With a NULL payload the OOB frame body is zero-filled. */
T_DECLARE_CASE(test_send_oob_zero_fills)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();

	const bool ok = mux_session_send_oob(&fx.ss, MUX_CTRL_PROBE, NULL, 4);

	const bool has_head = fx.ss.wire.oobbuf.head != NULL;
	unsigned char body[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	if (has_head) {
		memcpy(body,
		       fx.ss.wire.oobbuf.head->data + MUX_FRAME_HEADER_SIZE,
		       sizeof(body));
	}
	si_teardown(&fx);

	T_EXPECT(ok);
	T_EXPECT(has_head);
	const unsigned char zeros[4] = { 0, 0, 0, 0 };
	T_EXPECT_MEMEQ(body, zeros, sizeof(zeros));
}

T_DECLARE_CASE(test_send_oob_oom)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.pool_ctx.fail = true;

	const bool ok = mux_session_send_oob(&fx.ss, MUX_CTRL_PING, NULL, 0);

	const bool oob_empty = fx.ss.wire.oobbuf.head == NULL;
	si_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT(oob_empty);
}

/* A first PUSH on an INIT stream carries SYN and accounts the payload bytes. */
T_DECLARE_CASE(test_send_push_syn_on_init)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	struct mux_stream s = { .id = 4, .state = STREAM_INIT };
	struct mux_frame *const frame = si_alloc_frame(&fx, 100);

	mux_session_send_push(&fx.ss, &s, frame);

	const bool has_head = fx.ss.wire.sendbuf.head != NULL;
	struct mux_header h = { 0 };
	if (has_head) {
		mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	}
	si_teardown(&fx);

	T_EXPECT(has_head);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_PUSH | MUX_FLAG_SYN);
	T_EXPECT_EQ((int)h.length, 100);
	T_EXPECT_EQ((int)h.stream_id, 4);
	T_EXPECT_EQ(s.bytes_sent, (uint_least32_t)100);
	T_EXPECT_EQ(s.unacked_bytes, (uint_least32_t)100);
}

/* A final PUSH on an established stream with EOF reached and credit to grant
 * carries ACK|FIN, marks the FIN sent, and cancels any pending delay. */
T_DECLARE_CASE(test_send_push_ack_fin)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_grant_inc = 2;
	struct mux_stream s = {
		.id = 6,
		.state = STREAM_ESTABLISHED,
		.rx_eof = true,
		.delay_pending = true,
	};
	struct mux_frame *const frame = si_alloc_frame(&fx, 50);

	mux_session_send_push(&fx.ss, &s, frame);

	const bool has_head = fx.ss.wire.sendbuf.head != NULL;
	const int mark_fin = g_mark_fin_sent_calls;
	const int delay_remove = g_delay_remove_calls;
	struct mux_header h = { 0 };
	if (has_head) {
		mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	}
	si_teardown(&fx);

	T_EXPECT(has_head);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_PUSH | MUX_FLAG_ACK | MUX_FLAG_FIN);
	T_EXPECT_EQ((int)h.extra, 2);
	T_EXPECT_EQ(mark_fin, 1);
	T_EXPECT_EQ(delay_remove, 1);
	T_EXPECT_EQ(s.grant_sent, (uint_least32_t)(2u * MUX_WINDOW_UNIT));
}

/* mux_wire_sendbuf_push takes ownership: its real coalescing path copies the frame
 * into the open staging tail and returns it to the pool, so mux_session_send_push
 * must read neither `frame` nor a pointer into it afterwards. Regression -- the
 * VERYVERBOSE "frame out" log did exactly that, reading a freed frame in any
 * session carrying small data frames. Here the spy frees on push, as that path
 * does, so the sanitizer build traps on a post-push read; g_log_frame_calls
 * pins that the logging actually ran (this suite runs at VERYVERBOSE, see
 * main()), without which the case would pass vacuously. The accounting
 * assertions confirm the epilogue still works off its own locals. */
T_DECLARE_CASE(test_send_push_does_not_read_frame_after_push)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_push_frees_frame = true;
	struct mux_stream s = { .id = 8, .state = STREAM_ESTABLISHED };
	struct mux_frame *const frame = si_alloc_frame(&fx, 64);

	mux_session_send_push(&fx.ss, &s, frame);

	const int push_calls = g_sendbuf_push_calls;
	const int log_calls = g_log_frame_calls;
	const uint_least32_t free_calls = fx.pool_ctx.free_calls;
	struct mux_header logged;
	mux_read_header(g_last_logged_header, &logged);
	si_teardown(&fx);

	T_EXPECT_EQ(push_calls, 1);
	T_EXPECT_EQ(log_calls, 1);
	T_EXPECT_EQ(free_calls, (uint_least32_t)1);
	/* Asserting the captured bytes is what keeps the spy honest: it is the
	 * only reader of g_last_logged_header, and without one the spy's copy is
	 * a dead store that the optimizer drops (verified: at -O2 the spy becomes
	 * a bare counter increment reading nothing), leaving the case unable to
	 * trap on the post-push read it exists to pin. It also confirms the log
	 * receives the fully-formed header rather than an empty one. */
	T_EXPECT_EQ((int)logged.flags, MUX_FLAG_PUSH);
	T_EXPECT_EQ((int)logged.stream_id, 8);
	T_EXPECT_EQ((int)logged.length, 64);
	T_EXPECT_EQ(s.bytes_sent, (uint_least32_t)64);
	T_EXPECT_EQ(s.unacked_bytes, (uint_least32_t)64);
}

/* mux_session_emit_ack sends a session-level ACK carrying the unreported count
 * and records the emission. */
T_DECLARE_CASE(test_emit_ack_sends_unreported)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.unacked.unreported = 3;

	mux_session_emit_ack(&fx.ss);

	const int push_calls = g_sendbuf_push_calls;
	const int ack_calls = g_ack_emitted_calls;
	const uint_fast32_t ack_last = g_ack_emitted_last;
	const bool has_head = fx.ss.wire.sendbuf.head != NULL;
	struct mux_header h = { 0 };
	if (has_head) {
		mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	}
	si_teardown(&fx);

	T_EXPECT_EQ(push_calls, 1);
	T_EXPECT(has_head);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_ACK);
	T_EXPECT_EQ((int)h.stream_id, STREAMID_CTRL);
	T_EXPECT_EQ((int)h.extra, 3);
	T_EXPECT_EQ(ack_calls, 1);
	T_EXPECT_EQ(ack_last, (uint_fast32_t)3);
}

/* The session ACK count is clamped to the 16-bit Extra field. */
T_DECLARE_CASE(test_emit_ack_clamps_unreported)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.unacked.unreported = 70000; /* > UINT16_MAX */

	mux_session_emit_ack(&fx.ss);

	const uint_fast32_t ack_last = g_ack_emitted_last;
	si_teardown(&fx);

	T_EXPECT_EQ(ack_last, (uint_fast32_t)UINT16_MAX);
}

/* mux_session_discard_stream_frames drops only the unsent non-RST frames of the
 * target stream, keeping its RST and other streams' frames. */
T_DECLARE_CASE(test_discard_stream_frames_selective)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	si_queue_ctrl(&fx, 5, MUX_FLAG_PUSH); /* discarded */
	si_queue_ctrl(&fx, 5, MUX_FLAG_RST); /* kept (never drop a RST) */
	si_queue_ctrl(&fx, 7, MUX_FLAG_PUSH); /* kept (other stream) */

	mux_session_discard_stream_frames(&fx.ss, 5);

	const size_t count = fx.ss.wire.sendbuf.count;
	bool no_unsent_stream5_data = true;
	for (const struct mux_frame *f = fx.ss.wire.sendbuf.head; f != NULL;
	     f = f->next) {
		struct mux_header h;
		mux_read_header(f->data, &h);
		if (h.stream_id == 5 && (h.flags & MUX_FLAG_RST) == 0) {
			no_unsent_stream5_data = false;
		}
	}
	si_teardown(&fx);

	T_EXPECT_EQ(count, (size_t)2);
	T_EXPECT(no_unsent_stream5_data);
}

/* A single physical entry coalescing frames from two streams: discarding one
 * stream strips only its non-RST sub-frames in place and keeps the other
 * stream's data (and the target's own RST) -- not an all-or-nothing decision
 * from the first header, which would either free stream 7's data or leave
 * stream 5's stale data behind. */
T_DECLARE_CASE(test_discard_stream_frames_compacts_coalesced_entry)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	const uint_least16_t ids[4] = { 5, 7, 5, 5 };
	const uint_least8_t flags[4] = { MUX_FLAG_PUSH, MUX_FLAG_PUSH,
					 MUX_FLAG_RST, MUX_FLAG_PUSH };
	struct mux_frame *const node = si_queue_coalesced(&fx, ids, flags, 4);
	T_CHECK(node != NULL);

	mux_session_discard_stream_frames(&fx.ss, 5);

	/* The node survives, compacted to [stream 7 PUSH | stream 5 RST]. */
	const size_t count = fx.ss.wire.sendbuf.count;
	const bool head_is_node = fx.ss.wire.sendbuf.head == node;
	const size_t node_len = node->len;
	struct mux_header h0 = { 0 };
	struct mux_header h1 = { 0 };
	mux_read_header(node->data, &h0);
	mux_read_header(node->data + MUX_FRAME_HEADER_SIZE, &h1);
	si_teardown(&fx);

	T_EXPECT_EQ(count, (size_t)1);
	T_EXPECT(head_is_node);
	T_EXPECT_EQ(node_len, (size_t)(2 * MUX_FRAME_HEADER_SIZE));
	T_EXPECT_EQ((int)h0.stream_id, 7);
	T_EXPECT_EQ((int)h0.flags, MUX_FLAG_PUSH);
	T_EXPECT_EQ((int)h1.stream_id, 5);
	T_EXPECT_EQ((int)(h1.flags & MUX_FLAG_RST), MUX_FLAG_RST);
}

/* Even when every sub-frame of the entry belongs to the discarded stream, the
 * in-flight retransmit copy is left intact (not removed): removing it would not
 * advance retransmit_off, so send_stage_next would just re-copy the same ring
 * entry (pure churn). The copy replays its ring entry verbatim. */
T_DECLARE_CASE(test_discard_stream_frames_keeps_all_belong_retransmit_copy)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	const uint_least16_t ids[2] = { 5, 5 };
	const uint_least8_t flags[2] = { MUX_FLAG_PUSH, MUX_FLAG_PUSH };
	struct mux_frame *const copy = si_queue_coalesced(&fx, ids, flags, 2);
	T_CHECK(copy != NULL);
	fx.ss.unacked.retransmit_copy = copy;

	mux_session_discard_stream_frames(&fx.ss, 5);

	const size_t count = fx.ss.wire.sendbuf.count;
	const bool copy_kept = fx.ss.unacked.retransmit_copy == copy;
	si_teardown(&fx);

	T_EXPECT_EQ(count, (size_t)1);
	T_EXPECT(copy_kept);
}

/* mux_session_discard_stream_frames also strips a reset stream's frames parked on
 * wire.oobbuf (where mux_session_send_ctrl parks real-stream control during resume
 * replay), not just wire.sendbuf. */
T_DECLARE_CASE(test_discard_stream_frames_walks_oobbuf)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	struct mux_frame *const f = si_alloc_frame(&fx, 0);
	T_CHECK(f != NULL);
	const struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
		.length = 0,
		.stream_id = 5,
	};
	mux_write_header(f->data, &h);
	mux_frame_list_push(&fx.ss.wire.oobbuf, f);

	mux_session_discard_stream_frames(&fx.ss, 5);

	/* The parked SYN|ACK for the reset stream was stripped (whole node). */
	const size_t oob_count = fx.ss.wire.oobbuf.count;
	si_teardown(&fx);

	T_EXPECT_EQ(oob_count, (size_t)0);
}

/* An armed retransmit whose ring is NULL (a degenerate, production-unreachable
 * state) is treated as replay-drained rather than peeking the NULL ring. */
T_DECLARE_CASE(test_send_stage_next_drains_replay_when_ring_null)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.unacked.ring = NULL;
	fx.ss.unacked.retransmit_off = 0;

	mux_session_on_send(&fx.ss);

	const size_t retransmit_off = fx.ss.unacked.retransmit_off;
	si_teardown(&fx);

	T_EXPECT_EQ(retransmit_off, SIZE_MAX);
}

/* A coalesced entry that survives partial stripping (kept > 0) but IS the
 * in-flight retransmit copy is left byte-for-byte intact, not compacted: the
 * copy must replay its ring entry verbatim so the peer receives the exact
 * retransmitted frame, so its stripped-stream sub-frame is deliberately left
 * trailing the RST. Contrast
 * test_discard_stream_frames_compacts_coalesced_entry, which compacts the same
 * layout when it is NOT the retransmit copy. */
T_DECLARE_CASE(test_discard_stream_frames_keeps_retransmit_copy_verbatim)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	const uint_least16_t ids[4] = { 5, 7, 5, 5 };
	const uint_least8_t flags[4] = { MUX_FLAG_PUSH, MUX_FLAG_PUSH,
					 MUX_FLAG_RST, MUX_FLAG_PUSH };
	struct mux_frame *const copy = si_queue_coalesced(&fx, ids, flags, 4);
	T_CHECK(copy != NULL);
	fx.ss.unacked.retransmit_copy = copy;

	/* Snapshot the exact wire bytes before the discard. */
	const size_t orig_len = copy->len;
	unsigned char before[4 * MUX_FRAME_HEADER_SIZE];
	T_CHECK(orig_len == sizeof(before));
	memcpy(before, copy->data, orig_len);

	mux_session_discard_stream_frames(&fx.ss, 5);

	/* The node is kept, uncompacted (all four sub-frames still present),
	 * and remains the active retransmit copy. */
	const size_t count = fx.ss.wire.sendbuf.count;
	const bool head_is_copy = fx.ss.wire.sendbuf.head == copy;
	const bool copy_kept = fx.ss.unacked.retransmit_copy == copy;
	const size_t copy_len = copy->len;
	unsigned char after[sizeof(before)] = { 0 };
	if (copy_len == sizeof(after)) {
		memcpy(after, copy->data, sizeof(after));
	}
	si_teardown(&fx);

	T_EXPECT_EQ(count, (size_t)1);
	T_EXPECT(head_is_copy);
	T_EXPECT(copy_kept);
	T_EXPECT_EQ(copy_len, orig_len);
	T_EXPECT_MEMEQ(after, before, orig_len);
}

/* mux_notify_write is a no-op outside SESSION_ESTABLISHED (the write path is
 * only armed once the session is up). */
T_DECLARE_CASE(test_notify_write_noop_before_established)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_HANDSHAKE;

	mux_notify_write(&fx.ss);

	const bool tx_pending = fx.ss.wire.tx_pending;
	const int notify_calls = g_notify_calls;
	si_teardown(&fx);

	T_EXPECT(!tx_pending);
	T_EXPECT_EQ(notify_calls, 0);
}

/* mux_session_flush before establishment defers to a plain notify (no inline pump
 * or scheduler run). */
T_DECLARE_CASE(test_session_flush_defers_before_established)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_HANDSHAKE;

	mux_session_flush(&fx.ss);

	const int notify_calls = g_notify_calls;
	const int schedules = g_sched_schedule_calls;
	const int next_data = g_sched_next_data_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(notify_calls, 1);
	T_EXPECT_EQ(schedules, 0);
	T_EXPECT_EQ(next_data, 0);
}

/* flush_sendbuf_head: the per-entry transport write state machine. */

/* Queue one already-encoded frame at the sendbuf head for the flush tests. */
static struct mux_frame *
si_queue_sendbuf(struct si_fixture *restrict fx, const size_t len)
{
	struct mux_frame *const f =
		mux_frame_get(&fx->ss.pool, fx->ss.max_payload);
	if (f == NULL) {
		/* No case currently forces pool_ctx.fail; return NULL cleanly so a
		 * future OOM-path case can T_CHECK it instead of dereferencing NULL. */
		return NULL;
	}
	f->pos = 0;
	f->len = len;
	mux_frame_list_push(&fx->ss.wire.sendbuf, f);
	return f;
}

/* A fully accepted write pops the head and hands it to the unacked ring. */
T_DECLARE_CASE(test_flush_head_sends_fully)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	(void)si_queue_sendbuf(&fx, 100);

	bool made_progress = false;
	const bool stop = flush_sendbuf_head(&fx.ss, &made_progress);

	const int sent = g_wire_send_calls;
	const int tracked = g_track_sent_calls;
	const bool sendbuf_empty = fx.ss.wire.sendbuf.head == NULL;
	si_teardown(&fx);

	T_EXPECT(!stop); /* head fully sent and popped */
	T_EXPECT(made_progress);
	T_EXPECT_EQ(sent, 1);
	T_EXPECT_EQ(tracked, 1);
	T_EXPECT(sendbuf_empty);
}

/* A short write advances pos and asks the caller to stop (re-present on retry). */
T_DECLARE_CASE(test_flush_head_partial_write)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_send_nsend = 40;
	struct mux_frame *const f = si_queue_sendbuf(&fx, 100);

	bool made_progress = false;
	const bool stop = flush_sendbuf_head(&fx.ss, &made_progress);

	const size_t f_pos = f->pos;
	const bool head_is_f = fx.ss.wire.sendbuf.head == f;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT(made_progress);
	T_EXPECT_EQ(f_pos, (size_t)40);
	T_EXPECT(head_is_f); /* still head */
}

/* A zero-byte (EAGAIN) write keeps the frame in flight and closes the staging
 * tail so no further small frames pack into the blocked entry. */
T_DECLARE_CASE(test_flush_head_blocked_closes_staging)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_send_nsend = 0;
	struct mux_frame *const f = si_queue_sendbuf(&fx, 100);
	fx.ss.wire.sendbuf_staging = true; /* f is the staging tail */

	bool made_progress = false;
	const bool stop = flush_sendbuf_head(&fx.ss, &made_progress);

	const bool staging_closed = !fx.ss.wire.sendbuf_staging;
	const bool head_is_f = fx.ss.wire.sendbuf.head == f;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT(!made_progress);
	T_EXPECT(staging_closed); /* staging closed */
	T_EXPECT(head_is_f);
}

/* A transport error on a resumable session suspends (preserving state). */
T_DECLARE_CASE(test_flush_head_error_suspends)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_send_ret = false;
	fx.ss.handshake.has_session_id = true;
	(void)si_queue_sendbuf(&fx, 100);

	bool made_progress = false;
	const bool stop = flush_sendbuf_head(&fx.ss, &made_progress);

	const enum session_state state = fx.ss.state;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT_EQ(state, SESSION_SUSPENDED);
}

/* A transport error with no resumable identity resets the session. */
T_DECLARE_CASE(test_flush_head_error_resets)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_send_ret = false;
	fx.ss.handshake.has_session_id = false;
	(void)si_queue_sendbuf(&fx, 100);

	bool made_progress = false;
	const bool stop = flush_sendbuf_head(&fx.ss, &made_progress);

	const enum session_state state = fx.ss.state;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT_EQ(state, SESSION_CLOSED);
}

/* update_send_timeout re-arms the send watchdog while egress remains pending. */
T_DECLARE_CASE(test_update_send_timeout_rearms_while_pending)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	ev_timer_init(&fx.ss.w_send_timeout, si_noop_timer_cb, 0.0, 5.0);
	fx.ss.w_send_timeout.data = &fx.ss;
	(void)si_queue_sendbuf(&fx, 100); /* keeps egress non-empty */

	update_send_timeout(&fx.ss, true); /* progress=true forces the re-arm */

	const bool active = ev_is_active(&fx.ss.w_send_timeout);
	ev_timer_stop(fx.ss.loop, &fx.ss.w_send_timeout);
	si_teardown(&fx);

	T_EXPECT(active);
}

/* TCP_USER_TIMEOUT zeroes w_send_timeout.repeat, on the
 * (correct, for every other case) assumption that the kernel mechanism
 * covers "peer stopped acking data we already wrote to the socket". A resume
 * retransmit stalled by a frame-pool OOM never reached the socket at all --
 * retransmit_off stays set with sendbuf still empty -- so the kernel has
 * nothing to time out on either. update_send_timeout must still arm a real
 * interval for this one case, or #25's watchdog fix is unreachable dead code
 * on every build where TCP_USER_TIMEOUT actually works (i.e. Linux). */
T_DECLARE_CASE(
	test_update_send_timeout_arms_despite_kernel_timeout_for_oom_stall)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	ev_timer_init(&fx.ss.w_send_timeout, si_noop_timer_cb, 0.0, 0.0);
	fx.ss.w_send_timeout.data = &fx.ss;
	fx.ss.conf.send_timeout = 5;
	fx.ss.wire.kernel_send_timeout = true; /* TCP_USER_TIMEOUT installed */
	/* retransmit_off != SIZE_MAX with an empty sendbuf is exactly the
	 * signature send_queue_retransmit's OOM path (send.c:147-150) leaves
	 * behind: nothing to copy from was ever reached. */
	fx.ss.unacked.retransmit_off = 0;

	update_send_timeout(&fx.ss, false);

	const bool active = ev_is_active(&fx.ss.w_send_timeout);
	const ev_tstamp repeat = fx.ss.w_send_timeout.repeat;
	ev_timer_stop(fx.ss.loop, &fx.ss.w_send_timeout);
	fx.ss.unacked.retransmit_off = SIZE_MAX;
	si_teardown(&fx);

	T_EXPECT(active);
	T_EXPECT(repeat > 0.0);
}

/* Once the retransmit copy actually reaches sendbuf, the kernel mechanism
 * covers it again like any other queued bytes -- oom_stalled in
 * update_send_timeout must require an empty sendbuf, not just
 * retransmit_off != SIZE_MAX, else it would keep forcing a redundant
 * userspace re-arm for the entire remainder of a normal replay. */
T_DECLARE_CASE(test_update_send_timeout_trusts_kernel_once_sendbuf_queued)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	ev_timer_init(&fx.ss.w_send_timeout, si_noop_timer_cb, 0.0, 0.0);
	fx.ss.w_send_timeout.data = &fx.ss;
	fx.ss.conf.send_timeout = 5;
	fx.ss.wire.kernel_send_timeout = true; /* TCP_USER_TIMEOUT installed */
	fx.ss.unacked.retransmit_off = 0;
	(void)si_queue_sendbuf(&fx, 16); /* replay copy already staged */

	update_send_timeout(&fx.ss, false);

	const bool active = ev_is_active(&fx.ss.w_send_timeout);
	const ev_tstamp repeat = fx.ss.w_send_timeout.repeat;
	fx.ss.unacked.retransmit_off = SIZE_MAX;
	si_teardown(&fx);

	T_EXPECT(!active);
	T_EXPECT(!(repeat > 0.0));
}

/* Regression (#36): after an OOM stall clears, update_send_timeout must restore
 * w_send_timeout.repeat to 0.0 -- handing the watchdog back to the kernel --
 * rather than leaving the raised interval in place, which would keep re-arming
 * a redundant userspace watchdog for the rest of the connection. */
T_DECLARE_CASE(test_update_send_timeout_restores_kernel_after_oom_stall_clears)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	/* Simulate the state the OOM-stall branch leaves behind: the kernel
	 * timeout is installed, but repeat was raised and the timer armed. */
	fx.ss.conf.send_timeout = 5;
	fx.ss.wire.kernel_send_timeout = true;
	ev_timer_init(&fx.ss.w_send_timeout, si_noop_timer_cb, 0.0, 5.0);
	fx.ss.w_send_timeout.data = &fx.ss;
	ev_timer_again(fx.ss.loop, &fx.ss.w_send_timeout);
	T_CHECK(ev_is_active(&fx.ss.w_send_timeout));
	/* Stall cleared: the retransmit copy finally reached the sendbuf, so
	 * oom_stalled is false (non-empty sendbuf) but there is still pending
	 * work -- exactly when the raised repeat must be handed back to the
	 * kernel. */
	fx.ss.unacked.retransmit_off = 0;
	(void)si_queue_sendbuf(&fx, 16);

	update_send_timeout(&fx.ss, false);

	const bool active = ev_is_active(&fx.ss.w_send_timeout);
	const ev_tstamp repeat = fx.ss.w_send_timeout.repeat;
	fx.ss.unacked.retransmit_off = SIZE_MAX;
	si_teardown(&fx);

	T_EXPECT(!active);
	T_EXPECT(repeat == 0.0);
}

/* send_stage_next's priority ladder tries the resume
 * retransmit first and, on a frame-pool OOM, returns SEND_STAGE_DONE
 * immediately -- before ever attempting oobbuf/sched_head, even if either
 * has independent work queued. mux_session_on_send's old tx_pending computation
 * (residue || cipher_residue, i.e. sendbuf non-empty or ciphertext blocked)
 * missed this entirely: sendbuf stays empty since no copy was ever produced
 * to push onto it, so tx_pending would incorrectly end up false with
 * retransmit_off still != SIZE_MAX -- silently dropping EV_WRITE and
 * tripping mux_session_update_watcher's invariant ASSERT the next time it runs
 * with sched_head/oobbuf non-empty. */
T_DECLARE_CASE(test_session_on_send_sets_tx_pending_for_oom_stalled_retransmit)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	/* A real unacked ring with one entry so replay is genuinely pending; the
	 * retransmit *copy* then OOMs (pool_ctx.fail), stalling the replay with
	 * retransmit_off still armed and sendbuf empty. */
	struct mux_frame *const entry = si_alloc_frame(&fx, 0);
	T_CHECK(entry != NULL);
	entry->unacked_count = 1;
	struct mux_frame_ring *const ring =
		malloc(sizeof(struct mux_frame_ring) +
		       MUX_FRAME_RING_MIN * sizeof(struct mux_frame *));
	T_CHECK(ring != NULL);
	*ring = (struct mux_frame_ring){
		.capacity = MUX_FRAME_RING_MIN,
		.count = 1,
	};
	ring->entries[0] = entry;
	fx.ss.unacked.ring = ring;
	fx.ss.unacked.retransmit_off = 0;
	fx.pool_ctx.fail = true; /* the retransmit copy alloc fails */

	mux_session_on_send(&fx.ss);

	const bool sendbuf_empty = fx.ss.wire.sendbuf.head == NULL;
	const bool replay_armed = fx.ss.unacked.retransmit_off != SIZE_MAX;
	const bool tx_pending = fx.ss.wire.tx_pending;

	fx.ss.unacked.retransmit_off = SIZE_MAX;
	fx.ss.unacked.ring = NULL;
	mux_frame_put(&fx.ss.pool, entry);
	free(ring);
	si_teardown(&fx);

	T_EXPECT(sendbuf_empty);
	T_EXPECT(replay_armed);
	T_EXPECT(tx_pending);
}

/* dispatch_frame's post-hello early return (recv.c) can
 * strand already-buffered frames in wire.recvbuf when tx_pending was true
 * only because of non-sendable work that resolves without ever writing a
 * byte to the peer -- no peer ACK is then coming to trigger the EV_READ
 * that would otherwise re-drive dispatch. mux_session_on_send must redispatch
 * directly once tx_pending has genuinely settled to false. */
T_DECLARE_CASE(test_send_cb_redispatches_once_tx_pending_settles_false)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.unacked.retransmit_off = SIZE_MAX; /* no replay in progress */
	fx.ss.wire.tx_pending = true;
	/* sendbuf/oobbuf/sched_head all empty, mux_sched_next_data mocked to
	 * never produce: send_pump finds nothing sendable, tx_pending settles
	 * to false with no bytes ever written. */

	mux_session_on_send(&fx.ss);

	const bool tx_pending = fx.ss.wire.tx_pending;
	const int dispatch_calls = g_dispatch_pending_calls;
	si_teardown(&fx);

	T_EXPECT(!tx_pending);
	T_EXPECT_EQ(dispatch_calls, 1);
}

/* Transport-blocked residue keeps tx_pending true; redispatching stranded
 * frames now (before the blocked write even clears) would be premature. */
T_DECLARE_CASE(test_send_cb_no_redispatch_while_tx_pending_true)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.unacked.retransmit_off = SIZE_MAX;
	fx.ss.wire.tx_pending = true;
	g_wire_send_nsend = 0; /* EAGAIN: leaves the staged frame as residue */
	struct mux_frame *const f = si_queue_sendbuf(&fx, 16);
	T_CHECK(f != NULL);

	mux_session_on_send(&fx.ss);

	const bool tx_pending = fx.ss.wire.tx_pending;
	const int dispatch_calls = g_dispatch_pending_calls;
	si_teardown(&fx);

	T_EXPECT(tx_pending);
	T_EXPECT_EQ(dispatch_calls, 0);
}

/* Redispatch is gated on SESSION_ESTABLISHED, mirroring dispatch_frame's own
 * post-hello check: mid-handshake there is nothing to have stranded yet. */
T_DECLARE_CASE(test_send_cb_no_redispatch_outside_established)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_HANDSHAKE;
	fx.ss.unacked.retransmit_off = SIZE_MAX;
	fx.ss.wire.tx_pending = true;

	mux_session_on_send(&fx.ss);

	const int dispatch_calls = g_dispatch_pending_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(dispatch_calls, 0);
}

/* flush_sendbuf_head returns "no work" when the sendbuf is empty. */
T_DECLARE_CASE(test_flush_head_empty_sendbuf)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	bool made_progress = false;
	const bool has_work = flush_sendbuf_head(&fx.ss, &made_progress);
	si_teardown(&fx);
	T_EXPECT(!has_work);
	T_EXPECT(!made_progress);
}

/* A transport error during the client resume handshake suspends rather than
 * resets (covers the HANDSHAKE && !accepted arm). */
T_DECLARE_CASE(test_flush_head_error_suspends_in_handshake)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_wire_send_ret = false;
	fx.ss.state = SESSION_HANDSHAKE;
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;
	(void)si_queue_sendbuf(&fx, 100);

	bool made_progress = false;
	const bool stop = flush_sendbuf_head(&fx.ss, &made_progress);
	const enum session_state state = fx.ss.state;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT_EQ(state, SESSION_SUSPENDED);
}

/* send_head_must_flush reports true for a partially-written head. */
T_DECLARE_CASE(test_send_head_must_flush_partial_head)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	struct mux_frame *const f = si_queue_sendbuf(&fx, 100);
	f->pos = 10; /* partially written */
	const bool must_flush = send_head_must_flush(&fx.ss);
	si_teardown(&fx);
	T_EXPECT(must_flush);
}

/* send_handle_rx_closed on a non-resumable ESTABLISHED session discards buffers
 * and transitions to CLOSING.  mux_wire_discard_buffers frees the live replay copy,
 * so the branch must also mux_unacked_free_all to clear the dangling
 * retransmit_copy (and retransmit_off) -- else a recycled frame could
 * false-match it, exactly as mux_session_initiate_shutdown pairs the two. */
T_DECLARE_CASE(test_send_handle_rx_closed_terminal)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.wire.rx_open = false;
	fx.ss.handshake.has_session_id = false;
#if WITH_TLS
	fx.ss.wire.tlsconn = NULL;
#endif
	/* Arm a replay copy on the sendbuf (freed by mux_wire_discard_buffers). */
	const uint_least16_t ids[1] = { 7 };
	const uint_least8_t flags[1] = { MUX_FLAG_PUSH };
	struct mux_frame *const copy = si_queue_coalesced(&fx, ids, flags, 1);
	T_CHECK(copy != NULL);
	fx.ss.unacked.retransmit_copy = copy;
	fx.ss.unacked.retransmit_off = 0;

	const bool stop = send_handle_rx_closed(&fx.ss);
	const bool tx_pending = fx.ss.wire.tx_pending;
	const bool copy_cleared = fx.ss.unacked.retransmit_copy == NULL;
	const size_t retransmit_off = fx.ss.unacked.retransmit_off;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT(tx_pending);
	T_EXPECT(copy_cleared);
	T_EXPECT_EQ(retransmit_off, SIZE_MAX);
}

/* Resume replay must skip a partially-acked coalesced head's already-acked
 * leading sub-frames: send_queue_retransmit copies from partial_offset, so the
 * peer never receives delivered data twice. */
T_DECLARE_CASE(test_retransmit_skips_acked_head_prefix)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();

	enum { P1 = 4, P2 = 8 };
	const size_t sub1 = MUX_FRAME_HEADER_SIZE + P1;
	const size_t sub2 = MUX_FRAME_HEADER_SIZE + P2;
	struct mux_frame *const entry =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_CHECK(entry != NULL);
	mux_write_header(
		entry->data,
		&(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
				      .flags = MUX_FLAG_PUSH,
				      .length = P1,
				      .stream_id = 11 });
	mux_write_header(
		entry->data + sub1,
		&(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
				      .flags = MUX_FLAG_PUSH,
				      .length = P2,
				      .stream_id = 22 });
	for (size_t i = 0; i < P1; i++) {
		entry->data[MUX_FRAME_HEADER_SIZE + i] =
			(unsigned char)(0xA0 + i);
	}
	for (size_t i = 0; i < P2; i++) {
		entry->data[sub1 + MUX_FRAME_HEADER_SIZE + i] =
			(unsigned char)(0xB0 + i);
	}
	entry->len = sub1 + sub2;
	entry->unacked_count =
		1; /* sub-frame 1 already acked, only #2 unacked */

	struct mux_frame_ring *const ring =
		malloc(sizeof(struct mux_frame_ring) +
		       MUX_FRAME_RING_MIN * sizeof(struct mux_frame *));
	T_CHECK(ring != NULL);
	*ring = (struct mux_frame_ring){
		.capacity = MUX_FRAME_RING_MIN,
		.count = 1,
	};
	ring->entries[0] = entry;
	fx.ss.unacked.ring = ring;
	fx.ss.unacked.partial_offset = (uint_least32_t)sub1;
	fx.ss.unacked.retransmit_off = 0;

	bool retransmitting = false;
	T_CHECK(send_queue_retransmit(&fx.ss, &retransmitting));

	struct mux_frame *const copy = fx.ss.wire.sendbuf.head;
	T_CHECK(copy != NULL);
	/* Only the unacked second sub-frame is replayed, byte-for-byte. */
	const size_t copy_len = copy->len;
	bool replay_verbatim = false;
	if (copy_len == sub2) {
		replay_verbatim =
			memcmp(copy->data, entry->data + sub1, sub2) == 0;
	}

	fx.ss.unacked.retransmit_copy = NULL;
	fx.ss.unacked.ring = NULL;
	mux_frame_put(&fx.ss.pool, entry);
	free(ring);
	si_teardown(&fx); /* clears sendbuf, freeing the replay copy */

	T_EXPECT_EQ(copy_len, sub2);
	T_EXPECT(replay_verbatim);
}

/* A real-stream control frame (e.g. the RST recv.c sends for
 * a late frame on a closed stream) must not jump ahead of not-yet-
 * retransmitted ring entries while a resume replay is in progress, or a
 * peer's cumulative ACK could trim an entry that was never actually
 * transmitted. mux_session_send_ctrl must defer such a frame behind oobbuf
 * instead of pushing it straight onto the sendbuf head. */
T_DECLARE_CASE(test_send_ctrl_defers_ring_tracked_frame_during_replay)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();

	/* Two-entry unacked ring; only the first has been retransmitted so far
	 * (retransmit_off=1), matching mid-replay progress with more to go. */
	struct mux_frame *const e0 =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	struct mux_frame *const e1 =
		mux_frame_get(&fx.ss.pool, fx.ss.max_payload);
	T_CHECK(e0 != NULL && e1 != NULL);
	mux_write_header(
		e0->data, &(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
						.flags = MUX_FLAG_PUSH,
						.stream_id = 11 });
	e0->len = MUX_FRAME_HEADER_SIZE;
	e0->unacked_count = 1;
	mux_write_header(
		e1->data, &(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
						.flags = MUX_FLAG_PUSH,
						.stream_id = 11 });
	e1->len = MUX_FRAME_HEADER_SIZE;
	e1->unacked_count = 1;

	struct mux_frame_ring *const ring =
		malloc(sizeof(struct mux_frame_ring) +
		       MUX_FRAME_RING_MIN * sizeof(struct mux_frame *));
	T_CHECK(ring != NULL);
	*ring = (struct mux_frame_ring){
		.capacity = MUX_FRAME_RING_MIN,
		.count = 2,
	};
	ring->entries[0] = e0;
	ring->entries[1] = e1;
	fx.ss.unacked.ring = ring;
	fx.ss.unacked.retransmit_off = 1; /* e0 retransmitted, e1 pending */

	/* A late-frame RST for a real (unrelated) stream must not jump ahead
	 * of e1, still awaiting replay. */
	T_CHECK(mux_session_send_ctrl(
		&fx.ss, 33, MUX_FLAG_RST, MUX_STATUS_PROTOCOL_ERROR));

	/* Capture the post-defer state before the second send can perturb it. */
	const bool sendbuf_empty_after_rst = fx.ss.wire.sendbuf.head == NULL;
	const bool oob_has_head = fx.ss.wire.oobbuf.head != NULL;
	struct mux_header oobh = { 0 };
	if (oob_has_head) {
		mux_read_header(fx.ss.wire.oobbuf.head->data, &oobh);
	}

	/* A STREAMID_CTRL frame (e.g. a session ACK) never enters the unacked
	 * ring, so it is unaffected and still flows immediately. */
	T_CHECK(mux_session_send_ctrl(&fx.ss, STREAMID_CTRL, MUX_FLAG_ACK, 0));
	const bool sendbuf_has_head_after_ack = fx.ss.wire.sendbuf.head != NULL;

	fx.ss.unacked.ring = NULL;
	mux_frame_put(&fx.ss.pool, e0);
	mux_frame_put(&fx.ss.pool, e1);
	free(ring);
	si_teardown(&fx); /* clears sendbuf and oobbuf */

	T_EXPECT(sendbuf_empty_after_rst);
	T_EXPECT(oob_has_head);
	T_EXPECT_EQ((int)oobh.stream_id, 33);
	T_EXPECT_EQ((int)oobh.flags, MUX_FLAG_RST);
	T_EXPECT(sendbuf_has_head_after_ack);
}

/* Once replay finishes (retransmit_off == SIZE_MAX), mux_session_send_ctrl goes
 * straight to the sendbuf head again, matching pre-replay behavior. */
T_DECLARE_CASE(test_send_ctrl_immediate_when_not_replaying)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();

	T_CHECK(fx.ss.unacked.retransmit_off == SIZE_MAX);
	T_CHECK(mux_session_send_ctrl(&fx.ss, 5, MUX_FLAG_RST, 0));

	const bool sendbuf_has_head = fx.ss.wire.sendbuf.head != NULL;
	const bool oob_empty = fx.ss.wire.oobbuf.head == NULL;
	si_teardown(&fx);

	T_EXPECT(sendbuf_has_head);
	T_EXPECT(oob_empty);
}

/* send_stage_next step 3 (session-window stall gate): with unacked.stalled set,
 * new payload is held back -- mux_sched_next_data must NOT be called -- while
 * pending per-stream ACK/FIN still drain via mux_sched_flush_ctrl so the peer can
 * reopen its window. Data is primed (g_sched_next_data_frames > 0) to prove the
 * gate, not an empty producer, is what suppresses it. */
T_DECLARE_CASE(test_send_stage_next_stalled_flushes_ctrl_not_data)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.unacked.stalled = true; /* session window exhausted */
	g_sched_next_data_frames = 2; /* data ready, but gated by the stall */

	mux_session_on_send(&fx.ss);

	const int flush_ctrl = g_sched_flush_ctrl_calls;
	const int next_data = g_sched_next_data_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(flush_ctrl, 1); /* pending control still drained */
	T_EXPECT_EQ(next_data, 0); /* stalled: no new data staged */
}

/* send_stage_next step 2 (OOB drain): a queued OOB control (keepalive/PONG) is
 * handed to mux_wire_sendbuf_push ahead of the DRR data producer AND bypasses the
 * session-window stall. With the session stalled the data step (step 4, below
 * the stall gate) is never reached, yet the OOB frame is still staged and
 * flushed: OOB sits above both the stall gate and data in the priority ladder. */
T_DECLARE_CASE(test_send_stage_next_oob_drains_before_data_despite_stall)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.unacked.stalled = true; /* payload held by the session window */
	g_sched_next_data_frames = 2; /* data ready, but ranked below OOB */
	T_CHECK(mux_session_send_oob(&fx.ss, MUX_CTRL_PONG, NULL, 0));

	mux_session_on_send(&fx.ss);

	const int pushed = g_sendbuf_push_calls;
	const int next_data = g_sched_next_data_calls;
	const bool oob_drained = fx.ss.wire.oobbuf.head == NULL;
	si_teardown(&fx);

	T_EXPECT_EQ(pushed, 1); /* OOB reached mux_wire_sendbuf_push ... */
	T_EXPECT_EQ(
		next_data, 0); /* ... ahead of the (unreached) data producer */
	T_EXPECT(oob_drained); /* OOB popped from oobbuf and sent */
}

/* mux_session_flush_resp: outside SESSION_ESTABLISHED it is a no-op -- neither the
 * scheduler nor the inline pump runs (the recv->send response seam only fires
 * once the session is up). */
T_DECLARE_CASE(test_session_flush_resp_noop_before_established)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_HANDSHAKE;
	fx.ss.wire.tx_pending = true;

	mux_session_flush_resp(&fx.ss);

	const int schedules = g_sched_schedule_calls;
	const int next_data = g_sched_next_data_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(schedules, 0);
	T_EXPECT_EQ(next_data, 0);
}

/* mux_session_flush_resp: with nothing pending (tx_pending == false) it returns
 * before scheduling -- no response is owed, so the write path stays untouched. */
T_DECLARE_CASE(test_session_flush_resp_noop_without_tx_pending)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.wire.tx_pending = false;

	mux_session_flush_resp(&fx.ss);

	const int schedules = g_sched_schedule_calls;
	const int next_data = g_sched_next_data_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(schedules, 0);
	T_EXPECT_EQ(next_data, 0);
}

/* mux_session_flush_resp: ESTABLISHED with tx_pending and a clear pipe (empty
 * sendbuf, no TLS poll) pumps inline -- mux_session_on_send runs and reaches the
 * data scheduler this call rather than deferring to EV_WRITE. */
T_DECLARE_CASE(test_session_flush_resp_pumps_inline_when_pipe_clear)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.wire.tx_pending = true;
	/* sendbuf.head == NULL and tls_want == 0: the pipe is clear. */

	mux_session_flush_resp(&fx.ss);

	const int next_data = g_sched_next_data_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(next_data, 1); /* inline pump reached mux_sched_next_data */
}

/* mux_session_flush_resp: an occupied sendbuf defers to the armed EV_WRITE drain --
 * mux_sched_schedule still runs but the inline pump does not (no mux_sched_next_data),
 * so a half-written record is never re-entered mid-flight. */
T_DECLARE_CASE(test_session_flush_resp_defers_when_pipe_occupied)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.wire.tx_pending = true;
	(void)si_queue_sendbuf(&fx, 100); /* pipe occupied */

	mux_session_flush_resp(&fx.ss);

	const int schedules = g_sched_schedule_calls;
	const int next_data = g_sched_next_data_calls;
	si_teardown(&fx);

	T_EXPECT_EQ(schedules, 1); /* scheduler ran ... */
	T_EXPECT_EQ(next_data, 0); /* ... but no inline pump */
}

/* send_handle_rx_closed resumable arm: a plain TCP FIN (rx_open == false) on an
 * ESTABLISHED session that carries a session_id and has no TLS connection must
 * SUSPEND -- resume state is preserved, not torn down. */
T_DECLARE_CASE(test_send_handle_rx_closed_suspends_resumable)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.wire.rx_open = false;
	fx.ss.handshake.has_session_id = true;
#if WITH_TLS
	fx.ss.wire.tlsconn = NULL; /* plain TCP FIN, not a TLS close */
#endif

	const bool stop = send_handle_rx_closed(&fx.ss);

	const int suspends = g_suspend_calls;
	const enum session_state state = fx.ss.state;
	const bool has_session_id = fx.ss.handshake.has_session_id;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT_EQ(suspends, 1);
	T_EXPECT_EQ(state, SESSION_SUSPENDED);
	T_EXPECT(has_session_id); /* resume state kept intact */
}

#if WITH_TLS
/* send_handle_rx_closed with a live TLS connection: a close_notify is terminal
 * even when a session_id is cached -- the session goes CLOSING (not SUSPENDED)
 * and the cached session_id is discarded so the next reconnect starts fresh
 * rather than attempting an invalid resume. */
T_DECLARE_CASE(test_send_handle_rx_closed_tls_close_is_terminal)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.ss.state = SESSION_ESTABLISHED;
	fx.ss.wire.rx_open = false;
	fx.ss.accepted = false; /* outbound: clears the cached session_id */
	fx.ss.handshake.has_session_id = true;
	fx.ss.wire.tlsconn = (struct tls_connection *)&fx; /* live TLS */

	const bool stop = send_handle_rx_closed(&fx.ss);

	const int suspends = g_suspend_calls;
	const enum session_state state = fx.ss.state;
	const bool has_session_id = fx.ss.handshake.has_session_id;
	const bool tx_pending = fx.ss.wire.tx_pending;
	fx.ss.wire.tlsconn = NULL;
	si_teardown(&fx);

	T_EXPECT(stop);
	T_EXPECT_EQ(suspends, 0); /* terminal, not suspended */
	T_EXPECT_EQ(state, SESSION_CLOSING);
	T_EXPECT(!has_session_id); /* cached session_id discarded */
	T_EXPECT(tx_pending);
}
#endif /* WITH_TLS */

/* mux_session_discard_stream_frames keeps a partially-sent frame (pos != 0): once
 * bytes of an entry are on the wire it must finish to preserve framing sync, so
 * the pos-guard leaves it in place while a fresh (pos == 0) stream frame of the
 * same stream is discarded normally. */
T_DECLARE_CASE(test_discard_stream_frames_keeps_partially_sent)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	si_queue_ctrl(&fx, 5, MUX_FLAG_PUSH); /* partially sent: kept */
	struct mux_frame *const partial = fx.ss.wire.sendbuf.tail;
	partial->pos = MUX_FRAME_HEADER_SIZE; /* bytes already on the wire */
	si_queue_ctrl(
		&fx, 5, MUX_FLAG_PUSH); /* fresh stream-5 data: discarded */

	mux_session_discard_stream_frames(&fx.ss, 5);

	const size_t count = fx.ss.wire.sendbuf.count;
	const bool head_is_partial = fx.ss.wire.sendbuf.head == partial;
	const size_t partial_pos = partial->pos;
	si_teardown(&fx);

	T_EXPECT_EQ(count, (size_t)1); /* only the partial survives */
	T_EXPECT(head_is_partial);
	T_EXPECT_EQ(partial_pos, (size_t)MUX_FRAME_HEADER_SIZE);
}

#if WITH_TLS
/* mux_session_discard_stream_frames keeps the in-flight sendbuf head while a TLS
 * write is blocked (send_blocked && frame == head && tlsconn != NULL):
 * SSL_write's contract requires the identical bytes be re-presented, so the
 * head is left intact even though it belongs to the reset stream, while a
 * following stream-5 entry that is not the in-flight head is discarded. */
T_DECLARE_CASE(test_discard_stream_frames_keeps_blocked_tls_head)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	si_queue_ctrl(&fx, 5, MUX_FLAG_PUSH); /* in-flight TLS head: kept */
	struct mux_frame *const head = fx.ss.wire.sendbuf.head;
	si_queue_ctrl(&fx, 5, MUX_FLAG_PUSH); /* not the head: discarded */
	fx.ss.wire.send_blocked = true;
	fx.ss.wire.tlsconn = (struct tls_connection *)&fx;

	mux_session_discard_stream_frames(&fx.ss, 5);

	const size_t count = fx.ss.wire.sendbuf.count;
	const bool head_kept = fx.ss.wire.sendbuf.head == head;
	fx.ss.wire.tlsconn = NULL;
	si_teardown(&fx);

	T_EXPECT_EQ(count, (size_t)1); /* only the blocked head survives */
	T_EXPECT(head_kept);
}
#endif /* WITH_TLS */

static const struct testing_suite suite[] = {
	T_CASE(test_send_cb_defers_lp_drain_before_established),
	T_CASE(test_send_cb_drains_lp_when_established),
	T_CASE(test_session_flush_inline_when_pipe_clear),
	T_CASE(test_send_cb_resumes_lifecycle_drain_unconditionally),
	T_CASE(test_session_on_send_wire_flush_blocked_keeps_tx_pending),
	T_CASE(test_session_on_send_wire_flush_error_suspends_resumable),
	T_CASE(test_session_on_send_wire_flush_error_resets_non_resumable),
	T_CASE(test_send_pump_stages_and_flushes_multiple_frames),
	T_CASE(test_send_pump_coalesces_staged_frames_into_one_record),
	T_CASE(test_send_ctrl_encodes_and_clamps),
	T_CASE(test_send_ctrl_oom),
	T_CASE(test_send_oob_copies_payload),
	T_CASE(test_send_oob_zero_fills),
	T_CASE(test_send_oob_oom),
	T_CASE(test_send_push_syn_on_init),
	T_CASE(test_send_push_ack_fin),
	T_CASE(test_emit_ack_sends_unreported),
	T_CASE(test_emit_ack_clamps_unreported),
	T_CASE(test_discard_stream_frames_selective),
	T_CASE(test_discard_stream_frames_compacts_coalesced_entry),
	T_CASE(test_discard_stream_frames_keeps_all_belong_retransmit_copy),
	T_CASE(test_discard_stream_frames_walks_oobbuf),
	T_CASE(test_send_stage_next_drains_replay_when_ring_null),
	T_CASE(test_discard_stream_frames_keeps_retransmit_copy_verbatim),
	T_CASE(test_notify_write_noop_before_established),
	T_CASE(test_session_flush_defers_before_established),
	T_CASE(test_flush_head_sends_fully),
	T_CASE(test_flush_head_partial_write),
	T_CASE(test_flush_head_blocked_closes_staging),
	T_CASE(test_flush_head_error_suspends),
	T_CASE(test_flush_head_error_resets),
	T_CASE(test_update_send_timeout_rearms_while_pending),
	T_CASE(test_update_send_timeout_arms_despite_kernel_timeout_for_oom_stall),
	T_CASE(test_update_send_timeout_trusts_kernel_once_sendbuf_queued),
	T_CASE(test_update_send_timeout_restores_kernel_after_oom_stall_clears),
	T_CASE(test_session_on_send_sets_tx_pending_for_oom_stalled_retransmit),
	T_CASE(test_send_cb_redispatches_once_tx_pending_settles_false),
	T_CASE(test_send_cb_no_redispatch_while_tx_pending_true),
	T_CASE(test_send_cb_no_redispatch_outside_established),
	T_CASE(test_flush_head_empty_sendbuf),
	T_CASE(test_flush_head_error_suspends_in_handshake),
	T_CASE(test_send_head_must_flush_partial_head),
	T_CASE(test_send_handle_rx_closed_terminal),
	T_CASE(test_retransmit_skips_acked_head_prefix),
	T_CASE(test_send_ctrl_defers_ring_tracked_frame_during_replay),
	T_CASE(test_send_ctrl_immediate_when_not_replaying),
	T_CASE(test_send_push_does_not_read_frame_after_push),
	T_CASE(test_send_stage_next_stalled_flushes_ctrl_not_data),
	T_CASE(test_send_stage_next_oob_drains_before_data_despite_stall),
	T_CASE(test_session_flush_resp_noop_before_established),
	T_CASE(test_session_flush_resp_noop_without_tx_pending),
	T_CASE(test_session_flush_resp_pumps_inline_when_pipe_clear),
	T_CASE(test_session_flush_resp_defers_when_pipe_occupied),
	T_CASE(test_send_handle_rx_closed_suspends_resumable),
#if WITH_TLS
	T_CASE(test_send_handle_rx_closed_tls_close_is_terminal),
#endif
	T_CASE(test_discard_stream_frames_keeps_partially_sent),
#if WITH_TLS
	T_CASE(test_discard_stream_frames_keeps_blocked_tls_head),
#endif
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* Surface the VERYVERBOSE frame-out diagnostics in the producers. */
	slog_level_ = LOG_LEVEL_VERYVERBOSE;

	return testing_main(argc, argv, suite);
}
