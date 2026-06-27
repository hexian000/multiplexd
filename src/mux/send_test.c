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
static uint_fast32_t g_grant_inc;
static int g_mark_fin_sent_calls;
static int g_delay_remove_calls;
static uint_fast32_t g_unacked_delta;
static int g_ack_emitted_calls;
static uint_fast32_t g_ack_emitted_last;
static bool g_wire_send_ret;
static size_t g_wire_send_nsend; /* bytes accepted; SIZE_MAX = all requested */
static int g_wire_send_calls;
static int g_track_sent_calls;
static int g_suspend_calls;
static int g_reset_calls;

static void spies_reset(void)
{
	g_sched_schedule_calls = 0;
	g_sched_drain_lp_calls = 0;
	g_sched_flush_ctrl_calls = 0;
	g_sched_next_data_calls = 0;
	g_notify_calls = 0;
	g_sendbuf_push_calls = 0;
	g_grant_inc = 0;
	g_mark_fin_sent_calls = 0;
	g_delay_remove_calls = 0;
	g_unacked_delta = 0;
	g_ack_emitted_calls = 0;
	g_ack_emitted_last = 0;
	g_wire_send_ret = true;
	g_wire_send_nsend = SIZE_MAX;
	g_wire_send_calls = 0;
	g_track_sent_calls = 0;
	g_suspend_calls = 0;
	g_reset_calls = 0;
}

void sched_schedule(struct mux_session *ss)
{
	(void)ss;
	g_sched_schedule_calls++;
}

void sched_drain_lp(struct mux_session *restrict ss)
{
	(void)ss;
	g_sched_drain_lp_calls++;
}

void sched_flush_ctrl(struct mux_session *restrict ss)
{
	(void)ss;
	g_sched_flush_ctrl_calls++;
}

bool sched_next_data(struct mux_session *restrict ss)
{
	(void)ss;
	g_sched_next_data_calls++;
	return false; /* never produce a frame: keep send_pump bounded */
}

/* Benign no-op stubs for the remaining session.c collaborators */

void dispatch_frame(struct mux_session *ss)
{
	(void)ss;
}

void estimator_add_acked(struct mux_session *restrict ss, uint_least64_t bytes)
{
	(void)ss;
	(void)bytes;
}

void estimator_calculate(struct mux_session *restrict ss, int_fast64_t sent_ns)
{
	(void)ss;
	(void)sent_ns;
}

void estimator_init(struct mux_session *restrict ss, size_t bdp)
{
	(void)ss;
	(void)bdp;
}

size_t estimator_rx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return 0;
}

size_t estimator_tx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return 0;
}

bool handshake_enqueue_hello(
	struct mux_session *ss, int msgid, bool include_resume_seq)
{
	(void)ss;
	(void)msgid;
	(void)include_resume_seq;
	return true;
}

bool sched_add_stream(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
	return true;
}

uint_least16_t sched_alloc_stream_id(struct mux_session *ss)
{
	(void)ss;
	return STREAMID_CTRL;
}

void sched_coalesce_arm(struct mux_session *ss)
{
	(void)ss;
}

void sched_delay_remove(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
	g_delay_remove_calls++;
}

void sched_free_streams(struct mux_session *ss)
{
	(void)ss;
}

void sched_init(struct mux_session *restrict ss)
{
	(void)ss;
}

void sched_wake(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
}

void stream_check_ack(struct mux_stream *restrict s)
{
	(void)s;
}

void stream_free(struct mux_stream *s)
{
	(void)s;
}

uint_fast32_t stream_grant_inc(const struct mux_stream *s)
{
	(void)s;
	return g_grant_inc;
}

void stream_mark_fin_sent(struct mux_stream *s)
{
	(void)s;
	g_mark_fin_sent_calls++;
}

struct mux_stream *
stream_new(struct mux_session *restrict ss, uint_fast16_t id, bool active_open)
{
	(void)ss;
	(void)id;
	(void)active_open;
	return NULL;
}

void wire_conn_free(struct mux_session *ss)
{
	(void)ss;
}

void wire_discard_buffers(struct mux_session *ss)
{
	(void)ss;
}

bool wire_has_pending(const struct mux_session *ss)
{
	(void)ss;
	return false;
}

bool wire_recv(struct mux_session *ss, unsigned char *restrict buf, size_t *len)
{
	(void)ss;
	(void)buf;
	(void)len;
	return false;
}

bool wire_send(struct mux_session *ss, const unsigned char *buf, size_t *len)
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

void wire_sendbuf_push(struct mux_session *ss, struct mux_frame *frame)
{
	/* Functional enough for the producer tests: take ownership by appending
	 * to the real sendbuf list so the written header can be inspected and the
	 * frame freed at teardown. */
	g_sendbuf_push_calls++;
	mux_frame_list_push(&ss->wire.sendbuf, frame);
}

enum wire_flush_result wire_flush(struct mux_session *ss)
{
	(void)ss;
	return WIRE_FLUSH_DONE;
}

enum wire_shutdown_state wire_shutdown(struct mux_session *ss)
{
	(void)ss;
	return WIRE_SHUTDOWN_DONE;
}

bool wire_wait_eof(struct mux_session *ss)
{
	(void)ss;
	return false;
}

#if WITH_TLS
bool wire_tls_start(struct mux_session *ss)
{
	(void)ss;
	return true;
}

void wire_adopt_tlsconn(
	struct mux_session *restrict ss, struct tls_connection *restrict conn)
{
	(void)ss;
	(void)conn;
}

void wire_tls_log_status(struct mux_session *ss)
{
	(void)ss;
}
#endif /* WITH_TLS */

bool ringbuf_reserve(struct ringbuf **restrict rbp, size_t need, bool can_grow)
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
	.tls_readahead = 128 * 1024,
};

/* Session-core collaborators: send.c calls back into these for watcher/state
 * updates; the egress-flush assertions below depend only on the sched spies, so
 * these are benign no-ops. */
void session_update_watcher(struct mux_session *restrict ss)
{
	(void)ss;
}

void session_set_state(struct mux_session *ss, enum session_state newstate)
{
	ss->state = newstate;
}

void session_suspend(struct mux_session *ss)
{
	g_suspend_calls++;
	ss->state = SESSION_SUSPENDED;
}

void session_reset(struct mux_session *ss)
{
	g_reset_calls++;
	ss->state = SESSION_CLOSED;
}

void session_notify(struct mux_session *restrict ss)
{
	(void)ss;
	g_notify_calls++;
}

void session_log_frame_header(
	struct mux_session *restrict ss, const char *restrict what,
	const unsigned char *restrict raw,
	const struct mux_header *restrict hdr)
{
	(void)ss;
	(void)what;
	(void)raw;
	(void)hdr;
}

/* unacked collaborators referenced by the send pipeline (never reached in these
 * cases: no frame is produced, so the retransmit/track paths stay idle). */
void unacked_track_sent(struct mux_session *ss, struct mux_frame *frame)
{
	/* The real implementation takes ownership; mirror that so the flush
	 * tests, which fully send a frame, do not leak it. */
	g_track_sent_calls++;
	mux_frame_put(&ss->pool, frame);
}

uint_fast32_t unacked_ack_delta(const struct mux_session *ss)
{
	(void)ss;
	return g_unacked_delta;
}

void unacked_ack_emitted(struct mux_session *ss, uint_fast32_t emit)
{
	(void)ss;
	g_ack_emitted_calls++;
	g_ack_emitted_last = emit;
}

/* Pull in the unit under test after the collaborator definitions so its
 * external references bind to the spies above.  session_on_send / session_flush /
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

/* session_on_send: the low-priority lifecycle drain is gated on ESTABLISHED. */

/* Before ESTABLISHED, sched_drain_lp is a no-op, so session_on_send must leave
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

	session_on_send(&fx.ss);

	T_EXPECT(fx.ss.sched.lp_pending); /* not consumed */
	T_EXPECT_EQ(g_sched_drain_lp_calls, 0);
	/* HANDSHAKE breaks out of send_pump before the data scheduler. */
	T_EXPECT_EQ(g_sched_next_data_calls, 0);

	si_teardown(&fx);
}

/* Once ESTABLISHED, session_on_send consumes lp_pending and runs the drain at entry,
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

	session_on_send(&fx.ss);

	T_EXPECT(!fx.ss.sched.lp_pending); /* consumed */
	T_EXPECT_EQ(g_sched_drain_lp_calls, 1);
	T_EXPECT(!fx.ss.wire.send_blocked); /* drained: no residue */

	si_teardown(&fx);
}

/* session_flush: the low-load fast path flushes inline when the pipe is clear. */

/* sendbuf empty (transport idle) -> flush straight through session_on_send instead of
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

	session_flush(&fx.ss);

	/* Inline path ran session_on_send -> send_pump reached the data scheduler. */
	T_EXPECT_EQ(g_sched_next_data_calls, 1);
	T_EXPECT(
		!fx.ss.wire.tx_pending); /* session_on_send cleared it (no residue) */

	si_teardown(&fx);
}

/* session_on_send: the lifecycle drain is resumed unconditionally (sched_schedule
 * self-guards on an occupied sendbuf), even with an empty lp queue. */

/* Regression for the centralised guard: session_on_send must call sched_schedule on
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

	session_on_send(&fx.ss);

	T_EXPECT_EQ(g_sched_schedule_calls, 1);
	T_EXPECT(!fx.ss.wire.send_blocked); /* drained: no residue */
	T_EXPECT(!fx.ss.wire.tx_pending);

	si_teardown(&fx);
}

/* Frame producers: session_send_ctrl/_oob/_push, session_emit_ack, and
 * session_discard_stream_frames; wire_sendbuf_push spy captures produced
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
	const struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = flags,
		.length = 0,
		.stream_id = stream_id,
	};
	mux_write_header(f->data, &h);
	mux_frame_list_push(&fx->ss.wire.sendbuf, f);
}

/* session_send_ctrl encodes the header, clamps Extra to 16 bits, queues the
 * frame, and wakes the writer. */
T_DECLARE_CASE(test_send_ctrl_encodes_and_clamps)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();

	const bool ok = session_send_ctrl(
		&fx.ss, 5, MUX_FLAG_ACK, 100000 /* > UINT16_MAX */);

	T_EXPECT(ok);
	T_EXPECT_EQ(g_sendbuf_push_calls, 1);
	T_EXPECT(fx.ss.wire.tx_pending); /* mux_notify_write fired */
	struct mux_header h;
	mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_ACK);
	T_EXPECT_EQ((int)h.stream_id, 5);
	T_EXPECT_EQ((int)h.length, 0);
	T_EXPECT_EQ((int)h.extra, (int)UINT16_MAX);

	si_teardown(&fx);
}

/* On allocation failure session_send_ctrl reports failure and queues nothing. */
T_DECLARE_CASE(test_send_ctrl_oom)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	fx.pool_ctx.fail = true;

	const bool ok = session_send_ctrl(&fx.ss, 5, MUX_FLAG_RST, 0);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g_sendbuf_push_calls, 0);
	T_EXPECT(fx.ss.wire.sendbuf.head == NULL);

	si_teardown(&fx);
}

/* session_send_oob copies the supplied payload into a stream-0 frame queued on
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

	const bool ok = session_send_oob(
		&fx.ss, MUX_CTRL_PONG, payload, sizeof(payload));

	T_EXPECT(ok);
	T_EXPECT(fx.ss.wire.oobbuf.head != NULL);
	struct mux_header h;
	mux_read_header(fx.ss.wire.oobbuf.head->data, &h);
	T_EXPECT_EQ((int)h.stream_id, STREAMID_CTRL);
	T_EXPECT_EQ((int)h.extra, MUX_CTRL_PONG);
	T_EXPECT_EQ((int)h.length, (int)sizeof(payload));
	T_EXPECT_MEMEQ(
		fx.ss.wire.oobbuf.head->data + MUX_FRAME_HEADER_SIZE, payload,
		sizeof(payload));
	T_EXPECT(fx.ss.wire.tx_pending);

	si_teardown(&fx);
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

	const bool ok = session_send_oob(&fx.ss, MUX_CTRL_PROBE, NULL, 4);

	T_EXPECT(ok);
	T_CHECK(fx.ss.wire.oobbuf.head != NULL);
	const unsigned char zeros[4] = { 0, 0, 0, 0 };
	T_EXPECT_MEMEQ(
		fx.ss.wire.oobbuf.head->data + MUX_FRAME_HEADER_SIZE, zeros,
		sizeof(zeros));

	si_teardown(&fx);
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

	const bool ok = session_send_oob(&fx.ss, MUX_CTRL_PING, NULL, 0);

	T_EXPECT(!ok);
	T_EXPECT(fx.ss.wire.oobbuf.head == NULL);

	si_teardown(&fx);
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

	const bool ok = session_send_push(&fx.ss, &s, frame);

	T_EXPECT(ok);
	struct mux_header h;
	mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_PUSH | MUX_FLAG_SYN);
	T_EXPECT_EQ((int)h.length, 100);
	T_EXPECT_EQ((int)h.stream_id, 4);
	T_EXPECT_EQ(s.bytes_sent, (uint_least32_t)100);
	T_EXPECT_EQ(s.unacked_bytes, (uint_least32_t)100);

	si_teardown(&fx);
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

	const bool ok = session_send_push(&fx.ss, &s, frame);

	T_EXPECT(ok);
	struct mux_header h;
	mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_PUSH | MUX_FLAG_ACK | MUX_FLAG_FIN);
	T_EXPECT_EQ((int)h.extra, 2);
	T_EXPECT_EQ(g_mark_fin_sent_calls, 1);
	T_EXPECT_EQ(g_delay_remove_calls, 1);
	T_EXPECT(fx.ss.unacked.ack_pending);
	T_EXPECT_EQ(s.grant_sent, (uint_least32_t)(2u * MUX_WINDOW_UNIT));

	si_teardown(&fx);
}

/* session_emit_ack sends a session-level ACK carrying the unacked delta and
 * records the emission. */
T_DECLARE_CASE(test_emit_ack_sends_delta)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_unacked_delta = 3;

	session_emit_ack(&fx.ss);

	T_EXPECT_EQ(g_sendbuf_push_calls, 1);
	struct mux_header h;
	mux_read_header(fx.ss.wire.sendbuf.head->data, &h);
	T_EXPECT_EQ((int)h.flags, MUX_FLAG_ACK);
	T_EXPECT_EQ((int)h.stream_id, STREAMID_CTRL);
	T_EXPECT_EQ((int)h.extra, 3);
	T_EXPECT_EQ(g_ack_emitted_calls, 1);
	T_EXPECT_EQ(g_ack_emitted_last, (uint_fast32_t)3);

	si_teardown(&fx);
}

/* The session ACK delta is clamped to the 16-bit Extra field. */
T_DECLARE_CASE(test_emit_ack_clamps_delta)
{
	struct si_fixture fx;
	if (si_setup(&fx) != 0) {
		T_FATAL("si_setup failed");
		return;
	}
	spies_reset();
	g_unacked_delta = 70000; /* > UINT16_MAX */

	session_emit_ack(&fx.ss);

	T_EXPECT_EQ(g_ack_emitted_last, (uint_fast32_t)UINT16_MAX);

	si_teardown(&fx);
}

/* session_discard_stream_frames drops only the unsent non-RST frames of the
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

	session_discard_stream_frames(&fx.ss, 5);

	T_EXPECT_EQ(fx.ss.wire.sendbuf.count, (size_t)2);
	for (const struct mux_frame *f = fx.ss.wire.sendbuf.head; f != NULL;
	     f = f->next) {
		struct mux_header h;
		mux_read_header(f->data, &h);
		const bool is_unsent_stream5_data =
			h.stream_id == 5 && (h.flags & MUX_FLAG_RST) == 0;
		T_EXPECT(!is_unsent_stream5_data);
	}

	si_teardown(&fx);
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

	T_EXPECT(!fx.ss.wire.tx_pending);
	T_EXPECT_EQ(g_notify_calls, 0);

	si_teardown(&fx);
}

/* session_flush before establishment defers to a plain notify (no inline pump
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

	session_flush(&fx.ss);

	T_EXPECT_EQ(g_notify_calls, 1);
	T_EXPECT_EQ(g_sched_schedule_calls, 0);
	T_EXPECT_EQ(g_sched_next_data_calls, 0);

	si_teardown(&fx);
}

/* flush_sendbuf_head: the per-entry transport write state machine. */

/* Queue one already-encoded frame at the sendbuf head for the flush tests. */
static struct mux_frame *
si_queue_sendbuf(struct si_fixture *restrict fx, const size_t len)
{
	struct mux_frame *const f =
		mux_frame_get(&fx->ss.pool, fx->ss.max_payload);
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

	T_EXPECT(!stop); /* head fully sent and popped */
	T_EXPECT(made_progress);
	T_EXPECT_EQ(g_wire_send_calls, 1);
	T_EXPECT_EQ(g_track_sent_calls, 1);
	T_EXPECT(fx.ss.wire.sendbuf.head == NULL);

	si_teardown(&fx);
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

	T_EXPECT(stop);
	T_EXPECT(made_progress);
	T_EXPECT_EQ(f->pos, (size_t)40);
	T_EXPECT(fx.ss.wire.sendbuf.head == f); /* still head */

	si_teardown(&fx);
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

	T_EXPECT(stop);
	T_EXPECT(!made_progress);
	T_EXPECT(!fx.ss.wire.sendbuf_staging); /* staging closed */
	T_EXPECT(fx.ss.wire.sendbuf.head == f);

	si_teardown(&fx);
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

	T_EXPECT(stop);
	T_EXPECT_EQ(fx.ss.state, SESSION_SUSPENDED);

	si_teardown(&fx);
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

	T_EXPECT(stop);
	T_EXPECT_EQ(fx.ss.state, SESSION_CLOSED);

	si_teardown(&fx);
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
	T_EXPECT(ev_is_active(&fx.ss.w_send_timeout));

	ev_timer_stop(fx.ss.loop, &fx.ss.w_send_timeout);
	si_teardown(&fx);
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
	T_EXPECT(!flush_sendbuf_head(&fx.ss, &made_progress));
	T_EXPECT(!made_progress);
	si_teardown(&fx);
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
	T_EXPECT(flush_sendbuf_head(&fx.ss, &made_progress));
	T_EXPECT_EQ(fx.ss.state, SESSION_SUSPENDED);

	si_teardown(&fx);
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
	T_EXPECT(send_head_must_flush(&fx.ss));
	si_teardown(&fx);
}

/* send_handle_rx_closed on a non-resumable ESTABLISHED session discards buffers
 * and transitions to CLOSING. */
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

	T_EXPECT(send_handle_rx_closed(&fx.ss));
	T_EXPECT(fx.ss.wire.tx_pending);

	si_teardown(&fx);
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
	T_EXPECT_EQ(copy->len, sub2);
	T_EXPECT(memcmp(copy->data, entry->data + sub1, sub2) == 0);

	fx.ss.unacked.retransmit_copy = NULL;
	fx.ss.unacked.ring = NULL;
	mux_frame_put(&fx.ss.pool, entry);
	free(ring);
	si_teardown(&fx); /* clears sendbuf, freeing the replay copy */
}

static const struct testing_suite suite[] = {
	T_CASE(test_send_cb_defers_lp_drain_before_established),
	T_CASE(test_send_cb_drains_lp_when_established),
	T_CASE(test_session_flush_inline_when_pipe_clear),
	T_CASE(test_send_cb_resumes_lifecycle_drain_unconditionally),
	T_CASE(test_send_ctrl_encodes_and_clamps),
	T_CASE(test_send_ctrl_oom),
	T_CASE(test_send_oob_copies_payload),
	T_CASE(test_send_oob_zero_fills),
	T_CASE(test_send_oob_oom),
	T_CASE(test_send_push_syn_on_init),
	T_CASE(test_send_push_ack_fin),
	T_CASE(test_emit_ack_sends_delta),
	T_CASE(test_emit_ack_clamps_delta),
	T_CASE(test_discard_stream_frames_selective),
	T_CASE(test_notify_write_noop_before_established),
	T_CASE(test_session_flush_defers_before_established),
	T_CASE(test_flush_head_sends_fully),
	T_CASE(test_flush_head_partial_write),
	T_CASE(test_flush_head_blocked_closes_staging),
	T_CASE(test_flush_head_error_suspends),
	T_CASE(test_flush_head_error_resets),
	T_CASE(test_update_send_timeout_rearms_while_pending),
	T_CASE(test_flush_head_empty_sendbuf),
	T_CASE(test_flush_head_error_suspends_in_handshake),
	T_CASE(test_send_head_must_flush_partial_head),
	T_CASE(test_send_handle_rx_closed_terminal),
	T_CASE(test_retransmit_skips_acked_head_prefix),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* Surface the VERYVERBOSE frame-out diagnostics in the producers. */
	slog_level_ = LOG_LEVEL_VERYVERBOSE;

	return testing_main(argc, argv, suite);
}
