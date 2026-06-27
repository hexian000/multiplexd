/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* recv_test.c - white-box tests for recv.c (frame decode/dispatch, flag
 * matrices, stream-id parity, admission, window updates); recv.c #included,
 * all collaborators replaced by spies. */

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "os/clock.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* mock - collaborator spies; every routing-decision call is recorded
 * in struct spies; controllable return fields steer the decisions. */

static struct spies {
	int send_ctrl_calls;
	uint_fast16_t send_ctrl_id;
	uint_fast8_t send_ctrl_flags;
	uint_fast32_t send_ctrl_extra;

	int reset_calls;
	int suspend_calls;

	int recv_copy_calls;
	size_t recv_copy_len;
	int recv_rst_calls;
	int recv_fin_calls;
	int recv_window_calls;
	uint_fast32_t recv_window_inc;
	int check_ack_calls;
	int stream_start_calls;
	int stream_free_calls;
	int stream_close_calls;

	int notify_write_calls;
	int flush_oob_calls;
	int flush_resp_calls;
	int emit_ack_calls;
	int coalesce_arm_calls;

	int send_oob_calls;
	uint_fast8_t send_oob_extra;
	size_t send_oob_len;
	bool send_oob_ret;

	int est_add_calls;
	uint_least64_t est_add_bytes;
	int est_add_acked_calls;
	uint_least64_t est_add_acked_bytes;
	int est_calc_calls;
	int_fast64_t est_calc_sent_ns;
	size_t est_window_ret;

	struct unacked_ack_result ack_trim_ret;
	int ack_trim_calls;
	uint_fast32_t ack_trim_count;

	struct mux_stream *find_stream_ret;
	int find_stream_calls;
	bool add_stream_ret;
	int add_stream_calls;
	struct mux_stream *stream_new_ret;
	int stream_new_calls;

	int hello_calls;

	bool wire_recv_ret;
	size_t wire_recv_nread;
	const unsigned char *wire_recv_data;
	int wire_recv_calls;
	int wire_has_pending_remaining;
	bool ringbuf_reserve_ret;

	double keepalive_ret;
} g;

static void spies_reset(void)
{
	g = (struct spies){
		.send_oob_ret = true,
		.add_stream_ret = true,
		.ack_trim_ret = { .ok = true },
		.wire_recv_ret = true,
		.ringbuf_reserve_ret = true,
		.keepalive_ret = 10.0,
	};
}

/* Collaborator stubs.  Pulled in before recv.c so its external references
 * bind to these definitions. */

bool session_send_ctrl(
	struct mux_session *ss, uint_fast16_t stream_id, uint_fast8_t flags,
	uint_fast32_t extra)
{
	(void)ss;
	g.send_ctrl_calls++;
	g.send_ctrl_id = stream_id;
	g.send_ctrl_flags = flags;
	g.send_ctrl_extra = extra;
	return true;
}

bool session_send_oob(
	struct mux_session *ss, uint_fast8_t extra,
	const unsigned char *payload, size_t payload_len)
{
	(void)ss;
	(void)payload;
	g.send_oob_calls++;
	g.send_oob_extra = extra;
	g.send_oob_len = payload_len;
	return g.send_oob_ret;
}

void session_flush_oob(struct mux_session *ss)
{
	(void)ss;
	g.flush_oob_calls++;
}

void session_flush_resp(struct mux_session *ss)
{
	(void)ss;
	g.flush_resp_calls++;
}

void session_emit_ack(struct mux_session *ss)
{
	(void)ss;
	g.emit_ack_calls++;
}

void mux_notify_write(struct mux_session *ss)
{
	(void)ss;
	g.notify_write_calls++;
}

void session_reset(struct mux_session *ss)
{
	g.reset_calls++;
	ss->state = SESSION_CLOSED;
}

void session_suspend(struct mux_session *ss)
{
	g.suspend_calls++;
	ss->state = SESSION_SUSPENDED;
}

void session_log_frame_header(
	struct mux_session *ss, const char *what, const unsigned char *raw,
	const struct mux_header *hdr)
{
	(void)ss;
	(void)what;
	(void)raw;
	(void)hdr;
}

double keepalive_interval(const struct mux_session *ss)
{
	(void)ss;
	return g.keepalive_ret;
}

void stream_recv_copy(
	struct mux_stream *s, const unsigned char *payload, size_t payload_len)
{
	(void)s;
	(void)payload;
	g.recv_copy_calls++;
	g.recv_copy_len = payload_len;
}

void stream_recv_rst(struct mux_stream *s)
{
	(void)s;
	g.recv_rst_calls++;
}

void stream_recv_fin(struct mux_stream *s)
{
	(void)s;
	g.recv_fin_calls++;
}

void stream_recv_window(struct mux_stream *s, uint_fast32_t window_inc)
{
	(void)s;
	g.recv_window_calls++;
	g.recv_window_inc = window_inc;
}

void stream_check_ack(struct mux_stream *s)
{
	(void)s;
	g.check_ack_calls++;
}

void stream_start(struct mux_stream *s)
{
	(void)s;
	g.stream_start_calls++;
}

void stream_free(struct mux_stream *s)
{
	(void)s;
	g.stream_free_calls++;
}

void stream_close(struct mux_stream *s)
{
	(void)s;
	g.stream_close_calls++;
}

struct mux_stream *
stream_new(struct mux_session *ss, uint_fast16_t id, bool active_open)
{
	(void)ss;
	(void)id;
	(void)active_open;
	g.stream_new_calls++;
	return g.stream_new_ret;
}

int stream_format_tag(char *buf, size_t buflen, const struct mux_stream *s)
{
	(void)s;
	return snprintf(buf, buflen, "[test]");
}

struct mux_stream *sched_find_stream(struct mux_session *ss, uint_fast16_t id)
{
	(void)ss;
	(void)id;
	g.find_stream_calls++;
	return g.find_stream_ret;
}

bool sched_add_stream(struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	(void)s;
	g.add_stream_calls++;
	return g.add_stream_ret;
}

void sched_coalesce_arm(struct mux_session *ss)
{
	(void)ss;
	g.coalesce_arm_calls++;
}

void estimator_add(struct mux_session *ss, uint_least64_t bytes)
{
	(void)ss;
	g.est_add_calls++;
	g.est_add_bytes = bytes;
}

void estimator_add_acked(struct mux_session *ss, uint_least64_t bytes)
{
	(void)ss;
	g.est_add_acked_calls++;
	g.est_add_acked_bytes = bytes;
}

void estimator_calculate(struct mux_session *ss, int_fast64_t sent_ns)
{
	(void)ss;
	g.est_calc_calls++;
	g.est_calc_sent_ns = sent_ns;
}

size_t estimator_rx_window_size(const struct estimator_ctx *est)
{
	(void)est;
	return g.est_window_ret;
}

size_t estimator_tx_window_size(const struct estimator_ctx *est)
{
	(void)est;
	return g.est_window_ret;
}

struct unacked_ack_result
unacked_ack_trim(struct mux_session *ss, uint_fast32_t count)
{
	(void)ss;
	g.ack_trim_calls++;
	g.ack_trim_count = count;
	return g.ack_trim_ret;
}

bool handshake_process_hello(
	struct mux_session *ss, const struct mux_header *hdr, size_t frame_size)
{
	(void)hdr;
	g.hello_calls++;
	/* Mimic the real handler: consume the frame it parsed. */
	ringbuf_consume(ss->wire.recvbuf, frame_size);
	return true;
}

bool wire_recv(struct mux_session *ss, unsigned char *restrict buf, size_t *len)
{
	(void)ss;
	g.wire_recv_calls++;
	if (!g.wire_recv_ret) {
		return false;
	}
	/* Deliver the staged record on the first read only; subsequent reads in
	 * the same drain report EAGAIN (zero bytes) so the loop terminates. */
	const size_t n = (g.wire_recv_calls == 1) ? g.wire_recv_nread : 0;
	if (n > 0 && g.wire_recv_data != NULL) {
		memcpy(buf, g.wire_recv_data, n);
	}
	*len = n;
	return true;
}

bool wire_has_pending(const struct mux_session *ss)
{
	(void)ss;
	if (g.wire_has_pending_remaining > 0) {
		g.wire_has_pending_remaining--;
		return true;
	}
	return false;
}

bool ringbuf_reserve(struct ringbuf **restrict rbp, size_t need, bool can_grow)
{
	(void)rbp;
	(void)need;
	(void)can_grow;
	/* The fixture pre-sizes recvbuf large enough; never grow here unless a
	 * test is exercising the reserve-failure (OOM) path. */
	return g.ringbuf_reserve_ret;
}

void ringbuf_shrink(struct ringbuf **restrict rbp, size_t target_cap)
{
	/* The fixture's recvbuf is never grown, so shrinking is a no-op here. */
	(void)rbp;
	(void)target_cap;
}

/* Integer-keyed stream table opts (matches sched.c's use of the stream id as a
 * by-value key) so the fixture can populate the table for admission-control and
 * window-iterate paths. */
static uint_fast32_t id_hash(const void *key, uint_fast32_t seed)
{
	return (uint_fast32_t)((uintptr_t)key * 2654435761u) ^ seed;
}

static bool id_eq(const void *a, const void *b)
{
	return a == b;
}

const struct table_opts mux_stream_table_opts = {
	.hash = id_hash,
	.eq = id_eq,
};

/* frame.c data global the header-inline framing helpers reference; stubbed here
 * since this white-box TU does not link frame.c. */
const struct mux_config mux_conf_default = {
	.max_frame_payload = 65536 - MUX_FRAME_HEADER_SIZE,
};

/* Pull in the unit under test after the stubs so its references bind here. */
#include "mux/recv.c"

/* Fixture: a session with a real receive ring and event loop; no transport. */

#define RECVBUF_CAP (4u * (size_t)MUX_MAX_FRAME_SIZE)

struct recv_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
};

static void rf_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static int rf_setup(struct recv_fixture *restrict fx)
{
	*fx = (struct recv_fixture){ 0 };
	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}
	fx->ss = (struct mux_session){
		.loop = fx->loop,
		.state = SESSION_ESTABLISHED,
		.max_payload =
			(uint_least32_t)mux_conf_default.max_frame_payload,
		.session_window = 8,
		.stream_window = 4,
		.wire = { .rx_open = true },
	};
	fx->ss.wire.recvbuf = ringbuf_new(RECVBUF_CAP);
	if (fx->ss.wire.recvbuf == NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	ev_timer_init(&fx->ss.w_timeout, rf_timer_cb, 1.0, 1.0);
	ev_timer_init(&fx->ss.w_keepalive, rf_timer_cb, 1.0, 1.0);
	spies_reset();
	return 0;
}

static void rf_teardown(struct recv_fixture *restrict fx)
{
	ringbuf_free(fx->ss.wire.recvbuf);
	fx->ss.wire.recvbuf = NULL;
	if (fx->ss.sched.streams != NULL) {
		table_free(fx->ss.sched.streams);
		fx->ss.sched.streams = NULL;
	}
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* Write one frame (header + zeroed payload) into the receive ring. */
static void push_frame(
	struct recv_fixture *restrict fx, const struct mux_header *restrict hdr)
{
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + hdr->length;
	unsigned char *const p = ringbuf_write_ptr(fx->ss.wire.recvbuf);
	mux_write_header(p, hdr);
	memset(p + MUX_FRAME_HEADER_SIZE, 0, hdr->length);
	ringbuf_produce(fx->ss.wire.recvbuf, frame_size);
}

/* A bare stream with the given id and state; spies never dereference more. */
static struct mux_stream make_stream(uint_least16_t id, enum stream_state state)
{
	return (struct mux_stream){ .id = id, .state = state };
}

/* regression - targeted cases for one dispatch/validation decision each */

/* validate_flags_by_stream: the per-state inbound flag matrix. */

T_DECLARE_CASE(test_validate_flags_syn_sent)
{
	struct mux_stream s = make_stream(1, STREAM_SYN_SENT);
	/* SYN_SENT requires SYN|ACK; PUSH may ride along, nothing else may. */
	T_EXPECT(validate_flags_by_stream(&s, MUX_FLAG_SYN | MUX_FLAG_ACK));
	T_EXPECT(validate_flags_by_stream(
		&s, MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_PUSH));
	T_EXPECT(!validate_flags_by_stream(&s, MUX_FLAG_SYN));
	T_EXPECT(!validate_flags_by_stream(&s, MUX_FLAG_ACK));
	T_EXPECT(!validate_flags_by_stream(
		&s, MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_FIN));
}

T_DECLARE_CASE(test_validate_flags_established)
{
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	/* Any non-empty flag set is fine, except a bare SYN (no ACK). */
	T_EXPECT(validate_flags_by_stream(&s, MUX_FLAG_PUSH));
	T_EXPECT(validate_flags_by_stream(&s, MUX_FLAG_ACK));
	T_EXPECT(validate_flags_by_stream(&s, MUX_FLAG_FIN));
	T_EXPECT(validate_flags_by_stream(&s, MUX_FLAG_SYN | MUX_FLAG_ACK));
	T_EXPECT(!validate_flags_by_stream(&s, 0));
	T_EXPECT(!validate_flags_by_stream(&s, MUX_FLAG_SYN));
	T_EXPECT(!validate_flags_by_stream(&s, MUX_FLAG_SYN | MUX_FLAG_PUSH));
}

T_DECLARE_CASE(test_validate_flags_closing_states)
{
	/* CLOSE_WAIT / CLOSING accept only ACK and/or FIN. */
	struct mux_stream cw = make_stream(1, STREAM_CLOSE_WAIT);
	T_EXPECT(validate_flags_by_stream(&cw, MUX_FLAG_ACK));
	T_EXPECT(validate_flags_by_stream(&cw, MUX_FLAG_FIN));
	T_EXPECT(validate_flags_by_stream(&cw, MUX_FLAG_ACK | MUX_FLAG_FIN));
	T_EXPECT(!validate_flags_by_stream(&cw, 0));
	T_EXPECT(!validate_flags_by_stream(&cw, MUX_FLAG_PUSH));

	struct mux_stream cl = make_stream(1, STREAM_CLOSING);
	T_EXPECT(validate_flags_by_stream(&cl, MUX_FLAG_FIN));
	T_EXPECT(!validate_flags_by_stream(&cl, MUX_FLAG_SYN));
}

T_DECLARE_CASE(test_validate_flags_inert_states)
{
	/* SYN_RECEIVED, INIT, and CLOSED never accept a routed data frame here. */
	struct mux_stream sr = make_stream(1, STREAM_SYN_RECEIVED);
	T_EXPECT(!validate_flags_by_stream(&sr, MUX_FLAG_ACK));
	struct mux_stream in = make_stream(1, STREAM_INIT);
	T_EXPECT(!validate_flags_by_stream(&in, MUX_FLAG_ACK));
	struct mux_stream cd = make_stream(1, STREAM_CLOSED);
	T_EXPECT(!validate_flags_by_stream(&cd, MUX_FLAG_ACK));
	/* RST is stripped before the matrix, so RST-only reads as empty. */
	T_EXPECT(!validate_flags_by_stream(&sr, MUX_FLAG_RST));
}

/* is_ignorable_unknown_terminal_frame / is_valid_peer_stream_id. */

T_DECLARE_CASE(test_ignorable_terminal_frame)
{
	struct mux_header h = { .flags = MUX_FLAG_ACK, .length = 0 };
	T_EXPECT(is_ignorable_unknown_terminal_frame(&h));
	h.flags = MUX_FLAG_FIN;
	T_EXPECT(is_ignorable_unknown_terminal_frame(&h));
	h.flags = MUX_FLAG_ACK | MUX_FLAG_FIN;
	T_EXPECT(is_ignorable_unknown_terminal_frame(&h));

	/* Non-zero length disqualifies. */
	h.flags = MUX_FLAG_ACK;
	h.length = 1;
	T_EXPECT(!is_ignorable_unknown_terminal_frame(&h));
	/* Neither ACK nor FIN. */
	h.length = 0;
	h.flags = MUX_FLAG_PUSH;
	T_EXPECT(!is_ignorable_unknown_terminal_frame(&h));
	/* ACK plus an extra flag (PUSH) is not a bare terminal. */
	h.flags = MUX_FLAG_ACK | MUX_FLAG_PUSH;
	T_EXPECT(!is_ignorable_unknown_terminal_frame(&h));
}

T_DECLARE_CASE(test_valid_peer_stream_id)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Stream 0 is the control stream, never a peer-opened stream. */
	T_EXPECT(!is_valid_peer_stream_id(&fx.ss, STREAMID_CTRL));

	/* Server (accepted) peers must open odd ids; clients open even ids. */
	fx.ss.accepted = true;
	T_EXPECT(is_valid_peer_stream_id(&fx.ss, 3));
	T_EXPECT(!is_valid_peer_stream_id(&fx.ss, 4));

	fx.ss.accepted = false;
	T_EXPECT(is_valid_peer_stream_id(&fx.ss, 4));
	T_EXPECT(!is_valid_peer_stream_id(&fx.ss, 3));

	rf_teardown(&fx);
}

/* session_update_session_window / session_update_stream_window. */

T_DECLARE_CASE(test_update_session_window_floors_and_noop)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Below the initial-frames floor: clamps up to MUX_INITIAL_SEND_WINDOW. */
	fx.ss.session_window = 1;
	fx.ss.peer_stream_window = 0;
	session_update_session_window(&fx.ss, 0);
	const uint_least32_t initial =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	T_EXPECT_EQ(fx.ss.session_window, initial);

	/* Idempotent: same target is a no-op (no stall side effects). */
	session_update_session_window(&fx.ss, 0);
	T_EXPECT_EQ(fx.ss.session_window, initial);
	T_EXPECT_EQ(g.notify_write_calls, 0);

	/* peer_stream_window acts as a floor above the initial window. */
	fx.ss.peer_stream_window = initial + 10u;
	session_update_session_window(&fx.ss, 0);
	T_EXPECT_EQ(fx.ss.session_window, (uint_least32_t)(initial + 10u));

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_update_session_window_clears_stall_on_growth)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Stalled with a small backlog; a window large enough to cover it clears
	 * the stall and re-arms the writer. */
	fx.ss.session_window = 1;
	fx.ss.unacked.stalled = true;
	fx.ss.unacked.bytes = 20000;
	fx.ss.peer_stream_window = 0;

	/* window_bytes large enough that target_frames dominates the floors. */
	session_update_session_window(&fx.ss, (size_t)10u * MUX_WINDOW_UNIT);

	T_EXPECT(!fx.ss.unacked.stalled);
	T_EXPECT_EQ(g.notify_write_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_update_stream_window_grows_and_iterates)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Two streams in the table: one below the new window (grown by the
	 * callback) and one already above it (left untouched, the early return). */
	fx.ss.sched.streams = table_new(&mux_stream_table_opts);
	T_EXPECT(fx.ss.sched.streams != NULL);
	static struct mux_stream s_low, s_high;
	s_low = make_stream(2, STREAM_ESTABLISHED);
	s_low.recv_window = 0;
	s_high = make_stream(4, STREAM_ESTABLISHED);
	s_high.recv_window =
		100u * MUX_WINDOW_UNIT; /* already past the target */
	void *elem = &s_low;
	fx.ss.sched.streams = table_set(
		fx.ss.sched.streams, (const void *)(uintptr_t)s_low.id, &elem);
	T_EXPECT(fx.ss.sched.streams != NULL);
	elem = &s_high;
	fx.ss.sched.streams = table_set(
		fx.ss.sched.streams, (const void *)(uintptr_t)s_high.id, &elem);
	T_EXPECT(fx.ss.sched.streams != NULL);

	fx.ss.stream_window = 1;
	session_update_stream_window(&fx.ss, (size_t)5u * MUX_WINDOW_UNIT);

	T_EXPECT_EQ(fx.ss.stream_window, (uint_least32_t)5);
	/* The below-target stream grew and asked for an ACK check; the
	 * above-target stream was left as is. */
	T_EXPECT(s_low.recv_window > 0);
	T_EXPECT_EQ(
		s_high.recv_window, (uint_least32_t)(100u * MUX_WINDOW_UNIT));
	T_EXPECT_EQ(g.check_ack_calls, 1);

	/* Idempotent second call with the same target does nothing. */
	g.check_ack_calls = 0;
	session_update_stream_window(&fx.ss, (size_t)5u * MUX_WINDOW_UNIT);
	T_EXPECT_EQ(g.check_ack_calls, 0);

	rf_teardown(&fx);
}

/* dispatch_by_stream: routing for a known stream. */

T_DECLARE_CASE(test_dispatch_by_stream_rst)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_RST,
				.stream_id = 1 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	T_EXPECT_EQ(g.recv_rst_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_by_stream_invalid_flags_sends_rst)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A bare SYN (no ACK) on an established stream is invalid -> RST + reset. */
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 1 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT(s.rst_sent);
	T_EXPECT_EQ(g.recv_rst_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_by_stream_synack_establishes)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_SYN_SENT);
	s.send_window = 2u * MUX_WINDOW_UNIT;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
				.stream_id = 1,
				.extra = 3 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	T_EXPECT_EQ(g.recv_window_calls, 1);
	T_EXPECT_EQ(g.recv_window_inc, (uint_fast32_t)3);
	T_EXPECT_EQ(g.stream_start_calls, 1);
	/* peer_stream_window is recovered from send_window / MUX_WINDOW_UNIT. */
	T_EXPECT_EQ(fx.ss.peer_stream_window, (uint_least32_t)2);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_by_stream_synack_idempotent)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A duplicate SYN|ACK after establishment is consumed without re-running
	 * establishment side effects (resume replay tolerance). */
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
				.stream_id = 1,
				.extra = 3 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	T_EXPECT_EQ(g.stream_start_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_by_stream_push_fin)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH | MUX_FLAG_FIN,
				.stream_id = 1,
				.length = 64 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_copy_len, (size_t)64);
	T_EXPECT_EQ(g.recv_fin_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_by_stream_ack_grants_credit)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Plain ACK clears Nagle and grants window credit (no PUSH payload). */
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	s.unacked_bytes = 1234;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK,
				.stream_id = 1,
				.extra = 5 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	T_EXPECT_EQ(g.recv_window_calls, 1);
	T_EXPECT_EQ(g.recv_window_inc, (uint_fast32_t)5);
	T_EXPECT_EQ(s.unacked_bytes, (uint_least32_t)0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_by_stream_closed_ignores_rst)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_CLOSED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_RST,
				.stream_id = 1 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	/* RST on a closed stream is dropped silently, not forwarded. */
	T_EXPECT_EQ(g.recv_rst_calls, 0);
	T_EXPECT_EQ(g.send_ctrl_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_by_stream_closed_late_frame_rst_once)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_CLOSED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 1,
				.length = 8 };

	/* First late data frame: one RST is emitted and rst_sent latches. */
	push_frame(&fx, &h);
	dispatch_by_stream(&fx.ss, &s, &h);
	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT(s.rst_sent);

	/* Second late frame: suppressed, no further RST. */
	push_frame(&fx, &h);
	dispatch_by_stream(&fx.ss, &s, &h);
	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

/* dispatch_no_stream: routing for an unknown stream id. */

T_DECLARE_CASE(test_dispatch_no_stream_rst_ignored)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_RST,
				.stream_id = 7 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(g.send_ctrl_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_bad_syn_flags_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* SYN combined with a disallowed flag (FIN) closes the connection. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_FIN,
				.stream_id = 3 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.reset_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_bad_parity_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Accepted session expects odd peer ids; an even SYN id is a violation. */
	fx.ss.accepted = true;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 4 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.reset_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_draining_refuses)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	fx.ss.draining = true;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 3 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_new_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_max_streams_refuses)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	fx.ss.conf.max_streams = 1;
	/* Populate the table so its size reaches the cap. */
	fx.ss.sched.streams = table_new(&mux_stream_table_opts);
	T_EXPECT(fx.ss.sched.streams != NULL);
	void *elem = (void *)(uintptr_t)0x1;
	fx.ss.sched.streams = table_set(
		fx.ss.sched.streams, (const void *)(uintptr_t)9, &elem);
	T_EXPECT(fx.ss.sched.streams != NULL);

	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 3 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_new_calls, 0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_accept_null_refuses)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	static struct mux_stream newstream;
	newstream = make_stream(3, STREAM_SYN_RECEIVED);
	g.stream_new_ret = &newstream;
	/* callbacks.on_accept stays NULL: the stream is refused after creation. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 3,
				.extra = 1 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.stream_new_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_close_calls, 1);
	T_EXPECT(newstream.rst_sent);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

static bool
accept_reject_cb(void *ud, const struct mux_session *ss, struct mux_stream *s)
{
	(void)ud;
	(void)ss;
	(void)s;
	return false;
}

static bool
accept_ok_cb(void *ud, const struct mux_session *ss, struct mux_stream *s)
{
	(void)ud;
	(void)ss;
	(void)s;
	return true;
}

T_DECLARE_CASE(test_dispatch_no_stream_accept_rejects)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	fx.ss.callbacks.on_accept = accept_reject_cb;
	static struct mux_stream newstream;
	newstream = make_stream(3, STREAM_SYN_RECEIVED);
	g.stream_new_ret = &newstream;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 3,
				.extra = 1 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_close_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_accept_ok)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	fx.ss.callbacks.on_accept = accept_ok_cb;
	/* Auto-window mode exercises the estimator + session-window update side of
	 * the accept path and process_syn_payload. */
	fx.ss.auto_stream_window = true;
	fx.ss.auto_session_window = true;
	static struct mux_stream newstream;
	newstream = make_stream(3, STREAM_SYN_RECEIVED);
	g.stream_new_ret = &newstream;
	/* SYN|PUSH delivers initial payload through process_syn_payload. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_PUSH,
				.stream_id = 3,
				.extra = 1,
				.length = 16 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.stream_close_calls, 0);
	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_copy_len, (size_t)16);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_stream_new_oom)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	g.stream_new_ret = NULL; /* allocation failure */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 3,
				.extra = 1 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.stream_new_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_add_stream_fails)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	static struct mux_stream newstream;
	newstream = make_stream(3, STREAM_SYN_RECEIVED);
	g.stream_new_ret = &newstream;
	g.add_stream_ret = false; /* table insertion fails */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 3,
				.extra = 1 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.add_stream_calls, 1);
	T_EXPECT_EQ(g.stream_free_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_reserved_flags_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A non-SYN frame carrying a reserved flag bit closes the connection. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0x80,
				.stream_id = 7 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.reset_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_late_nonsyn_rst)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A non-SYN data frame for an unknown id: RST it, keep the session. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 7,
				.length = 8 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_PROTOCOL_ERROR);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_no_stream_ignorable_terminal)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A bare zero-length ACK|FIN for an unknown id is silently ignored. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK | MUX_FLAG_FIN,
				.stream_id = 7 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	T_EXPECT_EQ(g.send_ctrl_calls, 0);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

/* dispatch_frame: the decode loop, version/flag gates, and stream-0 control. */

T_DECLARE_CASE(test_dispatch_frame_accepts_oversized_length)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A max-size 16-bit length, larger than our own (default) frame cap: a peer
	 * may send a payload bigger than our configured frame size.  dispatch_frame
	 * must not reject it; with only the header buffered it waits for the body. */
	unsigned char *const p = ringbuf_write_ptr(fx.ss.wire.recvbuf);
	const struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.stream_id = 1,
		.length = (uint_least16_t)MUX_MAX_PAYLOAD_SIZE,
	};
	mux_write_header(p, &h);
	ringbuf_produce(fx.ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE);

	dispatch_frame(&fx.ss);

	/* Not rejected; the partial frame stays buffered awaiting its body. */
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(
		ringbuf_readable(fx.ss.wire.recvbuf),
		(size_t)MUX_FRAME_HEADER_SIZE);

	rf_teardown(&fx);
}

/* A fully-buffered oversized PUSH is delivered to the stream intact: the whole
 * payload (larger than MUX_MAX_PAYLOAD_SIZE) reaches stream_recv_copy. */
T_DECLARE_CASE(test_dispatch_by_stream_oversized_push)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	const uint_least16_t len =
		(uint_least16_t)(MUX_MAX_PAYLOAD_SIZE + 4096u);
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 1,
				.length = len };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_copy_len, (size_t)len);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_frame_unsupported_version_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_header h = { .version = 0x7f, .stream_id = 1 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	T_EXPECT_EQ(g.reset_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_frame_reserved_flags_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A reserved flag bit (0x80) outside MUX_FLAG_MASK closes the session. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0x80,
				.stream_id = 1 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	T_EXPECT_EQ(g.reset_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_frame_hello_routed_to_handshake)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_header h = { .version = 0, .stream_id = 0, .length = 4 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	T_EXPECT_EQ(g.hello_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_frame_session_ack_trims)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.auto_session_window = true;
	g.ack_trim_ret = (struct unacked_ack_result){ .ok = true,
						      .trimmed_bytes = 4096,
						      .unstalled = true };
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK,
				.stream_id = STREAMID_CTRL,
				.extra = 2 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	T_EXPECT_EQ(g.ack_trim_calls, 1);
	T_EXPECT_EQ(g.ack_trim_count, (uint_fast32_t)2);
	T_EXPECT_EQ(g.est_add_acked_calls, 1);
	T_EXPECT_EQ(g.est_add_acked_bytes, (uint_least64_t)4096);
	T_EXPECT_EQ(g.notify_write_calls, 1); /* unstalled -> re-arm writer */
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_frame_session_ack_overflow_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	g.ack_trim_ret = (struct unacked_ack_result){ .ok = false };
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK,
				.stream_id = STREAMID_CTRL,
				.extra = 9 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	T_EXPECT_EQ(g.reset_calls, 1);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_frame_ctrl_ping_pong_probe)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* PROBE (flags == 0, extra == MUX_CTRL_PROBE): discarded, no PONG. */
	struct mux_header probe = { .version = MUX_PROTOCOL_VERSION,
				    .flags = 0,
				    .stream_id = STREAMID_CTRL,
				    .extra = MUX_CTRL_PROBE };
	push_frame(&fx, &probe);
	dispatch_frame(&fx.ss);
	T_EXPECT_EQ(g.send_oob_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	/* PING: a PONG is queued (rate limiter clear since last_ns is in the
	 * distant past). */
	fx.ss.ping_recv_last_ns =
		clock_monotonic_ns() - 2 * MUX_PONG_RATE_LIMIT_NS;
	struct mux_header ping = { .version = MUX_PROTOCOL_VERSION,
				   .flags = 0,
				   .stream_id = STREAMID_CTRL,
				   .extra = MUX_CTRL_PING,
				   .length = MUX_PING_PAYLOAD_SIZE };
	push_frame(&fx, &ping);
	dispatch_frame(&fx.ss);
	T_EXPECT_EQ(g.send_oob_calls, 1);
	T_EXPECT_EQ(g.send_oob_extra, (uint_fast8_t)MUX_CTRL_PONG);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_dispatch_frame_data_forces_session_ack)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* session_window/4 clamps to >=2, so two received data frames hit the
	 * forced-ACK threshold. */
	fx.ss.session_window = 8;
	struct mux_stream s = make_stream(2, STREAM_ESTABLISHED);
	g.find_stream_ret = &s;

	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 2,
				.length = 8 };
	push_frame(&fx, &h);
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	T_EXPECT_EQ(fx.ss.unacked.recv_seq, (uint_least32_t)2);
	T_EXPECT_EQ(g.emit_ack_calls, 1);
	T_EXPECT_EQ(g.recv_copy_calls, 2);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

/* session_recv_ping / session_recv_pong control handlers. */

T_DECLARE_CASE(test_recv_ping_rate_limited)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A PING within the rate-limit window is dropped without a PONG. */
	fx.ss.ping_recv_last_ns = clock_monotonic_ns();
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PING,
				.length = MUX_PING_PAYLOAD_SIZE };
	push_frame(&fx, &h);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	session_recv_ping(&fx.ss, &h, frame_size);

	T_EXPECT_EQ(g.send_oob_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_recv_ping_oom_drops_pong)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.ping_recv_last_ns =
		clock_monotonic_ns() - 2 * MUX_PONG_RATE_LIMIT_NS;
	g.send_oob_ret = false; /* queueing the PONG fails */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PING,
				.length = MUX_PING_PAYLOAD_SIZE };
	push_frame(&fx, &h);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	session_recv_ping(&fx.ss, &h, frame_size);

	T_EXPECT_EQ(g.send_oob_calls, 1);
	T_EXPECT_EQ(g.flush_oob_calls, 0); /* not flushed on failure */
	/* ping_recv_last_ns is not advanced when the PONG could not be queued. */
	T_EXPECT(
		fx.ss.ping_recv_last_ns <
		clock_monotonic_ns() - MUX_PONG_RATE_LIMIT_NS);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

/* A PING larger than our frame cap cannot be echoed (we never send oversized),
 * so the connection is closed instead of replying with a truncated PONG. */
T_DECLARE_CASE(test_recv_ping_oversized_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.ping_recv_last_ns =
		clock_monotonic_ns() - 2 * MUX_PONG_RATE_LIMIT_NS;
	struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
		.length = (uint_least16_t)MUX_MAX_PAYLOAD_SIZE,
	};
	push_frame(&fx, &h);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	session_recv_ping(&fx.ss, &h, frame_size);

	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(g.send_oob_calls, 0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_recv_pong_short_payload_ignored)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A PONG shorter than the estimator timestamp is consumed but ignored. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PONG,
				.length = 4 };
	push_frame(&fx, &h);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	session_recv_pong(&fx.ss, &h, frame_size);

	T_EXPECT_EQ(g.est_calc_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_recv_pong_feeds_estimator)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.auto_stream_window = true;
	fx.ss.auto_session_window = true;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PONG,
				.length = MUX_PING_PAYLOAD_SIZE };
	/* Encode a timestamp into the payload before pushing. */
	unsigned char *const p = ringbuf_write_ptr(fx.ss.wire.recvbuf);
	mux_write_header(p, &h);
	write_uint64(p + MUX_FRAME_HEADER_SIZE, UINT64_C(123456789));
	ringbuf_produce(fx.ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE + h.length);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	session_recv_pong(&fx.ss, &h, frame_size);

	T_EXPECT_EQ(g.est_calc_calls, 1);
	T_EXPECT_EQ(g.est_calc_sent_ns, (int_fast64_t)123456789);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);

	rf_teardown(&fx);
}

/* recv_one / session_on_recv: the transport read pump. */

T_DECLARE_CASE(test_recv_one_error_suspends_resumable)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* An established session with a negotiated session id suspends (preserving
	 * streams) rather than resetting on a transport read error. */
	fx.ss.handshake.has_session_id = true;
	g.wire_recv_ret = false;

	const bool ok = recv_one(&fx.ss);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.suspend_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_recv_one_error_resets_fresh)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Without a negotiated session id there is nothing to resume: reset. */
	fx.ss.handshake.has_session_id = false;
	g.wire_recv_ret = false;

	const bool ok = recv_one(&fx.ss);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(g.suspend_calls, 0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_recv_one_handshake_suspends_resumable)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A client mid-resume handshake (HANDSHAKE, not accepted, with a session
	 * id) suspends rather than resets on a read error. */
	fx.ss.state = SESSION_HANDSHAKE;
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;
	g.wire_recv_ret = false;

	const bool ok = recv_one(&fx.ss);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.suspend_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_recv_one_reserve_oom_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Failing to reserve receive space is fatal: reset the session. */
	g.ringbuf_reserve_ret = false;

	const bool ok = recv_one(&fx.ss);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(
		g.wire_recv_calls, 0); /* never reached the transport read */

	rf_teardown(&fx);
}

T_DECLARE_CASE(test_session_on_recv_dispatches_and_loops)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Stage a single PROBE frame for wire_recv to deliver, then report one
	 * more pending read.  The second read returns zero bytes (EAGAIN), so the
	 * drain loop runs a second recv_one and then breaks. */
	static unsigned char frame[MUX_FRAME_HEADER_SIZE];
	const struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				      .flags = 0,
				      .stream_id = STREAMID_CTRL,
				      .extra = MUX_CTRL_PROBE };
	mux_write_header(frame, &h);
	g.wire_recv_data = frame;
	g.wire_recv_nread = sizeof(frame);
	g.wire_has_pending_remaining = 1; /* one extra loop iteration */

	session_on_recv(&fx.ss);

	/* Two reads: the initial recv_one plus one pending-driven iteration. */
	T_EXPECT_EQ(g.wire_recv_calls, 2);
	T_EXPECT_EQ(ringbuf_readable(fx.ss.wire.recvbuf), (size_t)0);
	/* The batch epilogue drains freshly queued egress exactly once. */
	T_EXPECT_EQ(g.flush_resp_calls, 1);

	rf_teardown(&fx);
}

static const struct testing_suite suite[] = {
	T_CASE(test_validate_flags_syn_sent),
	T_CASE(test_validate_flags_established),
	T_CASE(test_validate_flags_closing_states),
	T_CASE(test_validate_flags_inert_states),
	T_CASE(test_ignorable_terminal_frame),
	T_CASE(test_valid_peer_stream_id),
	T_CASE(test_update_session_window_floors_and_noop),
	T_CASE(test_update_session_window_clears_stall_on_growth),
	T_CASE(test_update_stream_window_grows_and_iterates),
	T_CASE(test_dispatch_by_stream_rst),
	T_CASE(test_dispatch_by_stream_invalid_flags_sends_rst),
	T_CASE(test_dispatch_by_stream_synack_establishes),
	T_CASE(test_dispatch_by_stream_synack_idempotent),
	T_CASE(test_dispatch_by_stream_push_fin),
	T_CASE(test_dispatch_by_stream_ack_grants_credit),
	T_CASE(test_dispatch_by_stream_closed_ignores_rst),
	T_CASE(test_dispatch_by_stream_closed_late_frame_rst_once),
	T_CASE(test_dispatch_no_stream_rst_ignored),
	T_CASE(test_dispatch_no_stream_bad_syn_flags_resets),
	T_CASE(test_dispatch_no_stream_bad_parity_resets),
	T_CASE(test_dispatch_no_stream_draining_refuses),
	T_CASE(test_dispatch_no_stream_max_streams_refuses),
	T_CASE(test_dispatch_no_stream_accept_null_refuses),
	T_CASE(test_dispatch_no_stream_accept_rejects),
	T_CASE(test_dispatch_no_stream_accept_ok),
	T_CASE(test_dispatch_no_stream_stream_new_oom),
	T_CASE(test_dispatch_no_stream_add_stream_fails),
	T_CASE(test_dispatch_no_stream_reserved_flags_resets),
	T_CASE(test_dispatch_no_stream_late_nonsyn_rst),
	T_CASE(test_dispatch_no_stream_ignorable_terminal),
	T_CASE(test_dispatch_frame_accepts_oversized_length),
	T_CASE(test_dispatch_by_stream_oversized_push),
	T_CASE(test_dispatch_frame_unsupported_version_resets),
	T_CASE(test_dispatch_frame_reserved_flags_resets),
	T_CASE(test_dispatch_frame_hello_routed_to_handshake),
	T_CASE(test_dispatch_frame_session_ack_trims),
	T_CASE(test_dispatch_frame_session_ack_overflow_resets),
	T_CASE(test_dispatch_frame_ctrl_ping_pong_probe),
	T_CASE(test_dispatch_frame_data_forces_session_ack),
	T_CASE(test_recv_ping_rate_limited),
	T_CASE(test_recv_ping_oom_drops_pong),
	T_CASE(test_recv_ping_oversized_resets),
	T_CASE(test_recv_pong_short_payload_ignored),
	T_CASE(test_recv_pong_feeds_estimator),
	T_CASE(test_recv_one_error_suspends_resumable),
	T_CASE(test_recv_one_error_resets_fresh),
	T_CASE(test_recv_one_handshake_suspends_resumable),
	T_CASE(test_recv_one_reserve_oom_resets),
	T_CASE(test_session_on_recv_dispatches_and_loops),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* Surface the VERYVERBOSE/DEBUG diagnostic branches in recv.c. */
	slog_level_ = LOG_LEVEL_VERYVERBOSE;

	return testing_main(argc, argv, suite);
}
