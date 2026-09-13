/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* recv_test.c - white-box tests for recv.c (frame decode/dispatch, flag
 * matrices, stream-id parity, admission, window updates); recv.c #included,
 * all collaborators replaced by spies. */

#include "estimator.h"
#include "frame.h"
#include "handshake.h"
#include "mux.h"
#include "sched.h"
#include "send.h"
#include "session.h"
#include "stream.h"
#include "unacked.h"
#include "wire.h"

#include "algo/hashtable.h"
#include "binary/serialize.h"
#include "meta/arraysize.h"
#include "os/clock.h"
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
	bool send_ctrl_ret;

	int reset_calls;
	int suspend_calls;

	int recv_copy_calls;
	size_t recv_copy_len;
	bool recv_copy_free_streams;
	int abort_calls;
	enum mux_status abort_code;
	bool abort_free_streams;
	int recv_rst_calls;
	uint_fast16_t recv_rst_status;
	int recv_fin_calls;
	int recv_window_calls;
	uint_fast32_t recv_window_inc;
	bool recv_window_free_streams;
	int check_ack_calls;
	int stream_start_calls;
	int stream_free_calls;
	int stream_close_calls;

	int notify_write_calls;
	int flush_oob_calls;
	int flush_resp_calls;
	int emit_ack_calls;
	int coalesce_arm_calls;

	int event_calls;
	enum mux_event event_type;
	int_least64_t event_ns;

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
	/* Handshake outcome the hello spy applies after consuming its frame. */
	bool hello_resets;
	bool hello_establishes;
	bool hello_tx_pending;

	bool wire_recv_ret;
	size_t wire_recv_nread;
	const unsigned char *wire_recv_data;
	int wire_recv_calls;
	int wire_has_pending_remaining;
	bool bytebuf_reserve_ret;

	double keepalive_ret;
} g;

static void spies_reset(void)
{
	g = (struct spies){
		.send_ctrl_ret = true,
		.send_oob_ret = true,
		.add_stream_ret = true,
		.ack_trim_ret = { .ok = true },
		.wire_recv_ret = true,
		.bytebuf_reserve_ret = true,
		.keepalive_ret = 10.0,
	};
}

/* Collaborator stubs.  Pulled in before recv.c so its external references
 * bind to these definitions. */

bool mux_session_send_ctrl(
	struct mux_session *restrict ss, uint_fast16_t stream_id,
	uint_fast8_t flags, uint_fast32_t extra)
{
	(void)ss;
	g.send_ctrl_calls++;
	g.send_ctrl_id = stream_id;
	g.send_ctrl_flags = flags;
	g.send_ctrl_extra = extra;
	return g.send_ctrl_ret;
}

bool mux_session_send_oob(
	struct mux_session *restrict ss, uint_fast8_t extra,
	const unsigned char *restrict payload, size_t payload_len)
{
	(void)ss;
	(void)payload;
	g.send_oob_calls++;
	g.send_oob_extra = extra;
	g.send_oob_len = payload_len;
	return g.send_oob_ret;
}

void mux_session_flush_oob(struct mux_session *restrict ss)
{
	(void)ss;
	g.flush_oob_calls++;
}

void mux_session_flush_resp(struct mux_session *ss)
{
	(void)ss;
	g.flush_resp_calls++;
}

void mux_session_emit_ack(struct mux_session *restrict ss)
{
	(void)ss;
	g.emit_ack_calls++;
}

void mux_notify_write(struct mux_session *restrict ss)
{
	(void)ss;
	g.notify_write_calls++;
}

void mux_session_reset(struct mux_session *ss)
{
	g.reset_calls++;
	ss->state = SESSION_CLOSED;
}

void mux_session_suspend(struct mux_session *ss)
{
	g.suspend_calls++;
	ss->state = SESSION_SUSPENDED;
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

void mux_session_log_frame_header(
	const struct mux_session *restrict ss, const char *restrict what,
	const unsigned char *restrict raw,
	const struct mux_header *restrict hdr)
{
	(void)ss;
	(void)what;
	(void)raw;
	(void)hdr;
}

double mux_keepalive_interval(const struct mux_session *restrict ss)
{
	(void)ss;
	return g.keepalive_ret;
}

void mux_stream_abort(struct mux_stream *s, const enum mux_status code)
{
	g.abort_calls++;
	g.abort_code = code;
	if (g.abort_free_streams) {
		/* Reproduce the drain cascade a real mux_stream_abort() triggers when it
		 * takes down the last active stream of a draining session, exactly as
		 * the mux_stream_recv_copy spy below does. */
		struct mux_session *const ss = s->session;
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
		ss->state = SESSION_CLOSING;
		bytebuf_reset(ss->wire.recvbuf);
	}
}

void mux_stream_recv_copy(
	struct mux_stream *s, const unsigned char *restrict payload,
	size_t payload_len)
{
	(void)payload;
	g.recv_copy_calls++;
	g.recv_copy_len = payload_len;
	if (g.recv_copy_free_streams) {
		/* Reproduce the drain cascade mux_stream_recv_copy() triggers when it
		 * aborts the last active stream of a draining session:
		 * mux_session_initiate_shutdown() -> mux_sched_free_streams() (frees every
		 * stream and nulls the table) + mux_wire_discard_buffers() (resets the
		 * recvbuf), then SESSION_CLOSING. */
		struct mux_session *const ss = s->session;
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
		ss->state = SESSION_CLOSING;
		bytebuf_reset(ss->wire.recvbuf);
	}
}

void mux_stream_recv_rst(struct mux_stream *s, const uint_fast16_t status)
{
	(void)s;
	g.recv_rst_calls++;
	g.recv_rst_status = status;
}

void mux_stream_recv_fin(struct mux_stream *s)
{
	(void)s;
	g.recv_fin_calls++;
}

void mux_stream_recv_window(struct mux_stream *s, uint_fast32_t window_inc)
{
	g.recv_window_calls++;
	g.recv_window_inc = window_inc;
	if (g.recv_window_free_streams) {
		/* Reproduce the drain cascade mux_stream_recv_window() triggers when a
		 * spec §6.6 credit overflow aborts the last active stream of a
		 * draining session: mux_sched_free_streams() (frees every stream and
		 * nulls the table) + mux_wire_discard_buffers() (resets the recvbuf),
		 * then SESSION_CLOSING -- identical to the recv_copy spy above. */
		struct mux_session *const ss = s->session;
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
		ss->state = SESSION_CLOSING;
		bytebuf_reset(ss->wire.recvbuf);
	}
}

void mux_stream_check_ack(struct mux_stream *restrict s)
{
	(void)s;
	g.check_ack_calls++;
}

void mux_stream_start(struct mux_stream *s)
{
	g.stream_start_calls++;
	/* Mirror production: the active opener's SYN|ACK collapses SYN_SENT to
	 * ESTABLISHED. process_syn_payload requires that transition to deliver a
	 * SYN|ACK fast-open response, so a no-op spy would leave the payload branch
	 * unreachable on the SYN|ACK path. */
	s->state = STREAM_ESTABLISHED;
}

void mux_stream_free(struct mux_stream *s)
{
	(void)s;
	g.stream_free_calls++;
}

void mux_stream_do_close(struct mux_stream *s)
{
	(void)s;
	g.stream_close_calls++;
}

struct mux_stream *mux_stream_new(
	struct mux_session *restrict ss, uint_fast16_t id, bool active_open)
{
	(void)ss;
	(void)id;
	(void)active_open;
	g.stream_new_calls++;
	return g.stream_new_ret;
}

int mux_stream_format_tag(
	char *restrict buf, size_t buflen, const struct mux_stream *restrict s)
{
	(void)s;
	return snprintf(buf, buflen, "[test]");
}

struct mux_stream *
mux_sched_find_stream(struct mux_session *restrict ss, uint_fast16_t id)
{
	(void)ss;
	(void)id;
	g.find_stream_calls++;
	return g.find_stream_ret;
}

bool mux_sched_add_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	(void)ss;
	(void)s;
	g.add_stream_calls++;
	return g.add_stream_ret;
}

void mux_sched_coalesce_arm(struct mux_session *restrict ss)
{
	(void)ss;
	g.coalesce_arm_calls++;
}

void mux_estimator_add(struct mux_session *restrict ss, uint_fast64_t bytes)
{
	(void)ss;
	g.est_add_calls++;
	g.est_add_bytes = bytes;
}

void mux_estimator_add_acked(
	struct mux_session *restrict ss, uint_fast64_t bytes)
{
	(void)ss;
	g.est_add_acked_calls++;
	g.est_add_acked_bytes = bytes;
}

void mux_estimator_calculate(
	struct mux_session *restrict ss, int_fast64_t sent_ns)
{
	(void)ss;
	g.est_calc_calls++;
	g.est_calc_sent_ns = sent_ns;
}

size_t mux_estimator_rx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return g.est_window_ret;
}

size_t mux_estimator_tx_window_size(const struct estimator_ctx *restrict est)
{
	(void)est;
	return g.est_window_ret;
}

struct unacked_ack_result
mux_unacked_ack_recv(struct mux_session *restrict ss, uint_fast32_t count)
{
	(void)ss;
	g.ack_trim_calls++;
	g.ack_trim_count = count;
	return g.ack_trim_ret;
}

bool mux_handshake_process_hello(
	struct mux_session *ss, const struct mux_header *restrict hdr,
	size_t frame_size)
{
	(void)hdr;
	g.hello_calls++;
	/* Mimic the real handler: consume the frame it parsed, then either reject
	 * the hello or complete the handshake -- possibly with our own reply
	 * still queued for the transport. */
	bytebuf_consume(ss->wire.recvbuf, frame_size);
	if (g.hello_resets) {
		mux_session_reset(ss);
		return false;
	}
	if (g.hello_establishes) {
		ss->state = SESSION_ESTABLISHED;
		ss->wire.tx_pending = g.hello_tx_pending;
	}
	return true;
}

bool mux_wire_recv(
	struct mux_session *ss, unsigned char *restrict buf,
	size_t *restrict len)
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

bool mux_wire_has_pending(const struct mux_session *restrict ss)
{
	(void)ss;
	if (g.wire_has_pending_remaining > 0) {
		g.wire_has_pending_remaining--;
		return true;
	}
	return false;
}

bool mux_bytebuf_reserve(
	struct bytebuf **restrict rbp, size_t need, bool can_grow)
{
	(void)rbp;
	(void)need;
	(void)can_grow;
	/* The fixture pre-sizes recvbuf large enough; never grow here unless a
	 * test is exercising the reserve-failure (OOM) path. */
	return g.bytebuf_reserve_ret;
}

void mux_bytebuf_shrink(struct bytebuf **restrict rbp, size_t target_cap)
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
const struct mux_session_config mux_session_config_default = {
	.max_frame_payload = 65536 - MUX_FRAME_HEADER_SIZE,
	.readahead = 128 * 1024,
};

/* Pull in the unit under test after the stubs so its references bind here. */
#include "recv.c"

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
		.max_payload = (uint_least32_t)mux_session_config_default
				       .max_frame_payload,
		.readahead = (size_t)mux_session_config_default.readahead,
		.session_window = 8,
		.stream_window = 4,
		.wire = { .rx_open = true },
	};
	fx->ss.wire.recvbuf = bytebuf_new(RECVBUF_CAP);
	if (fx->ss.wire.recvbuf == NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	/* A live (empty) stream table is the normal established-session state;
	 * production nulls it only via the drain cascade (session_streams_freed),
	 * which the recv-path guards key off. */
	fx->ss.sched.streams = table_new(&mux_stream_table_opts);
	if (fx->ss.sched.streams == NULL) {
		bytebuf_free(fx->ss.wire.recvbuf);
		fx->ss.wire.recvbuf = NULL;
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
	bytebuf_free(fx->ss.wire.recvbuf);
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
	unsigned char *const p = bytebuf_write_ptr(fx->ss.wire.recvbuf);
	mux_write_header(p, hdr);
	memset(p + MUX_FRAME_HEADER_SIZE, 0, hdr->length);
	bytebuf_produce(fx->ss.wire.recvbuf, frame_size);
}

/* A bare stream with the given id and state; spies never dereference more.
 * grant_sent carries mux_stream_new()'s implicit initial credit (frame.h) so the
 * fast-open credit check in process_syn_payload sees what production would. */
static struct mux_stream make_stream(uint_least16_t id, enum stream_state state)
{
	return (struct mux_stream){
		.id = id,
		.state = state,
		.grant_sent = MUX_DEFAULT_SEND_WINDOW,
	};
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
	/* CLOSE_WAIT / CLOSING accept ACK and/or FIN, plus a resume-replayed
	 * SYN|ACK (SYN is idempotent once ACK is present, same carve-out as
	 * ESTABLISHED/FIN_WAIT) -- but never a bare SYN with no ACK. */
	struct mux_stream cw = make_stream(1, STREAM_CLOSE_WAIT);
	T_EXPECT(validate_flags_by_stream(&cw, MUX_FLAG_ACK));
	T_EXPECT(validate_flags_by_stream(&cw, MUX_FLAG_FIN));
	T_EXPECT(validate_flags_by_stream(&cw, MUX_FLAG_ACK | MUX_FLAG_FIN));
	T_EXPECT(validate_flags_by_stream(&cw, MUX_FLAG_SYN | MUX_FLAG_ACK));
	T_EXPECT(validate_flags_by_stream(
		&cw, MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_PUSH));
	T_EXPECT(!validate_flags_by_stream(&cw, 0));
	T_EXPECT(!validate_flags_by_stream(&cw, MUX_FLAG_PUSH));
	T_EXPECT(!validate_flags_by_stream(&cw, MUX_FLAG_SYN));

	struct mux_stream cl = make_stream(1, STREAM_CLOSING);
	T_EXPECT(validate_flags_by_stream(&cl, MUX_FLAG_FIN));
	T_EXPECT(validate_flags_by_stream(&cl, MUX_FLAG_SYN | MUX_FLAG_ACK));
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
	const bool ctrl_rejected =
		!is_valid_peer_stream_id(&fx.ss, STREAMID_CTRL);

	/* Server (accepted) peers must open odd ids; clients open even ids. */
	fx.ss.accepted = true;
	const bool accepted_odd_ok = is_valid_peer_stream_id(&fx.ss, 3);
	const bool accepted_even_rejected = !is_valid_peer_stream_id(&fx.ss, 4);

	fx.ss.accepted = false;
	const bool client_even_ok = is_valid_peer_stream_id(&fx.ss, 4);
	const bool client_odd_rejected = !is_valid_peer_stream_id(&fx.ss, 3);

	/* Teardown first so a failing assert can't leak the fixture. */
	rf_teardown(&fx);

	T_EXPECT(ctrl_rejected);
	T_EXPECT(accepted_odd_ok);
	T_EXPECT(accepted_even_rejected);
	T_EXPECT(client_even_ok);
	T_EXPECT(client_odd_rejected);
}

/* mux_session_update_session_window / session_update_stream_window. */

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
	mux_session_update_session_window(&fx.ss, 0);
	const uint_least32_t initial =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	const uint_least32_t window_after_floor = fx.ss.session_window;

	/* Idempotent: same target is a no-op (no stall side effects). */
	mux_session_update_session_window(&fx.ss, 0);
	const uint_least32_t window_after_noop = fx.ss.session_window;
	const int notify_after_noop = g.notify_write_calls;

	/* peer_stream_window acts as a floor above the initial window. */
	fx.ss.peer_stream_window = initial + 10u;
	mux_session_update_session_window(&fx.ss, 0);
	const uint_least32_t window_after_peer_floor = fx.ss.session_window;

	/* Teardown before the asserts; T_FAILNOW would skip it otherwise. */
	rf_teardown(&fx);

	T_EXPECT_EQ(window_after_floor, initial);
	T_EXPECT_EQ(window_after_noop, initial);
	T_EXPECT_EQ(notify_after_noop, 0);
	T_EXPECT_EQ(window_after_peer_floor, (uint_least32_t)(initial + 10u));
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
	mux_session_update_session_window(
		&fx.ss, (size_t)10u * MUX_WINDOW_UNIT);

	const bool stalled = fx.ss.unacked.stalled;
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT(!stalled);
	T_EXPECT_EQ(g.notify_write_calls, 1);
}

T_DECLARE_CASE(test_update_stream_window_grows_and_iterates)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Two streams in the table (the fixture provides an empty one): one below
	 * the new window (grown by the callback) and one already above it (left
	 * untouched, the early return). */
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

	const uint_least32_t stream_window_after = fx.ss.stream_window;
	const uint_least32_t s_low_window = s_low.recv_window;
	const uint_least32_t s_high_window = s_high.recv_window;
	const int check_ack_after_grow = g.check_ack_calls;

	/* Idempotent second call with the same target does nothing. */
	g.check_ack_calls = 0;
	session_update_stream_window(&fx.ss, (size_t)5u * MUX_WINDOW_UNIT);
	const int check_ack_after_noop = g.check_ack_calls;

	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(stream_window_after, (uint_least32_t)5);
	/* The below-target stream grew and asked for an ACK check; the
	 * above-target stream was left as is. */
	T_EXPECT(s_low_window > 0);
	T_EXPECT_EQ(s_high_window, (uint_least32_t)(100u * MUX_WINDOW_UNIT));
	T_EXPECT_EQ(check_ack_after_grow, 1);
	T_EXPECT_EQ(check_ack_after_noop, 0);
}

T_DECLARE_CASE(test_update_stream_window_floors_to_initial)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* window_bytes=0 must clamp up to the initial-frames floor, exactly
	 * like mux_session_update_session_window, not just to 1 frame. */
	const uint_least32_t initial =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	fx.ss.stream_window = 1;
	session_update_stream_window(&fx.ss, 0);
	const uint_least32_t window_after_zero = fx.ss.stream_window;

	/* A small but nonzero request still below the floor clamps the same
	 * way. */
	fx.ss.stream_window = 1;
	session_update_stream_window(&fx.ss, (size_t)MUX_WINDOW_UNIT);
	const uint_least32_t window_after_small = fx.ss.stream_window;

	/* Idempotent at the floor: a second call with the same low target
	 * changes nothing further. */
	session_update_stream_window(&fx.ss, (size_t)MUX_WINDOW_UNIT);
	const uint_least32_t window_after_idempotent = fx.ss.stream_window;

	/* Teardown first so a failing assert can't leak the fixture. */
	rf_teardown(&fx);

	T_EXPECT_EQ(window_after_zero, initial);
	T_EXPECT(window_after_zero > (uint_least32_t)1);
	T_EXPECT_EQ(window_after_small, initial);
	T_EXPECT_EQ(window_after_idempotent, initial);
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
				.stream_id = 1,
				.extra = MUX_STATUS_REFUSED_STREAM };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown before the asserts; T_FAILNOW would skip it otherwise. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.recv_rst_calls, 1);
	/* The peer's status code must reach mux_stream_recv_rst,
	 * not just trigger the call. */
	T_EXPECT_EQ(
		g.recv_rst_status, (uint_fast16_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(readable, (size_t)0);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT(s.rst_sent);
	T_EXPECT_EQ(g.recv_rst_calls, 1);
	/* Not an actual peer RST, so this must report the
	 * locally-decided reason (matching the RST just sent above), not
	 * hdr->extra, which belongs to the invalid frame instead. */
	T_EXPECT_EQ(
		g.recv_rst_status, (uint_fast16_t)MUX_STATUS_PROTOCOL_ERROR);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* When the invalid-flags RST enqueue OOMs (mux_session_send_ctrl returns false),
 * rst_sent must stay false so the RST is retried on the next frame rather than
 * being permanently suppressed -- the #41 retryable-RST contract, which the
 * unconditional latch defeated. */
T_DECLARE_CASE(test_dispatch_by_stream_invalid_flags_rst_oom_retryable)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 1 };
	push_frame(&fx, &h);

	g.send_ctrl_ret =
		false; /* simulate a frame-pool OOM on the RST enqueue */
	dispatch_by_stream(&fx.ss, &s, &h);

	const bool rst_sent = s.rst_sent;
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	/* The RST could not be enqueued, so it must stay retryable. */
	T_EXPECT(!rst_sent);
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

	const uint_least32_t peer_stream_window = fx.ss.peer_stream_window;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.recv_window_calls, 1);
	T_EXPECT_EQ(g.recv_window_inc, (uint_fast32_t)3);
	T_EXPECT_EQ(g.stream_start_calls, 1);
	/* peer_stream_window is recovered from send_window / MUX_WINDOW_UNIT. */
	T_EXPECT_EQ(peer_stream_window, (uint_least32_t)2);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* on_event spy: records the STREAM_ESTABLISHED emission so a SYN|ACK case can
 * assert the one-shot latency report fires exactly once. */
static void event_spy_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	(void)data;
	(void)ss;
	g.event_calls++;
	g.event_type = event;
	g.event_ns = edata.stream_established.ns;
}

/* stream_report_established: the first SYN|ACK reports SYN-to-SYN|ACK latency
 * via MUX_EVENT_STREAM_ESTABLISHED, derived from the stream's syn_sent_ns, then
 * zeroes syn_sent_ns so a resume-replayed SYN|ACK never re-fires the event. No
 * other case assigns syn_sent_ns, so the latency computation, the emission, and
 * the one-shot reset are otherwise unreached. */
T_DECLARE_CASE(test_dispatch_by_stream_synack_reports_established_once)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.callbacks.on_event = event_spy_cb;
	struct mux_stream s = make_stream(1, STREAM_SYN_SENT);
	s.send_window = 2u * MUX_WINDOW_UNIT;
	/* Stamp the SYN as sent a known interval ago; the reported latency must be
	 * at least that delta (the real monotonic clock only advances further). */
	const int_least64_t delta = INT64_C(5000000); /* 5 ms */
	s.syn_sent_ns = (int_least64_t)clock_monotonic_ns() - delta;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
				.stream_id = 1,
				.extra = 3 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	const int event_calls_first = g.event_calls;
	const int event_type = (int)g.event_type;
	const int_least64_t event_ns = g.event_ns;
	const int_least64_t syn_sent_after = s.syn_sent_ns;

	/* A resume-replayed SYN|ACK: syn_sent_ns was reset to zero, so the report
	 * fires only the first time. */
	push_frame(&fx, &h);
	dispatch_by_stream(&fx.ss, &s, &h);
	const int event_calls_second = g.event_calls;

	rf_teardown(&fx);

	T_EXPECT_EQ(event_calls_first, 1);
	T_EXPECT_EQ(event_type, (int)MUX_EVENT_STREAM_ESTABLISHED);
	T_EXPECT(event_ns > 0);
	T_EXPECT(event_ns >= delta);
	/* The one-shot reset ran, so the replay reported nothing further. */
	T_EXPECT_EQ(syn_sent_after, (int_least64_t)0);
	T_EXPECT_EQ(event_calls_second, 1);
}

T_DECLARE_CASE(test_dispatch_by_stream_synack_idempotent)
{
	/* A duplicate SYN|ACK in any state validate_flags_by_stream() lets it
	 * through past SYN_SENT is consumed without re-running establishment
	 * side effects (resume replay tolerance), and without re-applying the
	 * ACK credit the original SYN|ACK already granted. */
	static const enum stream_state states[] = {
		STREAM_ESTABLISHED,
		STREAM_FIN_WAIT,
		STREAM_CLOSE_WAIT,
		STREAM_CLOSING,
	};
	for (size_t i = 0; i < ARRAY_SIZE(states); i++) {
		struct recv_fixture fx;
		if (rf_setup(&fx) != 0) {
			T_FATAL("rf_setup failed");
			return;
		}
		struct mux_stream s = make_stream(1, states[i]);
		struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
					.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
					.stream_id = 1,
					.extra = 3 };
		push_frame(&fx, &h);

		dispatch_by_stream(&fx.ss, &s, &h);

		const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
		/* Teardown first so a failing assert can't leak the fixture. */
		rf_teardown(&fx);

		T_EXPECT_EQ((int)s.state, (int)states[i]);
		T_EXPECT_EQ(g.stream_start_calls, 0);
		T_EXPECT_EQ(g.recv_window_calls, 0);
		T_EXPECT_EQ(readable, (size_t)0);
	}
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_copy_len, (size_t)64);
	T_EXPECT_EQ(g.recv_fin_calls, 1);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* dispatch_by_stream PUSH|FIN: when mux_stream_recv_copy() aborts the last active
 * stream of a draining session, the drain cascade frees the stream and resets
 * the recvbuf; dispatch_by_stream() must not consume the reset ring nor call
 * mux_stream_recv_fin() on the freed stream. Without the guard the consume would
 * assert on the reset ring (readable 0 < frame_size). */
T_DECLARE_CASE(test_dispatch_by_stream_push_fin_survives_stream_freed)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	s.session = &fx.ss;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH | MUX_FLAG_FIN,
				.stream_id = 1,
				.length = 64 };
	push_frame(&fx, &h);
	g.recv_copy_free_streams = true;

	dispatch_by_stream(&fx.ss, &s, &h);

	const bool streams_freed = fx.ss.sched.streams == NULL;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown before the asserts; T_FAILNOW would skip it otherwise. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_fin_calls, 0);
	T_EXPECT(streams_freed);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* dispatch_by_stream ACK|PUSH: mux_stream_recv_window() runs before the PUSH copy
 * and is itself free-capable -- a spec §6.6 credit overflow aborts the stream,
 * and on the last active stream of a draining session the cascade frees it and
 * resets the recvbuf. The post-copy guard cannot cover this earlier free, so
 * dispatch_by_stream() must bail right after the window update: no copy into the
 * freed stream, no FIN on it, no consume of the reset ring. Without the guard
 * the copy runs on freed memory and the consume asserts on the reset ring. */
T_DECLARE_CASE(test_dispatch_by_stream_ack_push_survives_window_abort)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	s.session = &fx.ss;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK | MUX_FLAG_PUSH,
				.stream_id = 1,
				.length = 64 };
	push_frame(&fx, &h);
	g.recv_window_free_streams = true;

	dispatch_by_stream(&fx.ss, &s, &h);

	const bool streams_freed = fx.ss.sched.streams == NULL;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.recv_window_calls, 1);
	T_EXPECT_EQ(g.recv_copy_calls, 0);
	T_EXPECT_EQ(g.recv_fin_calls, 0);
	T_EXPECT(streams_freed);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* dispatch_by_stream SYN|ACK: mux_stream_recv_window() runs on the SYN branch too
 * and is free-capable -- a spec §6.6 credit overflow can abort the stream, and
 * on the last active stream of a draining session the cascade frees it and
 * resets the recvbuf. The SYN-branch guard must bail right after the window
 * update: no establishment side effects (session window / mux_stream_start /
 * process_syn_payload) and no consume of the reset ring. Without the guard,
 * process_syn_payload's consume runs on the reset ring and asserts. */
T_DECLARE_CASE(test_dispatch_by_stream_synack_survives_window_abort)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_SYN_SENT);
	s.session = &fx.ss;
	s.send_window = 2u * MUX_WINDOW_UNIT;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
				.stream_id = 1,
				.extra = 3 };
	push_frame(&fx, &h);
	g.recv_window_free_streams = true;

	dispatch_by_stream(&fx.ss, &s, &h);

	const int recv_window_calls = g.recv_window_calls;
	const int stream_start_calls = g.stream_start_calls;
	const bool streams_freed = fx.ss.sched.streams == NULL;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	rf_teardown(&fx);

	T_EXPECT_EQ(recv_window_calls, 1);
	/* The guard fires right after the window update, before establishment. */
	T_EXPECT_EQ(stream_start_calls, 0);
	T_EXPECT(streams_freed);
	T_EXPECT_EQ(readable, (size_t)0);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.recv_window_calls, 1);
	T_EXPECT_EQ(g.recv_window_inc, (uint_fast32_t)5);
	T_EXPECT_EQ(s.unacked_bytes, (uint_least32_t)0);
	T_EXPECT_EQ(readable, (size_t)0);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	/* RST on a closed stream is dropped silently, not forwarded. */
	T_EXPECT_EQ(g.recv_rst_calls, 0);
	T_EXPECT_EQ(g.send_ctrl_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
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
	const int send_ctrl_after_first = g.send_ctrl_calls;
	const bool rst_sent_after_first = s.rst_sent;

	/* Second late frame: suppressed, no further RST. */
	push_frame(&fx, &h);
	dispatch_by_stream(&fx.ss, &s, &h);
	const int send_ctrl_after_second = g.send_ctrl_calls;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);

	/* Teardown before the asserts; T_FAILNOW would skip it otherwise. */
	rf_teardown(&fx);

	T_EXPECT_EQ(send_ctrl_after_first, 1);
	T_EXPECT(rst_sent_after_first);
	T_EXPECT_EQ(send_ctrl_after_second, 1);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* dispatch_no_stream: routing for an unknown stream id. */

T_DECLARE_CASE(test_dispatch_no_stream_rst_ignored)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_RST,
				.stream_id = 7 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown first so a failing assert can't leak the fixture. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(g.send_ctrl_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
}

T_DECLARE_CASE(test_dispatch_no_stream_bad_syn_flags_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A parity-valid peer SYN combined with FIN closes the connection
	 * before stream admission. A dialing session expects even peer ids. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_FIN,
				.stream_id = 2 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(g.stream_new_calls, 0);
	T_EXPECT_EQ(g.add_stream_calls, 0);
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

	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
}

T_DECLARE_CASE(test_dispatch_no_stream_non_syn_bad_parity_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Accepted sessions expect odd peer ids even for non-SYN frames. */
	fx.ss.accepted = true;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 4,
				.length = 8 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_new_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
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
	/* Populate the fixture's table so its size reaches the cap. */
	void *elem = (void *)(uintptr_t)0x1;
	fx.ss.sched.streams = table_set(
		fx.ss.sched.streams, (const void *)(uintptr_t)9, &elem);
	T_EXPECT(fx.ss.sched.streams != NULL);

	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN,
				.stream_id = 3 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_new_calls, 0);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown first so a failing assert can't leak the fixture. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.stream_new_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_close_calls, 1);
	T_EXPECT(newstream.rst_sent);
	T_EXPECT_EQ(readable, (size_t)0);
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

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	T_EXPECT_EQ(g.stream_close_calls, 1);
}

/* Spec §4.3.1: the active opener's fast-open payload on the opening SYN MUST NOT
 * exceed the flat 16384-octet implicit initial credit. dispatch_no_stream
 * rejects an oversized fast-open by closing the connection -- before it commits
 * any stream resources -- exactly as it does for the sibling bad-flags /
 * bad-parity §4.3.1 violations. The cap is the constant, not the live
 * grant_sent: in production on_accept would raise grant_sent to 65536 before
 * process_syn_payload's live-grant check runs, so that check can never see this
 * violation, which is why the flat cap is enforced up front here. */
T_DECLARE_CASE(test_dispatch_no_stream_oversized_fastopen_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	fx.ss.callbacks.on_accept = accept_ok_cb;
	static struct mux_stream newstream;
	newstream = make_stream(3, STREAM_SYN_RECEIVED);
	g.stream_new_ret = &newstream;
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	/* One octet past the flat 16384 cap; still a legal 16-bit frame length. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_PUSH,
				.stream_id = 3,
				.extra = 0,
				.length = MUX_DEFAULT_SEND_WINDOW + 1 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	const int reset_calls = g.reset_calls;
	const int stream_new_calls = g.stream_new_calls;
	const int copy_calls = g.recv_copy_calls;
	const int abort_calls = g.abort_calls;
	const uint_least64_t pushed =
		COUNTER_LOAD(fx.ss.cnt.traffic.byt_push_recv);
	rf_teardown(&fx);

	T_EXPECT_EQ(reset_calls, 1); /* connection closed */
	/* Rejected before committing any stream: no allocation, no on_accept. */
	T_EXPECT_EQ(stream_new_calls, 0);
	T_EXPECT_EQ(copy_calls, 0); /* payload never delivered */
	T_EXPECT_EQ(
		abort_calls,
		0); /* whole connection reset, not a stream abort */
	/* A rejected payload was never received, so it must not reach the traffic
	 * counter. */
	T_EXPECT_EQ(pushed, (uint_least64_t)0);
}

/* Spec conformance I-6 (the credit boundary): a fast-open of exactly the
 * granted credit is legal and must be accepted with no RST -- the check is
 * strictly greater-than. */
T_DECLARE_CASE(test_process_syn_payload_accepts_credit_boundary_fastopen)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	fx.ss.callbacks.on_accept = accept_ok_cb;
	static struct mux_stream newstream;
	newstream = make_stream(3, STREAM_SYN_RECEIVED);
	g.stream_new_ret = &newstream;
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_PUSH,
				.stream_id = 3,
				.extra = 0,
				.length = MUX_DEFAULT_SEND_WINDOW };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	const int abort_calls = g.abort_calls;
	const int copy_calls = g.recv_copy_calls;
	const size_t copy_len = g.recv_copy_len;
	const uint_least64_t pushed =
		COUNTER_LOAD(fx.ss.cnt.traffic.byt_push_recv);
	rf_teardown(&fx);

	T_EXPECT_EQ(abort_calls, 0);
	T_EXPECT_EQ(copy_calls, 1);
	T_EXPECT_EQ(copy_len, (size_t)MUX_DEFAULT_SEND_WINDOW);
	/* Accepted at the boundary, so it counts as received payload in full. */
	T_EXPECT_EQ(pushed, (uint_least64_t)MUX_DEFAULT_SEND_WINDOW);
}

/* The SYN|ACK reject path -- process_syn_payload's live-grant check, now the
 * path where that check actually fires -- carries the same drain-cascade hazard
 * as the copy path: mux_stream_abort can take down the last active stream of a
 * draining session, whose shutdown frees the streams and resets this recvbuf,
 * so the frame must not be consumed from a ring the cascade already reset. */
T_DECLARE_CASE(test_dispatch_by_stream_synack_reject_guards_drain_cascade)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_SYN_SENT);
	/* The cascade spy reaches the session through the stream, as the real
	 * mux_stream_abort does. grant_sent is make_stream()'s implicit 16384. */
	s.session = &fx.ss;
	s.send_window = 2u * MUX_WINDOW_UNIT;
	g.abort_free_streams = true;
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	/* A SYN|ACK fast-open response one octet past the credit we granted. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_ACK |
					 MUX_FLAG_PUSH,
				.stream_id = 1,
				.extra = 0,
				.length = MUX_DEFAULT_SEND_WINDOW + 1 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	const int abort_calls = g.abort_calls;
	const enum mux_status abort_code = g.abort_code;
	const bool streams_freed = fx.ss.sched.streams == NULL;
	/* The cascade reset the ring; nothing may consume from it afterwards. */
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	rf_teardown(&fx);

	T_EXPECT_EQ(abort_calls, 1);
	T_EXPECT_EQ((int)abort_code, (int)MUX_STATUS_FLOW_CONTROL_ERROR);
	T_EXPECT(streams_freed);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* process_syn_payload copy path (fast-open SYN): when mux_stream_recv_copy() aborts
 * the last active stream of a draining session, the drain cascade frees the
 * streams and resets the recvbuf. The guard after the copy must stop before the
 * consume; without it the consume runs on the reset ring and asserts. The ACK
 * path already sets recv_copy_free_streams, but this fast-open guard was never
 * exercised (the accept-ok case leaves it false). */
T_DECLARE_CASE(test_process_syn_payload_copy_guards_drain_cascade)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	fx.ss.callbacks.on_accept = accept_ok_cb;
	static struct mux_stream newstream;
	newstream = make_stream(3, STREAM_SYN_RECEIVED);
	/* The cascade spy reaches the session through the stream, as the real
	 * mux_stream_recv_copy does; mux_stream_new() would have wired this up. */
	newstream.session = &fx.ss;
	g.stream_new_ret = &newstream;
	g.recv_copy_free_streams = true;
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	/* An in-credit fast-open payload: copied, then the copy fires the cascade. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_PUSH,
				.stream_id = 3,
				.extra = 0,
				.length = 16 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	const int copy_calls = g.recv_copy_calls;
	const int abort_calls = g.abort_calls;
	const bool streams_freed = fx.ss.sched.streams == NULL;
	/* The cascade reset the ring; nothing may consume from it afterwards. */
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	rf_teardown(&fx);

	T_EXPECT_EQ(copy_calls, 1);
	T_EXPECT_EQ(abort_calls, 0);
	T_EXPECT(streams_freed);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* Spec §4.3.1 on the SYN|ACK path: the passive opener's fast-open response MUST
 * NOT exceed the credit the active opener granted -- grant_sent, the implicit
 * 16384 plus our SYN Extra. process_syn_payload rejects an over-credit
 * SYN|ACK|PUSH with FLOW_CONTROL_ERROR, never copies it, and still consumes the
 * frame. This is the path where the live-grant check actually fires; the SYN
 * path is bounded by the flat cap in dispatch_no_stream. Coverage here was
 * previously absent -- both SYN|ACK cases carried length = 0. */
T_DECLARE_CASE(test_dispatch_by_stream_synack_rejects_over_credit_fastopen)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_SYN_SENT);
	s.send_window = 2u * MUX_WINDOW_UNIT;
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	/* One octet past grant_sent (make_stream()'s implicit 16384). */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_ACK |
					 MUX_FLAG_PUSH,
				.stream_id = 1,
				.extra = 0,
				.length = MUX_DEFAULT_SEND_WINDOW + 1 };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	const int abort_calls = g.abort_calls;
	const enum mux_status abort_code = g.abort_code;
	const int copy_calls = g.recv_copy_calls;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	const uint_least64_t pushed =
		COUNTER_LOAD(fx.ss.cnt.traffic.byt_push_recv);
	rf_teardown(&fx);

	T_EXPECT_EQ(abort_calls, 1);
	T_EXPECT_EQ((int)abort_code, (int)MUX_STATUS_FLOW_CONTROL_ERROR);
	T_EXPECT_EQ(copy_calls, 0);
	T_EXPECT_EQ(pushed, (uint_least64_t)0);
	/* Consumed even though rejected, so the next frame stays aligned. */
	T_EXPECT_EQ(readable, (size_t)0);
}

/* Spec conformance I-6 on the SYN|ACK path: a fast-open response of exactly the
 * granted credit is legal and copied in full, with no abort -- the check is
 * strictly greater-than, matching the SYN-path boundary case. */
T_DECLARE_CASE(test_dispatch_by_stream_synack_accepts_credit_boundary_fastopen)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	struct mux_stream s = make_stream(1, STREAM_SYN_SENT);
	s.send_window = 2u * MUX_WINDOW_UNIT;
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_ACK |
					 MUX_FLAG_PUSH,
				.stream_id = 1,
				.extra = 0,
				.length = MUX_DEFAULT_SEND_WINDOW };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	const int abort_calls = g.abort_calls;
	const int copy_calls = g.recv_copy_calls;
	const size_t copy_len = g.recv_copy_len;
	const uint_least64_t pushed =
		COUNTER_LOAD(fx.ss.cnt.traffic.byt_push_recv);
	rf_teardown(&fx);

	T_EXPECT_EQ(abort_calls, 0);
	T_EXPECT_EQ(copy_calls, 1);
	T_EXPECT_EQ(copy_len, (size_t)MUX_DEFAULT_SEND_WINDOW);
	T_EXPECT_EQ(pushed, (uint_least64_t)MUX_DEFAULT_SEND_WINDOW);
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
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	/* SYN|PUSH delivers initial payload through process_syn_payload. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_SYN | MUX_FLAG_PUSH,
				.stream_id = 3,
				.extra = 1,
				.length = 16 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	const uint_least64_t pushed =
		COUNTER_LOAD(fx.ss.cnt.traffic.byt_push_recv);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.stream_close_calls, 0);
	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_copy_len, (size_t)16);
	T_EXPECT_EQ(readable, (size_t)0);
	/* The fast-open payload counts into byt_push_recv, same as an ordinary
	 * PUSH frame. */
	T_EXPECT_EQ(pushed, (uint_least64_t)16);
}

/* Deliver one 16-byte inbound payload -- an ordinary PUSH on an established
 * stream, or a SYN|PUSH fast-open through the accept path -- under the given
 * auto-window mode, leaving the spies to be read; false if setup failed. */
static bool drive_inbound_payload(
	const bool fastopen, const bool auto_stream, const bool auto_session)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		return false;
	}
	fx.ss.auto_stream_window = auto_stream;
	fx.ss.auto_session_window = auto_session;
	static struct mux_stream s;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION, .length = 16 };
	if (fastopen) {
		fx.ss.accepted = true;
		fx.ss.callbacks.on_accept = accept_ok_cb;
		s = make_stream(3, STREAM_SYN_RECEIVED);
		g.stream_new_ret = &s;
		h.flags = MUX_FLAG_SYN | MUX_FLAG_PUSH;
		h.stream_id = 3;
		push_frame(&fx, &h);
		dispatch_no_stream(&fx.ss, &h);
	} else {
		s = make_stream(1, STREAM_ESTABLISHED);
		h.flags = MUX_FLAG_PUSH;
		h.stream_id = 1;
		push_frame(&fx, &h);
		dispatch_by_stream(&fx.ss, &s, &h);
	}
	rf_teardown(&fx);
	return true;
}

/* Inbound PUSH payload is the only source of rx-side BDP samples: on both
 * delivery paths it feeds the estimator and flushes the probe it may arm
 * whenever either window is auto-sized, and never in manual mode. */
T_DECLARE_CASE(test_push_payload_feeds_estimator_in_auto_mode)
{
	static const struct {
		bool auto_stream;
		bool auto_session;
		int feeds;
	} modes[] = {
		{ false, false, 0 },
		{ true, false, 1 },
		{ false, true, 1 },
		{ true, true, 1 },
	};
	for (size_t i = 0; i < ARRAY_SIZE(modes); i++) {
		for (int fastopen = 0; fastopen <= 1; fastopen++) {
			if (!drive_inbound_payload(
				    fastopen, modes[i].auto_stream,
				    modes[i].auto_session)) {
				T_FATAL("rf_setup failed");
				return;
			}
			T_LOGF("mode %zu, fastopen=%d", i, fastopen);
			T_EXPECT_EQ(g.recv_copy_calls, 1);
			T_EXPECT_EQ(g.est_add_calls, modes[i].feeds);
			T_EXPECT_EQ(g.flush_oob_calls, modes[i].feeds);
			if (modes[i].feeds > 0) {
				T_EXPECT_EQ(
					g.est_add_bytes, (uint_least64_t)16);
			}
		}
	}
}

/* What one PUSH-payload delivery left behind, for comparing delivery paths. */
struct push_delivery {
	size_t copy_len;
	uint_least64_t pushed;
	size_t readable;
	int est_add_calls;
	uint_least64_t est_add_bytes;
	int flush_oob_calls;
};

/* Deliver one 16-byte PUSH payload carried by `flags` on stream 3 in `state`,
 * with the stream window auto-tuned so the estimator side runs.  A SYN without
 * ACK goes through the accept path, anything else to the known stream. */
static bool run_push_delivery(
	const uint_fast8_t flags, const enum stream_state state,
	struct push_delivery *restrict out)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		return false;
	}
	fx.ss.accepted = true;
	fx.ss.callbacks.on_accept = accept_ok_cb;
	fx.ss.auto_stream_window = true;
	mux_counter push_recv = 0;
	fx.ss.cnt.traffic.byt_push_recv = &push_recv;
	static struct mux_stream s;
	s = make_stream(3, state);
	s.send_window = 2u * MUX_WINDOW_UNIT;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = (uint_least8_t)flags,
				.stream_id = 3,
				.extra = 1,
				.length = 16 };
	push_frame(&fx, &h);

	if ((flags & (MUX_FLAG_SYN | MUX_FLAG_ACK)) == MUX_FLAG_SYN) {
		g.stream_new_ret = &s;
		dispatch_no_stream(&fx.ss, &h);
	} else {
		dispatch_by_stream(&fx.ss, &s, &h);
	}

	*out = (struct push_delivery){
		.copy_len = g.recv_copy_calls == 1 ? g.recv_copy_len : 0,
		.pushed = COUNTER_LOAD(fx.ss.cnt.traffic.byt_push_recv),
		.readable = bytebuf_readable(fx.ss.wire.recvbuf),
		.est_add_calls = g.est_add_calls,
		.est_add_bytes = g.est_add_bytes,
		.flush_oob_calls = g.flush_oob_calls,
	};
	rf_teardown(&fx);
	return true;
}

/* An ordinary PUSH, a SYN|ACK fast-open response and a SYN fast-open payload
 * all deliver through the same sequence: counted into byt_push_recv, copied,
 * consumed, and fed to the estimator with one OOB flush. */
T_DECLARE_CASE(test_push_delivery_same_on_every_path)
{
	static const struct {
		uint_fast8_t flags;
		enum stream_state state;
	} paths[] = {
		{ MUX_FLAG_PUSH, STREAM_ESTABLISHED },
		{ MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_PUSH,
		  STREAM_SYN_SENT },
		{ MUX_FLAG_SYN | MUX_FLAG_PUSH, STREAM_SYN_RECEIVED },
	};
	for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
		struct push_delivery d;
		if (!run_push_delivery(paths[i].flags, paths[i].state, &d)) {
			T_FATAL("rf_setup failed");
			return;
		}
		T_EXPECT_EQ(d.copy_len, (size_t)16);
		T_EXPECT_EQ(d.pushed, (uint_least64_t)16);
		T_EXPECT_EQ(d.readable, (size_t)0);
		T_EXPECT_EQ(d.est_add_calls, 1);
		T_EXPECT_EQ(d.est_add_bytes, (uint_least64_t)16);
		T_EXPECT_EQ(d.flush_oob_calls, 1);
	}
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.stream_new_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);
	/* The frame is already counted into recv_seq, so
	 * silently dropping it here (unlike the draining/max_streams
	 * branches) would leave the peer's opener hanging in SYN_SENT with
	 * no error signal. */
	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_INTERNAL_ERROR);
	T_EXPECT_EQ(readable, (size_t)0);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.add_stream_calls, 1);
	T_EXPECT_EQ(g.stream_free_calls, 1);
	/* Same as the mux_stream_new OOM branch above -- the
	 * frame is already counted into recv_seq, so this must not drop
	 * silently either. */
	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(g.send_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_INTERNAL_ERROR);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* Reserved-flag rejection is enforced upstream by dispatch_frame (covered by
 * test_dispatch_frame_reserved_flags_resets), which resets the session before
 * dispatch_no_stream is ever reached; dispatch_no_stream now ASSERTs that
 * invariant rather than re-checking it, so there is no reserved-flag path to
 * exercise here. */

T_DECLARE_CASE(test_dispatch_no_stream_late_nonsyn_rst)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	/* A non-SYN data frame for an unknown id: RST it, keep the session. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 7,
				.length = 8 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g.send_ctrl_extra, (uint_fast32_t)MUX_STATUS_PROTOCOL_ERROR);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
}

T_DECLARE_CASE(test_dispatch_no_stream_ignorable_terminal)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.accepted = true;
	/* A bare zero-length ACK|FIN for an unknown id is silently ignored. */
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK | MUX_FLAG_FIN,
				.stream_id = 7 };
	push_frame(&fx, &h);

	dispatch_no_stream(&fx.ss, &h);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_ctrl_calls, 0);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
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
	unsigned char *const p = bytebuf_write_ptr(fx.ss.wire.recvbuf);
	const struct mux_header h = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.stream_id = 1,
		.length = (uint_least16_t)MUX_MAX_PAYLOAD_SIZE,
	};
	mux_write_header(p, &h);
	bytebuf_produce(fx.ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE);

	dispatch_frame(&fx.ss);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	/* Not rejected; the partial frame stays buffered awaiting its body. */
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(readable, (size_t)MUX_FRAME_HEADER_SIZE);
}

/* Regression (#26): a reset inside the ctrl branch must stop the loop like one
 * in the stream path. mux_session_recv_ping's oversized-PING path resets the
 * session from a handler dispatch_ctrl_frame calls; unless that stops the loop
 * it would re-enter and dispatch the next frame on a CLOSED session. Two
 * back-to-back oversized PINGs: only the first may be dispatched. */
T_DECLARE_CASE(test_dispatch_frame_ctrl_reset_stops_loop)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.max_payload = 64; /* makes a 128-byte PING oversized */
	const struct mux_header ping = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
		.length = 128,
	};
	push_frame(&fx, &ping);
	push_frame(&fx, &ping);

	dispatch_frame(&fx.ss);

	rf_teardown(&fx);

	/* Only the first PING dispatched; the loop stopped on its reset rather
	 * than processing the second on a CLOSED session (which would reset
	 * again, giving 2). */
	T_EXPECT_EQ(g.reset_calls, 1);
}

/* dispatch_ctrl_frame reports a reset made by a handler it calls, not only its
 * own: an oversized PING is reset by mux_session_recv_ping, and the return
 * value alone must tell the caller to stop.  A discarded PROBE leaves the
 * session up and reports true. */
T_DECLARE_CASE(test_dispatch_ctrl_frame_reports_handler_reset)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.max_payload = 64; /* makes a 128-byte PING oversized */
	const struct mux_header probe = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PROBE,
		.length = 8,
	};
	const struct mux_header ping = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
		.length = 128,
	};
	push_frame(&fx, &probe);
	push_frame(&fx, &ping);

	const bool probe_ok = dispatch_ctrl_frame(
		&fx.ss, &probe, MUX_FRAME_HEADER_SIZE + probe.length);
	const int resets_after_probe = g.reset_calls;
	const bool ping_ok = dispatch_ctrl_frame(
		&fx.ss, &ping, MUX_FRAME_HEADER_SIZE + ping.length);
	const int state = fx.ss.state;

	rf_teardown(&fx);

	T_EXPECT(probe_ok);
	T_EXPECT_EQ(resets_after_probe, 0);
	T_EXPECT(!ping_ok);
	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(state, SESSION_CLOSED);
}

/* A fully-buffered oversized PUSH is delivered to the stream intact: the whole
 * payload (larger than the session's configured max_payload, 65528 here, but
 * still wire-legal) reaches mux_stream_recv_copy. */
T_DECLARE_CASE(test_dispatch_by_stream_oversized_push)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* MUX_MAX_PAYLOAD_SIZE (65535) is the 16-bit wire maximum and exceeds the
	 * fixture's configured max_payload (65528). The previous
	 * MUX_MAX_PAYLOAD_SIZE + 4096 wrapped in uint16 to an ordinary 4095. */
	const uint_least16_t len = (uint_least16_t)MUX_MAX_PAYLOAD_SIZE;
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 1,
				.length = len };
	push_frame(&fx, &h);

	dispatch_by_stream(&fx.ss, &s, &h);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_copy_len, (size_t)len);
	T_EXPECT_EQ(readable, (size_t)0);
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

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
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

	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.hello_calls, 1);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* A hello frame (version=0) arriving while still SESSION_HANDSHAKE -- its
 * ordinary arrival state -- must still reach mux_handshake_process_hello
 * unaffected by the pre-established gate below. */
T_DECLARE_CASE(test_dispatch_frame_hello_during_handshake_unaffected)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.state = SESSION_HANDSHAKE;
	struct mux_header h = { .version = 0, .stream_id = 0, .length = 4 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.hello_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* Queue a hello frame followed by one PUSH frame on stream 1, the shape of a
 * peer that pipelines its first data frame behind its hello; returns the PUSH
 * frame's size. */
static size_t push_hello_then_data(struct recv_fixture *restrict fx)
{
	const struct mux_header hello = { .version = 0,
					  .stream_id = 0,
					  .length = 4 };
	const struct mux_header data = { .version = MUX_PROTOCOL_VERSION,
					 .flags = MUX_FLAG_PUSH,
					 .stream_id = 1,
					 .length = 8 };
	push_frame(fx, &hello);
	push_frame(fx, &data);
	return MUX_FRAME_HEADER_SIZE + data.length;
}

/* A hello that resets the session stops the loop there: the frame queued
 * behind it belongs to a session that no longer exists and must not be
 * dispatched, nor re-reset as a pre-established frame. */
T_DECLARE_CASE(test_dispatch_frame_hello_reset_stops_loop)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.state = SESSION_HANDSHAKE;
	g.hello_resets = true;
	const size_t data_size = push_hello_then_data(&fx);

	dispatch_frame(&fx.ss);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	const enum session_state state = fx.ss.state;
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.hello_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(state, SESSION_CLOSED);
	T_EXPECT_EQ(g.find_stream_calls, 0);
	T_EXPECT_EQ(readable, data_size);
}

/* A hello that establishes the session while our own hello reply is still
 * queued (tx_pending) defers the frames behind it: they stay in recvbuf until
 * mux_session_on_send redispatches them once the reply has gone out. */
T_DECLARE_CASE(test_dispatch_frame_hello_established_defers_on_tx_pending)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.state = SESSION_HANDSHAKE;
	g.hello_establishes = true;
	g.hello_tx_pending = true;
	const size_t data_size = push_hello_then_data(&fx);

	dispatch_frame(&fx.ss);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	const enum session_state state = fx.ss.state;
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.hello_calls, 1);
	T_EXPECT_EQ(state, SESSION_ESTABLISHED);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(g.find_stream_calls, 0);
	T_EXPECT_EQ(g.recv_copy_calls, 0);
	T_EXPECT_EQ(readable, data_size);
}

/* With nothing left to send, a hello that establishes the session lets the
 * frame behind it dispatch in the same call. */
T_DECLARE_CASE(test_dispatch_frame_hello_established_continues)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.state = SESSION_HANDSHAKE;
	g.hello_establishes = true;
	g.hello_tx_pending = false;
	struct mux_stream s = make_stream(1, STREAM_ESTABLISHED);
	g.find_stream_ret = &s;
	(void)push_hello_then_data(&fx);

	dispatch_frame(&fx.ss);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.hello_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(g.find_stream_calls, 1);
	T_EXPECT_EQ(g.recv_copy_calls, 1);
	T_EXPECT_EQ(g.recv_copy_len, (size_t)8);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* A well-formed mux frame (version=MUX_PROTOCOL_VERSION) MUST NOT be
 * processed before the session reaches SESSION_ESTABLISHED (spec §5.2): one
 * arriving mid-handshake is a protocol violation, not an ordinary frame. */
T_DECLARE_CASE(test_dispatch_frame_nonhello_during_handshake_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.state = SESSION_HANDSHAKE;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_PUSH,
				.stream_id = 2,
				.length = 8 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
	/* The frame must not have reached ordinary stream dispatch. */
	T_EXPECT_EQ(g.find_stream_calls, 0);
	T_EXPECT_EQ(g.recv_copy_calls, 0);
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

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.ack_trim_calls, 1);
	T_EXPECT_EQ(g.ack_trim_count, (uint_fast32_t)2);
	T_EXPECT_EQ(g.est_add_acked_calls, 1);
	T_EXPECT_EQ(g.est_add_acked_bytes, (uint_least64_t)4096);
	T_EXPECT_EQ(g.notify_write_calls, 1); /* unstalled -> re-arm writer */
	T_EXPECT_EQ(readable, (size_t)0);
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

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
}

T_DECLARE_CASE(test_dispatch_frame_session_ack_payload_resets_before_trim)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	g.ack_trim_ret = (struct unacked_ack_result){ .ok = true };
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK,
				.stream_id = STREAMID_CTRL,
				.length = 1,
				.extra = 2 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(g.ack_trim_calls, 0);
}

T_DECLARE_CASE(test_dispatch_frame_session_ack_flags_resets_before_trim)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	g.ack_trim_ret = (struct unacked_ack_result){ .ok = true };
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = MUX_FLAG_ACK | MUX_FLAG_PUSH,
				.stream_id = STREAMID_CTRL,
				.extra = 2 };
	push_frame(&fx, &h);

	dispatch_frame(&fx.ss);

	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(g.ack_trim_calls, 0);
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
	const int send_oob_after_probe = g.send_oob_calls;
	const size_t readable_after_probe =
		bytebuf_readable(fx.ss.wire.recvbuf);

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
	const int send_oob_after_ping = g.send_oob_calls;
	const uint_fast8_t send_oob_extra = g.send_oob_extra;

	/* Teardown before the asserts; T_FAILNOW would skip it otherwise. */
	rf_teardown(&fx);

	T_EXPECT_EQ(send_oob_after_probe, 0);
	T_EXPECT_EQ(readable_after_probe, (size_t)0);
	T_EXPECT_EQ(send_oob_after_ping, 1);
	T_EXPECT_EQ(send_oob_extra, (uint_fast8_t)MUX_CTRL_PONG);
}

/* lossymux (spec §5.2.3.3): what the owner's datagram callbacks observed. */
struct dgram_spy {
	int dgram_calls;
	int close_calls;
	uint_least16_t flow;
	size_t len;
	unsigned char first;
	unsigned char last;
};
static struct dgram_spy g_dgram;

static void spy_on_dgram(
	void *data, struct mux_session *ss, const uint_least16_t flow,
	const unsigned char *payload, const size_t len)
{
	(void)data;
	(void)ss;
	g_dgram.dgram_calls++;
	g_dgram.flow = flow;
	g_dgram.len = len;
	g_dgram.first = len > 0 ? payload[0] : 0;
	g_dgram.last = len > 0 ? payload[len - 1] : 0;
}

static void spy_on_dgram_close(
	void *data, struct mux_session *ss, const uint_least16_t flow)
{
	(void)data;
	(void)ss;
	g_dgram.close_calls++;
	g_dgram.flow = flow;
}

/* rf_setup plus a negotiated lossymux extension and datagram callbacks. */
static int rf_setup_dgram(struct recv_fixture *restrict fx)
{
	if (rf_setup(fx) != 0) {
		return -1;
	}
	fx->ss.handshake.offered_lossymux = true;
	fx->ss.handshake.peer_lossymux = true;
	fx->ss.callbacks.on_dgram = spy_on_dgram;
	fx->ss.callbacks.on_dgram_close = spy_on_dgram_close;
	g_dgram = (struct dgram_spy){ 0 };
	return 0;
}

/* A DATAGRAM (stream 0, PUSH) reaches on_dgram with its payload in place,
 * counts into the datagram counters, and -- being a stream-0 frame -- is not
 * counted for the session ACK (spec §5.7.1).  It is accepted even when larger
 * than this endpoint's own outbound frame payload (spec §2.3). */
T_DECLARE_CASE(test_dispatch_frame_dgram_delivers_payload)
{
	struct recv_fixture fx;
	if (rf_setup_dgram(&fx) != 0) {
		T_FATAL("rf_setup_dgram failed");
		return;
	}
	mux_counter pkt_recv = 0;
	mux_counter byt_recv = 0;
	fx.ss.cnt.dgram.pkt_dgram_recv = &pkt_recv;
	fx.ss.cnt.dgram.byt_dgram_recv = &byt_recv;
	fx.ss.max_payload = MUX_MIN_FRAME_PAYLOAD;
	const uint_least16_t len =
		(uint_least16_t)(MUX_MIN_FRAME_PAYLOAD + 100);
	const struct mux_header hdr = { .version = MUX_PROTOCOL_VERSION,
					.flags = MUX_FLAG_PUSH,
					.stream_id = STREAMID_CTRL,
					.extra = 0x1235,
					.length = len };
	unsigned char *const p = bytebuf_write_ptr(fx.ss.wire.recvbuf);
	push_frame(&fx, &hdr);
	p[MUX_FRAME_HEADER_SIZE] = 0xA1;
	p[MUX_FRAME_HEADER_SIZE + len - 1] = 0xB2;
	dispatch_frame(&fx.ss);
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	const uint_least32_t recv_seq = fx.ss.unacked.recv_seq;
	const uint_least32_t unreported = fx.ss.unacked.unreported;
	const enum session_state state = fx.ss.state;

	rf_teardown(&fx);

	T_EXPECT_EQ(g_dgram.dgram_calls, 1);
	T_EXPECT_EQ(g_dgram.flow, (uint_least16_t)0x1235);
	T_EXPECT_EQ(g_dgram.len, (size_t)len);
	T_EXPECT_EQ(g_dgram.first, (unsigned char)0xA1);
	T_EXPECT_EQ(g_dgram.last, (unsigned char)0xB2);
	T_EXPECT_EQ(readable, (size_t)0);
	T_EXPECT_EQ(recv_seq, (uint_least32_t)0);
	T_EXPECT_EQ(unreported, (uint_least32_t)0);
	T_EXPECT_EQ(g.reset_calls, 0);
	T_EXPECT_EQ(state, (enum session_state)SESSION_ESTABLISHED);
	T_EXPECT_EQ((uint_least64_t)pkt_recv, (uint_least64_t)1);
	T_EXPECT_EQ((uint_least64_t)byt_recv, (uint_least64_t)len);
}

/* A FLOW-CLOSE (stream 0, FIN, no payload) reaches on_dgram_close. */
T_DECLARE_CASE(test_dispatch_frame_dgram_flow_close)
{
	struct recv_fixture fx;
	if (rf_setup_dgram(&fx) != 0) {
		T_FATAL("rf_setup_dgram failed");
		return;
	}
	push_frame(
		&fx, &(struct mux_header){ .version = MUX_PROTOCOL_VERSION,
					   .flags = MUX_FLAG_FIN,
					   .stream_id = STREAMID_CTRL,
					   .extra = 42 });
	dispatch_frame(&fx.ss);
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);

	rf_teardown(&fx);

	T_EXPECT_EQ(g_dgram.close_calls, 1);
	T_EXPECT_EQ(g_dgram.dgram_calls, 0);
	T_EXPECT_EQ(g_dgram.flow, (uint_least16_t)42);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* Frames lossymux does not define stay reserved stream-0 frames: silently
 * discarded with the session kept open (spec §4.1, I-14) -- whether the
 * extension was not negotiated (either side not offering it), the flow id is
 * 0, or the shape is not a DATAGRAM/FLOW-CLOSE. */
T_DECLARE_CASE(test_dispatch_frame_dgram_reserved_shapes_discarded)
{
	static const struct {
		bool offered;
		bool peer;
		uint_fast8_t flags;
		uint_least16_t extra;
		uint_least16_t length;
	} cases[] = {
		{ false, true, MUX_FLAG_PUSH, 1, 4 },
		{ true, false, MUX_FLAG_PUSH, 1, 4 },
		{ true, true, MUX_FLAG_PUSH, 0, 4 },
		{ true, true, MUX_FLAG_FIN, 0, 0 },
		{ true, true, MUX_FLAG_FIN, 1, 4 },
		{ true, true, MUX_FLAG_PUSH | MUX_FLAG_FIN, 1, 4 },
		{ true, true, MUX_FLAG_SYN, 1, 0 },
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct recv_fixture fx;
		if (rf_setup_dgram(&fx) != 0) {
			T_FATAL("rf_setup_dgram failed");
			return;
		}
		fx.ss.handshake.offered_lossymux = cases[i].offered;
		fx.ss.handshake.peer_lossymux = cases[i].peer;
		push_frame(
			&fx, &(struct mux_header){
				     .version = MUX_PROTOCOL_VERSION,
				     .flags = (uint_least8_t)cases[i].flags,
				     .stream_id = STREAMID_CTRL,
				     .extra = cases[i].extra,
				     .length = cases[i].length,
			     });
		dispatch_frame(&fx.ss);
		const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
		const enum session_state state = fx.ss.state;

		rf_teardown(&fx);

		T_EXPECT_EQ(g_dgram.dgram_calls, 0);
		T_EXPECT_EQ(g_dgram.close_calls, 0);
		T_EXPECT_EQ(readable, (size_t)0);
		T_EXPECT_EQ(g.reset_calls, 0);
		T_EXPECT_EQ(state, (enum session_state)SESSION_ESTABLISHED);
	}
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

	const uint_least32_t recv_seq = fx.ss.unacked.recv_seq;
	const uint_least32_t unreported = fx.ss.unacked.unreported;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(recv_seq, (uint_least32_t)2);
	T_EXPECT_EQ(unreported, (uint_least32_t)2);
	T_EXPECT_EQ(g.emit_ack_calls, 1);
	T_EXPECT_EQ(g.recv_copy_calls, 2);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* mux_session_recv_ping / mux_session_recv_pong control handlers. */

T_DECLARE_CASE(test_recv_ping_rate_limited)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* A PING within the rate-limit window is dropped without a PONG.  Stamp
	 * the last PONG at the far end of the clock's range so now - last stays
	 * negative however long this thread is descheduled before the call. */
	fx.ss.ping_recv_last_ns = INT_LEAST64_MAX;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PING,
				.length = MUX_PING_PAYLOAD_SIZE };
	push_frame(&fx, &h);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	mux_session_recv_ping(&fx.ss, &h, frame_size);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_oob_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
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

	mux_session_recv_ping(&fx.ss, &h, frame_size);

	/* ping_recv_last_ns is not advanced when the PONG could not be queued. */
	const bool ping_ns_not_advanced =
		fx.ss.ping_recv_last_ns <
		clock_monotonic_ns() - MUX_PONG_RATE_LIMIT_NS;
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.send_oob_calls, 1);
	T_EXPECT_EQ(g.flush_oob_calls, 0); /* not flushed on failure */
	T_EXPECT(ping_ns_not_advanced);
	T_EXPECT_EQ(readable, (size_t)0);
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

	mux_session_recv_ping(&fx.ss, &h, frame_size);

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(g.send_oob_calls, 0);
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

	mux_session_recv_pong(&fx.ss, &h, frame_size);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.est_calc_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* Start w_keepalive on a 1 s period and make the next jittered interval 42 s,
 * so a handler that restarts the keepalive interval is told apart from one
 * that leaves it alone. */
static void rf_arm_keepalive(struct recv_fixture *restrict fx)
{
	ev_timer_set(&fx->ss.w_keepalive, 1.0, 1.0);
	ev_timer_start(fx->loop, &fx->ss.w_keepalive);
	g.keepalive_ret = 42.0;
}

/* An answered PING completes a keepalive exchange -- a frame in, a PONG out --
 * so it restarts the keepalive interval; a PING dropped by the rate limit or
 * by OOM sent nothing back and leaves it alone. */
T_DECLARE_CASE(test_recv_ping_defers_keepalive_only_when_answered)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	rf_arm_keepalive(&fx);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PING,
				.length = 0 };
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	/* Rate-limited even if the test is descheduled before the handler. */
	fx.ss.ping_recv_last_ns = INT_LEAST64_MAX;
	push_frame(&fx, &h);
	mux_session_recv_ping(&fx.ss, &h, frame_size);
	const double repeat_limited = fx.ss.w_keepalive.repeat;
	const int sends_limited = g.send_oob_calls;

	/* OOM: the PONG could not be queued. */
	fx.ss.ping_recv_last_ns =
		clock_monotonic_ns() - 2 * MUX_PONG_RATE_LIMIT_NS;
	g.send_oob_ret = false;
	push_frame(&fx, &h);
	mux_session_recv_ping(&fx.ss, &h, frame_size);
	const double repeat_oom = fx.ss.w_keepalive.repeat;
	const int sends_oom = g.send_oob_calls;

	/* Answered. */
	g.send_oob_ret = true;
	push_frame(&fx, &h);
	mux_session_recv_ping(&fx.ss, &h, frame_size);
	const double repeat_answered = fx.ss.w_keepalive.repeat;
	const bool active = ev_is_active(&fx.ss.w_keepalive);
	const uint_fast8_t extra = g.send_oob_extra;
	const size_t len = g.send_oob_len;

	ev_timer_stop(fx.loop, &fx.ss.w_keepalive);
	rf_teardown(&fx);

	T_EXPECT_EQ(repeat_limited, 1.0);
	T_EXPECT_EQ(sends_limited, 0);
	T_EXPECT_EQ(repeat_oom, 1.0);
	T_EXPECT_EQ(sends_oom, 1);
	T_EXPECT_EQ(repeat_answered, 42.0);
	T_EXPECT_EQ(g.send_oob_calls, 2);
	T_EXPECT_EQ(g.flush_oob_calls, 1);
	T_EXPECT(active);
	/* An empty keepalive PING is echoed as an empty PONG. */
	T_EXPECT_EQ(extra, (uint_fast8_t)MUX_CTRL_PONG);
	T_EXPECT_EQ(len, (size_t)0);
}

/* Every PONG restarts the keepalive interval, including the empty one that
 * answers a keepalive PING and never reaches the estimator. */
T_DECLARE_CASE(test_recv_pong_defers_keepalive)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	rf_arm_keepalive(&fx);
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PONG,
				.length = 0 };
	push_frame(&fx, &h);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	mux_session_recv_pong(&fx.ss, &h, frame_size);

	const double repeat = fx.ss.w_keepalive.repeat;
	const bool active = ev_is_active(&fx.ss.w_keepalive);
	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	ev_timer_stop(fx.loop, &fx.ss.w_keepalive);
	rf_teardown(&fx);

	T_EXPECT_EQ(repeat, 42.0);
	T_EXPECT(active);
	T_EXPECT_EQ(g.est_calc_calls, 0);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* With keepalive disabled the timer is stopped, and a PONG must not start it. */
T_DECLARE_CASE(test_recv_pong_keepalive_disabled_stays_stopped)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	g.keepalive_ret = 0.0;
	struct mux_header h = { .version = MUX_PROTOCOL_VERSION,
				.flags = 0,
				.stream_id = STREAMID_CTRL,
				.extra = MUX_CTRL_PONG,
				.length = 0 };
	push_frame(&fx, &h);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	mux_session_recv_pong(&fx.ss, &h, frame_size);

	const bool active = ev_is_active(&fx.ss.w_keepalive);
	if (active) {
		ev_timer_stop(fx.loop, &fx.ss.w_keepalive);
	}
	rf_teardown(&fx);

	T_EXPECT(!active);
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
	unsigned char *const p = bytebuf_write_ptr(fx.ss.wire.recvbuf);
	mux_write_header(p, &h);
	write_uint64(p + MUX_FRAME_HEADER_SIZE, UINT64_C(123456789));
	bytebuf_produce(fx.ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE + h.length);
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + h.length;

	mux_session_recv_pong(&fx.ss, &h, frame_size);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT_EQ(g.est_calc_calls, 1);
	T_EXPECT_EQ(g.est_calc_sent_ns, (int_fast64_t)123456789);
	T_EXPECT_EQ(readable, (size_t)0);
}

/* recv_one / mux_session_on_recv: the transport read pump. */

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

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.suspend_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);
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

	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(g.suspend_calls, 0);
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

	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.suspend_calls, 1);
	T_EXPECT_EQ(g.reset_calls, 0);
}

/* recv_one: a TLS close_notify -- mux_wire_recv succeeds but reports nread==0 --
 * during the handshake has no send-side handler, so recv_one drives teardown
 * itself. A client mid-resume (session id negotiated, not yet accepted)
 * re-suspends to preserve its streams rather than resetting. */
T_DECLARE_CASE(test_recv_one_close_notify_handshake_suspends)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.state = SESSION_HANDSHAKE;
	fx.ss.wire.rx_open = false;
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = true;
	g.wire_recv_ret = true;
	g.wire_recv_nread = 0; /* close_notify: a zero-byte successful read */

	const bool ok = recv_one(&fx.ss);

	const int suspend_calls = g.suspend_calls;
	const int reset_calls = g.reset_calls;
	const int wire_recv_calls = g.wire_recv_calls;
	rf_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT_EQ(suspend_calls, 1);
	T_EXPECT_EQ(reset_calls, 0);
	T_EXPECT_EQ(wire_recv_calls, 1);
}

/* recv_one: the same handshake close_notify without a resumable session (no
 * negotiated session id) resets instead of suspending -- there is nothing to
 * resume into. */
T_DECLARE_CASE(test_recv_one_close_notify_handshake_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	fx.ss.state = SESSION_HANDSHAKE;
	fx.ss.wire.rx_open = false;
	fx.ss.accepted = false;
	fx.ss.handshake.has_session_id = false;
	g.wire_recv_ret = true;
	g.wire_recv_nread = 0;

	const bool ok = recv_one(&fx.ss);

	const int suspend_calls = g.suspend_calls;
	const int reset_calls = g.reset_calls;
	rf_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT_EQ(reset_calls, 1);
	T_EXPECT_EQ(suspend_calls, 0);
}

T_DECLARE_CASE(test_recv_one_reserve_oom_resets)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Failing to reserve receive space is fatal: reset the session. */
	g.bytebuf_reserve_ret = false;

	const bool ok = recv_one(&fx.ss);

	/* Teardown up front; a failing check below must not leak it. */
	rf_teardown(&fx);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g.reset_calls, 1);
	T_EXPECT_EQ(
		g.wire_recv_calls, 0); /* never reached the transport read */
}

T_DECLARE_CASE(test_session_on_recv_dispatches_and_loops)
{
	struct recv_fixture fx;
	if (rf_setup(&fx) != 0) {
		T_FATAL("rf_setup failed");
		return;
	}
	/* Stage a single PROBE frame for mux_wire_recv to deliver, then report one
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

	mux_session_on_recv(&fx.ss);

	const size_t readable = bytebuf_readable(fx.ss.wire.recvbuf);
	/* Free the fixture first so a failing assert can't leak it. */
	rf_teardown(&fx);

	/* Two reads: the initial recv_one plus one pending-driven iteration. */
	T_EXPECT_EQ(g.wire_recv_calls, 2);
	T_EXPECT_EQ(readable, (size_t)0);
	/* The batch epilogue drains freshly queued egress exactly once. */
	T_EXPECT_EQ(g.flush_resp_calls, 1);
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
	T_CASE(test_update_stream_window_floors_to_initial),
	T_CASE(test_dispatch_by_stream_rst),
	T_CASE(test_dispatch_by_stream_invalid_flags_sends_rst),
	T_CASE(test_dispatch_by_stream_invalid_flags_rst_oom_retryable),
	T_CASE(test_dispatch_by_stream_synack_establishes),
	T_CASE(test_dispatch_by_stream_synack_reports_established_once),
	T_CASE(test_dispatch_by_stream_synack_idempotent),
	T_CASE(test_dispatch_by_stream_push_fin),
	T_CASE(test_dispatch_by_stream_push_fin_survives_stream_freed),
	T_CASE(test_dispatch_by_stream_ack_push_survives_window_abort),
	T_CASE(test_dispatch_by_stream_synack_survives_window_abort),
	T_CASE(test_dispatch_by_stream_ack_grants_credit),
	T_CASE(test_dispatch_by_stream_closed_ignores_rst),
	T_CASE(test_dispatch_by_stream_closed_late_frame_rst_once),
	T_CASE(test_dispatch_no_stream_rst_ignored),
	T_CASE(test_dispatch_no_stream_bad_syn_flags_resets),
	T_CASE(test_dispatch_no_stream_bad_parity_resets),
	T_CASE(test_dispatch_no_stream_non_syn_bad_parity_resets),
	T_CASE(test_dispatch_no_stream_draining_refuses),
	T_CASE(test_dispatch_no_stream_max_streams_refuses),
	T_CASE(test_dispatch_no_stream_accept_null_refuses),
	T_CASE(test_dispatch_no_stream_accept_rejects),
	T_CASE(test_dispatch_no_stream_accept_ok),
	T_CASE(test_push_payload_feeds_estimator_in_auto_mode),
	T_CASE(test_push_delivery_same_on_every_path),
	T_CASE(test_dispatch_no_stream_oversized_fastopen_resets),
	T_CASE(test_process_syn_payload_accepts_credit_boundary_fastopen),
	T_CASE(test_process_syn_payload_copy_guards_drain_cascade),
	T_CASE(test_dispatch_by_stream_synack_rejects_over_credit_fastopen),
	T_CASE(test_dispatch_by_stream_synack_accepts_credit_boundary_fastopen),
	T_CASE(test_dispatch_by_stream_synack_reject_guards_drain_cascade),
	T_CASE(test_dispatch_no_stream_stream_new_oom),
	T_CASE(test_dispatch_no_stream_add_stream_fails),
	T_CASE(test_dispatch_no_stream_late_nonsyn_rst),
	T_CASE(test_dispatch_no_stream_ignorable_terminal),
	T_CASE(test_dispatch_frame_accepts_oversized_length),
	T_CASE(test_dispatch_frame_ctrl_reset_stops_loop),
	T_CASE(test_dispatch_ctrl_frame_reports_handler_reset),
	T_CASE(test_dispatch_by_stream_oversized_push),
	T_CASE(test_dispatch_frame_unsupported_version_resets),
	T_CASE(test_dispatch_frame_reserved_flags_resets),
	T_CASE(test_dispatch_frame_hello_routed_to_handshake),
	T_CASE(test_dispatch_frame_hello_during_handshake_unaffected),
	T_CASE(test_dispatch_frame_hello_reset_stops_loop),
	T_CASE(test_dispatch_frame_hello_established_defers_on_tx_pending),
	T_CASE(test_dispatch_frame_hello_established_continues),
	T_CASE(test_dispatch_frame_nonhello_during_handshake_resets),
	T_CASE(test_dispatch_frame_session_ack_trims),
	T_CASE(test_dispatch_frame_session_ack_overflow_resets),
	T_CASE(test_dispatch_frame_session_ack_payload_resets_before_trim),
	T_CASE(test_dispatch_frame_session_ack_flags_resets_before_trim),
	T_CASE(test_dispatch_frame_ctrl_ping_pong_probe),
	T_CASE(test_dispatch_frame_dgram_delivers_payload),
	T_CASE(test_dispatch_frame_dgram_flow_close),
	T_CASE(test_dispatch_frame_dgram_reserved_shapes_discarded),
	T_CASE(test_dispatch_frame_data_forces_session_ack),
	T_CASE(test_recv_ping_rate_limited),
	T_CASE(test_recv_ping_oom_drops_pong),
	T_CASE(test_recv_ping_oversized_resets),
	T_CASE(test_recv_pong_short_payload_ignored),
	T_CASE(test_recv_ping_defers_keepalive_only_when_answered),
	T_CASE(test_recv_pong_defers_keepalive),
	T_CASE(test_recv_pong_keepalive_disabled_stays_stopped),
	T_CASE(test_recv_pong_feeds_estimator),
	T_CASE(test_recv_one_error_suspends_resumable),
	T_CASE(test_recv_one_error_resets_fresh),
	T_CASE(test_recv_one_handshake_suspends_resumable),
	T_CASE(test_recv_one_close_notify_handshake_suspends),
	T_CASE(test_recv_one_close_notify_handshake_resets),
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
