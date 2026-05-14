/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/frame.h"
#include "mux/session.h"
#include "mux/stream.h"

#include "algo/hashtable.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mux/dispatch.c"

static int g_reset_calls;
static int g_send_ctrl_calls;
static uint_fast16_t g_last_ctrl_stream_id;
static uint_fast8_t g_last_ctrl_flags;
static uint_fast32_t g_last_ctrl_extra;
static int g_emit_ack_calls;
static int g_ack_trim_calls;
static uint_fast32_t g_last_ack_trim_count;
static bool g_ack_trim_result;
static int g_ping_calls;
static int g_pong_calls;
static int g_handshake_calls;
static bool g_handshake_result;
static bool g_handshake_promotes_established;
static bool g_handshake_sets_tx_pending;
static int g_stream_recv_rst_calls;
static int g_stream_recv_window_calls;
static uint_fast32_t g_last_window_inc;
static int g_stream_start_calls;
static int g_stream_recv_fin_calls;
static int g_estimator_add_calls;
static uintmax_t g_last_estimator_bytes;
static struct stream *g_sched_find_stream;

static void dispatch_test_reset(void)
{
	g_reset_calls = 0;
	g_send_ctrl_calls = 0;
	g_last_ctrl_stream_id = 0;
	g_last_ctrl_flags = 0;
	g_last_ctrl_extra = 0;
	g_emit_ack_calls = 0;
	g_ack_trim_calls = 0;
	g_last_ack_trim_count = 0;
	g_ack_trim_result = true;
	g_ping_calls = 0;
	g_pong_calls = 0;
	g_handshake_calls = 0;
	g_handshake_result = true;
	g_handshake_promotes_established = false;
	g_handshake_sets_tx_pending = false;
	g_stream_recv_rst_calls = 0;
	g_stream_recv_window_calls = 0;
	g_last_window_inc = 0;
	g_stream_start_calls = 0;
	g_stream_recv_fin_calls = 0;
	g_estimator_add_calls = 0;
	g_last_estimator_bytes = 0;
	g_sched_find_stream = NULL;
}

static void
consume_frame(struct mux_session *restrict ss, const size_t frame_size)
{
	if (ringbuf_readable(ss->wire.recvbuf) >= frame_size) {
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}
	ringbuf_reset(ss->wire.recvbuf);
}

int stream_format_tag(
	char *restrict buf, const size_t buflen,
	const struct stream *restrict s)
{
	(void)s;
	return snprintf(buf, buflen, "[stream]:");
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

void session_reset(struct mux_session *ss)
{
	ss->state = SESSION_CLOSED;
	g_reset_calls++;
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

void session_emit_ack(struct mux_session *ss)
{
	(void)ss;
	g_emit_ack_calls++;
}

void sched_coalesce_arm(struct mux_session *ss)
{
	(void)ss;
}

bool session_ack_trim(struct mux_session *restrict ss, const uint_fast32_t count)
{
	(void)ss;
	g_ack_trim_calls++;
	g_last_ack_trim_count = count;
	return g_ack_trim_result;
}

void session_recv_ping(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	(void)hdr;
	g_ping_calls++;
	consume_frame(ss, frame_size);
}

void session_recv_pong(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	(void)hdr;
	g_pong_calls++;
	consume_frame(ss, frame_size);
}

bool handshake_process_hello(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	(void)hdr;
	g_handshake_calls++;
	consume_frame(ss, frame_size);
	if (!g_handshake_result) {
		ss->state = SESSION_CLOSED;
		return false;
	}
	if (g_handshake_promotes_established) {
		ss->state = SESSION_ESTABLISHED;
	}
	if (g_handshake_sets_tx_pending) {
		ss->wire.tx_pending = true;
	}
	return g_handshake_result;
}

struct stream *sched_find_stream(
	struct mux_session *restrict ss, const uint_fast16_t stream_id)
{
	(void)ss;
	if (g_sched_find_stream != NULL &&
	    g_sched_find_stream->id == stream_id) {
		return g_sched_find_stream;
	}
	return NULL;
}

bool sched_add_stream(struct mux_session *restrict ss, struct stream *restrict s)
{
	void *elem = s;
	ss->sched.streams =
		table_set(ss->sched.streams, STREAMID_KEY(s->id), &elem);
	return ss->sched.streams != NULL;
}

struct stream *stream_new(
	struct mux_session *restrict ss, const uint_fast16_t id,
	const bool active_open)
{
	(void)active_open;
	struct stream *const s = calloc(1, sizeof(*s));
	if (s != NULL) {
		s->session = ss;
		s->id = (uint_least16_t)id;
		s->state = STREAM_SYN_RECEIVED;
	}
	return s;
}

void stream_close(struct stream *s)
{
	free(s);
}

void stream_free(struct stream *s)
{
	free(s);
}

void stream_recv_rst(struct stream *s)
{
	(void)s;
	g_stream_recv_rst_calls++;
}

void stream_recv_window(
	struct stream *restrict s, const uint_fast32_t window_inc)
{
	g_stream_recv_window_calls++;
	g_last_window_inc = window_inc;
	s->send_window = (uint_least32_t)(MUX_DEFAULT_SEND_WINDOW +
					  window_inc * MUX_WINDOW_UNIT);
}

void stream_start(struct stream *s)
{
	g_stream_start_calls++;
	s->state = STREAM_ESTABLISHED;
}

void stream_recv_copy(
	struct stream *restrict s, const unsigned char *restrict payload,
	size_t payload_len)
{
	(void)s;
	(void)payload;
	(void)payload_len;
}

void stream_recv_fin(struct stream *s)
{
	(void)s;
	g_stream_recv_fin_calls++;
}

void estimator_add(struct mux_session *restrict ss, const uintmax_t bytes)
{
	(void)ss;
	g_estimator_add_calls++;
	g_last_estimator_bytes = bytes;
}

static struct mux_session make_session(const bool accepted)
{
	struct mux_session ss = {
		.accepted = accepted,
		.state = SESSION_ESTABLISHED,
		.session_window = 8,
		.stream_window = 4,
		.tag = (char *)"[test]:",
	};
	ss.w_socket.fd = 17;
	ss.wire.recvbuf = ringbuf_new(MUX_FRAME_SIZE);
	T_CHECK(ss.wire.recvbuf != NULL);
	ringbuf_produce(ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE);
	return ss;
}

static void fill_frame(
	struct mux_frame *restrict frame, struct mux_session *restrict ss,
	const struct mux_header *restrict hdr)
{
	mux_write_header(frame->data, hdr);
	frame->len = MUX_FRAME_HEADER_SIZE + hdr->length;
	frame->pos = frame->len;
	ringbuf_free(ss->wire.recvbuf);
	ss->wire.recvbuf = ringbuf_new(frame->len);
	T_CHECK(ss->wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss->wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(ss->wire.recvbuf, frame->len);
}

static void
insert_dummy_stream(struct mux_session *restrict ss, const uint_least16_t id)
{
	struct stream *dummy = calloc(1, sizeof(*dummy));
	void *elem = dummy;
	T_CHECK(dummy != NULL);
	dummy->id = id;
	ss->sched.streams = table_new(TABLE_FAST);
	T_CHECK(ss->sched.streams != NULL);
	ss->sched.streams =
		table_set(ss->sched.streams, STREAMID_KEY(id), &elem);
	T_CHECK(ss->sched.streams != NULL);
}

static bool free_stream_cb(
	const struct hashtable *table, struct hashkey key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	(void)data;
	free(element);
	return true;
}

static void free_stream_table(struct mux_session *restrict ss)
{
	if (ss->sched.streams != NULL) {
		table_iterate(ss->sched.streams, free_stream_cb, NULL);
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
}

T_DECLARE_CASE(test_validate_flags_by_stream_states)
{
	struct stream syn_sent = { .state = STREAM_SYN_SENT };
	struct stream close_wait = { .state = STREAM_CLOSE_WAIT };
	struct stream established = { .state = STREAM_ESTABLISHED };

	T_EXPECT(validate_flags_by_stream(
		&syn_sent, MUX_FLAG_SYN | MUX_FLAG_ACK));
	T_EXPECT(!validate_flags_by_stream(&syn_sent, MUX_FLAG_SYN));
	T_EXPECT(validate_flags_by_stream(&close_wait, MUX_FLAG_ACK));
	T_EXPECT(validate_flags_by_stream(&close_wait, MUX_FLAG_FIN));
	T_EXPECT(validate_flags_by_stream(
		&close_wait, MUX_FLAG_ACK | MUX_FLAG_FIN));
	T_EXPECT(!validate_flags_by_stream(&close_wait, MUX_FLAG_PUSH));
	/* SYN|ACK on established stream: valid (resume retransmit). */
	T_EXPECT(validate_flags_by_stream(
		&established, MUX_FLAG_SYN | MUX_FLAG_ACK));
	/* SYN without ACK on established stream: invalid. */
	T_EXPECT(!validate_flags_by_stream(&established, MUX_FLAG_SYN));
}

T_DECLARE_CASE(test_dispatch_unknown_stream_terminal_ack_is_ignored)
{
	struct mux_session ss = make_session(false);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_ACK,
		.length = 0,
		.stream_id = 7,
		.extra = 0,
	};

	dispatch_test_reset();
	dispatch_no_stream(&ss, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 0);
	T_EXPECT_EQ(g_reset_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_unknown_stream_non_syn_payload_sends_rst)
{
	struct mux_session ss = make_session(false);
	struct mux_frame frame = { 0 };
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 1,
		.stream_id = 7,
		.extra = 0,
	};

	dispatch_test_reset();
	fill_frame(&frame, &ss, &hdr);
	dispatch_no_stream(&ss, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_stream_id, (uint_fast16_t)7);
	T_EXPECT_EQ(g_last_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT_EQ(
		g_last_ctrl_extra, (uint_fast32_t)MUX_STATUS_PROTOCOL_ERROR);
	T_EXPECT_EQ(g_reset_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_unknown_stream_second_payload_is_ignored)
{
	struct mux_session ss = make_session(false);
	struct mux_frame first = { 0 };
	struct mux_frame second = { 0 };
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 1,
		.stream_id = 7,
		.extra = 0,
	};

	dispatch_test_reset();
	fill_frame(&first, &ss, &hdr);
	dispatch_no_stream(&ss, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);

	fill_frame(&second, &ss, &hdr);
	dispatch_no_stream(&ss, &hdr);
	/* dispatch_no_stream sends RST for every unknown non-SYN frame;
	 * deduplication now happens only inside the tombstone window via
	 * s->rst_sent, which is inaccessible here (no stream in table). */
	T_EXPECT_EQ(g_send_ctrl_calls, 2);
	T_EXPECT_EQ(g_reset_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_unknown_syn_invalid_parity_sends_protocol_rst)
{
	struct mux_session ss = make_session(false);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};

	dispatch_test_reset();
	dispatch_no_stream(&ss, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 0);
	T_EXPECT_EQ(g_reset_calls, 1);
	T_EXPECT_EQ(
		ringbuf_readable(ss.wire.recvbuf),
		(size_t)MUX_FRAME_HEADER_SIZE);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_unknown_syn_max_streams_sends_refused_rst)
{
	struct mux_session ss = make_session(false);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 2,
		.extra = 0,
	};

	dispatch_test_reset();
	ss.conf.max_streams = 1;
	insert_dummy_stream(&ss, 4);
	dispatch_no_stream(&ss, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g_last_ctrl_extra, (uint_fast32_t)MUX_STATUS_REFUSED_STREAM);
	free_stream_table(&ss);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_frame_ctrl_ack_trims_unacked)
{
	struct mux_session ss = make_session(false);
	struct mux_frame frame = { 0 };
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_ACK,
		.length = 0,
		.stream_id = STREAMID_CTRL,
		.extra = 3,
	};

	dispatch_test_reset();
	fill_frame(&frame, &ss, &hdr);
	dispatch_frame(&ss);
	T_EXPECT_EQ(g_ack_trim_calls, 1);
	T_EXPECT_EQ(g_last_ack_trim_count, (uint_fast32_t)3);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_frame_ctrl_ping_calls_ping_handler)
{
	struct mux_session ss = make_session(false);
	struct mux_frame frame = { 0 };
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = 0,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};

	dispatch_test_reset();
	fill_frame(&frame, &ss, &hdr);
	dispatch_frame(&ss);
	T_EXPECT_EQ(g_ping_calls, 1);
	T_EXPECT_EQ(g_pong_calls, 0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_frame_reserved_flag_resets_session)
{
	struct mux_session ss = make_session(false);
	struct mux_frame frame = { 0 };
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0x20,
		.length = 0,
		.stream_id = 2,
		.extra = 0,
	};

	dispatch_test_reset();
	fill_frame(&frame, &ss, &hdr);
	dispatch_frame(&ss);
	T_EXPECT_EQ(g_reset_calls, 1);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_frame_version_zero_calls_handshake)
{
	struct mux_session ss = make_session(false);
	struct mux_frame frame = { 0 };
	const struct mux_header hdr = {
		.version = 0,
		.flags = 0,
		.length = 0,
		.stream_id = 0,
		.extra = 0,
	};

	dispatch_test_reset();
	fill_frame(&frame, &ss, &hdr);
	dispatch_frame(&ss);
	T_EXPECT_EQ(g_handshake_calls, 1);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_frame_stops_after_handshake_when_write_pending)
{
	struct mux_session ss = make_session(false);
	unsigned char buf[2 * MUX_FRAME_HEADER_SIZE];
	const struct mux_header hello = {
		.version = 0,
		.flags = 0,
		.length = 0,
		.stream_id = 0,
		.extra = 0,
	};
	const struct mux_header ack = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_ACK,
		.length = 0,
		.stream_id = STREAMID_CTRL,
		.extra = 1,
	};
	struct mux_header remaining = { 0 };

	dispatch_test_reset();
	ss.state = SESSION_HANDSHAKE;
	g_handshake_promotes_established = true;
	g_handshake_sets_tx_pending = true;
	mux_write_header(buf, &hello);
	mux_write_header(buf + MUX_FRAME_HEADER_SIZE, &ack);
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(sizeof(buf));
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), buf, sizeof(buf));
	ringbuf_produce(ss.wire.recvbuf, sizeof(buf));

	dispatch_frame(&ss);
	T_EXPECT_EQ(g_handshake_calls, 1);
	T_EXPECT_EQ(g_ack_trim_calls, 0);
	T_EXPECT_EQ(
		ringbuf_readable(ss.wire.recvbuf),
		(size_t)MUX_FRAME_HEADER_SIZE);
	mux_read_header(ringbuf_read_ptr(ss.wire.recvbuf), &remaining);
	T_EXPECT_EQ(remaining.version, (uint_fast8_t)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(remaining.stream_id, (uint_fast16_t)STREAMID_CTRL);
	T_EXPECT(ss.wire.tx_pending);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_invalid_flags_send_rst)
{
	struct mux_session ss = make_session(false);
	struct stream s = {
		.id = 2,
		.state = STREAM_CLOSE_WAIT,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 0,
		.stream_id = 2,
		.extra = 0,
	};

	dispatch_test_reset();
	dispatch_by_stream(&ss, &s, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(
		g_last_ctrl_extra, (uint_fast32_t)MUX_STATUS_PROTOCOL_ERROR);
	T_EXPECT_EQ(g_stream_recv_rst_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_ack_fin_grants_credit_and_fin)
{
	struct mux_session ss = make_session(false);
	struct stream s = {
		.id = 2,
		.state = STREAM_ESTABLISHED,
		.send_window = MUX_DEFAULT_SEND_WINDOW,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_ACK | MUX_FLAG_FIN,
		.length = 0,
		.stream_id = 2,
		.extra = 3,
	};

	dispatch_test_reset();
	dispatch_by_stream(&ss, &s, &hdr);
	T_EXPECT_EQ(g_stream_recv_window_calls, 1);
	T_EXPECT_EQ(g_last_window_inc, (uint_fast32_t)3);
	T_EXPECT_EQ(g_stream_recv_fin_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_closed_terminal_fin_is_ignored)
{
	struct mux_session ss = make_session(false);
	struct stream s = {
		.id = 2,
		.state = STREAM_CLOSED,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_FIN,
		.length = 0,
		.stream_id = 2,
		.extra = 0,
	};

	dispatch_test_reset();
	dispatch_by_stream(&ss, &s, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 0);
	T_EXPECT_EQ(g_stream_recv_rst_calls, 0);
	T_EXPECT_EQ(g_stream_recv_fin_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_closed_push_sends_rst)
{
	struct mux_session ss = make_session(false);
	struct mux_frame frame = { 0 };
	struct stream s = {
		.id = 2,
		.state = STREAM_CLOSED,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 1,
		.stream_id = 2,
		.extra = 0,
	};

	dispatch_test_reset();
	fill_frame(&frame, &ss, &hdr);
	dispatch_by_stream(&ss, &s, &hdr);
	/* First late PUSH on a tombstone stream: one RST is sent. */
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(g_last_ctrl_stream_id, (uint_fast16_t)2);
	T_EXPECT_EQ(g_last_ctrl_flags, (uint_fast8_t)MUX_FLAG_RST);
	T_EXPECT_EQ(
		g_last_ctrl_extra, (uint_fast32_t)MUX_STATUS_PROTOCOL_ERROR);
	T_EXPECT(s.rst_sent);
	T_EXPECT_EQ(g_stream_recv_rst_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_closed_push_rst_dedup)
{
	struct mux_session ss = make_session(false);
	struct mux_frame frame = { 0 };
	struct stream s = {
		.id = 2,
		.state = STREAM_CLOSED,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 1,
		.stream_id = 2,
		.extra = 0,
	};

	dispatch_test_reset();
	fill_frame(&frame, &ss, &hdr);
	dispatch_by_stream(&ss, &s, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT(s.rst_sent);

	/* Second late PUSH on the same tombstone stream: RST suppressed. */
	fill_frame(&frame, &ss, &hdr);
	dispatch_by_stream(&ss, &s, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_closed_rst_is_ignored)
{
	struct mux_session ss = make_session(false);
	struct stream s = {
		.id = 2,
		.state = STREAM_CLOSED,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_RST,
		.length = 0,
		.stream_id = 2,
		.extra = 0,
	};

	dispatch_test_reset();
	dispatch_by_stream(&ss, &s, &hdr);
	T_EXPECT_EQ(g_send_ctrl_calls, 0);
	T_EXPECT_EQ(g_stream_recv_rst_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_syn_ack_starts_stream)
{
	struct mux_session ss = make_session(false);
	struct stream s = {
		.id = 2,
		.state = STREAM_SYN_SENT,
		.send_window = MUX_DEFAULT_SEND_WINDOW,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
		.length = 0,
		.stream_id = 2,
		.extra = 2,
	};

	dispatch_test_reset();
	dispatch_by_stream(&ss, &s, &hdr);
	T_EXPECT_EQ(g_stream_recv_window_calls, 1);
	T_EXPECT_EQ(g_stream_start_calls, 1);
	T_EXPECT_EQ(
		ss.peer_stream_window,
		(uint_least32_t)(s.send_window / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_dispatch_by_stream_syn_ack_retransmit_on_established)
{
	struct mux_session ss = make_session(false);
	struct stream s = {
		.id = 2,
		.state = STREAM_ESTABLISHED,
		.send_window = MUX_DEFAULT_SEND_WINDOW,
	};
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN | MUX_FLAG_ACK,
		.length = 0,
		.stream_id = 2,
		.extra = 2,
	};

	dispatch_test_reset();
	dispatch_by_stream(&ss, &s, &hdr);
	/* Idempotent retransmit: frame consumed; no stream_start, no RST. */
	T_EXPECT_EQ(g_stream_start_calls, 0);
	T_EXPECT_EQ(g_send_ctrl_calls, 0);
	T_EXPECT_EQ(g_stream_recv_window_calls, 0);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_validate_flags_by_stream_states);
	T_RUN_CASE(t, test_dispatch_unknown_stream_terminal_ack_is_ignored);
	T_RUN_CASE(t, test_dispatch_unknown_stream_non_syn_payload_sends_rst);
	T_RUN_CASE(t, test_dispatch_unknown_stream_second_payload_is_ignored);
	T_RUN_CASE(
		t, test_dispatch_unknown_syn_invalid_parity_sends_protocol_rst);
	T_RUN_CASE(t, test_dispatch_unknown_syn_max_streams_sends_refused_rst);
	T_RUN_CASE(t, test_dispatch_frame_ctrl_ack_trims_unacked);
	T_RUN_CASE(t, test_dispatch_frame_ctrl_ping_calls_ping_handler);
	T_RUN_CASE(t, test_dispatch_frame_reserved_flag_resets_session);
	T_RUN_CASE(t, test_dispatch_frame_version_zero_calls_handshake);
	T_RUN_CASE(
		t,
		test_dispatch_frame_stops_after_handshake_when_write_pending);
	T_RUN_CASE(t, test_dispatch_by_stream_invalid_flags_send_rst);
	T_RUN_CASE(t, test_dispatch_by_stream_ack_fin_grants_credit_and_fin);
	T_RUN_CASE(t, test_dispatch_by_stream_closed_terminal_fin_is_ignored);
	T_RUN_CASE(t, test_dispatch_by_stream_closed_push_sends_rst);
	T_RUN_CASE(t, test_dispatch_by_stream_closed_push_rst_dedup);
	T_RUN_CASE(t, test_dispatch_by_stream_closed_rst_is_ignored);
	T_RUN_CASE(t, test_dispatch_by_stream_syn_ack_starts_stream);
	T_RUN_CASE(
		t, test_dispatch_by_stream_syn_ack_retransmit_on_established);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
