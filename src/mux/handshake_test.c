/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/handshake.c"

#include "algo/hashtable.h"

#include "mux/frame.h"
#include "mux/session.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static struct mux_session *g_resume_match;
static struct mux_session *g_resume_transport_ss;
static struct mux_session *g_resume_transport_new_ss;
static uint_least32_t g_resume_transport_seq;
static int g_reset_calls;
static int g_handshake_done_calls;
static int g_resume_transport_calls;
static int g_resume_ack_recv_calls;
static int g_sched_free_calls;
static int g_update_watcher_calls;

static void handshake_stub_reset(void)
{
	g_resume_match = NULL;
	g_resume_transport_ss = NULL;
	g_resume_transport_new_ss = NULL;
	g_resume_transport_seq = 0;
	g_reset_calls = 0;
	g_handshake_done_calls = 0;
	g_resume_transport_calls = 0;
	g_resume_ack_recv_calls = 0;
	g_sched_free_calls = 0;
	g_update_watcher_calls = 0;
}

static struct mux_frame *handshake_test_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(sizeof(*frame));
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void handshake_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = handshake_test_alloc,
		.free = handshake_test_free,
		.data = ctx,
	};
}

void session_reset(struct mux_session *ss)
{
	(void)ss;
	g_reset_calls++;
}

void session_handshake_done(struct mux_session *ss)
{
	(void)ss;
	g_handshake_done_calls++;
}

void session_update_watcher(struct mux_session *ss)
{
	(void)ss;
	g_update_watcher_calls++;
}

bool session_resume_transport(
	struct mux_session *restrict ss, struct mux_session *restrict new_ss,
	const uint_least32_t client_resume_seq)
{
	g_resume_transport_calls++;
	g_resume_transport_ss = ss;
	g_resume_transport_new_ss = new_ss;
	g_resume_transport_seq = client_resume_seq;
	return true;
}

bool session_resume_ack_recv(
	struct mux_session *restrict ss, const uint_least32_t peer_ack)
{
	g_resume_ack_recv_calls++;
	ss->last_ack_recv = peer_ack;
	return true;
}

void sched_free_streams(struct mux_session *ss)
{
	g_sched_free_calls++;
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
	}
	ss->sched.streams = NULL;
}

static struct mux_session *resume_lookup_cb(
	void *data, struct mux_session *new_ss, const unsigned char *session_id)
{
	(void)data;
	(void)new_ss;
	(void)session_id;
	return g_resume_match;
}

static void setup_session(
	struct mux_session *restrict ss,
	struct frame_pool_ctx *restrict pool_ctx, const bool accepted)
{
	*ss = (struct mux_session){
		.state = SESSION_HANDSHAKE,
		.accepted = accepted,
		.pool = make_pool(pool_ctx),
		.tag = (char *)"[test]:",
	};
	ss->w_socket.fd = 11;
}

static int build_hello_frame(
	struct mux_frame *restrict frame, struct mux_header *restrict hdr,
	const struct proto_hello *restrict hello)
{
	const int len =
		proto_hello_build(frame->data, sizeof(frame->data), hello);
	if (len > 0) {
		frame->len = (size_t)len;
		frame->pos = (size_t)len;
		mux_read_header(frame->data, hdr);
	}
	return len;
}

static void build_raw_hello_frame(
	struct mux_frame *restrict frame, struct mux_header *restrict hdr,
	const char *restrict json)
{
	const size_t json_len = strlen(json);
	const struct mux_header local_hdr = {
		.version = 0,
		.flags = 0,
		.length = (uint_least16_t)json_len,
		.stream_id = 0,
		.extra = 0,
	};
	mux_write_header(frame->data, &local_hdr);
	memcpy(frame->data + MUX_FRAME_HEADER_SIZE, json, json_len);
	frame->len = MUX_FRAME_HEADER_SIZE + json_len;
	frame->pos = frame->len;
	*hdr = local_hdr;
}

T_DECLARE_CASE(test_proto_hello_build_and_parse_roundtrip)
{
	unsigned char buf[MUX_FRAME_SIZE];
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.reject_inbound = true,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 23,
		.has_identity = true,
	};
	struct proto_hello parsed;

	memset(hello.session_id, 0x5A, sizeof(hello.session_id));
	memcpy(hello.identity, "svc-a", sizeof("svc-a"));

	const int len = proto_hello_build(buf, sizeof(buf), &hello);
	T_EXPECT(len > (int)MUX_FRAME_HEADER_SIZE);
	T_EXPECT(proto_hello_parse(
		buf + MUX_FRAME_HEADER_SIZE,
		(size_t)len - MUX_FRAME_HEADER_SIZE, &parsed));
	T_EXPECT_EQ(parsed.version, (int)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(parsed.msgid, hello.msgid);
	T_EXPECT(parsed.reject_inbound);
	T_EXPECT(parsed.has_session_id);
	T_EXPECT(parsed.has_resume_seq);
	T_EXPECT_EQ(parsed.resume_seq, hello.resume_seq);
	T_EXPECT(parsed.has_identity);
	T_EXPECT(
		memcmp(parsed.session_id, hello.session_id,
		       sizeof(parsed.session_id)) == 0);
	T_EXPECT_STREQ(parsed.identity, hello.identity);
}

T_DECLARE_CASE(test_proto_hello_parse_rejects_missing_type)
{
	static const unsigned char json[] = "{\"msgid\":0}";
	struct proto_hello parsed;

	T_EXPECT(!proto_hello_parse(json, sizeof(json) - 1, &parsed));
}

T_DECLARE_CASE(test_proto_hello_parse_rejects_bad_session_id)
{
	static const unsigned char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=1\","
		"\"msgid\":0,\"session_id\":\"bad\"}";
	struct proto_hello parsed;

	T_EXPECT(!proto_hello_parse(json, sizeof(json) - 1, &parsed));
}

T_DECLARE_CASE(test_proto_hello_parse_rejects_oversized_identity)
{
	char identity[257];
	char json[512];
	struct proto_hello parsed;

	memset(identity, 'a', sizeof(identity) - 1);
	identity[sizeof(identity) - 1] = '\0';
	(void)snprintf(
		json, sizeof(json),
		"{\"type\":\"application/x-multiplexd-proto; version=1\","
		"\"msgid\":0,\"extensions\":{\"identity\":\"%s\"}}",
		identity);

	T_EXPECT(!proto_hello_parse(
		(const unsigned char *)json, strlen(json), &parsed));
}

T_DECLARE_CASE(test_handshake_enqueue_hello_includes_session_identity_and_resume)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct proto_hello parsed;

	handshake_stub_reset();
	setup_session(&ss, &pool_ctx, false);
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0xA4, sizeof(ss.handshake.session_id));
	ss.handshake.identity = (char *)"cli-service";
	ss.conf.reject_inbound = true;
	ss.recv_seq = 41;
	ss.last_ack_recv = 99;

	T_EXPECT(handshake_enqueue_hello(&ss, PROTO_MSG_CLIENT_HELLO, true));
	T_CHECK(ss.wire.sendbuf.head != NULL);
	T_EXPECT(ss.wire.tx_pending);
	T_EXPECT(proto_hello_parse(
		ss.wire.sendbuf.head->data + MUX_FRAME_HEADER_SIZE,
		ss.wire.sendbuf.head->len - MUX_FRAME_HEADER_SIZE, &parsed));
	T_EXPECT_EQ(parsed.msgid, PROTO_MSG_CLIENT_HELLO);
	T_EXPECT(parsed.reject_inbound);
	T_EXPECT(parsed.has_session_id);
	T_EXPECT(parsed.has_resume_seq);
	T_EXPECT_EQ(parsed.resume_seq, (uint_least32_t)41);
	T_EXPECT(parsed.has_identity);
	T_EXPECT_STREQ(parsed.identity, "cli-service");

	mux_frame_put(&ss.pool, ss.wire.sendbuf.head);
}

T_DECLARE_CASE(test_handshake_process_server_hello_assigns_peer_identity)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct mux_frame frame = { 0 };
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.reject_inbound = true,
		.has_session_id = true,
		.has_identity = true,
	};

	handshake_stub_reset();
	setup_session(&ss, &pool_ctx, false);
	memcpy(hello.identity, "srv-a", sizeof("srv-a"));
	memset(hello.session_id, 0x44, sizeof(hello.session_id));
	T_CHECK(build_hello_frame(&frame, &hdr, &hello) > 0);
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame.len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame.data, frame.len);
	ringbuf_produce(ss.wire.recvbuf, frame.len);

	T_EXPECT(handshake_process_hello(&ss, &hdr, frame.len));
	T_EXPECT_EQ(g_reset_calls, 0);
	T_EXPECT_EQ(g_handshake_done_calls, 1);
	T_EXPECT_EQ(ringbuf_readable(ss.wire.recvbuf), (size_t)0);
	T_EXPECT(ss.handshake.peer_rejects_inbound_streams);
	T_EXPECT(ss.handshake.has_session_id);
	T_EXPECT(
		memcmp(ss.handshake.session_id, hello.session_id,
		       sizeof(hello.session_id)) == 0);
	T_EXPECT(ss.handshake.peer_identity != NULL);
	T_EXPECT_STREQ(ss.handshake.peer_identity, "srv-a");

	if (ss.sched.streams != NULL) {
		table_free(ss.sched.streams);
		ss.sched.streams = NULL;
	}
	free(ss.handshake.peer_identity);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_handshake_process_resume_hello_calls_on_resume_match)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct mux_session resumed = { 0 };
	struct mux_frame frame = { 0 };
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_CLIENT_HELLO,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 99,
	};

	handshake_stub_reset();
	setup_session(&ss, &pool_ctx, true);
	memset(hello.session_id, 0x2C, sizeof(hello.session_id));
	T_CHECK(build_hello_frame(&frame, &hdr, &hello) > 0);
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame.len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame.data, frame.len);
	ringbuf_produce(ss.wire.recvbuf, frame.len);
	ss.callbacks.on_resume = resume_lookup_cb;
	g_resume_match = &resumed;

	T_EXPECT(!handshake_process_hello(&ss, &hdr, frame.len));
	T_EXPECT_EQ(g_resume_transport_calls, 1);
	T_EXPECT(g_resume_transport_ss == &resumed);
	T_EXPECT(g_resume_transport_new_ss == &ss);
	T_EXPECT_EQ(g_resume_transport_seq, (uint_least32_t)99);
	T_EXPECT_EQ(g_handshake_done_calls, 0);
	T_EXPECT_EQ(g_reset_calls, 0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_handshake_process_confirmed_resume_calls_resume_ack_recv)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct mux_frame frame = { 0 };
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 123,
	};

	handshake_stub_reset();
	setup_session(&ss, &pool_ctx, false);
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0x61, sizeof(ss.handshake.session_id));
	memcpy(hello.session_id, ss.handshake.session_id,
	       sizeof(hello.session_id));
	T_CHECK(build_hello_frame(&frame, &hdr, &hello) > 0);
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame.len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame.data, frame.len);
	ringbuf_produce(ss.wire.recvbuf, frame.len);

	T_EXPECT(handshake_process_hello(&ss, &hdr, frame.len));
	T_EXPECT_EQ(g_resume_ack_recv_calls, 1);
	T_EXPECT_EQ(ss.last_ack_recv, (uint_least32_t)123);
	T_EXPECT_EQ(g_handshake_done_calls, 1);
	T_EXPECT_EQ(g_reset_calls, 0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_handshake_process_confirmed_resume_rearms_write_watcher)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct mux_frame frame = { 0 };
	struct mux_frame retransmit = { 0 };
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 7,
	};

	handshake_stub_reset();
	setup_session(&ss, &pool_ctx, false);
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0x31, sizeof(ss.handshake.session_id));
	memcpy(hello.session_id, ss.handshake.session_id,
	       sizeof(hello.session_id));
	ss.retransmit_cursor = &retransmit;
	T_CHECK(build_hello_frame(&frame, &hdr, &hello) > 0);
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame.len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame.data, frame.len);
	ringbuf_produce(ss.wire.recvbuf, frame.len);

	T_EXPECT(handshake_process_hello(&ss, &hdr, frame.len));
	T_EXPECT_EQ(g_resume_ack_recv_calls, 1);
	T_EXPECT_EQ(g_handshake_done_calls, 1);
	T_EXPECT_EQ(g_update_watcher_calls, 1);
	T_EXPECT(ss.wire.tx_pending);
	T_EXPECT_EQ(g_reset_calls, 0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_handshake_process_invalid_version_resets_session)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct mux_frame frame = { 0 };
	struct mux_header hdr;
	static const char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=9\","
		"\"msgid\":1}";

	handshake_stub_reset();
	setup_session(&ss, &pool_ctx, false);
	build_raw_hello_frame(&frame, &hdr, json);
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame.len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame.data, frame.len);
	ringbuf_produce(ss.wire.recvbuf, frame.len);

	T_EXPECT(!handshake_process_hello(&ss, &hdr, frame.len));
	T_EXPECT_EQ(g_reset_calls, 1);
	T_EXPECT_EQ(g_handshake_done_calls, 0);
	ringbuf_free(ss.wire.recvbuf);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_proto_hello_build_and_parse_roundtrip);
	T_RUN_CASE(t, test_proto_hello_parse_rejects_missing_type);
	T_RUN_CASE(t, test_proto_hello_parse_rejects_bad_session_id);
	T_RUN_CASE(t, test_proto_hello_parse_rejects_oversized_identity);
	T_RUN_CASE(
		t,
		test_handshake_enqueue_hello_includes_session_identity_and_resume);
	T_RUN_CASE(
		t, test_handshake_process_server_hello_assigns_peer_identity);
	T_RUN_CASE(
		t, test_handshake_process_resume_hello_calls_on_resume_match);
	T_RUN_CASE(
		t,
		test_handshake_process_confirmed_resume_calls_resume_ack_recv);
	T_RUN_CASE(
		t,
		test_handshake_process_confirmed_resume_rearms_write_watcher);
	T_RUN_CASE(t, test_handshake_process_invalid_version_resets_session);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
