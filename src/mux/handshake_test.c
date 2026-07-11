/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* handshake_test.c - white-box tests for handshake.c (proto_hello build/parse
 * and handshake_process_hello). Dependencies: handshake.c #included; real
 * frame.c/proto_schema.gen.c linked; session/unacked/sched mocked. */

#include "mux/handshake.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"

#include "algo/hashtable.h"
#include "utils/testing.h"

#include <inttypes.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pull in the static symbols under test directly. */
#include "mux/handshake.c"

/* mock - collaborator mocks, frame pool, session fixtures, helpers */

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static uint_least32_t g_resume_seq;
static int g_reset_calls;
static int g_handshake_done_calls;
static int g_resume_calls;
static int g_resume_ack_recv_calls;
static int g_sched_free_calls;
static int g_update_watcher_calls;
/* Configurable mock outcomes (defaults set by handshake_mock_reset). */
static bool g_resume_ack_result;
static bool g_resume_handled;

static void handshake_mock_reset(void)
{
	g_resume_seq = 0;
	g_reset_calls = 0;
	g_handshake_done_calls = 0;
	g_resume_calls = 0;
	g_resume_ack_recv_calls = 0;
	g_sched_free_calls = 0;
	g_update_watcher_calls = 0;
	g_resume_ack_result = true;
	g_resume_handled = false;
}

static struct mux_frame *handshake_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
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
	ss->state = SESSION_CLOSED;
	g_reset_calls++;
}

void session_handshake_done(struct mux_session *ss)
{
	(void)ss;
	g_handshake_done_calls++;
}

void update_watcher(struct mux_session *ss)
{
	(void)ss;
	g_update_watcher_calls++;
}

void session_notify(struct mux_session *restrict ss)
{
	update_watcher(ss);
}

bool unacked_resume_ack_recv(
	struct mux_session *restrict ss, const uint_least32_t peer_ack)
{
	g_resume_ack_recv_calls++;
	ss->unacked.last_ack_recv = peer_ack;
	return g_resume_ack_result;
}

void unacked_free_all(struct mux_session *ss)
{
	mux_frame_ring_free(&ss->unacked.ring, &ss->pool);
	ss->unacked.frames = 0;
	ss->unacked.bytes = 0;
	ss->unacked.partial_offset = 0;
	ss->unacked.retransmit_off = SIZE_MAX;
}

void sched_free_streams(struct mux_session *restrict ss)
{
	g_sched_free_calls++;
	ss->sched.sched_head = NULL;
	ss->sched.sched_tail = NULL;
	ss->sched.drr_active = NULL;
	ss->sched.lp_head = NULL;
	ss->sched.lp_tail = NULL;
	ss->sched.delay_head = NULL;
	ss->unacked.stalled = false;
	ss->sched.num_tombstones = 0;
	ss->sched.next_stream_id = 0;
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
}

static bool resume_lookup_cb(
	void *data, struct mux_session *new_ss, const unsigned char *session_id,
	const uint_least32_t resume_seq)
{
	(void)data;
	(void)new_ss;
	(void)session_id;
	g_resume_calls++;
	g_resume_seq = resume_seq;
	return g_resume_handled;
}

static void setup_session(
	struct mux_session *restrict ss,
	struct frame_pool_ctx *restrict pool_ctx, const bool accepted)
{
	*ss = (struct mux_session){
		.state = SESSION_HANDSHAKE,
		.accepted = accepted,
		.pool = make_pool(pool_ctx),
		.max_payload =
			(uint_least32_t)mux_conf_default.max_frame_payload,
		.tag = "[test]:",
	};
	ss->w_socket.fd = 11;
}

static void teardown_session(struct mux_session *restrict ss)
{
	/* Free frames queued by handshake_enqueue_hello (server fresh path). */
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	/* Free unacked ring (empty in fuzz sessions). */
	unacked_free_all(ss);
	/* Free peer identity string (strdup'd by handshake_process_hello). */
	free(ss->handshake.peer_identity);
	ss->handshake.peer_identity = NULL;
	/* Free stream table (allocated by table_new on client fresh-session path). */
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
	ringbuf_free(ss->wire.recvbuf);
	ss->wire.recvbuf = NULL;
}

static bool build_hello_frame(
	struct mux_frame *restrict frame, struct mux_header *restrict hdr,
	const struct proto_hello *restrict hello)
{
	if (!proto_hello_build(frame, MUX_MAX_PAYLOAD_SIZE, hello)) {
		return false;
	}
	frame->pos = frame->len;
	mux_read_header(frame->data, hdr);
	return true;
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

/* regression - targeted cases pinning one parse/dispatch decision each */

T_DECLARE_CASE(test_proto_hello_build_and_parse_roundtrip)
{
	struct mux_frame *const frame =
		malloc(MUX_FRAME_OBJECT_SIZE(MUX_MAX_PAYLOAD_SIZE));
	T_EXPECT(frame != NULL);
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

	T_EXPECT(proto_hello_build(frame, MUX_MAX_PAYLOAD_SIZE, &hello));
	T_EXPECT(frame->len > MUX_FRAME_HEADER_SIZE);
	T_EXPECT(proto_hello_parse(
		frame->data + MUX_FRAME_HEADER_SIZE,
		frame->len - MUX_FRAME_HEADER_SIZE, &parsed));
	T_EXPECT_EQ(parsed.version, (int)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(parsed.msgid, hello.msgid);
	T_EXPECT(parsed.reject_inbound);
	T_EXPECT(parsed.has_session_id);
	/* has_resume_seq is not populated on the parse side (has_session_id is
	 * the resume discriminant); only the resume_seq value is read back. */
	T_EXPECT_EQ(parsed.resume_seq, hello.resume_seq);
	T_EXPECT(parsed.has_identity);
	T_EXPECT(
		memcmp(parsed.session_id, hello.session_id,
		       sizeof(parsed.session_id)) == 0);
	T_EXPECT_STREQ(parsed.identity, hello.identity);
	free(frame);
}

T_DECLARE_CASE(test_proto_hello_parse_rejects_missing_type)
{
	static const unsigned char json[] = "{\"msgid\":0}";
	struct proto_hello parsed;

	T_EXPECT(!proto_hello_parse(json, sizeof(json) - 1, &parsed));
}

/* A type field with an embedded NUL (a JSON u0000 escape) whose
 * strlen-truncated prefix is itself a valid type ("...; version=1") must be
 * rejected, not silently accepted with the post-NUL bytes dropped:
 * proto_parse_type validates obj.type.len, not strlen. */
T_DECLARE_CASE(test_proto_hello_parse_rejects_type_embedded_nul)
{
	static const unsigned char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=1\\u0000x\","
		"\"msgid\":0}";
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

/* The identity extension is documented as UTF-8 on the wire
 * (proto_schema.json); malformed UTF-8 must be rejected by the shared JSON
 * string decoder proto_hello_parse relies on, not silently accepted. */
T_DECLARE_CASE(test_proto_hello_parse_rejects_invalid_utf8_identity)
{
	static const char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=1\","
		"\"msgid\":0,\"extensions\":{\"identity\":\"\xc2(\"}}";
	struct proto_hello parsed;

	T_EXPECT(!proto_hello_parse(
		(const unsigned char *)json, sizeof(json) - 1, &parsed));
}

/* Well-formed multi-byte UTF-8 in the identity extension must still parse. */
T_DECLARE_CASE(test_proto_hello_parse_accepts_well_formed_utf8_identity)
{
	static const char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=1\","
		"\"msgid\":0,\"extensions\":{\"identity\":\"\xc3\xa9\xe4\xb8\xad\"}}";
	struct proto_hello parsed;

	T_CHECK(proto_hello_parse(
		(const unsigned char *)json, sizeof(json) - 1, &parsed));
	T_EXPECT(parsed.has_identity);
	T_EXPECT_STREQ(parsed.identity, "\xc3\xa9\xe4\xb8\xad");
}

T_DECLARE_CASE(test_handshake_enqueue_hello_includes_session_identity_and_resume)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct proto_hello parsed;

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0xA4, sizeof(ss.handshake.session_id));
	ss.handshake.identity = (char *)"cli-service";
	ss.conf.reject_inbound = true;
	ss.unacked.recv_seq = 41;
	ss.unacked.unreported = 7;
	ss.unacked.last_ack_recv = 99;

	T_EXPECT(handshake_enqueue_hello(&ss, PROTO_MSG_CLIENT_HELLO, true));
	T_CHECK(ss.wire.sendbuf.head != NULL);
	T_EXPECT(ss.wire.tx_pending);
	T_EXPECT(proto_hello_parse(
		ss.wire.sendbuf.head->data + MUX_FRAME_HEADER_SIZE,
		ss.wire.sendbuf.head->len - MUX_FRAME_HEADER_SIZE, &parsed));
	T_EXPECT_EQ(parsed.msgid, PROTO_MSG_CLIENT_HELLO);
	T_EXPECT(parsed.reject_inbound);
	T_EXPECT(parsed.has_session_id);
	/* has_resume_seq is not populated on the parse side; only resume_seq is. */
	T_EXPECT_EQ(parsed.resume_seq, (uint_least32_t)41);
	T_EXPECT_EQ(ss.unacked.unreported, (uint_least32_t)0);
	T_EXPECT(parsed.has_identity);
	T_EXPECT_STREQ(parsed.identity, "cli-service");

	mux_frame_put(&ss.pool, ss.wire.sendbuf.head);
}

/* An identity.claim too long for the wire hello's identity field must be
 * omitted rather than truncated, and the hello must still build and send. */
T_DECLARE_CASE(test_handshake_enqueue_hello_omits_oversized_identity)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct proto_hello parsed;
	char identity[257];

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	memset(identity, 'a', sizeof(identity) - 1);
	identity[sizeof(identity) - 1] = '\0';
	T_CHECK(strlen(identity) == sizeof(parsed.identity));
	ss.handshake.identity = identity;

	T_EXPECT(handshake_enqueue_hello(&ss, PROTO_MSG_CLIENT_HELLO, false));
	T_CHECK(ss.wire.sendbuf.head != NULL);
	T_EXPECT(proto_hello_parse(
		ss.wire.sendbuf.head->data + MUX_FRAME_HEADER_SIZE,
		ss.wire.sendbuf.head->len - MUX_FRAME_HEADER_SIZE, &parsed));
	T_EXPECT_EQ(parsed.msgid, PROTO_MSG_CLIENT_HELLO);
	T_EXPECT(!parsed.has_identity);

	mux_frame_put(&ss.pool, ss.wire.sendbuf.head);
}

/* Declare a stack-backed frame with a real payload buffer: struct mux_frame's
 * data[] is a flexible array member, so a bare `struct mux_frame f` has no
 * payload storage.  Zero-initialised; pointer named @p name. */
#define TEST_FRAME(name)                                                       \
	alignas(max_align_t) unsigned char name##_buf_[MUX_FRAME_OBJECT_SIZE(  \
		(size_t)MUX_MAX_PAYLOAD_SIZE)] = { 0 };                        \
	struct mux_frame *const name = (struct mux_frame *)name##_buf_

T_DECLARE_CASE(test_handshake_process_server_hello_assigns_peer_identity)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.reject_inbound = true,
		.has_session_id = true,
		.has_identity = true,
	};

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	memcpy(hello.identity, "srv-a", sizeof("srv-a"));
	memset(hello.session_id, 0x44, sizeof(hello.session_id));
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(ss.wire.recvbuf, frame->len);

	T_EXPECT(handshake_process_hello(&ss, &hdr, frame->len));
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
	TEST_FRAME(frame);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_CLIENT_HELLO,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 99,
	};

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, true);
	memset(hello.session_id, 0x2C, sizeof(hello.session_id));
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(ss.wire.recvbuf, frame->len);
	ss.callbacks.on_resume = resume_lookup_cb;
	/* The owner reports it handled the resume (located the suspended session
	 * and took this transient session's transport). */
	g_resume_handled = true;

	T_EXPECT(!handshake_process_hello(&ss, &hdr, frame->len));
	T_EXPECT_EQ(g_resume_calls, 1);
	T_EXPECT_EQ(g_resume_seq, (uint_least32_t)99);
	/* Handed off: no fresh handshake, and the transient session is reset so
	 * socket_cb tears it down. */
	T_EXPECT_EQ(g_handshake_done_calls, 0);
	T_EXPECT_EQ(g_reset_calls, 1);
	T_EXPECT_EQ((int)ss.state, (int)SESSION_CLOSED);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_handshake_process_confirmed_resume_calls_resume_ack_recv)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 123,
	};

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0x61, sizeof(ss.handshake.session_id));
	memcpy(hello.session_id, ss.handshake.session_id,
	       sizeof(hello.session_id));
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(ss.wire.recvbuf, frame->len);

	T_EXPECT(handshake_process_hello(&ss, &hdr, frame->len));
	T_EXPECT_EQ(g_resume_ack_recv_calls, 1);
	T_EXPECT_EQ(ss.unacked.last_ack_recv, (uint_least32_t)123);
	T_EXPECT_EQ(g_handshake_done_calls, 1);
	T_EXPECT_EQ(g_reset_calls, 0);
	free(ss.handshake.peer_identity);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_handshake_process_confirmed_resume_rearms_write_watcher)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	TEST_FRAME(retransmit);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 7,
	};

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0x31, sizeof(ss.handshake.session_id));
	memcpy(hello.session_id, ss.handshake.session_id,
	       sizeof(hello.session_id));
	/* Set up retransmit state: ring with one frame, offset at head. */
	ss.unacked.ring = mux_frame_ring_grow(ss.unacked.ring);
	T_CHECK(ss.unacked.ring != NULL);
	retransmit->unacked_count = 1;
	T_CHECK(mux_frame_ring_push(&ss.unacked.ring, retransmit));
	ss.unacked.frames = 1;
	ss.unacked.retransmit_off = 0;
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(ss.wire.recvbuf, frame->len);

	T_EXPECT(handshake_process_hello(&ss, &hdr, frame->len));
	T_EXPECT_EQ(g_resume_ack_recv_calls, 1);
	T_EXPECT_EQ(g_handshake_done_calls, 1);
	T_EXPECT_EQ(g_update_watcher_calls, 1);
	T_EXPECT(ss.wire.tx_pending);
	T_EXPECT_EQ(g_reset_calls, 0);
	/* Ring owns retransmit (stack var); clear ring only, don't mux_frame_put. */
	free(ss.unacked.ring);
	ss.unacked.ring = NULL;
	free(ss.handshake.peer_identity);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_handshake_process_invalid_version_resets_session)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	struct mux_header hdr;
	static const char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=9\","
		"\"msgid\":1}";

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	build_raw_hello_frame(frame, &hdr, json);
	ringbuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = ringbuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	ringbuf_produce(ss.wire.recvbuf, frame->len);

	T_EXPECT(!handshake_process_hello(&ss, &hdr, frame->len));
	T_EXPECT_EQ(g_reset_calls, 1);
	T_EXPECT_EQ(g_handshake_done_calls, 0);
	ringbuf_free(ss.wire.recvbuf);
}

/* proto_hello_parse rejects a frame whose declared length exceeds the protocol
 * payload cap before touching the buffer. */
T_DECLARE_CASE(test_proto_hello_parse_rejects_oversized_json)
{
	static const unsigned char json[] = "{}";
	struct proto_hello parsed;
	T_EXPECT(!proto_hello_parse(
		json, (size_t)MUX_MAX_PAYLOAD_SIZE + 1, &parsed));
}

/* handshake_process_hello resets the session when a hello arrives outside the
 * SESSION_HANDSHAKE state. */
T_DECLARE_CASE(test_handshake_process_hello_outside_handshake_resets)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	struct mux_header hdr = { 0 };

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	ss.state = SESSION_ESTABLISHED; /* not HANDSHAKE */

	/* hdr is zero-initialized (length=0); frame_size must match the
	 * caller-guaranteed MUX_FRAME_HEADER_SIZE + hdr.length invariant. */
	T_EXPECT(!handshake_process_hello(&ss, &hdr, MUX_FRAME_HEADER_SIZE));
	T_EXPECT_EQ(g_reset_calls, 1);
}

/* fuzz - proto_hello_parse and handshake_process_hello, three modes:
 * random bytes, synthesized JSON, full frames with varied headers.
 * Set MUX_FUZZ_SEED/MUX_FUZZ_ITERATIONS to reproduce; seed fixed for CI. */

/* Splitmix64 PRNG */

static uint64_t g_prng;

static uint64_t prng_next(void)
{
	uint64_t z = (g_prng += UINT64_C(0x9e3779b97f4a7c15));
	z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
	return z ^ (z >> 31);
}

static uint32_t prng_u32(void)
{
	return (uint32_t)prng_next();
}

/* Returns a value in [0, n). n must be > 0. */
static size_t prng_range(const size_t n)
{
	return (size_t)(prng_next() % (uint64_t)n);
}

static bool prng_bool(void)
{
	return (prng_next() & 1u) != 0;
}

/* Input corpus: MIME type variants, session_id variants, etc. */

static const char *const k_types[] = {
	/* valid (3x weight so deep parsing paths are hit often) */
	"application/x-multiplexd-proto; version=1",
	"application/x-multiplexd-proto; version=1",
	"application/x-multiplexd-proto; version=1",
	/* wrong version number */
	"application/x-multiplexd-proto; version=2",
	"application/x-multiplexd-proto; version=0",
	"application/x-multiplexd-proto; version=255",
	"application/x-multiplexd-proto; version=256",
	"application/x-multiplexd-proto; version=99999999999999999999",
	"application/x-multiplexd-proto; version=-1",
	"application/x-multiplexd-proto; version=01",
	"application/x-multiplexd-proto; version=",
	/* missing version parameter */
	"application/x-multiplexd-proto",
	/* extra parameters */
	"application/x-multiplexd-proto; charset=utf-8; version=1",
	"application/x-multiplexd-proto; version=1; extra=ignored",
	/* wrong media type or subtype */
	"text/plain; version=1",
	"application/json; version=1",
	/* empty string */
	"",
};

#define k_ntypes (sizeof(k_types) / sizeof(k_types[0]))

/* Base64-encoded session_id variants (all exactly 24 chars unless noted). */
static const char *const k_session_ids[] = {
	/* valid: 24-char base64 encoding of 16 zero bytes */
	"AAAAAAAAAAAAAAAAAAAAAA==",
	/* valid: same length, different content */
	"AAAAAAAAAAAAAAAAAAAAAB==",
	/* too short: 23 chars */
	"AAAAAAAAAAAAAAAAAAAAAA=",
	/* too long: 25 chars */
	"AAAAAAAAAAAAAAAAAAAAAA===",
	/* missing padding: 22 chars */
	"AAAAAAAAAAAAAAAAAAAAAA",
	/* 24 chars with two invalid base64 characters */
	"AAAAAAAAAAAAAAAAAAAAAA!!",
	/* all-valid but non-zero content */
	"/////////////////////w==",
};

#define k_nsids (sizeof(k_session_ids) / sizeof(k_session_ids[0]))

/* resume_seq edge-case values as unsigned integers */
static const uint_fast64_t k_seqs[] = {
	0,
	1,
	65535,
	2147483647,
	4294967295UL, /* UINT32_MAX */
	4294967296ULL, /* UINT32_MAX + 1 */
	UINT_FAST64_MAX,
};

#define k_nseqs (sizeof(k_seqs) / sizeof(k_seqs[0]))

/* msgid edge-case values */
static const int k_msgids[] = {
	PROTO_MSG_CLIENT_HELLO,
	PROTO_MSG_SERVER_HELLO,
	PROTO_MSG_CLIENT_HELLO, /* doubled weight for valid values */
	PROTO_MSG_SERVER_HELLO,
	2,
	-1,
	0x7fffffff,
};

#define k_nmsgids (sizeof(k_msgids) / sizeof(k_msgids[0]))

/* Scratch buffer size for gen_structured_json; sized to never truncate
 * a complete structured JSON in practice (~600 chars maximum). */
#define JBUF_SIZE 768

/* Maximum JSON bytes fed to proto_hello_parse per iteration. */
#define FUZZ_JSON_CAP 512u

/* Maximum frame bytes for Mode C. */
#define FUZZ_FRAME_CAP (MUX_FRAME_HEADER_SIZE + FUZZ_JSON_CAP)

/* Append formatted text to json[], advancing the enclosing-scope `off` and
 * capping at JBUF_SIZE-1; calls past the buffer end are silently dropped. */
#define JAPP(...)                                                              \
	do {                                                                   \
		if (off < JBUF_SIZE - 1) {                                     \
			const int _space = JBUF_SIZE - 1 - off;                \
			const int _n = snprintf(                               \
				json + off, (size_t)(_space + 1),              \
				__VA_ARGS__);                                  \
			off += (_n > 0 && _n <= _space) ? _n : _space;         \
		}                                                              \
	} while (0)

/* Synthesize a structured hello JSON payload into buf (up to cap bytes);
 * applies 0-4 random bit-flip mutations.  Returns actual length written. */
static size_t gen_structured_json(unsigned char *restrict buf, const size_t cap)
{
	char json[JBUF_SIZE];
	int off = 0;

	const char *const type = k_types[prng_range(k_ntypes)];
	const int msgid = k_msgids[prng_range(k_nmsgids)];

	JAPP("{\"type\":\"%s\",\"msgid\":%d", type, msgid);

	if (prng_bool()) {
		const char *const sid = k_session_ids[prng_range(k_nsids)];
		JAPP(",\"session_id\":\"%s\"", sid);
	}

	if (prng_bool()) {
		const uint_fast64_t seq = k_seqs[prng_range(k_nseqs)];
		JAPP(",\"resume_seq\":%" PRIuFAST64, seq);
	}

	if (prng_bool()) {
		JAPP(",\"extensions\":{");
		bool first = true;

		if (prng_bool()) {
			/* reject_inbound: usually boolean, sometimes wrong type */
			if (prng_range(4) == 0) {
				JAPP("%s\"reject_inbound\":\"yes\"",
				     first ? "" : ",");
			} else {
				JAPP("%s\"reject_inbound\":true",
				     first ? "" : ",");
			}
			first = false;
		}

		if (prng_bool()) {
			/* Identity: lengths 0-300, crossing the 255-char limit. */
			const size_t id_len = prng_range(301);
			char id[301];
			for (size_t i = 0; i < id_len; i++) {
				id[i] = (char)('a' + (int)prng_range(26));
			}
			id[id_len] = '\0';
			JAPP("%s\"identity\":\"%s\"", first ? "" : ",", id);
			first = false;
		}

		/* Unknown extension key: should be silently ignored. */
		if (prng_bool()) {
			JAPP("%s\"unknown_ext_key\":42", first ? "" : ",");
		}

		JAPP("}");
	}

	/* Unknown top-level field: should be silently ignored. */
	if (prng_bool()) {
		JAPP(",\"_unknown\":\"ignored\"");
	}

	JAPP("}");

	/* Apply 0-4 random bit-flip mutations. */
	const int nflips = (int)prng_range(5);
	for (int i = 0; i < nflips && off > 0; i++) {
		const size_t pos = prng_range((size_t)off);
		const int bit = (int)prng_range(8);
		json[pos] = (char)(json[pos] ^ (1u << bit));
	}

	const size_t len = (off > 0) ? (size_t)off : 0u;
	const size_t copy_len = (len < cap) ? len : cap;
	memcpy(buf, json, copy_len);
	return copy_len;
}

#undef JAPP

/* Build a structured hello via proto_hello_build with randomized fields;
 * apply 0-4 bit-flip mutations.  Returns JSON length (after frame header). */
static size_t gen_hello_build(unsigned char *restrict buf, const size_t cap)
{
	static const uint32_t k_build_seqs[] = {
		0, 1, 65535, 2147483647u, 4294967295u,
	};

	struct proto_hello hello = { 0 };
	hello.msgid = k_msgids[prng_range(k_nmsgids)];
	hello.reject_inbound = prng_bool();

	if (prng_bool()) {
		hello.has_session_id = true;
		for (size_t i = 0; i < MUX_SESSION_ID_LEN; i++) {
			hello.session_id[i] = (unsigned char)prng_u32();
		}
	}

	if (prng_bool()) {
		hello.has_resume_seq = true;
		hello.resume_seq = k_build_seqs[prng_range(
			sizeof(k_build_seqs) / sizeof(k_build_seqs[0]))];
	}

	if (prng_bool()) {
		hello.has_identity = true;
		/* Length 0-254: all fit in proto_hello.identity[256]. */
		const size_t id_len = prng_range(255);
		for (size_t i = 0; i < id_len; i++) {
			hello.identity[i] = (char)('a' + (int)prng_range(26));
		}
		hello.identity[id_len] = '\0';
	}

	struct mux_frame *const frame =
		malloc(MUX_FRAME_OBJECT_SIZE(MUX_MAX_PAYLOAD_SIZE));
	if (frame == NULL ||
	    !proto_hello_build(frame, MUX_MAX_PAYLOAD_SIZE, &hello)) {
		free(frame);
		return 0u;
	}

	const size_t json_len = frame->len - MUX_FRAME_HEADER_SIZE;
	const size_t copy_len = (json_len < cap) ? json_len : cap;
	memcpy(buf, frame->data + MUX_FRAME_HEADER_SIZE, copy_len);
	free(frame);

	/* Apply 0-4 bit-flip mutations. */
	const int nflips = (int)prng_range(5);
	for (int i = 0; i < nflips && copy_len > 0; i++) {
		const size_t pos = prng_range(copy_len);
		const int bit = (int)prng_range(8);
		buf[pos] ^= (unsigned char)(1u << bit);
	}

	return copy_len;
}

static void print_fuzz_context(
	const size_t iter, const uint64_t seed, const unsigned char *input,
	const size_t len)
{
	(void)fprintf(
		stderr,
		"FUZZ FAILURE: iter=%zu seed=0x%016" PRIx64 " len=%zu\n", iter,
		seed, len);
	(void)fprintf(stderr, "  input:");
	for (size_t i = 0; i < len; i++) {
		(void)fprintf(stderr, " %02x", input[i]);
	}
	(void)fprintf(stderr, "\n");
	(void)fflush(stderr);
}

T_DECLARE_CASE(test_handshake_fuzz)
{
	/* Seed: use a different default from dispatch_fuzz so CI catches
	 * failures in different iteration orderings. */
	uint64_t seed = UINT64_C(0xdeadbeefcafe0002);
	const char *const env_seed = getenv("MUX_FUZZ_SEED");
	if (env_seed != NULL) {
		seed = (uint64_t)strtoull(env_seed, NULL, 0);
	}
	g_prng = seed;

	size_t iterations = 200000;
	const char *const env_iter = getenv("MUX_FUZZ_ITERATIONS");
	if (env_iter != NULL) {
		const unsigned long v = strtoul(env_iter, NULL, 10);
		if (v > 0) {
			iterations = (size_t)v;
		}
	}

	static unsigned char json_buf[FUZZ_JSON_CAP];
	static unsigned char frame_buf[FUZZ_FRAME_CAP];

	for (size_t iter = 0; iter < iterations; iter++) {
		handshake_mock_reset();
		g_resume_ack_result = prng_bool();

		const size_t mode = prng_range(10);

		/* Mode A (30%): Random bytes -> proto_hello_parse */
		if (mode < 3u) {
			const size_t len = prng_range(FUZZ_JSON_CAP + 1u);
			for (size_t i = 0; i < len; i++) {
				json_buf[i] = (unsigned char)prng_u32();
			}

			struct proto_hello out;
			const bool ok = proto_hello_parse(json_buf, len, &out);

			/* Invariant 1: successful parse implies valid version. */
			if (ok && out.version <= 0) {
				print_fuzz_context(iter, seed, json_buf, len);
				T_FATAL("invariant 1 violated: "
					"proto_hello_parse true but "
					"version <= 0");
			}

			/* Mode B (40%): Structured JSON -> proto_hello_parse */
		} else if (mode < 7u) {
			size_t len;
			if (prng_bool()) {
				/* B1: proto_hello_build with random fields
				 * and bit-flip mutations. */
				len = gen_hello_build(
					json_buf, sizeof(json_buf));
			} else {
				/* B2: Hand-crafted JSON with edge-case field
				 * values and bit-flip mutations. */
				len = gen_structured_json(
					json_buf, sizeof(json_buf));
			}

			struct proto_hello out;
			const bool ok = proto_hello_parse(json_buf, len, &out);

			if (ok && out.version <= 0) {
				print_fuzz_context(iter, seed, json_buf, len);
				T_FATAL("invariant 1 violated: "
					"proto_hello_parse true but "
					"version <= 0");
			}

			/* Mode C (30%): Frame -> handshake_process_hello */
		} else {
			/* Generate JSON body. */
			size_t json_len;
			if (prng_range(3u) == 0u) {
				/* Random body. */
				json_len = prng_range(FUZZ_JSON_CAP + 1u);
				for (size_t i = 0; i < json_len; i++) {
					frame_buf[MUX_FRAME_HEADER_SIZE + i] =
						(unsigned char)prng_u32();
				}
			} else {
				/* Structured body. */
				json_len = gen_structured_json(
					frame_buf + MUX_FRAME_HEADER_SIZE,
					FUZZ_JSON_CAP);
			}

			/* version=0 (hello) is not validated; keep 0 like the real
			 * call site.  flags/stream_id/extra: usually 0, sometimes
			 * corrupted to exercise the header-validation path. */
			struct mux_header hdr = {
				.version = 0,
				.flags = 0,
				.stream_id = 0,
				.extra = 0,
				.length = (uint_least16_t)json_len,
			};
			/* ~40 % of Mode C: corrupt one or more header fields. */
			if (prng_range(5u) >= 3u) {
				if (prng_bool()) {
					hdr.flags =
						(uint_least8_t)(1u +
								prng_range(
									255u));
				}
				if (prng_bool()) {
					hdr.stream_id =
						(uint_least16_t)(1u +
								 prng_range(
									 65535u));
				}
				if (prng_bool()) {
					hdr.extra =
						(uint_least16_t)(1u +
								 prng_range(
									 65535u));
				}
				/* Guarantee at least one field is non-zero so
				 * that the header-validation path is actually
				 * exercised. */
				if (hdr.flags == 0 && hdr.stream_id == 0 &&
				    hdr.extra == 0) {
					hdr.flags = 1;
				}
			}
			mux_write_header(frame_buf, &hdr);

			const size_t frame_size =
				MUX_FRAME_HEADER_SIZE + json_len;
			const bool accepted = prng_bool();

			/* Set up session. */
			struct frame_pool_ctx pool_ctx = { 0 };
			struct mux_session ss;
			setup_session(&ss, &pool_ctx, accepted);

			/* Client role: sometimes pre-populate session_id so
			 * a matching ServerHello exercises the confirmed-resume
			 * path (spec §5.8.3). */
			if (!accepted && prng_range(4u) == 0u) {
				ss.handshake.has_session_id = true;
				for (size_t i = 0; i < MUX_SESSION_ID_LEN;
				     i++) {
					ss.handshake.session_id[i] =
						(unsigned char)prng_u32();
				}
			}

			ss.wire.recvbuf = ringbuf_new(frame_size);
			if (ss.wire.recvbuf == NULL) {
				/* OOM: skip iteration. */
				continue;
			}
			memcpy(ringbuf_write_ptr(ss.wire.recvbuf), frame_buf,
			       frame_size);
			ringbuf_produce(ss.wire.recvbuf, frame_size);

			const bool ret =
				handshake_process_hello(&ss, &hdr, frame_size);

			/* Invariant 2: state must be a valid session_state. */
			if ((unsigned)ss.state > (unsigned)SESSION_CLOSED) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 2 violated: "
					"session state out of range");
			}

			/* Invariant 3: session_reset -> SESSION_CLOSED. */
			if (g_reset_calls > 0 && ss.state != SESSION_CLOSED) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 3 violated: "
					"session_reset called but "
					"state != SESSION_CLOSED");
			}

			/* Invariant 4: return true -> exactly one
			 * session_handshake_done call. */
			if (ret && g_handshake_done_calls != 1) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 4 violated: "
					"handshake_process_hello returned true "
					"but session_handshake_done not called "
					"exactly once");
			}

			/* Invariant 5: handshake_done and session_reset are
			 * mutually exclusive within a single call. */
			if (g_handshake_done_calls > 0 && g_reset_calls > 0) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 5 violated: "
					"session_handshake_done and "
					"session_reset both called");
			}

			teardown_session(&ss);
		}
	}
}

static const struct testing_suite suite[] = {
	T_CASE(test_proto_hello_build_and_parse_roundtrip),
	T_CASE(test_proto_hello_parse_rejects_missing_type),
	T_CASE(test_proto_hello_parse_rejects_type_embedded_nul),
	T_CASE(test_proto_hello_parse_rejects_bad_session_id),
	T_CASE(test_proto_hello_parse_rejects_oversized_identity),
	T_CASE(test_proto_hello_parse_rejects_invalid_utf8_identity),
	T_CASE(test_proto_hello_parse_accepts_well_formed_utf8_identity),
	T_CASE(test_handshake_enqueue_hello_includes_session_identity_and_resume),
	T_CASE(test_handshake_enqueue_hello_omits_oversized_identity),
	T_CASE(test_handshake_process_server_hello_assigns_peer_identity),
	T_CASE(test_handshake_process_resume_hello_calls_on_resume_match),
	T_CASE(test_handshake_process_confirmed_resume_calls_resume_ack_recv),
	T_CASE(test_handshake_process_confirmed_resume_rearms_write_watcher),
	T_CASE(test_handshake_process_invalid_version_resets_session),
	T_CASE(test_proto_hello_parse_rejects_oversized_json),
	T_CASE(test_handshake_process_hello_outside_handshake_resets),
	T_CASE(test_handshake_fuzz),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
