/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* handshake_test.c - white-box tests for handshake.c (proto_hello build/parse
 * and mux_handshake_process_hello). Dependencies: handshake.c #included; real
 * frame.c/proto_schema.gen.c linked; session/unacked/sched mocked. */

#include "mux/handshake.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/unacked.h"

#include "algo/hashtable.h"
#include "meta/arraysize.h"
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

/* proto_hello_parse only reads ss->tag to prefix its log lines; a zeroed
 * session (tag == NULL, so MUX_LOG falls back to "[?]:") is all the pure-parse
 * cases need, and spares them a full setup_session fixture. */
static const struct mux_session k_parse_test_session;

static int g_verify_calls;
static bool g_verify_result;
static bool g_verify_saw_null;
static char g_verify_identity[256];

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
	g_verify_calls = 0;
	g_verify_result = true;
	g_verify_saw_null = false;
	g_verify_identity[0] = '\0';
}

static bool
verify_identity_cb(void *data, struct mux_session *ss, const char *identity)
{
	(void)data;
	(void)ss;
	g_verify_calls++;
	g_verify_saw_null = (identity == NULL);
	if (identity != NULL) {
		(void)snprintf(
			g_verify_identity, sizeof(g_verify_identity), "%s",
			identity);
	}
	return g_verify_result;
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

void mux_session_reset(struct mux_session *ss)
{
	ss->state = SESSION_CLOSED;
	g_reset_calls++;
}

void mux_session_handshake_done(struct mux_session *ss)
{
	(void)ss;
	g_handshake_done_calls++;
}

void update_watcher(struct mux_session *ss)
{
	(void)ss;
	g_update_watcher_calls++;
}

void mux_session_notify(struct mux_session *restrict ss)
{
	update_watcher(ss);
}

bool mux_unacked_resume_ack_recv(
	struct mux_session *restrict ss, const uint_least32_t peer_ack)
{
	g_resume_ack_recv_calls++;
	ss->unacked.last_ack_recv = peer_ack;
	return g_resume_ack_result;
}

/* Mirrors unacked.c's teardown field for field: the gauge payback, the
 * unacked_set_replay_off routing (which also zeroes retransmitted_frames) and
 * retransmit_copy_count all belong to the contract handshake_client_fresh
 * relies on, so a double that skipped any of them would model behavior
 * production does not have. */
void mux_unacked_free_all(struct mux_session *ss)
{
	mux_frame_ring_free(&ss->unacked.ring, &ss->pool);
	COUNTER_SUB(ss->cnt.buffers.unacked_frames, ss->unacked.frames);
	ss->unacked.frames = 0;
	ss->unacked.bytes = 0;
	ss->unacked.partial_offset = 0;
	unacked_set_replay_off(&ss->unacked, SIZE_MAX);
	ss->unacked.retransmit_copy = NULL;
	ss->unacked.retransmit_copy_count = 0;
	ss->unacked.stalled = false;
}

void mux_sched_free_streams(struct mux_session *restrict ss)
{
	g_sched_free_calls++;
	ss->sched.sched_head = NULL;
	ss->sched.sched_tail = NULL;
	ss->sched.drr_active = NULL;
	ss->sched.lp_head = NULL;
	ss->sched.lp_tail = NULL;
	ss->sched.delay_head = NULL;
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
		.max_payload = (uint_least32_t)mux_session_config_default
				       .max_frame_payload,
		.tag = "[test]:",
	};
	ss->w_socket.fd = 11;
}

static void teardown_session(struct mux_session *restrict ss)
{
	/* Free frames queued by mux_handshake_enqueue_hello (server fresh path). */
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	/* Free unacked ring (empty in fuzz sessions). */
	mux_unacked_free_all(ss);
	/* Free peer identity string (strdup'd by mux_handshake_process_hello). */
	free(ss->handshake.peer_identity);
	ss->handshake.peer_identity = NULL;
	/* Free stream table (allocated by table_new on client fresh-session path). */
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
	bytebuf_free(ss->wire.recvbuf);
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

	const bool build_ok =
		proto_hello_build(frame, MUX_MAX_PAYLOAD_SIZE, &hello);
	const bool len_ok = build_ok && frame->len > MUX_FRAME_HEADER_SIZE;
	const bool parse_ok =
		len_ok && proto_hello_parse(
				  &k_parse_test_session,
				  frame->data + MUX_FRAME_HEADER_SIZE,
				  frame->len - MUX_FRAME_HEADER_SIZE, &parsed);
	/* Free the frame before asserting: a failing T_EXPECT longjmps out of the
	 * case, so freeing first keeps it from leaking. parsed is a stack copy. */
	free(frame);
	T_EXPECT(build_ok);
	T_EXPECT(len_ok);
	T_EXPECT(parse_ok);
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
}

/* The largest legal identity is 255 octets (proto_hello.identity is [256]);
 * round-trip the exact boundary so an off-by-one that drops or corrupts a valid
 * max-length claim is caught -- existing cases only test the 256-octet reject. */
T_DECLARE_CASE(test_proto_hello_build_and_parse_max_identity)
{
	struct mux_frame *const frame =
		malloc(MUX_FRAME_OBJECT_SIZE(MUX_MAX_PAYLOAD_SIZE));
	T_EXPECT(frame != NULL);
	struct proto_hello hello = {
		.msgid = PROTO_MSG_CLIENT_HELLO,
		.has_identity = true,
	};
	struct proto_hello parsed;

	memset(hello.identity, 'a', sizeof(hello.identity) - 1);
	hello.identity[sizeof(hello.identity) - 1] = '\0';
	T_CHECK(strlen(hello.identity) == sizeof(hello.identity) - 1); /* 255 */

	const bool build_ok =
		proto_hello_build(frame, MUX_MAX_PAYLOAD_SIZE, &hello);
	const bool parse_ok =
		build_ok &&
		proto_hello_parse(
			&k_parse_test_session,
			frame->data + MUX_FRAME_HEADER_SIZE,
			frame->len - MUX_FRAME_HEADER_SIZE, &parsed);
	/* Free the frame before asserting so a failing T_EXPECT can't skip it;
	 * parsed is a stack copy. */
	free(frame);
	T_EXPECT(build_ok);
	T_EXPECT(parse_ok);
	T_EXPECT(parsed.has_identity);
	T_EXPECT_STREQ(parsed.identity, hello.identity);
}

T_DECLARE_CASE(test_proto_hello_parse_rejects_missing_type)
{
	static const unsigned char json[] = "{\"msgid\":0}";
	struct proto_hello parsed;

	T_EXPECT(!proto_hello_parse(
		&k_parse_test_session, json, sizeof(json) - 1, &parsed));
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

	T_EXPECT(!proto_hello_parse(
		&k_parse_test_session, json, sizeof(json) - 1, &parsed));
}

T_DECLARE_CASE(test_proto_hello_parse_rejects_bad_session_id)
{
	static const unsigned char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=1\","
		"\"msgid\":0,\"session_id\":\"bad\"}";
	struct proto_hello parsed;

	T_EXPECT(!proto_hello_parse(
		&k_parse_test_session, json, sizeof(json) - 1, &parsed));
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
		&k_parse_test_session, (const unsigned char *)json,
		strlen(json), &parsed));
}

/* An identity extension with an embedded NUL (a JSON u0000 escape) whose
 * strlen-truncated prefix ("svc") is itself a valid identity must be rejected,
 * not silently accepted with the post-NUL bytes ("x") dropped: the wire length
 * and the effective (pre-NUL) value would otherwise disagree -- the same parser
 * differential proto_parse_type/proto_parse_session_id reject. */
T_DECLARE_CASE(test_proto_hello_parse_rejects_identity_embedded_nul)
{
	static const unsigned char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=1\","
		"\"msgid\":0,\"extensions\":{\"identity\":\"svc\\u0000x\"}}";
	struct proto_hello parsed;

	T_EXPECT(!proto_hello_parse(
		&k_parse_test_session, json, sizeof(json) - 1, &parsed));
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
		&k_parse_test_session, (const unsigned char *)json,
		sizeof(json) - 1, &parsed));
}

/* Well-formed multi-byte UTF-8 in the identity extension must still parse. */
T_DECLARE_CASE(test_proto_hello_parse_accepts_well_formed_utf8_identity)
{
	static const char json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=1\","
		"\"msgid\":0,\"extensions\":{\"identity\":\"\xc3\xa9\xe4\xb8\xad\"}}";
	struct proto_hello parsed;

	T_CHECK(proto_hello_parse(
		&k_parse_test_session, (const unsigned char *)json,
		sizeof(json) - 1, &parsed));
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

	T_EXPECT(
		mux_handshake_enqueue_hello(&ss, PROTO_MSG_CLIENT_HELLO, true));
	T_CHECK(ss.wire.sendbuf.head != NULL);
	const bool tx_pending = ss.wire.tx_pending;
	const bool parse_ok = proto_hello_parse(
		&ss, ss.wire.sendbuf.head->data + MUX_FRAME_HEADER_SIZE,
		ss.wire.sendbuf.head->len - MUX_FRAME_HEADER_SIZE, &parsed);
	const uint_least32_t unreported = ss.unacked.unreported;
	/* Free the queued frame before asserting so a failing T_EXPECT can't skip
	 * it; parsed is a stack copy. */
	mux_frame_put(&ss.pool, ss.wire.sendbuf.head);
	T_EXPECT(tx_pending);
	T_EXPECT(parse_ok);
	T_EXPECT_EQ(parsed.msgid, PROTO_MSG_CLIENT_HELLO);
	T_EXPECT(parsed.reject_inbound);
	T_EXPECT(parsed.has_session_id);
	/* has_resume_seq is not populated on the parse side; only resume_seq is. */
	T_EXPECT_EQ(parsed.resume_seq, (uint_least32_t)41);
	T_EXPECT_EQ(unreported, (uint_least32_t)0);
	T_EXPECT(parsed.has_identity);
	T_EXPECT_STREQ(parsed.identity, "cli-service");
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

	T_EXPECT(mux_handshake_enqueue_hello(
		&ss, PROTO_MSG_CLIENT_HELLO, false));
	T_CHECK(ss.wire.sendbuf.head != NULL);
	const bool parse_ok = proto_hello_parse(
		&ss, ss.wire.sendbuf.head->data + MUX_FRAME_HEADER_SIZE,
		ss.wire.sendbuf.head->len - MUX_FRAME_HEADER_SIZE, &parsed);
	/* Free the queued frame before asserting so a failing T_EXPECT can't skip
	 * it; parsed is a stack copy. */
	mux_frame_put(&ss.pool, ss.wire.sendbuf.head);
	T_EXPECT(parse_ok);
	T_EXPECT_EQ(parsed.msgid, PROTO_MSG_CLIENT_HELLO);
	T_EXPECT(!parsed.has_identity);
}

/* Declare a stack-backed frame with a real payload buffer: struct mux_frame's
 * data[] is a flexible array member, so a bare `struct mux_frame f` has no
 * payload storage.  Zero-initialised; pointer named @p name. */
#define TEST_FRAME(name)                                                       \
	alignas(max_align_t) unsigned char name##_buf_[MUX_FRAME_OBJECT_SIZE(  \
		(size_t)MUX_MAX_PAYLOAD_SIZE)] = { 0 };                        \
	struct mux_frame *const name = (struct mux_frame *)name##_buf_

/* Feed one ClientHello into a server-role session with on_verify_identity
 * installed.  @p session_id, when non-NULL, makes it a resume hello. */
T_DECLARE_SUBCASE(
	run_verify_identity_hello, const char *restrict identity,
	const bool resume, bool *restrict ok_out)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_CLIENT_HELLO,
		.has_identity = identity != NULL,
		.has_session_id = resume,
	};

	setup_session(&ss, &pool_ctx, true);
	ss.callbacks.on_verify_identity = verify_identity_cb;
	ss.callbacks.on_resume = resume_lookup_cb;
	if (identity != NULL) {
		(void)snprintf(
			hello.identity, sizeof(hello.identity), "%s", identity);
	}
	if (resume) {
		memset(hello.session_id, 0x55, sizeof(hello.session_id));
	}
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	*ok_out = mux_handshake_process_hello(&ss, &hdr, frame->len);
	teardown_session(&ss);
	/* Every frame the hello path allocated was returned to the pool. */
	T_EXPECT_EQ(pool_ctx.alloc_calls, pool_ctx.free_calls);
}

/* A rejecting on_verify_identity resets the session and never completes the
 * handshake, so no stream can be admitted (spec Section 10.1). */
T_DECLARE_CASE(test_handshake_verify_identity_rejects)
{
	handshake_mock_reset();
	g_verify_result = false;
	bool ok = true;
	T_CALL_SUBCASE(run_verify_identity_hello, "svc-a", false, &ok);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g_verify_calls, 1);
	T_EXPECT_STREQ(g_verify_identity, "svc-a");
	T_EXPECT_EQ(g_reset_calls, 1);
	T_EXPECT_EQ(g_handshake_done_calls, 0);
}

/* The accepting path is unchanged: the callback sees the claimed identity and
 * the handshake completes. */
T_DECLARE_CASE(test_handshake_verify_identity_accepts)
{
	handshake_mock_reset();
	g_verify_result = true;
	bool ok = false;
	T_CALL_SUBCASE(run_verify_identity_hello, "svc-a", false, &ok);

	T_EXPECT(ok);
	T_EXPECT_EQ(g_verify_calls, 1);
	T_EXPECT_STREQ(g_verify_identity, "svc-a");
	T_EXPECT_EQ(g_reset_calls, 0);
	T_EXPECT_EQ(g_handshake_done_calls, 1);
}

/* A peer claiming no identity still fires the callback, with NULL, so a policy
 * that wants to reject anonymous peers can. */
T_DECLARE_CASE(test_handshake_verify_identity_null_when_unclaimed)
{
	handshake_mock_reset();
	bool ok = false;
	T_CALL_SUBCASE(run_verify_identity_hello, NULL, false, &ok);

	T_EXPECT(ok);
	T_EXPECT_EQ(g_verify_calls, 1);
	T_EXPECT(g_verify_saw_null);
}

/* The check runs before process_hello_server(), so a rejected resume hello
 * never reaches on_resume and its transport is never handed off. */
T_DECLARE_CASE(test_handshake_verify_identity_precedes_resume)
{
	handshake_mock_reset();
	g_verify_result = false;
	g_resume_handled = true;
	bool ok = true;
	T_CALL_SUBCASE(run_verify_identity_hello, "svc-a", true, &ok);

	T_EXPECT(!ok);
	T_EXPECT_EQ(g_verify_calls, 1);
	T_EXPECT_EQ(g_resume_calls, 0);
	T_EXPECT_EQ(g_reset_calls, 1);
	T_EXPECT_EQ(g_handshake_done_calls, 0);
}

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
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);
	const int reset_calls = g_reset_calls;
	const int done_calls = g_handshake_done_calls;
	const size_t readable = bytebuf_readable(ss.wire.recvbuf);
	const bool peer_rejects = ss.handshake.peer_rejects_inbound_streams;
	const bool has_session_id = ss.handshake.has_session_id;
	const bool session_id_match =
		memcmp(ss.handshake.session_id, hello.session_id,
		       sizeof(hello.session_id)) == 0;
	const bool has_peer_identity = ss.handshake.peer_identity != NULL;
	char peer_identity[sizeof(hello.identity)] = { 0 };
	if (has_peer_identity) {
		(void)snprintf(
			peer_identity, sizeof(peer_identity), "%s",
			ss.handshake.peer_identity);
	}
	/* Tear the fixtures down before asserting: a failing T_EXPECT longjmps out
	 * of the case, so freeing first keeps peer_identity / recvbuf / the stream
	 * table from leaking. Every asserted value is captured above. */
	if (ss.sched.streams != NULL) {
		table_free(ss.sched.streams);
		ss.sched.streams = NULL;
	}
	free(ss.handshake.peer_identity);
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(ok);
	T_EXPECT_EQ(reset_calls, 0);
	T_EXPECT_EQ(done_calls, 1);
	T_EXPECT_EQ(readable, (size_t)0);
	T_EXPECT(peer_rejects);
	T_EXPECT(has_session_id);
	T_EXPECT(session_id_match);
	T_EXPECT(has_peer_identity);
	T_EXPECT_STREQ(peer_identity, "srv-a");
}

/* The client's fresh-session fallback delegates the whole unacked teardown to
 * mux_unacked_free_all, so this pins the field set that contract owns: the
 * replay cursor routed through unacked_set_replay_off (which also zeroes
 * retransmitted_frames), retransmit_copy_count cleared, and the unacked_frames
 * gauge paid back. A double that skipped any of them would let a case here
 * pass against behavior production does not have. */
T_DECLARE_CASE(test_handshake_client_fresh_clears_unacked_replay_state)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.has_session_id = true,
	};
	mux_gauge unacked_gauge = 7;

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	/* Server answers with an id of its own: not a confirmed resume, so the
	 * client falls back to a fresh session. */
	memset(hello.session_id, 0x44, sizeof(hello.session_id));
	ss.cnt.buffers.unacked_frames = &unacked_gauge;
	ss.unacked.frames = 7;
	ss.unacked.retransmit_off = 0;
	ss.unacked.retransmitted_frames = 3;
	ss.unacked.retransmit_copy_count = 5;
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);
	const size_t frames = ss.unacked.frames;
	const size_t replay_off = ss.unacked.retransmit_off;
	const size_t retransmitted = ss.unacked.retransmitted_frames;
	const size_t copy_count = ss.unacked.retransmit_copy_count;
	const size_t gauge =
		(size_t)COUNTER_LOAD(ss.cnt.buffers.unacked_frames);

	if (ss.sched.streams != NULL) {
		table_free(ss.sched.streams);
		ss.sched.streams = NULL;
	}
	free(ss.handshake.peer_identity);
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(ok);
	T_EXPECT_EQ(frames, (size_t)0);
	T_EXPECT_EQ(replay_off, SIZE_MAX);
	T_EXPECT_EQ(retransmitted, (size_t)0);
	T_EXPECT_EQ(copy_count, (size_t)0);
	T_EXPECT_EQ(gauge, (size_t)0);
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
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);
	ss.callbacks.on_resume = resume_lookup_cb;
	/* The owner reports it handled the resume (located the suspended session
	 * and took this transient session's transport). */
	g_resume_handled = true;

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);
	const int resume_calls = g_resume_calls;
	const uint_least32_t resume_seq = g_resume_seq;
	const int done_calls = g_handshake_done_calls;
	const int reset_calls = g_reset_calls;
	const int state = (int)ss.state;
	/* Free the recvbuf before asserting so a failing T_EXPECT can't skip it;
	 * the captured values are stack copies. */
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(!ok);
	T_EXPECT_EQ(resume_calls, 1);
	T_EXPECT_EQ(resume_seq, (uint_least32_t)99);
	/* Handed off: no fresh handshake, and the transient session is reset so
	 * socket_cb tears it down. */
	T_EXPECT_EQ(done_calls, 0);
	T_EXPECT_EQ(reset_calls, 1);
	T_EXPECT_EQ(state, (int)SESSION_CLOSED);
}

/* process_hello_server's on_resume-miss fallback (spec §5.8.3 step 4): when
 * on_resume reports no matching suspended session, the server logs a warning and
 * falls through to a fresh ServerHello carrying its own session_id, then
 * completes the handshake. */
T_DECLARE_CASE(
	test_handshake_process_resume_hello_on_resume_miss_falls_back_fresh)
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
	struct proto_hello parsed;

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, true);
	/* The server was assigned its own session_id before this ClientHello. */
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0x77, sizeof(ss.handshake.session_id));
	/* The resume attempt carries a different (now-unknown) id. */
	memset(hello.session_id, 0x2C, sizeof(hello.session_id));
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);
	ss.callbacks.on_resume = resume_lookup_cb;
	/* No matching suspended session: the owner declines the resume. */
	g_resume_handled = false;

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);
	const int resume_calls = g_resume_calls;
	const uint_least32_t resume_seq = g_resume_seq;
	const int done_calls = g_handshake_done_calls;
	const int reset_calls = g_reset_calls;
	/* A fresh ServerHello carrying the server's own session_id was queued. */
	const bool sendbuf_queued = ss.wire.sendbuf.head != NULL;
	const bool parse_ok =
		sendbuf_queued &&
		proto_hello_parse(
			&ss, ss.wire.sendbuf.head->data + MUX_FRAME_HEADER_SIZE,
			ss.wire.sendbuf.head->len - MUX_FRAME_HEADER_SIZE,
			&parsed);
	const bool session_id_match =
		parse_ok && memcmp(parsed.session_id, ss.handshake.session_id,
				   sizeof(parsed.session_id)) == 0;
	/* Tear the fixture down before asserting: a failing T_EXPECT longjmps out
	 * of the case, so teardown first keeps the queued frame / recvbuf from
	 * leaking. parsed and the captured values are stack-resident. */
	teardown_session(&ss);

	T_EXPECT(ok);
	T_EXPECT_EQ(resume_calls, 1);
	T_EXPECT_EQ(resume_seq, (uint_least32_t)99);
	T_EXPECT_EQ(done_calls, 1);
	T_EXPECT_EQ(reset_calls, 0);
	T_CHECK(sendbuf_queued);
	T_EXPECT(parse_ok);
	T_EXPECT_EQ(parsed.msgid, PROTO_MSG_SERVER_HELLO);
	T_EXPECT(parsed.has_session_id);
	T_EXPECT(session_id_match);
}

/* Spec §5.2.2: the server always includes session_id in its ServerHello, so
 * one without it is a server protocol violation and must close the connection.
 * Accepting it would leave the client ESTABLISHED still flagged
 * has_session_id but holding the previous, now-defunct id -- every piece of
 * state behind it having just been wiped -- and the next reconnect would offer
 * that dead id in a resume ClientHello. */
T_DECLARE_CASE(test_handshake_process_server_hello_without_session_id_rejected)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.has_session_id = false,
	};

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	/* An id left over from the session this client is trying to resume. */
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0x61, sizeof(ss.handshake.session_id));
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);

	const int reset_calls = g_reset_calls;
	const int done_calls = g_handshake_done_calls;
	free(ss.handshake.peer_identity);
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(!ok);
	T_EXPECT_EQ(reset_calls, 1);
	T_EXPECT_EQ(done_calls, 0);
}

/* The same rejection applies to a client with no session to resume: spec §5.2.2
 * is unconditional, so a session_id-less ServerHello is a server protocol
 * violation whether or not we were resuming. This is the half a plain first
 * connect hits, and it is the stricter half -- before the guard such a client
 * came up ESTABLISHED, merely unable to ever resume. Pinned separately so a
 * guard narrowed to only the resume case (has_session_id && !peer's) cannot
 * regress it unnoticed. */
T_DECLARE_CASE(
	test_handshake_process_fresh_server_hello_without_session_id_rejected)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss;
	TEST_FRAME(frame);
	struct mux_header hdr;
	struct proto_hello hello = {
		.msgid = PROTO_MSG_SERVER_HELLO,
		.has_session_id = false,
	};

	handshake_mock_reset();
	setup_session(&ss, &pool_ctx, false);
	/* No prior session: nothing to resume, so this is a first connect. */
	ss.handshake.has_session_id = false;
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);

	const int reset_calls = g_reset_calls;
	const int done_calls = g_handshake_done_calls;
	const bool adopted = ss.handshake.has_session_id;
	free(ss.handshake.peer_identity);
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(!ok);
	T_EXPECT_EQ(reset_calls, 1);
	T_EXPECT_EQ(done_calls, 0);
	/* Nothing was adopted, so no reconnect can offer an id we never got. */
	T_EXPECT(!adopted);
}

/* The peer-protocol-violation half of the confirmed-resume path: when the
 * server's resume_seq cannot be reconciled against what we actually sent,
 * mux_unacked_resume_ack_recv fails and the session must reset rather than come up
 * with a trimmed-wrong unacked log. */
T_DECLARE_CASE(test_handshake_process_confirmed_resume_ack_rejected)
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
	g_resume_ack_result = false;
	setup_session(&ss, &pool_ctx, false);
	ss.handshake.has_session_id = true;
	memset(ss.handshake.session_id, 0x61, sizeof(ss.handshake.session_id));
	memcpy(hello.session_id, ss.handshake.session_id,
	       sizeof(hello.session_id));
	T_CHECK(build_hello_frame(frame, &hdr, &hello));
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);

	const int ack_calls = g_resume_ack_recv_calls;
	const int reset_calls = g_reset_calls;
	const int done_calls = g_handshake_done_calls;
	free(ss.handshake.peer_identity);
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(!ok);
	T_EXPECT_EQ(ack_calls, 1);
	T_EXPECT_EQ(reset_calls, 1);
	T_EXPECT_EQ(done_calls, 0);
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
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);
	const int ack_calls = g_resume_ack_recv_calls;
	const uint_least32_t last_ack_recv = ss.unacked.last_ack_recv;
	const int done_calls = g_handshake_done_calls;
	const int reset_calls = g_reset_calls;
	/* Free the fixtures before asserting so a failing T_EXPECT can't skip them;
	 * the captured values are stack copies. */
	free(ss.handshake.peer_identity);
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(ok);
	T_EXPECT_EQ(ack_calls, 1);
	T_EXPECT_EQ(last_ack_recv, (uint_least32_t)123);
	T_EXPECT_EQ(done_calls, 1);
	T_EXPECT_EQ(reset_calls, 0);
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
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);
	const int ack_calls = g_resume_ack_recv_calls;
	const int done_calls = g_handshake_done_calls;
	const int watcher_calls = g_update_watcher_calls;
	const bool tx_pending = ss.wire.tx_pending;
	const int reset_calls = g_reset_calls;
	/* Free the fixtures before asserting so a failing T_EXPECT can't skip them;
	 * the captured values are stack copies.
	 * Ring owns retransmit (stack var); clear ring only, don't mux_frame_put. */
	free(ss.unacked.ring);
	ss.unacked.ring = NULL;
	free(ss.handshake.peer_identity);
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(ok);
	T_EXPECT_EQ(ack_calls, 1);
	T_EXPECT_EQ(done_calls, 1);
	T_EXPECT_EQ(watcher_calls, 1);
	T_EXPECT(tx_pending);
	T_EXPECT_EQ(reset_calls, 0);
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
	bytebuf_free(ss.wire.recvbuf);
	ss.wire.recvbuf = bytebuf_new(frame->len);
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(ss.wire.recvbuf, frame->len);

	const bool ok = mux_handshake_process_hello(&ss, &hdr, frame->len);
	const int reset_calls = g_reset_calls;
	const int done_calls = g_handshake_done_calls;
	/* Free the recvbuf before asserting so a failing T_EXPECT can't skip it;
	 * the captured values are stack copies. */
	bytebuf_free(ss.wire.recvbuf);

	T_EXPECT(!ok);
	T_EXPECT_EQ(reset_calls, 1);
	T_EXPECT_EQ(done_calls, 0);
}

/* A worst-case hello -- resume form, claiming MUX_MAX_CLAIM_LEN octets of
 * control characters, each of which JSON-escapes to \u00XX -- must still build
 * into the smallest configurable frame. It did not when a claim could reach the
 * spec's 255 octets: proto_hello_build failed, mux_handshake_enqueue_hello
 * reset the session, and every reconnect repeated it. Also pins
 * MUX_MAX_HELLO_JSON_SIZE against the real marshaller, since the floor's
 * static_assert is only as good as that constant. */
T_DECLARE_CASE(test_worst_case_hello_fits_minimum_frame)
{
	TEST_FRAME(frame);
	struct proto_hello msg = {
		.msgid = PROTO_MSG_CLIENT_HELLO,
		.reject_inbound = true,
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = UINT32_MAX,
		.has_identity = true,
	};
	memset(msg.session_id, 0xFF, sizeof(msg.session_id));
	memset(msg.identity, 0x01, MUX_MAX_CLAIM_LEN);
	msg.identity[MUX_MAX_CLAIM_LEN] = '\0';

	T_EXPECT(proto_hello_build(frame, MUX_MIN_FRAME_PAYLOAD, &msg));
	const size_t json_len = frame->len - MUX_FRAME_HEADER_SIZE;
	T_EXPECT_EQ(json_len, (size_t)MUX_MAX_HELLO_JSON_SIZE);
}

/* Spec §5.2.2 admits only the canonical decimal version, and a strict peer
 * closes on anything else. strtoumax accepts leading whitespace, a '+' sign and
 * leading zeros, and each of those is an RFC 2045 token character, so these
 * forms parsed as a plain 1 and established. */
T_DECLARE_CASE(test_proto_parse_type_requires_canonical_version)
{
	static const char k_good[] =
		"application/x-multiplexd-proto; version=1";
	static const char *const k_bad[] = {
		"application/x-multiplexd-proto; version=01",
		"application/x-multiplexd-proto; version=001",
		"application/x-multiplexd-proto; version=+1",
		"application/x-multiplexd-proto; version=\" 1\"",
	};

	int version = 0;
	T_EXPECT(proto_parse_type(
		&k_parse_test_session, k_good, strlen(k_good), &version));
	T_EXPECT_EQ(version, 1);

	for (size_t i = 0; i < ARRAY_SIZE(k_bad); i++) {
		version = 0;
		T_EXPECT(!proto_parse_type(
			&k_parse_test_session, k_bad[i], strlen(k_bad[i]),
			&version));
	}
}

/* proto_hello_parse rejects a frame whose declared length exceeds the protocol
 * payload cap before touching the buffer. */
T_DECLARE_CASE(test_proto_hello_parse_rejects_oversized_json)
{
	static const unsigned char json[] = "{}";
	struct proto_hello parsed;
	T_EXPECT(!proto_hello_parse(
		&k_parse_test_session, json, (size_t)MUX_MAX_PAYLOAD_SIZE + 1,
		&parsed));
}

/* mux_handshake_process_hello resets the session when a hello arrives outside the
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
	T_EXPECT(
		!mux_handshake_process_hello(&ss, &hdr, MUX_FRAME_HEADER_SIZE));
	T_EXPECT_EQ(g_reset_calls, 1);
}

/* fuzz - proto_hello_parse and mux_handshake_process_hello, three modes:
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
		/* Length 0-255: the 255 case is the largest legal identity and
		 * still fits in proto_hello.identity[256] (255 chars + NUL). */
		const size_t id_len = prng_range(256);
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
			const bool ok = proto_hello_parse(
				&k_parse_test_session, json_buf, len, &out);

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
			const bool ok = proto_hello_parse(
				&k_parse_test_session, json_buf, len, &out);

			if (ok && out.version <= 0) {
				print_fuzz_context(iter, seed, json_buf, len);
				T_FATAL("invariant 1 violated: "
					"proto_hello_parse true but "
					"version <= 0");
			}

			/* Mode C (30%): Frame -> mux_handshake_process_hello */
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
				/* Half the time seed the id to the decode of a
				 * corpus session_id (k_session_ids[0] -> 16 zero
				 * bytes) so a generated ServerHello carrying that
				 * same id actually confirms the resume.  A fully
				 * random id matches the base64 corpus only
				 * ~2^-128 of the time, which would leave
				 * is_confirmed_resume / mux_unacked_resume_ack_recv
				 * unreached. */
				const bool seed_corpus_id =
					prng_bool() &&
					proto_parse_session_id(
						k_session_ids[0],
						strlen(k_session_ids[0]),
						ss.handshake.session_id);
				if (!seed_corpus_id) {
					for (size_t i = 0;
					     i < MUX_SESSION_ID_LEN; i++) {
						ss.handshake.session_id[i] =
							(unsigned char)
								prng_u32();
					}
				}
			}

			ss.wire.recvbuf = bytebuf_new(frame_size);
			if (ss.wire.recvbuf == NULL) {
				/* OOM: skip iteration. */
				continue;
			}
			memcpy(bytebuf_write_ptr(ss.wire.recvbuf), frame_buf,
			       frame_size);
			bytebuf_produce(ss.wire.recvbuf, frame_size);

			const bool ret = mux_handshake_process_hello(
				&ss, &hdr, frame_size);

			/* Invariant 2: state must be a valid session_state. */
			if ((unsigned)ss.state > (unsigned)SESSION_CLOSED) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 2 violated: "
					"session state out of range");
			}

			/* Invariant 3: mux_session_reset -> SESSION_CLOSED. */
			if (g_reset_calls > 0 && ss.state != SESSION_CLOSED) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 3 violated: "
					"mux_session_reset called but "
					"state != SESSION_CLOSED");
			}

			/* Invariant 4: return true -> exactly one
			 * mux_session_handshake_done call. */
			if (ret && g_handshake_done_calls != 1) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 4 violated: "
					"mux_handshake_process_hello returned true "
					"but mux_session_handshake_done not called "
					"exactly once");
			}

			/* Invariant 5: handshake_done and mux_session_reset are
			 * mutually exclusive within a single call. */
			if (g_handshake_done_calls > 0 && g_reset_calls > 0) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 5 violated: "
					"mux_session_handshake_done and "
					"mux_session_reset both called");
			}

			teardown_session(&ss);
		}
	}
}

static const struct testing_suite suite[] = {
	T_CASE(test_proto_hello_build_and_parse_roundtrip),
	T_CASE(test_proto_hello_build_and_parse_max_identity),
	T_CASE(test_proto_hello_parse_rejects_missing_type),
	T_CASE(test_proto_hello_parse_rejects_type_embedded_nul),
	T_CASE(test_proto_hello_parse_rejects_bad_session_id),
	T_CASE(test_proto_hello_parse_rejects_oversized_identity),
	T_CASE(test_proto_hello_parse_rejects_identity_embedded_nul),
	T_CASE(test_proto_hello_parse_rejects_invalid_utf8_identity),
	T_CASE(test_proto_hello_parse_accepts_well_formed_utf8_identity),
	T_CASE(test_handshake_enqueue_hello_includes_session_identity_and_resume),
	T_CASE(test_handshake_enqueue_hello_omits_oversized_identity),
	T_CASE(test_handshake_process_server_hello_assigns_peer_identity),
	T_CASE(test_handshake_client_fresh_clears_unacked_replay_state),
	T_CASE(test_handshake_verify_identity_rejects),
	T_CASE(test_handshake_verify_identity_accepts),
	T_CASE(test_handshake_verify_identity_null_when_unclaimed),
	T_CASE(test_handshake_verify_identity_precedes_resume),
	T_CASE(test_handshake_process_resume_hello_calls_on_resume_match),
	T_CASE(test_handshake_process_resume_hello_on_resume_miss_falls_back_fresh),
	T_CASE(test_handshake_process_confirmed_resume_calls_resume_ack_recv),
	T_CASE(test_handshake_process_server_hello_without_session_id_rejected),
	T_CASE(test_handshake_process_fresh_server_hello_without_session_id_rejected),
	T_CASE(test_handshake_process_confirmed_resume_ack_rejected),
	T_CASE(test_handshake_process_confirmed_resume_rearms_write_watcher),
	T_CASE(test_handshake_process_invalid_version_resets_session),
	T_CASE(test_worst_case_hello_fits_minimum_frame),
	T_CASE(test_proto_parse_type_requires_canonical_version),
	T_CASE(test_proto_hello_parse_rejects_oversized_json),
	T_CASE(test_handshake_process_hello_outside_handshake_resets),
	T_CASE(test_handshake_fuzz),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
