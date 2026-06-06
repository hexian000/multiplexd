/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file handshake_fuzz_test.c
 * @brief Deterministic PRNG-driven fuzzer for proto_hello_parse and
 * handshake_process_hello.
 *
 * Attack surface covered:
 *   - proto_hello_parse with random bytes, synthesized JSON, and
 *     bit-flipped built hellos
 *   - proto_parse_type MIME string validation: wrong type/subtype,
 *     missing version, version 0/2/255/256/overflow/negative/leading-zero,
 *     extra parameters
 *   - proto_parse_session_id Base64 decoding: valid/invalid lengths,
 *     invalid characters, all-padding
 *   - resume_seq boundary values: 0, UINT32_MAX, UINT32_MAX+1, UINTMAX_MAX
 *   - identity string: lengths 0-300 (crosses the 255-char rejection limit)
 *   - Missing mandatory JSON fields (type, msgid)
 *   - Wrong-type values for extensions (e.g. reject_inbound as a string)
 *   - Unknown extension keys and unknown top-level fields (silently ignored)
 *   - handshake_process_hello frame header validation: non-zero flags,
 *     non-zero stream_id, non-zero extra
 *   - Server role (accepted=true) and client role (accepted=false) paths
 *   - Client-side confirmed resume (has_session_id + matching session_id +
 *     has_resume_seq in ServerHello)
 *   - session_resume_ack_recv failure (randomized return value)
 *
 * Three input modes per iteration, chosen randomly:
 *   - random:     uniform random bytes → proto_hello_parse            (30%)
 *   - structured: synthesized JSON or bit-flipped built hello →
 *                 proto_hello_parse                                   (40%)
 *   - frame:      full hello frame (header + body) with varied
 *                 flags/stream_id/extra → handshake_process_hello     (30%)
 *
 * Invariants checked after every call:
 *   1. proto_hello_parse returns true → parsed.version > 0
 *   2. ss.state is a valid session_state value after any call
 *   3. session_reset called → ss.state == SESSION_CLOSED
 *   4. handshake_process_hello returns true → session_handshake_done
 *      called exactly once
 *   5. g_handshake_done_calls and g_reset_calls are mutually exclusive
 *      per call
 *
 * Reproducibility: set MUX_FUZZ_SEED (hex) and MUX_FUZZ_ITERATIONS.
 * Default seed is fixed so CI runs are deterministic.
 */

#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/session.h"

#include "algo/hashtable.h"
#include "utils/testing.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pull in the static symbols under test directly. */
#include "mux/handshake.c"

/* ------------------------------------------------------------------ */
/* Splitmix64 PRNG                                                     */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Mock state                                                          */
/* ------------------------------------------------------------------ */

static int g_reset_calls;
static int g_handshake_done_calls;
static int g_update_watcher_calls;
static int g_resume_transport_calls;
static int g_resume_ack_calls;
static int g_sched_free_calls;
static bool g_resume_ack_result;

static void fuzz_mocks_reset(void)
{
	g_reset_calls = 0;
	g_handshake_done_calls = 0;
	g_update_watcher_calls = 0;
	g_resume_transport_calls = 0;
	g_resume_ack_calls = 0;
	g_sched_free_calls = 0;
}

/* ------------------------------------------------------------------ */
/* Mock implementations                                                */
/* ------------------------------------------------------------------ */

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

void session_update_watcher(struct mux_session *ss)
{
	(void)ss;
	g_update_watcher_calls++;
}

bool session_resume_transport(
	struct mux_session *restrict ss, struct mux_session *restrict new_ss,
	const uint_least32_t client_resume_seq)
{
	(void)new_ss;
	(void)client_resume_seq;
	g_resume_transport_calls++;
	session_reset(ss);
	return true;
}

bool session_resume_ack_recv(
	struct mux_session *restrict ss, const uint_least32_t peer_ack)
{
	ss->last_ack_recv = peer_ack;
	g_resume_ack_calls++;
	return g_resume_ack_result;
}

void sched_free_streams(struct mux_session *restrict ss)
{
	g_sched_free_calls++;
	ss->sched.sched_head = NULL;
	ss->sched.sched_tail = NULL;
	ss->sched.round_end = NULL;
	ss->sched.drr_active = NULL;
	ss->sched.lp_head = NULL;
	ss->sched.lp_tail = NULL;
	ss->sched.delay_head = NULL;
	ss->send_stalled = false;
	ss->sched.num_tombstones = 0;
	memset(ss->sched.id_bitmap, 0, sizeof(ss->sched.id_bitmap));
	if (ss->sched.streams != NULL) {
		table_free(ss->sched.streams);
		ss->sched.streams = NULL;
	}
}

bool sched_add_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	(void)ss;
	(void)s;
	return true;
}

/* ------------------------------------------------------------------ */
/* Frame pool helpers                                                  */
/* ------------------------------------------------------------------ */

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static struct mux_frame *fuzz_frame_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const f = malloc(sizeof(*f));
	if (f != NULL) {
		ctx->alloc_calls++;
	}
	return f;
}

static void fuzz_frame_free(void *data, struct mux_frame *f)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(f);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = fuzz_frame_alloc,
		.free = fuzz_frame_free,
		.data = ctx,
	};
}

/* ------------------------------------------------------------------ */
/* Session setup / teardown                                            */
/* ------------------------------------------------------------------ */

static void setup_session(
	struct mux_session *restrict ss,
	struct frame_pool_ctx *restrict pool_ctx, const bool accepted)
{
	*ss = (struct mux_session){
		.state = SESSION_HANDSHAKE,
		.accepted = accepted,
		.pool = make_pool(pool_ctx),
		.tag = (char *)"[fuzz]:",
	};
	ss->w_socket.fd = -1;
}

static void teardown_session(struct mux_session *restrict ss)
{
	/* Free frames queued by handshake_enqueue_hello (server fresh path). */
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	/* Free unacked ring (empty in fuzz sessions). */
	unacked_ring_free_all(ss);
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

/* ------------------------------------------------------------------ */
/* Input corpus: MIME type variants, session_id variants, etc.        */
/* ------------------------------------------------------------------ */

static const char *const k_types[] = {
	/* valid (3× weight so deep parsing paths are hit often) */
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
static const uintmax_t k_seqs[] = {
	0,
	1,
	65535,
	2147483647,
	4294967295UL, /* UINT32_MAX */
	4294967296ULL, /* UINT32_MAX + 1 */
	UINTMAX_MAX,
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

/* ------------------------------------------------------------------ */
/* Input generation                                                    */
/* ------------------------------------------------------------------ */

/* Scratch buffer size for gen_structured_json; sized to never truncate
 * a complete structured JSON in practice (~600 chars maximum). */
#define JBUF_SIZE 768

/* Maximum JSON bytes fed to proto_hello_parse per iteration. */
#define FUZZ_JSON_CAP 512u

/* Maximum frame bytes for Mode C. */
#define FUZZ_FRAME_CAP (MUX_FRAME_HEADER_SIZE + FUZZ_JSON_CAP)

/*
 * Append formatted text to json[0..JBUF_SIZE-1], tracking the number of
 * bytes actually written in the variable `off` (declared in the enclosing
 * scope).  When the buffer is full, further calls are silently dropped.
 *
 * Uses _space to hold the remaining capacity, then caps the increment at
 * _space so `off` never exceeds JBUF_SIZE-1.
 */
#define JAPP(fmt, ...)                                                         \
	do {                                                                   \
		if (off < JBUF_SIZE - 1) {                                     \
			const int _space = JBUF_SIZE - 1 - off;                \
			const int _n = snprintf(                               \
				json + off, (size_t)(_space + 1), (fmt),       \
				##__VA_ARGS__);                                \
			off += (_n > 0 && _n <= _space) ? _n : _space;         \
		}                                                              \
	} while (0)

/*
 * Synthesize a structured hello JSON payload into buf (up to cap bytes).
 * Applies 0-4 random bit-flip mutations after building the JSON.
 * Returns the actual payload length written.
 */
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
		const uintmax_t seq = k_seqs[prng_range(k_nseqs)];
		JAPP(",\"resume_seq\":%" PRIuMAX, seq);
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
		json[pos] ^= (char)(1u << bit);
	}

	const size_t len = (off > 0) ? (size_t)off : 0u;
	const size_t copy_len = (len < cap) ? len : cap;
	memcpy(buf, json, copy_len);
	return copy_len;
}

#undef JAPP

/*
 * Build a structured hello using proto_hello_build with randomized field
 * values, then apply 0-4 bit-flip mutations to the JSON portion.
 * Returns the JSON length (bytes after the frame header).
 */
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

	unsigned char frame_buf[MUX_FRAME_SIZE];
	const int frame_len =
		proto_hello_build(frame_buf, sizeof(frame_buf), &hello);
	if (frame_len <= (int)MUX_FRAME_HEADER_SIZE) {
		return 0u;
	}

	const size_t json_len =
		(size_t)(frame_len - (int)MUX_FRAME_HEADER_SIZE);
	const size_t copy_len = (json_len < cap) ? json_len : cap;
	memcpy(buf, frame_buf + MUX_FRAME_HEADER_SIZE, copy_len);

	/* Apply 0-4 bit-flip mutations. */
	const int nflips = (int)prng_range(5);
	for (int i = 0; i < nflips && copy_len > 0; i++) {
		const size_t pos = prng_range(copy_len);
		const int bit = (int)prng_range(8);
		buf[pos] ^= (unsigned char)(1u << bit);
	}

	return copy_len;
}

/* ------------------------------------------------------------------ */
/* Failure reporter                                                    */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Fuzz test case                                                      */
/* ------------------------------------------------------------------ */

T_DECLARE_CASE(test_handshake_fuzz)
{
	/* Seed: use a different default from dispatch_fuzz so CI catches
	 * failures in different iteration orderings. */
	uint64_t seed = UINT64_C(0xdeadbeefcafe0002);
	const char *env_seed = getenv("MUX_FUZZ_SEED");
	if (env_seed != NULL) {
		seed = (uint64_t)strtoull(env_seed, NULL, 0);
	}
	g_prng = seed;

	size_t iterations = 200000;
	const char *env_iter = getenv("MUX_FUZZ_ITERATIONS");
	if (env_iter != NULL) {
		const unsigned long v = strtoul(env_iter, NULL, 10);
		if (v > 0) {
			iterations = (size_t)v;
		}
	}

	static unsigned char json_buf[FUZZ_JSON_CAP];
	static unsigned char frame_buf[FUZZ_FRAME_CAP];

	for (size_t iter = 0; iter < iterations; iter++) {
		fuzz_mocks_reset();
		g_resume_ack_result = prng_bool();

		const size_t mode = prng_range(10);

		/* ------------------------------------------------------------------ */
		/* Mode A (30%): Random bytes → proto_hello_parse                     */
		/* ------------------------------------------------------------------ */
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

			/* ------------------------------------------------------------------ */
			/* Mode B (40%): Structured JSON → proto_hello_parse                  */
			/* ------------------------------------------------------------------ */
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

			/* ------------------------------------------------------------------ */
			/* Mode C (30%): Frame → handshake_process_hello                      */
			/* ------------------------------------------------------------------ */
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

			/* Build frame header.
			 * version=0 is the hello version; handshake_process_hello
			 * does not validate it (the dispatcher does), so keep it 0
			 * to reflect the real call site.
			 * Vary flags/stream_id/extra: valid (0) most of the time to
			 * exercise JSON parsing; corrupted sometimes to exercise the
			 * early-reject path. */
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
				fuzz_mocks_reset();
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

			/* Invariant 3: session_reset → SESSION_CLOSED. */
			if (g_reset_calls > 0 && ss.state != SESSION_CLOSED) {
				print_fuzz_context(
					iter, seed, frame_buf, frame_size);
				T_FATAL("invariant 3 violated: "
					"session_reset called but "
					"state != SESSION_CLOSED");
			}

			/* Invariant 4: return true → exactly one
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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_handshake_fuzz);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
