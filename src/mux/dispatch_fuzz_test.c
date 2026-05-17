/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file dispatch_fuzz_test.c
 * @brief Deterministic PRNG-driven fuzzer for dispatch_frame and helpers.
 *
 * Attack surface covered:
 *   - All branches of dispatch_frame / dispatch_by_stream / dispatch_no_stream
 *   - validate_flags_by_stream × all 8 stream states
 *   - is_ignorable_unknown_terminal_frame
 *   - process_syn_payload
 *   - Header field edge cases: version, flags (5 defined + 3 reserved bits),
 *     length 0..MUX_MAX_PAYLOAD_SIZE, stream_id parity / CTRL=0, extra
 *   - Session-level ACK arithmetic (recv_seq / ack_seq / unacked_frames)
 *   - Multi-frame buffers and partial-frame (incomplete) tail bytes
 *   - Pre-existing streams at each state (dispatch_by_stream path)
 *   - CTRL sub-commands: PING, PONG, PROBE, reserved
 *   - Reserved flag bits → session reset
 *   - ack_trim returning false → session reset
 *
 * Two input modes per iteration, chosen randomly:
 *   - structured: synthesised mux_header(s) + small payloads + bit-flip mutations
 *   - random:     uniform random bytes
 *
 * Invariants checked after every dispatch_frame call:
 *   1. ack_seq never leads recv_seq  (modular distance < 2^31)
 *   2. ss.state is a valid session_state enum value
 *   3. When session_reset was called, ss.state == SESSION_CLOSED
 *
 * Reproducibility: set MUX_FUZZ_SEED (hex) and MUX_FUZZ_ITERATIONS.
 * Default seed is fixed so CI runs are deterministic.
 */

#include "mux/frame.h"
#include "mux/session.h"
#include "mux/stream.h"

#include "utils/testing.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pull in the static symbols under test directly. */
#include "mux/dispatch.c"

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
static struct mux_stream *g_sched_find_stream;

/* on_accept mock control */
static bool g_on_accept_result;

/* ------------------------------------------------------------------ */
/* Live-stream tracking for cleanup                                    */
/* ------------------------------------------------------------------ */

/* stream_new allocates; stream_close frees.  When on_accept returns true,
 * the stream survives dispatch_no_stream and must be freed at cleanup. */
#define FUZZ_MAX_LIVE_STREAMS 64
static struct mux_stream *g_live_streams[FUZZ_MAX_LIVE_STREAMS];
static int g_live_stream_count;

static void fuzz_track_stream(struct mux_stream *s)
{
	if (g_live_stream_count < FUZZ_MAX_LIVE_STREAMS) {
		g_live_streams[g_live_stream_count++] = s;
	}
}

static void fuzz_untrack_stream(struct mux_stream *s)
{
	for (int i = 0; i < g_live_stream_count; i++) {
		if (g_live_streams[i] == s) {
			g_live_streams[i] =
				g_live_streams[--g_live_stream_count];
			return;
		}
	}
}

static void fuzz_cleanup_streams(void)
{
	for (int i = g_live_stream_count - 1; i >= 0; i--) {
		free(g_live_streams[i]);
	}
	g_live_stream_count = 0;
}

/* ------------------------------------------------------------------ */
/* Mock reset                                                          */
/* ------------------------------------------------------------------ */

static void fuzz_mocks_reset(void)
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
	g_on_accept_result = true;
}

/* ------------------------------------------------------------------ */
/* Mock helpers                                                        */
/* ------------------------------------------------------------------ */

static void
consume_frame(struct mux_session *restrict ss, const size_t frame_size)
{
	if (ringbuf_readable(ss->wire.recvbuf) >= frame_size) {
		ringbuf_consume(ss->wire.recvbuf, frame_size);
		return;
	}
	ringbuf_reset(ss->wire.recvbuf);
}

/* ------------------------------------------------------------------ */
/* Mock implementations                                                */
/* ------------------------------------------------------------------ */

int stream_format_tag(
	char *restrict buf, const size_t buflen,
	const struct mux_stream *restrict s)
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

/* Update ack_seq to prevent recv_seq - ack_seq growing without bound. */
void session_emit_ack(struct mux_session *ss)
{
	ss->ack_seq = ss->recv_seq;
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

struct mux_stream *sched_find_stream(
	struct mux_session *restrict ss, const uint_fast16_t stream_id)
{
	(void)ss;
	if (g_sched_find_stream != NULL &&
	    g_sched_find_stream->id == stream_id) {
		return g_sched_find_stream;
	}
	return NULL;
}

/* No-op: max_streams is set to 0 in the fuzz session, skipping the
 * table_size check.  We track accepted streams separately for cleanup. */
bool sched_add_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s)
{
	(void)ss;
	fuzz_track_stream(s);
	return true;
}

/* on_accept callback: controls stream acceptance per iteration. */
static bool
fuzz_on_accept(void *ud, struct mux_session *ss, struct mux_stream *s)
{
	(void)ud;
	(void)ss;
	(void)s;
	/* When rejected, dispatch.c calls stream_close which untrack+frees. */
	return g_on_accept_result;
}

struct mux_stream *stream_new(
	struct mux_session *restrict ss, const uint_fast16_t id,
	const bool active_open)
{
	(void)active_open;
	struct mux_stream *const s = calloc(1, sizeof(*s));
	if (s != NULL) {
		s->session = ss;
		s->id = (uint_least16_t)id;
		s->state = STREAM_SYN_RECEIVED;
		/* syn_sent_ns = 0: skips clock_monotonic_ns on SYN|ACK path. */
	}
	return s;
}

void stream_close(struct mux_stream *s)
{
	fuzz_untrack_stream(s);
	free(s);
}

void stream_free(struct mux_stream *s)
{
	fuzz_untrack_stream(s);
	free(s);
}

void stream_recv_rst(struct mux_stream *s)
{
	(void)s;
	g_stream_recv_rst_calls++;
}

void stream_recv_window(
	struct mux_stream *restrict s, const uint_fast32_t window_inc)
{
	g_stream_recv_window_calls++;
	g_last_window_inc = window_inc;
	s->send_window = (uint_least32_t)(MUX_DEFAULT_SEND_WINDOW +
					  window_inc * MUX_WINDOW_UNIT);
}

void stream_start(struct mux_stream *s)
{
	g_stream_start_calls++;
	s->state = STREAM_ESTABLISHED;
}

void stream_recv_copy(
	struct mux_stream *restrict s, const unsigned char *restrict payload,
	const size_t payload_len)
{
	(void)s;
	(void)payload;
	(void)payload_len;
}

void stream_recv_fin(struct mux_stream *s)
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

/* ------------------------------------------------------------------ */
/* Input generation                                                    */
/* ------------------------------------------------------------------ */

/* Keep each input small so iterations stay fast under sanitisers. */
#define FUZZ_INPUT_CAP 384u

/*
 * Structured mode: synthesise 1-3 mux frames, optionally append a
 * partial header, then apply a few random bit flips.
 * target_stream_id: when non-zero, half of frames target this ID to
 * drive the dispatch_by_stream path.
 */
static size_t gen_structured(
	unsigned char *restrict buf, const size_t cap, const bool accepted,
	const uint_least16_t target_stream_id)
{
	static const uint8_t flag_combos[] = {
		/* Valid combinations */
		MUX_FLAG_SYN,
		MUX_FLAG_SYN | MUX_FLAG_ACK,
		MUX_FLAG_SYN | MUX_FLAG_ACK | MUX_FLAG_PUSH,
		MUX_FLAG_ACK,
		MUX_FLAG_ACK | MUX_FLAG_FIN,
		MUX_FLAG_FIN,
		MUX_FLAG_RST,
		MUX_FLAG_PUSH,
		MUX_FLAG_PUSH | MUX_FLAG_ACK,
		MUX_FLAG_PUSH | MUX_FLAG_FIN,
		0,
		/* Invalid / edge cases */
		0x20, /* reserved bit */
		0xff, /* all bits */
		MUX_FLAG_SYN | MUX_FLAG_RST,
		MUX_FLAG_FIN | MUX_FLAG_SYN,
	};
	static const uint8_t versions[] = {
		MUX_PROTOCOL_VERSION,
		MUX_PROTOCOL_VERSION,
		MUX_PROTOCOL_VERSION,
		0, /* hello */
		2, /* unsupported */
		0xff,
	};

	size_t off = 0;
	const int nframes = (int)(1 + prng_range(3));

	for (int i = 0; i < nframes; i++) {
		struct mux_header hdr;

		hdr.version = versions[prng_range(
			sizeof(versions) / sizeof(versions[0]))];
		hdr.flags = flag_combos[prng_range(
			sizeof(flag_combos) / sizeof(flag_combos[0]))];

		/* stream_id selection */
		if (target_stream_id != 0 && prng_bool()) {
			/* Target the pre-inserted stream to exercise
			 * dispatch_by_stream. */
			hdr.stream_id = target_stream_id;
		} else {
			const uint32_t r = prng_u32() % 6u;
			if (r == 0) {
				hdr.stream_id = STREAMID_CTRL;
			} else if (r < 3u) {
				/* Valid peer parity for this session role */
				const uint16_t base =
					(uint16_t)(2u * (1u + prng_range(32)));
				hdr.stream_id =
					accepted ? (uint16_t)(base | 1u) : base;
			} else {
				hdr.stream_id = (uint16_t)prng_u32();
			}
		}

		/* Small payload for speed; dispatcher still exercises all
		 * payload-touching branches. */
		hdr.length = (uint_least16_t)prng_range(33);
		hdr.extra = (uint_least16_t)prng_u32();

		const size_t fsz = MUX_FRAME_HEADER_SIZE + hdr.length;
		if (off + fsz > cap) {
			break;
		}

		mux_write_header(buf + off, &hdr);
		for (size_t j = 0; j < hdr.length; j++) {
			buf[off + MUX_FRAME_HEADER_SIZE + j] =
				(unsigned char)prng_u32();
		}
		off += fsz;
	}

	/* Optionally append a partial frame header (incomplete-frame path). */
	if (prng_bool() && off + MUX_FRAME_HEADER_SIZE <= cap) {
		const size_t partial =
			1u + prng_range(MUX_FRAME_HEADER_SIZE - 1u);
		for (size_t j = 0; j < partial; j++) {
			buf[off + j] = (unsigned char)prng_u32();
		}
		off += partial;
	}

	/* Bit-flip mutations: corrupt 0-4 random bit positions. */
	const int nflips = (int)prng_range(5);
	for (int i = 0; i < nflips && off > 0; i++) {
		const size_t pos = prng_range(off);
		const int bit = (int)prng_range(8);
		buf[pos] ^= (unsigned char)(1u << bit);
	}

	return off;
}

/* Random mode: completely uniform byte sequence. */
static size_t gen_random(unsigned char *restrict buf, const size_t cap)
{
	const size_t maxlen = cap < 128u ? cap : 128u;
	const size_t len = prng_range(maxlen + 1u);
	for (size_t i = 0; i < len; i++) {
		buf[i] = (unsigned char)prng_u32();
	}
	return len;
}

/* ------------------------------------------------------------------ */
/* Session factory                                                     */
/* ------------------------------------------------------------------ */

static void fuzz_make_session(struct mux_session *ss, const bool accepted)
{
	memset(ss, 0, sizeof(*ss));
	ss->accepted = accepted;
	ss->state = SESSION_ESTABLISHED;
	ss->session_window = 8;
	ss->stream_window = 4;
	ss->tag = (char *)"[fuzz]:";
	ss->w_socket.fd = -1;
	ss->conf.max_streams = 0; /* skip table_size check */
	ss->callbacks.on_accept = fuzz_on_accept;
	/* on_event intentionally NULL: skips latency callback */
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

T_DECLARE_CASE(test_dispatch_fuzz)
{
	/* Seed: environment variable overrides for long-run campaigns. */
	uint64_t seed = UINT64_C(0xdeadbeefcafe0001);
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

	static unsigned char input_buf[FUZZ_INPUT_CAP];

	/* Stream states available for the pre-inserted stream. */
	static const enum stream_state kStreamStates[] = {
		STREAM_SYN_SENT, STREAM_SYN_RECEIVED, STREAM_ESTABLISHED,
		STREAM_FIN_WAIT, STREAM_CLOSE_WAIT,   STREAM_CLOSING,
		STREAM_CLOSED,
	};
	static const size_t kNStates =
		sizeof(kStreamStates) / sizeof(kStreamStates[0]);

	for (size_t iter = 0; iter < iterations; iter++) {
		/* -- Mock configuration ----------------------------------- */
		fuzz_mocks_reset();
		g_ack_trim_result = prng_u32() % 8u != 0u;
		g_handshake_result = prng_u32() % 4u != 0u;
		g_handshake_promotes_established = prng_bool();
		g_handshake_sets_tx_pending = prng_bool();
		g_on_accept_result = prng_u32() % 4u != 0u;

		/* -- Session role ----------------------------------------- */
		const bool accepted = prng_bool();

		/* -- Pre-inserted stream (exercises dispatch_by_stream) ---- */
		/* 75 % of iterations have a pre-existing stream so that
		 * dispatch_by_stream is reached often. */
		struct mux_stream prestream = { 0 };
		uint_least16_t target_id = 0;
		if (prng_range(4u) != 0u) {
			/* Use a valid peer-parity stream ID for the role. */
			target_id = (uint_least16_t)(accepted ? 1u : 2u);
			prestream.id = target_id;
			prestream.state = kStreamStates[prng_range(kNStates)];
			prestream.send_window = MUX_DEFAULT_SEND_WINDOW;
			/* syn_sent_ns = 0: skips clock_monotonic_ns. */
			g_sched_find_stream = &prestream;
		}

		/* -- Input ------------------------------------------------ */
		size_t input_len;
		if (prng_bool()) {
			input_len = gen_structured(
				input_buf, sizeof(input_buf), accepted,
				target_id);
		} else {
			input_len = gen_random(input_buf, sizeof(input_buf));
		}

		/* -- Session and receive buffer --------------------------- */
		struct mux_session ss;
		fuzz_make_session(&ss, accepted);

		const size_t bufcap = input_len > 0u ? input_len : 1u;
		ss.wire.recvbuf = ringbuf_new(bufcap);
		if (ss.wire.recvbuf == NULL) {
			/* OOM: skip iteration without failing the test. */
			fuzz_cleanup_streams();
			continue;
		}

		if (input_len > 0u) {
			memcpy(ringbuf_write_ptr(ss.wire.recvbuf), input_buf,
			       input_len);
			ringbuf_produce(ss.wire.recvbuf, input_len);
		}

		/* -- Dispatch --------------------------------------------- */
		dispatch_frame(&ss);

		/* -- Invariant checks ------------------------------------- */

		/* 1. ack_seq never leads recv_seq (modular distance < 2^31).
		 *    session_emit_ack mock keeps them in sync, so the distance
		 *    is bounded by the coalesce threshold (≤ session_window). */
		if ((int32_t)(ss.recv_seq - ss.ack_seq) < 0) {
			print_fuzz_context(iter, seed, input_buf, input_len);
			T_FATAL("invariant violated: ack_seq > recv_seq");
		}

		/* 2. ss.state is a valid session_state value. */
		if ((unsigned)ss.state > (unsigned)SESSION_CLOSED) {
			print_fuzz_context(iter, seed, input_buf, input_len);
			T_FATAL("invariant violated: session state out of range");
		}

		/* 3. session_reset implies SESSION_CLOSED. */
		if (g_reset_calls > 0 && ss.state != SESSION_CLOSED) {
			print_fuzz_context(iter, seed, input_buf, input_len);
			T_FATAL("invariant violated: session_reset called but "
				"state != SESSION_CLOSED");
		}

		/* -- Cleanup ---------------------------------------------- */
		fuzz_cleanup_streams();
		ringbuf_free(ss.wire.recvbuf);
	}
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_dispatch_fuzz);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
