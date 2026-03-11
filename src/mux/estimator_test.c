/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/estimator.h"

#include "mux/frame.h"
#include "mux/session.h"

#include "os/clock.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static intmax_t estimator_test_clock_monotonic_ns(void);

#define clock_monotonic_ns estimator_test_clock_monotonic_ns
#include "mux/estimator.c"
#undef clock_monotonic_ns

enum {
	TEST_BDP_LIMIT = 16u * 1024u * 1024u,
	CLOCK_SEQ_MAX = 8,
	URGENT_PAYLOAD_MAX = 16,
};

static intmax_t g_clock_seq[CLOCK_SEQ_MAX];
static size_t g_clock_len;
static size_t g_clock_pos;
static bool g_send_urgent_ok;
static int g_send_urgent_calls;
static uint_fast8_t g_last_urgent_extra;
static unsigned char g_last_urgent_payload[URGENT_PAYLOAD_MAX];
static size_t g_last_urgent_payload_len;

static void estimator_test_reset(void)
{
	g_clock_len = 0;
	g_clock_pos = 0;
	g_send_urgent_ok = true;
	g_send_urgent_calls = 0;
	g_last_urgent_extra = 0;
	memset(g_last_urgent_payload, 0, sizeof(g_last_urgent_payload));
	g_last_urgent_payload_len = 0;
}

static void set_clock_sequence(const intmax_t *seq, const size_t len)
{
	T_CHECK(len > 0);
	T_CHECK(len <= CLOCK_SEQ_MAX);
	memcpy(g_clock_seq, seq, len * sizeof(seq[0]));
	g_clock_len = len;
	g_clock_pos = 0;
}

static intmax_t estimator_test_clock_monotonic_ns(void)
{
	if (g_clock_len == 0) {
		return 0;
	}
	if (g_clock_pos >= g_clock_len) {
		return g_clock_seq[g_clock_len - 1];
	}
	return g_clock_seq[g_clock_pos++];
}

bool session_send_oob(
	struct mux_session *restrict ss, const uint_fast8_t extra,
	const unsigned char *restrict payload, const size_t payload_len)
{
	(void)ss;
	g_send_urgent_calls++;
	g_last_urgent_extra = extra;
	g_last_urgent_payload_len = payload_len;
	if (payload_len <= sizeof(g_last_urgent_payload)) {
		memcpy(g_last_urgent_payload, payload, payload_len);
	}
	return g_send_urgent_ok;
}

static struct mux_session make_session(void)
{
	return (struct mux_session){
		.auto_window = true,
		.session_window = 4,
		.stream_window = 4,
		.tag = (char *)"[test]:",
	};
}

T_DECLARE_CASE(test_estimator_seed_clamps_bdp_to_limit)
{
	struct mux_session ss = make_session();

	estimator_seed(&ss, UINT32_MAX);
	T_EXPECT_EQ(ss.estimator.bdp, (size_t)TEST_BDP_LIMIT);
	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_STARTUP);
}

T_DECLARE_CASE(test_estimator_stop_resets_all_learned_state)
{
	struct mux_session ss = make_session();
	const intmax_t now = 200;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.bdp = 1234;
	ss.estimator.rtt_wnd[0].val = 0.25;
	ss.estimator.probe_sent_ns = 10;
	ss.estimator.cycle_window_bytes = 20;
	ss.estimator.sample = 30;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 40;

	estimator_stop(&ss);
	T_EXPECT_EQ(ss.estimator.epoch_ns, now);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (intmax_t)0);
	T_EXPECT_EQ(ss.estimator.probe_sent_ns, (intmax_t)0);
	T_EXPECT_EQ(ss.estimator.cycle_window_bytes, (size_t)0);
	T_EXPECT_EQ(ss.estimator.sample, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.bdp, (size_t)0);
	T_EXPECT(ss.estimator.rtt_wnd[0].val == 0.0);
}

T_DECLARE_CASE(test_estimator_add_accumulates_sample_while_ping_in_flight)
{
	struct mux_session ss = make_session();
	const intmax_t now = MUX_PING_TIMEOUT_NS - 1;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 0;
	ss.estimator.sample = 15;

	estimator_add(&ss, 20);
	T_EXPECT_EQ(ss.estimator.sample, (size_t)35);
	T_EXPECT_EQ(g_send_urgent_calls, 0);
	T_EXPECT(ss.estimator.ping_in_flight);
}

/* After a PING timeout the cycle is discarded and a new probe starts
 * immediately: last_probe_ns is NOT updated by the timeout path so the
 * rate-limit check does not block the fresh probe. */
T_DECLARE_CASE(test_estimator_add_timeout_discards_cycle_and_restarts_probe)
{
	struct mux_session ss = make_session();
	const intmax_t seq[] = {
		MUX_PING_TIMEOUT_NS + 1, /* now_ns for timeout check */
		MUX_PING_TIMEOUT_NS + 1, /* sent_ns for probe start */
	};

	estimator_test_reset();
	set_clock_sequence(seq, sizeof(seq) / sizeof(seq[0]));
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 0;
	ss.estimator.sample = 44;
	/* last_probe_ns = 0: rate-limit check is skipped after timeout */

	estimator_add(&ss, 50);
	/* Cycle state cleared by timeout. */
	T_EXPECT_EQ(ss.estimator.sample, (size_t)50);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (intmax_t)0);
	/* A new probe must have been started immediately. */
	T_EXPECT_EQ(g_send_urgent_calls, 1);
	T_EXPECT_EQ(g_last_urgent_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.probe_sent_ns, seq[1]);
}

T_DECLARE_CASE(test_estimator_add_starts_cycle_after_rate_limit)
{
	struct mux_session ss = make_session();
	const intmax_t now = MUX_PING_RATE_LIMIT_NS + 9;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.last_probe_ns = 1;

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_urgent_calls, 1);
	T_EXPECT_EQ(g_last_urgent_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT_EQ(g_last_urgent_payload_len, (size_t)MUX_PING_PAYLOAD_SIZE);
	T_EXPECT_EQ(ss.estimator.sample, (size_t)40000);
	T_EXPECT_EQ(
		ss.estimator.cycle_window_bytes,
		(size_t)(ss.session_window * MUX_WINDOW_UNIT));
	T_EXPECT_EQ(ss.estimator.probe_sent_ns, now);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT(!ss.estimator.probe_was_stalled);
}

T_DECLARE_CASE(test_estimator_calculate_discards_stale_timestamp)
{
	struct mux_session ss = make_session();

	estimator_test_reset();
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 100;
	ss.estimator.sample = 45000;

	estimator_calculate(&ss, 99);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.sample, (size_t)45000);
}

T_DECLARE_CASE(test_estimator_add_records_send_stalled)
{
	struct mux_session ss = make_session();
	const intmax_t now = MUX_PING_RATE_LIMIT_NS + 9;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.last_probe_ns = 1;
	ss.send_stalled = true;

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_urgent_calls, 1);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT(ss.estimator.probe_was_stalled);
}

T_DECLARE_CASE(
	test_estimator_calculate_doubles_bdp_when_stalled_and_invalid_cycle)
{
	struct mux_session ss = make_session();
	const intmax_t now = 200;
	const size_t initial_bdp = 65536;
	const size_t cycle_window = (size_t)4 * MUX_WINDOW_UNIT;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 100;
	/* sample < 2 * MUX_MAX_PAYLOAD_SIZE → invalid cycle */
	ss.estimator.sample = (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.cycle_window_bytes = cycle_window;
	ss.estimator.probe_was_stalled = true;
	ss.estimator.phase = EST_STARTUP;
	ss.estimator.bdp = initial_bdp;

	estimator_calculate(&ss, 100);
	T_EXPECT_EQ(ss.estimator.bdp, (size_t)(initial_bdp + cycle_window));
	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_STARTUP);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
}

T_DECLARE_CASE(test_estimator_calculate_discards_pre_epoch_pong)
{
	struct mux_session ss = make_session();

	estimator_test_reset();
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 100;
	ss.estimator.epoch_ns = 101;

	estimator_calculate(&ss, 100);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (intmax_t)0);
}

T_DECLARE_CASE(test_estimator_calculate_invalid_rtt_clears_cycle)
{
	struct mux_session ss = make_session();
	const intmax_t now = 100;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 100;
	ss.estimator.sample = 50000;

	estimator_calculate(&ss, 100);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
}

T_DECLARE_CASE(
	test_estimator_calculate_transitions_to_track_when_not_window_limited)
{
	struct mux_session ss = make_session();
	const intmax_t now = 200;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 100;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.cycle_window_bytes = 4u * (size_t)MUX_WINDOW_UNIT;
	ss.estimator.phase = EST_STARTUP;
	ss.estimator.bdp = 1000;

	estimator_calculate(&ss, 100);
	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_TRACK);
	T_EXPECT(ss.estimator.rtt_wnd[0].val > 0.0);
	T_EXPECT(ss.estimator.bw_wnd[0].val > 0.0);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

T_DECLARE_CASE(test_estimator_calculate_grows_bdp_when_window_limited)
{
	struct mux_session ss = make_session();
	const intmax_t now = 200;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 100;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.cycle_window_bytes = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.phase = EST_STARTUP;
	ss.estimator.bdp = 1000;

	estimator_calculate(&ss, 100);
	T_EXPECT(ss.estimator.bdp > (size_t)1000);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_estimator_seed_clamps_bdp_to_limit);
	T_RUN_CASE(t, test_estimator_stop_resets_all_learned_state);
	T_RUN_CASE(
		t, test_estimator_add_accumulates_sample_while_ping_in_flight);
	T_RUN_CASE(
		t,
		test_estimator_add_timeout_discards_cycle_and_restarts_probe);
	T_RUN_CASE(t, test_estimator_add_starts_cycle_after_rate_limit);
	T_RUN_CASE(t, test_estimator_add_records_send_stalled);
	T_RUN_CASE(t, test_estimator_calculate_discards_stale_timestamp);
	T_RUN_CASE(t, test_estimator_calculate_discards_pre_epoch_pong);
	T_RUN_CASE(t, test_estimator_calculate_invalid_rtt_clears_cycle);
	T_RUN_CASE(
		t,
		test_estimator_calculate_transitions_to_track_when_not_window_limited);
	T_RUN_CASE(t, test_estimator_calculate_grows_bdp_when_window_limited);
	T_RUN_CASE(
		t,
		test_estimator_calculate_doubles_bdp_when_stalled_and_invalid_cycle);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
