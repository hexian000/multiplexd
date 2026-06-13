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

static int_fast64_t estimator_test_clock_monotonic_ns(void);

#define clock_monotonic_ns estimator_test_clock_monotonic_ns
#include "mux/estimator.c"
#undef clock_monotonic_ns

enum {
	CLOCK_SEQ_MAX = 8,
	URGENT_PAYLOAD_MAX = 16,
};

static int_least64_t g_clock_seq[CLOCK_SEQ_MAX];
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

static void set_clock_sequence(const int_fast64_t *seq, const size_t len)
{
	T_CHECK(len > 0);
	T_CHECK(len <= CLOCK_SEQ_MAX);
	memcpy(g_clock_seq, seq, len * sizeof(seq[0]));
	g_clock_len = len;
	g_clock_pos = 0;
}

static int_fast64_t estimator_test_clock_monotonic_ns(void)
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

void session_suspend(struct mux_session *restrict ss)
{
	(void)ss;
}

void session_notify_closed(struct mux_session *restrict ss, const bool expired)
{
	(void)ss;
	(void)expired;
}

static struct mux_session make_session(void)
{
	struct mux_session ss = {
		.auto_stream_window = true,
		.auto_session_window = true,
		.session_window = 4,
		.stream_window = 4,
		.tag = (char *)"[test]:",
		.conf.timeout = 600,
		.conf.ping_timeout = 4,
	};
	return ss;
}

T_DECLARE_CASE(test_estimator_init_seeds_effective_bdp)
{
	struct mux_session ss = make_session();

	estimator_init(&ss, (size_t)WNDSIZE_MAX);
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp,
		(size_t)WNDSIZE_MAX);
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_TX].effective_bdp,
		(size_t)WNDSIZE_MAX);
	estimator_init(&ss, 0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].effective_bdp, (size_t)0);
}

T_DECLARE_CASE(test_estimator_init_resets_all_state)
{
	struct mux_session ss = make_session();

	/* Seed every field to confirm estimator_init zeros them all. */
	for (int i = 0; i < ESTIMATOR_DIR_COUNT; i++) {
		ss.estimator.dir[i].effective_bdp = 65536;
		wndfilter_reset(
			&ss.estimator.dir[i].bw_wnd, 0, INT64_C(50000000));
		ss.estimator.dir[i].sample = 30;
		ss.estimator.dir[i].phase = ESTIMATOR_TRACK;
		ss.estimator.dir[i].stable_rounds = 7;
	}
	wndfilter_reset(&ss.estimator.rtt_wnd, 0, INT64_C(1000000000));
	ss.estimator.last_probe_ns = 10;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 40;

	estimator_init(&ss, 12345);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (int_fast64_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT(wndfilter_get(&ss.estimator.rtt_wnd) == 0);
	for (int i = 0; i < ESTIMATOR_DIR_COUNT; i++) {
		T_EXPECT_EQ(ss.estimator.dir[i].sample, (size_t)0);
		T_EXPECT_EQ(ss.estimator.dir[i].effective_bdp, (size_t)12345);
		T_EXPECT(wndfilter_get(&ss.estimator.dir[i].bw_wnd) == 0);
		T_EXPECT_EQ(ss.estimator.dir[i].phase, ESTIMATOR_STARTUP);
		T_EXPECT_EQ(ss.estimator.dir[i].stable_rounds, (size_t)0);
	}
}

T_DECLARE_CASE(test_estimator_add_accumulates_sample_while_ping_in_flight)
{
	struct mux_session ss = make_session();
	const int_fast64_t now =
		(int_fast64_t)ss.conf.ping_timeout * INT64_C(1000000000) - 1;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 0;
	ss.estimator.dir[ESTIMATOR_RX].sample = 15;

	estimator_add(&ss, 20);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)35);
	T_EXPECT_EQ(g_send_urgent_calls, 0);
	T_EXPECT(ss.estimator.ping_in_flight);
}

/* After a PING timeout the in-flight cycle is discarded; the session is
 * closed (no session_id) or suspended (has session_id), and no new probe
 * is started on the same call.  last_probe_ns is NOT updated. */
T_DECLARE_CASE(test_estimator_add_timeout_discards_cycle_and_restarts_probe)
{
	struct mux_session ss = make_session();
	const int_fast64_t ping_timeout_ns =
		(int_fast64_t)ss.conf.ping_timeout * INT64_C(1000000000);
	const int_fast64_t now_ns = ping_timeout_ns + 1;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 0;
	ss.estimator.dir[ESTIMATOR_RX].sample = 44;

	estimator_add(&ss, 50);
	/* Cycle discarded; session closed; no new probe fired. */
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (int_fast64_t)0);
	T_EXPECT_EQ(g_send_urgent_calls, 0);
}

T_DECLARE_CASE(test_estimator_add_starts_cycle_after_rate_limit)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 9;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	/* TRACK enforces the rate limit; the window has just elapsed. */
	ss.estimator.dir[ESTIMATOR_RX].phase = ESTIMATOR_TRACK;
	ss.estimator.last_probe_ns = 1;

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_urgent_calls, 1);
	T_EXPECT_EQ(g_last_urgent_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT_EQ(g_last_urgent_payload_len, (size_t)MUX_PING_PAYLOAD_SIZE);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)40000);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
	T_EXPECT(ss.estimator.ping_in_flight);
}

/* TRACK enforces the 1 s rate limit: a recent probe blocks a new cycle. */
T_DECLARE_CASE(test_estimator_add_track_enforces_rate_limit)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 5;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.dir[ESTIMATOR_RX].phase = ESTIMATOR_TRACK;
	ss.estimator.last_probe_ns = now - (MUX_PING_RATE_LIMIT_NS / 2);

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_urgent_calls, 0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
}

/* STARTUP enforces the 1 s rate limit: a recent probe blocks a new cycle. */
T_DECLARE_CASE(test_estimator_add_startup_enforces_rate_limit)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 5;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.dir[ESTIMATOR_RX].phase = ESTIMATOR_STARTUP;
	ss.estimator.last_probe_ns = now - (MUX_PING_RATE_LIMIT_NS / 2);

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_urgent_calls, 0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
}

T_DECLARE_CASE(test_estimator_add_acked_accumulates_while_ping_in_flight)
{
	struct mux_session ss = make_session();
	const int_fast64_t now =
		(int_fast64_t)ss.conf.ping_timeout * INT64_C(1000000000) - 1;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 0;
	ss.estimator.dir[ESTIMATOR_TX].sample = 15;

	estimator_add_acked(&ss, 20);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].sample, (size_t)35);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(g_send_urgent_calls, 0);
	T_EXPECT(ss.estimator.ping_in_flight);
}

/* PING timeout discards the whole cycle: both sample and ack_sample are
 * reset, regardless of which probe function observed the timeout. */
T_DECLARE_CASE(test_estimator_add_acked_timeout_resets_both_samples)
{
	struct mux_session ss = make_session();
	const int_fast64_t ping_timeout_ns =
		(int_fast64_t)ss.conf.ping_timeout * INT64_C(1000000000);
	const int_fast64_t now_ns = ping_timeout_ns + 1;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 0;
	ss.estimator.dir[ESTIMATOR_RX].sample = 44;
	ss.estimator.dir[ESTIMATOR_TX].sample = 50;

	estimator_add_acked(&ss, 99);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (int_fast64_t)0);
	T_EXPECT_EQ(g_send_urgent_calls, 0);
}

T_DECLARE_CASE(test_estimator_add_acked_starts_cycle_after_rate_limit)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 9;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	/* TRACK enforces the rate limit; the window has just elapsed. */
	ss.estimator.dir[ESTIMATOR_RX].phase = ESTIMATOR_TRACK;
	ss.estimator.last_probe_ns = 1;

	estimator_add_acked(&ss, 40000);
	T_EXPECT_EQ(g_send_urgent_calls, 1);
	T_EXPECT_EQ(g_last_urgent_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT_EQ(g_last_urgent_payload_len, (size_t)MUX_PING_PAYLOAD_SIZE);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].sample, (size_t)40000);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
	T_EXPECT(ss.estimator.ping_in_flight);
}

T_DECLARE_CASE(test_estimator_calculate_discards_stale_timestamp)
{
	struct mux_session ss = make_session();

	estimator_test_reset();
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 100;
	ss.estimator.dir[ESTIMATOR_RX].sample = 45000;

	estimator_calculate(&ss, 99);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)45000);
}

T_DECLARE_CASE(test_estimator_calculate_invalid_rtt_clears_cycle)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = 100;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 100;
	ss.estimator.dir[ESTIMATOR_RX].sample = 50000;

	estimator_calculate(&ss, 100);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
}

/* Window-limited cycle: sample > 2/3 of effective_bdp → triples effective_bdp. */
T_DECLARE_CASE(test_estimator_calculate_updates_effective_bdp)
{
	struct mux_session ss = make_session();
	/* rtt = 10 ms; sample = 2 frames = 32768 B → bw_sample = 3276800 B/s. */
	const int_fast64_t rtt_ns = INT64_C(10000000);
	const int_fast64_t now_ns = INT64_C(15) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample =
		2u * (size_t)MUX_MAX_PAYLOAD_SIZE; /* 32768 */
	/* window_limited: 32768 > 40000 × 2/3 = 26666 → true. */
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = 40000;
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].sample, (size_t)0);

	estimator_calculate(&ss, sent_ns);
	/* window_limited = true → stays STARTUP, effective_bdp = 40000 × 3 = 120000. */
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)120000);
	T_EXPECT_EQ(
		estimator_window_size(&ss.estimator, ESTIMATOR_RX),
		(size_t)120000);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now_ns);
	T_EXPECT(wndfilter_get(&ss.estimator.dir[ESTIMATOR_RX].bw_wnd) > 0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].stable_rounds, (size_t)0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].sample, (size_t)0);
	/* The idle tx direction is untouched: no bw sample, no growth. */
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].effective_bdp, (size_t)0);
	T_EXPECT(wndfilter_get(&ss.estimator.dir[ESTIMATOR_TX].bw_wnd) == 0);
}

/* Mirror of test_estimator_calculate_updates_effective_bdp, but the cycle is
 * driven entirely by the tx sample (rx sample stays 0): a pure sender's
 * ack-clock alone must grow the tx effective_bdp via the fast-startup path,
 * while the idle rx direction stays untouched. */
T_DECLARE_CASE(test_estimator_calculate_ack_sample_drives_tx)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000);
	const int_fast64_t now_ns = INT64_C(15) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.dir[ESTIMATOR_TX].sample =
		2u * (size_t)MUX_MAX_PAYLOAD_SIZE; /* 32768 */
	/* window_limited: demand=32768 > 40000 × 2/3 = 26666 → true. */
	ss.estimator.dir[ESTIMATOR_TX].effective_bdp = 40000;
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);

	estimator_calculate(&ss, sent_ns);
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_TX].effective_bdp, (size_t)120000);
	T_EXPECT_EQ(
		estimator_window_size(&ss.estimator, ESTIMATOR_TX),
		(size_t)120000);
	T_EXPECT(wndfilter_get(&ss.estimator.dir[ESTIMATOR_TX].bw_wnd) > 0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].stable_rounds, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].sample, (size_t)0);
	/* The idle rx direction is untouched: no bw sample, no growth. */
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)0);
	T_EXPECT(wndfilter_get(&ss.estimator.dir[ESTIMATOR_RX].bw_wnd) == 0);
}

/* STARTUP exit: after STARTUP_STABLE_ROUNDS consecutive non-window-limited
 * rounds the window is confirmed to have headroom.  The cycle that reaches the
 * threshold transitions to TRACK and preserves effective_bdp. */
T_DECLARE_CASE(test_estimator_startup_stable_rounds_exit_to_track)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now_ns = INT64_C(100) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;
	/* bw_high = 500 MB/s → bdp = 500e6 × 10e-3 = 5 MB. */
	const int_fast64_t bw_high = INT64_C(500000000);

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	wndfilter_reset(
		&ss.estimator.dir[ESTIMATOR_RX].bw_wnd,
		now_ns - INT64_C(1000000), bw_high);
	/* One short of the threshold: this cycle pushes it over. */
	ss.estimator.dir[ESTIMATOR_RX].stable_rounds =
		STARTUP_STABLE_ROUNDS - 1;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample = (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* effective_bdp large enough that the sample is not window-limited:
	 * 16384 ≤ 10 MB × 2/3 = 6 666 666 → window_limited = false. */
	const size_t bdp_bytes =
		(size_t)((double)bw_high * (double)rtt_ns / 1e9);
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = bdp_bytes * 2;

	estimator_calculate(&ss, sent_ns);

	/* bw_wnd reflects its seeded peak (app-limited bw_sample is below it). */
	T_EXPECT_EQ(
		wndfilter_get(&ss.estimator.dir[ESTIMATOR_RX].bw_wnd), bw_high);
	/* stable_rounds reaches the threshold → exit to TRACK; effective_bdp
	 * preserved. */
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].stable_rounds,
		(size_t)STARTUP_STABLE_ROUNDS);
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, bdp_bytes * 2);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_TRACK);
}

/* estimator_calculate stores the computed effective_bdp. */
T_DECLARE_CASE(test_estimator_effective_bdp_stores_value)
{
	struct mux_session ss = make_session();
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = 65536;
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)65536);
	/* With a different value. */
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = 100000;
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)100000);
}

/* estimator_window_size floors the result at WNDSIZE_MIN even when
 * window_limited only triples a small effective_bdp. */
T_DECLARE_CASE(test_estimator_calculate_effective_bdp_floored_at_min)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_sample_ns = INT64_C(1000000000); /* 1 s */
	const int_fast64_t now_ns =
		INT64_C(700) * INT64_C(1000000000) + rtt_sample_ns;
	const int_fast64_t sent_ns = now_ns - rtt_sample_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample =
		2u * (size_t)MUX_MAX_PAYLOAD_SIZE; /* 32768 */
	/* window_limited: 32768 > 10000 × 2/3 = 6666 → true. */
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = 10000;

	estimator_calculate(&ss, sent_ns);

	/* window_limited → effective_bdp = 10000 × 3 = 30000 < WNDSIZE_MIN;
	 * estimator_window_size floors to WNDSIZE_MIN. */
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)30000);
	T_EXPECT_EQ(
		estimator_window_size(&ss.estimator, ESTIMATOR_RX),
		WNDSIZE_MIN);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now_ns);
}

/* sample = 0 → bw_sample = 0; the windowed peak is still zero, so
 * phase_startup returns early (bw_max == 0) and effective_bdp is preserved. */
T_DECLARE_CASE(test_estimator_calculate_invalid_cycle_preserves_effective_bdp)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = 200;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = 2u * (size_t)WNDSIZE_MIN;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 100;
	/* sample = 0: no BW sample is fed to the filters this cycle. */
	ss.estimator.dir[ESTIMATOR_RX].sample = 0;

	estimator_calculate(&ss, 100);
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp,
		2u * (size_t)WNDSIZE_MIN);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* STARTUP, app-limited (sample < 2/3 effective_bdp): not window-limited, so
 * effective_bdp is unchanged and stable_rounds is incremented toward the
 * STARTUP exit threshold. */
T_DECLARE_CASE(test_estimator_startup_app_limited_increments_stable_rounds)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now_ns = INT64_C(200) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;
	const int_fast64_t bw_val = INT64_C(100000000); /* 100 MB/s */

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.dir[ESTIMATOR_RX].bw_wnd,
		now_ns - INT64_C(1000000), bw_val);
	ss.estimator.dir[ESTIMATOR_RX].stable_rounds = 3;

	/* bdp = 100e6 × 10e-3 = 1 MB.  effective_bdp at 5 MB so that
	 * sample = 16384 ≤ 5 MB × 2/3 = 3 333 333 → window_limited = false. */
	const size_t bdp_bytes =
		(size_t)((double)bw_val * (double)rtt_ns / 1e9);
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = bdp_bytes * 5;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample = (size_t)MUX_MAX_PAYLOAD_SIZE;

	estimator_calculate(&ss, sent_ns);

	/* Not window-limited: effective_bdp unchanged, stable_rounds advanced. */
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, bdp_bytes * 5);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].stable_rounds, (size_t)4);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_STARTUP);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* STARTUP, window-limited: triples effective_bdp and resets stable_rounds to
 * zero, restarting the headroom-confirmation count. */
T_DECLARE_CASE(test_estimator_startup_window_limited_resets_stable_rounds)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now_ns = INT64_C(200) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;
	const int_fast64_t bw_val = INT64_C(100000000); /* 100 MB/s */

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.dir[ESTIMATOR_RX].bw_wnd,
		now_ns - INT64_C(1000000), bw_val);
	ss.estimator.dir[ESTIMATOR_RX].stable_rounds = 5;

	/* window_limited: 32768 > 30000 × 2/3 = 20000 → true. */
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = 30000;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample =
		2u * (size_t)MUX_MAX_PAYLOAD_SIZE; /* 32768 */

	estimator_calculate(&ss, sent_ns);

	/* window_limited → effective_bdp tripled; stable_rounds reset; stays STARTUP. */
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)90000);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].stable_rounds, (size_t)0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_STARTUP);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* TRACK: sample ≤ effective_bdp → stays in TRACK;
 * effective_bdp set to bdp × 1.25 (bdp + bdp/4). */
T_DECLARE_CASE(test_estimator_track_sample_within_window_stays_track)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now_ns = INT64_C(300) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;
	/* Seed bw_wnd with a value larger than the sample will produce
	 * (sample × 1e9 / rtt_ns ≈ 1.64 GB/s) so the peak is predictable. */
	const int_fast64_t bw_val = INT64_C(2000000000); /* 2 GB/s */
	const int_fast64_t seed_ts = now_ns - INT64_C(1000000);

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.dir[ESTIMATOR_RX].bw_wnd, seed_ts, bw_val);
	ss.estimator.dir[ESTIMATOR_RX].phase = ESTIMATOR_TRACK;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample = (size_t)MUX_MAX_PAYLOAD_SIZE;

	estimator_calculate(&ss, sent_ns);

	/* bw_max = 2 GB/s, rtt_min_ns = 10 ms
	 * bdp = 2e9 × 1e7 / 1e9 = 20 MB
	 * sample = 16384 ≤ 25 MB → stays TRACK. */
	const size_t bdp_bytes =
		(size_t)((double)bw_val * (double)rtt_ns / 1e9);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp,
		bdp_bytes + bdp_bytes / 4);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* TRACK: first cycle seeds a small BDP; second cycle has a
 * much larger sample that exceeds bdp × 1.25.  The first RTT is kept
 * small so the windowed-minimum RTT stays low, bounding the computed BDP. */
T_DECLARE_CASE(test_estimator_track_sample_exceeds_window_returns_to_startup)
{
	struct mux_session ss = make_session();
	const int_fast64_t ts0 = INT64_C(1000000000);

	/* Cycle 1: tiny sample, small rtt → small BDP. */
	const int_fast64_t sent1_ns = ts0;
	const int_fast64_t rtt1_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now1_ns = ts0 + rtt1_ns;

	/* Cycle 2: huge sample, moderate rtt → bw_sample beats cycle-1 peak;
	 * with rtt_min_ns still at 10 ms, bdp × 1.25 < sample → STARTUP. */
	const int_fast64_t sent2_ns = ts0 + INT64_C(1000000000);
	const int_fast64_t rtt2_ns = INT64_C(30000000); /* 30 ms */
	const int_fast64_t now2_ns = sent2_ns + rtt2_ns;

	estimator_test_reset();

	/* Cycle 1: sample=1000 → bw_sample=100 kB/s, rtt_min=10 ms, bdp=1 kB. */
	ss.estimator.dir[ESTIMATOR_RX].phase = ESTIMATOR_TRACK;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent1_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample = 1000u;
	set_clock_sequence(&now1_ns, 1);
	estimator_calculate(&ss, sent1_ns);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_TRACK);
	T_EXPECT(ss.estimator.dir[ESTIMATOR_RX].effective_bdp > 0);

	/* Cycle 2: sample=1000× → bw_sample beats cycle-1 peak;
	 * sample > bdp × 1.25 → phase returns to STARTUP. */
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent2_ns;
	ss.estimator.dir[ESTIMATOR_RX].sample =
		1000u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	set_clock_sequence(&now2_ns, 1);
	estimator_calculate(&ss, sent2_ns);

	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].stable_rounds, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* Mirror of test_estimator_track_sample_exceeds_window_returns_to_startup,
 * but both cycles drive the tx direction via the ack-clock: a pure sender
 * (no estimator_add activity) must trigger the TRACK→STARTUP re-entry on
 * the tx estimate alone, leaving the idle rx direction untouched. */
T_DECLARE_CASE(test_estimator_track_ack_sample_exceeds_window_returns_to_startup)
{
	struct mux_session ss = make_session();
	const int_fast64_t ts0 = INT64_C(1000000000);

	const int_fast64_t sent1_ns = ts0;
	const int_fast64_t rtt1_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now1_ns = ts0 + rtt1_ns;

	const int_fast64_t sent2_ns = ts0 + INT64_C(1000000000);
	const int_fast64_t rtt2_ns = INT64_C(30000000); /* 30 ms */
	const int_fast64_t now2_ns = sent2_ns + rtt2_ns;

	estimator_test_reset();

	/* Cycle 1: tx sample=1000 → bw_sample=100 kB/s, rtt_min=10 ms, bdp=1 kB. */
	ss.estimator.dir[ESTIMATOR_TX].phase = ESTIMATOR_TRACK;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent1_ns;
	ss.estimator.dir[ESTIMATOR_TX].sample = 1000u;
	set_clock_sequence(&now1_ns, 1);
	estimator_calculate(&ss, sent1_ns);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].phase, ESTIMATOR_TRACK);
	T_EXPECT(ss.estimator.dir[ESTIMATOR_TX].effective_bdp > 0);

	/* Cycle 2: tx sample=1000× → bw_sample beats cycle-1 peak;
	 * demand > bdp × 1.25 → tx phase returns to STARTUP. */
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent2_ns;
	ss.estimator.dir[ESTIMATOR_TX].sample =
		1000u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	set_clock_sequence(&now2_ns, 1);
	estimator_calculate(&ss, sent2_ns);

	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].stable_rounds, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].sample, (size_t)0);
	/* The idle rx direction never left its initial state. */
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)0);
}

/* Asymmetric cycle: both directions carry traffic, but only rx is
 * window-limited.  rx must fast-startup (×3) while tx, app-limited in the
 * same cycle, only advances its stable_rounds — no MAX-coupling between
 * the directions. */
T_DECLARE_CASE(test_estimator_asymmetric_samples_grow_independently)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now_ns = INT64_C(15) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	/* rx window-limited: 32768 > 40000 × 2/3 = 26666. */
	ss.estimator.dir[ESTIMATOR_RX].sample =
		2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.dir[ESTIMATOR_RX].effective_bdp = 40000;
	/* tx app-limited: 1000 ≤ 40000 × 2/3. */
	ss.estimator.dir[ESTIMATOR_TX].sample = 1000u;
	ss.estimator.dir[ESTIMATOR_TX].effective_bdp = 40000;

	estimator_calculate(&ss, sent_ns);

	/* rx: fast-startup tripled the window and reset stable_rounds. */
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_RX].effective_bdp, (size_t)120000);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_RX].stable_rounds, (size_t)0);
	/* tx: unchanged window, headroom round counted. */
	T_EXPECT_EQ(
		ss.estimator.dir[ESTIMATOR_TX].effective_bdp, (size_t)40000);
	T_EXPECT_EQ(ss.estimator.dir[ESTIMATOR_TX].stable_rounds, (size_t)1);
	/* Both bandwidth filters got their own samples. */
	T_EXPECT(
		wndfilter_get(&ss.estimator.dir[ESTIMATOR_RX].bw_wnd) >
		wndfilter_get(&ss.estimator.dir[ESTIMATOR_TX].bw_wnd));
	T_EXPECT(wndfilter_get(&ss.estimator.dir[ESTIMATOR_TX].bw_wnd) > 0);
}

/* estimator_ping sets last_probe_ns so a subsequent probe cycle observes
 * the rate-limit interval. */
T_DECLARE_CASE(test_estimator_ping_sets_last_probe_ns)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = INT64_C(1000000000);

	estimator_test_reset();
	set_clock_sequence(&now, 1);

	estimator_ping(&ss);
	T_EXPECT_EQ(g_send_urgent_calls, 1);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT(ss.estimator.last_probe_ns == now);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_estimator_ping_sets_last_probe_ns);
	T_RUN_CASE(t, test_estimator_init_seeds_effective_bdp);
	T_RUN_CASE(t, test_estimator_init_resets_all_state);
	T_RUN_CASE(
		t, test_estimator_add_accumulates_sample_while_ping_in_flight);
	T_RUN_CASE(
		t,
		test_estimator_add_timeout_discards_cycle_and_restarts_probe);
	T_RUN_CASE(t, test_estimator_add_starts_cycle_after_rate_limit);
	T_RUN_CASE(t, test_estimator_add_track_enforces_rate_limit);
	T_RUN_CASE(t, test_estimator_add_startup_enforces_rate_limit);
	T_RUN_CASE(
		t, test_estimator_add_acked_accumulates_while_ping_in_flight);
	T_RUN_CASE(t, test_estimator_add_acked_timeout_resets_both_samples);
	T_RUN_CASE(t, test_estimator_add_acked_starts_cycle_after_rate_limit);
	T_RUN_CASE(t, test_estimator_calculate_discards_stale_timestamp);
	T_RUN_CASE(t, test_estimator_calculate_invalid_rtt_clears_cycle);
	T_RUN_CASE(t, test_estimator_calculate_updates_effective_bdp);
	T_RUN_CASE(t, test_estimator_calculate_ack_sample_drives_tx);
	T_RUN_CASE(t, test_estimator_startup_stable_rounds_exit_to_track);
	T_RUN_CASE(t, test_estimator_effective_bdp_stores_value);
	T_RUN_CASE(t, test_estimator_calculate_effective_bdp_floored_at_min);
	T_RUN_CASE(
		t,
		test_estimator_calculate_invalid_cycle_preserves_effective_bdp);
	T_RUN_CASE(
		t, test_estimator_startup_app_limited_increments_stable_rounds);
	T_RUN_CASE(
		t, test_estimator_startup_window_limited_resets_stable_rounds);
	T_RUN_CASE(t, test_estimator_track_sample_within_window_stays_track);
	T_RUN_CASE(
		t,
		test_estimator_track_sample_exceeds_window_returns_to_startup);
	T_RUN_CASE(
		t,
		test_estimator_track_ack_sample_exceeds_window_returns_to_startup);
	T_RUN_CASE(t, test_estimator_asymmetric_samples_grow_independently);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
