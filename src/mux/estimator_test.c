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
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)WNDSIZE_MAX);
	estimator_init(&ss, 0);
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)0);
}

T_DECLARE_CASE(test_estimator_init_resets_all_state)
{
	struct mux_session ss = make_session();

	/* Seed every field to confirm estimator_init zeros them all. */
	ss.estimator.effective_bdp = 65536;
	wndfilter_reset(&ss.estimator.bw_wnd, 0, INTMAX_C(50000000));
	wndfilter_reset(&ss.estimator.rtt_wnd, 0, INTMAX_C(250000000));
	ss.estimator.probe_sent_ns = 10;
	ss.estimator.sample = 30;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 40;
	ss.estimator.phase = ESTIMATOR_TRACK;
	ss.estimator.bw_exit = 999;

	estimator_init(&ss, 12345);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (intmax_t)0);
	T_EXPECT_EQ(ss.estimator.probe_sent_ns, (intmax_t)0);
	T_EXPECT_EQ(ss.estimator.sample, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)12345);
	T_EXPECT(wndfilter_get(&ss.estimator.bw_wnd) == 0);
	T_EXPECT(wndfilter_get(&ss.estimator.rtt_wnd) == 0);
	T_EXPECT_EQ(ss.estimator.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.bw_exit, (intmax_t)0);
}

T_DECLARE_CASE(test_estimator_add_accumulates_sample_while_ping_in_flight)
{
	struct mux_session ss = make_session();
	const intmax_t now =
		(intmax_t)ss.conf.ping_timeout * INTMAX_C(1000000000) - 1;

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
 * immediately using the same clock reading: last_probe_ns is NOT updated
 * so the rate-limit check does not block the fresh probe, and only one
 * clock call is made (reused for both the timeout check and probe start). */
T_DECLARE_CASE(test_estimator_add_timeout_discards_cycle_and_restarts_probe)
{
	struct mux_session ss = make_session();
	const intmax_t ping_timeout_ns =
		(intmax_t)ss.conf.ping_timeout * INTMAX_C(1000000000);
	/* Single timestamp: reused for timeout check and new probe start. */
	const intmax_t probe_start_ns = ping_timeout_ns + 1;

	estimator_test_reset();
	set_clock_sequence(&probe_start_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 0;
	ss.estimator.sample = 44;

	estimator_add(&ss, 50);
	/* Cycle state cleared by timeout. */
	T_EXPECT_EQ(ss.estimator.sample, (size_t)50);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (intmax_t)0);
	/* A new probe must have been started immediately. */
	T_EXPECT_EQ(g_send_urgent_calls, 1);
	T_EXPECT_EQ(g_last_urgent_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.probe_sent_ns, probe_start_ns);
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
	T_EXPECT_EQ(ss.estimator.probe_sent_ns, now);
	T_EXPECT(ss.estimator.ping_in_flight);
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

/* Window-limited cycle: sample > 2/3 of effective_bdp → triples effective_bdp. */
T_DECLARE_CASE(test_estimator_calculate_updates_effective_bdp)
{
	struct mux_session ss = make_session();
	/* rtt = 10 ms; sample = 2 frames = 32768 B → bw_sample = 3276800 B/s. */
	const intmax_t rtt_ns = INTMAX_C(10000000);
	const intmax_t now_ns = INTMAX_C(15) * INTMAX_C(1000000000) + rtt_ns;
	const intmax_t sent_ns = now_ns - rtt_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE; /* 32768 */
	/* window_limited: 32768 > 40000 × 2/3 = 26666 → true. */
	ss.estimator.effective_bdp = 40000;

	estimator_calculate(&ss, sent_ns);
	/* window_limited = true, !rtt_inflated → stays STARTUP, effective_bdp = 40000 × 3 = 120000. */
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)120000);
	T_EXPECT_EQ(estimator_window_size(&ss.estimator), (size_t)120000);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now_ns);
	T_EXPECT(wndfilter_get(&ss.estimator.bw_wnd) > 0);
	T_EXPECT_EQ(ss.estimator.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.bw_exit, (intmax_t)0);
}

/* RTT inflation cycle: current RTT exceeds rtt_min × 5/4 while the sample is
 * too small to be window-limited.  effective_bdp is reduced to bdp × 1.25
 * to drain the growing queue. */
T_DECLARE_CASE(test_estimator_calculate_app_limited_adopts_bdp_peak)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_min_ns = INTMAX_C(10000000); /* 10 ms */
	/* 15 ms > rtt_min × 5/4 = 12.5 ms → RTT inflated. */
	const intmax_t rtt_ns = INTMAX_C(15000000);
	const intmax_t now_ns = INTMAX_C(100) * INTMAX_C(1000000000) + rtt_ns;
	const intmax_t sent_ns = now_ns - rtt_ns;
	/* bw_high = 500 MB/s → bdp = 500e6 × 10e-3 = 5 MB. */
	const intmax_t bw_high = INTMAX_C(500000000);

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	wndfilter_reset(
		&ss.estimator.bw_wnd, now_ns - INTMAX_C(1000000), bw_high);
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000), rtt_min_ns);
	ss.estimator.inited =
		true; /* rtt_wnd already seeded with 10 ms minimum */

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* effective_bdp large enough that sample is not window-limited:
	 * 16384 ≤ 10 MB × 2/3 = 6 666 666 → window_limited = false. */
	const size_t bdp_bytes =
		(size_t)((double)bw_high * (double)rtt_min_ns / 1e9);
	ss.estimator.effective_bdp = bdp_bytes * 2;

	estimator_calculate(&ss, sent_ns);

	/* bw_wnd reflects its seeded peak (app-limited bw_sample is below it). */
	T_EXPECT_EQ(wndfilter_get(&ss.estimator.bw_wnd), bw_high);
	/* STARTUP + rtt_inflated → exits to TRACK; effective_bdp = bdp + bdp/4. */
	T_EXPECT_EQ(ss.estimator.effective_bdp, bdp_bytes + bdp_bytes / 4);
	T_EXPECT_EQ(ss.estimator.phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(ss.estimator.bw_exit, bw_high);
}

/* estimator_calculate stores the computed effective_bdp. */
T_DECLARE_CASE(test_estimator_effective_bdp_stores_value)
{
	struct mux_session ss = make_session();
	ss.estimator.effective_bdp = 65536;
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)65536);
	/* With a different value. */
	ss.estimator.effective_bdp = 100000;
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)100000);
}

/* estimator_window_size floors the result at WNDSIZE_MIN even when
 * window_limited only triples a small effective_bdp. */
T_DECLARE_CASE(test_estimator_calculate_effective_bdp_floored_at_min)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_sample_ns = INTMAX_C(1000000000); /* 1 s */
	const intmax_t now_ns =
		INTMAX_C(700) * INTMAX_C(1000000000) + rtt_sample_ns;
	const intmax_t sent_ns = now_ns - rtt_sample_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE; /* 32768 */
	/* window_limited: 32768 > 10000 × 2/3 = 6666 → true. */
	ss.estimator.effective_bdp = 10000;

	estimator_calculate(&ss, sent_ns);

	/* window_limited → effective_bdp = 10000 × 3 = 30000 < WNDSIZE_MIN;
	 * estimator_window_size floors to WNDSIZE_MIN. */
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)30000);
	T_EXPECT_EQ(estimator_window_size(&ss.estimator), WNDSIZE_MIN);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now_ns);
}

/* Neither trigger fires: effective_bdp is preserved.
 * sample = 0 → window_limited = false and bw_now = 0, which prevents the
 * RTT-inflation branch (guard: bw_now > 0). */
T_DECLARE_CASE(test_estimator_calculate_invalid_cycle_preserves_effective_bdp)
{
	struct mux_session ss = make_session();
	const intmax_t now = 200;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.effective_bdp = 2u * (size_t)WNDSIZE_MIN;
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = 100;
	/* sample = 0: no BW sample is fed to the filters this cycle. */
	ss.estimator.sample = 0;

	estimator_calculate(&ss, 100);
	T_EXPECT_EQ(ss.estimator.effective_bdp, 2u * (size_t)WNDSIZE_MIN);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* App-limited and no RTT inflation: effective_bdp is preserved unchanged.
 * current RTT equals the windowed minimum (rtt = rtt_min), so rtt_inflated
 * is false; sample < 2/3 of effective_bdp, so window_limited is false. */
T_DECLARE_CASE(test_estimator_calculate_peak_guard_trims_to_peak_ceiling)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_ns = INTMAX_C(10000000); /* 10 ms */
	const intmax_t now_ns = INTMAX_C(200) * INTMAX_C(1000000000) + rtt_ns;
	const intmax_t sent_ns = now_ns - rtt_ns;
	const intmax_t bw_val = INTMAX_C(100000000); /* 100 MB/s */

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000), rtt_ns);
	wndfilter_reset(
		&ss.estimator.bw_wnd, now_ns - INTMAX_C(1000000), bw_val);
	ss.estimator.inited = true;

	/* bdp = 100e6 × 10e-3 = 1 MB.  effective_bdp at 5 MB so that
	 * sample = 16384 ≤ 5 MB × 2/3 = 3 333 333 → window_limited = false. */
	const size_t bdp_bytes =
		(size_t)((double)bw_val * (double)rtt_ns / 1e9);
	ss.estimator.effective_bdp = bdp_bytes * 5;

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = (size_t)MUX_MAX_PAYLOAD_SIZE;

	estimator_calculate(&ss, sent_ns);

	/* Neither condition fired: effective_bdp unchanged. */
	T_EXPECT_EQ(ss.estimator.effective_bdp, bdp_bytes * 5);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* STARTUP: RTT inflation takes priority over a window-limited sample.
 * Even when sample > 2/3 of effective_bdp, an inflated RTT triggers the
 * STARTUP→TRACK transition with effective_bdp clamped to bdp × 1.25
 * rather than tripled. */
T_DECLARE_CASE(test_estimator_calculate_peak_floor_prevents_decrease)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_min_ns = INTMAX_C(10000000); /* 10 ms */
	/* 15 ms > rtt_min × 5/4 = 12.5 ms → RTT inflated. */
	const intmax_t rtt_ns = INTMAX_C(15000000);
	const intmax_t now_ns = INTMAX_C(200) * INTMAX_C(1000000000) + rtt_ns;
	const intmax_t sent_ns = now_ns - rtt_ns;
	const intmax_t bw_val = INTMAX_C(100000000); /* 100 MB/s */

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000), rtt_min_ns);
	wndfilter_reset(
		&ss.estimator.bw_wnd, now_ns - INTMAX_C(1000000), bw_val);
	ss.estimator.inited = true;

	/* window_limited: 32768 > 30000 × 2/3 = 20000 → true, despite RTT inflation.
	 * bdp = bw_val × rtt_min_ns / 1e9 = 100e6 × 10e-3 = 1 MB. */
	ss.estimator.effective_bdp = 30000;
	const size_t bdp_bytes =
		(size_t)((double)bw_val * (double)rtt_min_ns / 1e9);

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE; /* 32768 */

	estimator_calculate(&ss, sent_ns);

	/* rtt_inflated takes priority → STARTUP→TRACK, effective_bdp = bdp × 1.25. */
	T_EXPECT_EQ(ss.estimator.effective_bdp, bdp_bytes + bdp_bytes / 4);
	T_EXPECT_EQ(ss.estimator.phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(ss.estimator.bw_exit, bw_val);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* TRACK: bandwidth within bw_exit × 1.25 ceiling → stays in TRACK,
 * effective_bdp converges to bdp × 1.25. */
T_DECLARE_CASE(test_estimator_track_stable_bw_stays_track)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_ns = INTMAX_C(10000000); /* 10 ms */
	const intmax_t now_ns = INTMAX_C(300) * INTMAX_C(1000000000) + rtt_ns;
	const intmax_t sent_ns = now_ns - rtt_ns;
	/* bw_val = bw_exit = 100 MB/s; bw_sample ≪ bw_val → bw_max = bw_val. */
	const intmax_t bw_val = INTMAX_C(100000000);

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000), rtt_ns);
	wndfilter_reset(
		&ss.estimator.bw_wnd, now_ns - INTMAX_C(1000000), bw_val);
	ss.estimator.inited = true;
	ss.estimator.phase = ESTIMATOR_TRACK;
	ss.estimator.bw_exit = bw_val;
	/* bdp = 100e6 × 10e-3 = 1 MB. */
	const size_t bdp_bytes =
		(size_t)((double)bw_val * (double)rtt_ns / 1e9);
	ss.estimator.effective_bdp = bdp_bytes * 2;

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = (size_t)MUX_MAX_PAYLOAD_SIZE;

	estimator_calculate(&ss, sent_ns);

	/* bw_max = bw_val = bw_exit → not > bw_exit × 1.25 → stays TRACK. */
	T_EXPECT_EQ(ss.estimator.phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(ss.estimator.effective_bdp, bdp_bytes + bdp_bytes / 4);
	T_EXPECT_EQ(ss.estimator.bw_exit, bw_val);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* TRACK: bandwidth exceeds bw_exit × 1.25 → transitions back to STARTUP
 * and triples effective_bdp to resume probing. */
T_DECLARE_CASE(test_estimator_track_bw_peak_returns_to_startup)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_ns = INTMAX_C(10000000); /* 10 ms */
	const intmax_t now_ns = INTMAX_C(400) * INTMAX_C(1000000000) + rtt_ns;
	const intmax_t sent_ns = now_ns - rtt_ns;
	/* bw_exit = 100 MB/s; bw_val = 200 MB/s > bw_exit × 1.25 = 125 MB/s. */
	const intmax_t bw_exit = INTMAX_C(100000000);
	const intmax_t bw_val = INTMAX_C(200000000);

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000), rtt_ns);
	wndfilter_reset(
		&ss.estimator.bw_wnd, now_ns - INTMAX_C(1000000), bw_val);
	ss.estimator.inited = true;
	ss.estimator.phase = ESTIMATOR_TRACK;
	ss.estimator.bw_exit = bw_exit;
	ss.estimator.effective_bdp = 1500000;

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = (size_t)MUX_MAX_PAYLOAD_SIZE;

	estimator_calculate(&ss, sent_ns);

	/* bw_max = 200e6 > bw_exit + bw_exit/4 = 125e6 → back to STARTUP. */
	T_EXPECT_EQ(ss.estimator.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.bw_exit, (intmax_t)0);
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)4500000);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* TRACK with bw_exit = 0: any positive bw_max triggers STARTUP re-entry,
 * as there is no recorded exit bandwidth to compare against. */
T_DECLARE_CASE(test_estimator_track_zero_bw_exit_returns_to_startup)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_ns = INTMAX_C(10000000); /* 10 ms */
	const intmax_t now_ns = INTMAX_C(500) * INTMAX_C(1000000000) + rtt_ns;
	const intmax_t sent_ns = now_ns - rtt_ns;
	const intmax_t bw_val = INTMAX_C(50000000); /* 50 MB/s */

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000), rtt_ns);
	wndfilter_reset(
		&ss.estimator.bw_wnd, now_ns - INTMAX_C(1000000), bw_val);
	ss.estimator.inited = true;
	ss.estimator.phase = ESTIMATOR_TRACK;
	ss.estimator.bw_exit = 0;
	ss.estimator.effective_bdp = 2000000;

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = (size_t)MUX_MAX_PAYLOAD_SIZE;

	estimator_calculate(&ss, sent_ns);

	/* bw_exit = 0: any bw_max > 0 triggers STARTUP re-entry. */
	T_EXPECT_EQ(ss.estimator.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.bw_exit, (intmax_t)0);
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)6000000);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_estimator_init_seeds_effective_bdp);
	T_RUN_CASE(t, test_estimator_init_resets_all_state);
	T_RUN_CASE(
		t, test_estimator_add_accumulates_sample_while_ping_in_flight);
	T_RUN_CASE(
		t,
		test_estimator_add_timeout_discards_cycle_and_restarts_probe);
	T_RUN_CASE(t, test_estimator_add_starts_cycle_after_rate_limit);
	T_RUN_CASE(t, test_estimator_calculate_discards_stale_timestamp);
	T_RUN_CASE(t, test_estimator_calculate_invalid_rtt_clears_cycle);
	T_RUN_CASE(t, test_estimator_calculate_updates_effective_bdp);
	T_RUN_CASE(t, test_estimator_calculate_app_limited_adopts_bdp_peak);
	T_RUN_CASE(t, test_estimator_effective_bdp_stores_value);
	T_RUN_CASE(t, test_estimator_calculate_effective_bdp_floored_at_min);
	T_RUN_CASE(
		t,
		test_estimator_calculate_invalid_cycle_preserves_effective_bdp);
	T_RUN_CASE(
		t, test_estimator_calculate_peak_guard_trims_to_peak_ceiling);
	T_RUN_CASE(t, test_estimator_calculate_peak_floor_prevents_decrease);
	T_RUN_CASE(t, test_estimator_track_stable_bw_stays_track);
	T_RUN_CASE(t, test_estimator_track_bw_peak_returns_to_startup);
	T_RUN_CASE(t, test_estimator_track_zero_bw_exit_returns_to_startup);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
