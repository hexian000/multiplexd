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
		.auto_window = true,
		.session_window = 4,
		.stream_window = 4,
		.tag = (char *)"[test]:",
		.conf.timeout = 600,
		.conf.ping_timeout = 4,
	};
	ewma_init_span(&ss.estimator.bdp_ewma, BDP_EWMA_SPAN);
	return ss;
}

T_DECLARE_CASE(test_estimator_seed_clamps_effective_bdp_to_limit)
{
	struct mux_session ss = make_session();

	estimator_seed(&ss, UINT32_MAX);
	/* bdp stores the raw seeded value; effective_bdp is clamped to BDP_MAX. */
	T_EXPECT_EQ(ss.estimator.bdp, (size_t)UINT32_MAX);
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)BDP_MAX);
	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_STARTUP);
}

T_DECLARE_CASE(test_estimator_stop_resets_all_learned_state)
{
	struct mux_session ss = make_session();
	const intmax_t now = 200;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.bdp = 1234;
	wndfilter_reset(&ss.estimator.rtt_wnd, 0, INTMAX_C(250000000));
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
	T_EXPECT(wndfilter_get(&ss.estimator.rtt_wnd) == 0);
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
 * immediately: last_probe_ns is NOT updated by the timeout path so the
 * rate-limit check does not block the fresh probe. */
T_DECLARE_CASE(test_estimator_add_timeout_discards_cycle_and_restarts_probe)
{
	struct mux_session ss = make_session();
	const intmax_t ping_timeout_ns =
		(intmax_t)ss.conf.ping_timeout * INTMAX_C(1000000000);
	const intmax_t seq[] = {
		ping_timeout_ns + 1, /* now_ns for timeout check */
		ping_timeout_ns + 1, /* sent_ns for probe start */
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
	T_EXPECT(wndfilter_get(&ss.estimator.rtt_wnd) > 0);
	/* The cycle was app-limited (sample fit inside the window): rtt_min
	 * is recorded, but bw_wnd/sample_wnd are intentionally NOT updated so
	 * a future idle stretch cannot age the high-water mark down. */
	T_EXPECT_EQ(wndfilter_get(&ss.estimator.bw_wnd), (intmax_t)0);
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

/* TRACK bidirectional: bw_wnd and sample_wnd have both expired so the next
 * valid cycle forces wnd_max_update to reset to the current (smaller) sample,
 * and bdp must follow the estimate down. */
T_DECLARE_CASE(test_estimator_track_bdp_shrinks_when_window_expires)
{
	struct mux_session ss = make_session();
	/* now is well past BW_WND_NS (600 s) so all wnd slots are considered
	 * expired and wnd_max_update resets to the current sample. */
	const intmax_t now_ns = INTMAX_C(700) * INTMAX_C(1000000000);
	/* rtt_min calibrated close to now: rtt_wnd[0].t is only 10 ms ago so
	 * the "aged >= RTT_WND_NS/4" guard fails and inflated_rounds is cleared
	 * instead of being incremented. */
	const intmax_t sent_ns = now_ns - INTMAX_C(10000000); /* 10 ms RTT */

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* Window-limited so the cycle counts as link-driving evidence; app-limited
	 * cycles intentionally hold the prior bw/sample/bdp windowed maxes. */
	ss.estimator.cycle_window_bytes = ss.estimator.sample;
	ss.estimator.phase = EST_TRACK;
	/* Seed a very large bdp; the fresh cycle should shrink it. */
	ss.estimator.bdp = 4u * 1024u * 1024u;
	/* Seed stale (expired) bw/sample windows with large values. */
	wndfilter_reset(&ss.estimator.bw_wnd, 0, (intmax_t)1e9);
	wndfilter_reset(&ss.estimator.sample_wnd, 0, (intmax_t)1e10);
	/* Seed a valid rtt_min close to now so the inflation guard is skipped. */
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000),
		INTMAX_C(10000000));

	estimator_calculate(&ss, sent_ns);

	/* bw/sample windows expired → reset to current cycle values.
	 * target = MAX(sample, bw * rtt_min); bdp is the raw result, and
	 * effective_bdp is clamped to [BDP_MIN, BDP_MAX]. */
	T_EXPECT(ss.estimator.bdp < 4u * 1024u * 1024u);
	T_EXPECT(ss.estimator.effective_bdp >= (size_t)BDP_MIN);
	T_EXPECT(ss.estimator.effective_bdp < 4u * 1024u * 1024u);
}

/* TRACK force-age: INFLATE_ROUNDS consecutive cycles with rtt_sample ≥
 * INFLATE_HI * rtt_min collapse bw_wnd/sample_wnd to the current sample,
 * driving bdp to BDP_MIN when the sample itself is small. */
T_DECLARE_CASE(test_estimator_track_force_age_collapses_bdp_after_inflate_rounds)
{
	struct mux_session ss = make_session();
	/* rtt_min aged well past RTT_WND_NS/4 (75 s). */
	const intmax_t rtt_min_t = 0;
	const double rtt_min = 0.01; /* 10 ms */
	/* Each probe: now is at 80 s so now - rtt_min_t > RTT_WND_NS/4. */
	const intmax_t now_base = INTMAX_C(80) * INTMAX_C(1000000000);
	/* rtt_sample = 100 ms; ratio = 10.0 ≥ INFLATE_HI (1.5). */
	const intmax_t rtt_sample_ns = INTMAX_C(100000000);

	/* Provide INFLATE_ROUNDS clock values; each calculate call reads one. */
	intmax_t clocks[INFLATE_ROUNDS];
	for (int i = 0; i < INFLATE_ROUNDS; i++) {
		clocks[i] = now_base + (intmax_t)i * rtt_sample_ns;
	}

	estimator_test_reset();
	set_clock_sequence(clocks, INFLATE_ROUNDS);

	ss.estimator.phase = EST_TRACK;
	ss.estimator.bdp = 4u * 1024u * 1024u; /* start large */
	wndfilter_reset(
		&ss.estimator.rtt_wnd, rtt_min_t, (intmax_t)(rtt_min * 1e9));
	/* Window-limited cycles so inflation detection sees real link-driving
	 * samples; without this the new app-limited gating skips inflation. */
	const size_t cycle_window = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;

	for (int i = 0; i < INFLATE_ROUNDS; i++) {
		const intmax_t now_ns = clocks[i];
		const intmax_t sent = now_ns - rtt_sample_ns;
		ss.estimator.ping_in_flight = true;
		ss.estimator.probe_sent_ns = sent;
		ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
		ss.estimator.cycle_window_bytes = cycle_window;
		/* Isolate the inflation path from the TRACK→STARTUP re-probe
		 * heuristic: window-limited cycles otherwise switch phase
		 * after saturated_rounds reaches 2. */
		ss.estimator.saturated_rounds = 0;
		ss.estimator.phase = EST_TRACK;
		estimator_calculate(&ss, sent);
	}

	/* After INFLATE_ROUNDS inflated cycles, force-age fires: bdp is the raw
	 * small sample; effective_bdp is floored at BDP_MIN. */
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)BDP_MIN);
	T_EXPECT_EQ(ss.estimator.inflated_rounds, (uint_least8_t)0);
}

/* TRACK hysteresis: inflate counter is cleared when ratio drops to ≤
 * INFLATE_LO, preventing a spurious force-age on isolated RTT spikes. */
T_DECLARE_CASE(test_estimator_track_inflate_counter_cleared_when_ratio_drops)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_min_t = 0;
	const double rtt_min = 0.01;
	const intmax_t now_base = INTMAX_C(80) * INTMAX_C(1000000000);
	/* Two inflated cycles followed by one normal cycle (ratio 1.0). */
	const intmax_t rtt_high_ns = INTMAX_C(100000000); /* 100 ms, ratio 10 */
	const intmax_t rtt_low_ns = INTMAX_C(10000000); /* 10 ms, ratio 1.0 */
	const intmax_t clocks[3] = {
		now_base,
		now_base + rtt_high_ns,
		now_base + 2 * rtt_high_ns + rtt_low_ns,
	};
	const intmax_t sent[3] = {
		clocks[0] - rtt_high_ns,
		clocks[1] - rtt_high_ns,
		clocks[2] - rtt_low_ns,
	};

	estimator_test_reset();
	set_clock_sequence(clocks, 3);

	ss.estimator.phase = EST_TRACK;
	ss.estimator.bdp = 4u * 1024u * 1024u;
	wndfilter_reset(
		&ss.estimator.rtt_wnd, rtt_min_t, (intmax_t)(rtt_min * 1e9));

	/* First two cycles: ratio ≥ INFLATE_HI → inflated_rounds increments. */
	for (int i = 0; i < 2; i++) {
		ss.estimator.ping_in_flight = true;
		ss.estimator.probe_sent_ns = sent[i];
		ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
		/* Window-limited so inflation detection runs (app-limited cycles
		 * intentionally skip it).  Isolate from the TRACK→STARTUP
		 * re-probe path by resetting saturated_rounds each cycle. */
		ss.estimator.cycle_window_bytes = ss.estimator.sample;
		ss.estimator.saturated_rounds = 0;
		ss.estimator.phase = EST_TRACK;
		estimator_calculate(&ss, sent[i]);
	}
	T_EXPECT_EQ(ss.estimator.inflated_rounds, (uint_least8_t)2);

	/* Third cycle: ratio ≤ INFLATE_LO → counter cleared, no force-age. */
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent[2];
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.cycle_window_bytes = ss.estimator.sample;
	ss.estimator.saturated_rounds = 0;
	ss.estimator.phase = EST_TRACK;
	estimator_calculate(&ss, sent[2]);

	T_EXPECT_EQ(ss.estimator.inflated_rounds, (uint_least8_t)0);
	/* No force-age: effective_bdp may change via normal bidirectional
	 * tracking but should not be reset to BDP_MIN solely due to force-age. */
	T_EXPECT(ss.estimator.effective_bdp >= (size_t)BDP_MIN);
}

/* TRACK inflation guard: when rtt_wnd[0] was updated too recently (less
 * than RTT_WND_NS/4 ago), the inflation check is skipped entirely and
 * inflated_rounds is kept at zero. */
T_DECLARE_CASE(test_estimator_track_inflate_skipped_when_rtt_min_uncalibrated)
{
	struct mux_session ss = make_session();
	/* rtt_min updated only 1 s ago; RTT_WND_NS/4 = 75 s, so guard fails. */
	const intmax_t now_ns = INTMAX_C(80) * INTMAX_C(1000000000);
	const intmax_t rtt_sample_ns = INTMAX_C(100000000); /* 100 ms */
	const intmax_t sent_ns = now_ns - rtt_sample_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	ss.estimator.phase = EST_TRACK;
	ss.estimator.bdp = 65536;
	/* rtt_wnd.s[0].t is 1 s before now: now - t = 1 s < RTT_WND_NS/4 = 75 s. */
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000000),
		INTMAX_C(10000000));
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* Window-limited so estimator_phase_track actually runs (app-limited
	 * cycles short-circuit before reaching the inflation guard). */
	ss.estimator.cycle_window_bytes = ss.estimator.sample;

	estimator_calculate(&ss, sent_ns);

	/* Guard failed: inflated_rounds must be 0 (cleared, not incremented). */
	T_EXPECT_EQ(ss.estimator.inflated_rounds, (uint_least8_t)0);
}

/* STARTUP phase: the RTT inflation block lives exclusively inside EST_TRACK,
 * so inflated_rounds must remain zero regardless of rtt_sample magnitude. */
T_DECLARE_CASE(test_estimator_startup_ignores_rtt_inflation)
{
	struct mux_session ss = make_session();
	/* rtt well aged and ratio >> INFLATE_HI; in STARTUP this is irrelevant. */
	const intmax_t now_ns = INTMAX_C(80) * INTMAX_C(1000000000);
	const intmax_t rtt_sample_ns = INTMAX_C(500000000); /* 500 ms */
	const intmax_t sent_ns = now_ns - rtt_sample_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	ss.estimator.phase = EST_STARTUP;
	ss.estimator.bdp = 65536;
	wndfilter_reset(&ss.estimator.rtt_wnd, 0, INTMAX_C(10000000));
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* Window-limited to keep phase in STARTUP. */
	ss.estimator.cycle_window_bytes = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;

	estimator_calculate(&ss, sent_ns);

	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_STARTUP);
	T_EXPECT_EQ(ss.estimator.inflated_rounds, (uint_least8_t)0);
}

/* STARTUP phase: after BW_FLAT_ROUNDS consecutive window-limited probes where
 * bw_sample grows by less than 25 % relative to the prior windowed maximum,
 * the phase transitions to EST_TRACK so window growth stops at the physical
 * bandwidth ceiling. */
T_DECLARE_CASE(test_estimator_startup_exits_to_track_after_bw_flat_rounds)
{
	struct mux_session ss = make_session();
	/* rtt = 10 ms; 2 frames → bw_sample ≈ 3.2 MB/s. */
	const intmax_t rtt_ns = INTMAX_C(10000000);
	const intmax_t clocks[BW_FLAT_ROUNDS] = {
		rtt_ns,
		INTMAX_C(1000000000) + rtt_ns,
		INTMAX_C(2000000000) + rtt_ns,
	};
	/* Seed bw_wnd higher than bw_sample so bw_prev_max > 0 and the flat
	 * condition (< 25 % growth) is met from the very first probe. */
	const intmax_t bw_seed = INTMAX_C(5000000); /* 5 MB/s */

	estimator_test_reset();
	set_clock_sequence(clocks, BW_FLAT_ROUNDS);

	ss.estimator.phase = EST_STARTUP;
	ss.estimator.bdp = 65536;
	wndfilter_reset(&ss.estimator.bw_wnd, 0, bw_seed);

	for (int i = 0; i < BW_FLAT_ROUNDS; i++) {
		const intmax_t sent_ns = clocks[i] - rtt_ns;
		ss.estimator.ping_in_flight = true;
		ss.estimator.probe_sent_ns = sent_ns;
		ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
		ss.estimator.cycle_window_bytes =
			2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
		estimator_calculate(&ss, sent_ns);
		if (i < BW_FLAT_ROUNDS - 1) {
			T_EXPECT_EQ(
				ss.estimator.phase,
				(enum estimator_phase)EST_STARTUP);
		}
	}

	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_TRACK);
	T_EXPECT_EQ(ss.estimator.bw_flat_rounds, (uint_least8_t)0);
}

/* STARTUP phase: when a probe's bw_sample grows by >= 25 % relative to the
 * prior windowed maximum, bw_flat_rounds is reset so the phase stays in
 * STARTUP and window growth continues. */
T_DECLARE_CASE(test_estimator_startup_flat_counter_resets_on_bw_growth)
{
	struct mux_session ss = make_session();
	const intmax_t rtt_ns = INTMAX_C(10000000); /* 10 ms */
	const intmax_t clocks[2] = {
		rtt_ns,
		INTMAX_C(1000000000) + rtt_ns,
	};
	/* Seed bw_wnd to 5 MB/s; bw_sample_1 ≈ 3.2 MB/s is below the 25 %
	 * growth threshold (5 MB/s × 5/4 = 6.25 MB/s), so the first probe
	 * increments bw_flat_rounds to 1. */
	const intmax_t bw_seed = INTMAX_C(5000000);

	estimator_test_reset();
	set_clock_sequence(clocks, 2);

	ss.estimator.phase = EST_STARTUP;
	ss.estimator.bdp = 65536;
	wndfilter_reset(&ss.estimator.bw_wnd, 0, bw_seed);

	/* Cycle 1: flat bandwidth → bw_flat_rounds increments to 1. */
	const intmax_t sent1 = clocks[0] - rtt_ns;
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent1;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.cycle_window_bytes = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	estimator_calculate(&ss, sent1);
	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_STARTUP);
	T_EXPECT_EQ(ss.estimator.bw_flat_rounds, (uint_least8_t)1);

	/* Cycle 2: 4 frames / 10 ms = 6.5 MB/s > 5 MB/s × 5/4 → growth
	 * exceeds the 25 % threshold → bw_flat_rounds resets to 0. */
	const intmax_t sent2 = clocks[1] - rtt_ns;
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent2;
	ss.estimator.sample = 4u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.cycle_window_bytes = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	estimator_calculate(&ss, sent2);
	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_STARTUP);
	T_EXPECT_EQ(ss.estimator.bw_flat_rounds, (uint_least8_t)0);
}

/* TRACK EWMA smoothing: when consecutive cycles produce different targets,
 * bdp must be smoothed by the EWMA rather than jumping instantly to the new
 * target.  After two cycles with increasing samples the result must lie
 * strictly between the first and second cycle's target values. */
T_DECLARE_CASE(test_estimator_track_bdp_smoothed_across_cycles)
{
	struct mux_session ss = make_session();
	/* rtt_min = 1 ms seeded 1 ms before now_base; rtt samples = 10 ms.
	 * Seeding rtt_wnd very close to now ensures that the inflation guard
	 * (now - rtt_wnd[0].t < RTT_WND_NS/4 = 75 s) skips force-age, so
	 * bdp_ewma.ready stays 1 between the two cycles. */
	const intmax_t rtt_ns = INTMAX_C(10000000); /* 10 ms */
	const intmax_t now_base = INTMAX_C(80) * INTMAX_C(1000000000);
	const intmax_t clocks[2] = { now_base, now_base + rtt_ns };

	estimator_test_reset();
	set_clock_sequence(clocks, 2);

	ss.estimator.phase = EST_TRACK;
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_base - INTMAX_C(1000000),
		INTMAX_C(1000000));

	/* Cycle 1: sample = 2 frames.  bdp_ewma.ready=0 so bdp is set directly
	 * to target1 = sample_max = 2 * MUX_MAX_PAYLOAD_SIZE. */
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = now_base - rtt_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* Window-limited so estimator_phase_track runs (app-limited cycles
	 * skip the EWMA update); reset saturated_rounds each cycle to keep
	 * phase in TRACK across the two iterations. */
	ss.estimator.cycle_window_bytes = ss.estimator.sample;
	ss.estimator.saturated_rounds = 0;
	estimator_calculate(&ss, now_base - rtt_ns);
	const size_t bdp1 = ss.estimator.bdp;

	/* Cycle 2: sample = 4 frames → target2 > target1.  EWMA must produce a
	 * value strictly between the two targets (not yet fully converged). */
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = now_base;
	ss.estimator.sample = 4u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	ss.estimator.cycle_window_bytes = ss.estimator.sample;
	ss.estimator.saturated_rounds = 0;
	estimator_calculate(&ss, now_base);

	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_TRACK);
	T_EXPECT(ss.estimator.bdp > bdp1);
	T_EXPECT(ss.estimator.bdp < 4u * (size_t)MUX_MAX_PAYLOAD_SIZE);
}

/* TRACK bidirectional: even when the derived target is very small,
 * effective_bdp is never allowed to fall below BDP_MIN. */
T_DECLARE_CASE(test_estimator_track_effective_bdp_floored_at_min_bdp)
{
	struct mux_session ss = make_session();
	/* Large rtt_sample makes bw_sample = sample / rtt tiny; rtt_min aged.
	 * Use now_ns > BW_WND_NS (600 s) so the stale bw/sample_wnd slots
	 * expire and wnd_max_update resets to the current (small) sample. */
	const intmax_t now_ns = INTMAX_C(700) * INTMAX_C(1000000000);
	const intmax_t rtt_sample_ns = INTMAX_C(1000000000); /* 1 s */
	const intmax_t sent_ns = now_ns - rtt_sample_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	ss.estimator.phase = EST_TRACK;
	ss.estimator.bdp = 4u * 1024u * 1024u;
	/* Expire all bw/sample windows so they reset to current sample. */
	wndfilter_reset(&ss.estimator.bw_wnd, 0, (intmax_t)1e6);
	wndfilter_reset(&ss.estimator.sample_wnd, 0, (intmax_t)1e10);
	/* rtt_min close to now: inflation guard skips; only bidirectional
	 * targeting runs. */
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000),
		INTMAX_C(1000000000));
	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* Window-limited so the TRACK bidirectional target actually runs and
	 * pushes the small computed bdp into bdp_clamped → effective_bdp
	 * floor; app-limited cycles intentionally hold the prior estimate. */
	ss.estimator.cycle_window_bytes = ss.estimator.sample;

	estimator_calculate(&ss, sent_ns);

	/* target = MAX(32768, bw_sample * rtt_min) which is tiny; bdp is the raw
	 * result while effective_bdp is floored at BDP_MIN. */
	T_EXPECT_EQ(ss.estimator.effective_bdp, (size_t)BDP_MIN);
}

/* TRACK app-limited: a cycle that did not drive the link to capacity must
 * leave bw_wnd, sample_wnd, bdp_wnd, and effective_bdp untouched.  This is
 * the throughput-first guarantee for long idle stretches: an established
 * high-water mark survives even when BW_WND_NS / BDP_WND_NS would otherwise
 * age it out, so the window does not shrink and starve a future burst. */
T_DECLARE_CASE(test_estimator_track_app_limited_preserves_windowed_max)
{
	struct mux_session ss = make_session();
	/* now is well past BDP_WND_NS (7200 s) so any unfrozen wndfilter would
	 * age the seeded peaks out and reset to the current (tiny) values. */
	const intmax_t now_ns = INTMAX_C(8000) * INTMAX_C(1000000000);
	const intmax_t sent_ns = now_ns - INTMAX_C(10000000); /* 10 ms RTT */
	const intmax_t bw_peak = INTMAX_C(100000000); /* 100 MB/s */
	const size_t bdp_peak = 4u * 1024u * 1024u; /* 4 MiB */

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);

	ss.estimator.phase = EST_TRACK;
	/* Seed historical peaks at t=0; they must survive the app-limited cycle. */
	wndfilter_reset(&ss.estimator.bw_wnd, 0, bw_peak);
	wndfilter_reset(&ss.estimator.sample_wnd, 0, (intmax_t)bdp_peak);
	wndfilter_reset(&ss.estimator.bdp_wnd, 0, (intmax_t)bdp_peak);
	ss.estimator.effective_bdp = bdp_peak;
	/* rtt_min close to now so the inflation guard is skipped regardless. */
	wndfilter_reset(
		&ss.estimator.rtt_wnd, now_ns - INTMAX_C(1000000),
		INTMAX_C(10000000));

	ss.estimator.ping_in_flight = true;
	ss.estimator.probe_sent_ns = sent_ns;
	ss.estimator.sample = 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* Large window: sample + payload < cycle_window → app-limited. */
	ss.estimator.cycle_window_bytes =
		(size_t)ss.session_window * MUX_WINDOW_UNIT;

	estimator_calculate(&ss, sent_ns);

	/* Peaks held; effective_bdp preserved.  RTT min still updates (it is
	 * valid regardless of demand) so rtt_wnd may change. */
	T_EXPECT_EQ(wndfilter_get(&ss.estimator.bw_wnd), bw_peak);
	T_EXPECT_EQ(
		wndfilter_get(&ss.estimator.sample_wnd), (intmax_t)bdp_peak);
	T_EXPECT_EQ(wndfilter_get(&ss.estimator.bdp_wnd), (intmax_t)bdp_peak);
	T_EXPECT_EQ(ss.estimator.effective_bdp, bdp_peak);
	T_EXPECT_EQ(ss.estimator.phase, (enum estimator_phase)EST_TRACK);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_estimator_seed_clamps_effective_bdp_to_limit);
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
	T_RUN_CASE(t, test_estimator_track_bdp_shrinks_when_window_expires);
	T_RUN_CASE(
		t,
		test_estimator_track_force_age_collapses_bdp_after_inflate_rounds);
	T_RUN_CASE(
		t,
		test_estimator_track_inflate_counter_cleared_when_ratio_drops);
	T_RUN_CASE(
		t,
		test_estimator_track_inflate_skipped_when_rtt_min_uncalibrated);
	T_RUN_CASE(t, test_estimator_startup_ignores_rtt_inflation);
	T_RUN_CASE(
		t, test_estimator_startup_exits_to_track_after_bw_flat_rounds);
	T_RUN_CASE(t, test_estimator_startup_flat_counter_resets_on_bw_growth);
	T_RUN_CASE(t, test_estimator_track_bdp_smoothed_across_cycles);
	T_RUN_CASE(t, test_estimator_track_app_limited_preserves_windowed_max);
	T_RUN_CASE(t, test_estimator_track_effective_bdp_floored_at_min_bdp);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
