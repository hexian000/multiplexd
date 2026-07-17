/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* estimator_test.c - white-box tests for the BDP/RTT estimator in estimator.c.
 * estimator.c is #included; clock_monotonic_ns redirected to a scripted mock;
 * session_send_oob is the only other mocked collaborator; no siblings linked. */

#include "mux/estimator.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"

#include "algo/wndfilter.h"
#include "binary/serialize.h"

/* Pre-include clock.h so its guard blocks the later clock_monotonic_ns-mocked
 * inclusion pulled in by estimator.c below. */
#include "os/clock.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int_fast64_t estimator_test_clock_monotonic_ns(void);

#define clock_monotonic_ns estimator_test_clock_monotonic_ns
#include "mux/estimator.c"
#undef clock_monotonic_ns

/* mock - scripted monotonic clock, session_send_oob spy, reset helper */

enum {
	CLOCK_SEQ_MAX = 8,
	OOB_PAYLOAD_MAX = 16,
};

static int_fast64_t g_clock_seq[CLOCK_SEQ_MAX];
static size_t g_clock_len;
static size_t g_clock_pos;
static bool g_send_oob_ok;
static int g_send_oob_calls;
static uint_fast8_t g_last_oob_extra;
static unsigned char g_last_oob_payload[OOB_PAYLOAD_MAX];
static size_t g_last_oob_payload_len;

static void estimator_test_reset(void)
{
	g_clock_len = 0;
	g_clock_pos = 0;
	g_send_oob_ok = true;
	g_send_oob_calls = 0;
	g_last_oob_extra = 0;
	memset(g_last_oob_payload, 0, sizeof(g_last_oob_payload));
	g_last_oob_payload_len = 0;
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
	g_send_oob_calls++;
	g_last_oob_extra = extra;
	g_last_oob_payload_len = payload_len;
	if (payload_len <= sizeof(g_last_oob_payload)) {
		memcpy(g_last_oob_payload, payload, payload_len);
	}
	return g_send_oob_ok;
}

static struct mux_session make_session(void)
{
	struct mux_session ss = {
		.auto_stream_window = true,
		.auto_session_window = true,
		.session_window = 4,
		.stream_window = 4,
		.tag = "[test]:",
		.conf.timeout = 600,
	};
	return ss;
}

/* regression - targeted cases for one estimator behavior each */

T_DECLARE_CASE(test_estimator_init_seeds_effective_bdp)
{
	struct mux_session ss = make_session();

	estimator_init(&ss, (size_t)WNDSIZE_MAX);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)WNDSIZE_MAX);
	T_EXPECT_EQ(ss.estimator.tx.effective_bdp, (size_t)WNDSIZE_MAX);
	/* A seed of 0 is clamped to WNDSIZE_MIN: effective_bdp == 0 is an
	 * absorbing fixed point for STARTUP's multiplicative growth. */
	estimator_init(&ss, 0);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)WNDSIZE_MIN);
	T_EXPECT_EQ(ss.estimator.tx.effective_bdp, (size_t)WNDSIZE_MIN);
}

T_DECLARE_CASE(test_estimator_init_resets_all_state)
{
	struct mux_session ss = make_session();

	/* Seed every field to confirm estimator_init zeros them all. */
	struct estimator_dir_ctx *const dirs[] = {
		&ss.estimator.rx,
		&ss.estimator.tx,
	};
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		dirs[i]->effective_bdp = 65536;
		wndfilter_reset(&dirs[i]->bw_wnd, 0, INT64_C(50000000));
		dirs[i]->sample = 30;
		dirs[i]->bdp = 20000;
		dirs[i]->phase = ESTIMATOR_TRACK;
		dirs[i]->stable_rounds = 7;
	}
	wndfilter_reset(&ss.estimator.rtt_wnd, 0, INT64_C(1000000000));
	ss.estimator.rtt = INT64_C(5000000);
	ss.estimator.last_probe_ns = 40;
	ss.estimator.ping_in_flight = true;

	/* Seed above WNDSIZE_MIN (65536) so estimator_init's clamp is a no-op and
	 * the reset of effective_bdp to the seed is observable. */
	estimator_init(&ss, 131072);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (int_fast64_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rtt, (int_fast64_t)0);
	T_EXPECT(wndfilter_get(&ss.estimator.rtt_wnd) == 0);
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		T_EXPECT_EQ(dirs[i]->sample, (size_t)0);
		T_EXPECT_EQ(dirs[i]->bdp, (size_t)0);
		T_EXPECT_EQ(dirs[i]->effective_bdp, (size_t)131072);
		T_EXPECT(wndfilter_get(&dirs[i]->bw_wnd) == 0);
		T_EXPECT_EQ(dirs[i]->phase, ESTIMATOR_STARTUP);
		T_EXPECT_EQ(dirs[i]->stable_rounds, (size_t)0);
	}
}

/* estimator_suspend clears only in-flight probe/sample state; learned
 * bw/RTT filters, effective_bdp, and phase must survive. */
T_DECLARE_CASE(test_estimator_suspend_clears_probe_preserves_learned)
{
	struct mux_session ss = make_session();

	ss.estimator.rx.effective_bdp = 65536;
	ss.estimator.tx.effective_bdp = 131072;
	ss.estimator.rx.phase = ESTIMATOR_TRACK;
	ss.estimator.rx.stable_rounds = 7;
	wndfilter_reset(&ss.estimator.rx.bw_wnd, 0, INT64_C(50000000));
	wndfilter_reset(&ss.estimator.rtt_wnd, 0, INT64_C(1000000000));
	ss.estimator.ping_in_flight = true;
	ss.estimator.rx.sample = 12345;
	ss.estimator.tx.sample = 6789;
	ss.estimator.last_probe_ns = 999;

	estimator_suspend(&ss);

	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.tx.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)65536);
	T_EXPECT_EQ(ss.estimator.tx.effective_bdp, (size_t)131072);
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(ss.estimator.rx.stable_rounds, (size_t)7);
	T_EXPECT(wndfilter_get(&ss.estimator.rx.bw_wnd) == 50000000);
	T_EXPECT(wndfilter_get(&ss.estimator.rtt_wnd) == 1000000000);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (int_fast64_t)999);
}

T_DECLARE_CASE(test_estimator_add_accumulates_sample_while_ping_in_flight)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = INT64_C(1000000000);

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 0;
	ss.estimator.rx.sample = 15;

	estimator_add(&ss, 20);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)35);
	T_EXPECT_EQ(g_send_oob_calls, 0);
	T_EXPECT(ss.estimator.ping_in_flight);
}

T_DECLARE_CASE(test_estimator_add_starts_cycle_after_rate_limit)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 9;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	/* TRACK enforces the rate limit; the window has just elapsed.  Both
	 * directions must be in TRACK for the 1 s floor to apply. */
	ss.estimator.rx.phase = ESTIMATOR_TRACK;
	ss.estimator.tx.phase = ESTIMATOR_TRACK;
	ss.estimator.last_probe_ns = 1;

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_oob_calls, 1);
	T_EXPECT_EQ(g_last_oob_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT_EQ(g_last_oob_payload_len, (size_t)MUX_PING_PAYLOAD_SIZE);
	/* The PING payload carries the send timestamp back for RTT correlation:
	 * session_recv_pong reads it and estimator_calculate matches it against
	 * last_probe_ns. */
	T_EXPECT_EQ(read_uint64(g_last_oob_payload), (uint_fast64_t)now);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)40000);
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
	/* Both directions in TRACK so the 1 s floor (not the 100 ms STARTUP
	 * floor) applies. */
	ss.estimator.rx.phase = ESTIMATOR_TRACK;
	ss.estimator.tx.phase = ESTIMATOR_TRACK;
	ss.estimator.last_probe_ns = now - (MUX_PING_RATE_LIMIT_NS / 2);

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_oob_calls, 0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
}

/* STARTUP enforces the faster 100 ms floor: a probe within it blocks a new
 * cycle. */
T_DECLARE_CASE(test_estimator_add_startup_enforces_rate_limit)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 5;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.rx.phase = ESTIMATOR_STARTUP;
	ss.estimator.last_probe_ns = now - (MUX_PING_STARTUP_INTERVAL_NS / 2);

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_oob_calls, 0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
}

/* STARTUP probes once the 100 ms floor has elapsed, even though <1 s has passed
 * (TRACK would still rate-limit here). */
T_DECLARE_CASE(test_estimator_add_startup_starts_cycle_after_floor)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 5;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.rx.phase = ESTIMATOR_STARTUP;
	/* 200 ms ago: past the 100 ms STARTUP floor but within the 1 s TRACK
	 * floor. */
	ss.estimator.last_probe_ns = now - 2 * MUX_PING_STARTUP_INTERVAL_NS;

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_oob_calls, 1);
	T_EXPECT_EQ(g_last_oob_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT_EQ(g_last_oob_payload_len, (size_t)MUX_PING_PAYLOAD_SIZE);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)40000);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
	T_EXPECT(ss.estimator.ping_in_flight);
}

T_DECLARE_CASE(test_estimator_add_acked_accumulates_while_ping_in_flight)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = INT64_C(1000000000);

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 0;
	ss.estimator.tx.sample = 15;

	estimator_add_acked(&ss, 20);
	T_EXPECT_EQ(ss.estimator.tx.sample, (size_t)35);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(g_send_oob_calls, 0);
	T_EXPECT(ss.estimator.ping_in_flight);
}

T_DECLARE_CASE(test_estimator_add_acked_starts_cycle_after_rate_limit)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 9;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	/* TRACK enforces the rate limit; the window has just elapsed.  Both
	 * directions must be in TRACK for the 1 s floor to apply. */
	ss.estimator.rx.phase = ESTIMATOR_TRACK;
	ss.estimator.tx.phase = ESTIMATOR_TRACK;
	ss.estimator.last_probe_ns = 1;

	estimator_add_acked(&ss, 40000);
	T_EXPECT_EQ(g_send_oob_calls, 1);
	T_EXPECT_EQ(g_last_oob_extra, (uint_fast8_t)MUX_CTRL_PING);
	T_EXPECT_EQ(g_last_oob_payload_len, (size_t)MUX_PING_PAYLOAD_SIZE);
	T_EXPECT_EQ(ss.estimator.tx.sample, (size_t)40000);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
	T_EXPECT(ss.estimator.ping_in_flight);
}

/* A failed OOB send aborts the probe cycle without side effects: send_ping
 * returns before stamping last_probe_ns/ping_in_flight, so the estimator stays
 * idle, the sample is not overwritten, and the next estimator_add retries. */
T_DECLARE_CASE(test_estimator_add_send_ping_failure_preserves_state)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = MUX_PING_RATE_LIMIT_NS + 9;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	g_send_oob_ok = false;
	/* Not rate-limited (last_probe_ns long past) and no ping in flight, so the
	 * cycle reaches send_ping. */
	ss.estimator.last_probe_ns = 1;
	ss.estimator.rx.sample = 15;

	estimator_add(&ss, 40000);
	T_EXPECT_EQ(g_send_oob_calls, 1);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, (int_fast64_t)1);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)15);
}

T_DECLARE_CASE(test_estimator_calculate_discards_stale_timestamp)
{
	struct mux_session ss = make_session();

	estimator_test_reset();
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 100;
	ss.estimator.rx.sample = 45000;

	estimator_calculate(&ss, 99);
	T_EXPECT(ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)45000);
}

T_DECLARE_CASE(test_estimator_calculate_invalid_rtt_clears_cycle)
{
	struct mux_session ss = make_session();
	const int_fast64_t now = 100;

	estimator_test_reset();
	set_clock_sequence(&now, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 100;
	ss.estimator.rx.sample = 50000;

	estimator_calculate(&ss, 100);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now);
}

/* A pathologically tiny RTT (1 ns; never happens on a real link, but nothing
 * rejects it) with an ordinary sample drives the raw bw_sample far past
 * INT_FAST64_MAX / WND_FEEDBACK_FLOOR_NS, the bound window_size() needs to
 * multiply bw_max by WND_FEEDBACK_FLOOR_NS without overflowing
 * int_fast64_t. Checked directly against bw_wnd rather than the final
 * window_size(): window_size()'s own clamp to WNDSIZE_MAX rescues an
 * out-of-range floor either way (correctly saturated or UB-wrapped), so
 * the final value alone can't distinguish a real fix from silent
 * wraparound -- unlike bw_max, which is exactly what calc_dir clamps. */
T_DECLARE_CASE(test_estimator_calculate_tiny_rtt_does_not_overflow_window)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = 1;
	const int_fast64_t now_ns = INT64_C(15) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	/* 10 MB in a single (1 ns!) cycle -> bw_sample_raw = 1e7 * 1e9 / 1 =
	 * 1e16, far past INT_FAST64_MAX / WND_FEEDBACK_FLOOR_NS (~1.5e13). */
	ss.estimator.rx.sample = 10000000u;

	estimator_calculate(&ss, sent_ns);

	const int_fast64_t bw_max = wndfilter_get(&ss.estimator.rx.bw_wnd);
	T_EXPECT(bw_max <= INT_FAST64_MAX / WND_FEEDBACK_FLOOR_NS);

	const size_t window = estimator_rx_window_size(&ss.estimator);
	T_EXPECT(window >= (size_t)WNDSIZE_MIN);
	T_EXPECT(window <= (size_t)WNDSIZE_MAX);
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
	ss.estimator.rx.sample = 2u * (size_t)MUX_MAX_RECORD; /* 32768 */
	/* window_limited: 32768 > 40000 × 2/3 = 26666 → true. */
	ss.estimator.rx.effective_bdp = 40000;
	T_EXPECT_EQ(ss.estimator.tx.sample, (size_t)0);

	estimator_calculate(&ss, sent_ns);
	/* window_limited = true → stays STARTUP, effective_bdp = 40000 × 3 = 120000. */
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)120000);
	T_EXPECT_EQ(estimator_rx_window_size(&ss.estimator), (size_t)120000);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.last_probe_ns, now_ns);
	T_EXPECT(wndfilter_get(&ss.estimator.rx.bw_wnd) > 0);
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.rx.stable_rounds, (size_t)0);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.tx.sample, (size_t)0);
	/* The idle tx direction is untouched: no bw sample, no growth. */
	T_EXPECT_EQ(ss.estimator.tx.effective_bdp, (size_t)0);
	T_EXPECT(wndfilter_get(&ss.estimator.tx.bw_wnd) == 0);
}

/* Mirror of test_estimator_calculate_updates_effective_bdp driven by the tx
 * sample only: a pure sender's ack-clock must grow tx effective_bdp via fast
 * startup while the idle rx direction stays untouched. */
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
	ss.estimator.tx.sample = 2u * (size_t)MUX_MAX_RECORD; /* 32768 */
	/* window_limited: demand=32768 > 40000 × 2/3 = 26666 → true. */
	ss.estimator.tx.effective_bdp = 40000;
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);

	estimator_calculate(&ss, sent_ns);
	T_EXPECT_EQ(ss.estimator.tx.effective_bdp, (size_t)120000);
	T_EXPECT_EQ(estimator_tx_window_size(&ss.estimator), (size_t)120000);
	T_EXPECT(wndfilter_get(&ss.estimator.tx.bw_wnd) > 0);
	T_EXPECT_EQ(ss.estimator.tx.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.tx.stable_rounds, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.tx.sample, (size_t)0);
	/* The idle rx direction is untouched: no bw sample, no growth. */
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)0);
	T_EXPECT(wndfilter_get(&ss.estimator.rx.bw_wnd) == 0);
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
		&ss.estimator.rx.bw_wnd, now_ns - INT64_C(1000000), bw_high);
	/* One short of the threshold: this cycle pushes it over. */
	ss.estimator.rx.stable_rounds = STARTUP_STABLE_ROUNDS - 1;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.rx.sample = (size_t)MUX_MAX_RECORD;
	/* effective_bdp large enough that the sample is not window-limited:
	 * 16384 ≤ 10 MB × 2/3 = 6 666 666 → window_limited = false. */
	const size_t bdp_bytes =
		(size_t)((double)bw_high * (double)rtt_ns / 1e9);
	ss.estimator.rx.effective_bdp = bdp_bytes * 2;

	estimator_calculate(&ss, sent_ns);

	/* bw_wnd reflects its seeded peak (app-limited bw_sample is below it). */
	T_EXPECT_EQ(wndfilter_get(&ss.estimator.rx.bw_wnd), bw_high);
	/* stable_rounds reaches the threshold → exit to TRACK; effective_bdp
	 * preserved. */
	T_EXPECT_EQ(
		ss.estimator.rx.stable_rounds, (size_t)STARTUP_STABLE_ROUNDS);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, bdp_bytes * 2);
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_TRACK);
}

/* window_size raises its floor above WNDSIZE_MIN to bw_max × WND_FEEDBACK_FLOOR_NS
 * when the bandwidth-derived floor lands strictly between WNDSIZE_MIN and
 * WNDSIZE_MAX: 500 MB/s × 0.6 ms = 300000 B, so a smaller effective_bdp is
 * floored up to it. */
T_DECLARE_CASE(test_estimator_window_size_raises_floor_from_bandwidth)
{
	struct mux_session ss = make_session();
	/* bw_max = 500 MB/s → bw_floor = 500e6 × 600000 / 1e9 = 300000 B,
	 * above WNDSIZE_MIN (65536) and below WNDSIZE_MAX. */
	const int_fast64_t bw_max = INT64_C(500000000);

	wndfilter_reset(&ss.estimator.rx.bw_wnd, 0, bw_max);
	/* effective_bdp below the derived floor, so the floor governs the result. */
	ss.estimator.rx.effective_bdp = (size_t)WNDSIZE_MIN;

	T_EXPECT_EQ(estimator_rx_window_size(&ss.estimator), (size_t)300000);
}

/* estimator_init and estimator_calculate both end with session_publish_estimate,
 * mirroring rtt/rx.bdp/tx.bdp into the relaxed-atomic _pub_* gauges /stats reads.
 * The mirrors are poisoned before each call so a dropped publish is caught. */
T_DECLARE_CASE(test_estimator_publishes_estimate_mirrors)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now_ns = INT64_C(15) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;

	/* estimator_init publishes the freshly-zeroed gauges over the poison. */
	PUB_STORE(ss._pub_rtt, INT64_C(123));
	PUB_STORE(ss._pub_bdp_rx, (size_t)456);
	PUB_STORE(ss._pub_bdp_tx, (size_t)789);
	estimator_init(&ss, 0);
	T_EXPECT_EQ(PUB_LOAD(ss._pub_rtt), (int_fast64_t)0);
	T_EXPECT_EQ(PUB_LOAD(ss._pub_bdp_rx), (size_t)0);
	T_EXPECT_EQ(PUB_LOAD(ss._pub_bdp_tx), (size_t)0);

	/* A completed cycle publishes the newly computed rtt and BDP. */
	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.rx.sample = 2u * (size_t)MUX_MAX_RECORD; /* 32768 */
	ss.estimator.rx.effective_bdp = 40000;

	PUB_STORE(ss._pub_rtt, INT64_C(-1));
	PUB_STORE(ss._pub_bdp_rx, (size_t)999999);
	PUB_STORE(ss._pub_bdp_tx, (size_t)999999);
	estimator_calculate(&ss, sent_ns);

	T_EXPECT(ss.estimator.rx.bdp > 0);
	T_EXPECT_EQ(PUB_LOAD(ss._pub_rtt), rtt_ns);
	T_EXPECT_EQ(PUB_LOAD(ss._pub_bdp_rx), ss.estimator.rx.bdp);
	T_EXPECT_EQ(PUB_LOAD(ss._pub_bdp_tx), ss.estimator.tx.bdp);
}

/* estimator_rx_window_size floors the result at WNDSIZE_MIN even when
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
	ss.estimator.rx.sample = 2u * (size_t)MUX_MAX_RECORD; /* 32768 */
	/* window_limited: 32768 > 10000 × 2/3 = 6666 → true. */
	ss.estimator.rx.effective_bdp = 10000;

	estimator_calculate(&ss, sent_ns);

	/* window_limited → effective_bdp = 10000 × 3 = 30000 < WNDSIZE_MIN;
	 * estimator_rx_window_size floors to WNDSIZE_MIN. */
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)30000);
	T_EXPECT_EQ(estimator_rx_window_size(&ss.estimator), WNDSIZE_MIN);
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
	ss.estimator.rx.effective_bdp = 2u * (size_t)WNDSIZE_MIN;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = 100;
	/* sample = 0: no BW sample is fed to the filters this cycle. */
	ss.estimator.rx.sample = 0;

	estimator_calculate(&ss, 100);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, 2u * (size_t)WNDSIZE_MIN);
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
		&ss.estimator.rx.bw_wnd, now_ns - INT64_C(1000000), bw_val);
	ss.estimator.rx.stable_rounds = 3;

	/* bdp = 100e6 × 10e-3 = 1 MB.  effective_bdp at 5 MB so that
	 * sample = 16384 ≤ 5 MB × 2/3 = 3 333 333 → window_limited = false. */
	const size_t bdp_bytes =
		(size_t)((double)bw_val * (double)rtt_ns / 1e9);
	ss.estimator.rx.effective_bdp = bdp_bytes * 5;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.rx.sample = (size_t)MUX_MAX_RECORD;

	estimator_calculate(&ss, sent_ns);

	/* Not window-limited: effective_bdp unchanged, stable_rounds advanced. */
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, bdp_bytes * 5);
	T_EXPECT_EQ(ss.estimator.rx.stable_rounds, (size_t)4);
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_STARTUP);
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
		&ss.estimator.rx.bw_wnd, now_ns - INT64_C(1000000), bw_val);
	ss.estimator.rx.stable_rounds = 5;

	/* window_limited: 32768 > 30000 × 2/3 = 20000 → true. */
	ss.estimator.rx.effective_bdp = 30000;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.rx.sample = 2u * (size_t)MUX_MAX_RECORD; /* 32768 */

	estimator_calculate(&ss, sent_ns);

	/* window_limited → effective_bdp tripled; stable_rounds reset; stays STARTUP. */
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)90000);
	T_EXPECT_EQ(ss.estimator.rx.stable_rounds, (size_t)0);
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_STARTUP);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* TRACK stays TRACK when the cycle's bdp does not exceed effective_bdp
 * (phase_track's only condition is `effective_bdp != 0 && bdp > effective_bdp`).
 * effective_bdp is seeded above the computed bdp so the guard is exercised as a
 * genuine bdp <= effective_bdp -- not short-circuited by an unseeded
 * effective_bdp == 0; a stay-TRACK cycle then resets effective_bdp to bdp×1.25. */
T_DECLARE_CASE(test_estimator_track_bdp_within_effective_stays_track)
{
	struct mux_session ss = make_session();
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const int_fast64_t now_ns = INT64_C(300) * INT64_C(1000000000) + rtt_ns;
	const int_fast64_t sent_ns = now_ns - rtt_ns;
	/* Seed bw_wnd with a value larger than the sample will produce
	 * (sample × 1e9 / rtt_ns ≈ 1.64 MB/s) so the peak is predictable. */
	const int_fast64_t bw_val = INT64_C(2000000000); /* 2 GB/s */
	const int_fast64_t seed_ts = now_ns - INT64_C(1000000);
	/* bw_max = 2 GB/s, rtt_min_ns = 10 ms → bdp = 2e9 × 1e7 / 1e9 = 20 MB. */
	const size_t bdp_bytes =
		(size_t)((double)bw_val * (double)rtt_ns / 1e9);

	estimator_test_reset();
	set_clock_sequence(&now_ns, 1);
	wndfilter_reset(&ss.estimator.rx.bw_wnd, seed_ts, bw_val);
	ss.estimator.rx.phase = ESTIMATOR_TRACK;
	/* Above bdp, so bdp > effective_bdp is genuinely false (stays TRACK). */
	ss.estimator.rx.effective_bdp = bdp_bytes + bdp_bytes / 4;

	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent_ns;
	ss.estimator.rx.sample = (size_t)MUX_MAX_RECORD;

	estimator_calculate(&ss, sent_ns);

	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, bdp_bytes + bdp_bytes / 4);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* TRACK→STARTUP when the cycle's bdp exceeds effective_bdp: the first cycle
 * seeds a small effective_bdp; the second cycle's much larger sample drives
 * bdp past bdp×1.25 of it.  The first RTT is kept small so the windowed-minimum
 * RTT stays low, bounding the computed bdp. */
T_DECLARE_CASE(test_estimator_track_bdp_exceeds_effective_returns_to_startup)
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
	ss.estimator.rx.phase = ESTIMATOR_TRACK;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent1_ns;
	ss.estimator.rx.sample = 1000u;
	set_clock_sequence(&now1_ns, 1);
	estimator_calculate(&ss, sent1_ns);
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_TRACK);
	T_EXPECT(ss.estimator.rx.effective_bdp > 0);

	/* Cycle 2: sample=1000× → bw_sample beats cycle-1 peak, so the new bdp
	 * exceeds cycle-1's effective_bdp (bdp1 × 1.25) → phase returns to STARTUP. */
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent2_ns;
	ss.estimator.rx.sample = 1000u * (size_t)MUX_MAX_RECORD;
	set_clock_sequence(&now2_ns, 1);
	estimator_calculate(&ss, sent2_ns);

	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.rx.stable_rounds, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
}

/* Mirror of test_estimator_track_bdp_exceeds_effective_returns_to_startup
 * for the tx direction: ack-clock alone must trigger TRACK→STARTUP
 * while the idle rx direction stays untouched. */
T_DECLARE_CASE(test_estimator_track_ack_bdp_exceeds_effective_returns_to_startup)
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
	ss.estimator.tx.phase = ESTIMATOR_TRACK;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent1_ns;
	ss.estimator.tx.sample = 1000u;
	set_clock_sequence(&now1_ns, 1);
	estimator_calculate(&ss, sent1_ns);
	T_EXPECT_EQ(ss.estimator.tx.phase, ESTIMATOR_TRACK);
	T_EXPECT(ss.estimator.tx.effective_bdp > 0);

	/* Cycle 2: tx sample=1000× → bw_sample beats cycle-1 peak;
	 * demand > bdp × 1.25 → tx phase returns to STARTUP. */
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent2_ns;
	ss.estimator.tx.sample = 1000u * (size_t)MUX_MAX_RECORD;
	set_clock_sequence(&now2_ns, 1);
	estimator_calculate(&ss, sent2_ns);

	T_EXPECT_EQ(ss.estimator.tx.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.tx.stable_rounds, (size_t)0);
	T_EXPECT(!ss.estimator.ping_in_flight);
	T_EXPECT_EQ(ss.estimator.rx.sample, (size_t)0);
	T_EXPECT_EQ(ss.estimator.tx.sample, (size_t)0);
	/* The idle rx direction never left its initial state. */
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_STARTUP);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)0);
}

/* Asymmetric cycle: rx window-limited (×3 fast-startup), tx app-limited
 * (advances stable_rounds only) — growth is per-direction with no
 * MAX-coupling. */
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
	ss.estimator.rx.sample = 2u * (size_t)MUX_MAX_RECORD;
	ss.estimator.rx.effective_bdp = 40000;
	/* tx app-limited: 1000 ≤ 40000 × 2/3. */
	ss.estimator.tx.sample = 1000u;
	ss.estimator.tx.effective_bdp = 40000;

	estimator_calculate(&ss, sent_ns);

	/* rx: fast-startup tripled the window and reset stable_rounds. */
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, (size_t)120000);
	T_EXPECT_EQ(ss.estimator.rx.stable_rounds, (size_t)0);
	/* tx: unchanged window, headroom round counted. */
	T_EXPECT_EQ(ss.estimator.tx.effective_bdp, (size_t)40000);
	T_EXPECT_EQ(ss.estimator.tx.stable_rounds, (size_t)1);
	/* Both bandwidth filters got their own samples. */
	T_EXPECT(
		wndfilter_get(&ss.estimator.rx.bw_wnd) >
		wndfilter_get(&ss.estimator.tx.bw_wnd));
	T_EXPECT(wndfilter_get(&ss.estimator.tx.bw_wnd) > 0);
}

/* Regression: a transient RTT spike inflates d->sample (no probe timeout) but
 * not the per-RTT load, so window, BDP and phase must stay put while only the
 * raw RTT reflects the spike. */
T_DECLARE_CASE(test_estimator_rtt_spike_does_not_inflate_window)
{
	struct mux_session ss = make_session();
	/* Steady 16 MB/s link, 10 ms RTT → bdp = 160 000 B. */
	const int_fast64_t bw = INT64_C(16000000);
	const int_fast64_t rtt_ns = INT64_C(10000000); /* 10 ms */
	const size_t bdp_bytes = (size_t)((double)bw * (double)rtt_ns / 1e9);

	estimator_test_reset();
	ss.estimator.rx.phase = ESTIMATOR_TRACK;

	/* Cycle 1: a normal cycle establishes bw_max, the min-RTT and the
	 * TRACK window (bdp × 1.25). */
	const int_fast64_t sent1_ns = INT64_C(1000000000);
	const int_fast64_t now1_ns = sent1_ns + rtt_ns;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent1_ns;
	ss.estimator.rx.sample = bdp_bytes; /* 1 BDP per RTT */
	set_clock_sequence(&now1_ns, 1);
	estimator_calculate(&ss, sent1_ns);

	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(ss.estimator.rx.bdp, bdp_bytes);
	const size_t window = bdp_bytes + bdp_bytes / 4;
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, window);

	/* Cycle 2: 2.58 s RTT spike — sample = bw × spike >> window.
	 * Pre-fix: raw count tripped TRACK→STARTUP.  This verifies normalized
	 * demand and d->bdp stay unchanged. */
	const int_fast64_t spike_ns = INT64_C(2580000000); /* 2.58 s */
	const int_fast64_t sent2_ns = now1_ns + INT64_C(1000000000);
	const int_fast64_t now2_ns = sent2_ns + spike_ns;
	ss.estimator.ping_in_flight = true;
	ss.estimator.last_probe_ns = sent2_ns;
	ss.estimator.rx.sample = (size_t)((double)bw * (double)spike_ns / 1e9);
	set_clock_sequence(&now2_ns, 1);
	estimator_calculate(&ss, sent2_ns);

	/* Window, BDP and phase are all unmoved; only the raw RTT reflects the
	 * spike. */
	T_EXPECT_EQ(ss.estimator.rx.phase, ESTIMATOR_TRACK);
	T_EXPECT_EQ(ss.estimator.rx.bdp, bdp_bytes);
	T_EXPECT_EQ(ss.estimator.rx.effective_bdp, window);
	T_EXPECT_EQ(estimator_rx_window_size(&ss.estimator), window);
	T_EXPECT_EQ(ss.estimator.rtt, spike_ns);
}

static const struct testing_suite suite[] = {
	T_CASE(test_estimator_init_seeds_effective_bdp),
	T_CASE(test_estimator_init_resets_all_state),
	T_CASE(test_estimator_suspend_clears_probe_preserves_learned),
	T_CASE(test_estimator_add_accumulates_sample_while_ping_in_flight),
	T_CASE(test_estimator_add_starts_cycle_after_rate_limit),
	T_CASE(test_estimator_add_track_enforces_rate_limit),
	T_CASE(test_estimator_add_startup_enforces_rate_limit),
	T_CASE(test_estimator_add_startup_starts_cycle_after_floor),
	T_CASE(test_estimator_add_acked_accumulates_while_ping_in_flight),
	T_CASE(test_estimator_add_acked_starts_cycle_after_rate_limit),
	T_CASE(test_estimator_add_send_ping_failure_preserves_state),
	T_CASE(test_estimator_calculate_discards_stale_timestamp),
	T_CASE(test_estimator_calculate_invalid_rtt_clears_cycle),
	T_CASE(test_estimator_calculate_tiny_rtt_does_not_overflow_window),
	T_CASE(test_estimator_calculate_updates_effective_bdp),
	T_CASE(test_estimator_calculate_ack_sample_drives_tx),
	T_CASE(test_estimator_startup_stable_rounds_exit_to_track),
	T_CASE(test_estimator_window_size_raises_floor_from_bandwidth),
	T_CASE(test_estimator_publishes_estimate_mirrors),
	T_CASE(test_estimator_calculate_effective_bdp_floored_at_min),
	T_CASE(test_estimator_calculate_invalid_cycle_preserves_effective_bdp),
	T_CASE(test_estimator_startup_app_limited_increments_stable_rounds),
	T_CASE(test_estimator_startup_window_limited_resets_stable_rounds),
	T_CASE(test_estimator_track_bdp_within_effective_stays_track),
	T_CASE(test_estimator_track_bdp_exceeds_effective_returns_to_startup),
	T_CASE(test_estimator_track_ack_bdp_exceeds_effective_returns_to_startup),
	T_CASE(test_estimator_asymmetric_samples_grow_independently),
	T_CASE(test_estimator_rtt_spike_does_not_inflate_window),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
