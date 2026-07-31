/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/send.h"
#include "mux/session.h"

#include "algo/wndfilter.h"
#include "binary/serialize.h"
#include "meta/minmax.h"
#include "os/clock.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* WINDOW_UPDATE encodes grant as uint16 in MUX_WINDOW_UNIT units. */
#define WNDSIZE_MAX ((size_t)UINT16_MAX * MUX_WINDOW_UNIT)
#define WNDSIZE_MIN ((size_t)MUX_INITIAL_SEND_WINDOW)

/* Minimum per-window feedback latency floor.  On low-latency paths min-RTT
 * is dominated by this floor, so the window is raised to bw×floor to keep
 * a high-bandwidth pipe saturated between window updates. */
#define WND_FEEDBACK_FLOOR_NS (INT64_C(600000))

#define WND_RTT_MIN_NS (INT64_C(600) * INT64_C(1000000000))
#define WND_BW_MAX_NS (INT64_C(86400) * INT64_C(1000000000))

#define STARTUP_STABLE_ROUNDS 16

/* STARTUP phase fast-growth multiplier applied to effective_bdp whenever demand
 * approaches the current window (demand × 1.5 > effective_bdp). */
#define STARTUP_GROWTH_FACTOR 3u

void mux_estimator_init(struct mux_session *restrict ss, const size_t bdp)
{
	ss->estimator = (struct estimator_ctx){ 0 };
	/* Clamp the seed to at least WNDSIZE_MIN: effective_bdp == 0 is an
	 * absorbing fixed point for phase_startup's multiplicative growth
	 * (0 * factor == 0), and demand + demand/2 > 0 always fires, so STARTUP
	 * would never exit and the BDP estimate would never feed the window. */
	const size_t seed = MAX(bdp, WNDSIZE_MIN);
	ss->estimator.rx.effective_bdp = seed;
	ss->estimator.tx.effective_bdp = seed;
	session_publish_estimate(ss);
}

static void reset_samples(struct estimator_ctx *restrict est)
{
	est->rx.sample = 0;
	est->tx.sample = 0;
}

void mux_estimator_suspend(struct mux_session *restrict ss)
{
	struct estimator_ctx *const restrict est = &ss->estimator;
	est->ping_in_flight = false;
	reset_samples(est);
}

static bool
send_ping(struct mux_session *restrict ss, const int_fast64_t now_ns)
{
	unsigned char payload[MUX_PING_PAYLOAD_SIZE];
	write_uint64(payload, (uint_fast64_t)now_ns);
	if (!mux_session_send_oob(ss, MUX_CTRL_PING, payload, sizeof(payload))) {
		return false;
	}
	struct estimator_ctx *const restrict est = &ss->estimator;
	est->last_probe_ns = now_ns;
	est->ping_in_flight = true;
	return true;
}

/* Shared probe-start/rate-limit/accumulate logic for mux_estimator_add and
 * mux_estimator_add_acked, parameterized by direction. */
static void run_probe_cycle(
	struct mux_session *restrict ss, struct estimator_dir_ctx *restrict d,
	const char *restrict label, const uint_fast64_t bytes)
{
	struct estimator_ctx *const restrict est = &ss->estimator;
	if (est->ping_in_flight) {
		/* No probe timeout: the ordered transport delivers the PONG
		 * eventually, and abandoning early can't speed it up (a new PING only
		 * queues behind it).  A dead link is caught by send_timeout/w_timeout
		 * instead, both of which route through
		 * session_on_dead_link() (session.c). */
		d->sample += (size_t)bytes;
		LOGD_F("PING in flight; accumulating %s sample, %zu bytes",
		       label, d->sample);
		return;
	}

	const int_fast64_t sent_ns = clock_monotonic_ns();
	/* The probe cycle is shared by both directions but the growth phase is
	 * per-direction: probe at the faster STARTUP rate until both directions
	 * reach TRACK, so a fresh window converges quickly. */
	const int_fast64_t min_interval = (est->rx.phase == ESTIMATOR_STARTUP ||
					   est->tx.phase == ESTIMATOR_STARTUP) ?
						  MUX_PING_STARTUP_INTERVAL_NS :
						  MUX_PING_RATE_LIMIT_NS;
	if (est->last_probe_ns != 0 &&
	    sent_ns - est->last_probe_ns < min_interval) {
		LOGD_F("rate-limited, %" PRIdFAST64 " ms remaining",
		       (int_fast64_t)(min_interval -
				      (sent_ns - est->last_probe_ns)) /
			       1000000);
		return;
	}

	if (!send_ping(ss, sent_ns)) {
		LOGD("failed to send PING; skipping estimator cycle");
		return;
	}
	LOGD_F("probe starting, %s sample=%zu", label, (size_t)bytes);
	d->sample = (size_t)bytes;
}

void mux_estimator_add(
	struct mux_session *restrict ss, const uint_fast64_t bytes)
{
	run_probe_cycle(ss, &ss->estimator.rx, "rx", bytes);
}

void mux_estimator_add_acked(
	struct mux_session *restrict ss, const uint_fast64_t bytes)
{
	run_probe_cycle(ss, &ss->estimator.tx, "tx", bytes);
}

static void phase_startup(
	struct mux_session *restrict ss, struct estimator_dir_ctx *restrict d,
	const size_t demand, const char *restrict label)
{
	const int_fast64_t bw_max = wndfilter_get(&d->bw_wnd);
	if (bw_max == 0) {
		return;
	}

	/* fast-startup: increase effective BDP aggressively */
	if (demand + demand / 2 > d->effective_bdp) {
		d->effective_bdp = MIN(
			d->effective_bdp * STARTUP_GROWTH_FACTOR, WNDSIZE_MAX);
		d->stable_rounds = 0;
		return;
	}

	d->stable_rounds++;
	if (d->stable_rounds < STARTUP_STABLE_ROUNDS) {
		return;
	}

	/* Window has headroom for STARTUP_STABLE_ROUNDS consecutive rounds: exit STARTUP. */
	d->phase = ESTIMATOR_TRACK;
	MUX_LOG_F(
		INFO, ss,
		"estimator: %s STARTUP→TRACK bw=%" PRIdFAST64 " B/s bdp=%zu B",
		label, bw_max, d->bdp);
}

static void phase_track(
	struct mux_session *restrict ss, struct estimator_dir_ctx *restrict d,
	const char *restrict label)
{
	/* Re-enter STARTUP only when measured BDP outgrows the window.  Keying
	 * on d->bdp (spike-immune) rather than the raw byte count avoids
	 * re-ramping on RTT jitter; the != 0 guard is defensive against an unseeded
	 * effective_bdp -- mux_estimator_init always seeds a non-zero window, so it only
	 * matters to white-box tests that skip it. */
	if (d->effective_bdp != 0 && d->bdp > d->effective_bdp) {
		d->phase = ESTIMATOR_STARTUP;
		d->stable_rounds = 0;
		MUX_LOG_F(
			INFO, ss,
			"estimator: %s TRACK→STARTUP bw=%" PRIdFAST64
			" B/s bdp=%zu B",
			label, wndfilter_get(&d->bw_wnd), d->bdp);
		return;
	}

	/* steady-state tracking: BDP × 1.25. */
	d->effective_bdp = d->bdp + d->bdp / 4;
}

/* Per-PONG cycle inputs shared by both directions' calculations. */
struct calc_cycle {
	int_fast64_t rtt_ns;
	int_fast64_t rtt_min_ns;
	int_fast64_t now_ns;
};

/* Convert a non-negative bandwidth-delay-product double to size_t, clamping to
 * [0, SIZE_MAX]. Converting an out-of-range double to an integer type is
 * undefined behavior (C11 6.3.1.4p1), and bdp_sample can reach ~9e15 at the
 * extremes of the bw_max and rtt_min_ns clamps -- within a 64-bit size_t but
 * past a 32-bit one. SIZE_MAX may round up to SIZE_MAX+1 as a double, so the
 * `v < (double)SIZE_MAX` test below keeps the in-range cast strictly below the
 * destination's max. */
static size_t bdp_to_size(const double v)
{
	if (v <= 0.0) {
		return 0;
	}
	/* Inverted comparison so a NaN -- for which every ordered comparison is
	 * false, so `v <= 0.0` above does not catch it -- saturates to SIZE_MAX
	 * instead of reaching the out-of-range (size_t)v cast (UB, C11 6.3.1.4p1). */
	if (!(v < (double)SIZE_MAX)) {
		return SIZE_MAX;
	}
	return (size_t)v;
}

/* Update one direction's bandwidth/BDP estimate and advance its growth
 * phase from this cycle's sample. */
static void calc_dir(
	struct mux_session *restrict ss, struct estimator_dir_ctx *restrict d,
	const char *restrict label, const struct calc_cycle *restrict c)
{
	/* Clamp the sample to prevent overflow: the value × 1e9 must fit in
	 * int_fast64_t. Compare in uintmax_t first so a size_t narrower than
	 * int_fast64_t (e.g. a 32-bit size_t) clamps to SIZE_MAX instead of
	 * silently truncating the bound itself. */
	const uintmax_t clamp_1e9 =
		(uintmax_t)(INT_FAST64_MAX / INT64_C(1000000000));
	const size_t clamp_max =
		clamp_1e9 < SIZE_MAX ? (size_t)clamp_1e9 : SIZE_MAX;
	const size_t sample_clamped = MIN(d->sample, clamp_max);
	const int_fast64_t bw_sample_raw =
		(int_fast64_t)sample_clamped * INT64_C(1000000000) / c->rtt_ns;
	/* Clamp so window_size()'s later bw_max * WND_FEEDBACK_FLOOR_NS cannot
	 * overflow int_fast64_t, however small rtt_ns is: the product above is
	 * only bounded by sample_clamped's *1e9 headroom, not by rtt_ns, which
	 * can be tiny. This bound (~13.6 TB/s) exceeds any real link speed by
	 * orders of magnitude, so it never affects a legitimate measurement. */
	const int_fast64_t bw_sample =
		MIN(bw_sample_raw, INT_FAST64_MAX / WND_FEEDBACK_FLOOR_NS);
	(void)wndfilter_update_max(
		&d->bw_wnd, WND_BW_MAX_NS, c->now_ns, bw_sample);

	const int_fast64_t bw_max = wndfilter_get(&d->bw_wnd);
	const double bdp_sample = (double)bw_max * (double)c->rtt_min_ns / 1e9;
	d->bdp = bdp_to_size(bdp_sample);

	/* Demand normalized to one min-RTT: a transient RTT spike stretches
	 * the cycle and inflates d->sample, which would otherwise trip
	 * spurious STARTUP growth. */
	const double demand_bdp =
		(double)bw_sample * (double)c->rtt_min_ns / 1e9;
	const size_t demand = bdp_to_size(demand_bdp);

	switch (d->phase) {
	case ESTIMATOR_STARTUP:
		phase_startup(ss, d, demand, label);
		break;
	case ESTIMATOR_TRACK:
		phase_track(ss, d, label);
		break;
	}
}

void mux_estimator_calculate(
	struct mux_session *restrict ss, const int_fast64_t sent_ns)
{
	struct estimator_ctx *const restrict est = &ss->estimator;
	if (!est->ping_in_flight || sent_ns != est->last_probe_ns) {
		LOGD_F("discarding PONG: sent_ns=%" PRIdFAST64
		       " last_probe_ns=%" PRIdLEAST64,
		       sent_ns, est->last_probe_ns);
		return;
	}

	const int_fast64_t now_ns = clock_monotonic_ns();
	const int_fast64_t rtt_ns = now_ns - sent_ns;
	if (rtt_ns <= 0) {
		LOGD_F("invalid RTT sample: now=%" PRIdFAST64
		       " sent=%" PRIdFAST64,
		       now_ns, sent_ns);
		est->ping_in_flight = false;
		reset_samples(est);
		est->last_probe_ns = now_ns;
		return;
	}
	const int_fast64_t rtt_min_ns = wndfilter_update_min(
		&est->rtt_wnd, WND_RTT_MIN_NS, now_ns, rtt_ns);

	est->rtt = rtt_ns;
	/* Each direction is estimated independently: rx from inbound PUSH
	 * bytes, tx from locally-sent bytes acked by the peer this cycle,
	 * so asymmetric channel capacities yield independent windows. */
	const struct calc_cycle cycle = {
		.rtt_ns = rtt_ns,
		.rtt_min_ns = rtt_min_ns,
		.now_ns = now_ns,
	};
	calc_dir(ss, &est->rx, "rx", &cycle);
	calc_dir(ss, &est->tx, "tx", &cycle);
	session_publish_estimate(ss);

	const struct estimator_dir_ctx *const restrict rx = &est->rx;
	const struct estimator_dir_ctx *const restrict tx = &est->tx;
	MUX_LOG_F(
		INFO, ss,
		"PONG: rtt=%.1f ms (min=%.1f ms) rx{bw=%" PRIdFAST64
		" B/s bdp=%zu B eff=%zu B phase=%s sample=%zu} tx{bw=%" PRIdFAST64
		" B/s bdp=%zu B eff=%zu B phase=%s sample=%zu}",
		(double)rtt_ns / 1e6, (double)rtt_min_ns / 1e6,
		wndfilter_get(&rx->bw_wnd), rx->bdp, rx->effective_bdp,
		rx->phase == ESTIMATOR_STARTUP ? "startup" : "track",
		rx->sample, wndfilter_get(&tx->bw_wnd), tx->bdp,
		tx->effective_bdp,
		tx->phase == ESTIMATOR_STARTUP ? "startup" : "track",
		tx->sample);

	est->ping_in_flight = false;
	reset_samples(est);
	est->last_probe_ns = now_ns;
}

static size_t window_size(const struct estimator_dir_ctx *restrict d)
{
	/* Raise the floor to cover inherent feedback latency (WND_FEEDBACK_FLOOR_NS).
	 * bw_max cannot exceed INT_FAST64_MAX / WND_FEEDBACK_FLOOR_NS: calc_dir
	 * clamps every bw_sample fed into bw_wnd to that bound, specifically so
	 * this product can't overflow int_fast64_t. */
	size_t floor = WNDSIZE_MIN;
	const int_fast64_t bw_max = wndfilter_get(&d->bw_wnd);
	if (bw_max > 0) {
		const int_fast64_t bw_floor =
			bw_max * WND_FEEDBACK_FLOOR_NS / INT64_C(1000000000);
		/* Compare in int_fast64_t before narrowing: bw_floor can reach
		 * ~9.22e9, past a 32-bit size_t, so a premature (size_t) cast would
		 * wrap a large value below WNDSIZE_MAX and yield too small a floor.
		 * Once bounded by WNDSIZE_MAX (~1.07e9) the cast is exact everywhere. */
		if (bw_floor > (int_fast64_t)floor) {
			floor = bw_floor > (int_fast64_t)WNDSIZE_MAX ?
					WNDSIZE_MAX :
					(size_t)bw_floor;
		}
	}
	return CLAMP(d->effective_bdp, floor, WNDSIZE_MAX);
}

size_t mux_estimator_rx_window_size(const struct estimator_ctx *restrict est)
{
	return window_size(&est->rx);
}

size_t mux_estimator_tx_window_size(const struct estimator_ctx *restrict est)
{
	return window_size(&est->tx);
}
