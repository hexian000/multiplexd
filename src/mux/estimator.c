/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/estimator.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/send.h"
#include "mux/session.h"

#include "algo/wndfilter.h"
#include "os/clock.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* WINDOW_UPDATE encodes grant as uint16 in MUX_WINDOW_UNIT units. */
#define WNDSIZE_MAX ((size_t)UINT16_MAX * MUX_WINDOW_UNIT)
#define WNDSIZE_MIN ((size_t)4 * MUX_WINDOW_UNIT)

/* Minimum feedback latency: the inherent per-window round-trip the link cannot
 * beat (peer decrypt + window-update emit + our re-fill).  On low-latency paths
 * min-RTT is dominated by this floor, so the window floor is raised to
 * bandwidth*WND_FEEDBACK_FLOOR_NS to keep a high-bandwidth pipe saturated
 * between window updates.  Bandwidth-scaled, so low-bandwidth links are
 * unaffected. */
#define WND_FEEDBACK_FLOOR_NS (INT64_C(600000))

#define WND_RTT_MIN_NS (INT64_C(600) * INT64_C(1000000000))
#define WND_BW_MAX_NS (INT64_C(86400) * INT64_C(1000000000))

#define STARTUP_STABLE_ROUNDS 16

/* STARTUP phase fast-growth multiplier applied to effective_bdp whenever demand
 * approaches the current window (demand × 1.5 > effective_bdp). */
#define STARTUP_GROWTH_FACTOR 3u

void estimator_init(struct mux_session *restrict ss, const size_t bdp)
{
	ss->estimator = (struct estimator_ctx){ 0 };
	ss->estimator.rx.effective_bdp = bdp;
	ss->estimator.tx.effective_bdp = bdp;
}

static void reset_samples(struct estimator_ctx *restrict est)
{
	est->rx.sample = 0;
	est->tx.sample = 0;
}

static bool
send_ping(struct mux_session *restrict ss, const int_fast64_t now_ns)
{
	unsigned char payload[MUX_PING_PAYLOAD_SIZE];
	write_uint64(payload, (uint_fast64_t)now_ns);
	if (!session_send_oob(ss, MUX_CTRL_PING, payload, sizeof(payload))) {
		return false;
	}
	struct estimator_ctx *restrict est = &ss->estimator;
	est->last_probe_ns = now_ns;
	est->ping_in_flight = true;
	return true;
}

/* Shared probe-start/rate-limit/accumulate logic for estimator_add and
 * estimator_add_acked, parameterized by direction. */
static void estimator_probe(
	struct mux_session *restrict ss, struct estimator_dir_ctx *restrict d,
	const char *restrict label, const uint_least64_t bytes)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	if (est->ping_in_flight) {
		/* No probe timeout: the ordered transport delivers the PONG
		 * eventually, and abandoning early can't speed it up (a new PING only
		 * queues behind it).  A dead link is caught by send_timeout/w_timeout. */
		d->sample += (size_t)bytes;
		LOGD_F("PING in flight; accumulating %s sample, %zu bytes",
		       label, d->sample);
		return;
	}

	const int_fast64_t sent_ns = clock_monotonic_ns();
	/* The probe cycle is shared by both directions but the growth phase is
	 * per-direction: probe at the faster STARTUP rate until both directions
	 * reach TRACK, so a fresh window converges quickly. */
	const int_fast64_t min_interval =
		(ss->estimator.rx.phase == ESTIMATOR_STARTUP ||
		 ss->estimator.tx.phase == ESTIMATOR_STARTUP) ?
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

void estimator_add(struct mux_session *restrict ss, const uint_least64_t bytes)
{
	estimator_probe(ss, &ss->estimator.rx, "rx", bytes);
}

void estimator_add_acked(
	struct mux_session *restrict ss, const uint_least64_t bytes)
{
	estimator_probe(ss, &ss->estimator.tx, "tx", bytes);
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
	 * re-ramping on RTT jitter; the != 0 guard skips the first seeded cycle. */
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

/* Update one direction's bandwidth/BDP estimate and advance its growth
 * phase from this cycle's sample. */
static void calc_dir(
	struct mux_session *restrict ss, struct estimator_dir_ctx *restrict d,
	const char *restrict label, const struct calc_cycle *restrict c)
{
	/* Clamp the sample to prevent overflow: the value × 1e9 must fit in
	 * int_fast64_t. */
	const size_t clamp_max = (size_t)(INT_FAST64_MAX / INT64_C(1000000000));
	const size_t sample_clamped = MIN(d->sample, clamp_max);
	const int_fast64_t bw_sample =
		(int_fast64_t)sample_clamped * INT64_C(1000000000) / c->rtt_ns;
	(void)wndfilter_update_max(
		&d->bw_wnd, WND_BW_MAX_NS, c->now_ns, bw_sample);

	const int_fast64_t bw_max = wndfilter_get(&d->bw_wnd);
	const double bdp_sample = (double)bw_max * (double)c->rtt_min_ns / 1e9;
	d->bdp = (size_t)bdp_sample;

	/* Demand is normalized to one min-RTT, not the raw byte count:
	 * with no probe timeout a transient RTT spike stretches the cycle
	 * and inflates d->sample, which would otherwise trip spurious
	 * STARTUP growth. */
	const double demand_bdp =
		(double)bw_sample * (double)c->rtt_min_ns / 1e9;
	const size_t demand = (size_t)demand_bdp;

	switch (d->phase) {
	case ESTIMATOR_STARTUP:
		phase_startup(ss, d, demand, label);
		break;
	case ESTIMATOR_TRACK:
		phase_track(ss, d, label);
		break;
	}
}

void estimator_calculate(
	struct mux_session *restrict ss, const int_fast64_t sent_ns)
{
	struct estimator_ctx *restrict est = &ss->estimator;
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

	const struct estimator_dir_ctx *restrict rx = &est->rx;
	const struct estimator_dir_ctx *restrict tx = &est->tx;
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
	/* Raise the floor to cover the inherent feedback latency on low-latency,
	 * high-bandwidth paths (see WND_FEEDBACK_FLOOR_NS).  bw_max is the windowed
	 * peak-bandwidth estimate; the product cannot overflow because bw_max is
	 * bounded by a real measurement and the floor is capped at WNDSIZE_MAX. */
	size_t floor = WNDSIZE_MIN;
	const int_fast64_t bw_max = wndfilter_get(&d->bw_wnd);
	if (bw_max > 0) {
		const int_fast64_t bw_floor =
			bw_max * WND_FEEDBACK_FLOOR_NS / INT64_C(1000000000);
		if ((size_t)bw_floor > floor) {
			floor = (size_t)bw_floor > WNDSIZE_MAX ?
					WNDSIZE_MAX :
					(size_t)bw_floor;
		}
	}
	return CLAMP(d->effective_bdp, floor, WNDSIZE_MAX);
}

size_t estimator_rx_window_size(const struct estimator_ctx *restrict est)
{
	return window_size(&est->rx);
}

size_t estimator_tx_window_size(const struct estimator_ctx *restrict est)
{
	return window_size(&est->tx);
}
