/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file estimator.c
 * @brief Internal mux RTT and bandwidth estimator implementation.
 */

#include "mux/estimator.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"

#include "algo/wndfilter.h"
#include "os/clock.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Single WINDOW_UPDATE grant encoding limit: Extra is uint16 in MUX_WINDOW_UNIT
 * bytes.  Capping BDP here keeps every credit advertisement expressible in
 * one frame. */
#define BDP_MAX ((size_t)UINT16_MAX * MUX_WINDOW_UNIT)
/* Minimum BDP: never shrink below the initial send window floor. */
#define BDP_MIN ((size_t)MUX_INITIAL_SEND_WINDOW)
#define RTT_WND_NS (INTMAX_C(300) * INTMAX_C(1000000000))
#define BW_WND_NS (INTMAX_C(600) * INTMAX_C(1000000000))
#define BDP_WND_NS (INTMAX_C(7200) * INTMAX_C(1000000000))
/* RTT inflation thresholds: LO = 6/5 (1.20), HI = 3/2 (1.50). */
#define INFLATE_ROUNDS 3

void estimator_init(struct mux_session *restrict ss)
{
	ss->estimator = (struct estimator_ctx){ 0 };
}

void estimator_seed(struct mux_session *restrict ss, const size_t bdp)
{
	estimator_init(ss);
	ss->estimator.bdp = bdp;
	ss->estimator.effective_bdp = CLAMP(bdp, BDP_MIN, BDP_MAX);
}

void estimator_stop(struct mux_session *restrict ss)
{
	const intmax_t now_ns = clock_monotonic_ns();
	const size_t effective_bdp = ss->estimator.effective_bdp;
	estimator_init(ss);
	/* Ignore stale PONGs that arrive from the previous transport epoch. */
	ss->estimator.epoch_ns = now_ns;
	/* Seed bdp_wnd with the last known effective_bdp so session_update_window
	 * continues to use the learned value across reconnect.  New measurements
	 * will replace it via wndfilter_update_max as the probe cycle refines the
	 * estimate; the preserved maximum ages out naturally after BDP_WND_NS. */
	if (effective_bdp > 0) {
		ss->estimator.effective_bdp = effective_bdp;
		wndfilter_reset(
			&ss->estimator.bdp_wnd, now_ns,
			(intmax_t)effective_bdp);
	}
}

void estimator_add(struct mux_session *restrict ss, const uintmax_t bytes)
{
	if (!ss->auto_window) {
		return;
	}
	struct estimator_ctx *restrict est = &ss->estimator;
	if (est->ping_in_flight) {
		const intmax_t now_ns = clock_monotonic_ns();
		if (now_ns - est->probe_sent_ns >=
		    (intmax_t)ss->conf.ping_timeout * INTMAX_C(1000000000)) {
			LOGD_F("PING timeout; discarding cycle, sample=%zu",
			       est->sample);
			est->ping_in_flight = false;
			est->sample = 0;
			est->probe_sent_ns = 0;
			/* Timeouts do not count as completed probes; the next cycle may
			 * restart immediately once fresh payload arrives. */
			/* Fall through to start a fresh cycle. */
		} else {
			est->sample += (size_t)bytes;
			LOGD_F("PING in flight; accumulating sample, %zu bytes",
			       est->sample);
			return;
		}
	}

	/* Rate-limit only after completed probes so dropped PONGs do not pin the
	 * estimator behind an old timestamp forever. */
	const intmax_t sent_ns = clock_monotonic_ns();
	if (est->last_probe_ns != 0 &&
	    sent_ns - est->last_probe_ns < MUX_PING_RATE_LIMIT_NS) {
		LOGD_F("estimator: rate-limited, %" PRIdMAX " ms remaining",
		       (intmax_t)(MUX_PING_RATE_LIMIT_NS -
				  (sent_ns - est->last_probe_ns)) /
			       1000000);
		return;
	}

	est->sample = (size_t)bytes;
	est->cycle_window_bytes = (size_t)ss->session_window * MUX_WINDOW_UNIT;
	est->probe_was_stalled = ss->send_stalled;
	LOGD_F("estimator: probe starting, window=%zu stalled=%d",
	       est->cycle_window_bytes, (int)est->probe_was_stalled);
	unsigned char payload[MUX_PING_PAYLOAD_SIZE];
	write_uint64(payload, (uint_fast64_t)sent_ns);
	if (!session_send_oob(ss, MUX_CTRL_PING, payload, sizeof(payload))) {
		LOGD("failed to send PING; skipping estimator cycle");
		est->sample = 0;
		est->cycle_window_bytes = 0;
		return;
	}
	est->probe_sent_ns = sent_ns;
	est->ping_in_flight = true;
}

static void estimator_phase_startup(
	struct estimator_ctx *restrict est, const bool valid_cycle,
	const bool window_limited)
{
	if (!valid_cycle && est->probe_was_stalled) {
		/* A fully stalled window can still justify slow-start growth. */
		est->bdp = est->bdp + est->cycle_window_bytes;
	} else if (valid_cycle && window_limited) {
		/* The window capped delivery, so grow aggressively. */
		est->bdp = est->bdp + est->sample;
	} else if (valid_cycle) {
		/* The sample fit inside the window; switch to steady tracking. */
		est->phase = EST_TRACK;
		est->saturated_rounds = 0;
	}
}

/* RTT inflation detection and force-age.  Only act when rtt_min is stable
 * (aged >= RTT_WND_NS/4 ≈ 75 s) to avoid acting on an uncalibrated baseline.
 * On triggered force-age, *bw_max and *sample_max are updated to the current
 * cycle's values so the BDP calculation immediately reflects fresh data. */
static bool estimator_handle_inflation(
	struct estimator_ctx *restrict est, const intmax_t now_ns,
	const intmax_t rtt_ns, const intmax_t rtt_min_ns,
	const intmax_t bw_sample, intmax_t *restrict bw_max,
	intmax_t *restrict sample_max)
{
	if (now_ns - est->rtt_wnd.s[0].t < RTT_WND_NS / 4) {
		/* rtt_min not yet calibrated; do not count inflation. */
		est->inflated_rounds = 0;
		return false;
	}
	/* ratio = rtt_ns/rtt_min_ns; LO = 6/5 (1.20), HI = 3/2 (1.50). */
	if (rtt_ns * 5 <= rtt_min_ns * 6) { /* ratio <= LO */
		est->inflated_rounds = 0;
		return false;
	}
	if (rtt_ns * 2 < rtt_min_ns * 3 || /* ratio < HI */
	    ++est->inflated_rounds < INFLATE_ROUNDS) {
		/* Hysteresis: ratio in (LO, HI) leaves inflated_rounds unchanged. */
		return false;
	}
	/* Force-age: collapse all 3 slots of bw_wnd and sample_wnd to the
	 * current sample.  bw_sample is a valid physical-bandwidth estimate
	 * even during bufferbloat: bottleneck capacity is unchanged; only
	 * queuing delay is inflated. */
	wndfilter_reset(&est->bw_wnd, now_ns, bw_sample);
	wndfilter_reset(&est->sample_wnd, now_ns, (intmax_t)est->sample);
	*bw_max = bw_sample;
	*sample_max = (intmax_t)est->sample;
	est->inflated_rounds = 0;
	est->saturated_rounds = 0;
	return true;
}

static bool estimator_phase_track(
	struct estimator_ctx *restrict est, const bool valid_cycle,
	const bool window_limited, const intmax_t now_ns, const intmax_t rtt_ns,
	const intmax_t rtt_min_ns, const intmax_t bw_sample)
{
	if (!valid_cycle) {
		/* Idle: leave bdp unchanged; bw_wnd/sample_wnd age
		 * naturally over BW_WND_NS; wnd_max_update resets to
		 * the current sample when the window expires. */
		return false;
	}
	intmax_t bw_max = wndfilter_get(&est->bw_wnd);
	intmax_t sample_max = wndfilter_get(&est->sample_wnd);
	const bool inflation = estimator_handle_inflation(
		est, now_ns, rtt_ns, rtt_min_ns, bw_sample, &bw_max,
		&sample_max);
	/* Bidirectional target: pure physical BDP, no headroom.
	 * Headroom is added by session_update_window. */
	{
		/* bw_max * rtt_min_ns may overflow intmax_t across BW/RTT window
		 * boundaries; use double which is exact for results <= BDP_MAX. */
		double target =
			MAX((double)sample_max,
			    (double)bw_max * (double)rtt_min_ns / 1e9);
		est->bdp = (size_t)target;
	}
	/* STARTUP re-probe path: unchanged semantics. */
	if (!window_limited) {
		est->saturated_rounds = 0;
	} else if (++est->saturated_rounds >= 2) {
		/* BDP may have grown past the current estimate;
		 * switch back to STARTUP after two saturated
		 * rounds to avoid a premature re-probe. */
		est->phase = EST_STARTUP;
	}
	return inflation;
}

void estimator_calculate(struct mux_session *restrict ss, const intmax_t sent_ns)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	if (!est->ping_in_flight || sent_ns != est->probe_sent_ns) {
		LOGD_F("discarding PONG: sent_ns=%" PRIdMAX
		       " probe_sent_ns=%" PRIdMAX,
		       sent_ns, est->probe_sent_ns);
		return;
	}
	/* Drop PONGs from an older transport epoch. */
	if (sent_ns < est->epoch_ns) {
		LOGD_F("discarding PONG: sent=%" PRIdMAX " epoch=%" PRIdMAX,
		       sent_ns, est->epoch_ns);
		return;
	}

	const intmax_t now_ns = clock_monotonic_ns();
	const intmax_t rtt_ns = now_ns - sent_ns;
	if (rtt_ns <= 0) {
		LOGD_F("invalid RTT sample: now=%" PRIdMAX " sent=%" PRIdMAX,
		       now_ns, sent_ns);
		est->ping_in_flight = false;
		est->sample = 0;
		est->last_probe_ns = now_ns;
		return;
	}

	const intmax_t rtt_min_ns =
		wndfilter_get(&est->rtt_wnd) == 0 ?
			wndfilter_reset(&est->rtt_wnd, now_ns, rtt_ns) :
			wndfilter_update_min(
				&est->rtt_wnd, RTT_WND_NS, now_ns, rtt_ns);

	/* Smaller samples are too noisy to update bandwidth state. */
	const bool valid_cycle =
		est->sample >= 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* window_limited means one more full frame would have filled the window. */
	const bool window_limited =
		est->sample + (size_t)MUX_MAX_PAYLOAD_SIZE >=
		est->cycle_window_bytes;

	intmax_t bw_sample = 0;
	if (valid_cycle) {
		/* sample <= session_window * MUX_WINDOW_UNIT <= 5/4 * BDP_MAX;
		 * numerator <= 5/4 * BDP_MAX * 1e9 ≈ 1.34e18 < INTMAX_MAX. */
		bw_sample =
			(intmax_t)est->sample * INTMAX_C(1000000000) / rtt_ns;
		(void)wndfilter_update_max(
			&est->bw_wnd, BW_WND_NS, now_ns, bw_sample);
		(void)wndfilter_update_max(
			&est->sample_wnd, BW_WND_NS, now_ns,
			(intmax_t)est->sample);
	}

	bool inflation = false;
	switch (est->phase) {
	case EST_STARTUP:
		estimator_phase_startup(est, valid_cycle, window_limited);
		break;
	case EST_TRACK:
		inflation = estimator_phase_track(
			est, valid_cycle, window_limited, now_ns, rtt_ns,
			rtt_min_ns, bw_sample);
		break;
	default:
		FAILMSGF("invalid estimator phase: %d", est->phase);
	}

	/* Update the BDP_WND_NS windowed maximum BDP.  On RTT inflation the
	 * window is force-aged to the corrected estimate to avoid letting an
	 * inflated peak persist for up to 2 hours. */
	const size_t bdp_clamped = CLAMP(est->bdp, BDP_MIN, BDP_MAX);
	if (inflation) {
		wndfilter_reset(&est->bdp_wnd, now_ns, (intmax_t)bdp_clamped);
		est->effective_bdp = bdp_clamped;
	} else {
		est->effective_bdp = (size_t)wndfilter_update_max(
			&est->bdp_wnd, BDP_WND_NS, now_ns,
			(intmax_t)bdp_clamped);
	}

	est->ping_in_flight = false;
	est->sample = 0;
	est->last_probe_ns = now_ns;
	const intmax_t bw_max = wndfilter_get(&est->bw_wnd);

	MUX_LOG_F(
		INFO, ss,
		"PONG: rtt_min=%.1f ms bw=%" PRIdMAX " B/s (max=%" PRIdMAX
		" B/s)"
		" in %.1f ms bdp=%zu B phase=%s stalled=%d infl=%u",
		(double)rtt_min_ns / 1e6, bw_sample, bw_max,
		(double)rtt_ns / 1e6, est->bdp,
		est->phase == EST_STARTUP ? "STARTUP" : "TRACK",
		(int)est->probe_was_stalled, (unsigned)est->inflated_rounds);
}
