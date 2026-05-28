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

#include "algo/ewma.h"
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
/* STARTUP bandwidth convergence: exit to TRACK after this many consecutive
 * window_limited valid cycles where bw_sample grew by less than 1/4 of the
 * prior windowed maximum (BW_FLAT_THRESHOLD = 25%). */
#define BW_FLAT_ROUNDS 3
/* BDP EWMA span: alpha = 2 / (span + 1).  4 → α = 0.4; moderate smoothing
 * without masking genuine capacity shifts. */
#define BDP_EWMA_SPAN 4

void estimator_init(struct mux_session *restrict ss)
{
	ss->estimator = (struct estimator_ctx){ 0 };
	ewma_init_span(&ss->estimator.bdp_ewma, BDP_EWMA_SPAN);
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
	/* Preserve effective_bdp across reconnect; ages out after BDP_WND_NS. */
	if (effective_bdp > 0) {
		ss->estimator.effective_bdp = effective_bdp;
		wndfilter_reset(
			&ss->estimator.bdp_wnd, now_ns,
			(intmax_t)effective_bdp);
	}
}

void estimator_add(struct mux_session *restrict ss, const uintmax_t bytes)
{
	if (!ss->auto_stream_window) {
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
			/* Fall through to start a fresh cycle. */
		} else {
			est->sample += (size_t)bytes;
			LOGD_F("PING in flight; accumulating sample, %zu bytes",
			       est->sample);
			return;
		}
	}

	/* Rate-limit from last completed probe; timeouts do not advance last_probe_ns. */
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
	est->cycle_stream_window_bytes =
		(size_t)ss->stream_window * MUX_WINDOW_UNIT;
	est->cycle_session_window_bytes =
		(size_t)ss->session_window * MUX_WINDOW_UNIT;
	est->probe_was_stalled = ss->send_stalled;
	LOGD_F("estimator: probe starting, stream_window=%zu stalled=%d",
	       est->cycle_stream_window_bytes, (int)est->probe_was_stalled);
	unsigned char payload[MUX_PING_PAYLOAD_SIZE];
	write_uint64(payload, (uint_fast64_t)sent_ns);
	if (!session_send_oob(ss, MUX_CTRL_PING, payload, sizeof(payload))) {
		LOGD("failed to send PING; skipping estimator cycle");
		est->sample = 0;
		est->cycle_stream_window_bytes = 0;
		return;
	}
	est->probe_sent_ns = sent_ns;
	est->ping_in_flight = true;
}

static void estimator_phase_startup(
	struct estimator_ctx *restrict est, const bool valid_cycle,
	const bool window_limited, const intmax_t bw_sample,
	const intmax_t bw_prev_max)
{
	if (!valid_cycle && est->probe_was_stalled) {
		/* Stall-driven growth is bounded by session_window (TX cap); using
		 * stream_window would cause runaway growth before peer_stream_window
		 * is received. */
		est->bw_flat_rounds = 0;
		est->bdp = est->bdp + est->cycle_session_window_bytes;
	} else if (valid_cycle && window_limited) {
		/* The window capped delivery, so grow aggressively. */
		est->bdp = est->bdp + est->sample;
		/* Exit to TRACK after BW_FLAT_ROUNDS consecutive cycles of flat bandwidth (< 25% growth). */
		if (bw_prev_max > 0 && bw_sample * 4 < bw_prev_max * 5) {
			if (++est->bw_flat_rounds >= BW_FLAT_ROUNDS) {
				est->phase = EST_TRACK;
				est->saturated_rounds = 0;
				est->bw_flat_rounds = 0;
				est->bdp_ewma.ready = 0;
			}
		} else {
			est->bw_flat_rounds = 0;
		}
	} else if (valid_cycle) {
		/* The sample fit inside the window; switch to steady tracking. */
		est->phase = EST_TRACK;
		est->saturated_rounds = 0;
		est->bw_flat_rounds = 0;
		est->bdp_ewma.ready = 0;
	} else {
		/* Invalid non-stalled: reset to avoid spurious TRACK transition. */
		est->bw_flat_rounds = 0;
	}
}

/* Detect RTT inflation; force-age bw/sample filters and snap bdp_ewma when
 * triggered.  Requires rtt_min aged >= RTT_WND_NS/4 to avoid false positives. */
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
	if (rtt_ns * 5 <= rtt_min_ns * 6) { /* ratio <= LO */
		est->inflated_rounds = 0;
		return false;
	}
	if (rtt_ns * 2 < rtt_min_ns * 3 || /* ratio < HI */
	    ++est->inflated_rounds < INFLATE_ROUNDS) {
		return false;
	}
	/* Force-age: collapse bw/sample filters to current values.
	 * bw_sample is valid during bufferbloat (capacity unchanged; queuing delay inflated). */
	wndfilter_reset(&est->bw_wnd, now_ns, bw_sample);
	wndfilter_reset(&est->sample_wnd, now_ns, (intmax_t)est->sample);
	*bw_max = bw_sample;
	*sample_max = (intmax_t)est->sample;
	est->inflated_rounds = 0;
	est->saturated_rounds = 0;
	/* Snap the EWMA so the corrected target lands without smoothing. */
	est->bdp_ewma.ready = 0;
	return true;
}

/* TRACK update; caller guarantees valid_cycle && window_limited.
 * Returns true on inflation force-age. */
static bool estimator_phase_track(
	struct estimator_ctx *restrict est, const intmax_t now_ns,
	const intmax_t rtt_ns, const intmax_t rtt_min_ns,
	const intmax_t bw_sample)
{
	intmax_t bw_max = wndfilter_get(&est->bw_wnd);
	intmax_t sample_max = wndfilter_get(&est->sample_wnd);
	const bool inflation = estimator_handle_inflation(
		est, now_ns, rtt_ns, rtt_min_ns, bw_sample, &bw_max,
		&sample_max);
	/* Pure physical BDP; headroom added by session_update_stream_window.
	 * bw_max * rtt_min_ns may overflow intmax_t; double is exact for results <= BDP_MAX. */
	const double target = MAX(
		(double)sample_max, (double)bw_max * (double)rtt_min_ns / 1e9);
	est->bdp = (size_t)ewma_add(&est->bdp_ewma, target);
	if (++est->saturated_rounds >= 2) {
		/* BDP may have grown past the current estimate; re-probe. */
		est->phase = EST_STARTUP;
		est->bw_flat_rounds = 0;
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
	/* window_limited means one more full frame would have filled the stream_window. */
	const bool window_limited =
		est->sample + (size_t)MUX_MAX_PAYLOAD_SIZE >=
		est->cycle_stream_window_bytes;
	/* app_limited: valid but below window; hold BW/BDP filters to preserve the high-water mark. */
	const bool app_limited = valid_cycle && !window_limited;

	intmax_t bw_sample = 0;
	intmax_t bw_prev_max = 0;
	if (valid_cycle && window_limited) {
		/* sample <= stream_window * MUX_WINDOW_UNIT <= 5/4 * BDP_MAX;
		 * numerator <= 5/4 * BDP_MAX * 1e9 ≈ 1.34e18 < INTMAX_MAX. */
		bw_sample =
			(intmax_t)est->sample * INTMAX_C(1000000000) / rtt_ns;
		bw_prev_max = wndfilter_get(&est->bw_wnd);
		(void)wndfilter_update_max(
			&est->bw_wnd, BW_WND_NS, now_ns, bw_sample);
		(void)wndfilter_update_max(
			&est->sample_wnd, BW_WND_NS, now_ns,
			(intmax_t)est->sample);
	}

	bool inflation = false;
	switch (est->phase) {
	case EST_STARTUP:
		estimator_phase_startup(
			est, valid_cycle, window_limited, bw_sample,
			bw_prev_max);
		break;
	case EST_TRACK:
		if (app_limited) {
			/* Hold windowed maxima; reset re-probe counter. */
			est->saturated_rounds = 0;
		} else if (valid_cycle) { /* implies window_limited */
			inflation = estimator_phase_track(
				est, now_ns, rtt_ns, rtt_min_ns, bw_sample);
		}
		/* !valid_cycle: let filters age naturally. */
		break;
	default:
		FAILMSGF("invalid estimator phase: %d", est->phase);
	}

	/* Update bdp_wnd peak: force-reset on inflation, hold on app_limited, otherwise update. */
	const size_t bdp_clamped = CLAMP(est->bdp, BDP_MIN, BDP_MAX);
	if (inflation) {
		wndfilter_reset(&est->bdp_wnd, now_ns, (intmax_t)bdp_clamped);
	} else if (!app_limited) {
		(void)wndfilter_update_max(
			&est->bdp_wnd, BDP_WND_NS, now_ns,
			(intmax_t)bdp_clamped);
	}
	const intmax_t held = wndfilter_get(&est->bdp_wnd);
	est->effective_bdp = held > 0 ? (size_t)held : bdp_clamped;

	est->ping_in_flight = false;
	est->sample = 0;
	est->last_probe_ns = now_ns;

	const char *cycle_label =
		inflation ? "inflation" :
		!valid_cycle ?
			    (est->probe_was_stalled ? "stalled" : "invalid") :
		app_limited ? "app-limited" :
			      "saturated";
	MUX_LOG_F(
		INFO, ss,
		"PONG: rtt=%.1f ms (min=%.1f ms) bw=%" PRIdMAX
		" B/s (max=%" PRIdMAX " B/s)"
		" bdp=%zu B (eff=%zu B) phase=%s cycle=%s"
		" sat=%u infl=%u flat=%u",
		(double)rtt_ns / 1e6, (double)rtt_min_ns / 1e6, bw_sample,
		wndfilter_get(&est->bw_wnd), est->bdp, est->effective_bdp,
		est->phase == EST_STARTUP ? "STARTUP" : "TRACK", cycle_label,
		(unsigned)est->saturated_rounds, (unsigned)est->inflated_rounds,
		(unsigned)est->bw_flat_rounds);
}
