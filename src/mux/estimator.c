/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file estimator.c
 * @brief Internal mux RTT and bandwidth estimator implementation.
 */

#include "mux/estimator.h"

#include "mux/frame.h"
#include "mux/session.h"

#include "os/clock.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BDP_LIMIT ((size_t)16 * 1024 * 1024)
#define RTT_WND_NS (INTMAX_C(300) * INTMAX_C(1000000000))
#define BW_WND_NS (INTMAX_C(600) * INTMAX_C(1000000000))

/* 3-slot windowed min/max filter (Kathleen Nichols, 2012): s[0] is the
 * current best sample, s[1] is the staged replacement when s[0] ages out,
 * and s[2] tracks the newest accepted sample. */
static double
wnd_sub(struct estimator_wnd_slot s[static 3],
	const struct estimator_wnd_slot *restrict val, const intmax_t wnd_ns)
{
	const intmax_t dt = val->t - s[2].t;
	if (val->t - s[0].t > wnd_ns) {
		/* Rotate out expired slots. */
		s[0] = s[1];
		s[1] = s[2];
		s[2] = *val;
		if (val->t - s[0].t > wnd_ns) {
			/* Two oldest slots expired in the same step. */
			s[0] = s[1];
			s[1] = s[2];
			s[2] = *val;
		}
	} else if (s[1].t == s[0].t && dt > wnd_ns / 4) {
		/* After a reset, spread the duplicated slots back across the window. */
		s[2] = s[1] = *val;
	} else if (s[2].t == s[1].t && dt > wnd_ns / 2) {
		/* Restore mid-window coverage after a duplicated recent slot. */
		s[2] = *val;
	}
	return s[0].val;
}

static double wnd_min_update(
	struct estimator_wnd_slot s[static 3], const intmax_t t, const double v,
	const intmax_t wnd_ns)
{
	const struct estimator_wnd_slot val = { .val = v, .t = t };
	if (s[0].val == 0.0 || v <= s[0].val || t - s[2].t > wnd_ns) {
		/* New global minimum, uninitialised, or all slots expired: reset. */
		s[0] = s[1] = s[2] = val;
		return v;
	}
	if (v <= s[1].val) {
		/* Improves s[1]; also replace the most recent slot. */
		s[2] = s[1] = val;
	} else if (v <= s[2].val) {
		/* Improves only the most recent slot. */
		s[2] = val;
	}
	return wnd_sub(s, &val, wnd_ns);
}

static double wnd_max_update(
	struct estimator_wnd_slot s[static 3], const intmax_t t, const double v,
	const intmax_t wnd_ns)
{
	const struct estimator_wnd_slot val = { .val = v, .t = t };
	if (s[0].val == 0.0 || v >= s[0].val || t - s[2].t > wnd_ns) {
		/* New global maximum, uninitialised, or all slots expired: reset. */
		s[0] = s[1] = s[2] = val;
		return v;
	}
	if (v >= s[1].val) {
		/* Improves s[1]; also replace the most recent slot. */
		s[2] = s[1] = val;
	} else if (v >= s[2].val) {
		/* Improves only the most recent slot. */
		s[2] = val;
	}
	return wnd_sub(s, &val, wnd_ns);
}

void estimator_init(struct mux_session *restrict ss)
{
	ss->estimator = (struct estimator_ctx){ 0 };
}

void estimator_seed(struct mux_session *restrict ss, const size_t bdp)
{
	estimator_init(ss);
	ss->estimator.bdp = MIN(bdp, BDP_LIMIT);
}

void estimator_stop(struct mux_session *restrict ss)
{
	const intmax_t now_ns = clock_monotonic_ns();
	estimator_init(ss);
	/* Ignore stale PONGs that arrive from the previous transport epoch. */
	ss->estimator.epoch_ns = now_ns;
}

void estimator_add(struct mux_session *restrict ss, const uintmax_t bytes)
{
	if (!ss->auto_window) {
		return;
	}
	struct estimator_ctx *restrict est = &ss->estimator;
	if (est->ping_in_flight) {
		const intmax_t now_ns = clock_monotonic_ns();
		if (now_ns - est->probe_sent_ns >= MUX_PING_TIMEOUT_NS) {
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
	const double rtt_sample = (double)(now_ns - sent_ns) / 1e9;
	if (rtt_sample <= 0.0) {
		LOGD_F("invalid RTT sample: now=%" PRIdMAX " sent=%" PRIdMAX,
		       now_ns, sent_ns);
		est->ping_in_flight = false;
		est->sample = 0;
		est->last_probe_ns = now_ns;
		return;
	}

	const double rtt_min =
		wnd_min_update(est->rtt_wnd, now_ns, rtt_sample, RTT_WND_NS);

	/* Smaller samples are too noisy to update bandwidth state. */
	const bool valid_cycle =
		est->sample >= 2u * (size_t)MUX_MAX_PAYLOAD_SIZE;
	/* window_limited means one more full frame would have filled the window. */
	const bool window_limited =
		est->sample + (size_t)MUX_MAX_PAYLOAD_SIZE >=
		est->cycle_window_bytes;

	double bw_sample = 0.0;
	double bw_max = est->bw_wnd[0].val;
	double sample_max = est->sample_wnd[0].val;
	if (valid_cycle) {
		bw_sample = (double)est->sample / rtt_sample;
		bw_max = wnd_max_update(
			est->bw_wnd, now_ns, bw_sample, BW_WND_NS);
		sample_max = wnd_max_update(
			est->sample_wnd, now_ns, (double)est->sample,
			BW_WND_NS);
	}

	switch (est->phase) {
	case EST_STARTUP:
		if (!valid_cycle && est->probe_was_stalled) {
			/* A fully stalled window can still justify slow-start growth. */
			est->bdp = MIN(
				est->bdp + est->cycle_window_bytes, BDP_LIMIT);
		} else if (valid_cycle && window_limited) {
			/* The window capped delivery, so grow aggressively. */
			est->bdp = MIN(est->bdp + est->sample, BDP_LIMIT);
		} else if (valid_cycle) {
			/* The sample fit inside the window; switch to steady tracking. */
			est->phase = EST_TRACK;
			est->saturated_rounds = 0;
		}
		break;
	case EST_TRACK:
		if (valid_cycle) {
			const double target =
				MAX(sample_max, bw_max * rtt_min * 1.25);
			if (target > (double)est->bdp) {
				est->bdp =
					(size_t)MIN(target, (double)BDP_LIMIT);
			}
			if (window_limited) {
				/* BDP may have grown past the current estimate;
				 * switch back to STARTUP after two saturated
				 * rounds to avoid a premature re-probe. */
				if (++est->saturated_rounds >= 2) {
					est->phase = EST_STARTUP;
				}
			} else {
				est->saturated_rounds = 0;
			}
		}
		break;
	default:
		FAILMSGF("invalid estimator phase: %d", est->phase);
	}

	est->ping_in_flight = false;
	est->sample = 0;
	est->last_probe_ns = now_ns;

	MUX_LOG_F(
		INFO, ss,
		"PONG: rtt_min=%.1f ms bw=%.0f B/s (max=%.0f B/s)"
		" in %.1f ms bdp=%zu B phase=%s stalled=%d",
		rtt_min * 1000.0, bw_sample, bw_max, rtt_sample * 1000.0,
		est->bdp, est->phase == EST_STARTUP ? "STARTUP" : "TRACK",
		(int)est->probe_was_stalled);
}
