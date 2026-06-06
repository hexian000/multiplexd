/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/estimator.h"

#include "mux/frame.h"
#include "mux/mux.h"
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

#define WND_RTT_MIN_NS (INTMAX_C(600) * INTMAX_C(1000000000))
#define WND_BW_MAX_NS (INTMAX_C(86400) * INTMAX_C(1000000000))

#define STARTUP_STABLE_ROUNDS 16

void estimator_init(struct mux_session *restrict ss, const size_t bdp)
{
	ss->estimator = (struct estimator_ctx){ 0 };
	ss->estimator.effective_bdp = bdp;
}

static bool send_ping(struct mux_session *restrict ss, const intmax_t now_ns)
{
	unsigned char payload[MUX_PING_PAYLOAD_SIZE];
	write_uint64(payload, (uint_fast64_t)now_ns);
	if (!session_send_oob(ss, MUX_CTRL_PING, payload, sizeof(payload))) {
		return false;
	}
	struct estimator_ctx *restrict est = &ss->estimator;
	est->last_probe_ns = (int_least64_t)now_ns;
	est->ping_in_flight = true;
	return true;
}

bool estimator_ping(struct mux_session *restrict ss)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	if (est->ping_in_flight) {
		return true;
	}
	const intmax_t now_ns = clock_monotonic_ns();
	if (!send_ping(ss, now_ns)) {
		return false;
	}
	est->sample = 0;
	return true;
}

void estimator_add(struct mux_session *restrict ss, const uint_least64_t bytes)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	const intmax_t sent_ns = clock_monotonic_ns();
	if (est->ping_in_flight) {
		if (sent_ns - est->last_probe_ns >=
		    (intmax_t)ss->conf.ping_timeout * INTMAX_C(1000000000)) {
			est->ping_in_flight = false;
			est->sample = 0;
			if (ss->handshake.has_session_id) {
				MUX_LOG(WARNING, ss,
					"estimator PING timeout; suspending for resume");
				session_suspend(ss);
			} else {
				MUX_LOG(WARNING, ss, "estimator PING timeout");
				session_notify_closed(ss, false);
			}
			return;
		}
		est->sample += (size_t)bytes;
		LOGD_F("PING in flight; accumulating sample, %zu bytes",
		       est->sample);
		return;
	}

	/* Rate limit applies in every phase, including STARTUP. */
	if (est->last_probe_ns != 0 &&
	    sent_ns - est->last_probe_ns < MUX_PING_RATE_LIMIT_NS) {
		LOGD_F("estimator: rate-limited, %" PRIdMAX " ms remaining",
		       (intmax_t)(MUX_PING_RATE_LIMIT_NS -
				  (sent_ns - est->last_probe_ns)) /
			       1000000);
		return;
	}

	if (!send_ping(ss, sent_ns)) {
		LOGD("failed to send PING; skipping estimator cycle");
		return;
	}
	LOGD_F("estimator: probe starting, bytes=%zu", bytes);
	est->sample = (size_t)bytes;
}

static void phase_startup(struct mux_session *restrict ss)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	const intmax_t bw_max = wndfilter_get(&est->bw_wnd);
	if (bw_max == 0) {
		return;
	}

	/* fast-startup: increase effective BDP aggressively */
	if (est->sample + est->sample / 2 > est->effective_bdp) {
		est->effective_bdp = MIN(est->effective_bdp * 3, WNDSIZE_MAX);
		est->stable_rounds = 0;
		return;
	}

	est->stable_rounds++;
	if (est->stable_rounds < STARTUP_STABLE_ROUNDS) {
		return;
	}

	/* Window has headroom for STARTUP_STABLE_ROUNDS consecutive rounds: exit STARTUP. */
	est->phase = ESTIMATOR_TRACK;
	MUX_LOG_F(
		INFO, ss,
		"estimator: STARTUP→TRACK bw=%" PRIdMAX " B/s bdp=%zu B",
		bw_max, est->bdp);
}

static void phase_track(struct mux_session *restrict ss)
{
	struct estimator_ctx *restrict est = &ss->estimator;

	/* steady-state tracking: BDP × 1.25. */
	est->effective_bdp = est->bdp + est->bdp / 4;

	if (est->sample <= est->effective_bdp) {
		return;
	}

	/* Link bandwidth improved: re-enter STARTUP. */
	est->phase = ESTIMATOR_STARTUP;
	est->stable_rounds = 0;
	MUX_LOG_F(
		INFO, ss,
		"estimator: TRACK→STARTUP bw=%" PRIdMAX " B/s bdp=%zu B",
		wndfilter_get(&est->bw_wnd), est->bdp);
}

void estimator_calculate(struct mux_session *restrict ss, const intmax_t sent_ns)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	if (!est->ping_in_flight || sent_ns != est->last_probe_ns) {
		LOGD_F("discarding PONG: sent_ns=%" PRIdMAX
		       " last_probe_ns=%" PRIdLEAST64,
		       sent_ns, est->last_probe_ns);
		return;
	}

	const intmax_t now_ns = clock_monotonic_ns();
	const intmax_t rtt_ns = now_ns - sent_ns;
	if (rtt_ns <= 0) {
		LOGD_F("invalid RTT sample: now=%" PRIdMAX " sent=%" PRIdMAX,
		       now_ns, sent_ns);
		est->ping_in_flight = false;
		est->sample = 0;
		est->last_probe_ns = (int_least64_t)now_ns;
		return;
	}
	const intmax_t rtt_min_ns = wndfilter_update_min(
		&est->rtt_wnd, WND_RTT_MIN_NS, now_ns, rtt_ns);

	est->rtt = (int_least64_t)rtt_ns;
	/* Clamp sample to prevent overflow: sample × 1e9 must fit in intmax_t. */
	const size_t sample_clamped =
		MIN(est->sample, (size_t)(INTMAX_MAX / INTMAX_C(1000000000)));
	const intmax_t bw_sample =
		(intmax_t)sample_clamped * INTMAX_C(1000000000) / rtt_ns;
	(void)wndfilter_update_max(
		&est->bw_wnd, WND_BW_MAX_NS, now_ns, bw_sample);

	const intmax_t bw_max = wndfilter_get(&est->bw_wnd);
	const double bdp_sample = (double)bw_max * (double)rtt_min_ns / 1e9;
	est->bdp = (size_t)bdp_sample;

	switch (est->phase) {
	case ESTIMATOR_STARTUP:
		phase_startup(ss);
		break;
	case ESTIMATOR_TRACK:
		phase_track(ss);
		break;
	}
	est->ping_in_flight = false;
	est->sample = 0;
	est->last_probe_ns = (int_least64_t)now_ns;

	MUX_LOG_F(
		INFO, ss,
		"PONG: rtt=%.1f ms (min=%.1f ms) bw=%" PRIdMAX
		" B/s bdp=%zu B (eff=%zu B, phase=%s)",
		(double)rtt_ns / 1e6, (double)rtt_min_ns / 1e6, bw_max,
		est->bdp, est->effective_bdp,
		est->phase == ESTIMATOR_STARTUP ? "startup" : "track");
}

size_t estimator_window_size(const struct estimator_ctx *restrict est)
{
	return CLAMP(est->effective_bdp, WNDSIZE_MIN, WNDSIZE_MAX);
}
