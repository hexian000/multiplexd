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

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* WINDOW_UPDATE encodes grant as uint16 in MUX_WINDOW_UNIT units. */
#define WNDSIZE_MAX ((size_t)UINT16_MAX * MUX_WINDOW_UNIT)
#define WNDSIZE_MIN ((size_t)4 * MUX_WINDOW_UNIT)

#define WND_RTT_MIN_NS (INTMAX_C(30) * INTMAX_C(1000000000))
#define WND_BW_MAX_NS (INTMAX_C(86400) * INTMAX_C(1000000000))

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
	est->probe_sent_ns = now_ns;
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

void estimator_add(struct mux_session *restrict ss, const uintmax_t bytes)
{
	if (!ss->auto_stream_window) {
		return;
	}
	struct estimator_ctx *restrict est = &ss->estimator;
	intmax_t sent_ns;
	if (est->ping_in_flight) {
		sent_ns = clock_monotonic_ns();
		if (sent_ns - est->probe_sent_ns >=
		    (intmax_t)ss->conf.ping_timeout * INTMAX_C(1000000000)) {
			LOGD_F("PING timeout; discarding cycle, sample=%zu",
			       est->sample);
			est->ping_in_flight = false;
			est->sample = 0;
			est->probe_sent_ns = 0;
			/* Fall through to start a fresh cycle; sent_ns set. */
		} else {
			est->sample += (size_t)bytes;
			LOGD_F("PING in flight; accumulating sample, %zu bytes",
			       est->sample);
			return;
		}
	} else {
		/* Rate-limit from last completed probe; timeouts do not advance
		 * last_probe_ns so a fresh probe starts immediately. */
		sent_ns = clock_monotonic_ns();
	}
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

void estimator_calculate(struct mux_session *restrict ss, const intmax_t sent_ns)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	if (!est->ping_in_flight || sent_ns != est->probe_sent_ns) {
		LOGD_F("discarding PONG: sent_ns=%" PRIdMAX
		       " probe_sent_ns=%" PRIdMAX,
		       sent_ns, est->probe_sent_ns);
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

	est->rtt = rtt_ns;
	if (!est->inited) {
		wndfilter_reset(&est->rtt_wnd, now_ns, rtt_ns);
		est->inited = true;
	}

	const intmax_t rtt_min_ns = wndfilter_update_min(
		&est->rtt_wnd, WND_RTT_MIN_NS, now_ns, rtt_ns);

	intmax_t bw_max = 0;
	if (est->sample > 0) {
		/* sample ≤ stream_window × MUX_WINDOW_UNIT ≤ WNDSIZE_MAX (clamped);
		 * numerator ≤ WNDSIZE_MAX × INTMAX_C(1000000000) < INTMAX_MAX. */
		const intmax_t bw_sample =
			(intmax_t)est->sample * INTMAX_C(1000000000) / rtt_ns;
		bw_max = wndfilter_update_max(
			&est->bw_wnd, WND_BW_MAX_NS, now_ns, bw_sample);
	} else {
		bw_max = wndfilter_get(&est->bw_wnd);
	}

	est->bdp = (size_t)((double)bw_max * (double)rtt_min_ns / 1e9);

	const bool window_limited = /* sample > 2/3 of the window target */
		(est->sample + est->sample / 2 > est->effective_bdp);
	const bool rtt_inflated = (rtt_ns > rtt_min_ns + rtt_min_ns / 4);

	if (window_limited) {
		/* Fast-start: triple the target to probe for more bandwidth. */
		est->effective_bdp *= 3;
	} else if (rtt_inflated && bw_max > 0) {
		/* Queue building: clamp to BDP estimate with 1.25× headroom. */
		est->effective_bdp = est->bdp + est->bdp / 4;
	}
	est->ping_in_flight = false;
	est->sample = 0;
	est->last_probe_ns = now_ns;

	MUX_LOG_F(
		INFO, ss,
		"PONG: rtt=%.1f ms (min=%.1f ms) bw=%" PRIdMAX
		" B/s bdp=%zu B (eff=%zu B)",
		(double)rtt_ns / 1e6, (double)rtt_min_ns / 1e6, bw_max,
		est->bdp, est->effective_bdp);
}

size_t estimator_window_size(const struct estimator_ctx *restrict est)
{
	return CLAMP(est->effective_bdp, WNDSIZE_MIN, WNDSIZE_MAX);
}
