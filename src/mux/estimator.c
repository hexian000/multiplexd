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

#define WND_RTT_MIN_NS (INT64_C(600) * INT64_C(1000000000))
#define WND_BW_MAX_NS (INT64_C(86400) * INT64_C(1000000000))

#define STARTUP_STABLE_ROUNDS 16

static const char *const estimator_dir_label[ESTIMATOR_DIR_COUNT] = {
	[ESTIMATOR_RX] = "rx",
	[ESTIMATOR_TX] = "tx",
};

void estimator_init(struct mux_session *restrict ss, const size_t bdp)
{
	ss->estimator = (struct estimator_ctx){ 0 };
	for (int i = 0; i < ESTIMATOR_DIR_COUNT; i++) {
		ss->estimator.dir[i].effective_bdp = bdp;
	}
}

static void reset_samples(struct estimator_ctx *restrict est)
{
	for (int i = 0; i < ESTIMATOR_DIR_COUNT; i++) {
		est->dir[i].sample = 0;
	}
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

bool estimator_ping(struct mux_session *restrict ss)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	if (est->ping_in_flight) {
		return true;
	}
	const int_fast64_t now_ns = clock_monotonic_ns();
	if (!send_ping(ss, now_ns)) {
		return false;
	}
	reset_samples(est);
	return true;
}

/* Shared probe-start/rate-limit/accumulate logic for estimator_add and
 * estimator_add_acked, parameterized by direction. */
static void estimator_probe(
	struct mux_session *restrict ss, const enum estimator_dir dir,
	const uint_least64_t bytes)
{
	struct estimator_ctx *restrict est = &ss->estimator;
	struct estimator_dir_ctx *restrict d = &est->dir[dir];
	const char *restrict label = estimator_dir_label[dir];
	const int_fast64_t sent_ns = clock_monotonic_ns();
	if (est->ping_in_flight) {
		if (sent_ns - est->last_probe_ns >=
		    (int_fast64_t)ss->conf.ping_timeout * INT64_C(1000000000)) {
			est->ping_in_flight = false;
			reset_samples(est);
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
		d->sample += (size_t)bytes;
		LOGD_F("PING in flight; accumulating %s sample, %zu bytes",
		       label, d->sample);
		return;
	}

	/* Rate limit applies in every phase, including STARTUP. */
	if (est->last_probe_ns != 0 &&
	    sent_ns - est->last_probe_ns < MUX_PING_RATE_LIMIT_NS) {
		LOGD_F("estimator: rate-limited, %" PRIdFAST64 " ms remaining",
		       (int_fast64_t)(MUX_PING_RATE_LIMIT_NS -
				      (sent_ns - est->last_probe_ns)) /
			       1000000);
		return;
	}

	if (!send_ping(ss, sent_ns)) {
		LOGD("failed to send PING; skipping estimator cycle");
		return;
	}
	LOGD_F("estimator: probe starting, %s sample=%zu", label,
	       (size_t)bytes);
	d->sample = (size_t)bytes;
}

void estimator_add(struct mux_session *restrict ss, const uint_least64_t bytes)
{
	estimator_probe(ss, ESTIMATOR_RX, bytes);
}

void estimator_add_acked(
	struct mux_session *restrict ss, const uint_least64_t bytes)
{
	estimator_probe(ss, ESTIMATOR_TX, bytes);
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
		d->effective_bdp = MIN(d->effective_bdp * 3, WNDSIZE_MAX);
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
	const size_t demand, const char *restrict label)
{
	/* steady-state tracking: BDP × 1.25. */
	d->effective_bdp = d->bdp + d->bdp / 4;

	if (demand <= d->effective_bdp) {
		return;
	}

	/* Link bandwidth improved: re-enter STARTUP. */
	d->phase = ESTIMATOR_STARTUP;
	d->stable_rounds = 0;
	MUX_LOG_F(
		INFO, ss,
		"estimator: %s TRACK→STARTUP bw=%" PRIdFAST64 " B/s bdp=%zu B",
		label, wndfilter_get(&d->bw_wnd), d->bdp);
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
	 * so asymmetric channel capacities yield independent windows.
	 * Clamp each sample to prevent overflow: the value × 1e9 must fit
	 * in int_fast64_t. */
	const size_t clamp_max = (size_t)(INT_FAST64_MAX / INT64_C(1000000000));
	for (int i = 0; i < ESTIMATOR_DIR_COUNT; i++) {
		struct estimator_dir_ctx *restrict d = &est->dir[i];
		const size_t sample_clamped = MIN(d->sample, clamp_max);
		const int_fast64_t bw_sample = (int_fast64_t)sample_clamped *
					       INT64_C(1000000000) / rtt_ns;
		(void)wndfilter_update_max(
			&d->bw_wnd, WND_BW_MAX_NS, now_ns, bw_sample);

		const int_fast64_t bw_max = wndfilter_get(&d->bw_wnd);
		const double bdp_sample =
			(double)bw_max * (double)rtt_min_ns / 1e9;
		d->bdp = (size_t)bdp_sample;

		switch (d->phase) {
		case ESTIMATOR_STARTUP:
			phase_startup(ss, d, d->sample, estimator_dir_label[i]);
			break;
		case ESTIMATOR_TRACK:
			phase_track(ss, d, d->sample, estimator_dir_label[i]);
			break;
		}
	}

	const struct estimator_dir_ctx *restrict rx = &est->dir[ESTIMATOR_RX];
	const struct estimator_dir_ctx *restrict tx = &est->dir[ESTIMATOR_TX];
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

size_t estimator_window_size(
	const struct estimator_ctx *restrict est, const enum estimator_dir dir)
{
	return CLAMP(est->dir[dir].effective_bdp, WNDSIZE_MIN, WNDSIZE_MAX);
}
