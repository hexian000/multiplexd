/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file estimator.h
 * @brief BDP estimator for adaptive receive-window credit allocation.
 */

#ifndef MUX_ESTIMATOR_H
#define MUX_ESTIMATOR_H

#include "algo/wndfilter.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_frame;
struct mux_session;

/* Estimator state, embedded by value in mux_session.
 * At most one PING is outstanding at any time. */
struct estimator_ctx {
	/* PING payload timestamp; valid when ping_in_flight is true. */
	intmax_t probe_sent_ns;
	/* Last probe completion time; 0 = none. */
	intmax_t last_probe_ns;
	size_t sample; /* bytes in the current probe cycle */

	struct wndfilter rtt_wnd;
	struct wndfilter bw_wnd;

	intmax_t rtt;
	size_t bdp;
	size_t effective_bdp;

	bool ping_in_flight : 1;
	bool inited : 1;
};

/* Reset all estimator state; effective_bdp is seeded from bdp. */
void estimator_init(struct mux_session *restrict ss, size_t bdp);

/* Liveness PING, bypassing the data-driven rate limit.
 * No-op when a probe is already in flight.  Returns false on send failure. */
bool estimator_ping(struct mux_session *restrict ss);

void estimator_add(struct mux_session *restrict ss, uintmax_t bytes);
void estimator_calculate(struct mux_session *restrict ss, intmax_t sent_ns);

size_t estimator_window_size(const struct estimator_ctx *restrict est);

#endif /* MUX_ESTIMATOR_H */
