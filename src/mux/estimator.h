/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file estimator.h
 * @brief BDP estimator for adaptive receive-window credit allocation.
 */

#ifndef MUX_ESTIMATOR_H
#define MUX_ESTIMATOR_H

#include "algo/wndfilter.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_session;

enum estimator_phase {
	ESTIMATOR_STARTUP = 0,
	ESTIMATOR_TRACK,
};

/* Per-direction bandwidth/BDP estimate and window-growth phase. */
struct estimator_dir_ctx {
	size_t sample;
	struct wndfilter bw_wnd;
	size_t bdp;
	size_t effective_bdp;
	enum estimator_phase phase;
	uint_least32_t stable_rounds;
};

/* Estimator state embedded in mux_session.  Both directions share one PING/PONG
 * probe cycle and the RTT filter (one PING outstanding at most).  rx sizes
 * stream_window (inbound PUSH bytes); tx sizes session_window (peer-acked). */
struct estimator_ctx {
	int_least64_t last_probe_ns;
	struct wndfilter rtt_wnd;
	int_least64_t rtt;
	struct estimator_dir_ctx rx, tx;
	bool ping_in_flight : 1;
};

/* Reset all estimator state; both directions' effective_bdp are seeded
 * from bdp. */
void estimator_init(struct mux_session *restrict ss, size_t bdp);

/* Clear in-flight probe/sample state on transport loss (ESTABLISHED ->
 * SUSPENDED/CLOSED). Learned bw/RTT filters and effective_bdp survive so a
 * resumed session keeps its window instead of re-probing from scratch. */
void estimator_suspend(struct mux_session *restrict ss);

void estimator_add(struct mux_session *restrict ss, uint_fast64_t bytes);
void estimator_add_acked(struct mux_session *restrict ss, uint_fast64_t bytes);
void estimator_calculate(struct mux_session *restrict ss, int_fast64_t sent_ns);

size_t estimator_rx_window_size(const struct estimator_ctx *restrict est);
size_t estimator_tx_window_size(const struct estimator_ctx *restrict est);

#endif /* MUX_ESTIMATOR_H */
