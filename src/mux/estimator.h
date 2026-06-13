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

enum estimator_phase {
	ESTIMATOR_STARTUP = 0,
	ESTIMATOR_TRACK,
};

/* Each direction of the link is estimated independently so asymmetric
 * channel capacities yield independently sized windows. */
enum estimator_dir {
	/* inbound PUSH bytes; sizes stream_window (our receive grant) */
	ESTIMATOR_RX = 0,
	/* locally-sent bytes acked by the peer; sizes session_window
	 * (our unacked-frame send cap) */
	ESTIMATOR_TX,
	ESTIMATOR_DIR_COUNT,
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

/* Estimator state, embedded by value in mux_session.
 * Both directions share one PING/PONG probe cycle and the RTT filter;
 * at most one PING is outstanding at any time. */
struct estimator_ctx {
	int_least64_t last_probe_ns;
	struct wndfilter rtt_wnd;
	int_least64_t rtt;
	struct estimator_dir_ctx dir[ESTIMATOR_DIR_COUNT];
	bool ping_in_flight : 1;
};

/* Reset all estimator state; both directions' effective_bdp are seeded
 * from bdp. */
void estimator_init(struct mux_session *restrict ss, size_t bdp);

/* Liveness PING, bypassing the data-driven rate limit.
 * No-op when a probe is already in flight.  Returns false on send failure. */
bool estimator_ping(struct mux_session *restrict ss);

void estimator_add(struct mux_session *restrict ss, uint_least64_t bytes);
void estimator_add_acked(struct mux_session *restrict ss, uint_least64_t bytes);
void estimator_calculate(struct mux_session *restrict ss, int_fast64_t sent_ns);

size_t estimator_window_size(
	const struct estimator_ctx *restrict est, enum estimator_dir dir);

#endif /* MUX_ESTIMATOR_H */
