/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file estimator.h
 * @brief Internal RTT and bandwidth estimator interface.
 */

#ifndef MUX_ESTIMATOR_H
#define MUX_ESTIMATOR_H

#include "algo/ewma.h"
#include "algo/wndfilter.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_frame;
struct mux_session;

enum estimator_phase { EST_STARTUP, EST_TRACK };

/* BDP/RTT estimator state, embedded by value in mux_session. */
struct estimator_ctx {
	/* PING payload timestamp; valid when ping_in_flight is true. */
	intmax_t probe_sent_ns;
	/* Last completed probe time (PONG received or timed out); 0 = none. */
	intmax_t last_probe_ns;
	/* Bumped by estimator_stop(); PONGs with sent_ns < epoch_ns are stale. */
	intmax_t epoch_ns;
	/* Bytes accumulated in the current PING cycle. */
	size_t sample;
	/* stream_window * MUX_WINDOW_UNIT snapshot at probe start; window_limited threshold. */
	size_t cycle_stream_window_bytes;
	/* session_window * MUX_WINDOW_UNIT snapshot at probe start; bounds
	 * stall-driven growth in STARTUP (TX cap, not the larger RX stream_window). */
	size_t cycle_session_window_bytes;
	/* Windowed minimum RTT; get == 0 means uninitialised. */
	struct wndfilter rtt_wnd;
	/* Windowed maximum bandwidth (bytes/s). */
	struct wndfilter bw_wnd;
	/* Windowed maximum sample size (bytes). */
	struct wndfilter sample_wnd;
	/* Physical BDP estimate in bytes; 0 = none. Unclamped; see effective_bdp. */
	size_t bdp;
	/* TRACK-phase EWMA of the BDP target; snapped on inflation force-age
	 * and on every STARTUP→TRACK transition. */
	struct ewma bdp_ewma;
	/* STARTUP: aggressive window growth; TRACK: steady-state BDP refinement. */
	enum estimator_phase phase;
	/* Consecutive window-limited rounds counted in TRACK phase. */
	uint_least8_t saturated_rounds;
	/* Consecutive cycles with RTT ratio >= INFLATE_HI; triggers force-age at INFLATE_ROUNDS. */
	uint_least8_t inflated_rounds;
	/* Consecutive flat-bandwidth cycles in STARTUP; triggers TRACK exit at BW_FLAT_ROUNDS. */
	uint_least8_t bw_flat_rounds;
	bool ping_in_flight : 1;
	/* Session was send-stalled at probe start; enables stall-driven STARTUP growth. */
	bool probe_was_stalled : 1;
	/* BDP_WND_NS peak BDP; seeded on suspend, ages out naturally. */
	struct wndfilter bdp_wnd;
	/* Peak BDP clamped to [BDP_MIN, BDP_MAX]; read by session_update_stream_window.
	 * Preserved across reconnect. */
	size_t effective_bdp;
};

void estimator_init(struct mux_session *restrict ss);

/* Reset estimator and seed BDP; called when automatic sizing is first enabled. */
void estimator_seed(struct mux_session *restrict ss, size_t bdp);

/* Reset probe/phase state on reconnect; preserve effective_bdp; bump epoch_ns. */
void estimator_stop(struct mux_session *restrict ss);

/* Accumulate inbound payload bytes; no-op when automatic sizing is disabled. */
void estimator_add(struct mux_session *restrict ss, uintmax_t bytes);

void estimator_calculate(struct mux_session *restrict ss, intmax_t sent_ns);

#endif /* MUX_ESTIMATOR_H */
