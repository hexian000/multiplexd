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
	/* Timestamp written into the outgoing PING payload; valid only when
	 * ping_in_flight is true. */
	intmax_t probe_sent_ns;
	/* Monotonic time of the last completed probe (PONG received or cycle
	 * timed out); 0 = none. Used for rate-limiting new probes. */
	intmax_t last_probe_ns;
	/* Monotonic time of the last estimator_stop(); PINGs sent before this
	 * time belong to a previous session and their PONGs must be discarded. */
	intmax_t epoch_ns;
	/* Byte-count sample accumulated during the current in-flight PING cycle. */
	size_t sample;
	/* Snapshot of session_window * MUX_WINDOW_UNIT taken at probe start. */
	size_t cycle_window_bytes;
	/* Windowed minimum RTT; get == 0 means uninitialised. */
	struct wndfilter rtt_wnd;
	/* Windowed maximum bandwidth (bytes/s). */
	struct wndfilter bw_wnd;
	/* Windowed maximum sample size (bytes). */
	struct wndfilter sample_wnd;
	/* Pure physical BDP estimate in bytes; 0 = none yet.
	 * Not clamped; BDP_MIN/BDP_MAX are applied only when computing
	 * effective_bdp. */
	size_t bdp;
	/* EWMA of the TRACK-phase BDP target; smooths cycle-to-cycle variation
	 * before bdp feeds the bdp_wnd windowed maximum.  Snapped (reset to
	 * ready=0) on RTT inflation force-age and on every STARTUP→TRACK
	 * transition so the first TRACK cycle after growth sets bdp directly. */
	struct ewma bdp_ewma;
	/* Estimator phase: STARTUP grows the window aggressively; TRACK refines
	 * the BDP estimate using windowed BW and sample statistics. */
	enum estimator_phase phase;
	/* Consecutive window-limited rounds counted in TRACK phase. */
	uint_least8_t saturated_rounds;
	/* Consecutive valid cycles with rtt_sample >= 3/2 * rtt_min (INFLATE_HI);
	 * reset to 0 when ratio drops below 6/5 (INFLATE_LO) or rtt_min is not
	 * yet aged past RTT_WND_NS/4. Triggers force-age at INFLATE_ROUNDS. */
	uint_least8_t inflated_rounds;
	/* Consecutive STARTUP window_limited cycles where bw_sample grew by less
	 * than BW_FLAT_THRESHOLD of the prior maximum; triggers TRACK transition
	 * to stop window growth once physical bandwidth has plateaued. */
	uint_least8_t bw_flat_rounds;
	bool ping_in_flight : 1;
	/* true when the session was send-stalled (unacked >= session_window)
	 * at the moment the probe PING was fired; used in STARTUP to detect
	 * window exhaustion even when the sample is too small to be valid. */
	bool probe_was_stalled : 1;
	/* Windowed maximum BDP over BDP_WND_NS; fed by each completed PONG cycle.
	 * Seeded with effective_bdp on session suspend; ages out after BDP_WND_NS. */
	struct wndfilter bdp_wnd;
	/* Windowed maximum BDP clamped to [BDP_MIN, BDP_MAX]; read by
	 * session_update_window.  Preserved across session suspend/resume. */
	size_t effective_bdp;
};

void estimator_init(struct mux_session *restrict ss);

/* Reset estimator and seed BDP; called when automatic sizing is first enabled. */
void estimator_seed(struct mux_session *restrict ss, size_t bdp);

/* Reset probe/phase state for session reconnect.  effective_bdp and bdp_wnd
 * are preserved so the window is maintained until a new estimate arrives.
 * epoch_ns is bumped to discard stale PONGs from the previous transport. */
void estimator_stop(struct mux_session *restrict ss);

/* Accumulate inbound payload bytes; no-op when automatic sizing is disabled. */
void estimator_add(struct mux_session *restrict ss, uintmax_t bytes);

void estimator_calculate(struct mux_session *restrict ss, intmax_t sent_ns);

#endif /* MUX_ESTIMATOR_H */
