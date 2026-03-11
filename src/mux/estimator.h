/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file estimator.h
 * @brief Internal RTT and bandwidth estimator interface.
 */

#ifndef MUX_ESTIMATOR_H
#define MUX_ESTIMATOR_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_frame;
struct mux_session;

struct estimator_wnd_slot {
	double val;
	intmax_t t;
};

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
	/* 3-slot windowed minimum RTT; [0].val is the current min, 0.0 = uninit. */
	struct estimator_wnd_slot rtt_wnd[3];
	/* 3-slot windowed maximum BW; [0].val is the current max, 0.0 = uninit. */
	struct estimator_wnd_slot bw_wnd[3];
	/* 3-slot windowed maximum sample size; [0].val is the max, 0.0 = uninit. */
	struct estimator_wnd_slot sample_wnd[3];
	/* BDP estimate in bytes; 0 = none yet. */
	size_t bdp;
	/* Estimator phase: STARTUP grows the window aggressively; TRACK refines
	 * the BDP estimate using windowed BW and sample statistics. */
	enum estimator_phase phase;
	/* Consecutive window-limited rounds counted in TRACK phase. */
	uint_least8_t saturated_rounds;
	bool ping_in_flight : 1;
	/* true when the session was send-stalled (unacked >= session_window)
	 * at the moment the probe PING was fired; used in STARTUP to detect
	 * window exhaustion even when the sample is too small to be valid. */
	bool probe_was_stalled : 1;
};

void estimator_init(struct mux_session *restrict ss);

/* Reset estimator and seed BDP; called when automatic sizing is first enabled. */
void estimator_seed(struct mux_session *restrict ss, size_t bdp);

/* Reset all estimator state; only epoch_ns is preserved to discard stale PONGs. */
void estimator_stop(struct mux_session *restrict ss);

/* Accumulate inbound payload bytes; no-op when automatic sizing is disabled. */
void estimator_add(struct mux_session *restrict ss, uintmax_t bytes);

void estimator_calculate(struct mux_session *restrict ss, intmax_t sent_ns);

#endif /* MUX_ESTIMATOR_H */
