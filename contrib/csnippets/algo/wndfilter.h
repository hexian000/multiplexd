/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ALGO_WNDFILTER_H
#define ALGO_WNDFILTER_H

#include <stdbool.h>
#include <stdint.h>

/** @defgroup wndfilter
 * @brief Windowed min/max filter by Kathleen Nichols (2012).
 * @details Tracks the minimum (or maximum) value of a data stream over a
 * fixed time window using three slots. Uses constant space and constant
 * time per update, yet almost always delivers the same result as an
 * implementation that retains all window data.
 * @{ */

/**
 * @brief A single data point for the windowed min/max tracker.
 */
struct wndfilter_sample {
	/* timestamp of the measurement */
	int_least64_t t;
	/* value measured */
	int_least64_t v;
};

/**
 * @brief State for the windowed min/max tracker.
 * @details s[0] holds the best value, s[1] the 2nd-best, s[2] the 3rd-best.
 * All three are within the current window.
 * @note Caller-allocated, with no init function: zero-initialize the state or
 *   seed it with wndfilter_reset() before the first update. An update on an
 *   indeterminate state reads @c ready; should that land non-zero, the seeding
 *   is skipped and the slots pass for measurements, so the filter reports a
 *   value it was never given until their timestamps age out of the window.
 */
struct wndfilter {
	struct wndfilter_sample s[3];
	/* true once the slots hold measurements; they are undefined until
	 * then */
	bool ready;
};

/**
 * @brief Get the current tracked min/max value.
 * @param w Pointer to the tracker state.
 * @return The best value in the current window.
 * @note Meaningful only after wndfilter_reset() or at least one update; on a
 *   zero-initialized state that has seen no measurement it returns 0.
 */
static inline int_fast64_t wndfilter_get(const struct wndfilter *restrict w)
{
	return w->s[0].v;
}

/**
 * @brief Reset the tracker to a single initial measurement.
 * @param w Pointer to the tracker state.
 * @param t Timestamp of the measurement.
 * @param v The measured value.
 * @note Writes every field and reads none, so it also seeds a state that was
 *   never initialized.
 */
void wndfilter_reset(
	struct wndfilter *restrict w, int_fast64_t t, int_fast64_t v);

/**
 * @brief Update the tracker and return the running minimum.
 * @param w Pointer to the tracker state.
 * @param wnd Length of the tracking window (same units as t).
 * @param t Timestamp of the new measurement.
 * @param v The new measured value.
 * @return The minimum value in the current window.
 */
int_fast64_t wndfilter_update_min(
	struct wndfilter *restrict w, int_fast64_t wnd, int_fast64_t t,
	int_fast64_t v);

/**
 * @brief Update the tracker and return the running maximum.
 * @param w Pointer to the tracker state.
 * @param wnd Length of the tracking window (same units as t).
 * @param t Timestamp of the new measurement.
 * @param v The new measured value.
 * @return The maximum value in the current window.
 */
int_fast64_t wndfilter_update_max(
	struct wndfilter *restrict w, int_fast64_t wnd, int_fast64_t t,
	int_fast64_t v);

/** @} */

#endif /* ALGO_WNDFILTER_H */
