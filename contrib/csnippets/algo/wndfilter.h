/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ALGO_WNDFILTER_H
#define ALGO_WNDFILTER_H

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
	intmax_t t;
	/* value measured */
	intmax_t v;
};

/**
 * @brief State for the windowed min/max tracker.
 * @details s[0] holds the best value, s[1] the 2nd-best, s[2] the 3rd-best.
 * All three are within the current window.
 */
struct wndfilter {
	struct wndfilter_sample s[3];
};

/**
 * @brief Get the current tracked min/max value.
 * @param m Pointer to the tracker state.
 * @return The best value in the current window.
 */
static inline intmax_t wndfilter_get(const struct wndfilter *w)
{
	return w->s[0].v;
}

/**
 * @brief Reset the tracker to a single initial measurement.
 * @param m Pointer to the tracker state.
 * @param t Timestamp of the measurement.
 * @param v The measured value.
 */
void wndfilter_reset(struct wndfilter *restrict w, intmax_t t, intmax_t v);

/**
 * @brief Update the tracker and return the running minimum.
 * @param m Pointer to the tracker state.
 * @param wnd Length of the tracking window (same units as t).
 * @param t Timestamp of the new measurement.
 * @param v The new measured value.
 * @return The minimum value in the current window.
 */
intmax_t wndfilter_update_min(
	struct wndfilter *restrict w, intmax_t wnd, intmax_t t, intmax_t v);

/**
 * @brief Update the tracker and return the running maximum.
 * @param m Pointer to the tracker state.
 * @param wnd Length of the tracking window (same units as t).
 * @param t Timestamp of the new measurement.
 * @param v The new measured value.
 * @return The maximum value in the current window.
 */
intmax_t wndfilter_update_max(
	struct wndfilter *restrict w, intmax_t wnd, intmax_t t, intmax_t v);

/** @} */

#endif /* ALGO_WNDFILTER_H */
