/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ALGO_EWMA_H
#define ALGO_EWMA_H

/** @defgroup ewma
 * @brief Exponentially Weighted Moving Average (EWMA).
 * @details Computes S[n] = alpha * x[n] + (1 - alpha) * S[n-1].
 *   The first sample is used directly as the initial value (bias-free
 *   cold start), so no warm-up period is required.
 * @{ */

/**
 * @brief EWMA state.
 * @note Read @c value directly after at least one call to ewma_add().
 *   The @c value field is undefined while @c ready is zero.
 */
struct ewma {
	/* smoothing factor in (0, 1] */
	double alpha;
	/* current EWMA value; valid only when ready != 0 */
	double value;
	/* non-zero after the first sample has been added */
	int ready;
};

/**
 * @brief Initialize EWMA with a direct smoothing factor.
 * @param e     EWMA state to initialize.
 * @param alpha Smoothing factor; must satisfy 0 < alpha <= 1.
 *   Larger values give more weight to recent samples.
 */
static inline void ewma_init(struct ewma *const e, const double alpha)
{
	e->alpha = alpha;
	e->value = 0.0;
	e->ready = 0;
}

/**
 * @brief Initialize EWMA using a span (window size).
 * @param e The EWMA state to initialize.
 * @param n Span in number of samples; must be >= 1.
 *   The smoothing factor is derived as alpha = 2 / (n + 1).
 */
static inline void ewma_init_span(struct ewma *const e, const unsigned int n)
{
	ewma_init(e, 2.0 / (n + 1));
}

/**
 * @brief Add a new sample and update the EWMA.
 * @param e The EWMA state.
 * @param x The new sample value.
 * @return The updated EWMA value.
 * @details On the first call the sample is stored directly (bias-free
 *   initialization).  On subsequent calls the standard recurrence is
 *   applied: S = alpha * x + (1 - alpha) * S.
 */
static inline double ewma_add(struct ewma *const e, const double x)
{
	if (!e->ready) {
		e->value = x;
		e->ready = 1;
	} else {
		e->value = e->alpha * x + (1.0 - e->alpha) * e->value;
	}
	return e->value;
}

/** @} */

#endif /* ALGO_EWMA_H */
