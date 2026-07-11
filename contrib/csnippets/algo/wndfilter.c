/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "wndfilter.h"

#include <stdbool.h>
#include <stdint.h>

void wndfilter_reset(
	struct wndfilter *restrict w, const int_fast64_t t,
	const int_fast64_t v)
{
	const struct wndfilter_sample val = { .t = t, .v = v };
	w->s[2] = w->s[1] = w->s[0] = val;
	w->ready = true;
}

/* Elapsed time as an unsigned delta. The reference BBR filter subtracts u32
 * timestamps, whose wraparound is well-defined; computing the delta in signed
 * int_fast64_t here could instead reach signed-overflow UB for an extreme t
 * gap. Window values are non-negative, so the unsigned comparisons below match
 * the signed originals for any realistic (monotonic) timestamp. */
static inline uint_fast64_t
time_delta(const int_fast64_t now, const int_fast64_t then)
{
	return (uint_fast64_t)now - (uint_fast64_t)then;
}

/* As time advances, update the 1st, 2nd, and 3rd best slots. */
static int_fast64_t subwin_update(
	struct wndfilter *restrict w, const int_fast64_t wnd,
	const struct wndfilter_sample *restrict val)
{
	const uint_fast64_t uwnd = (uint_fast64_t)wnd;
	const uint_fast64_t dt = time_delta(val->t, w->s[0].t);

	if (dt > uwnd) {
		/*
		 * Passed the entire window without a new val so shift the
		 * 2nd and 3rd choices forward.  Iterate once because the
		 * new 1st choice (old 2nd) may also be outside the window.
		 */
		w->s[0] = w->s[1];
		w->s[1] = w->s[2];
		w->s[2] = *val;
		if (time_delta(val->t, w->s[0].t) > uwnd) {
			w->s[0] = w->s[1];
			w->s[1] = w->s[2];
			w->s[2] = *val;
		}
	} else if (w->s[1].t == w->s[0].t && dt > uwnd / 4) {
		/*
		 * A quarter-window passed without a new val so take a fresh
		 * 2nd choice from the 2nd quarter of the window.
		 */
		w->s[2] = w->s[1] = *val;
	} else if (w->s[2].t == w->s[1].t && dt > uwnd / 2) {
		/*
		 * Half the window passed without a new val so take a fresh
		 * 3rd choice from the last half of the window.
		 */
		w->s[2] = *val;
	}
	return w->s[0].v;
}

int_fast64_t wndfilter_update_min(
	struct wndfilter *restrict w, const int_fast64_t wnd,
	const int_fast64_t t, const int_fast64_t v)
{
	if (!w->ready) {
		wndfilter_reset(w, t, v);
		return w->s[0].v;
	}
	const struct wndfilter_sample val = { .t = t, .v = v };

	if (val.v <= w->s[0].v ||
	    time_delta(val.t, w->s[2].t) > (uint_fast64_t)wnd) {
		wndfilter_reset(w, t, v);
		return w->s[0].v;
	}
	if (val.v <= w->s[1].v) {
		w->s[2] = w->s[1] = val;
	} else if (val.v <= w->s[2].v) {
		w->s[2] = val;
	}
	return subwin_update(w, wnd, &val);
}

int_fast64_t wndfilter_update_max(
	struct wndfilter *restrict w, const int_fast64_t wnd,
	const int_fast64_t t, const int_fast64_t v)
{
	if (!w->ready) {
		wndfilter_reset(w, t, v);
		return w->s[0].v;
	}
	const struct wndfilter_sample val = { .t = t, .v = v };

	if (val.v >= w->s[0].v ||
	    time_delta(val.t, w->s[2].t) > (uint_fast64_t)wnd) {
		wndfilter_reset(w, t, v);
		return w->s[0].v;
	}
	if (val.v >= w->s[1].v) {
		w->s[2] = w->s[1] = val;
	} else if (val.v >= w->s[2].v) {
		w->s[2] = val;
	}
	return subwin_update(w, wnd, &val);
}
