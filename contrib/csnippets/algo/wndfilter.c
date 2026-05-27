/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "wndfilter.h"

#include <stdint.h>

intmax_t wndfilter_reset(
	struct wndfilter *restrict w, const intmax_t t, const intmax_t v)
{
	const struct wndfilter_sample val = { .t = t, .v = v };

	w->s[2] = w->s[1] = w->s[0] = val;
	return w->s[0].v;
}

/* As time advances, update the 1st, 2nd, and 3rd best slots. */
static intmax_t subwin_update(
	struct wndfilter *restrict w, const intmax_t wnd,
	const struct wndfilter_sample *restrict val)
{
	const intmax_t dt = val->t - w->s[0].t;

	if (dt > wnd) {
		/*
		 * Passed the entire window without a new val so shift the
		 * 2nd and 3rd choices forward.  Iterate once because the
		 * new 1st choice (old 2nd) may also be outside the window.
		 */
		w->s[0] = w->s[1];
		w->s[1] = w->s[2];
		w->s[2] = *val;
		if (val->t - w->s[0].t > wnd) {
			w->s[0] = w->s[1];
			w->s[1] = w->s[2];
			w->s[2] = *val;
		}
	} else if (w->s[1].t == w->s[0].t && dt > wnd / 4) {
		/*
		 * A quarter-window passed without a new val so take a fresh
		 * 2nd choice from the 2nd quarter of the window.
		 */
		w->s[2] = w->s[1] = *val;
	} else if (w->s[2].t == w->s[1].t && dt > wnd / 2) {
		/*
		 * Half the window passed without a new val so take a fresh
		 * 3rd choice from the last half of the window.
		 */
		w->s[2] = *val;
	}
	return w->s[0].v;
}

intmax_t wndfilter_update_min(
	struct wndfilter *restrict w, const intmax_t wnd, const intmax_t t,
	const intmax_t v)
{
	const struct wndfilter_sample val = { .t = t, .v = v };

	if (val.v <= w->s[0].v || val.t - w->s[2].t > wnd) {
		return wndfilter_reset(w, t, v);
	}
	if (val.v <= w->s[1].v) {
		w->s[2] = w->s[1] = val;
	} else if (val.v <= w->s[2].v) {
		w->s[2] = val;
	}
	return subwin_update(w, wnd, &val);
}

intmax_t wndfilter_update_max(
	struct wndfilter *restrict w, const intmax_t wnd, const intmax_t t,
	const intmax_t v)
{
	const struct wndfilter_sample val = { .t = t, .v = v };

	if (val.v >= w->s[0].v || val.t - w->s[2].t > wnd) {
		return wndfilter_reset(w, t, v);
	}
	if (val.v >= w->s[1].v) {
		w->s[2] = w->s[1] = val;
	} else if (val.v >= w->s[2].v) {
		w->s[2] = val;
	}
	return subwin_update(w, wnd, &val);
}
