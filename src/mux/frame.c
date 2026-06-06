/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file frame.c
 * @brief Mux frame serialization and parsing helpers.
 */

#include "mux/frame.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

bool ringbuf_reserve(struct ringbuf **restrict rbp, size_t need, bool can_grow)
{
	struct ringbuf *rb = *rbp;
	if (need == 0 || ringbuf_write_space(rb) >= need) {
		return true;
	}

	ringbuf_compact(rb);
	if (ringbuf_write_space(rb) >= need) {
		return true;
	}
	if (!can_grow) {
		return false;
	}

	if (need > SIZE_MAX - rb->len) {
		return false;
	}
	const size_t min_cap = rb->len + need;
	size_t new_cap = rb->cap > 0 ? rb->cap : 1;
	for (; new_cap < min_cap; new_cap *= 2) {
		if (new_cap > SIZE_MAX / 2) {
			new_cap = min_cap;
			break;
		}
	}

	struct ringbuf *const new_rb =
		realloc(rb, sizeof(struct ringbuf) + new_cap);
	if (new_rb == NULL) {
		return false;
	}
	new_rb->cap = new_cap;
	*rbp = new_rb;
	return true;
}

/* --- Frame pointer ring --- */

struct mux_frame_ring *mux_frame_ring_new(const size_t cap)
{
	struct mux_frame_ring *r =
		malloc(sizeof(*r) + cap * sizeof(r->entries[0]));
	if (r == NULL) {
		return NULL;
	}
	r->capacity = cap;
	r->head = 0;
	r->count = 0;
	for (size_t i = 0; i < cap; i++) {
		r->entries[i] = NULL;
	}
	return r;
}

struct mux_frame_ring *mux_frame_ring_grow(struct mux_frame_ring *r)
{
	const size_t old_cap = r != NULL ? r->capacity : 0;
	const size_t old_count = r != NULL ? r->count : 0;
	const size_t new_cap =
		old_cap > 0 ? old_cap * 2 : (size_t)MUX_FRAME_RING_MIN;

	struct mux_frame_ring *nr =
		malloc(sizeof(*nr) + new_cap * sizeof(nr->entries[0]));
	if (nr == NULL) {
		return NULL;
	}
	nr->capacity = new_cap;
	nr->head = 0;
	nr->count = old_count;
	for (size_t i = 0; i < old_count; i++) {
		nr->entries[i] = r->entries[(r->head + i) & (old_cap - 1)];
	}
	free(r);
	return nr;
}
