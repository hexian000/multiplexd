/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file frame.c
 * @brief Mux frame serialization and parsing helpers.
 */

#include "mux/frame.h"

#include "mux/mux.h"

#include "algo/hashtable.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Prebuilt stream-table config, so tests can link frame.c without the full
 * session state machine. */
static uint_fast32_t stream_id_hash(const void *key, const uint_fast32_t seed)
{
	const uint_least16_t id = (uint_least16_t)(uintptr_t)key;
	uint_fast32_t hash = seed;
	hash ^= (uint_fast32_t)(id & 0xffu);
	hash *= (uint_fast32_t)0x01000193u;
	hash ^= (uint_fast32_t)((id >> 8) & 0xffu);
	hash *= (uint_fast32_t)0x01000193u;
	return hash;
}

static bool stream_id_eq(const void *a, const void *b)
{
	return a == b;
}

const struct table_opts mux_stream_table_opts = {
	.hash = stream_id_hash,
	.eq = stream_id_eq,
	.flags = TABLE_FAST,
};

/* Defined here, with the leaf frame allocator, so it resolves in any TU that
 * links frame.c without the full session state machine. */
const struct mux_config mux_conf_default = {
	.max_frame_payload = 16384 - MUX_FRAME_HEADER_SIZE,
	.tls_readahead = 128 * 1024,
};

bool ringbuf_reserve(struct ringbuf **restrict rbp, size_t need, bool can_grow)
{
	struct ringbuf *const rb = *rbp;
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

void ringbuf_shrink(struct ringbuf **restrict rbp, const size_t target_cap)
{
	struct ringbuf *const rb = *rbp;
	/* Keep whichever is larger: the requested floor or the live bytes. */
	const size_t want = rb->len > target_cap ? rb->len : target_cap;
	if (rb->cap <= want) {
		return;
	}
	/* Move the live bytes to the front so realloc preserves them. */
	ringbuf_compact(rb);
	struct ringbuf *const new_rb =
		realloc(rb, sizeof(struct ringbuf) + want);
	if (new_rb == NULL) {
		/* Realloc-smaller failed: keep the larger buffer (non-fatal). */
		return;
	}
	new_rb->cap = want;
	*rbp = new_rb;
}

/* --- Frame pointer ring --- */

struct mux_frame_ring *mux_frame_ring_new(const size_t cap)
{
	struct mux_frame_ring *const r =
		malloc(sizeof(*r) + cap * sizeof(struct mux_frame *));
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

	struct mux_frame_ring *const nr =
		malloc(sizeof(*nr) + new_cap * sizeof(struct mux_frame *));
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
