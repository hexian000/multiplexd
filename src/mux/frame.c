/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file frame.c
 * @brief Out-of-line mux frame support: the stream-table hash options,
 *        mux_status_str, mux_conf_default, and the bytebuf / frame-ring bodies.
 *        (The frame serialization/parsing helpers are static inline in frame.h.)
 */

#include "mux/frame.h"

#include "mux/mux.h"
#include "mux/session.h"

#include "algo/hashtable.h"
#include "hash/fnv1a.h"
#include "utils/debug.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Prebuilt stream-table config, so tests can link frame.c without the full
 * session state machine. */
static uint_fast32_t stream_id_hash(const void *key, const uint_fast32_t seed)
{
	/* FNV-1a over the 16-bit stream id via csnippets' shared implementation
	 * (the same fnv1a_32 its own ptr_hash uses), rather than hand-rolling the
	 * rounds and the FNV prime a second time. */
	const uint16_t id = (uint16_t)(uintptr_t)key;
	return fnv1a_32(&id, sizeof(id), seed);
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

const char *mux_status_str(const uint_fast16_t status)
{
	switch ((enum mux_status)status) {
	case MUX_STATUS_NO_ERROR:
		return "NO_ERROR";
	case MUX_STATUS_PROTOCOL_ERROR:
		return "PROTOCOL_ERROR";
	case MUX_STATUS_FLOW_CONTROL_ERROR:
		return "FLOW_CONTROL_ERROR";
	case MUX_STATUS_INTERNAL_ERROR:
		return "INTERNAL_ERROR";
	case MUX_STATUS_REFUSED_STREAM:
		return "REFUSED_STREAM";
	case MUX_STATUS_CANCEL:
		return "CANCEL";
	}
	return "UNKNOWN";
}

/* Defined here, with the leaf frame allocator, so it resolves in any TU that
 * links frame.c without the full session state machine. */
const struct mux_config mux_conf_default = {
	.max_frame_payload = 16384 - MUX_FRAME_HEADER_SIZE,
	.readahead = 128 * 1024,
};

bool bytebuf_reserve(
	struct bytebuf **restrict rbp, const size_t need, const bool can_grow)
{
	struct bytebuf *const rb = *rbp;
	if (need == 0 || bytebuf_write_space(rb) >= need) {
		return true;
	}

	bytebuf_compact(rb);
	if (bytebuf_write_space(rb) >= need) {
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

	if (new_cap > SIZE_MAX - sizeof(struct bytebuf)) {
		return false;
	}
	struct bytebuf *const new_rb =
		realloc(rb, sizeof(struct bytebuf) + new_cap);
	if (new_rb == NULL) {
		return false;
	}
	new_rb->cap = new_cap;
	*rbp = new_rb;
	return true;
}

void bytebuf_shrink(struct bytebuf **restrict rbp, const size_t target_cap)
{
	struct bytebuf *const rb = *rbp;
	/* Keep whichever is larger: the requested floor or the live bytes. */
	const size_t want = rb->len > target_cap ? rb->len : target_cap;
	if (rb->cap <= want) {
		return;
	}
	/* Move the live bytes to the front so realloc preserves them. */
	bytebuf_compact(rb);
	struct bytebuf *const new_rb =
		realloc(rb, sizeof(struct bytebuf) + want);
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
	ASSERT(cap == 0 || (cap & (cap - 1)) == 0);
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
	ASSERT(r == NULL || r->capacity == 0 ||
	       (r->capacity & (r->capacity - 1)) == 0);
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
	/* Slots beyond the linearised entries are raw malloc memory; clear them
	 * so unused slots read as NULL like a freshly allocated ring. */
	for (size_t i = old_count; i < new_cap; i++) {
		nr->entries[i] = NULL;
	}
	free(r);
	return nr;
}
