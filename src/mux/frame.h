/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file frame.h
 * @brief Mux frame layout, constants, serialization helpers, and ring buffer.
 */

#ifndef MUX_FRAME_H
#define MUX_FRAME_H

#include "mux/mux.h"

#include "utils/serialize.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Frame format (8-byte header + payload):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Version    |     Flags     |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Stream ID           |             Extra             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Payload (0-16384 octets)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- ......

   The 2-byte Extra field interpretation depends on frame flags:
   - RST clear, SYN or ACK set: credit grant in units of MUX_WINDOW_UNIT
     bytes (receiver adds extra * MUX_WINDOW_UNIT to cumulative send
     credit).  This applies even when FIN is also set (e.g. ACK|FIN).
   - RST set: status code (enum mux_status); all other flags are ignored.
   - FIN set, ACK clear, RST clear: Extra MUST be zero.
   The initial per-stream credit is MUX_DEFAULT_SEND_WINDOW bytes
   (implicit, not transmitted).  In-memory send_window stores cumulative
   granted credit in bytes; unit conversion is applied only in
   mux_write_header / mux_read_header.
*/

/* MUX_FRAME_HEADER_SIZE, MUX_MAX_FRAME_SIZE, and MUX_MAX_PAYLOAD_SIZE are defined
 * together in mux.h so the frame-size cap stays the single anchor. */

#define MUX_PROTOCOL_VERSION 0x01

/* Default send window before receiving peer's advertisement */
#define MUX_DEFAULT_SEND_WINDOW 16384u

/* Maximum downward jitter on the idle keepalive interval */
#define MUX_KEEPALIVE_JITTER 0.2

/* Coalescing timer tick interval in seconds. */
#define MUX_COALESCING_INTERVAL 0.04

/* Number of ticks before a Nagle-held small frame is flushed.
 * Matches the recommended 40 ms reference limit from spec §7.1. */
#define MUX_NAGLE_TICKS 1

/* Number of ticks before a sub-threshold delayed-ACK grant is flushed.
 * 1 tick × 40 ms = 40 ms, halving the ACK latency relative to the common
 * 200 ms TCP delayed-ACK limit while still coalescing within a tick. */
#define MUX_DELAYED_ACK_TICKS 1

/* Maximum coalescing ticks before a pending session ACK is forced out.
 * 2 ticks × 40 ms = 80 ms. */
#define MUX_SESSION_ACK_MAX_TICKS 2

/* Maximum TLS 1.3 record plaintext length (RFC 8446 §5.1: 2^14 bytes).  A frame
 * fitting the open sendbuf entry within one record is coalesced onto it; one
 * that would overflow is sent by reference (zero-copy). */
#define MUX_MAX_RECORD 16384u

/* Receive read-ahead window: contiguous recvbuf space offered to one transport
 * read, amortizing the recv() and event-loop cost over several frames.  The
 * wire frame size is unchanged. */
#define MUX_RECV_READAHEAD ((size_t)128 * 1024)

/* Stream-0 / Flags=0 keepalive subtypes (spec §2.4.4, §5.3). */
#define MUX_CTRL_PROBE 0x0000u
#define MUX_CTRL_PING 0x0001u
#define MUX_CTRL_PONG 0x0002u

/* Payload size of the internal RTT timestamp for the BDP estimator's PING/PONG
 * cycle (other PING/PONG payload lengths are also permitted). */
#define MUX_PING_PAYLOAD_SIZE 8u

/* Seconds a CLOSED stream stays in the stream table before being freed.
 * During this tombstone period late frames are answered with at most one RST. */
#define MUX_TOMBSTONE_PERIOD_S 10.0

/* Minimum nanoseconds between outbound BDP probes in the steady-state (TRACK)
 * phase (1 s). */
#define MUX_PING_RATE_LIMIT_NS (INT64_C(1000000000))

/* Minimum nanoseconds between outbound BDP probes while the session is still
 * ramping (STARTUP phase) (100 ms): faster probing converges the window. */
#define MUX_PING_STARTUP_INTERVAL_NS (INT64_C(100000000))

/* Minimum nanoseconds between honouring consecutive inbound PINGs (50 ms);
 * kept below the startup probe interval so a peer's PINGs are always answered. */
#define MUX_PONG_RATE_LIMIT_NS (INT64_C(50000000))

/* Frame structure.  Payload starts at data[MUX_FRAME_HEADER_SIZE].  data[] is a
 * flexible array member, so a frame object is mux_frame_object_size(max_payload)
 * bytes, never plain sizeof(struct mux_frame). */
struct mux_frame {
	union {
		size_t pos;
		size_t unacked_count;
	};
	size_t cap, len;
	struct mux_frame *next;
	unsigned char data[];
};

/* Allocation size of a frame object whose payload buffer holds up to
 * @p max_payload bytes.  mux_frame_object_size() is the out-of-line equivalent
 * for pool implementers (e.g. the app) that include only the public mux.h. */
#define MUX_FRAME_OBJECT_SIZE(max_payload)                                     \
	(offsetof(struct mux_frame, data) + MUX_FRAME_HEADER_SIZE +            \
	 (size_t)(max_payload))

enum mux_flags {
	MUX_FLAG_FIN = 0x01,
	MUX_FLAG_SYN = 0x02,
	MUX_FLAG_RST = 0x04,
	MUX_FLAG_PUSH = 0x08,
	MUX_FLAG_ACK = 0x10,

	MUX_FLAG_MASK = MUX_FLAG_FIN | MUX_FLAG_SYN | MUX_FLAG_RST |
			MUX_FLAG_PUSH | MUX_FLAG_ACK,
};

/* Status codes carried in the Extra field when RST is set */
enum mux_status {
	MUX_STATUS_NO_ERROR = 0x0000,
	MUX_STATUS_PROTOCOL_ERROR = 0x0001,
	MUX_STATUS_FLOW_CONTROL_ERROR = 0x0002,
	MUX_STATUS_INTERNAL_ERROR = 0x0003,
	MUX_STATUS_REFUSED_STREAM = 0x0004,
	MUX_STATUS_CANCEL = 0x0005,
};

/* Allocate a frame whose payload buffer holds up to @p cap bytes.  The pool
 * allocator only returns a sized block; this function stamps frame->cap and
 * resets the runtime cursor fields. */
static inline struct mux_frame *
mux_frame_get(const struct mux_frame_allocator *restrict pool, const size_t cap)
{
	struct mux_frame *frame =
		pool->alloc(pool->data, MUX_FRAME_OBJECT_SIZE(cap));
	if (frame != NULL) {
		frame->pos = 0;
		frame->cap = cap;
		frame->len = 0;
		frame->next = NULL;
	}
	return frame;
}

static inline void mux_frame_put(
	const struct mux_frame_allocator *restrict pool,
	struct mux_frame *frame)
{
	pool->free(pool->data, frame);
}

struct mux_frame_list {
	struct mux_frame *head;
	struct mux_frame *tail;
	/* number of frames currently in the list */
	size_t count;
};

static inline void mux_frame_list_push(
	struct mux_frame_list *restrict list, struct mux_frame *restrict frame)
{
	frame->next = NULL;
	if (list->tail != NULL) {
		list->tail->next = frame;
	} else {
		list->head = frame;
	}
	list->tail = frame;
	list->count++;
}

/* O(1) head insertion.  Updates tail when the list was previously empty. */
static inline void mux_frame_list_push_front(
	struct mux_frame_list *restrict list, struct mux_frame *restrict frame)
{
	frame->next = list->head;
	list->head = frame;
	if (list->tail == NULL) {
		list->tail = frame;
	}
	list->count++;
}

static inline struct mux_frame *
mux_frame_list_pop(struct mux_frame_list *restrict list)
{
	struct mux_frame *frame = list->head;
	if (frame != NULL) {
		list->head = frame->next;
		if (list->head == NULL) {
			list->tail = NULL;
		}
		frame->next = NULL;
		list->count--;
	}
	return frame;
}

/* O(1) removal of the node following @prev (or head when @prev is NULL).
 * Caller must guarantee the target exists; maintains head, tail, and count. */
static inline struct mux_frame *mux_frame_list_remove_after(
	struct mux_frame_list *restrict list, struct mux_frame *prev)
{
	struct mux_frame *const frame =
		(prev != NULL) ? prev->next : list->head;
	struct mux_frame *const next = frame->next;
	if (prev != NULL) {
		prev->next = next;
	} else {
		list->head = next;
	}
	if (list->tail == frame) {
		list->tail = prev;
	}
	frame->next = NULL;
	list->count--;
	return frame;
}

static inline void mux_frame_list_clear(
	struct mux_frame_list *restrict list,
	const struct mux_frame_allocator *restrict pool)
{
	struct mux_frame *frame = list->head;
	while (frame != NULL) {
		struct mux_frame *const next = frame->next;
		frame->next = NULL;
		mux_frame_put(pool, frame);
		frame = next;
	}
	list->head = NULL;
	list->tail = NULL;
	list->count = 0;
}

struct mux_header {
	uint_least8_t version;
	uint_least8_t flags;
	uint_least16_t length;
	uint_least16_t stream_id;
	uint_least16_t extra;
};

static inline void mux_write_header(
	unsigned char *restrict buf, const struct mux_header *restrict header)
{
	write_uint8(buf + 0, header->version);
	write_uint8(buf + 1, header->flags);
	write_uint16(buf + 2, header->length);
	write_uint16(buf + 4, header->stream_id);
	write_uint16(buf + 6, header->extra);
}

static inline void mux_read_header(
	const unsigned char *restrict buf, struct mux_header *restrict header)
{
	header->version = read_uint8(buf + 0);
	header->flags = read_uint8(buf + 1);
	header->length = read_uint16(buf + 2);
	header->stream_id = read_uint16(buf + 4);
	header->extra = read_uint16(buf + 6);
}

/* --- Ring buffer --- */

struct ringbuf {
	size_t off, len, cap;
	unsigned char data[];
};

bool ringbuf_reserve(struct ringbuf **restrict rbp, size_t need, bool can_grow);

/* Shrink the ring's capacity back toward target_cap, reclaiming memory grown to
 * assemble an oversized inbound frame.  Never shrinks below the live byte count,
 * and is a no-op when the capacity is already at or below target_cap. */
void ringbuf_shrink(struct ringbuf **restrict rbp, size_t target_cap);

static inline struct ringbuf *ringbuf_new(const size_t cap)
{
	struct ringbuf *const rb = malloc(sizeof(struct ringbuf) + cap);
	if (rb == NULL) {
		return NULL;
	}
	rb->off = 0;
	rb->len = 0;
	rb->cap = cap;
	return rb;
}

static inline void ringbuf_free(struct ringbuf *restrict rb)
{
	free(rb);
}

static inline void ringbuf_reset(struct ringbuf *restrict rb)
{
	rb->off = 0;
	rb->len = 0;
}

static inline size_t ringbuf_readable(const struct ringbuf *restrict rb)
{
	return rb->len;
}

static inline size_t ringbuf_write_space(const struct ringbuf *restrict rb)
{
	return rb->cap - rb->off - rb->len;
}

static inline const unsigned char *
ringbuf_read_ptr(const struct ringbuf *restrict rb)
{
	return rb->data + rb->off;
}

static inline unsigned char *ringbuf_write_ptr(struct ringbuf *restrict rb)
{
	return rb->data + rb->off + rb->len;
}

static inline void ringbuf_produce(struct ringbuf *restrict rb, size_t n)
{
	assert(n <= ringbuf_write_space(rb));
	rb->len += n;
}

static inline void ringbuf_consume(struct ringbuf *restrict rb, size_t n)
{
	assert(n <= rb->len);
	rb->off += n;
	rb->len -= n;
	if (rb->len == 0) {
		rb->off = 0;
	}
}

static inline void ringbuf_compact(struct ringbuf *restrict rb)
{
	if (rb->off == 0 || rb->len == 0) {
		if (rb->len == 0) {
			rb->off = 0;
		}
		return;
	}
	memmove(rb->data, rb->data + rb->off, rb->len);
	rb->off = 0;
}

/* --- Frame pointer ring ---
 * Dynamic circular array of struct mux_frame * pointers: O(1) tail push, O(k)
 * head trim, heap-allocated as a single block (entries[] is a FAM). */

#define MUX_FRAME_RING_MIN 16

struct mux_frame_ring {
	size_t capacity;
	/* index of oldest entry */
	size_t head;
	/* number of entries stored */
	size_t count;
	struct mux_frame *entries[];
};

/* Allocate a new ring with initial @p cap (may be 0; grows on first push).
 * Returns NULL on OOM. */
struct mux_frame_ring *mux_frame_ring_new(size_t cap);

/* Grow capacity 2× (or to MUX_FRAME_RING_MIN on first alloc) and linearise.
 * Returns new ring pointer on success; returns NULL on OOM (old ring intact). */
struct mux_frame_ring *mux_frame_ring_grow(struct mux_frame_ring *r);

static inline size_t
mux_frame_ring_size(const struct mux_frame_ring *restrict r)
{
	return r != NULL ? r->count : 0;
}

/* O(1) peek at the frame at @p offset from head (0 = oldest).
 * Returns NULL when the ring is empty. */
static inline struct mux_frame *
mux_frame_ring_peek(const struct mux_frame_ring *restrict r, size_t offset)
{
	if (r == NULL || r->count == 0 || r->capacity == 0) {
		return NULL;
	}
	return r->entries[(r->head + offset) & (r->capacity - 1)];
}

/* O(1) append; returns false only on OOM (after failed grow attempt).
 * May update *rp if the ring is reallocated by grow. */
static inline bool mux_frame_ring_push(
	struct mux_frame_ring **restrict rp, struct mux_frame *restrict frame)
{
	struct mux_frame_ring *r = *rp;
	if (r == NULL) {
		r = mux_frame_ring_new(MUX_FRAME_RING_MIN);
		if (r == NULL) {
			return false;
		}
		*rp = r;
	}
	if (r->count >= r->capacity) {
		r = mux_frame_ring_grow(r);
		if (r == NULL) {
			return false;
		}
		*rp = r;
	}
	const size_t tail = (r->head + r->count) & (r->capacity - 1);
	r->entries[tail] = frame;
	r->count++;
	return true;
}

/* O(1) pop and return the oldest frame; NULL if ring is empty. */
static inline struct mux_frame *
mux_frame_ring_pop(struct mux_frame_ring *restrict r)
{
	if (r == NULL || r->count == 0) {
		return NULL;
	}
	struct mux_frame *f = r->entries[r->head];
	r->entries[r->head] = NULL;
	r->head = (r->head + 1) & (r->capacity - 1);
	r->count--;
	return f;
}

/* Free all mux_frame entries via @p pool, free the ring, and set *rp = NULL.
 * Safe to call when *rp is NULL. */
static inline void mux_frame_ring_free(
	struct mux_frame_ring **restrict rp,
	const struct mux_frame_allocator *restrict pool)
{
	struct mux_frame_ring *r = *rp;
	if (r == NULL) {
		return;
	}
	for (size_t i = 0; i < r->count; i++) {
		struct mux_frame *f =
			r->entries[(r->head + i) & (r->capacity - 1)];
		mux_frame_put(pool, f);
	}
	free(r);
	*rp = NULL;
}

#endif /* MUX_FRAME_H */
