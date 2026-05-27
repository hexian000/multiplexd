/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file frame.h
 * @brief Mux frame layout, constants, serialization helpers, and ring buffer.
 */

#ifndef MUX_FRAME_H
#define MUX_FRAME_H

#include "mux/mux.h"

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

#define MUX_FRAME_HEADER_SIZE 8u
#define MUX_FRAME_SIZE (MUX_FRAME_HEADER_SIZE + MUX_MAX_PAYLOAD_SIZE)

/* Protocol version */
#define MUX_PROTOCOL_VERSION 0x01

/* Default send window before receiving peer's advertisement */
#define MUX_DEFAULT_SEND_WINDOW 16384u

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

/* Initial quickack budget assigned to a stream on establishment or
 * receive-window growth; exhausted one ACK at a time. */
#define MUX_QUICKACK_BUDGET 8

/* Stream-0 / Flags=0 keepalive subtypes (spec §2.4.4, §5.3). */
#define MUX_CTRL_PROBE 0x0000u
#define MUX_CTRL_PING 0x0001u
#define MUX_CTRL_PONG 0x0002u

/* Payload size of the internal RTT timestamp used by the BDP estimator's
 * dedicated PING/PONG cycle.  The protocol also permits other PING/PONG
 * payload lengths; this constant is only for the estimator path. */
#define MUX_PING_PAYLOAD_SIZE 8u

/* Seconds a CLOSED stream stays in the stream table before being freed.
 * During this tombstone period late frames are answered with at most one RST. */
#define MUX_TOMBSTONE_PERIOD_S 10.0

/* Minimum nanoseconds between honouring consecutive inbound PINGs (1 s). */
#define MUX_PING_RATE_LIMIT_NS (INTMAX_C(1000000000))

/* Frame structure.  Payload starts at data[MUX_FRAME_HEADER_SIZE]. */
struct mux_frame {
	union {
		size_t pos;
		size_t unacked_count;
	};
	size_t len;
	struct mux_frame *next;
	unsigned char data[MUX_FRAME_SIZE];
};

/* Frame flags */
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

struct mux_frame *
mux_frame_get(const struct mux_frame_allocator *restrict pool);

void mux_frame_put(
	const struct mux_frame_allocator *restrict pool,
	struct mux_frame *frame);

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

void mux_write_header(
	unsigned char *restrict buf, const struct mux_header *restrict header);

void mux_read_header(
	const unsigned char *restrict buf, struct mux_header *restrict header);

/* --- Ring buffer --- */

struct ringbuf {
	size_t off, len, cap;
	unsigned char data[];
};

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

static inline bool
ringbuf_reserve(struct ringbuf **restrict rbp, size_t need, bool can_grow)
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
	while (new_cap < min_cap) {
		if (new_cap > SIZE_MAX / 2) {
			new_cap = min_cap;
			break;
		}
		new_cap *= 2;
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

#endif /* MUX_FRAME_H */
