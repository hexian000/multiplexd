/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file sched.h
 * @brief Internal mux stream scheduler interface.
 */

#ifndef MUX_SCHED_H
#define MUX_SCHED_H

#include <stdbool.h>
#include <stdint.h>

struct mux_session;
struct mux_stream;
struct hashtable;

/* Send scheduler: round-robin ready queue (EV_IDLE), coalescing delay queue
 * (EV_TIMER), stream table, stream-ID allocation, and per-stream send-event
 * emission (SYN, ACK/FIN) at scheduling time. */

/* Free all streams; clear the ready queue, delay list, and stream table. */
void sched_free_streams(struct mux_session *ss);

/* Insert a stream into the table; returns false on alloc failure or duplicate ID. */
bool sched_add_stream(struct mux_session *ss, struct mux_stream *s);

/* Look up a stream by ID; returns NULL if not found. */
struct mux_stream *
sched_find_stream(struct mux_session *ss, uint_fast16_t stream_id);

/* Return the next unused stream ID; returns STREAMID_CTRL when IDs are exhausted. */
uint_least16_t sched_alloc_stream_id(struct mux_session *ss);

/* Remove a stream from the coalescing delay list. */
void sched_delay_remove(struct mux_session *ss, struct mux_stream *s);

/* Enqueue a stream onto the ready queue and arm the appropriate watcher. */
void sched_wake(struct mux_session *ss, struct mux_stream *s);

/* Arm the coalescing delay list for a stream. */
void sched_delay(
	struct mux_session *restrict ss, struct mux_stream *restrict s,
	const uint_fast8_t ticks);

/* Dequeue one data-ready stream from the DRR queue and produce at most one
 * PUSH frame into sendbuf.  On the first visit to a stream in each round its
 * deficit is incremented by MUX_MAX_PAYLOAD_SIZE bytes; subsequent frames are
 * served via drr_active without a re-queue round-trip until the deficit is
 * exhausted.  Returns true if a data frame was produced. */
bool sched_next_data(struct mux_session *restrict ss);

/* Emit pending per-stream ACK/FIN control headers for all live streams
 * without touching the DRR data queue.  Must be called when the session
 * send window is exhausted so that credit-grant frames still reach the
 * peer (and unblock the session stall). */
void sched_flush_ctrl(struct mux_session *restrict ss);

/* Arm the coalescing timer if it is not already active.  Called when a
 * stream enters the delay list or when a deferred session ACK is pending. */
void sched_coalesce_arm(struct mux_session *ss);

/* Initialise w_sched and w_coalesce watchers; called once in session_new. */
void sched_init(struct mux_session *restrict ss);

#endif /* MUX_SCHED_H */
