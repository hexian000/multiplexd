/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file sched.h
 * @brief Internal mux stream scheduler interface.
 */

#ifndef MUX_SCHED_H
#define MUX_SCHED_H

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_session;
struct mux_stream;
struct hashtable;

/* Stream scheduling and table state.  Embedded by value in mux_session. */
struct sched_ctx {
	/* Per-session stream table, keyed by uint_least16_t stream ID. */
	struct hashtable *streams;
	/* CLOSED (tombstone) streams in the stream table; linger for
	 * MUX_TOMBSTONE_PERIOD_S but are no longer live. */
	size_t num_tombstones;
	/* Round-robin ready queue head and tail. */
	struct mux_stream *sched_head;
	struct mux_stream *sched_tail;
	/* Currently active DRR stream: dequeued and holding remaining deficit.
	 * Not in the ready queue; NULL when no stream is mid-round. */
	struct mux_stream *drr_active;
	/* Coalescing delay list: streams waiting for the next w_coalesce tick. */
	struct mux_stream *delay_head;
	/* Low-priority queue for lifecycle events (INIT SYN / CLOSED cleanup),
	 * kept separate from the DRR data queue. */
	struct mux_stream *lp_head;
	struct mux_stream *lp_tail;
	/* Set when lp_head has work to drain; armed (via session_notify →
	 * EV_WRITE) only while the sendbuf is clear. */
	bool lp_pending;
	/* Fixed-period coalescing timer: flushes Nagle-held frames and
	 * sub-threshold window updates every MUX_COALESCING_INTERVAL seconds. */
	ev_timer w_coalesce;
	/* Wrap-around stream-ID counter: client assigns odd IDs, server even;
	 * +2 per allocation, wrapping to the parity base. */
	uint_least16_t next_stream_id;
};

/* Send scheduler: round-robin DRR ready queue, low-priority lifecycle queue
 * (drained by session_on_send), coalescing delay queue (EV_TIMER), stream table,
 * stream-ID allocation, and per-stream send-event emission (SYN, ACK/FIN) at
 * scheduling time. */

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

/* Request a drain of the low-priority lifecycle queue: arm EV_WRITE (via
 * session_notify) when there is queued work and the sendbuf is clear.  Safe to
 * call unconditionally (self-guards on an occupied sendbuf or empty queue). */
void sched_schedule(struct mux_session *ss);

/* Drain the low-priority lifecycle queue (INIT -> SYN batching, CLOSED ->
 * cleanup).  Run by session_on_send before it pumps. */
void sched_drain_lp(struct mux_session *restrict ss);

/* Arm the coalescing delay list for a stream. */
void sched_delay(
	struct mux_session *restrict ss, struct mux_stream *restrict s,
	const uint_fast8_t ticks);

/* Scan the DRR ready queue and produce at most one PUSH frame into sendbuf,
 * skipping streams that cannot produce one (credit exhausted, queue empty,
 * Nagle-held, or non-ESTABLISHED).  A stream earns a one-frame DRR quantum on
 * its first visit and is served via drr_active until the deficit drains; a sole
 * ready stream drains its whole queue in one pass.  Returns true if a frame was
 * produced. */
bool sched_next_data(struct mux_session *restrict ss);

/* Emit pending per-stream ACK/FIN control headers for all DRR-queued streams,
 * packed into a single sendbuf staging entry.  Safe to call regardless of
 * send_stalled. */
void sched_flush_ctrl(struct mux_session *restrict ss);

/* Arm the coalescing timer if it is not already active.  Called when a
 * stream enters the delay list or when a deferred session ACK is pending. */
void sched_coalesce_arm(struct mux_session *ss);

/* Initialise the w_coalesce watcher; called once in session_new. */
void sched_init(struct mux_session *restrict ss);

#endif /* MUX_SCHED_H */
