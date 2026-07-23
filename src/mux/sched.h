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
	/* Set when lp_head has work to drain; armed (via mux_session_notify →
	 * EV_WRITE) only while the sendbuf is clear. */
	bool lp_pending;
	/* Fixed-period coalescing timer: flushes Nagle-held frames and
	 * sub-threshold window updates every MUX_COALESCING_INTERVAL seconds. */
	ev_timer w_coalesce;
	/* Wrap-around stream-ID counter: client assigns odd IDs, server even;
	 * +2 per allocation, wrapping to the parity base. */
	uint_least16_t next_stream_id;
};

/* Send scheduler: DRR ready queue, low-priority lifecycle queue, coalescing
 * delay queue, stream table, stream-ID allocation, and per-stream send-event
 * emission (SYN, ACK/FIN) at scheduling time. */

/* Free all streams; clear the ready queue, delay list, and stream table. */
void mux_sched_free_streams(struct mux_session *restrict ss);

/* Insert a stream into the table; returns false on alloc failure or duplicate ID. */
bool mux_sched_add_stream(
	struct mux_session *restrict ss, struct mux_stream *restrict s);

/* Look up a stream by ID; returns NULL if not found. */
struct mux_stream *
mux_sched_find_stream(struct mux_session *restrict ss, uint_fast16_t stream_id);

/* Return the next unused stream ID; returns STREAMID_CTRL when IDs are exhausted. */
uint_least16_t mux_sched_alloc_stream_id(struct mux_session *restrict ss);

/* Remove a stream from the coalescing delay list. */
void mux_sched_delay_remove(
	struct mux_session *restrict ss, struct mux_stream *restrict s);

/* Route a stream to the scheduler. Before SESSION_ESTABLISHED it is just
 * enqueued (the split queues are not active yet) and nothing is armed. Once
 * ESTABLISHED, INIT/CLOSED streams go to the low-priority lifecycle queue (never
 * the DRR ready queue) and others to the DRR ready queue, then the write path is
 * armed via mux_session_notify. */
void mux_sched_wake(
	struct mux_session *restrict ss, struct mux_stream *restrict s);

/* React to the stream table's active (non-tombstone) count possibly having
 * just reached zero: initiate drain-shutdown, or arm the idle timer. Safe to
 * call whenever the table or tombstone count changes; a no-op when streams
 * remain active or the session isn't ESTABLISHED. */
void mux_sched_check_no_active_streams(struct mux_session *restrict ss);

/* Request a drain of the low-priority lifecycle queue: arm EV_WRITE (via
 * mux_session_notify) when there is queued work and the sendbuf is clear.  Safe to
 * call unconditionally (self-guards on an occupied sendbuf or empty queue). */
void mux_sched_schedule(struct mux_session *restrict ss);

/* Drain the low-priority lifecycle queue (INIT -> SYN batching, CLOSED ->
 * cleanup).  Run by mux_session_on_send before it pumps. */
void mux_sched_drain_lp(struct mux_session *restrict ss);

/* Arm the coalescing delay list for a stream. */
void mux_sched_delay(
	struct mux_session *restrict ss, struct mux_stream *restrict s,
	const uint_fast8_t ticks);

/* Scan the DRR ready queue and stage at most one PUSH frame into sendbuf,
 * skipping streams that cannot produce (credit, queue empty, Nagle, or
 * non-ESTABLISHED).  Returns true if a frame was produced. */
bool mux_sched_next_data(struct mux_session *restrict ss);

/* Emit pending per-stream ACK/FIN control headers for all DRR-queued streams,
 * packed into a single sendbuf staging entry.  Safe to call regardless of
 * send_stalled. */
void mux_sched_flush_ctrl(struct mux_session *restrict ss);

/* Arm the coalescing timer if it is not already active.  Called when a
 * stream enters the delay list or when a deferred session ACK is pending. */
void mux_sched_coalesce_arm(struct mux_session *restrict ss);

/* Initialise the w_coalesce watcher; called once in mux_session_new. */
void mux_sched_init(struct mux_session *restrict ss);

#endif /* MUX_SCHED_H */
