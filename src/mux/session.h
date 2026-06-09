/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file session.h
 * @brief Internal mux session state machine interface.
 */

#ifndef MUX_SESSION_H
#define MUX_SESSION_H

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "os/socket.h"
#include "utils/slog.h"

#include <ev.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_stream;
struct mux_session;
struct tls_context;
struct tls_connection;
struct hashtable;

#define STREAMID_CTRL 0

/* Session state */
enum session_state {
	/* Session object created, not yet started */
	SESSION_INIT,
	/* TCP connection in progress (client only) */
	SESSION_CONNECT,
	/* Protocol hello exchange in progress */
	SESSION_HANDSHAKE,
	/* Session ready; stream operations allowed */
	SESSION_ESTABLISHED,
	/* Transport lost; streams and unacked ring preserved; awaiting reconnect */
	SESSION_SUSPENDED,
	/* Graceful shutdown of the transport layer initiated */
	SESSION_CLOSING,
	/* Waiting for the peer to close the transport */
	SESSION_CLOSE_WAIT,
	/* Session fully terminated */
	SESSION_CLOSED,
};

/* Bits per bitmap word; derived from the actual width of uint_fast32_t. */
#define BITMAP_WORD_BITS ((int)(CHAR_BIT * sizeof(uint_fast32_t)))
/* Number of words in the per-session stream-ID allocation bitmap.
 * Covers all 32768 possible (id >> 1) indices. */
#define SCHED_ID_BITMAP_WORDS                                                  \
	((32768 + BITMAP_WORD_BITS - 1) / BITMAP_WORD_BITS)

/* Stream scheduling and table state.  Embedded by value in mux_session. */
struct sched_ctx {
	/* Per-session stream table, keyed by uint_least16_t stream ID. */
	struct hashtable *streams;
	/* Single-entry lookup cache for sched_find_stream.  Frame bursts target
	 * the same stream, so caching the last hit skips the hash lookup.  The
	 * cached stream's own id is the key; cleared whenever a stream leaves
	 * the table (sched_remove_stream / sched_free_streams). */
	struct mux_stream *cache_stream;
	/* Number of CLOSED (tombstone) streams currently in the stream table.
	 * These linger for MUX_TOMBSTONE_PERIOD_S but are no longer "live".
	 * Used to exclude tombstones from the max_streams admission gate. */
	size_t num_tombstones;
	/* Round-robin ready queue head and tail. */
	struct mux_stream *sched_head;
	struct mux_stream *sched_tail;
	/* Tail of the ready queue at the start of the current scheduling round;
	 * used by the EV_WRITE data path to enforce DRR round fairness. */
	struct mux_stream *round_end;
	/* Currently active DRR stream: dequeued and holding remaining deficit.
	 * Not in the ready queue; NULL when no stream is mid-round. */
	struct mux_stream *drr_active;
	/* Coalescing delay list: streams waiting for the next w_coalesce tick. */
	struct mux_stream *delay_head;
	/* Low-priority queue for lifecycle events (INIT SYN / CLOSED cleanup).
	 * Drained in EV_IDLE; kept separate from the DRR data queue so the
	 * data path never skips over INIT/CLOSED streams. */
	struct mux_stream *lp_head;
	struct mux_stream *lp_tail;
	/* Control-pending list: streams with queued ACK or FIN that have no
	 * data to piggyback on.  Drained by sched_flush_ctrl during send-stall
	 * and opportunistically by sched_next_data during normal operation. */
	struct mux_stream *ctrl_head;
	ev_idle w_sched;
	/* Fixed-period coalescing timer: flushes Nagle-held frames and
	 * sub-threshold window updates every MUX_COALESCING_INTERVAL seconds. */
	ev_timer w_coalesce;
	/* Bitmap of occupied stream IDs, indexed by (id >> 1).  Maintained in
	 * sync with the stream table to enable O(n/BITMAP_WORD_BITS) ID allocation. */
	uint_fast32_t id_bitmap[SCHED_ID_BITMAP_WORDS];
};

/* Session-level ACK, identity, resume, and peer capability state.
 * Embedded by value in mux_session. */
struct handshake_ctx {
	/* Session identity and resume state (spec §5.8) */
	/* Server-assigned 16-byte session identity, shared by both peers. */
	unsigned char session_id[16];
	/* true when session_id has been assigned (always true for server sessions) */
	bool has_session_id : 1;

	/* Peer capabilities and identity extension */
	bool peer_rejects_inbound_streams : 1;
	/* This node's identity announced in hello. */
	char *identity;
	/* Internal peer label for diagnostics; NOT sent in hello. */
	char *peer_id;
	/* Identity received from the peer's hello. */
	char *peer_identity;
};

/* COUNTER_ADD/SUB/LOAD/STORE operate on mux_session_counters pointer fields.
 * All macros are NULL-safe: when the pointer argument is NULL the
 * operation is silently skipped (returns 0 for ADD/SUB/LOAD). */
#if WITH_THREADS
#define COUNTER_ADD(p, v)                                                      \
	((p) ? atomic_fetch_add_explicit((p), (v), memory_order_relaxed) : 0)
#define COUNTER_SUB(p, v)                                                      \
	((p) ? atomic_fetch_sub_explicit((p), (v), memory_order_relaxed) : 0)
#define COUNTER_LOAD(p)                                                        \
	((p) ? atomic_load_explicit((p), memory_order_relaxed) : 0)
#define COUNTER_STORE(p, v)                                                    \
	((p) ? atomic_store_explicit((p), (v), memory_order_relaxed) : (void)0)
#else
#define COUNTER_ADD(p, v) ((p) ? (*(p) += (uint_least64_t)(v)) : 0)
#define COUNTER_SUB(p, v) ((p) ? (*(p) -= (uint_least64_t)(v)) : 0)
#define COUNTER_LOAD(p) ((p) ? *(p) : 0)
#define COUNTER_STORE(p, v) ((p) ? (void)(*(p) = (v)) : (void)0)
#endif

/* All fields of mux_session are accessed only from the owning ev_loop thread. */
struct mux_session {
	struct ev_loop *loop;
	struct mux_config conf;
	/* Frame allocator; set at creation time and never changed. */
	struct mux_frame_allocator pool;
	/* One-deep frame cache layered over pool; holds at most one idle frame
	 * so the steady alloc/free churn of the data path rarely reaches the
	 * cross-thread server allocator.  Accessed only via session_frame_alloc
	 * / session_frame_free; released by session_cleanup. */
	struct mux_frame *frame_spare;
	/* Non-owning pointer to the session log tag buffer; set at creation time. */
	char *tag;
	/* Pointer block into server_stats; NULL pointers are silently skipped. */
	struct mux_session_counters cnt;
	/* Local counter for tracking. */
	size_t num_halfopen;
	/* Per-session frame counters for internal flow control.
	 * These are also pushed to the server-level aggregates via
	 * mux_session_counters pointers when available (non-NULL). */
	size_t recv_buffered_bytes;
	size_t send_buffered_frames;
	size_t unacked_frames;
	/* Local per-session diagnostics. */
	int_least64_t last_connect_latency_ns;
	/* Total mux bytes received from the transport for diagnostics. */
	uint_least64_t bytes_recv;
	/* Monotonic ns of the last inbound PING; used for inbound PING rate limiting. */
	int_least64_t ping_recv_last_ns;
	enum session_state state;
	int_least64_t last_modified;
	/* Peer address captured when session reaches SESSION_ESTABLISHED. */
	union sockaddr_max peer_addr;
	struct mux_callbacks callbacks;
	void *userdata;

	/* Event watchers */
	struct {
		ev_io w_socket;
		ev_timer w_timeout;
		ev_timer w_keepalive;
		ev_timer w_send_timeout;
		ev_timer w_connect_timeout;
		ev_timer w_idle_timeout;
	};

	/* true for accepted (server-role) sessions */
	bool accepted : 1;
	/* true when the unacked ring has reached the session window cap;
	 * data frame sends are suspended until the peer acknowledges frames. */
	bool send_stalled : 1;
	/* true when stream_window was configured as 0; the BDP estimator probes
	 * bandwidth on each inbound PUSH cycle and stream_window tracks the
	 * resulting effective_bdp with headroom. */
	bool auto_stream_window : 1;
	/* true when session_window was configured as 0; session_window tracks
	 * peer_stream_window (updated on each SYN and SYN|ACK). */
	bool auto_session_window : 1;
	/* true when the session should shut down as soon as its last stream
	 * closes; set by session_drain() and cleared on reconnect. */
	bool draining : 1;

	/* Effective unacked-frame cap for the session; in auto mode updated from
	 * peer_stream_window (the peer's per-stream receive window) whenever a
	 * SYN or SYN|ACK is received.  A floor of
	 * MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT is always enforced. */
	uint_least32_t session_window;
	/* Effective per-stream receive window (frames); in auto mode tracks the
	 * RX BDP with headroom so per-stream credit is never the bottleneck.
	 * Grows and shrinks with the BDP estimate; already-granted per-stream
	 * recv_window is not clawed back on shrink. */
	uint_least32_t stream_window;
	/* Peer's effective per-stream receive window (frames); updated
	 * unconditionally on each SYN and SYN|ACK (supports shrinking);
	 * not derived from ACK credit grants. */
	uint_least32_t peer_stream_window;

	/* Transport I/O state (socket buffers, TLS connection, flow-control flags). */
	struct wire_ctx wire;

	/* Stream scheduling and table state. */
	struct sched_ctx sched;

	/* Session-level ACK and retransmission state (spec §5.7). */
	struct {
		/* count of non-stream-0 frames sent (incremented after full flush) */
		uint_least32_t send_seq;
		/* count of non-stream-0 frames received */
		uint_least32_t recv_seq;
		/* recv_seq value at the time of the last session ACK emission */
		uint_least32_t ack_seq;
		/* cumulative send_seq acknowledged by the peer */
		uint_least32_t last_ack_recv;
		/* ticks elapsed since the last session ACK was sent while frames are
		 * pending; reset to 0 on emission or when recv_seq == ack_seq */
		int session_ack_ticks;
		/* true when a stream ACK has been sent since the last session ACK,
		 * meaning a session-level ACK piggyback should be scheduled */
		bool ack_pending : 1;
		/* non-stream-0 frames fully flushed but not yet acked.
		 * Frame pointer ring; O(1) trim by advancing head. */
		struct mux_frame_ring *unacked;
		/* Offset from unacked->entries[unacked->head] to the first
		 * un-retransmitted frame when replaying after a resume;
		 * SIZE_MAX when no retransmit is in progress. */
		size_t retransmit_off;
		/* transient copy currently queued/flushing for retransmission;
		 * NULL when no retransmit copy is in flight */
		struct mux_frame *retransmit_copy;
	};

	/* Session negotiation results: identity, peer capabilities, service IDs. */
	struct handshake_ctx handshake;

	/* BDP/RTT estimator for auto stream-window mode. */
	struct estimator_ctx estimator;

	/* Reconnection state */
	struct {
		/* monotonic ns when SESSION_CONNECT entered */
		intmax_t connect_started;
	};
};

/* Acquire a frame for the session, reusing the one-deep spare when present.
 * The returned frame carries the same freshly-reset state as mux_frame_get. */
static inline struct mux_frame *
session_frame_alloc(struct mux_session *restrict ss)
{
	struct mux_frame *const frame = ss->frame_spare;
	if (frame == NULL) {
		return mux_frame_get(&ss->pool);
	}
	ss->frame_spare = NULL;
	frame->pos = 0;
	frame->len = 0;
	frame->next = NULL;
	return frame;
}

/* Release a frame back to the session, retaining it as the spare when the
 * cache slot is free; otherwise it returns to the shared allocator. */
static inline void session_frame_free(
	struct mux_session *restrict ss, struct mux_frame *restrict frame)
{
	if (ss->frame_spare == NULL) {
		ss->frame_spare = frame;
		return;
	}
	mux_frame_put(&ss->pool, frame);
}

#define MUX_LOG_F(level, ss, format, ...)                                      \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, "%s " format,                                     \
		      (ss)->tag != NULL ? (ss)->tag : "[?]:", __VA_ARGS__);    \
	} while (0)
#define MUX_LOG(level, ss, message) MUX_LOG_F(level, ss, "%s", message)

/* Allocate and initialize a new session; takes ownership of opts->fd. */
struct mux_session *
session_new(struct ev_loop *restrict loop, const struct mux_session_opts *opts);

/* Tear down and free a session; caller must remove it from external lists first. */
void session_close(struct mux_session *restrict ss);

/* Apply a new configuration snapshot; safe to call on a running session. */
void session_set_config(
	struct mux_session *restrict ss,
	const struct mux_config *restrict conf);

/* Begin I/O: accepted -> start handshake; client (fd=-1) -> no-op;
 * call mux_attach_fd() afterward to supply a connected fd. */
void session_start(struct mux_session *restrict ss);

/* Accept an already-connected fd and transition to SESSION_CONNECT.
 * Valid from SESSION_INIT (initial client connect), SESSION_SUSPENDED
 * (resume attempt), or SESSION_CLOSED (demand-triggered reconnect after
 * idle-close or resume-timeout expiry).  Takes ownership of fd. */
void session_attach_fd(struct mux_session *restrict ss, int fd);

/* Drop in-flight data, close all streams, and begin the transport close sequence. */
void session_initiate_shutdown(struct mux_session *restrict ss);

/* Signal the session to drain: reject new inbound streams and initiate a
 * graceful shutdown as soon as the last active stream closes.  If the session
 * is already idle (no streams), shutdown is initiated immediately.  Cleared
 * automatically when the session reconnects via session_attach_fd(). */
void session_drain(struct mux_session *ss);

/* Open a new locally-initiated stream; returns NULL when the session rejects it. */
struct mux_stream *session_open_stream(struct mux_session *restrict ss);

/* Remove all unsent non-RST frames for stream_id from the session send buffer.
 * RST frames are preserved so a previously-queued RST is never suppressed.
 * Must be called before sending a new RST so stale ACK/FIN/PUSH entries do
 * not arrive at the peer ahead of the RST. */
void session_discard_stream_frames(
	struct mux_session *restrict ss, uint_fast16_t stream_id);

/* Recompute and apply the correct EV_READ/EV_WRITE mask for the mux socket watcher. */
void session_notify(struct mux_session *restrict ss);

/** Prebuilt table_opts for the per-session stream table, keyed by stream ID.
 * Uses a 16-bit integer hash suitable for the stream-ID key space. */
extern const struct table_opts mux_stream_table_opts;

/* Enqueue a PUSH data frame for stream s into the send buffer; takes ownership of frame. */
bool session_send_push(
	struct mux_session *ss, struct mux_stream *s, struct mux_frame *frame);

/* Enqueue a packed control frame for stream_id with the given flags and extra value. */
bool session_send_ctrl(
	struct mux_session *restrict ss, uint_fast16_t stream_id,
	uint_fast8_t flags, uint_fast32_t extra);

/* Enqueue one out-of-band stream-0 frame (PROBE/PING/PONG).
	 * payload_len is the exact payload size to encode; pass NULL to
	 * zero-fill the payload.  Returns true on success, false on OOM. */
bool session_send_oob(
	struct mux_session *restrict ss, uint_fast8_t extra,
	const unsigned char *restrict payload, size_t payload_len);

/* Flush the send buffer once; call after enqueuing control frames outside the I/O callback. */
void session_flush(struct mux_session *restrict ss);

/* Flush OOB control frames (PING/PONG/PROBE) to the wire immediately, bypassing
 * EV_WRITE and the scheduler queue.  Drives send_cb inline when not already
 * pending; no-op when state != SESSION_ESTABLISHED.  Call after ringbuf_consume
 * to guarantee the receive frame has been retired before any teardown that
 * send_cb may trigger. */
void session_flush_oob(struct mux_session *restrict ss);

/* Wake the scheduler for stream s and, if EV_WRITE was not already pending,
 * flush the send pipeline inline to avoid an extra libev iteration.
 * Must only be called from stream.c:recv_cb(); do not call from any path
 * that may already be inside session.c:send_cb(). */
void session_eager_flush(
	struct mux_session *restrict ss, struct mux_stream *restrict s);

/* Co-unit internal interface: used by handshake.c and dispatch.c.
 * Do not call from unrelated translation units. */

/* Log a parsed frame header at VERYVERBOSE level. */
void session_log_frame_header(
	struct mux_session *restrict ss, const char *restrict what,
	const unsigned char *restrict raw,
	const struct mux_header *restrict hdr);

/* Internal callbacks: declared here so handshake.c and dispatch.c can call
 * back into session.c. handshake, dispatch, and wire are co-units; do not
 * call these from unrelated TUs. */

/* Close the transport and transition to SESSION_CLOSED.
 * For established sessions that qualify for resumption, use session_suspend()
 * instead; session_reset() discards all stream and unacked state. */
void session_reset(struct mux_session *ss);

/* Call session_reset then fire MUX_EVENT_CLOSED if the session closed.
 * expired is set when the event is triggered by a resume-timeout. */
void session_notify_closed(struct mux_session *restrict ss, bool expired);

/* Suspend the transport on error, preserving stream and unacked state for resume. */
void session_suspend(struct mux_session *ss);

/* Complete session establishment after a successful hello exchange. */
void session_handshake_done(struct mux_session *ss);

/* Migrate transport fd from new_ss, send ServerHello, and start retransmission. */
bool session_resume_transport(
	struct mux_session *restrict ss, struct mux_session *restrict new_ss,
	uint_least32_t client_resume_seq);

/* Trim count frames from the unacked ring after a session-level ACK from the peer. */
bool session_ack_trim(struct mux_session *restrict ss, uint_fast32_t count);

/* Discard all frames in the unacked ring, free the ring array, and reset
 * counters.  Defined inline so handshake tests can use it without linking
 * the full session TU. */
static inline void unacked_ring_free_all(struct mux_session *restrict ss)
{
	mux_frame_ring_free(&ss->unacked, &ss->pool);
	ss->unacked_frames = 0;
	ss->retransmit_off = SIZE_MAX;
}

/* Apply the peer's resume_seq to trim our unacked ring on session resume. */
bool session_resume_ack_recv(
	struct mux_session *restrict ss, uint_least32_t peer_ack);

/* Emit a session-level ACK for all unacknowledged non-stream-0 frames. */
void session_emit_ack(struct mux_session *restrict ss);

/* Process an inbound PING: send PONG if rate limit permits. */
void session_recv_ping(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	size_t frame_size);

/* Process an inbound PONG: feed timestamp to the BDP estimator. */
void session_recv_pong(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	size_t frame_size);

/* Update session_window from the current peer_stream_window value.
 * Must be called after each SYN and SYN|ACK that changes peer_stream_window.
 * No-op when auto_session_window is false. */
void session_update_session_window(struct mux_session *restrict ss);

#endif /* MUX_SESSION_H */
