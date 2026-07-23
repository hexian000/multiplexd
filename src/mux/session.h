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
#include "mux/unacked.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <netinet/tcp.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

struct mux_stream;
struct mux_session;
struct tls_context;
struct tls_connection;
struct hashtable;

/* Socket/event helpers shared by session.c and stream.c. */

static inline void modify_io_events(
	struct ev_loop *restrict loop, ev_io *restrict watcher,
	const int events)
{
	const int fd = watcher->fd;
	ASSERT(fd != -1);
	const int ioevents = events & (EV_READ | EV_WRITE);
	if (ioevents == EV_NONE) {
		if (ev_is_active(watcher)) {
			LOGV_F("io: [fd:%d] stop", fd);
			ev_io_stop(loop, watcher);
		}
		return;
	}
	if (ioevents != (watcher->events & (EV_READ | EV_WRITE))) {
		ev_io_stop(loop, watcher);
#ifdef ev_io_modify
		ev_io_modify(watcher, ioevents);
#else
		ev_io_set(watcher, fd, ioevents);
#endif
	}
	if (!ev_is_active(watcher)) {
		LOGV_F("io: [fd:%d] events=0x%x", fd, ioevents);
		ev_io_start(loop, watcher);
	}
}

/* Set TCP_USER_TIMEOUT (@p ms); 0 on success, -1 if unsupported or setsockopt
 * fails. */
static inline int socket_user_timeout(const int fd, const int ms)
{
#if WITH_TCP_USER_TIMEOUT
	if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &ms, sizeof(ms)) !=
	    0) {
		const int err = errno;
		LOGW_F("setsockopt [fd:%d]: TCP_USER_TIMEOUT (%d) %s", fd, err,
		       strerror(err));
		return -1;
	}
	return 0;
#else /* WITH_TCP_USER_TIMEOUT */
	(void)fd;
	(void)ms;
	return -1;
#endif /* WITH_TCP_USER_TIMEOUT */
}

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

/* struct sched_ctx is defined in sched.h and struct handshake_ctx in
 * handshake.h; both are embedded by value in mux_session below. */

/* COUNTER_ADD/SUB/LOAD operate on mux_session_counters pointer fields; all are
 * NULL-safe (skipped, returning 0, when the pointer is NULL). */
#if WITH_THREADS
#define COUNTER_ADD(p, v)                                                      \
	((p) ? atomic_fetch_add_explicit((p), (v), memory_order_relaxed) : 0)
#define COUNTER_SUB(p, v)                                                      \
	((p) ? atomic_fetch_sub_explicit((p), (v), memory_order_relaxed) : 0)
#define COUNTER_LOAD(p)                                                        \
	((p) ? atomic_load_explicit((p), memory_order_relaxed) : 0)
#else /* WITH_THREADS */
#define COUNTER_ADD(p, v) ((p) ? (*(p) += (uint_least64_t)(v)) : 0)
#define COUNTER_SUB(p, v) ((p) ? (*(p) -= (uint_least64_t)(v)) : 0)
#define COUNTER_LOAD(p) ((p) ? *(p) : 0)
#endif /* WITH_THREADS */

/* PUB_STORE/PUB_LOAD publish session-thread-owned scalars to relaxed-atomic
 * mirrors for race-free cross-thread reads; unlike COUNTER_*, they operate on
 * field lvalues (never NULL), sidestepping the -Waddress check on &field. */
#if WITH_THREADS
#define PUB_STORE(field, v)                                                    \
	atomic_store_explicit(&(field), (v), memory_order_relaxed)
#define PUB_LOAD(field) atomic_load_explicit(&(field), memory_order_relaxed)
#else
#define PUB_STORE(field, v) ((void)((field) = (v)))
#define PUB_LOAD(field) (field)
#endif /* WITH_THREADS */

/* All fields of mux_session are accessed only from the owning ev_loop thread. */
struct mux_session {
	struct ev_loop *loop;
	struct mux_config conf;
	/* Frame allocator; set at creation time and never changed. */
	struct mux_frame_allocator pool;
	/* Authoritative logical max outbound frame payload, frozen from conf at
	 * creation.  Framing paths size buffers and bound lengths by this; the
	 * physical buffer capacity is carried per frame as frame->cap (>= this). */
	uint_least32_t max_payload;
	/* Receive read-ahead window in bytes, frozen from conf at creation; 0
	 * disables read-ahead (recv falls back to a one-frame window). */
	size_t readahead;
	/* Non-owning pointer to the session log tag buffer; set at creation time. */
	const char *tag;
	/* Pointer block into server_stats; NULL pointers are silently skipped. */
	struct mux_session_counters cnt;
	size_t num_halfopen;
	/* Per-session flow-control counters; also mirrored to server aggregates
	 * via cnt when set. */
	size_t recv_buffered_bytes;
	size_t send_buffered_frames;
	int_least64_t last_connect_latency_ns;
	/* Total mux bytes received, for diagnostics. */
	uint_least64_t bytes_recv;
	/* Monotonic ns of the last inbound PING; for PING rate limiting. */
	int_least64_t ping_recv_last_ns;
	enum session_state state;
	int_least64_t last_modified;
	/* Peer address captured when session reaches SESSION_ESTABLISHED. */
	union sockaddr_max peer_addr;
	struct mux_callbacks callbacks;
	void *userdata;

	/* Event watchers */
	struct {
		/* fd is closed exactly once (guarded by != -1, reset to -1
		 * after) by mux_session_suspend/session_cleanup; never close it
		 * directly elsewhere (e.g. tunnel.c's task_drop_transport). */
		ev_io w_socket;
		ev_timer w_timeout;
		ev_timer w_keepalive;
		ev_timer w_send_timeout;
		ev_timer w_connect_timeout;
		ev_timer w_idle_timeout;
	};

	/* true for accepted (server-role) sessions */
	bool accepted : 1;
	/* stream_window configured as 0: track the RX BDP estimate automatically. */
	bool auto_stream_window : 1;
	/* session_window configured as 0: track the TX BDP estimate automatically. */
	bool auto_session_window : 1;
	/* shut down once the last stream closes; set by mux_session_drain(). */
	bool draining : 1;

	/* Unacked-frame cap (the send-stall gate); auto mode tracks the TX BDP
	 * above an initial-window floor. */
	uint_least32_t session_window;
	/* Per-stream receive window (frames); auto mode tracks the RX BDP.
	 * Granted recv_window is not clawed back on shrink. */
	uint_least32_t stream_window;
	/* Peer's per-stream receive window (frames); updated on each SYN/SYN|ACK. */
	uint_least32_t peer_stream_window;

	/* Relaxed-atomic mirrors of session-thread-owned gauges, published at their
	 * write sites so mux_state()/mux_session_stats() can be read race-free from
	 * the server thread (the /stats path).  Never read on the data path. */
#if WITH_THREADS
	atomic_int _pub_state; /* mirrors enum session_state */
	atomic_size_t _pub_stream_window;
	atomic_size_t _pub_peer_stream_window;
	atomic_int_least64_t _pub_rtt;
	atomic_size_t _pub_bdp_rx;
	atomic_size_t _pub_bdp_tx;
#else /* WITH_THREADS */
	enum session_state _pub_state;
	size_t _pub_stream_window;
	size_t _pub_peer_stream_window;
	int_least64_t _pub_rtt;
	size_t _pub_bdp_rx;
	size_t _pub_bdp_tx;
#endif /* WITH_THREADS */

	/* Transport I/O state (socket buffers, TLS connection, flow-control flags). */
	struct wire_ctx wire;

	/* Stream scheduling and table state. */
	struct sched_ctx sched;

	/* Session-level ACK, unacked ring, and retransmission state (spec §5.7). */
	struct unacked_ctx unacked;

	/* Session negotiation results: identity, peer capabilities, service IDs. */
	struct handshake_ctx handshake;

	/* BDP/RTT estimator for auto stream-window mode. */
	struct estimator_ctx estimator;

	/* Reconnection state: monotonic ns when SESSION_CONNECT entered. */
	int_least64_t connect_started;
};

#define MUX_LOG_F(level, ss, format, ...)                                      \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, "%s " format,                                     \
		      (ss)->tag != NULL ? (ss)->tag : "[?]:", __VA_ARGS__);    \
	} while (0)
#define MUX_LOG(level, ss, message) MUX_LOG_F(level, ss, "%s", message)

/* Fire a session event to the owner's callback, if one is registered. */
static inline void session_emit(
	struct mux_session *restrict ss, const enum mux_event event,
	const union mux_event_data data)
{
	if (ss->callbacks.on_event != NULL) {
		ss->callbacks.on_event(ss->userdata, ss, event, data);
	}
}

/* Set the local per-stream receive window and publish its mirror. */
static inline void session_set_stream_window(
	struct mux_session *restrict ss, const uint_least32_t frames)
{
	ss->stream_window = frames;
	PUB_STORE(ss->_pub_stream_window, (size_t)frames);
}

/* Set the peer's advertised per-stream window and publish its mirror. */
static inline void session_set_peer_stream_window(
	struct mux_session *restrict ss, const uint_least32_t frames)
{
	ss->peer_stream_window = frames;
	PUB_STORE(ss->_pub_peer_stream_window, (size_t)frames);
}

/* Publish the estimator's rtt/bdp gauges to their mirrors; call after any
 * estimator update (mux_estimator_calculate / mux_estimator_init). */
static inline void session_publish_estimate(struct mux_session *restrict ss)
{
	PUB_STORE(ss->_pub_rtt, ss->estimator.rtt);
	PUB_STORE(ss->_pub_bdp_rx, ss->estimator.rx.bdp);
	PUB_STORE(ss->_pub_bdp_tx, ss->estimator.tx.bdp);
}

/* True once the graceful-drain cascade has bulk-freed the session's streams.
 * Closing the last active stream of a draining session runs stream_mark_closed
 * -> mux_sched_check_no_active_streams -> mux_session_initiate_shutdown ->
 * mux_sched_free_streams, which frees every struct mux_stream and nulls the
 * scheduler's stream table (the struct mux_session itself survives; the same
 * shutdown also runs mux_wire_discard_buffers, resetting the recvbuf). Within a
 * single synchronous callback that is the only path that frees a stream, so a
 * recv/flush caller that just invoked such a path must re-check this before
 * touching the stream again -- or consuming the recvbuf, which the cascade has
 * reset out from under it. */
static inline bool session_streams_freed(const struct mux_session *restrict ss)
{
	return ss->sched.streams == NULL;
}

/* Recompute and apply the EV_READ/EV_WRITE mask for the mux socket watcher.
 * Shared by session.c and the send/recv pipelines. */
void mux_session_update_watcher(struct mux_session *restrict ss);

/* conf.keepalive scaled by a random jitter factor; shared with recv.c so a
 * received PONG can re-arm the keepalive deadline. */
double mux_keepalive_interval(const struct mux_session *restrict ss);

/* Allocate and initialize a new session; takes ownership of opts->fd. */
struct mux_session *mux_session_new(
	struct ev_loop *restrict loop, const struct mux_session_opts *opts);

/* Tear down and free a session; caller must remove it from external lists first. */
void mux_session_close(struct mux_session *restrict ss);

/* Apply a new configuration snapshot; safe to call on a running session. */
void mux_session_set_config(
	struct mux_session *restrict ss,
	const struct mux_config *restrict conf);

/* Begin I/O: accepted -> start handshake; client (fd=-1) -> no-op;
 * call mux_attach_fd() afterward to supply a connected fd. */
void mux_session_start(struct mux_session *restrict ss);

/* Accept a connected fd and transition to SESSION_CONNECT.
 * Valid from SESSION_INIT (initial connect), SESSION_SUSPENDED (resume),
 * or SESSION_CLOSED (reconnect after idle/timeout).  Takes fd ownership. */
void mux_session_attach_fd(struct mux_session *restrict ss, int fd);

/* Drop in-flight data, close all streams, and begin the transport close sequence. */
void mux_session_initiate_shutdown(struct mux_session *restrict ss);

/* Drain: reject new inbound streams and begin graceful shutdown when the last
 * stream closes (or immediately if already idle); cleared by mux_session_attach_fd()
 * on a genuinely fresh (re)connect, but preserved across a resume from
 * SUSPENDED so a transport blip can't silently cancel a pending drain. */
void mux_session_drain(struct mux_session *restrict ss);

/* Open a new locally-initiated stream; returns NULL when the session rejects it. */
struct mux_stream *mux_session_open_stream(struct mux_session *restrict ss);

/* Request a deferred flush: mark egress pending and arm EV_WRITE. */
void mux_session_notify(struct mux_session *restrict ss);

/** Prebuilt table_opts for the per-session stream table, keyed by stream ID.
 * Uses a 16-bit integer hash suitable for the stream-ID key space. */
extern const struct table_opts mux_stream_table_opts;

/* Frame producers and flush entry points live in send.h;
 * frame dispatch and receive-side window updates live in recv.h. */

/* Log a parsed frame header at VERYVERBOSE level. */
void mux_session_log_frame_header(
	const struct mux_session *restrict ss, const char *restrict what,
	const unsigned char *restrict raw,
	const struct mux_header *restrict hdr);

/* Internal callbacks: declared here so handshake.c and recv.c can call
 * back into session.c. handshake, recv, and wire are co-units; do not
 * call these from unrelated TUs. */

/* Transition the session state machine to newstate, emitting the
 * corresponding lifecycle events and (re)arming timers.  Exposed so the send
 * pipeline can drive SESSION_CLOSING on a peer-closed transport. */
void mux_session_set_state(struct mux_session *ss, enum session_state newstate);

/* Close the transport and transition to SESSION_CLOSED.
 * For established sessions that qualify for resumption, use mux_session_suspend()
 * instead; mux_session_reset() discards all stream and unacked state. */
void mux_session_reset(struct mux_session *ss);

/* Call mux_session_reset then fire MUX_EVENT_CLOSED if the session closed.
 * expired is set when the event is triggered by a resume-timeout. */
void mux_session_notify_closed(struct mux_session *restrict ss, bool expired);

/* Suspend the transport on error, preserving stream and unacked state for resume. */
void mux_session_suspend(struct mux_session *restrict ss);

/* On a transport loss, mux_session_suspend() a resumable session (preserving its
 * streams) or mux_session_reset() it otherwise. */
void mux_session_suspend_or_reset(struct mux_session *restrict ss);

/* Complete session establishment after a successful hello exchange. */
void mux_session_handshake_done(struct mux_session *ss);

/* Resume handoff primitives (mux_transport_detach / mux_resume_attach /
 * mux_transport_discard) are declared in mux.h: the owner orchestrates any
 * cross-loop handoff, so they are part of the public, loop-agnostic API. */

#endif /* MUX_SESSION_H */
