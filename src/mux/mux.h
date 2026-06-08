/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file mux.h
 * @brief Public mux session and stream API.
 */

#ifndef MUX_H
#define MUX_H

#include <ev.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

struct mux_callbacks;
struct mux_frame;
struct mux_session;
struct mux_stream;

#if WITH_TLS
struct tls_context;
struct tls_connection;
#endif

/* --- Protocol constants --- */

/* Maximum frame payload in bytes; equals the window credit unit. */
#define MUX_MAX_PAYLOAD_SIZE 16384u

/* Window field unit: the wire Extra field counts credit in MUX_WINDOW_UNIT bytes. */
#define MUX_WINDOW_UNIT MUX_MAX_PAYLOAD_SIZE

/* Initial per-stream send window before BDP estimation converges. */
#define MUX_INITIAL_SEND_WINDOW 65536u

/* Session identity length in bytes; transmitted as Base64 in the hello JSON. */
#define MUX_SESSION_ID_LEN 16u

/* --- Frame allocator --- */

/* Caller-supplied allocator for mux_frame objects; passed to mux_new() and
 * shared across sessions that use a common pool. */
struct mux_frame_allocator {
	struct mux_frame *(*alloc)(void *data);
	void (*free)(void *data, struct mux_frame *frame);
	void *data;
};

/* Returns the allocation size of a mux_frame object.
 * Use in frame pool implementations instead of sizeof(struct mux_frame). */
size_t mux_frame_object_size(void);

/* Traffic byte counters; embedded in mux_session_counters. */
struct mux_traffic_counters {
#if WITH_THREADS
	atomic_uint_least64_t *byt_mux_recv;
	atomic_uint_least64_t *byt_mux_sent;
	/* PUSH-frame payload bytes only (no frame headers, no non-PUSH frames) */
	atomic_uint_least64_t *byt_push_recv;
	atomic_uint_least64_t *byt_push_sent;
#else
	uint_least64_t *byt_mux_recv;
	uint_least64_t *byt_mux_sent;
	/* PUSH-frame payload bytes only (no frame headers, no non-PUSH frames) */
	uint_least64_t *byt_push_recv;
	uint_least64_t *byt_push_sent;
#endif
};

/* Pointer-block into server_stats for direct session-thread updates
 * (counters route; see src/server.h).  Pointer fields point to
 * server_counters atomic or plain counters depending on the build mode.
 * NULL pointers are silently skipped by COUNTER_*. */
struct mux_session_counters {
#if WITH_THREADS
	atomic_uint_least64_t *num_session_created;
	atomic_uint_least64_t *num_session_connect;
	atomic_uint_least64_t *num_session_connected;
	atomic_uint_least64_t *num_session_disconnected;
	atomic_uint_least64_t *num_session_finalized;
	atomic_size_t *num_sessions;
	atomic_size_t *num_session_halfopen;
	atomic_size_t *num_streams;
	atomic_size_t *num_stream_halfopen;
	atomic_uint_least64_t *num_stream_opened;
	atomic_uint_least64_t *num_stream_accepted;
	atomic_uint_least64_t *num_stream_fastopen;
	atomic_uint_least64_t *num_stream_established;
	atomic_uint_least64_t *num_stream_succeeded;
	atomic_uint_least64_t *num_stream_failed;
	atomic_uint_least64_t *num_rst_sent;
	atomic_uint_least64_t *num_rst_recv;
	atomic_uint_least64_t *num_stream_errors;
	atomic_size_t *recv_buffered_bytes;
	atomic_size_t *send_buffered_frames;
	atomic_size_t *unacked_frames;
#else
	uint_least64_t *num_session_created;
	uint_least64_t *num_session_connect;
	uint_least64_t *num_session_connected;
	uint_least64_t *num_session_disconnected;
	uint_least64_t *num_session_finalized;
	size_t *num_sessions;
	size_t *num_session_halfopen;
	size_t *num_streams;
	size_t *num_stream_halfopen;
	uint_least64_t *num_stream_opened;
	uint_least64_t *num_stream_accepted;
	uint_least64_t *num_stream_fastopen;
	uint_least64_t *num_stream_established;
	uint_least64_t *num_stream_succeeded;
	uint_least64_t *num_stream_failed;
	uint_least64_t *num_rst_sent;
	uint_least64_t *num_rst_recv;
	uint_least64_t *num_stream_errors;
	size_t *recv_buffered_bytes;
	size_t *send_buffered_frames;
	size_t *unacked_frames;
#endif
	struct mux_traffic_counters traffic;
};

/* --- Mux configuration subset --- */

/* Configuration snapshot copied from the caller at session creation. */
struct mux_config {
	/* Maximum number of concurrent streams per session. */
	int max_streams;
	/* Maximum number of half-open (unacknowledged SYN) streams. */
	int max_halfopen;

	/* Timeout in seconds for a single TCP-connect and mux-handshake attempt. */
	int connect_timeout;
	/* Inactivity timeout in seconds before the session is considered dead. */
	int timeout;
	/* Interval in seconds between keepalive PROBE probes. */
	int keepalive;
	/* Timeout in seconds for a PING response in the BDP estimator. */
	int ping_timeout;
	/* Timeout in seconds for a blocked send before the session is reset. */
	int send_timeout;
	/* Seconds of stream-idle time before the session is shut down. */
	int idle_timeout;
	/* Seconds a suspended server session waits for the client to resume. */
	int resume_timeout;

	/* Maximum unacknowledged frames in flight for the whole session. */
	int session_window;
	/* Per-stream receive window size in frames. */
	int stream_window;

	/* Receive-buffer level in bytes at which window grants are fully suppressed; 0 disables pressure scaling. */
	int mem_pressure_hi;
	/* Receive-buffer level in bytes at which window-grant scaling begins (default: hi/2). */
	int mem_pressure_lo;

	/* Send frames immediately without coalescing. */
	bool nodelay : 1;
	/* Reject new inbound streams opened by the peer. */
	bool reject_inbound : 1;

#if WITH_TLS
	/* TLS context for outbound reconnects; NULL leaves the existing context unchanged. */
	struct tls_context *tlsctx;
#endif
};

/* --- Session creation options --- */

/* Options passed to mux_new().  Takes ownership of fd when fd >= 0.
 * String pointers are copied if non-NULL.
 * cnt pointer fields may be NULL; skipped when updating server-level counters. */
struct mux_session_opts {
	const struct mux_callbacks *callbacks;
	void *userdata;
	const struct mux_config *conf;
	int fd;
	const unsigned char *id;
	/* Identity claimed in hello; copied if non-NULL. */
	const char *identity;
	/* Internal peer label for diagnostics; NOT transmitted; copied if non-NULL. */
	const char *peer_id;
	/* Pointer-block into server_stats; all NULL pointers are silently skipped. */
	struct mux_session_counters cnt;
	/* Frame allocator; data field is set by the caller per-session. */
	struct mux_frame_allocator pool;
	/* Non-owning pointer to the session log tag buffer; must outlive the session. */
	char *tag;
#if WITH_TLS
	struct tls_context *tlsctx;
	struct tls_connection *conn;
#endif
};

/* --- Session lifecycle --- */

/* Allocate a new session.  Takes ownership of opts->fd. */
struct mux_session *
mux_new(struct ev_loop *restrict loop, const struct mux_session_opts *opts);

/* Tear down and free a session.  Caller must remove it from external lists first. */
void mux_close(struct mux_session *ss);
/* Clear all callbacks on a session.  Safe to call from any thread after the
 * session's worker thread has been joined. */
void mux_set_callbacks(struct mux_session *ss, const struct mux_callbacks *cb);

/* Initiate graceful shutdown: drop in-flight data, close all streams,
 * begin the transport-level close handshake (TLS close_notify then TCP
 * half-close).  MUX_EVENT_CLOSED is emitted asynchronously when done. */
void mux_shutdown(struct mux_session *ss);

/* Start I/O: inbound → begin handshake; outbound (fd=-1) → no-op;
 * call mux_attach_fd() afterward to supply a connected fd. */
void mux_start(struct mux_session *ss);

/* Attach an already-connected fd to a client session.
 * Valid from SESSION_INIT (initial connect) or SESSION_SUSPENDED (resume).
 * The caller is responsible for creating the socket, calling connect(), and
 * configuring TCP options before passing fd here.  Takes ownership of fd.
 * Transitions the session to SESSION_CONNECT. */
void mux_attach_fd(struct mux_session *ss, int fd);

/* --- Session accessors --- */

int mux_fd(const struct mux_session *ss);

#if WITH_TLS
/* Returns the TLS connection object, or NULL when TLS is not in use.
 * The returned pointer is owned by the session and must not be freed. */
struct tls_connection *mux_tls_conn(const struct mux_session *ss);
#endif

/* Returns NULL before SESSION_ESTABLISHED. */
const struct sockaddr *mux_peer_addr(const struct mux_session *ss);

enum mux_state {
	MUX_STATE_ESTABLISHED,
	MUX_STATE_CONNECT,
	MUX_STATE_CLOSED,
	MUX_STATE_SUSPENDED,
};

enum mux_state mux_state(const struct mux_session *ss);

/* Returns the 16-byte session identity.
 * For accepted sessions this equals the id passed to mux_new().
 * For dialed sessions this starts as the local id and is replaced by the
 * server-assigned value when ServerHello arrives. */
const unsigned char *mux_session_id(const struct mux_session *ss);

/* Returns a read-only pointer to the session's configuration snapshot. */
const struct mux_config *mux_conf(const struct mux_session *ss);

/* Snapshot of per-session estimator state.  Filled by mux_session_stats(). */
struct mux_session_stats {
	/* Per-stream receive window advertised to the peer, in bytes. */
	size_t rx_window;
	/* Per-stream send window limited by the peer, in bytes. */
	size_t tx_window;
	/* Round-trip time in nanoseconds; 0 when no measurement has been
	 * completed yet. */
	int_least64_t rtt;
	/* Bandwidth-delay product in bytes; 0 if not yet estimated. */
	size_t bdp;
};

/* Populate *out with a consistent snapshot of session estimator state. */
void mux_session_stats(
	const struct mux_session *ss, struct mux_session_stats *restrict out);

/* --- Session mutators --- */

/* Replace the session's configuration snapshot (config reload).
 * When WITH_TLS, a non-NULL conf->tlsctx also replaces the TLS context
 * for outbound reconnects; NULL leaves the existing context unchanged. */
void mux_set_config(
	struct mux_session *ss, const struct mux_config *restrict conf);

/* Signal the session to drain: stop accepting new inbound streams and
 * initiate a graceful shutdown as soon as the last active stream closes.
 * If the session is already idle, shutdown is initiated immediately.
 * Cleared automatically when the session reconnects (mux_attach_fd()). */
void mux_drain(struct mux_session *ss);

enum mux_event {
	/* Connect or handshake attempt started; fires per attempt. */
	MUX_EVENT_CONNECT,
	/* Connect or handshake attempt ended before ESTABLISHED. */
	MUX_EVENT_CONNECT_FAILED,
	/* Initial handshake completed on this session object. */
	MUX_EVENT_ESTABLISHED,
	/* Established transport went away; emitted whenever the session
	 * leaves ESTABLISHED. */
	MUX_EVENT_LOST,
	/* Transport was lost and the session is now SESSION_SUSPENDED.
	 * Resume-capable callers may wait for a peer reconnect or attach a new
	 * connected fd with mux_attach_fd(). */
	MUX_EVENT_SUSPENDED,
	/* Suspended session finished the resume handshake. */
	MUX_EVENT_RESUMED,
	/* Active-open stream established (SYN|ACK received). */
	MUX_EVENT_STREAM_ESTABLISHED,
	/* Session reached its terminal state; on_event fires before mux_close(). */
	MUX_EVENT_CLOSED,
};

/* Payload for on_event().
 * ESTABLISHED, RESUMED: .connected.ns is session setup latency;
 *   .connected.peer_id is the peer's internal label;
 *   .connected.peer_identity is the identity claimed in the peer's hello.
 * STREAM_ESTABLISHED: .stream_established.ns is SYN-to-SYN|ACK latency.
 * SUSPENDED: the session is already in SESSION_SUSPENDED.
 * CLOSED: .closed.clean reports peer FIN or TLS close_notify;
 *   .closed.expired is true when the session was in SESSION_SUSPENDED and
 *   the resume_timeout fired (peer never reconnected).
 * Other events: zero-initialized. */
union mux_event_data {
	/* ESTABLISHED, RESUMED */
	struct {
		intmax_t ns;
		const char *peer_id;
		const char *peer_identity;
	} connected;
	/* STREAM_ESTABLISHED */
	struct {
		intmax_t ns;
	} stream_established;
	/* CLOSED */
	struct {
		bool clean;
		bool expired;
	} closed;
};

/*
 * on_accept   Called for each new inbound stream.  Must call
 *             mux_stream_attach() or mux_stream_io_start() and return true
 *             to accept, or return false to reject.
 * on_event    Called on session lifecycle changes. Typical resume-capable
 *             sequence: CONNECT → ESTABLISHED, then LOST → SUSPENDED,
 *             then CONNECT → RESUMED. LOST fires whenever the session
 *             leaves ESTABLISHED.
 *             MUX_EVENT_CLOSED fires before mux_close.
 * on_resume   Called on the new (transient) session when a resume hello
 *             arrives.  Match session_id against suspended sessions and
 *             return the matching mux_session, or NULL for a fresh session.
 */
struct mux_callbacks {
	bool (*on_accept)(
		void *data, const struct mux_session *, struct mux_stream *);
	void (*on_event)(
		void *data, struct mux_session *, enum mux_event,
		union mux_event_data);
	struct mux_session *(*on_resume)(
		void *data, struct mux_session *new_ss,
		const unsigned char *session_id);
};

/* --- Stream I/O watcher --- */

/*
 * Per-stream I/O event watcher for direct (non-attach-fd) mode.
 * EV_READ  – data available, peer FIN (returns 0), or RST (returns -1/ECONNRESET)
 * EV_WRITE – send window open
 */
typedef struct mux_stream_io mux_stream_io;
struct mux_stream_io {
	EV_WATCHER(mux_stream_io)
	/* private */
	struct ev_loop *loop;
	struct mux_stream *stream;
	/* EV_READ | EV_WRITE */
	int events;
};

#define mux_stream_io_init(w, cb_, s_, events_)                                \
	do {                                                                   \
		ev_init((w), (cb_));                                           \
		mux_stream_io_set((w), (s_), (events_));                       \
	} while (0)

#define mux_stream_io_set(w, s_, events_)                                      \
	do {                                                                   \
		(w)->stream = (s_);                                            \
		(w)->events = (events_);                                       \
	} while (0)

/* Activate the watcher; begins direct I/O mode.
 * For passive-open streams sends SYN|ACK and transitions to ESTABLISHED. */
void mux_stream_io_start(struct ev_loop *loop, mux_stream_io *restrict w);

void mux_stream_io_modify(
	struct ev_loop *loop, mux_stream_io *restrict w, int events);

void mux_stream_io_stop(struct ev_loop *loop, mux_stream_io *restrict w);

/* --- Stream operations --- */

/* Open a new outbound stream.  Returns NULL when the session is not
 * established or the halfopen backlog is full. */
struct mux_stream *mux_open_stream(struct mux_session *ss);

/* Attach a local socket fd to a stream; takes ownership of fd.
 * Data transfer is blocked until the peer replies with SYN|ACK.
 * Mutually exclusive with mux_stream_io_start(). */
void mux_stream_attach(struct mux_stream *s, int fd);

uint_least16_t mux_stream_id(const struct mux_stream *s);

/* Queue up to *len bytes for sending.  On return *len holds bytes queued
 * (may be less if the window is partially full, or zero when exhausted —
 * retry after EV_WRITE).  Returns -1/EINVAL when not in a writable state,
 * -1/EAGAIN when the frame pool is exhausted before any data is queued. */
int mux_stream_send(
	struct mux_stream *s, const void *restrict buf, size_t *restrict len);

/* Copy up to *len bytes from the receive buffer.  On return *len holds bytes
 * copied; zero means peer FIN.  Returns -1/ECONNRESET on RST, -1/EAGAIN
 * when no data is available.
 * When the local side has also sent FIN (state CLOSING) and the receive
 * buffer drains, the stream closes inside this call; in that case the caller
 * MUST NOT use the stream pointer again after receiving zero.  When the
 * local side has not yet sent FIN (state CLOSE_WAIT) the stream remains
 * valid; the caller is expected to follow up with mux_stream_shutdown()
 * or mux_stream_close(). */
int mux_stream_recv(
	struct mux_stream *restrict s, void *restrict buf,
	size_t *restrict len);

/* Half-close the write side (shutdown(fd, SHUT_WR)). */
void mux_stream_shutdown(struct mux_stream *s);

/* Close with close(fd) semantics: RST if receive buffer has unread data,
 * otherwise no protocol frame is sent (caller must have sent RST or FIN). */
void mux_stream_close(struct mux_stream *s);

#endif /* MUX_H */
