/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file mux.h
 * @brief Public mux session and stream API.
 */

#ifndef MUX_H
#define MUX_H

#include <ev.h>

#include <assert.h>
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

/**
 * @defgroup mux
 * @brief Multiplexed, resumable session/stream transport over a single byte
 * stream (optionally TLS).
 * @{
 */

/* --- Protocol constants --- */

/* Frame wire layout: an 8-byte header followed by the payload.  The per-session
 * payload cap is configurable (mux_config.max_frame_payload). */
#define MUX_FRAME_HEADER_SIZE 8u

/* Compile-time frame-buffer cap: the payload length is a 16-bit wire field, so
 * the largest legal payload is 65535 bytes.  The runtime per-session frame size
 * is configured up to this via mux_config.max_frame_payload. */
#define MUX_MAX_PAYLOAD_SIZE 65535u
#define MUX_MAX_FRAME_SIZE (MUX_FRAME_HEADER_SIZE + MUX_MAX_PAYLOAD_SIZE)

/* Wire Extra field counts window credit in units of this many bytes. */
#define MUX_WINDOW_UNIT 16384u

/* Auto stream/session receive-window floor (bytes) before BDP estimation
 * converges: the smallest value the auto stream_window/session_window and the
 * estimator's WNDSIZE_MIN are clamped up to. Despite the historical name it is
 * not a send window -- stream_new sets each stream's send window from
 * MUX_DEFAULT_SEND_WINDOW. */
#define MUX_INITIAL_SEND_WINDOW 65536u

/* The payload length is carried in a 16-bit wire field, so a full frame must
 * fit; and the receive-window floor must admit one max-size frame, otherwise a
 * just-read frame could exceed every credit grant and never drain (deadlock). */
static_assert(
	MUX_MAX_PAYLOAD_SIZE <= UINT16_MAX,
	"frame payload exceeds 16-bit length field");
static_assert(
	MUX_INITIAL_SEND_WINDOW >= MUX_MAX_PAYLOAD_SIZE,
	"receive-window floor must admit one max-size frame");

/* Session identity length in bytes; transmitted as Base64 in the hello JSON. */
#define MUX_SESSION_ID_LEN 16u

/* --- Frame allocator --- */

/**
 * @brief Caller-supplied allocator for mux_frame objects, passed to mux_new().
 * @note alloc returns a block of at least @p size bytes (or NULL); the mux
 * layer stamps the frame fields itself. Need not be thread-safe: the data
 * pointer is private to one session's thread.
 */
struct mux_frame_allocator {
	struct mux_frame *(*alloc)(void *data, size_t size);
	void (*free)(void *data, struct mux_frame *frame);
	void *data;
};

/* Smallest configurable frame payload: a 1 KiB minimum frame minus the header.
 * Must comfortably exceed the hello handshake JSON. */
#define MUX_MIN_FRAME_PAYLOAD (1024u - MUX_FRAME_HEADER_SIZE)

/**
 * @brief Allocation size of a mux_frame object holding up to @p max_payload
 * payload bytes.
 * @param max_payload Payload capacity in bytes.
 * @return Object size in bytes; use in frame pool implementations instead of
 * sizeof(struct mux_frame) (whose data[] is a flexible array member).
 */
size_t mux_frame_object_size(size_t max_payload);

#if WITH_THREADS
typedef atomic_uint_least64_t mux_counter;
typedef atomic_size_t mux_gauge;
#else
typedef uint_least64_t mux_counter;
typedef size_t mux_gauge;
#endif

/* Traffic byte counters; embedded in mux_session_counters. */
struct mux_traffic_counters {
	mux_counter *byt_mux_recv;
	mux_counter *byt_mux_sent;
	/* PUSH-frame payload bytes only (no frame headers, no non-PUSH frames) */
	mux_counter *byt_push_recv;
	mux_counter *byt_push_sent;
};

/* Pointer-block into server_stats for direct session-thread updates.
 * Pointer fields point to atomic or plain counters by build mode.
 * NULL pointers are silently skipped by COUNTER_*. */
struct mux_session_counters {
	mux_counter *num_session_created;
	mux_counter *num_session_connect;
	mux_counter *num_session_connected;
	mux_counter *num_session_disconnected;
	mux_counter *num_session_finalized;
	mux_gauge *num_sessions;
	mux_gauge *num_session_halfopen;
	mux_gauge *num_streams;
	mux_gauge *num_stream_halfopen;
	mux_counter *num_stream_opened;
	mux_counter *num_stream_accepted;
	mux_counter *num_stream_fastopen;
	mux_counter *num_stream_established;
	mux_counter *num_stream_succeeded;
	mux_counter *num_stream_failed;
	mux_counter *num_rst_sent;
	mux_counter *num_rst_recv;
	mux_counter *num_stream_errors;
	mux_gauge *recv_buffered_bytes;
	mux_gauge *send_buffered_frames;
	mux_gauge *unacked_frames;
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
	/* Inactivity deadline in seconds: the session is dead when no frame arrives
	 * for this long.  0 (with keepalive) disables it. */
	int timeout;
	/* Interval in seconds between one-way keepalive PROBE frames.  0 disables
	 * keepalive (and timeout). */
	int keepalive;
	/* Timeout in seconds for a blocked send before the session is reset;
	 * this is what detects an outbound black-hole during active transfer. */
	int send_timeout;
	/* Seconds of stream-idle time before the session is shut down. */
	int idle_timeout;
	/* Seconds a suspended server session waits for the client to resume. */
	int resume_timeout;

	/* Maximum unacknowledged byte cap for the whole session (stored in frames;
	 * the effective stall gate is session_window × MUX_WINDOW_UNIT bytes). */
	int session_window;
	/* Per-stream receive window size (stored in frames; config value in bytes). */
	int stream_window;

	/* Maximum payload bytes per outbound frame, in [MUX_MIN_FRAME_PAYLOAD,
	 * MUX_MAX_PAYLOAD_SIZE].  Fixed at session creation; a mux_set_config change
	 * takes effect only on a new session. */
	int max_frame_payload;

	/* mux.readahead: receive read-ahead window in bytes offered to one transport
	 * read so a single recv() drains several frames, amortizing the recv() and
	 * event-loop cost.  With tls.socket_offload only its >0 state matters (it
	 * drives the TLS library read-ahead).  0 disables read-ahead.  The wire
	 * frame size is unchanged. */
	int readahead;

	/* Receive-buffer level in bytes at which window grants are fully suppressed; 0 disables pressure scaling. */
	int mem_pressure_hi;
	/* Receive-buffer level in bytes at which window-grant scaling begins (default: hi/2). */
	int mem_pressure_lo;

	/* Send frames immediately without coalescing. */
	bool nodelay : 1;
	/* Advertise the reject_inbound HELLO extension (spec §5.2.3.1) so the peer
	 * opens no inbound streams.  Read at handshake time only. */
	bool reject_inbound : 1;

#if WITH_TLS
	/* TLS context for outbound reconnects; NULL leaves the existing context unchanged. */
	struct tls_context *tlsctx;
	/* Let the TLS library own the socket fd. When false, wire.c drives the
	 * socket and shuttles ciphertext through the library (memory transport). */
	bool tls_socket_offload : 1;
#endif
};

extern const struct mux_config mux_conf_default;

/* --- Session creation options --- */

/* Options passed to mux_new().  Takes ownership of fd when fd >= 0 and of
 * conn when set, on both success and failure; the caller must not close fd
 * or free conn itself, before or after the call.
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
	/* Frame allocator; data field is set by the caller per-session.  The
	 * pool's frame buffers must be sized to hold conf->max_frame_payload, the
	 * session's frozen max outbound payload. */
	struct mux_frame_allocator pool;
	/* Non-owning pointer to the session log tag buffer; must outlive the session. */
	const char *tag;
#if WITH_TLS
	struct tls_context *tlsctx;
	struct tls_connection *conn;
#endif
};

/* --- Session lifecycle --- */

/**
 * @brief Allocate a new session.
 * @param loop Event loop the session runs on.
 * @param[in] opts Session options; takes ownership of opts->fd and
 * opts->conn (see struct mux_session_opts), including on failure.
 * @return The new session, or NULL on failure.
 */
struct mux_session *
mux_new(struct ev_loop *restrict loop, const struct mux_session_opts *opts);

/**
 * @brief Tear down and free a session.
 * @param ss Session to free.
 * @note The caller must remove it from any external lists first.
 */
void mux_close(struct mux_session *ss);

/**
 * @brief Replace the session's callback table.
 * @param ss Target session.
 * @param[in] cb New callbacks; must not be NULL (it is copied by value). Pass a
 * zeroed table (e.g. &(struct mux_callbacks){0}) to clear all callbacks.
 * @note Safe to call from any thread once the session's worker thread has been
 * joined.
 */
void mux_set_callbacks(struct mux_session *ss, const struct mux_callbacks *cb);

/**
 * @brief Initiate graceful shutdown: drop in-flight data, close all streams,
 * and begin the transport close handshake (TLS close_notify then TCP
 * half-close).
 * @param ss Target session.
 * @note ::MUX_EVENT_CLOSED is emitted asynchronously when done.
 */
void mux_shutdown(struct mux_session *ss);

/**
 * @brief Start session I/O.
 * @param ss Target session.
 * @note Inbound sessions begin the handshake; outbound sessions (fd == -1) are
 * a no-op until mux_attach_fd() supplies a connected fd.
 */
void mux_start(struct mux_session *ss);

/**
 * @brief Attach an already-connected fd to a client session.
 * @param ss Target session; valid from SESSION_INIT (initial connect),
 * SESSION_SUSPENDED (resume), or SESSION_CLOSED (reconnect after idle/timeout).
 * Transitions it to SESSION_CONNECT.
 * @param fd Connected socket; takes ownership.
 * @note The caller creates the socket, calls connect(), and sets TCP options
 * before passing @p fd here.
 */
void mux_attach_fd(struct mux_session *ss, int fd);

/* --- Session accessors --- */

/**
 * @brief The session's transport fd.
 * @param ss Target session.
 * @return The fd, or -1 when none is attached.
 * @note Reads ss directly (no atomic mirror): call only from the owning
 * ev_loop thread, per struct mux_session's threading invariant.
 */
int mux_fd(const struct mux_session *ss);

#if WITH_TLS
/**
 * @brief The session's TLS connection object.
 * @param ss Target session.
 * @return The connection, owned by the session (do not free), or NULL when TLS
 * is not in use.
 * @note Reads ss directly (no atomic mirror): call only from the owning
 * ev_loop thread, per struct mux_session's threading invariant.
 */
struct tls_connection *mux_tls_conn(const struct mux_session *ss);
#endif /* WITH_TLS */

/**
 * @brief The peer's socket address.
 * @param ss Target session.
 * @return The peer address, or NULL before SESSION_ESTABLISHED.
 * @note Reads ss directly (no atomic mirror): call only from the owning
 * ev_loop thread, per struct mux_session's threading invariant.
 */
const struct sockaddr *mux_peer_addr(const struct mux_session *ss);

enum mux_state {
	MUX_STATE_ESTABLISHED,
	MUX_STATE_CONNECT,
	MUX_STATE_CLOSED,
	MUX_STATE_SUSPENDED,
};

/**
 * @brief The session's coarse lifecycle state.
 * @param ss Target session.
 * @return The current ::mux_state.
 * @note Reads a relaxed-atomic mirror: safe to call from any thread, unlike
 * most other accessors in this section.
 */
enum mux_state mux_state(const struct mux_session *ss);

/**
 * @brief The session identity (MUX_SESSION_ID_LEN bytes).
 * @param ss Target session.
 * @return Pointer to the identity. For accepted sessions this equals the id
 * passed to mux_new(); for dialed sessions it starts as the local id and is
 * replaced by the server-assigned value when ServerHello arrives.
 * @note Reads ss directly (no atomic mirror): call only from the owning
 * ev_loop thread, per struct mux_session's threading invariant.
 */
const unsigned char *mux_session_id(const struct mux_session *ss);

/**
 * @brief The session's configuration snapshot.
 * @param ss Target session.
 * @return Read-only pointer to the config.
 * @note Reads ss directly (no atomic mirror): call only from the owning
 * ev_loop thread, per struct mux_session's threading invariant.
 */
const struct mux_config *mux_conf(const struct mux_session *ss);

/* Snapshot of per-session estimator state.  Filled by mux_session_stats(). */
struct mux_session_stats {
	/* Per-stream receive window advertised to the peer, in bytes. */
	size_t rx_window;
	/* Per-stream send window limited by the peer, in bytes. */
	size_t tx_window;
	/* Nanoseconds; 0 before the first measurement. */
	int_least64_t rtt;
	/* Receive direction (inbound PUSH), bytes; 0 until estimated. Raw
	 * estimator output, not clamped like rx_window; the two may differ. */
	size_t bdp_rx;
	/* Send direction (locally-sent bytes acked by peer), bytes; 0 until
	 * estimated. Raw estimator output; see the bdp_rx note. */
	size_t bdp_tx;
};

/**
 * @brief Snapshot the session's estimator state.
 * @param ss Target session.
 * @param[out] out Receives a consistent snapshot.
 * @note Reads relaxed-atomic mirrors: safe to call from any thread, unlike
 * most other accessors in this section.
 */
void mux_session_stats(
	const struct mux_session *ss, struct mux_session_stats *restrict out);

/* --- Session mutators --- */

/**
 * @brief Replace the session's configuration snapshot (config reload).
 * @param ss Target session.
 * @param[in] conf New config. When WITH_TLS, a non-NULL conf->tlsctx also
 * replaces the TLS context for outbound reconnects; NULL leaves it unchanged.
 */
void mux_set_config(
	struct mux_session *ss, const struct mux_config *restrict conf);

/**
 * @brief Signal the session to drain: reject new inbound streams and shut down
 * gracefully once the last active stream closes.
 * @param ss Target session; if already idle, shutdown begins immediately.
 * @note Cleared automatically on a genuinely fresh (re)connect via
 * mux_attach_fd(). A client reconnect that resumes from SESSION_SUSPENDED
 * deliberately preserves the pending drain (so a drained-then-suspended-then-
 * resumed session keeps draining and does not accept new streams), lest a
 * transport blip silently cancel a drain and leave the session running on stale
 * pre-reload settings. A server-side resume of an accepted session (the peer
 * reconnecting into it) instead cancels the drain: that path re-establishes the
 * session and must accept new streams again. The asymmetry is deliberate at
 * both sites.
 */
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

/**
 * @brief Payload for on_event(), tagged by the ::mux_event.
 * @note ESTABLISHED/RESUMED use .connected; STREAM_ESTABLISHED uses
 * .stream_established; CLOSED uses .closed; other events are zero-initialized.
 */
union mux_event_data {
	/* ESTABLISHED, RESUMED */
	struct {
		/* session setup latency, ns */
		int_least64_t ns;
		/* peer's internal label */
		const char *peer_id;
		/* identity claimed in the peer's hello */
		const char *peer_identity;
	} connected;
	/* STREAM_ESTABLISHED */
	struct {
		/* SYN-to-SYN|ACK latency, ns */
		int_least64_t ns;
	} stream_established;
	/* CLOSED */
	struct {
		/* peer FIN or TLS close_notify (vs. error/reset) */
		bool clean;
		/* suspended session's resume_timeout fired (peer never reconnected) */
		bool expired;
	} closed;
};

/**
 * @brief Session callbacks, all invoked on the session's own loop.
 */
struct mux_callbacks {
	/**
	 * @brief Called for each new inbound stream.
	 * @return true to accept (after mux_stream_attach() or
	 * mux_stream_io_start()), false to reject.
	 */
	bool (*on_accept)(
		void *data, const struct mux_session *, struct mux_stream *);
	/**
	 * @brief Called on session lifecycle changes.
	 * @note Typical resume sequence: CONNECT → ESTABLISHED, LOST → SUSPENDED,
	 * CONNECT → RESUMED. ::MUX_EVENT_CLOSED fires before mux_close().
	 */
	void (*on_event)(
		void *data, struct mux_session *, enum mux_event,
		union mux_event_data);
	/**
	 * @brief Called on the transient session @p new_ss when a resume hello
	 * arrives.
	 * @return true after locating the session matching @p session_id and
	 * moving new_ss's transport onto it (mux_transport_detach() then
	 * mux_resume_attach(), possibly on the matched session's loop); false to
	 * treat new_ss as a fresh session.
	 * @note On true the mux layer tears new_ss down. The mux layer is
	 * loop-agnostic: any cross-loop handoff is the owner's responsibility.
	 */
	bool (*on_resume)(
		void *data, struct mux_session *new_ss,
		const unsigned char *session_id, uint_least32_t resume_seq);
};

/* Transport (socket fd + TLS connection) detached from a transient session for
 * a resume handoff.  A plain value type so the owner can carry it across a loop
 * boundary; the mux layer performs no thread/loop operations on it. */
struct mux_transport {
	int fd;
	int_least64_t connect_started;
#if WITH_TLS
	struct tls_connection *tlsconn;
#endif
};

/**
 * @brief Detach the live transport from a transient session that received a
 * resume hello.
 * @param new_ss Transient session; runs on its loop. Afterwards it owns no
 * transport, so tearing it down neither closes the fd nor frees the TLS
 * connection.
 * @param[out] out Receives the detached transport.
 */
void mux_transport_detach(
	struct mux_session *restrict new_ss,
	struct mux_transport *restrict out);

/**
 * @brief Install a detached transport on a resumed session and complete the
 * resume handshake (send ServerHello, replay unacked frames).
 * @param ss Resumed session; must run on its own loop.
 * @param[in] transport Detached transport; always consumed (installed on
 * success, else fd closed and TLS connection freed).
 * @param resume_seq Peer's resume sequence number.
 */
void mux_resume_attach(
	struct mux_session *restrict ss,
	struct mux_transport *restrict transport, uint_least32_t resume_seq);

/**
 * @brief Discard a detached transport that will not be installed.
 * @param[in] transport Transport to discard; closes the fd and frees the TLS
 * connection.
 */
void mux_transport_discard(struct mux_transport *restrict transport);

/* --- Stream I/O watcher --- */

/**
 * @brief Per-stream I/O event watcher for direct (non-attach-fd) mode.
 * @note EV_READ fires on data available, peer FIN (recv returns 0), or a peer
 * RST or local abort (recv returns -1/ECONNRESET); EV_WRITE fires when the
 * send window opens.
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

/**
 * @brief Activate the watcher, entering direct I/O mode.
 * @param loop Event loop.
 * @param[in] w Stream I/O watcher.
 * @note For passive-open streams this sends SYN|ACK and transitions to
 * ESTABLISHED.
 * @return true if the watcher is now bound and will deliver events; false if the
 * stream had already left every attachable state (a peer-triggerable race, e.g.
 * a peer RST): the binding is severed (w->stream cleared) and no event will ever
 * fire, so the caller must not keep waiting on @p w.
 */
bool mux_stream_io_start(struct ev_loop *loop, mux_stream_io *restrict w);

/**
 * @brief Change the events a stream I/O watcher reports.
 * @param loop Event loop.
 * @param[in] w Stream I/O watcher.
 * @param events New event mask (EV_READ | EV_WRITE).
 */
void mux_stream_io_modify(
	struct ev_loop *loop, mux_stream_io *restrict w, int events);

/**
 * @brief Permanently detach a stream I/O watcher from its stream.
 * @note This is terminal, not a reversible pause: it severs the watcher from
 * the stream (and the stream from the watcher), so the watcher cannot be
 * re-armed with mux_stream_io_start afterwards. The application still owns the
 * stream and must still mux_stream_close() it. To merely pause/resume delivery,
 * use mux_stream_io_modify(loop, w, 0) instead.
 * @param loop Event loop.
 * @param[in] w Stream I/O watcher.
 */
void mux_stream_io_stop(struct ev_loop *loop, mux_stream_io *restrict w);

/* --- Stream operations --- */

/**
 * @brief Open a new outbound stream.
 * @param ss Target session.
 * @return The new stream, or NULL when the session is not established or the
 * halfopen backlog is full.
 */
struct mux_stream *mux_open_stream(struct mux_session *ss);

/**
 * @brief Attach a local socket fd to a stream; takes ownership of @p fd.
 * @param s Target stream.
 * @param fd Local socket; data transfer is blocked until the peer replies
 * SYN|ACK.
 * @note Mutually exclusive with mux_stream_io_start().
 */
void mux_stream_attach(struct mux_stream *s, int fd);

/**
 * @brief The stream's wire id.
 * @param s Target stream.
 * @return The stream id.
 */
uint_least16_t mux_stream_id(const struct mux_stream *s);

/**
 * @brief Queue up to *len bytes for sending.
 * @param s Target stream.
 * @param[in] buf Source bytes.
 * @param[inout] len In: bytes to queue. Out: bytes queued (may be less when the
 * window is partially full, or zero when exhausted — retry after EV_WRITE).
 * @return 0 on success; -1/EINVAL when not writable, -1/EAGAIN when the frame
 * pool is exhausted before any data is queued.
 */
int mux_stream_send(
	struct mux_stream *restrict s, const void *restrict buf,
	size_t *restrict len);

/**
 * @brief Copy up to *len bytes from the receive buffer.
 * @param s Target stream.
 * @param[out] buf Destination.
 * @param[inout] len In: buffer capacity. Out: bytes copied (zero means peer
 * FIN).
 * @return 0 on success; -1/ECONNRESET on a peer RST or local abort (e.g. a
 * local I/O failure), -1/EAGAIN when no data is available.
 * @note If the local side has also sent FIN (CLOSING) and the buffer drains,
 * the stream closes inside this call — do not use @p s again after a zero
 * return. In CLOSE_WAIT (local FIN not yet sent) @p s stays valid; follow up
 * with mux_stream_shutdown() or mux_stream_close().
 */
int mux_stream_recv(
	struct mux_stream *restrict s, void *restrict buf,
	size_t *restrict len);

/**
 * @brief Half-close the write side (shutdown(fd, SHUT_WR)).
 * @param s Target stream.
 */
void mux_stream_shutdown(struct mux_stream *s);

/**
 * @brief Close with close(fd) semantics.
 * @param s Target stream.
 * @note Sends RST (abortive close) if the receive buffer has unread data;
 * otherwise initiates a graceful FIN, as mux_stream_shutdown() does. No RST is
 * sent for a stream that already received one -- spec §4.3.4 requires the
 * receiver answer an RST with no frame at all -- so closing from an
 * ECONNRESET notification is silent even with data still buffered.
 * @note The caller relinquishes @p s: it must not be used again, and in direct
 * mode mux_stream_recv() will not be called for it, so the library stops
 * deferring the stream's final transition to that call.
 */
void mux_stream_close(struct mux_stream *s);

/** @} */

#endif /* MUX_H */
