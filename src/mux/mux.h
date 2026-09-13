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
 * payload cap is configurable (mux_session_config.max_frame_payload). */
#define MUX_FRAME_HEADER_SIZE 8u

/* Compile-time frame-buffer cap: the payload length is a 16-bit wire field, so
 * the largest legal payload is 65535 bytes.  The runtime per-session frame size
 * is configured up to this via mux_session_config.max_frame_payload. */
#define MUX_MAX_PAYLOAD_SIZE 65535u

/* Wire Extra field counts window credit in units of this many bytes. */
#define MUX_WINDOW_UNIT 16384u

/* The payload length is carried in a 16-bit wire field, so a full frame must
 * fit. */
static_assert(
	MUX_MAX_PAYLOAD_SIZE <= UINT16_MAX,
	"frame payload exceeds 16-bit length field");

/* The derived frame-buffer cap MUX_MAX_FRAME_SIZE and the receive-window floor
 * MUX_INITIAL_SEND_WINDOW are internal to the mux stack; see frame.h and
 * estimator.h respectively. */

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

/* Longest identity this implementation claims. Spec §5.2.2 allows 255 octets,
 * but JSON escaping expands a control character to \u00XX, so a claim at the
 * wire limit marshals past the smallest configurable frame and the hello could
 * never be sent. Bounding what we claim keeps the floor below honest; a
 * received identity is still accepted up to the spec's 255. */
#define MUX_MAX_CLAIM_LEN 63u

/* Smallest configurable frame payload: a 1 KiB minimum frame minus the header.
 * Must comfortably exceed the hello handshake JSON; the invariant against the
 * largest possible hello (MUX_MAX_HELLO_JSON_SIZE) is asserted in handshake.h. */
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

/* lossymux datagram counters (spec §5.2.3.3); embedded in
 * mux_session_counters.  Sent/received count DATAGRAM frames handed to or taken
 * from the transport; dropped counts datagrams the session discarded instead
 * of sending (queue full, oversized, extension inactive, or lost to a suspend). */
struct mux_dgram_counters {
	mux_counter *pkt_dgram_sent;
	mux_counter *pkt_dgram_recv;
	mux_counter *pkt_dgram_dropped;
	/* Datagram payload bytes only (no frame headers). */
	mux_counter *byt_dgram_sent;
	mux_counter *byt_dgram_recv;
};

/* Pointer-block into server_stats for direct session-thread updates.
 * Pointer fields point to atomic or plain counters by build mode.
 * NULL pointers are silently skipped by COUNTER_*.  Grouped by subject so the
 * ~20 pointers stay legible and the caller wires one sub-block at a time; each
 * field is still an independent pointer, so a field may target per-session,
 * per-tunnel, or server-global storage as the caller chooses. */
struct mux_session_counters {
	/* Session lifecycle: cumulative counters plus the live/half-open gauges. */
	struct {
		mux_counter *num_session_created;
		mux_counter *num_session_connect;
		mux_counter *num_session_connected;
		mux_counter *num_session_disconnected;
		mux_counter *num_session_finalized;
		mux_gauge *num_sessions;
		mux_gauge *num_session_halfopen;
	} session;
	/* Stream lifecycle: the live/half-open gauges plus cumulative counters. */
	struct {
		mux_gauge *num_streams;
		mux_gauge *num_stream_halfopen;
		mux_counter *num_stream_opened;
		mux_counter *num_stream_accepted;
		mux_counter *num_stream_fastopen;
		mux_counter *num_stream_established;
		mux_counter *num_stream_succeeded;
		mux_counter *num_stream_failed;
	} stream;
	/* Reset and stream-error counters. */
	struct {
		mux_counter *num_rst_sent;
		mux_counter *num_rst_recv;
		mux_counter *num_stream_errors;
	} errors;
	/* Buffer-occupancy gauges. */
	struct {
		mux_gauge *recv_buffered_bytes;
		mux_gauge *send_buffered_frames;
		mux_gauge *unacked_frames;
	} buffers;
	/* Traffic byte counters. */
	struct mux_traffic_counters traffic;
	/* lossymux datagram counters. */
	struct mux_dgram_counters dgram;
};

/* --- Mux configuration subset --- */

/* Configuration snapshot copied from the caller at session creation. */
struct mux_session_config {
	/* Maximum number of concurrent streams per session. */
	int max_streams;
	/* Maximum number of half-open (unacknowledged SYN) streams. */
	int max_halfopen;

	/* Timeout in seconds for a single TCP-connect and mux-handshake attempt. */
	int connect_timeout;
	/* Inactivity deadline in seconds: the session is dead when no frame arrives
	 * for this long.  0 (with keepalive) disables it. */
	int timeout;
	/* Interval in seconds between keepalive PINGs, each answered by the
	 * peer's PONG; a completed PING/PONG exchange in either direction restarts
	 * it.  0 disables keepalive (and timeout). */
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

	/* Session receive-buffer high watermark in bytes for window-grant scaling.
	 * Above the low watermark, grants scale down to a 1/8 floor; if at least
	 * one MUX_WINDOW_UNIT is grantable, at least one unit is retained.
	 * This is not a receive-memory cap. <=0 disables pressure scaling. */
	int mem_pressure_hi;
	/* Session receive-buffer low watermark in bytes: no scaling at or below
	 * this level, then linear decay to the high watermark. Equal watermarks
	 * give a step to the 1/8 floor above them. 0 defaults to hi/2. */
	int mem_pressure_lo;

	/* mux.lossymux.idle_timeout: seconds without a datagram in either
	 * direction before a UDP flow is dropped.  Read by the flow owner, not by
	 * the session. */
	int lossymux_idle_timeout;
	/* mux.lossymux.queue: datagrams queued awaiting transmission before a new
	 * one is dropped. */
	int lossymux_queue;

	/* Send frames immediately without coalescing. */
	bool nodelay : 1;
	/* Advertise the reject_inbound HELLO extension (spec §5.2.3.1) so the peer
	 * opens no inbound streams.  Read at handshake time only. */
	bool reject_inbound : 1;
	/* Offer the bilateral lossymux HELLO extension (spec §5.2.3.3); datagrams
	 * flow only when the peer offers it too.  Read at handshake time only. */
	bool lossymux : 1;

#if WITH_TLS
	/* Let the TLS library own the socket fd. When false, wire.c drives the
	 * socket and shuttles ciphertext through the library (memory transport).
	 * Read when a TLS connection is created; a live connection keeps the mode
	 * it was built with, so a mux_set_config change takes effect only on the
	 * next connection. */
	bool tls_socket_offload : 1;
#endif
};

extern const struct mux_session_config mux_session_config_default;

/* --- Session creation options --- */

/* Options passed to mux_new().  Takes ownership of fd when fd >= 0 and of
 * conn when set, on both success and failure; the caller must not close fd
 * or free conn itself, before or after the call.
 * String pointers are copied if non-NULL.
 * cnt pointer fields may be NULL; skipped when updating server-level counters. */
struct mux_session_opts {
	const struct mux_callbacks *callbacks;
	void *userdata;
	const struct mux_session_config *conf;
	int fd;
	/* Session ID of MUX_SESSION_ID_LEN octets; required, never NULL. */
	const unsigned char *id;
	/* Identity claimed in hello; copied if non-NULL. A claim longer than
	 * MUX_MAX_CLAIM_LEN octets is omitted from the hello with a warning. */
	const char *identity;
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
 * @note Frees every stream of @p ss, including one the application still
 * holds -- a direct-mode stream it has not yet released with
 * mux_stream_close(), or an opened one it has not attached: no stream of the
 * session may be used afterwards.
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
 * @note Only a session in HANDSHAKE or ESTABLISHED closes asynchronously: this
 * call emits ::MUX_EVENT_CONNECT_FAILED or ::MUX_EVENT_LOST as it leaves that
 * state, and ::MUX_EVENT_CLOSED follows from the session loop once the
 * transport close handshake ends. From any other state (INIT, CONNECT,
 * SUSPENDED, CLOSING or CLOSE_WAIT) the session is force-closed with no
 * protocol exchange, and ::MUX_EVENT_CLOSED is emitted re-entrantly before this
 * call returns; an already CLOSED session emits nothing. So after this returns
 * the caller must not touch anything its CLOSED handler may have released --
 * ss itself included, when that handler calls mux_close().
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

/* --- Session accessors: owning ev_loop thread only ---
 *
 * Every accessor in this group reads the session object directly, with no
 * atomic mirror, so it must be called only from the session's own ev_loop
 * thread, per struct mux_session's threading invariant.  The any-thread
 * accessors that read relaxed-atomic mirrors are grouped separately below. */

/**
 * @brief The session's transport fd.
 * @param ss Target session.
 * @return The fd, or -1 when none is attached.
 */
int mux_fd(const struct mux_session *ss);

#if WITH_TLS
/**
 * @brief The session's TLS connection object.
 * @param ss Target session.
 * @return The connection, owned by the session (do not free), or NULL when TLS
 * is not in use.
 */
struct tls_connection *mux_tls_conn(const struct mux_session *ss);
#endif /* WITH_TLS */

/**
 * @brief The peer's socket address.
 * @param ss Target session.
 * @return The peer address, or NULL before SESSION_ESTABLISHED.
 */
const struct sockaddr *mux_peer_addr(const struct mux_session *ss);

/**
 * @brief The session identity (MUX_SESSION_ID_LEN bytes).
 * @param ss Target session.
 * @return Pointer to the identity. For accepted sessions this equals the id
 * passed to mux_new(); for dialed sessions it starts as the local id and is
 * replaced by the server-assigned value when ServerHello arrives.
 */
const unsigned char *mux_session_id(const struct mux_session *ss);

/**
 * @brief The identity claimed by the peer in its hello.
 * @param ss Target session.
 * @return The identity, or NULL when the peer claimed none. Owned by the
 * session; valid until the next hello is processed.
 * @note Available as soon as the hello is parsed, which is earlier than the
 * ::MUX_EVENT_ESTABLISHED or ::MUX_EVENT_RESUMED that publishes it as
 * .connected.peer_identity.
 */
const char *mux_peer_identity(const struct mux_session *ss);

/**
 * @brief The session's configuration snapshot.
 * @param ss Target session.
 * @return Read-only pointer to the config.
 */
const struct mux_session_config *mux_conf(const struct mux_session *ss);

/* --- Session accessors: safe from any thread ---
 *
 * These read relaxed-atomic mirrors published by the session thread, so unlike
 * the owning-loop-only accessors above they may be called from any thread (the
 * server thread's /stats path relies on this). */

/* Coarse lifecycle reported by mux_state(); the internal state machine
 * (doc/impl.md §4.1) collapses onto these.  CLOSING is distinct from CLOSED
 * because the two admit different operations: a CLOSED session can be redialed
 * and a SUSPENDED one resumed, while a CLOSING one still owns its transport and
 * accepts neither. */
enum mux_state {
	/* Usable: streams may be opened and carried. */
	MUX_STATE_ESTABLISHED,
	/* Coming up (INIT, CONNECT or HANDSHAKE): not usable yet. */
	MUX_STATE_CONNECT,
	/* Gone.  Accepted by mux_attach_fd(), so a dialed session here may be
	 * redialed on demand. */
	MUX_STATE_CLOSED,
	/* Transport lost but resumable: streams and unacked frames are held for
	 * replay.  Accepted by mux_attach_fd() and eligible as a resume target. */
	MUX_STATE_SUSPENDED,
	/* Shutting down (CLOSING or CLOSE_WAIT): no longer usable, but not yet
	 * gone.  Rejected by mux_attach_fd(), and never a resume target -- the
	 * attach would be dropped and the peer's fresh transport discarded. */
	MUX_STATE_CLOSING,
};

/**
 * @brief The session's coarse lifecycle state.
 * @param ss Target session.
 * @return The current ::mux_state.
 */
enum mux_state mux_state(const struct mux_session *ss);

/* Approximate per-session estimator diagnostics, filled by mux_session_stats(). */
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
 * @brief Sample the session's estimator diagnostics.
 * @param ss Target session.
 * @param[out] out Receives individually sampled fields. Concurrent updates
 * may leave fields from different updates; no coherent cross-field snapshot
 * is guaranteed.
 */
void mux_session_stats(
	const struct mux_session *ss, struct mux_session_stats *restrict out);

/* --- Session mutators --- */

/**
 * @brief Replace the session's configuration snapshot (config reload).
 * @param ss Target session.
 * @param[in] conf New config. A pure value replace; to swap the TLS context
 * used for outbound reconnects, use mux_set_tlsctx() separately.
 */
void mux_set_config(
	struct mux_session *ss, const struct mux_session_config *restrict conf);

#if WITH_TLS
/**
 * @brief Replace the TLS context used for the session's outbound reconnects.
 * @param ss Target session.
 * @param[in] tlsctx New TLS context. Borrowed: the session stores the pointer
 * for future reconnects, so it must outlive that use; the caller keeps
 * ownership.
 */
void mux_set_tlsctx(struct mux_session *ss, struct tls_context *tlsctx);
#endif /* WITH_TLS */

/**
 * @brief Signal the session to drain: reject new inbound streams and shut down
 * gracefully once the last active stream closes.
 * @param ss Target session; if already idle, shutdown begins immediately.
 * @note Cleared automatically only on a genuinely fresh (re)connect via
 * mux_attach_fd(). Every resume preserves the pending drain, on both sides: a
 * client reconnect that resumes from SESSION_SUSPENDED and a server-side resume
 * of an accepted session (the peer reconnecting into it) both keep draining and
 * keep rejecting new streams. A drain requested by a config reload is
 * independent of the transport failure, so a transport blip must not silently
 * cancel it and leave the session running on stale pre-reload settings
 * indefinitely. The symmetry is deliberate at both sites.
 */
void mux_drain(struct mux_session *ss);

enum mux_event {
	/* Connect or handshake attempt started; fires per attempt. */
	MUX_EVENT_CONNECT,
	/* Connect or handshake attempt ended before ESTABLISHED.  A failed
	 * resume attempt leaves the session SESSION_SUSPENDED, still resumable
	 * by mux_attach_fd() until resume_timeout, counted from the transport
	 * loss, expires; no SUSPENDED or CLOSED follows it.  Any other failed
	 * attempt is followed by CLOSED. */
	MUX_EVENT_CONNECT_FAILED,
	/* Initial handshake completed on this session object. */
	MUX_EVENT_ESTABLISHED,
	/* Established transport went away; emitted whenever the session
	 * leaves ESTABLISHED. */
	MUX_EVENT_LOST,
	/* An established transport was lost and the session is now
	 * SESSION_SUSPENDED.  Resume-capable callers may wait for a peer
	 * reconnect or attach a new connected fd with mux_attach_fd(). */
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
 * .stream_established; CONNECT_FAILED uses .connect_failed; CLOSED uses
 * .closed; other events are zero-initialized.
 */
union mux_event_data {
	/* ESTABLISHED, RESUMED */
	struct {
		/* session setup latency, ns */
		int_least64_t ns;
		/* identity claimed in the peer's hello */
		const char *peer_identity;
	} connected;
	/* STREAM_ESTABLISHED */
	struct {
		/* SYN-to-SYN|ACK latency, ns */
		int_least64_t ns;
	} stream_established;
	/* CONNECT_FAILED */
	struct {
		/* errno that ended the attempt, or 0 when none was observed */
		int err;
	} connect_failed;
	/* CLOSED */
	struct {
		/* peer FIN or TLS close_notify (vs. error/reset) */
		bool clean;
		/* suspended session's resume_timeout fired (peer never reconnected) */
		bool expired;
		/* errno that ended the transport, or 0 when none was observed;
		 * lets the owner's reconnect policy tell an unreachable path
		 * from a peer that merely declined */
		int err;
	} closed;
};

/**
 * @brief Session callbacks, all invoked on the session's own loop.
 */
struct mux_callbacks {
	/**
	 * @brief Called for each new inbound stream.
	 * @return true to accept (after mux_stream_attach_fd() or
	 * mux_stream_io_start()), false to reject.
	 */
	bool (*on_accept)(
		void *data, const struct mux_session *, struct mux_stream *);
	/**
	 * @brief Called on session lifecycle changes.
	 * @note Typical resume sequence: CONNECT → ESTABLISHED, LOST → SUSPENDED,
	 * CONNECT → RESUMED; each failed resume attempt in between reports
	 * CONNECT → CONNECT_FAILED. ::MUX_EVENT_CLOSED fires before mux_close().
	 */
	void (*on_event)(
		void *data, struct mux_session *, enum mux_event,
		union mux_event_data);
	/**
	 * @brief Called once the peer's claimed identity is known, before the
	 * handshake completes and before any stream can be admitted.
	 * @param identity Identity claimed in the peer's hello, or NULL when the
	 * peer claimed none.
	 * @return true to accept the session; false to reject it, which resets
	 * the session without admitting a stream.
	 * @note Fires on every hello, a resume hello included, so each new
	 * transport is checked rather than only the first. A NULL callback
	 * accepts unconditionally.
	 */
	bool (*on_verify_identity)(
		void *data, struct mux_session *ss, const char *identity);
	/**
	 * @brief Called on the transient session @p new_ss when a resume hello
	 * arrives.
	 * @return true after locating the session matching @p session_id and
	 * moving new_ss's transport onto it (mux_transport_detach() then
	 * mux_resume_attach(), possibly on the matched session's loop); false to
	 * treat new_ss as a fresh session.
	 * @note On true the mux layer tears new_ss down. The mux layer is
	 * loop-agnostic: any cross-loop handoff is the owner's responsibility.
	 * @note false requires new_ss to still own its transport: the handshake
	 * continues on it. An owner whose handoff fails after
	 * mux_transport_detach() must restore it with mux_transport_reattach()
	 * before returning false.
	 */
	bool (*on_resume)(
		void *data, struct mux_session *new_ss,
		const unsigned char *session_id, uint_least32_t resume_seq);
	/**
	 * @brief Called for each DATAGRAM frame received while lossymux is
	 * active (spec §5.2.3.3).
	 * @param flow Flow id, never 0.
	 * @param payload Borrowed; valid only for the duration of the call.
	 * @note May send datagrams; must not close or shut down the session.
	 * A NULL callback discards the datagram.
	 */
	void (*on_dgram)(
		void *data, struct mux_session *ss, uint_least16_t flow,
		const unsigned char *payload, size_t len);
	/**
	 * @brief Called for each FLOW-CLOSE frame received while lossymux is
	 * active: the peer has dropped @p flow (never 0).
	 * @note Same restrictions as on_dgram.
	 */
	void (*on_dgram_close)(
		void *data, struct mux_session *ss, uint_least16_t flow);
};

/* Transport (socket fd + TLS connection) detached from a transient session for
 * a resume handoff.  A plain value type so the owner can carry it across a loop
 * boundary; the mux layer performs no thread/loop operations on it.
 * Carries no buffered ciphertext: mux_transport_detach requires the transient's
 * outbound memory-transport buffer to be empty, which holds while no
 * post-handshake records can arrive before the resume hello. */
struct mux_transport {
	int fd;
	int_least64_t connect_started;
	/* Extensions from the resume hello (spec §5.2.2 defines the active set
	 * from the hello exchange, and a resume is one). The transient session
	 * that parsed them is discarded, so they ride across to the resumed
	 * session here. Owned: mux_resume_attach consumes it,
	 * mux_transport_discard frees it. NULL when the hello claimed none, in
	 * which case the resumed session keeps its current identity. */
	char *peer_identity;
	bool reject_inbound;
	/* The resume hello offered lossymux (spec §5.2.3.3). */
	bool lossymux;
#if WITH_TLS
	struct tls_connection *tlsconn;
	/* The mode tlsconn was built with: true when it owns fd (socket offload),
	 * false for a memory transport.  Travels with the connection because the
	 * resumed session may have been created under a different config. */
	bool tls_offload;
#endif
};

/**
 * @brief Detach the live transport from a transient session that received a
 * resume hello.
 * @param new_ss Transient session; runs on its loop. Afterwards it owns no
 * transport, so tearing it down neither closes the fd nor frees the TLS
 * connection.
 * @param[out] out Receives the detached transport.
 * @note Reversible: an owner that cannot complete the handoff restores
 * @p new_ss with mux_transport_reattach() instead of discarding the transport.
 */
void mux_transport_detach(
	struct mux_session *restrict new_ss,
	struct mux_transport *restrict out);

/**
 * @brief Put a detached transport back on the transient session it came from,
 * undoing mux_transport_detach().
 * @param new_ss The session the transport was detached from; must still own no
 * transport and run on its loop.
 * @param[in] transport Detached transport; always consumed.
 * @note For an owner that detached before discovering it cannot hand the
 * transport off. The session is left exactly as mux_transport_detach() found
 * it, with the socket watcher stopped -- the handshake path that called
 * ::mux_callbacks::on_resume re-arms it -- so declining the resume afterwards
 * serves @p new_ss as a fresh session on its own transport.
 */
void mux_transport_reattach(
	struct mux_session *restrict new_ss,
	struct mux_transport *restrict transport);

/**
 * @brief Install a detached transport on a resumed session and complete the
 * resume handshake (send ServerHello, replay unacked frames).
 * @param ss Resumed session; must run on its own loop.
 * @param[in] transport Detached transport; always consumed (installed on
 * success, else fd closed and TLS connection freed).
 * @param resume_seq Peer's resume sequence number.
 */
void mux_resume_attach(
	struct mux_session *ss, struct mux_transport *restrict transport,
	uint_least32_t resume_seq);

/**
 * @brief Discard a detached transport that will not be installed.
 * @param[in] transport Transport to discard; closes the fd and frees the TLS
 * connection.
 */
void mux_transport_discard(struct mux_transport *restrict transport);

/* --- Datagram operations (lossymux, spec §5.2.3.3) --- */

/**
 * @brief Whether datagrams can be sent now: the session is established and
 * both hellos offered lossymux.
 * @param ss Target session; call on its loop.
 */
bool mux_dgram_ready(const struct mux_session *ss);

/**
 * @brief Queue one datagram for @p flow; best effort.
 * @param ss Target session.
 * @param flow Non-zero flow id; a locally opened flow uses the local stream-id
 * parity (odd on the dialing side, even on the accepting side).
 * @param buf Datagram payload; copied.
 * @param len Payload length.
 * @return true when queued; false when dropped (counted as such): lossymux is
 * not ready, @p len exceeds the session's frame payload, the send queue holds
 * mux_session_config::lossymux_queue datagrams already, or allocation failed.
 * @note A queued datagram may still be dropped if the transport is lost
 * before it is written.
 */
bool mux_dgram_send(
	struct mux_session *ss, uint_least16_t flow, const void *buf,
	size_t len);

/**
 * @brief Tell the peer, best effort, that @p flow is gone (FLOW-CLOSE).
 * @param ss Target session.
 * @param flow Non-zero flow id.
 * @note Silently does nothing when lossymux is not ready or the queue is full.
 */
void mux_dgram_close(struct mux_session *ss, uint_least16_t flow);

/* --- Stream operations --- */

/**
 * @brief Open a new outbound stream.
 * @param ss Target session.
 * @return The new stream, or NULL when it cannot be opened right now: the
 * session is not established or is draining, the peer rejects inbound streams,
 * the halfopen backlog or the stream cap is full, stream IDs are exhausted, or
 * allocation failed.
 * @note The library does not free the stream before the application gives
 * it a mode with mux_stream_attach_fd() or mux_stream_io_start(), or gives it
 * up with mux_stream_close(). A reset, or its session tearing its streams down
 * -- mux_shutdown(), the end of a mux_drain(), a session reset, or a resume
 * the peer rejects -- closes it in the meantime, and the deferred call then
 * rejects it. mux_close() frees it regardless.
 */
struct mux_stream *mux_stream_open(struct mux_session *ss);

/**
 * @brief Attach a local socket fd to a stream; takes ownership of @p fd.
 * @param s Target stream.
 * @param fd Local socket; data transfer is blocked until the peer replies
 * SYN|ACK.
 * @note A stream from mux_stream_open() may be attached at any time until it
 * closes, before or after the peer's SYN|ACK; what the peer sent meanwhile is
 * delivered to @p fd. A stream that has already closed -- reset, or torn down
 * with its session, before this call -- is rejected: @p fd is closed. Either
 * way the library owns @p s from here.
 * @note This is socket mode. It is mutually exclusive with direct mode, whose
 * watcher and data-transfer API (mux_stream_io_start() etc.) live in the
 * companion header mux/stream_io.h.
 */
void mux_stream_attach_fd(struct mux_stream *s, int fd);

/**
 * @brief The stream's wire id.
 * @param s Target stream.
 * @return The stream id.
 */
uint_least16_t mux_stream_id(const struct mux_stream *s);

/* Direct-mode stream I/O -- the ::mux_stream_io watcher plus mux_stream_send(),
 * mux_stream_recv(), mux_stream_shutdown() and mux_stream_close() -- is the
 * alternative to attaching a socket fd. Its API lives in mux/stream_io.h so the
 * everyday socket-mode surface here stays small. */

/** @} */

#endif /* MUX_H */
