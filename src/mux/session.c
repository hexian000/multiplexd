/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file session.c
 * @brief Internal mux session state machine implementation.
 */

#include "mux/session.h"

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/handshake.h"
#include "mux/mux.h"
#include "mux/recv.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/stream.h"
#include "mux/unacked.h"
#include "mux/wire.h"
#include "shim/util.h"

#include "algo/hashtable.h"
#include "io/io.h"
#include "math/rand.h"
#include "meta/arraysize.h"
#include "meta/minmax.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

static const char *session_state_str[] = {
	[SESSION_INIT] = "INIT",
	[SESSION_CONNECT] = "CONNECT",
	[SESSION_HANDSHAKE] = "HANDSHAKE",
	[SESSION_ESTABLISHED] = "ESTABLISHED",
	[SESSION_SUSPENDED] = "SUSPENDED",
	[SESSION_CLOSING] = "CLOSING",
	[SESSION_CLOSE_WAIT] = "CLOSE_WAIT",
	[SESSION_CLOSED] = "CLOSED",
};

void session_update_watcher(struct mux_session *restrict ss)
{
	int events = 0;
#if WITH_TLS
	if (ss->wire.tls_want != 0) {
		modify_io_events(ss->loop, &ss->w_socket, ss->wire.tls_want);
		return;
	}
#endif
	switch (ss->state) {
	case SESSION_CONNECT:
		events = EV_WRITE;
		break;
	case SESSION_HANDSHAKE:
	case SESSION_ESTABLISHED:
	case SESSION_CLOSING:
		if (ss->wire.rx_open) {
			events = EV_READ;
		}
		if (ss->wire.tx_pending || !ss->wire.rx_open) {
			events |= EV_WRITE;
		}
		/* No sendable work may be left when EV_WRITE is off, except
		 * send_stalled: the session-level ACK handler re-arms EV_WRITE. */
		ASSERT(ss->state != SESSION_ESTABLISHED ||
		       ss->unacked.stalled || (events & EV_WRITE) ||
		       (ss->sched.sched_head == NULL &&
			ss->wire.sendbuf.head == NULL &&
			ss->wire.oobbuf.head == NULL));
		break;
	case SESSION_CLOSE_WAIT:
		/* Wait for peer to close; if receive is closed, drive teardown via write. */
		events = ss->wire.rx_open ? EV_READ : EV_WRITE;
		break;
	case SESSION_SUSPENDED:
		/* No transport I/O while waiting for reconnect. */
		/* falls through */
	default:
		return;
	}
	modify_io_events(ss->loop, &ss->w_socket, events);
}

/* conf.keepalive scaled by a random factor in (1 - MUX_KEEPALIVE_JITTER, 1],
 * never exceeding the configured value.  Returns it unchanged when disabled. */
double keepalive_interval(const struct mux_session *restrict ss)
{
	const double base = (double)ss->conf.keepalive;
	if (!(base > 0.0)) {
		return base;
	}
	return base * (1.0 - MUX_KEEPALIVE_JITTER * frand());
}

static void handshake_start(struct mux_session *ss)
{
	session_set_state(ss, SESSION_HANDSHAKE);
	if (!ss->accepted) {
		/* Client: build and send ClientHello. */
		handshake_enqueue_hello(
			ss, PROTO_MSG_CLIENT_HELLO,
			ss->handshake.has_session_id /* resume request */);
	}
}

static void closing_cb(struct mux_session *ss)
{
	switch (wire_shutdown(ss)) {
	case WIRE_SHUTDOWN_PENDING:
		return;
	case WIRE_SHUTDOWN_DONE:
		session_set_state(ss, SESSION_CLOSE_WAIT);
		return;
	case WIRE_SHUTDOWN_ERROR:
		session_reset(ss);
		return;
	}
}

static void close_wait_cb(struct mux_session *ss)
{
	/* wire_wait_eof distinguishes a confirmed peer close from a spurious
	 * wakeup with nothing pending yet, but the teardown itself stays
	 * unconditional either way -- CLOSE_WAIT is backstopped by the
	 * close-timeout watchdog regardless, so a spurious wakeup only costs
	 * an early (not incorrect) reset; this only makes the log account for
	 * it accurately. */
	switch (wire_wait_eof(ss)) {
	case WIRE_EOF_CONFIRMED:
		MUX_LOG(VERBOSE, ss, "shutdown completed");
		break;
	case WIRE_EOF_PENDING:
		MUX_LOG(DEBUG, ss, "spurious wakeup during shutdown");
		break;
	case WIRE_EOF_ERROR:
		MUX_LOG(DEBUG, ss, "unexpected state after shutdown");
		break;
	}
	session_reset(ss);
}

static void connect_cb(struct mux_session *ss)
{
	const int err = socket_get_error(ss->w_socket.fd);
	if (err != 0) {
		MUX_LOG_F(WARNING, ss, "connect: (%d) %s", err, strerror(err));
		session_reset(ss);
		return;
	}

	MUX_LOG(INFO, ss, "TCP connected");

#if WITH_TLS
	if (!wire_tls_start(ss)) {
		MUX_LOG(ERROR, ss, "TLS connect failed");
		session_reset(ss);
		return;
	}
#endif /* WITH_TLS */

	handshake_start(ss);
}

static void socket_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct mux_session *const restrict ss = w->data;
	ASSERT(loop == ss->loop);
	(void)loop;
	MUX_LOG_F(
		VERBOSE, ss, "mux socket: state=%s revents=%d",
		session_state_str[ss->state], revents);

#if WITH_TLS
	/* Consume the pending TLS I/O request.  Fall through to session_on_recv
	 * below to drive TLS handshake progress regardless of direction. */
	const bool tls_poll = (ss->wire.tls_want != 0);
	ss->wire.tls_want = 0;
#endif

	switch (ss->state) {
	case SESSION_CONNECT:
		connect_cb(ss);
		break;
	case SESSION_HANDSHAKE:
	case SESSION_ESTABLISHED:
		if ((revents & EV_READ) != 0
#if WITH_TLS
		    || tls_poll
#endif
		) {
			session_on_recv(ss);
			if (ss->state != SESSION_ESTABLISHED &&
			    ss->state != SESSION_HANDSHAKE) {
				break;
			}
		}
		/* EV_WRITE drives both the backpressure drain (residue) and the
		 * deferred flush of freshly produced frames (coalesced here). */
		if ((revents & EV_WRITE) != 0) {
			session_on_send(ss);
		}
		break;
	case SESSION_CLOSING:
		closing_cb(ss);
		break;
	case SESSION_CLOSE_WAIT:
		close_wait_cb(ss);
		break;
	default:
		FAILMSGF("unexpected session state %d", ss->state);
	}

	if (ss->state == SESSION_CLOSED) {
		ss->last_modified = (int_least64_t)clock_monotonic_ns();
		session_emit(
			ss, MUX_EVENT_CLOSED,
			(union mux_event_data){
				.closed.clean = ss->wire.rx_eof,
			});
		return;
	}
	/* Apply the final event mask; recv-side producers may have left residue. */
	session_update_watcher(ss);
}

/* Tear down a session on a fatal liveness condition: suspend for resume when a
 * session id was negotiated, else close (@p reason is logged).  This is the
 * sole dead-link detector (reached via send_timeout/w_timeout below);
 * run_probe_cycle() (estimator.c) deliberately has no probe timeout of its
 * own and defers to this instead, even while traffic is flowing. */
static void session_on_dead_link(
	struct mux_session *restrict ss, const char *restrict reason)
{
	if (ss->handshake.has_session_id) {
		MUX_LOG_F(WARNING, ss, "%s; suspending for resume", reason);
		session_suspend(ss);
		if (ss->state == SESSION_CLOSED) {
			/* session_suspend() can itself close ss on a nested
			 * ring-push OOM (unacked_push); tell the owner since
			 * nothing else did. Checking == CLOSED, not
			 * != SUSPENDED: session_suspend()'s own synchronous
			 * MUX_EVENT_SUSPENDED can reentrantly reconnect a
			 * dialed session all the way to SESSION_CONNECT, which
			 * is neither SUSPENDED nor CLOSED and must not be
			 * mistaken for the latter. */
			session_emit(
				ss, MUX_EVENT_CLOSED,
				(union mux_event_data){ 0 });
		}
		return;
	}
	MUX_LOG_F(WARNING, ss, "%s", reason);
	session_notify_closed(ss, false);
}

static void
connect_timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *const restrict ss = w->data;
	ASSERT(loop == ss->loop);
	(void)loop;
	const bool was_suspended = (ss->state == SESSION_SUSPENDED);
	switch (ss->state) {
	case SESSION_CONNECT:
		MUX_LOG(WARNING, ss, "connect timeout");
		break;
	case SESSION_HANDSHAKE:
		MUX_LOG(WARNING, ss, "connect timeout");
		/* A resume attempt that is merely slow, not dead, must not
		 * destroy streams/unacked data -- mirrors session_on_dead_link()
		 * and the send.c I/O-error paths for this same state.
		 * session_suspend()'s own precondition excludes SESSION_CONNECT
		 * (transport not up yet), so this can't also cover that case. */
		if (!ss->accepted && ss->handshake.has_session_id) {
			session_suspend(ss);
			if (ss->state == SESSION_CLOSED) {
				/* session_suspend() can itself close ss on a
				 * nested ring-push OOM (unacked_push); tell the
				 * owner since nothing else did. Checking ==
				 * CLOSED, not != SUSPENDED: the reentrant
				 * reconnect this same function's own dialed
				 * path can trigger (via MUX_EVENT_SUSPENDED)
				 * may legitimately land on SESSION_CONNECT. */
				session_emit(
					ss, MUX_EVENT_CLOSED,
					(union mux_event_data){ 0 });
			}
			return;
		}
		break;
	case SESSION_SUSPENDED:
		MUX_LOG(WARNING, ss, "session resume timed out");
		break;
	case SESSION_CLOSING:
	case SESSION_CLOSE_WAIT:
		MUX_LOG(WARNING, ss, "close timeout");
		break;
	default:
		FAILMSGF("unexpected session state %d", ss->state);
	}
	session_notify_closed(ss, was_suspended);
}

static void
send_timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *const restrict ss = w->data;
	ASSERT(loop == ss->loop);
	(void)loop;
	switch (ss->state) {
	case SESSION_ESTABLISHED:
		break;
	default:
		FAILMSGF("unexpected session state %d", ss->state);
	}
	session_on_dead_link(ss, "send timeout");
}

static void timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *const restrict ss = w->data;
	ASSERT(loop == ss->loop);
	(void)loop;
	CHECKMSGF(
		ss->state == SESSION_ESTABLISHED, "unexpected session state %d",
		ss->state);
	/* A shared session_id suspends rather than closes so streams survive
	 * short blackholes; sessions without one are torn down immediately. */
	session_on_dead_link(ss, "session timeout");
}

static void keepalive_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *const restrict ss = w->data;
	ASSERT(loop == ss->loop);
	(void)loop;
	CHECKMSGF(
		ss->state == SESSION_ESTABLISHED, "unexpected session state %d",
		ss->state);

	/* Encrypted TCP-keepalive: a one-way PROBE the peer discards, but whose
	 * arrival resets its w_timeout.  No reply is expected; death detection is
	 * w_timeout (inbound) plus send_timeout (outbound), not this path. */
	if (!session_send_oob(ss, MUX_CTRL_PROBE, NULL, 0)) {
		/* OOM: skip this cycle; the timer re-arms below regardless. */
		MUX_LOG(DEBUG, ss,
			"keepalive PROBE skipped: frame pool exhausted");
	} else {
		MUX_LOG(VERBOSE, ss, "keepalive PROBE sent");
	}
	const double keepalive = keepalive_interval(ss);
	ev_timer_set(&ss->w_keepalive, 0.0, keepalive);
	ev_timer_again(ss->loop, &ss->w_keepalive);
	session_flush_oob(ss);
}

static void idle_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_session *const restrict ss = w->data;
	ASSERT(loop == ss->loop);
	(void)loop;
	CHECKMSGF(
		ss->state == SESSION_ESTABLISHED, "unexpected session state %d",
		ss->state);
	MUX_LOG(INFO, ss, "idle timeout, closing session");
	session_notify_closed(ss, false);
}

/* Tear down a partially-initialized session on any session_new failure
 * exit after `ss` was allocated; safe at any point since session_new's
 * leading compound literal zero-inits every field this touches. */
static void session_new_cleanup(
	struct mux_session *restrict ss, const struct mux_session_opts *opts)
{
	free(ss->handshake.peer_id);
	free(ss->handshake.identity);
	ringbuf_free(ss->wire.recvbuf);
	table_free(ss->sched.streams);
	mux_frame_ring_free(&ss->unacked.ring, &ss->pool);
	free(ss);
	if (opts->fd >= 0) {
		socket_close(opts->fd);
	}
#if WITH_TLS
	wire_tlsconn_free(opts->conn);
#endif
}

struct mux_session *
session_new(struct ev_loop *restrict loop, const struct mux_session_opts *opts)
{
	const struct mux_config *const conf = opts->conf;
	const int fd = opts->fd;
	const unsigned char *const id = opts->id;

	struct mux_session *ss = malloc(sizeof(struct mux_session));
	if (ss == NULL) {
		LOGOOM();
		if (fd >= 0) {
			socket_close(fd);
		}
#if WITH_TLS
		wire_tlsconn_free(opts->conn);
#endif
		return NULL;
	}
	*ss = (struct mux_session){
		.loop = loop,
		.conf = *conf,
		.pool = opts->pool,
		/* Freeze the framing payload cap from conf so a later mux_set_config
		 * cannot desync it from the pool's buffer size; the caller sizes
		 * the pool from the same value. conf_load_mux() always clamps
		 * max_frame_payload to at least MUX_MIN_FRAME_PAYLOAD, so no
		 * fallback is needed here. */
		.max_payload = (uint_least32_t)conf->max_frame_payload,
		.readahead = (size_t)conf->readahead,
		.tag = opts->tag,
		.callbacks = *opts->callbacks,
		.userdata = opts->userdata,
		.cnt = opts->cnt,
#if WITH_TLS
		.wire.tlsctx = opts->tlsctx,
		.wire.tlsconn = opts->conn,
#endif
		.state = SESSION_INIT,
		.last_modified = (int_least64_t)clock_monotonic_ns(),
		.accepted = (fd >= 0),
		.wire.rx_open = true,
		/* For accepted sessions, start timing from creation so setup time
		 * covers from accept() to SESSION_ESTABLISHED. */
		.connect_started = (fd >= 0) ? clock_monotonic_ns() : 0,
	};
	ss->unacked.retransmit_off = SIZE_MAX;

	ss->sched.streams = table_new(&mux_stream_table_opts);
	if (ss->sched.streams == NULL) {
		session_new_cleanup(ss, opts);
		return NULL;
	}
	ss->wire.recvbuf = ringbuf_new(IO_BUFSIZE);
	if (ss->wire.recvbuf == NULL) {
		LOGOOM();
		session_new_cleanup(ss, opts);
		return NULL;
	}

	memcpy(ss->handshake.session_id, id, MUX_SESSION_ID_LEN);
	ss->handshake.has_session_id = (fd >= 0);

	if (opts->identity != NULL) {
		ss->handshake.identity = strdup(opts->identity);
		if (ss->handshake.identity == NULL) {
			LOGOOM();
			session_new_cleanup(ss, opts);
			return NULL;
		}
	}
	if (opts->peer_id != NULL) {
		ss->handshake.peer_id = strdup(opts->peer_id);
		if (ss->handshake.peer_id == NULL) {
			LOGOOM();
			session_new_cleanup(ss, opts);
			return NULL;
		}
	}

	ev_io_init(&ss->w_socket, socket_cb, fd, EV_READ);
	ss->w_socket.data = ss;

	const double timeout = (double)conf->timeout;
	ev_timer_init(&ss->w_timeout, timeout_cb, 0.0, timeout);
	ss->w_timeout.data = ss;

	const double keepalive = (double)conf->keepalive;
	ev_timer_init(&ss->w_keepalive, keepalive_cb, 0.0, keepalive);
	ss->w_keepalive.data = ss;

	const double send_timeout = (double)conf->send_timeout;
	ev_timer_init(&ss->w_send_timeout, send_timeout_cb, 0.0, send_timeout);
	ss->w_send_timeout.data = ss;

	const double connect_timeout = (double)conf->connect_timeout;
	ev_timer_init(
		&ss->w_connect_timeout, connect_timeout_cb, 0.0,
		connect_timeout);
	ss->w_connect_timeout.data = ss;

	sched_init(ss);

	const double idle_timeout = (double)conf->idle_timeout;
	ev_timer_init(&ss->w_idle_timeout, idle_cb, 0.0, idle_timeout);
	ss->w_idle_timeout.data = ss;
	/* Must follow all ev_timer_init calls (session_set_config uses
	 * ev_timer_set). */
	estimator_init(ss, MUX_INITIAL_SEND_WINDOW);
	session_set_config(ss, conf);
	COUNTER_ADD(ss->cnt.num_session_created, 1);
	return ss;
}

/* Reset stream_window to half the current RX estimate (floored at the initial
 * window) on every exit from ESTABLISHED so a resumed session re-probes
 * conservatively. */
static void session_reset_stream_window_floor(struct mux_session *restrict ss)
{
	session_set_stream_window(
		ss,
		(uint_least32_t)MAX(
			estimator_rx_window_size(&ss->estimator) / 2 /
				MUX_WINDOW_UNIT,
			(size_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT)));
}

/* Move frames in @p list into the unacked retransmit ring instead of losing
 * them; a frame identical to unacked.retransmit_copy is freed instead, since
 * it is already tracked there (only ever true for wire.sendbuf; the check is
 * a harmless no-op for wire.oobbuf, which never holds the live copy).
 * unacked_track_sent can itself reset ss (a ring-push OOM); once that
 * happens, stop feeding it further frames -- unacked_push would otherwise
 * lazily reallocate the ring it just freed and resurrect tracking state on
 * a session that is supposed to be fully torn down. */
static void session_capture_frame_list(
	struct mux_session *restrict ss, struct mux_frame_list *restrict list)
{
	if (list->head == NULL) {
		return;
	}
	struct mux_frame_list captured = *list;
	*list = (struct mux_frame_list){ 0 };
	struct mux_frame *frame;
	while ((frame = mux_frame_list_pop(&captured)) != NULL) {
		if (ss->state == SESSION_CLOSED ||
		    frame == ss->unacked.retransmit_copy) {
			mux_frame_put(&ss->pool, frame);
		} else {
			unacked_track_sent(ss, frame);
		}
	}
}

static void session_capture_sendbuf(struct mux_session *restrict ss)
{
	session_capture_frame_list(ss, &ss->wire.sendbuf);
}

static void session_stop(struct mux_session *ss)
{
	struct ev_loop *const loop = ss->loop;
	ev_io_stop(loop, &ss->w_socket);
	ss->sched.lp_pending = false;
	ev_timer_stop(loop, &ss->w_timeout);
	ev_timer_stop(loop, &ss->w_keepalive);
	ev_timer_stop(loop, &ss->w_send_timeout);
	ev_timer_stop(loop, &ss->w_connect_timeout);
	ev_timer_stop(loop, &ss->sched.w_coalesce);
	ev_timer_stop(loop, &ss->w_idle_timeout);
	session_reset_stream_window_floor(ss);
}

static void session_cleanup(struct mux_session *restrict ss)
{
	sched_free_streams(ss);
	wire_conn_free(ss);
	if (ss->w_socket.fd != -1) {
		socket_close(ss->w_socket.fd);
		ss->w_socket.fd = -1;
	}

	wire_discard_buffers(ss);
	unacked_free_all(ss);
	ss->unacked.retransmit_copy = NULL;
}

static void handshake_cleanup(struct mux_session *restrict ss)
{
	free(ss->handshake.identity);
	free(ss->handshake.peer_id);
	free(ss->handshake.peer_identity);
}

void session_close(struct mux_session *restrict ss)
{
	MUX_LOG(VERBOSE, ss, "finalizing");
	/* Route a still-live session (e.g. force-closed during shutdown before it
	 * finished a graceful handshake) through session_reset first, so leaving
	 * ESTABLISHED/CONNECT/HANDSHAKE still fires MUX_EVENT_LOST and the
	 * num_sessions/num_session_disconnected bookkeeping that a bare
	 * session_stop skips. A no-op when already CLOSED; session_stop and
	 * session_cleanup below are idempotent. */
	session_reset(ss);
	session_stop(ss);
	session_cleanup(ss);
	ringbuf_free(ss->wire.recvbuf);
#if WITH_TLS
	ringbuf_free(ss->wire.rawbuf);
#endif
	handshake_cleanup(ss);
	COUNTER_ADD(ss->cnt.num_session_finalized, 1);
	free(ss);
}

void session_set_config(
	struct mux_session *restrict ss, const struct mux_config *restrict conf)
{
	const bool was_auto_stream_window = ss->auto_stream_window;
	const bool was_auto_session_window = ss->auto_session_window;
	ss->conf = *conf;
	ss->auto_stream_window = (conf->stream_window <= 0);
	ss->auto_session_window = (conf->session_window <= 0);
	const uint_fast32_t initial_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;
	/* auto window resets to the floor only on a manual->auto switch, else keeps
	 * the learned value; manual mode uses the configured value verbatim. */
	if (ss->auto_stream_window) {
		if (!was_auto_stream_window) {
			session_set_stream_window(ss, initial_frames);
		}
	} else {
		session_set_stream_window(
			ss, (uint_least32_t)conf->stream_window);
	}
	/* As above, but auto session_window additionally enforces the floor. */
	if (ss->auto_session_window) {
		if (!was_auto_session_window ||
		    ss->session_window < initial_frames) {
			ss->session_window = initial_frames;
		}
	} else {
		ss->session_window = (uint_least32_t)conf->session_window;
	}

	/* Always update repeat so a later reconnect arms with the new value; on a
	 * live session also start/stop now, so toggling keepalive on (period 0 →
	 * timer was stopped) or off takes effect immediately. */
	const double timeout = (double)conf->timeout;
	ev_timer_set(&ss->w_timeout, 0.0, timeout);
	const double keepalive = keepalive_interval(ss);
	ev_timer_set(&ss->w_keepalive, 0.0, keepalive);
	if (ss->state == SESSION_ESTABLISHED) {
		if (timeout > 0.0) {
			ev_timer_again(ss->loop, &ss->w_timeout);
		} else {
			ev_timer_stop(ss->loop, &ss->w_timeout);
		}
		if (keepalive > 0.0) {
			ev_timer_again(ss->loop, &ss->w_keepalive);
		} else {
			ev_timer_stop(ss->loop, &ss->w_keepalive);
		}
	}

	const double send_timeout = (double)conf->send_timeout;
	ev_timer_set(&ss->w_send_timeout, 0.0, send_timeout);
	if (ss->w_socket.fd != -1 &&
	    socket_user_timeout(ss->w_socket.fd, conf->send_timeout * 1000) ==
		    0) {
		ss->w_send_timeout.repeat = 0.0;
	}
	if (ss->w_send_timeout.repeat > 0.0) {
		if (ev_is_active(&ss->w_send_timeout)) {
			ev_timer_again(ss->loop, &ss->w_send_timeout);
		}
	} else {
		ev_timer_stop(ss->loop, &ss->w_send_timeout);
	}

	/* w_connect_timeout is polymorphically reused: the CONNECT/HANDSHAKE
	 * deadline (conf.connect_timeout), the SUSPENDED resume-deadline
	 * (conf.resume_timeout, one-shot armed in session_suspend), and the
	 * CLOSING/CLOSE_WAIT graceful-close deadline (one-shot armed in
	 * session_initiate_shutdown). Re-arming it here in any of those repurposed
	 * states would clobber the running timer: during SUSPENDED it restarts the
	 * resume deadline with connect_timeout -- or, if that is 0, cancels it,
	 * wedging the session suspended forever; during a graceful close
	 * ev_timer_again turns the one-shot close deadline into a periodic timer
	 * (each reload resetting the elapsed deadline) or, with connect_timeout 0,
	 * stops it, so a peer that never finishes the close handshake leaves the
	 * session stuck in CLOSING/CLOSE_WAIT and never freed. Skip those states;
	 * ss->conf was already updated above, so w_connect_timeout is re-armed from
	 * the reloaded value when it is next needed (session_attach_fd on resume,
	 * session_initiate_shutdown on close). */
	if (ss->state != SESSION_SUSPENDED && ss->state != SESSION_CLOSING &&
	    ss->state != SESSION_CLOSE_WAIT) {
		const double connect_timeout = (double)conf->connect_timeout;
		ev_timer_set(&ss->w_connect_timeout, 0.0, connect_timeout);
		if (ev_is_active(&ss->w_connect_timeout)) {
			ev_timer_again(ss->loop, &ss->w_connect_timeout);
		}
	}

	const double idle_timeout = (double)conf->idle_timeout;
	if (idle_timeout > 0.0) {
		ev_timer_set(&ss->w_idle_timeout, 0.0, idle_timeout);
		if (ev_is_active(&ss->w_idle_timeout)) {
			ev_timer_again(ss->loop, &ss->w_idle_timeout);
		}
	} else {
		ev_timer_stop(ss->loop, &ss->w_idle_timeout);
		ev_timer_set(&ss->w_idle_timeout, 0.0, 0.0);
	}

	/* Seed the estimator only when first entering auto mode; re-seeding an
	 * already-auto session would wipe the learned RTT/BW windows. */
	if (ss->auto_stream_window && !was_auto_stream_window) {
		estimator_init(ss, (size_t)ss->stream_window * MUX_WINDOW_UNIT);
	}
}

void session_start(struct mux_session *restrict ss)
{
	if (ss->w_socket.fd == -1) {
		/* Client session without transport; caller must supply a
		 * connected fd via mux_attach_fd() before I/O begins. */
		return;
	}
	MUX_LOG(VERBOSE, ss, "starting");

#if WITH_TLS
	if (!wire_tls_start(ss)) {
		MUX_LOG(ERROR, ss, "TLS start failed");
		session_notify_closed(ss, false);
		return;
	}
#endif

	if (socket_user_timeout(
		    ss->w_socket.fd, ss->conf.send_timeout * 1000) == 0) {
		ss->w_send_timeout.repeat = 0.0;
	}
	handshake_start(ss);
	/* Arm EV_WRITE synchronously: this runs before the first ev_run, so
	 * session_notify's session_update_watcher must set the mask for the
	 * next poll. */
	session_notify(ss);
	ev_timer_again(ss->loop, &ss->w_connect_timeout);
}

void session_attach_fd(struct mux_session *restrict ss, const int fd)
{
	CHECKMSGF(
		ss->state == SESSION_INIT || ss->state == SESSION_SUSPENDED ||
			ss->state == SESSION_CLOSED,
		"session_attach_fd: unexpected state %d", ss->state);

	/* Transitioning out of SUSPENDED: stop the resume timeout and
	 * restore repeat clobbered by session_suspend's one-shot reuse. */
	if (ss->state == SESSION_SUSPENDED) {
		ev_timer_stop(ss->loop, &ss->w_connect_timeout);
		ss->w_connect_timeout.repeat = (double)ss->conf.connect_timeout;

		/* A stream can independently abort/close while suspended, queuing
		 * a fresh frame into wire.sendbuf (session_send_ctrl ->
		 * wire_sendbuf_push); capture it into the retransmit ring so it
		 * still gets sent, instead of leaking into the next handshake
		 * where handshake_enqueue_hello's ASSERT(sendbuf.head == NULL)
		 * expects the hello to be the first queued frame (mirrors the
		 * server-side session_resume_attach). */
		session_capture_sendbuf(ss);
		wire_discard_buffers(ss);

		if (ss->state == SESSION_CLOSED) {
			/* The capture above reset ss on a ring-push OOM
			 * (unacked_push); it is already fully torn down.
			 * Discard the not-yet-attached fd and tell the owner
			 * instead of reviving a closed session below. */
			socket_close(fd);
			session_emit(
				ss, MUX_EVENT_CLOSED,
				(union mux_event_data){ 0 });
			return;
		}
	}

	if (ss->sched.streams == NULL) {
		ss->sched.streams = table_new(&mux_stream_table_opts);
		if (ss->sched.streams == NULL) {
			LOGOOM();
			socket_close(fd);
			/* Emit MUX_EVENT_CLOSED so tunnel_on_event's
			 * handle_closed schedules a reconnect (or no-ops for a
			 * shutting-down/on-demand tunnel); session_notify_closed
			 * is a safe no-op if ss was already closed. */
			session_notify_closed(ss, false);
			return;
		}
	}
	ss->wire.rx_open = true;
	ss->wire.tx_pending = false;
	ss->wire.send_blocked = false;
	ss->wire.rx_eof = false;
#if WITH_TLS
	ss->wire.tls_want = 0;
#endif
	if (ss->state != SESSION_SUSPENDED) {
		/* Only a genuinely fresh (re)connect starts un-draining; resuming
		 * a drained session must not silently cancel a pending drain
		 * (from a config reload) that a transport blip merely
		 * interrupted -- otherwise the session keeps running on stale
		 * pre-reload settings indefinitely, with no signal that the
		 * drain was dropped. */
		ss->draining = false;
	}

	/* Detach the old fd first: reconnecting from SUSPENDED leaves the socket
	 * watcher active on the stale fd, and ev_io_set alone does not update the
	 * backend. */
	ev_io_stop(ss->loop, &ss->w_socket);
	ev_io_set(&ss->w_socket, fd, EV_WRITE);
	if (socket_user_timeout(fd, ss->conf.send_timeout * 1000) == 0) {
		ss->w_send_timeout.repeat = 0.0;
	}
	/* Time from attach so setup spans socket creation to ESTABLISHED. */
	ss->connect_started = clock_monotonic_ns();
	session_set_state(ss, SESSION_CONNECT);
	ev_io_start(ss->loop, &ss->w_socket);
	/* Arm EV_WRITE so post-connect frames (ClientHello, then data) flush in the
	 * iteration that produces them. */
	session_notify(ss);
	ev_timer_again(ss->loop, &ss->w_connect_timeout);

	MUX_LOG_F(DEBUG, ss, "transport attached [fd:%d]", fd);
}

/* Initiate an immediate graceful shutdown: abandon transfers, close streams,
 * discard buffered data, then enter SESSION_CLOSING for the transport close
 * handshake (TLS close_notify then TCP FIN). */
void session_initiate_shutdown(struct mux_session *restrict ss)
{
	if (ss->state != SESSION_ESTABLISHED &&
	    ss->state != SESSION_HANDSHAKE) {
		/* Not transferring: force-close without any protocol exchange.
		 * Route through session_notify_closed so CLOSED is emitted only on
		 * a real transition -- the session can already be CLOSED here (the
		 * shutdown loop dispatches task_mux_shutdown asynchronously and the
		 * session may reach CLOSED between snapshot and task), and an
		 * unguarded re-emit would spuriously repeat MUX_EVENT_CLOSED. */
		session_notify_closed(ss, false);
		return;
	}
	MUX_LOG(INFO, ss,
		"initiating graceful shutdown; dropping in-flight data");

	/* Stop all timers and the lifecycle drain; keep the socket watcher so the
	 * close frames still flush via EV_WRITE. */
	struct ev_loop *const restrict loop = ss->loop;
	ss->sched.lp_pending = false;
	ev_timer_stop(loop, &ss->w_timeout);
	ev_timer_stop(loop, &ss->w_keepalive);
	ev_timer_stop(loop, &ss->w_send_timeout);
	ev_timer_stop(loop, &ss->w_connect_timeout);
	ev_timer_stop(loop, &ss->sched.w_coalesce);
	ev_timer_stop(loop, &ss->w_idle_timeout);
	session_reset_stream_window_floor(ss);

	/* Free all streams: closes local fds, drains queues; no protocol
	 * frames are sent (per spec §5.6: streams are implicitly aborted). */
	sched_free_streams(ss);

	/* Discard all pending session-level data. */
	wire_discard_buffers(ss);
	unacked_free_all(ss);

	session_set_state(ss, SESSION_CLOSING);
	/* connect_timeout == 0 means disabled (schema-legal, conf_check() no
	 * longer clamps it up); this is a one-shot at-delay arm, not
	 * ev_timer_again, so an unconditional arm with at=0 would fire
	 * immediately instead of never -- skip arming entirely instead. */
	if (ss->conf.connect_timeout > 0) {
		ev_timer_set(
			&ss->w_connect_timeout,
			(double)ss->conf.connect_timeout, 0.0);
		ev_timer_start(loop, &ss->w_connect_timeout);
	}
	ss->wire.tx_pending = true;
	/* Synchronous arm: this may be called outside the loop, so EV_WRITE
	 * must be set before the next poll. */
	session_update_watcher(ss);
}

void session_drain(struct mux_session *restrict ss)
{
	ss->draining = true;
	/* Already idle (established, no active streams): shut down now.  Subtract
	 * tombstones, which linger for late-frame suppression and aren't active. */
	if (ss->state == SESSION_ESTABLISHED && ss->sched.streams != NULL &&
	    table_size(ss->sched.streams) == ss->sched.num_tombstones) {
		session_initiate_shutdown(ss);
	}
}

struct mux_stream *session_open_stream(struct mux_session *restrict ss)
{
	if (ss->state == SESSION_CLOSED) {
		MUX_LOG(VERBOSE, ss, "open_stream: session closed");
		return NULL;
	}
	if (ss->state != SESSION_ESTABLISHED) {
		MUX_LOG_F(
			VERBOSE, ss,
			"open_stream: session not established (state=%s)",
			session_state_str[ss->state]);
		return NULL;
	}
	if (ss->draining) {
		MUX_LOG(VERBOSE, ss, "open_stream: session draining");
		return NULL;
	}
	if (ss->handshake.peer_rejects_inbound_streams) {
		MUX_LOG(ERROR, ss, "peer does not accept inbound streams");
		return NULL;
	}
	if (ss->conf.max_halfopen > 0 &&
	    ss->num_halfopen >= (size_t)ss->conf.max_halfopen) {
		MUX_LOG_F(
			VERBOSE, ss, "open_stream: max_halfopen (%d) reached",
			ss->conf.max_halfopen);
		return NULL;
	}
	if (ss->conf.max_streams > 0 &&
	    table_size(ss->sched.streams) - ss->sched.num_tombstones >=
		    (size_t)ss->conf.max_streams) {
		MUX_LOG_F(
			VERBOSE, ss, "open_stream: max_streams (%d) reached",
			ss->conf.max_streams);
		return NULL;
	}
	const uint_fast16_t id = sched_alloc_stream_id(ss);
	if (id == STREAMID_CTRL) {
		/* All stream IDs in this parity class are active (spec §4.1);
		 * reject the request and wait for existing streams to close. */
		MUX_LOG(VERBOSE, ss, "open_stream: stream IDs exhausted");
		return NULL;
	}

	struct mux_stream *const s = stream_new(ss, id, true);
	if (s == NULL) {
		LOGOOM();
		return NULL;
	}
	if (!sched_add_stream(ss, s)) {
		MUX_LOG(ERROR, ss, "open_stream: stream_add failed");
		stream_free(s);
		return NULL;
	}
	MUX_LOG_F(DEBUG, ss, "opened stream %" PRIuFAST16, id);
	sched_wake(ss, s);
	MUX_LOG_F(
		VERYVERBOSE, ss, "queued initial SYN for stream %" PRIuLEAST16,
		s->id);
	return s;
}

/* Mark egress pending and arm EV_WRITE; the send pump runs on the next loop
 * iteration (coalesced) or inline via session_flush under low load. */
void session_notify(struct mux_session *restrict ss)
{
	ss->wire.tx_pending = true;
	if (ss->w_socket.fd != -1) {
		session_update_watcher(ss);
	}
}

static void format_frame_flags(
	char *restrict buf, const size_t buflen, const uint_fast8_t flags)
{
	static const struct {
		uint_least8_t flag;
		const char *name;
	} names[] = {
		{ MUX_FLAG_SYN, "SYN" },   { MUX_FLAG_ACK, "ACK" },
		{ MUX_FLAG_FIN, "FIN" },   { MUX_FLAG_RST, "RST" },
		{ MUX_FLAG_PUSH, "PUSH" },
	};

	char *p = buf;
	const char *const end = buf + buflen;
	bool wrote = false;
	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		if ((flags & names[i].flag) == 0) {
			continue;
		}
		if (wrote && p + 1 < end) {
			*p++ = '|';
		}
		for (const char *s = names[i].name; *s != '\0' && p + 1 < end;
		     s++) {
			*p++ = *s;
		}
		wrote = true;
	}
	const uint_fast8_t unknown = flags & (uint_fast8_t)(~MUX_FLAG_MASK);
	if (unknown != 0) {
		const int ret = snprintf(
			p, (size_t)(end - p), "%sUNKNOWN(0x%02" PRIxFAST8 ")",
			wrote ? "|" : "", unknown);
		if (ret < 0 && buflen > 0) {
			buf[0] = '\0';
		}
		return;
	}
	if (!wrote) {
		const int ret = snprintf(buf, buflen, "NONE");
		if (ret < 0 && buflen > 0) {
			buf[0] = '\0';
		}
	} else if (p < end) {
		*p = '\0';
	}
}

void session_log_frame_header(
	struct mux_session *restrict ss, const char *restrict what,
	const unsigned char *restrict raw,
	const struct mux_header *restrict hdr)
{
	if (!LOGLEVEL(VERYVERBOSE)) {
		return;
	}
	char flags_str[64];
	format_frame_flags(flags_str, sizeof(flags_str), hdr->flags);

	LOG_BIN_F(
		VERYVERBOSE, raw, MUX_FRAME_HEADER_SIZE, 0,
		"[fd:%d] %s: stream_id=%" PRIuLEAST16 " length=%" PRIuLEAST16
		" flags=0x%02" PRIxLEAST8 "(%s)"
		" extra=%" PRIuLEAST16,
		ss->w_socket.fd, what, hdr->stream_id, hdr->length, hdr->flags,
		flags_str, hdr->extra);
}

void session_set_state(struct mux_session *ss, enum session_state newstate)
{
	if (ss->state == newstate) {
		return;
	}
	MUX_LOG_F(
		DEBUG, ss, "state: %s -> %s", session_state_str[ss->state],
		session_state_str[newstate]);
	const enum session_state oldstate = ss->state;

	if (oldstate == SESSION_ESTABLISHED) {
		ev_timer_stop(ss->loop, &ss->w_timeout);
		ev_timer_stop(ss->loop, &ss->w_keepalive);
		ev_timer_stop(ss->loop, &ss->w_send_timeout);
		estimator_suspend(ss);
		session_reset_stream_window_floor(ss);
		COUNTER_ADD(ss->cnt.num_session_disconnected, 1);
		COUNTER_SUB(ss->cnt.num_sessions, 1);
		session_emit(ss, MUX_EVENT_LOST, (union mux_event_data){ 0 });
	} else if (
		(oldstate == SESSION_CONNECT ||
		 oldstate == SESSION_HANDSHAKE) &&
		newstate != SESSION_CONNECT && newstate != SESSION_HANDSHAKE &&
		newstate != SESSION_ESTABLISHED &&
		newstate != SESSION_SUSPENDED) {
		COUNTER_SUB(ss->cnt.num_session_halfopen, 1);
		session_emit(
			ss, MUX_EVENT_CONNECT_FAILED,
			(union mux_event_data){ 0 });
	}

	ss->state = newstate;
	PUB_STORE(ss->_pub_state, newstate);

	if ((newstate == SESSION_CONNECT || newstate == SESSION_HANDSHAKE) &&
	    oldstate != SESSION_CONNECT && oldstate != SESSION_HANDSHAKE) {
		COUNTER_ADD(ss->cnt.num_session_connect, 1);
		COUNTER_ADD(ss->cnt.num_session_halfopen, 1);
		session_emit(
			ss, MUX_EVENT_CONNECT, (union mux_event_data){ 0 });
	} else if (newstate == SESSION_ESTABLISHED) {
		if (ss->connect_started > 0) {
			const int_fast64_t lat =
				clock_monotonic_ns() - ss->connect_started;
			ss->last_connect_latency_ns = lat;
			ss->connect_started = 0;
		}
		/* peer_addr survives suspend but is cleared after reconnect, so
		 * it distinguishes first establishment (CONNECT) from resume. */
		const bool first_establish =
			(ss->peer_addr.sa.sa_family == AF_UNSPEC);
		(void)socket_get_peer(ss->w_socket.fd, &ss->peer_addr);
		ev_timer_again(ss->loop, &ss->w_keepalive);
		COUNTER_ADD(ss->cnt.num_session_connected, 1);
		COUNTER_SUB(ss->cnt.num_session_halfopen, 1);
		COUNTER_ADD(ss->cnt.num_sessions, 1);
		session_emit(
			ss,
			first_establish ? MUX_EVENT_ESTABLISHED :
					  MUX_EVENT_RESUMED,
			(union mux_event_data){
				.connected.ns = ss->last_connect_latency_ns,
				.connected.peer_id = ss->handshake.peer_id,
				.connected.peer_identity =
					ss->handshake.peer_identity,
			});
	}
}

void session_reset(struct mux_session *ss)
{
	if (ss->state == SESSION_CLOSED) {
		return;
	}
	MUX_LOG(VERBOSE, ss, "closing");
	session_set_state(ss, SESSION_CLOSED);
	session_stop(ss);
	session_cleanup(ss);

	if (ss->accepted) {
		return;
	}
	/* Reset peer_addr so the next establishment is recognised as first. */
	memset(&ss->peer_addr, 0, sizeof(ss->peer_addr));
	ss->num_halfopen = 0;
	/* A full reset destroys streams and the unacked ring, so there is
	 * nothing left locally to resume; clear has_session_id (mirrors
	 * send.c's send_handle_rx_closed) so the next connect attempt starts a
	 * fresh session instead of requesting resume with a stale id, which a
	 * still-suspended server session could accept as a ghost resume. */
	ss->handshake.has_session_id = false;
}

void session_notify_closed(struct mux_session *restrict ss, const bool expired)
{
	/* Emit only on a real transition: session_reset() is a no-op when
	 * already CLOSED (e.g. an OOM retrying session_attach_fd's reconnect
	 * path on a session that closed earlier), and re-firing the event for
	 * a transition that didn't happen would double-schedule a reconnect. */
	const bool was_closed = (ss->state == SESSION_CLOSED);
	session_reset(ss);
	if (!was_closed && ss->state == SESSION_CLOSED) {
		session_emit(
			ss, MUX_EVENT_CLOSED,
			(union mux_event_data){
				.closed.clean = ss->wire.rx_eof,
				.closed.expired = expired,
			});
	}
}

void session_suspend(struct mux_session *restrict ss)
{
	ASSERT(ss->state == SESSION_ESTABLISHED ||
	       (ss->state == SESSION_HANDSHAKE && !ss->accepted &&
		ss->handshake.has_session_id));
	if (ss->state == SESSION_HANDSHAKE) {
		MUX_LOG(WARNING, ss,
			"transport lost during resume handshake; re-suspending");
		/* session_set_state()'s halfopen accounting only pays back the
		 * CONNECT/HANDSHAKE-entry increment on a transition directly
		 * out of {CONNECT,HANDSHAKE}; SUSPENDED is deliberately excluded
		 * there (a suspended resume attempt is still "pending"). But if
		 * this session is later torn down straight from SUSPENDED
		 * (e.g. connect_timeout_cb's resume-timeout arm), oldstate is
		 * SUSPENDED at that point too, so the debt is never paid and
		 * num_session_halfopen leaks by one, permanently. Settle it
		 * here instead, at the one moment oldstate is still HANDSHAKE. */
		COUNTER_SUB(ss->cnt.num_session_halfopen, 1);
	} else {
		MUX_LOG(WARNING, ss,
			"transport lost; session suspended awaiting resume");
	}
	session_set_state(ss, SESSION_SUSPENDED);

	/* Move partially flushed frames into the resume log before teardown. */
	session_capture_sendbuf(ss);

	ss->wire.sendbuf_staging = false;
	ss->unacked.retransmit_copy = NULL;

	/* True OOB traffic (PING/PONG/PROBE, STREAMID_CTRL) never replays across
	 * resume; unacked_track_sent discards those unconditionally same as
	 * before. But a real-stream-id control frame session_send_ctrl deferred
	 * here behind an already-in-progress replay must not be dropped on a
	 * second suspend, so migrate the list the same way wire.sendbuf is
	 * captured above instead of unconditionally clearing it. */
	session_capture_frame_list(ss, &ss->wire.oobbuf);

	if (ss->state == SESSION_CLOSED) {
		/* A capture above reset ss on a ring-push OOM (unacked_push);
		 * it is already fully torn down (session_reset ->
		 * session_cleanup). Skip re-arming anything below and emitting
		 * MUX_EVENT_SUSPENDED for a session that never actually
		 * suspended -- every caller checks ss->state == SESSION_CLOSED
		 * (or, for session_resume_attach's accepted-only call site,
		 * the equivalent != SESSION_SUSPENDED) after this call and
		 * emits MUX_EVENT_CLOSED itself when so, so this function must
		 * not also emit it here (that would double-emit). */
		return;
	}

	/* Resume replay always restarts from the current unacked head. */
	if (ss->unacked.ring != NULL && ss->unacked.ring->count > 0) {
		ss->unacked.retransmit_off = 0;
	} else {
		ss->unacked.retransmit_off = SIZE_MAX;
	}
	ev_io_stop(ss->loop, &ss->w_socket);
	ss->sched.lp_pending = false;
	ev_timer_stop(ss->loop, &ss->w_timeout);
	ev_timer_stop(ss->loop, &ss->w_keepalive);
	ev_timer_stop(ss->loop, &ss->w_send_timeout);
	ev_timer_stop(ss->loop, &ss->w_connect_timeout);
	ev_timer_stop(ss->loop, &ss->sched.w_coalesce);
	ev_timer_stop(ss->loop, &ss->w_idle_timeout);

	wire_conn_free(ss);
	if (ss->w_socket.fd != -1) {
		socket_close(ss->w_socket.fd);
		ss->w_socket.fd = -1;
	}
	ringbuf_reset(ss->wire.recvbuf);
	ss->wire.rx_open = true;
	ss->wire.tx_pending = false;
#if WITH_TLS
	ss->wire.tls_want = 0;
#endif

	/* Reuse w_connect_timeout as a one-shot resume deadline.  send_timeout
	 * is not used in SESSION_SUSPENDED; it gates live sends only.
	 * resume_timeout == 0 means disabled (held suspended indefinitely;
	 * schema-legal, conf_check() no longer clamps it up). This is a
	 * one-shot at-delay arm, not ev_timer_again, so an unconditional arm
	 * with at=0 would fire immediately instead of never -- skip arming
	 * entirely instead. */
	if (ss->conf.resume_timeout > 0) {
		const double wait = (double)ss->conf.resume_timeout;
		ev_timer_set(&ss->w_connect_timeout, wait, 0.0);
		ev_timer_start(ss->loop, &ss->w_connect_timeout);
	}

	/* Notify after entering SUSPENDED: dialed sessions may reconnect now,
	 * accepted sessions wait for the peer to resume. */
	session_emit(ss, MUX_EVENT_SUSPENDED, (union mux_event_data){ 0 });
}

void session_handshake_done(struct mux_session *ss)
{
	MUX_LOG(VERBOSE, ss, "mux negotiation completed");
	ev_timer_stop(ss->loop, &ss->w_connect_timeout);
	/* Distinguish fresh establish from resume before session_set_state
	 * clears connect_started and updates peer_addr. */
	const bool is_resume = (ss->peer_addr.sa.sa_family != AF_UNSPEC);
	session_set_state(ss, SESSION_ESTABLISHED);
	ev_timer_again(ss->loop, &ss->w_timeout);
	if (LOGLEVEL(NOTICE)) {
		char str[32];
		format_duration(
			str, sizeof(str),
			make_duration_nanos(ss->last_connect_latency_ns));
		const char *const verb = is_resume ? "resumed" : "established";
		if (ss->peer_addr.sa.sa_family != AF_UNSPEC) {
			char peer_str[64];
			(void)sa_format(
				peer_str, sizeof(peer_str), &ss->peer_addr.sa);
			MUX_LOG_F(
				NOTICE, ss, "session %s peer=%s setup=%s", verb,
				peer_str, str);
		} else {
			MUX_LOG_F(NOTICE, ss, "session %s setup=%s", verb, str);
		}
	}
	ss->last_modified = (int_least64_t)clock_monotonic_ns();

#if WITH_TLS && !defined(NDEBUG)
	/* mux handshake completion implies TLS is up; log KTLS offload status. */
	wire_tls_log_status(ss);
#endif

	if (!ss->accepted) {
		/* Subtract tombstones (late-frame suppression only, not active
		 * streams), matching session_drain()/session_open_stream()'s
		 * "active stream count" -- otherwise the idle timer fails to
		 * arm until a recently-closed stream's tombstone also expires. */
		if (ss->conf.idle_timeout > 0 &&
		    table_size(ss->sched.streams) == ss->sched.num_tombstones) {
			ev_timer_again(ss->loop, &ss->w_idle_timeout);
		}
	}

	/* Re-activate streams queued during suspension: data-ready arms EV_WRITE
	 * directly, INIT/CLOSED lifecycle via sched_schedule (also EV_WRITE). */
	if (ss->sched.sched_head != NULL) {
		ss->wire.tx_pending = true;
	}
	sched_schedule(ss);
	/* Re-arm w_coalesce on resume with preserved Nagle/ACK backlog or
	 * unreported session ACKs.  sched_coalesce_arm is idempotent. */
	if (ss->sched.delay_head != NULL || ss->unacked.unreported > 0) {
		sched_coalesce_arm(ss);
	}

	/* If draining was requested before the handshake completed and there
	 * are no active streams, initiate a graceful shutdown immediately.
	 * Subtract tombstones here too, matching the idle check above (and
	 * session_drain()/sched_remove_stream()) -- a resume with one
	 * lingering tombstone must not defer shutdown up to
	 * MUX_TOMBSTONE_PERIOD_S. */
	if (ss->draining && ss->sched.streams != NULL &&
	    table_size(ss->sched.streams) == ss->sched.num_tombstones) {
		session_initiate_shutdown(ss);
	}
}

void mux_transport_detach(
	struct mux_session *restrict new_ss, struct mux_transport *restrict out)
{
	out->fd = new_ss->w_socket.fd;
	out->connect_started = new_ss->connect_started;
	/* Stop the transient's watcher before stealing its fd, else
	 * session_reset(new_ss) -> ev_io_stop fires on fd=-1 (libev assertion). */
	ev_io_stop(new_ss->loop, &new_ss->w_socket);
	new_ss->w_socket.fd = -1;
#if WITH_TLS
	out->tlsconn = new_ss->wire.tlsconn;
	new_ss->wire.tlsconn = NULL;
	new_ss->wire.tlsctx = NULL;
#endif
}

/* Install a detached transport on a suspended session; sends ServerHello
 * and replays unacked frames.  Consumes @p t on success; leaves it
 * untouched on failure for the caller to discard. */
static void session_resume_attach(
	struct mux_session *restrict ss, struct mux_transport *restrict t,
	const uint_least32_t client_resume_seq)
{
	/* The suspended session may have been torn down (resume timeout or
	 * protocol error) between the handoff and this attach. */
	if (ss->state != SESSION_ESTABLISHED &&
	    ss->state != SESSION_SUSPENDED) {
		return;
	}
	/* Race: the server session is still ESTABLISHED when the client
	 * reconnects.  Suspend first so resume logic finds SUSPENDED state. */
	if (ss->state == SESSION_ESTABLISHED) {
		session_suspend(ss);
		if (ss->state != SESSION_SUSPENDED) {
			/* Either a nested ring-push OOM closed ss inside
			 * session_suspend() itself, or session_suspend()'s
			 * synchronous MUX_EVENT_SUSPENDED let a reentrant owner
			 * callback tear ss down; either way nothing else has
			 * told the owner, so do it here. */
			session_emit(
				ss, MUX_EVENT_CLOSED,
				(union mux_event_data){ 0 });
			return;
		}
	}

	MUX_LOG_F(
		INFO, ss,
		"resuming from suspended state, client_resume_seq=%" PRIuLEAST32,
		client_resume_seq);

	/* Trim the frames the client already received. */
	if (!unacked_resume_ack_recv(ss, client_resume_seq)) {
		session_reset(ss);
		/* Now CLOSED but still in the caller's list; emit MUX_EVENT_CLOSED
		 * so the owner removes it. */
		session_emit(
			ss, MUX_EVENT_CLOSED,
			(union mux_event_data){
				.closed.clean = ss->wire.rx_eof,
			});
		return;
	}

	/* Install the migrated transport; ss now owns the fd and TLS connection.
	 * wire_adopt_tlsconn rebinds the TLS notifier from the transient session
	 * to ss so it never fires on the (about-to-be-freed) transient session. */
	const int new_fd = t->fd;
	t->fd = -1;
#if WITH_TLS
	wire_adopt_tlsconn(ss, t->tlsconn);
	t->tlsconn = NULL;
#endif
	if (ss->w_socket.fd != -1) {
		socket_close(ss->w_socket.fd);
	}

	/* A stream can independently abort/close while suspended, queuing a
	 * fresh frame into wire.sendbuf; capture it so the retransmit replay
	 * below covers it. */
	session_capture_sendbuf(ss);

	/* Reset transport buffers and egress flags so a stale send_blocked cannot
	 * stall the first post-resume flush (mirrors session_attach_fd). */
	wire_discard_buffers(ss);
	ss->wire.rx_open = true;
	ss->wire.tx_pending = false;
	ss->wire.send_blocked = false;
#if WITH_TLS
	ss->wire.tls_want = 0;
#endif

	ev_io_set(&ss->w_socket, new_fd, EV_READ | EV_WRITE);

	ev_timer_stop(ss->loop, &ss->w_send_timeout);
	/* Stop the one-shot resume deadline that session_suspend started.
	 * Restore repeat so the subsequent ev_timer_again arms correctly. */
	ev_timer_stop(ss->loop, &ss->w_connect_timeout);
	ss->w_connect_timeout.repeat = (double)ss->conf.connect_timeout;

	/* Transfer the attach timestamp so setup time covers from session_new()
	 * to SESSION_ESTABLISHED on the resumed session too. */
	ss->connect_started = t->connect_started;

	/* Send ServerHello identifying the client back to itself. */
	session_set_state(ss, SESSION_HANDSHAKE);
	/* Resume cancels any pending drain: the session is being
	 * re-established and must accept new streams again. */
	ss->draining = false;
	ev_timer_again(ss->loop, &ss->w_connect_timeout);
	if (!handshake_enqueue_hello(ss, PROTO_MSG_SERVER_HELLO, true)) {
		/* handshake_enqueue_hello already called session_reset(ss), which
		 * closed the just-installed fd; inform the owner so it removes the
		 * session from its list. */
		if (ss->state == SESSION_CLOSED) {
			session_emit(
				ss, MUX_EVENT_CLOSED,
				(union mux_event_data){
					.closed.clean = ss->wire.rx_eof,
				});
		}
		return;
	}
	session_handshake_done(ss);

	/* Start retransmit replay and I/O. */
	if (ss->unacked.ring != NULL && ss->unacked.ring->count > 0) {
		ss->unacked.retransmit_off = 0;
		ss->wire.tx_pending = true;
	}
	ev_io_start(ss->loop, &ss->w_socket);
	/* Synchronous arm for the queued ServerHello / retransmit replay
	 * (mirrors session_start). */
	session_notify(ss);
}

void mux_resume_attach(
	struct mux_session *restrict ss,
	struct mux_transport *restrict transport,
	const uint_least32_t resume_seq)
{
	session_resume_attach(ss, transport, resume_seq);
	/* Single consume point: a no-op when the attach installed the transport
	 * (fd/tlsconn already cleared), frees it on every failure path. */
	mux_transport_discard(transport);
}

void mux_transport_discard(struct mux_transport *restrict transport)
{
	if (transport->fd != -1) {
		socket_close(transport->fd);
		transport->fd = -1;
	}
#if WITH_TLS
	wire_tlsconn_free(transport->tlsconn);
	transport->tlsconn = NULL;
#endif
}
