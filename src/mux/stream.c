/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file stream.c
 * @brief Internal mux stream state machine implementation.
 */

#include "mux/stream.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "util.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* Format a stream log prefix into buf ("[N] me <- peer:" or "-> peer:").
 * me/peer: identity, then IP, then "[fd:N]".  Returns snprintf byte count. */
int stream_format_tag(
	char *restrict buf, size_t buflen, const struct mux_stream *restrict s)
{
	const struct mux_session *const ss = s->session;
	/* Peer-initiated streams are received on a server session with an
	 * odd stream ID (server-side streams are even by parity).  The
	 * arithmetic also holds for client sessions with even IDs, but
	 * those never occur in practice. */
	const bool peer_initiated = (bool)(s->id & 1u) == ss->accepted;
	const char *const arrow = peer_initiated ? " <- " : " -> ";

	char me[64];
	if (ss->handshake.identity != NULL) {
		(void)snprintf(me, sizeof(me), "%s", ss->handshake.identity);
	} else {
		union sockaddr_max addr;
		if (socket_get_addr(ss->w_socket.fd, &addr) > 0) {
			sa_format(me, sizeof(me), &addr.sa);
		} else {
			const int ret = snprintf(
				me, sizeof(me), "[fd:%d]", ss->w_socket.fd);
			if (ret < 0) {
				me[0] = '\0';
			}
		}
	}

	char peer[64];
	if (ss->handshake.peer_identity != NULL) {
		(void)snprintf(
			peer, sizeof(peer), "%s", ss->handshake.peer_identity);
	} else if (ss->handshake.peer_id != NULL) {
		(void)snprintf(peer, sizeof(peer), "%s", ss->handshake.peer_id);
	} else if (ss->peer_addr.sa.sa_family != AF_UNSPEC) {
		sa_format(peer, sizeof(peer), &ss->peer_addr.sa);
	} else {
		const int ret = snprintf(
			peer, sizeof(peer), "[fd:%d]", ss->w_socket.fd);
		if (ret < 0) {
			peer[0] = '\0';
		}
	}

	return snprintf(
		buf, buflen, "[%" PRIuLEAST16 "] %s%s%s:", s->id, me, arrow,
		peer);
}

#define STREAM_LOG_F(level, s, format, ...)                                    \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char stream_tag_[256];                                         \
		(void)stream_format_tag(                                       \
			stream_tag_, sizeof(stream_tag_), (s));                \
		LOG_F(level, "%s " format, stream_tag_, __VA_ARGS__);          \
	} while (0)
#define STREAM_LOG(level, s, message) STREAM_LOG_F(level, s, "%s", message)

static const char *stream_state_str[] = {
	[STREAM_INIT] = "INIT",
	[STREAM_SYN_SENT] = "SYN_SENT",
	[STREAM_SYN_RECEIVED] = "SYN_RECEIVED",
	[STREAM_ESTABLISHED] = "ESTABLISHED",
	[STREAM_FIN_WAIT] = "FIN_WAIT",
	[STREAM_CLOSE_WAIT] = "CLOSE_WAIT",
	[STREAM_CLOSING] = "CLOSING",
	[STREAM_CLOSED] = "CLOSED",
};

static void stream_stop(struct mux_stream *s);
static inline bool stream_can_send_data(const struct mux_stream *restrict s);

static void stream_set_state(
	struct mux_stream *restrict s, const enum stream_state newstate)
{
	const enum stream_state oldstate = s->state;
	const bool new_halfopen = newstate == STREAM_INIT ||
				  newstate == STREAM_SYN_SENT ||
				  newstate == STREAM_SYN_RECEIVED;

	if (!s->halfopen_counted && new_halfopen) {
		s->session->num_halfopen++;
		s->halfopen_counted = true;
		COUNTER_ADD(s->session->cnt.num_stream_halfopen, 1);
	} else if (s->halfopen_counted && !new_halfopen) {
		ASSERT(s->session->num_halfopen > 0);
		s->session->num_halfopen--;
		s->halfopen_counted = false;
		COUNTER_SUB(s->session->cnt.num_stream_halfopen, 1);
	}
	if (oldstate == newstate) {
		return;
	}
	STREAM_LOG_F(
		DEBUG, s, "state: %s -> %s", stream_state_str[oldstate],
		stream_state_str[newstate]);
	s->state = newstate;
	if (newstate == STREAM_ESTABLISHED) {
		s->quickack_budget = MUX_QUICKACK_BUDGET;
		COUNTER_ADD(s->session->cnt.num_stream_established, 1);
	}
}

static inline void stream_mark_closed(struct mux_stream *restrict s)
{
	const bool was_init = (s->state == STREAM_INIT);
	stream_stop(s);
	/* The tombstone only needs the stream ID for late-frame suppression. */
	if (!s->is_direct && s->socket.w_io.fd != -1) {
		SOCKET_CLOSE_FD(s->socket.w_io.fd);
		s->socket.w_io.fd = -1;
	}
	/* From the caller's perspective the stream is already dead. */
	if (s->rst_received || s->rst_sent) {
		COUNTER_ADD(s->session->cnt.num_stream_failed, 1);
	} else {
		COUNTER_ADD(s->session->cnt.num_stream_succeeded, 1);
	}
	stream_set_state(s, STREAM_CLOSED);
	if (!was_init) {
		/* Late-frame suppression lingers until tombstone_cb hands cleanup back. */
		s->session->sched.num_tombstones++;
		ev_timer_set(&s->w_tombstone, MUX_TOMBSTONE_PERIOD_S, 0.0);
		ev_timer_start(s->session->loop, &s->w_tombstone);
	} else {
		/* No SYN left the host, so there is no peer-visible state to linger. */
		sched_wake(s->session, s);
	}
}

static inline bool
stream_can_shutdown_write_now(const struct mux_stream *restrict s)
{
	return s->is_direct || s->socket.connected;
}

static void stream_shutdown_local_write(struct mux_stream *restrict s)
{
	if (s->tx_shutdown) {
		return;
	}
	if (!s->is_direct) {
		SOCKET_SHUTDOWN_FD(s->socket.w_io.fd, WR);
	}
	s->tx_shutdown = true;
}

static void update_watcher(struct mux_stream *restrict s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	if (!s->socket.connected) {
		modify_io_events(s->session->loop, &s->socket.w_io, EV_WRITE);
		return;
	}

	const int prev_events = s->socket.w_io.events & (EV_READ | EV_WRITE);
	int events = 0;
	uint_fast32_t read_credit = 0;
	/* STREAM_INIT may queue only one fast-open payload before SYN leaves. */
	if (!s->rx_eof &&
	    (s->state == STREAM_ESTABLISHED || s->state == STREAM_CLOSE_WAIT ||
	     (s->state == STREAM_INIT && s->send_queue.head == NULL))) {
		/* stream_read_credit_avail also subtracts queued bytes. */
		read_credit = stream_read_credit_avail(s);
		if (read_credit != 0) {
			events |= EV_READ;
		}
	}
	if (ringbuf_readable(s->recvbuf) > 0) {
		events |= EV_WRITE;
	}
	if ((prev_events & EV_READ) == 0 && (events & EV_READ) != 0) {
		STREAM_LOG_F(
			DEBUG, s,
			"local read resumed: state=%s credit=%" PRIuFAST32
			" queued=%" PRIuLEAST32,
			stream_state_str[s->state], read_credit,
			s->queued_send_bytes);
	} else if (
		(prev_events & EV_READ) != 0 && (events & EV_READ) == 0 &&
		!s->rx_eof && stream_can_send_data(s)) {
		STREAM_LOG_F(
			DEBUG, s,
			"local read gated: state=%s credit=%" PRIuFAST32
			" queued=%" PRIuLEAST32,
			stream_state_str[s->state], stream_read_credit_avail(s),
			s->queued_send_bytes);
	}
	modify_io_events(s->session->loop, &s->socket.w_io, events);
}

static void stream_stop(struct mux_stream *s)
{
	/* stream_free and EV_IDLE cleanup both pass through here. */
	ev_timer_stop(s->session->loop, &s->w_tombstone);
	if (s->delay_pending) {
		struct mux_session *const ss = s->session;
		if (s->delay_prev != NULL) {
			s->delay_prev->delay_next = s->delay_next;
		} else {
			ss->sched.delay_head = s->delay_next;
		}
		if (s->delay_next != NULL) {
			s->delay_next->delay_prev = s->delay_prev;
		}
		s->delay_prev = NULL;
		s->delay_next = NULL;
		s->delay_pending = false;
		s->delay_ticks = 0;
	}
	if (s->is_direct) {
		return;
	}
	struct ev_loop *loop = s->session->loop;
	ev_io_stop(loop, &s->socket.w_io);
	ev_timer_stop(loop, &s->socket.w_timeout);
}

/* Abort the stream locally and emit one peer-visible RST. */
static void
stream_abort(struct mux_stream *restrict s, const enum mux_status code)
{
	STREAM_LOG(DEBUG, s, "aborting (RST)");
	COUNTER_ADD(s->session->cnt.num_stream_errors, 1);
	session_discard_stream_frames(s->session, s->id);
	if (!s->rst_sent) {
		s->rst_sent = true;
		session_send_ctrl(s->session, s->id, MUX_FLAG_RST, code);
	}
	stream_mark_closed(s);
}

/*
 * Update the send-side timeout after a flush attempt (socket mode only).
 * Stop the timer when the receive queue is empty; reset (ev_timer_again) on
 * progress, or arm it for the first time when blocked with pending data.
 */
static void
update_send_timeout(struct mux_stream *restrict s, const bool progress)
{
	if (s->socket.w_timeout.repeat <= 0.0) {
		return;
	}
	if (ringbuf_readable(s->recvbuf) == 0) {
		ev_timer_stop(s->session->loop, &s->socket.w_timeout);
		return;
	}
	if (!ev_is_active(&s->socket.w_timeout) || progress) {
		ev_timer_again(s->session->loop, &s->socket.w_timeout);
	}
}

/* Write data to the local socket fd, handling partial writes and EAGAIN.
 * Returns bytes written (may be 0 on EAGAIN).  On hard error calls
 * stream_abort and returns 0; caller must check s->state afterwards. */
static size_t stream_local_write(
	struct mux_stream *restrict s, const unsigned char *restrict data,
	const size_t len)
{
	const int sfd = s->socket.w_io.fd;
	size_t nwrite = 0;
	while (nwrite < len) {
		size_t nbytes = len - nwrite;
		const int err = socket_send(sfd, data + nwrite, &nbytes);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				break;
			}
			LOGE_F("send [fd:%d]: (%d) %s", sfd, err,
			       strerror(err));
			stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
			return 0;
		}
		if (nbytes == 0) {
			break;
		}
		nwrite += nbytes;
	}
	return nwrite;
}

static void stream_flush_local(struct mux_stream *s)
{
	bool made_progress = false;
	while (ringbuf_readable(s->recvbuf) > 0) {
		const size_t len = ringbuf_readable(s->recvbuf);
		const unsigned char *const data = ringbuf_read_ptr(s->recvbuf);
		const size_t nwrite = stream_local_write(s, data, len);
		if (nwrite == 0) {
			update_send_timeout(s, made_progress);
			return;
		}

		made_progress = true;
		ringbuf_consume(s->recvbuf, nwrite);
		s->buffered_bytes -= nwrite;
		s->session->recv_buffered_bytes -= nwrite;
		COUNTER_SUB(s->session->cnt.recv_buffered_bytes, nwrite);
		STREAM_LOG_F(
			VERBOSE, s,
			"local send: %zu bytes, buffered=%" PRIuLEAST32, nwrite,
			s->buffered_bytes);

		stream_check_ack(s);
	}

	update_send_timeout(s, false);
	if ((s->state == STREAM_CLOSE_WAIT || s->state == STREAM_CLOSING) &&
	    ringbuf_readable(s->recvbuf) == 0) {
		if (!s->tx_shutdown) {
			STREAM_LOG(VERBOSE, s, "shutdown local send");
			stream_shutdown_local_write(s);
		}
		/* Close only when both FINs exchanged and recv fully flushed.
		 * The outer guard limits state to CLOSE_WAIT or CLOSING, so
		 * only CLOSING signals "both FINs done". */
		if (s->state == STREAM_CLOSING) {
			stream_mark_closed(s);
		}
	}
}

/*
 * Deliver @p revents to the user-supplied direct-I/O watcher, filtered by the
 * events it registered interest in.  No-op when no watcher is present or when
 * @p revents contains no interesting bits.
 */
static inline void
stream_feed_user(struct mux_stream *restrict s, const int revents)
{
	if (!s->is_direct) {
		return;
	}
	struct mux_stream_io *const w = s->direct.w_io;
	if (w == NULL) {
		return;
	}
	const int filtered = revents & w->events;
	if (filtered == 0) {
		return;
	}
	ev_feed_event(w->loop, w, filtered);
}

void stream_on_send(struct mux_stream *restrict s)
{
	/* Re-evaluate the socket-mode watcher after a frame has been dequeued
	 * from send_queue by the mux scheduler.  Freeing one slot may restore
	 * read credit and re-enable EV_READ for the next local socket read. */
	if (!s->is_direct) {
		update_watcher(s);
		return;
	}
	/* Notify the user that send credit is available; otherwise credit
	 * would only be visible after the peer sends a window update. */
	if (stream_read_credit_avail(s) > 0) {
		stream_feed_user(s, EV_WRITE);
	}
}

static inline void
stream_queue_send(struct mux_stream *s, struct mux_frame *frame)
{
	frame->pos = 0;
	s->queued_send_bytes +=
		(uint_least32_t)(frame->len - MUX_FRAME_HEADER_SIZE);
	mux_frame_list_push(&s->send_queue, frame);
	s->session->send_buffered_frames++;
	COUNTER_ADD(s->session->cnt.send_buffered_frames, 1);
}

static inline bool stream_can_send_data(const struct mux_stream *restrict s)
{
	return s->state == STREAM_INIT || s->state == STREAM_ESTABLISHED ||
	       s->state == STREAM_CLOSE_WAIT;
}

static bool recv_cb(struct mux_stream *restrict s)
{
	if (s->rx_eof || !stream_can_send_data(s)) {
		return false;
	}

	const uint_fast32_t read_credit = stream_read_credit_avail(s);
	if (read_credit == 0) {
		STREAM_LOG(VERBOSE, s, "send credit exhausted, pausing read");
		return false;
	}

	struct mux_frame *frame = session_frame_alloc(s->session);
	if (frame == NULL) {
		STREAM_LOG(WARNING, s, "out of memory for send frame");
		return false;
	}

	unsigned char *buf = frame->data + MUX_FRAME_HEADER_SIZE;
	size_t nread;
	{
		const int fd = s->socket.w_io.fd;
		size_t nrecv = MUX_MAX_PAYLOAD_SIZE;
		const int err = socket_recv(fd, buf, &nrecv);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				session_frame_free(s->session, frame);
				return false; /* wait for EV_READ */
			}
			LOGE_F("recv [fd:%d]: (%d) %s", fd, err, strerror(err));
			session_frame_free(s->session, frame);
			stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
			return false;
		}
		nread = nrecv; /* 0 means EOF */
	}

	if (nread > 0) {
		STREAM_LOG_F(VERBOSE, s, "local recv: %zu bytes", nread);
		frame->len = MUX_FRAME_HEADER_SIZE + nread;

		stream_queue_send(s, frame);
	} else {
		session_frame_free(s->session, frame);
		s->rx_eof = true;
		STREAM_LOG(VERBOSE, s, "local recv: EOF");
	}

	session_eager_flush(s->session, s);
	return nread > 0;
}

static void local_on_connected(struct mux_stream *restrict s)
{
	ev_timer_stop(s->session->loop, &s->socket.w_timeout);
	const int sockerr = socket_get_error(s->socket.w_io.fd);
	if (sockerr != 0) {
		STREAM_LOG_F(
			WARNING, s, "connect [fd:%d]: (%d) %s",
			s->socket.w_io.fd, sockerr, strerror(sockerr));
		stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
		return;
	}
	STREAM_LOG_F(VERBOSE, s, "connected [fd:%d]", s->socket.w_io.fd);
	s->socket.connected = true;
}

static void send_cb(struct mux_stream *restrict s)
{
	if (!s->socket.connected) {
		local_on_connected(s);
		if (s->state == STREAM_CLOSED) {
			return;
		}
	}

	stream_flush_local(s);
}

static void local_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct mux_stream *restrict s = w->data;
	ASSERT(!s->is_direct);
	ASSERT(loop == s->session->loop);
	UNUSED(loop);
	ASSERT(s->state == STREAM_INIT || s->state == STREAM_ESTABLISHED ||
	       s->state == STREAM_FIN_WAIT || s->state == STREAM_CLOSE_WAIT);
	STREAM_LOG_F(
		VERBOSE, s, "stream socket: state=%s revents=%d",
		stream_state_str[s->state], revents);
	if (revents & EV_READ) {
		while (recv_cb(s) && s->state != STREAM_CLOSED) {
		}
	}
	if ((revents & EV_WRITE) && s->state != STREAM_CLOSED) {
		send_cb(s);
	}
	update_watcher(s);
	session_flush(s->session);
}

static void timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_stream *restrict s = w->data;
	ASSERT(loop == s->session->loop);
	UNUSED(loop);
	ASSERT(!s->is_direct);
	struct mux_session *restrict ss = s->session;
	STREAM_LOG(WARNING, s, "local socket timeout");
	stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
	session_flush(ss);
}

static void tombstone_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_stream *restrict s = w->data;
	ASSERT(loop == s->session->loop);
	UNUSED(loop);
	ASSERT(s->state == STREAM_CLOSED);
	STREAM_LOG(DEBUG, s, "tombstone expired; scheduling cleanup");
	ASSERT(s->session->sched.num_tombstones > 0);
	s->session->sched.num_tombstones--;
	/* Re-enter the normal EV_IDLE cleanup path: sched_wake routes CLOSED
	 * streams to the lp queue, which calls sched_remove_stream + stream_free. */
	sched_wake(s->session, s);
}

struct mux_stream *stream_new(
	struct mux_session *restrict ss, const uint_fast16_t id,
	const bool active_open)
{
	struct mux_stream *s = malloc(sizeof(struct mux_stream));
	if (s == NULL) {
		return NULL;
	}
	const struct mux_config *restrict conf = &ss->conf;
	*s = (struct mux_stream){
		.id = id,
		.state = STREAM_INIT,
		.session = ss,
		.recv_window =
			(uint_fast32_t)ss->stream_window * MUX_MAX_PAYLOAD_SIZE,
		.send_window = MUX_DEFAULT_SEND_WINDOW,
		.grant_sent = MUX_DEFAULT_SEND_WINDOW,
		.unacked_bytes = 0,
		.deficit = 0,
	};
	ev_io_init(&s->socket.w_io, local_cb, -1, EV_NONE);
	s->socket.w_io.data = s;
	const double timeout = (double)conf->send_timeout;
	ev_timer_init(&s->socket.w_timeout, timeout_cb, 0.0, timeout);
	s->socket.w_timeout.data = s;
	s->recvbuf = ringbuf_new(MUX_MAX_PAYLOAD_SIZE);
	if (s->recvbuf == NULL) {
		free(s);
		return NULL;
	}
	if (active_open) {
		COUNTER_ADD(ss->cnt.num_stream_opened, 1);
	} else {
		COUNTER_ADD(ss->cnt.num_stream_accepted, 1);
	}
	COUNTER_ADD(ss->cnt.num_streams, 1);
	stream_set_state(s, active_open ? STREAM_INIT : STREAM_SYN_RECEIVED);
	ev_timer_init(&s->w_tombstone, tombstone_cb, 0.0, 0.0);
	s->w_tombstone.data = s;
	STREAM_LOG_F(DEBUG, s, "created, state=%s", stream_state_str[s->state]);
	return s;
}

/* Detach the user watcher from the stream without invoking any callback. */
static void stream_detach_user(struct mux_stream *restrict s)
{
	if (!s->is_direct) {
		return;
	}
	struct mux_stream_io *const w = s->direct.w_io;
	if (w == NULL) {
		return;
	}
	ev_clear_pending(w->loop, w);
	w->stream = NULL;
	w->active = 0;
	s->direct.w_io = NULL;
}

void stream_free(struct mux_stream *s)
{
	if (s == NULL) {
		return;
	}
	LOGV_F("[stream:%" PRIuLEAST16 "] freeing", s->id);
	if (s->halfopen_counted) {
		ASSERT(s->session->num_halfopen > 0);
		s->session->num_halfopen--;
		s->halfopen_counted = false;
		COUNTER_SUB(s->session->cnt.num_stream_halfopen, 1);
	}
	COUNTER_SUB(s->session->cnt.num_streams, 1);

	/* Safety net: detach/stop without invoking callbacks. */
	stream_detach_user(s);
	stream_stop(s);
	s->session->send_buffered_frames -= s->send_queue.count;
	COUNTER_SUB(s->session->cnt.send_buffered_frames, s->send_queue.count);
	mux_frame_list_clear(&s->send_queue, &s->session->pool);
	s->session->recv_buffered_bytes -= s->recvbuf->len;
	COUNTER_SUB(s->session->cnt.recv_buffered_bytes, s->recvbuf->len);
	ringbuf_free(s->recvbuf);
	if (!s->is_direct && s->socket.w_io.fd != -1) {
		SOCKET_CLOSE_FD(s->socket.w_io.fd);
	}
	free(s);
}

void stream_attach_fd(struct mux_stream *s, const int fd)
{
	ASSERT(s->state == STREAM_SYN_RECEIVED || s->state == STREAM_INIT ||
	       s->state == STREAM_SYN_SENT);
	ASSERT(!s->is_direct);

	struct ev_loop *loop = s->session->loop;
	if (socket_user_timeout(fd, s->session->conf.send_timeout * 1000) ==
	    0) {
		s->socket.w_timeout.repeat = 0.0;
	}
	if (s->state == STREAM_SYN_RECEIVED) {
		STREAM_LOG_F(
			INFO, s, "stream accepted, local connect [fd:%d]", fd);
		/* Send SYN|ACK immediately so the peer can start data transfer
		 * while the local connect() is still in progress.  Received data
		 * is buffered and flushed once the connection completes. */
		const uint_fast32_t inc = stream_grant_inc(s);
		session_send_ctrl(
			s->session, s->id, MUX_FLAG_SYN | MUX_FLAG_ACK, inc);
		s->grant_sent += inc * MUX_WINDOW_UNIT;
		s->ack_pending = false;
		stream_set_state(s, STREAM_ESTABLISHED);
		s->socket.connected = false;
		ev_io_set(&s->socket.w_io, fd, EV_WRITE);
		if (s->socket.w_timeout.repeat > 0.0) {
			ev_timer_again(loop, &s->socket.w_timeout);
		}
	} else {
		STREAM_LOG_F(VERBOSE, s, "local accept [fd:%d]", fd);
		s->socket.connected = true;
		/* One frame may be read here for fast open (SYN|PUSH);
		 * update_watcher will set EV_READ when the queue is empty. */
		ev_io_set(&s->socket.w_io, fd, EV_NONE);
	}
	ev_io_start(loop, &s->socket.w_io);
	update_watcher(s);
}

void stream_io_start(struct ev_loop *loop, struct mux_stream_io *w)
{
	struct mux_stream *s = w->stream;
	ASSERT(s != NULL);
	ASSERT(s->state == STREAM_SYN_RECEIVED || s->state == STREAM_INIT ||
	       s->state == STREAM_SYN_SENT);
	ASSERT(!s->is_direct); /* neither mode activated yet */

	w->loop = loop;
	if (s->state == STREAM_SYN_RECEIVED) {
		/* Passive opener: local side is ready, complete the handshake. */
		STREAM_LOG(INFO, s, "stream accepted (direct)");
		const uint_fast32_t inc = stream_grant_inc(s);
		session_send_ctrl(
			s->session, s->id, MUX_FLAG_SYN | MUX_FLAG_ACK, inc);
		s->grant_sent += inc * MUX_WINDOW_UNIT;
		s->ack_pending = false;
		stream_set_state(s, STREAM_ESTABLISHED);
	} else {
		STREAM_LOG(VERBOSE, s, "direct attach (active)");
	}

	s->is_direct = true;
	s->direct.w_io = w;
	w->active = 1;

	if (ringbuf_readable(s->recvbuf) > 0 || s->state == STREAM_CLOSE_WAIT ||
	    s->state == STREAM_CLOSING) {
		stream_feed_user(s, EV_READ);
	}
	if (stream_can_send_data(s) && stream_read_credit_avail(s) != 0) {
		stream_feed_user(s, EV_WRITE);
	}
}

void stream_mark_syn_sent(struct mux_stream *s)
{
	ASSERT(s->state == STREAM_INIT);
	stream_set_state(s, STREAM_SYN_SENT);
	/* Fast-open path: fd is attached; stop watcher while SYN is in flight.
	 * If fd == -1, the watcher was never started. */
	if (s->socket.w_io.fd != -1) {
		update_watcher(s);
	}
}

static inline void stream_notify_writable(struct mux_stream *restrict s)
{
	if (!s->is_direct) {
		update_watcher(s);
	}
	stream_feed_user(s, EV_WRITE);
}

void stream_start(struct mux_stream *s)
{
	STREAM_LOG(VERBOSE, s, "starting");
	ASSERT(s->state == STREAM_SYN_SENT);
	stream_set_state(s, STREAM_ESTABLISHED);
	if (s->rx_eof &&
	    !(s->state == STREAM_FIN_WAIT || s->state == STREAM_CLOSING) &&
	    s->send_queue.head == NULL) {
		STREAM_LOG(VERBOSE, s, "early local EOF, scheduling FIN");
		sched_wake(s->session, s);
	}
	stream_notify_writable(s);
}

struct mux_frame *stream_dequeue_send(struct mux_stream *restrict s)
{
	/* Allow first payload in pre-SYN stage, then regular established states. */
	if (!stream_can_send_data(s)) {
		return NULL;
	}

	struct mux_frame *frame = s->send_queue.head;
	if (frame == NULL) {
		/* Clear stale nagle_flush: the delay timer may have fired for
		 * a delayed-ACK when no data was queued; consuming the flag
		 * here prevents the next small frame from bypassing Nagle. */
		s->nagle_flush = false;
		return NULL;
	}

	const uint_fast32_t credit = stream_credit_avail(s);
	if (credit == 0) {
		STREAM_LOG(VERBOSE, s, "send credit exhausted");
		return NULL;
	}
	STREAM_LOG_F(
		VERYVERBOSE, s, "dequeue_send credit=%" PRIuFAST32, credit);
	const size_t payload = frame->len - MUX_FRAME_HEADER_SIZE;
	STREAM_LOG_F(
		VERYVERBOSE, s,
		"dequeue_send payload=%zu frame_len=%zu frame_pos=%zu", payload,
		frame->len, frame->pos);

	if (payload == 0 || payload > credit) {
		STREAM_LOG_F(
			VERYVERBOSE, s,
			"dequeue blocked: payload=%zu credit=%" PRIuFAST32,
			payload, credit);
		return NULL;
	}

	/* Nagle: hold small frames while unacked data is in-flight.
	 * nagle_flush is a one-shot bypass set by the delay scheduler. */
	const bool nagle_bypass = s->nagle_flush;
	s->nagle_flush = false;
	if (!s->session->conf.nodelay && !nagle_bypass &&
	    s->unacked_bytes > 0 && payload < (size_t)MUX_MAX_PAYLOAD_SIZE) {
		STREAM_LOG_F(
			VERYVERBOSE, s,
			"nagle hold: payload=%zu unacked=%" PRIuLEAST32,
			payload, s->unacked_bytes);
		return NULL;
	}

	frame = mux_frame_list_pop(&s->send_queue);
	s->queued_send_bytes -=
		(uint_least32_t)(frame->len - MUX_FRAME_HEADER_SIZE);
	s->session->send_buffered_frames--;
	COUNTER_SUB(s->session->cnt.send_buffered_frames, 1);
	return frame;
}

/* Scale per-stream window grants by session receive-buffer pressure.
 * Disabled when mem_pressure_hi <= 0; fast path returns 1.0 when
 * nothing is buffered.  Linear decay from 1.0 to a minimum scale
 * in [s_lo, s_hi]; clamped at the minimum beyond s_hi. */
static double session_pressure_scale(const struct mux_session *restrict ss)
{
	if (ss->conf.mem_pressure_hi <= 0) {
		return 1.0;
	}
	if (ss->recv_buffered_bytes == 0) {
		return 1.0;
	}
	const double buffered = (double)ss->recv_buffered_bytes;
	const double s_high = (double)ss->conf.mem_pressure_hi;
	const double s_low = ss->conf.mem_pressure_lo > 0 ?
				     (double)ss->conf.mem_pressure_lo :
				     s_high * 0.5;
	if (buffered <= s_low) {
		return 1.0;
	}
	if (buffered >= s_high) {
		return 0.125;
	}
	return 1.0 - (buffered - s_low) / (s_high - s_low) * (1.0 - 0.125);
}

/* Compute the window increment to grant the peer (in MUX_WINDOW_UNIT units).
 * Scales by session_pressure_scale(); floors at one unit to avoid starvation. */
uint_fast32_t stream_grant_inc(const struct mux_stream *restrict s)
{
	const uint_fast32_t grantable = stream_grantable_bytes(s);
	/* Sub-unit grantable cannot be expressed on the wire (spec §6.4:
	 * extra = floor(grantable / MUX_WINDOW_UNIT)); applying the safety
	 * floor below would otherwise over-grant beyond the true available
	 * receive window, violating spec §6.3. */
	if (grantable < (uint_fast32_t)MUX_WINDOW_UNIT) {
		return 0;
	}
	const double scale = session_pressure_scale(s->session);
	const uint_fast32_t scaled = (uint_fast32_t)((double)grantable * scale);
	/* Safety floor: always grant at least one unit when grantable allows
	 * so no stream is starved and the flow-control loop cannot deadlock. */
	const uint_fast32_t effective =
		MAX(scaled, (uint_fast32_t)MUX_WINDOW_UNIT);
	const uint_fast32_t grant =
		MIN(effective / (uint_fast32_t)MUX_WINDOW_UNIT,
		    (uint_fast32_t)UINT16_MAX);
	if (scale < 1.0) {
		STREAM_LOG_F(
			VERBOSE, s,
			"memory pressure: scale=%.3f grantable=%" PRIuFAST32
			" grant=%" PRIuFAST32,
			scale, grantable, grant);
	}
	return grant;
}

/* In auto-window mode, lazily sync recv_window down to the current session
 * stream_window target whenever the safety constraint is satisfied: all
 * credit already granted to the peer has been consumed (outstanding == 0 or
 * buffered + outstanding fits inside the new target).  Called at the top of
 * stream_check_ack so every grant evaluation sees the up-to-date window. */
static void stream_try_shrink_recv_window(struct mux_stream *restrict s)
{
	if (!s->session->auto_stream_window) {
		return;
	}
	const uint_fast32_t target =
		(uint_fast32_t)s->session->stream_window * MUX_MAX_PAYLOAD_SIZE;
	if (target >= s->recv_window) {
		return;
	}
	/* outstanding = credit peer may still spend (wrapping subtraction). */
	const uint_fast32_t outstanding =
		(uint_fast32_t)(s->grant_sent - s->bytes_received);
	if (s->buffered_bytes + outstanding > target) {
		return;
	}
	STREAM_LOG_F(
		DEBUG, s,
		"recv_window shrink: %" PRIuLEAST32 " -> %" PRIuFAST32
		" (buffered=%" PRIuLEAST32 " outstanding=%" PRIuFAST32 ")",
		s->recv_window, target, s->buffered_bytes, outstanding);
	s->recv_window = target;
}

void stream_check_ack(struct mux_stream *restrict s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	stream_try_shrink_recv_window(s);
	if (s->ack_pending) {
		return;
	}
	const uint_fast32_t grantable = stream_grantable_bytes(s);
	/* Sub-unit grantable cannot be sent; see stream_grant_inc(). */
	if (grantable < (uint_fast32_t)MUX_WINDOW_UNIT) {
		return;
	}
	/* Immediate ACK when the quickack budget is active (TCP-style quickack
	 * for stream startup and window-growth events), or when grantable credit
	 * reaches the 2-frame batch threshold (avoids half-window starvation at
	 * large auto-tuned receive windows). */
	const uint_fast32_t immediate =
		2u * (uint_fast32_t)MUX_MAX_PAYLOAD_SIZE;
	const bool quickack = grantable >= immediate || s->quickack_budget > 0;
	if (!quickack) {
		/* Sub-threshold: arm the coalescing timer so the grant is conveyed on
		 * the next flush (spec §6.4, §7.1). */
		STREAM_LOG_F(
			VERBOSE, s,
			"ACK delayed: grantable=%" PRIuFAST32
			" quickack_remaining=%u",
			grantable, (unsigned)s->quickack_budget);
		sched_delay(s->session, s, MUX_DELAYED_ACK_TICKS);
		return;
	}
	if (s->quickack_budget > 0) {
		s->quickack_budget--;
	}
	STREAM_LOG_F(
		DEBUG, s,
		"ACK immediate: grantable=%" PRIuFAST32
		" quickack_remaining=%u",
		grantable, (unsigned)s->quickack_budget);
	s->ack_pending = true;
	if (s->send_queue.head == NULL && s->sched_queue != SCHED_QUEUE_DRR &&
	    s != s->session->sched.drr_active) {
		/* No data to piggyback on and not already in DRR: queue
		 * for pure control-frame emission via ctrl_pending list. */
		sched_ctrl_enqueue(s->session, s);
		s->session->wire.tx_pending = true;
		session_notify(s->session);
	} else if (s->sched_queue != SCHED_QUEUE_DRR) {
		sched_wake(s->session, s);
	}
}

static inline void stream_notify_readable(struct mux_stream *restrict s)
{
	if (s->is_direct) {
		stream_feed_user(s, EV_READ);
		return;
	}
	if (s->socket.connected) {
		stream_flush_local(s);
	}
	update_watcher(s);
	stream_feed_user(s, EV_READ);
}

void stream_recv_copy(
	struct mux_stream *restrict s, const unsigned char *restrict payload,
	size_t payload_len)
{
	/* Window updates are quantized to MUX_WINDOW_UNIT; up to one full
	 * payload of over-window data is tolerated.  Hard cap: recv_window. */
	if (s->state == STREAM_CLOSED) {
		STREAM_LOG_F(
			VERBOSE, s,
			"discarding PUSH frame (%zu bytes) in CLOSED state",
			payload_len);
		return;
	}

	STREAM_LOG_F(
		VERYVERBOSE, s, "receiving PUSH frame with %zu bytes",
		payload_len);
	if (s->buffered_bytes + payload_len > s->recv_window) {
		STREAM_LOG_F(
			WARNING, s,
			"recv window overflow: payload_len=%zu buffered=%" PRIuLEAST32
			" window=%" PRIuLEAST32,
			payload_len, s->buffered_bytes, s->recv_window);
		stream_abort(s, MUX_STATUS_FLOW_CONTROL_ERROR);
		return;
	}

	/* Fast path: when the receive buffer is empty and the local socket
	 * is connected and writable, write the payload directly to the local
	 * fd, bypassing the intermediate recvbuf memcpy and the flush round-
	 * trip through the event loop.  Only the unwritten remainder falls
	 * through to the normal ringbuf path. */
	if (payload_len > 0 && ringbuf_readable(s->recvbuf) == 0 &&
	    s->socket.connected && !s->is_direct &&
	    (s->state == STREAM_ESTABLISHED || s->state == STREAM_CLOSE_WAIT)) {
		const size_t nwrite =
			stream_local_write(s, payload, payload_len);
		if (s->state == STREAM_CLOSED) {
			return;
		}
		if (nwrite > 0) {
			s->bytes_received += nwrite;
			payload += nwrite;
			payload_len -= nwrite;
			stream_check_ack(s);
			if (payload_len == 0) {
				STREAM_LOG_F(
					VERYVERBOSE, s,
					"direct write: %zu bytes, "
					"received=%" PRIuLEAST32,
					nwrite, s->bytes_received);
				return;
			}
		}
	}

	if (payload_len == 0) {
		return;
	}

	if (!ringbuf_reserve(&s->recvbuf, payload_len, true)) {
		STREAM_LOG(WARNING, s, "out of memory for receive buffer");
		stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
		return;
	}

	if (payload_len > 0) {
		memcpy(ringbuf_write_ptr(s->recvbuf), payload, payload_len);
		ringbuf_produce(s->recvbuf, payload_len);
	}
	s->session->recv_buffered_bytes += payload_len;
	COUNTER_ADD(s->session->cnt.recv_buffered_bytes, payload_len);
	s->bytes_received += payload_len;
	s->buffered_bytes += payload_len;

	STREAM_LOG_F(
		VERYVERBOSE, s,
		"queued %zu bytes, received=%" PRIuLEAST32
		" buffered=%" PRIuLEAST32,
		payload_len, s->bytes_received, s->buffered_bytes);

	stream_notify_readable(s);
}

void stream_recv_window(struct mux_stream *s, const uint_fast32_t window_inc)
{
	const uint_fast32_t inc_bytes = window_inc * MUX_WINDOW_UNIT;

	/* spec §6.6: pre-check with 64-bit arithmetic avoids wrapping.
	 * The applicable bound is INT32_MAX (the range within which §6.6
	 * wrapping arithmetic is correct); recv_window is not on the wire. */
	const uint_fast32_t outstanding = stream_credit_avail(s);
	if ((uintmax_t)outstanding + inc_bytes > (uintmax_t)INT32_MAX) {
		STREAM_LOG_F(
			WARNING, s,
			"excessive send credit: outstanding=%" PRIuFAST32
			" inc=%" PRIuFAST32,
			outstanding, inc_bytes);
		stream_abort(s, MUX_STATUS_FLOW_CONTROL_ERROR);
		return;
	}

	s->send_window += inc_bytes;

	STREAM_LOG_F(
		VERYVERBOSE, s,
		"recv_window: inc=%" PRIuFAST32 " send_window=%" PRIuLEAST32
		" sent=%" PRIuLEAST32,
		window_inc, s->send_window, s->bytes_sent);
	if (outstanding == 0 && inc_bytes > 0) {
		STREAM_LOG_F(
			DEBUG, s,
			"send credit restored: inc=%" PRIuFAST32
			" credit=%" PRIuFAST32 " queued=%" PRIuLEAST32,
			window_inc, stream_credit_avail(s),
			s->queued_send_bytes);
	}

	if (outstanding + inc_bytes == 0) {
		STREAM_LOG(VERYVERBOSE, s, "send credit still exhausted");
		return;
	}

	stream_notify_writable(s);

	if (s->send_queue.head != NULL) {
		sched_wake(s->session, s);
	}
}

void stream_mark_fin_sent(struct mux_stream *s)
{
	if (s->state == STREAM_FIN_WAIT || s->state == STREAM_CLOSING) {
		return;
	}
	STREAM_LOG(DEBUG, s, "sent FIN");

	switch (s->state) {
	case STREAM_ESTABLISHED:
		stream_set_state(s, STREAM_FIN_WAIT);
		break;
	case STREAM_CLOSE_WAIT:
		/* Both FINs exchanged; enter CLOSING until recv fully flushed */
		stream_set_state(s, STREAM_CLOSING);
		if (ringbuf_readable(s->recvbuf) == 0 && !s->is_direct) {
			stream_mark_closed(s);
		}
		break;
	default:
		STREAM_LOG_F(
			WARNING, s, "FIN sent in unexpected state=%s",
			stream_state_str[s->state]);
		break;
	}
}

void stream_recv_fin(struct mux_stream *s)
{
	if (s->state == STREAM_CLOSE_WAIT || s->state == STREAM_CLOSING) {
		return;
	}

	STREAM_LOG(DEBUG, s, "received FIN");

	switch (s->state) {
	case STREAM_ESTABLISHED:
		stream_set_state(s, STREAM_CLOSE_WAIT);
		break;
	case STREAM_FIN_WAIT:
		/* Both FINs exchanged; enter CLOSING until recv fully flushed */
		stream_set_state(s, STREAM_CLOSING);
		break;
	default:
		STREAM_LOG_F(
			WARNING, s, "FIN received in unexpected state=%s",
			stream_state_str[s->state]);
		break;
	}

	/* For socket mode with no pending recv data: shutdown local write
	 * immediately.  For direct mode the user reads via mux_stream_recv,
	 * which handles shutdown and close; defer to avoid blocking EOF
	 * delivery.  In socket mode, also defer when connect is still in
	 * progress; stream_flush_local shuts down the write side then. */
	if (!s->is_direct && ringbuf_readable(s->recvbuf) == 0 &&
	    !s->tx_shutdown && stream_can_shutdown_write_now(s)) {
		STREAM_LOG(VERBOSE, s, "shutdown local send (no pending)");
		stream_shutdown_local_write(s);
		/* Close if both FINs exchanged and recv fully flushed.
		 * The switch above transitions FIN_WAIT to CLOSING, so only
		 * CLOSING is reachable here. */
		if (s->state == STREAM_CLOSING) {
			stream_mark_closed(s);
		}
	}
	stream_feed_user(s, EV_READ);
}

static void stream_rst_notify_direct(struct mux_stream *restrict s)
{
	struct mux_stream_io *const w = s->direct.w_io;
	if (w == NULL) {
		return;
	}
	ev_clear_pending(w->loop, w);
	ev_invoke(w->loop, w, EV_READ);
}

static void stream_rst_notify_socket(struct mux_stream *restrict s)
{
	/* Abortively close the local socket to propagate RST to the peer. */
	socket_set_linger(s->socket.w_io.fd, true, 0);
}

void stream_recv_rst(struct mux_stream *s)
{
	STREAM_LOG(DEBUG, s, "received RST");
	s->rst_received = true;
	if (!s->is_direct) {
		stream_rst_notify_socket(s);
	} else {
		/* Fire EV_READ synchronously before watcher detach so the
		 * user callback sees rst_received; it may call mux_stream_close(),
		 * transitioning to STREAM_CLOSED — guard teardown against that. */
		stream_rst_notify_direct(s);
	}
	if (s->state == STREAM_CLOSED) {
		return;
	}
	stream_detach_user(s);
	/* Discard outbound frames and the inbound receive buffer (spec §4.3.4:
	 * data buffered in the receive buffer MUST be discarded on RST). */
	session_discard_stream_frames(s->session, s->id);
	s->session->recv_buffered_bytes -= s->recvbuf->len;
	COUNTER_SUB(s->session->cnt.recv_buffered_bytes, s->recvbuf->len);
	ringbuf_reset(s->recvbuf);
	s->buffered_bytes = 0;
	stream_mark_closed(s);
}

void stream_close(struct mux_stream *s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	STREAM_LOG(VERBOSE, s, "closing");
	if (ringbuf_readable(s->recvbuf) > 0) {
		STREAM_LOG(DEBUG, s, "unread data at close, sending RST");
		s->session->recv_buffered_bytes -= s->recvbuf->len;
		COUNTER_SUB(
			s->session->cnt.recv_buffered_bytes, s->recvbuf->len);
		ringbuf_reset(s->recvbuf);
		s->buffered_bytes = 0;
		session_discard_stream_frames(s->session, s->id);
		if (!s->rst_sent) {
			s->rst_sent = true;
			session_send_ctrl(
				s->session, s->id, MUX_FLAG_RST,
				MUX_STATUS_CANCEL);
		}
	}
	stream_detach_user(s);
	stream_mark_closed(s);
}

void stream_shutdown(struct mux_stream *s)
{
	STREAM_LOG(VERBOSE, s, "local shutdown (write-EOF)");
	s->rx_eof = true;
	sched_wake(s->session, s);
}
