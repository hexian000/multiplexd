/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file mux.c
 * @brief Public mux API wrappers over the internal session machinery.
 */

#include "mux/mux.h"

#include "mux/estimator.h"
#include "mux/frame.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "mux/stream_io.h"
#include "mux/wire.h"

#include "meta/minmax.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

size_t mux_frame_object_size(const size_t max_payload)
{
	return MUX_FRAME_OBJECT_SIZE(max_payload);
}

struct mux_session *
mux_new(struct ev_loop *restrict loop, const struct mux_session_opts *opts)
{
	return mux_session_new(loop, opts);
}

void mux_close(struct mux_session *ss)
{
	mux_session_close(ss);
}

void mux_set_callbacks(struct mux_session *ss, const struct mux_callbacks *cb)
{
	ss->callbacks = *cb;
}

void mux_shutdown(struct mux_session *ss)
{
	mux_session_initiate_shutdown(ss);
}

void mux_start(struct mux_session *ss)
{
	mux_session_start(ss);
}

void mux_attach_fd(struct mux_session *ss, const int fd)
{
	mux_session_attach_fd(ss, fd);
}

/* --- Session accessors --- */

int mux_fd(const struct mux_session *ss)
{
	return ss->w_socket.fd;
}

#if WITH_TLS
struct tls_connection *mux_tls_conn(const struct mux_session *ss)
{
	return ss->wire.tlsconn;
}
#endif

const struct sockaddr *mux_peer_addr(const struct mux_session *ss)
{
	if (ss->peer_addr.sa.sa_family == AF_UNSPEC) {
		return NULL;
	}
	return &ss->peer_addr.sa;
}

enum mux_state mux_state(const struct mux_session *ss)
{
	/* Read the relaxed-atomic mirror: callable from the server thread. */
	switch ((enum session_state)PUB_LOAD(ss->_pub_state)) {
	case SESSION_ESTABLISHED:
		return MUX_STATE_ESTABLISHED;
	case SESSION_CLOSING:
	case SESSION_CLOSE_WAIT:
		return MUX_STATE_CLOSING;
	case SESSION_SUSPENDED:
		return MUX_STATE_SUSPENDED;
	case SESSION_INIT:
	case SESSION_CONNECT:
	case SESSION_HANDSHAKE:
		return MUX_STATE_CONNECT;
	default:
		return MUX_STATE_CLOSED;
	}
}

const unsigned char *mux_session_id(const struct mux_session *ss)
{
	return ss->handshake.session_id;
}

const char *mux_peer_identity(const struct mux_session *ss)
{
	return ss->handshake.peer_identity;
}

const struct mux_session_config *mux_conf(const struct mux_session *ss)
{
	return &ss->conf;
}

void mux_session_stats(
	const struct mux_session *ss, struct mux_session_stats *restrict out)
{
	/* Read the relaxed-atomic mirrors: callable from the server thread. */
	out->rx_window = PUB_LOAD(ss->_pub_stream_window) * MUX_WINDOW_UNIT;
	out->tx_window =
		PUB_LOAD(ss->_pub_peer_stream_window) * MUX_WINDOW_UNIT;
	out->rtt = PUB_LOAD(ss->_pub_rtt);
	out->bdp_rx = PUB_LOAD(ss->_pub_bdp_rx);
	out->bdp_tx = PUB_LOAD(ss->_pub_bdp_tx);
}

/* --- Session mutators --- */

void mux_set_config(
	struct mux_session *ss, const struct mux_session_config *restrict conf)
{
	mux_session_set_config(ss, conf);
}

#if WITH_TLS
void mux_set_tlsctx(struct mux_session *ss, struct tls_context *tlsctx)
{
	mux_wire_set_tlsctx(ss, tlsctx);
}
#endif

void mux_drain(struct mux_session *ss)
{
	mux_session_drain(ss);
}

/* --- Stream I/O watcher --- */

bool mux_stream_io_start(struct ev_loop *loop, mux_stream_io *restrict w)
{
	return mux_stream_do_io_start(loop, w);
}

void mux_stream_io_modify(
	struct ev_loop *loop, mux_stream_io *restrict w, const int events)
{
	const int removed = w->events & ~events;
	const int added = events & ~w->events;
	w->events = events;
	/* A pending fed event for a bit the caller just removed must not fire
	 * (mirrors libev's ev_io_modify clearing pending): drop the pending event
	 * and re-feed only the bits still wanted. */
	if (removed != 0) {
		const int pending = ev_clear_pending(loop, w);
		const int keep = pending & events;
		if (keep != 0) {
			ev_feed_event(loop, w, keep);
		}
	}
	if (added == 0) {
		return;
	}
	/* Deliver any conditions that are already satisfied for the new events. */
	struct mux_stream *const s = w->stream;
	if (s == NULL) {
		return;
	}
	int ready = 0;
	if ((added & EV_READ) && stream_direct_read_ready(s)) {
		ready |= EV_READ;
	}
	if ((added & EV_WRITE) && stream_direct_write_ready(s)) {
		ready |= EV_WRITE;
	}
	if (ready != 0) {
		ev_feed_event(loop, w, ready);
	}
}

void mux_stream_io_stop(struct ev_loop *loop, mux_stream_io *restrict w)
{
	ev_clear_pending(loop, w);
	struct mux_stream *const s = w->stream;
	/* Only clear the direct union arm for an actually-direct stream: a
	 * socket-mode stream's s->socket overlaps s->direct, so an unconditional
	 * write would clobber socket.w_io (reachable when mux_stream_do_io_start no-oped
	 * on an unattachable stream, leaving is_direct false but w->stream bound). */
	if (s != NULL && s->is_direct) {
		s->direct.w_io = NULL;
	}
	w->stream = NULL;
	w->active = 0;
}

/* --- Stream operations --- */

struct mux_stream *mux_stream_open(struct mux_session *ss)
{
	return mux_session_open_stream(ss);
}

void mux_stream_attach_fd(struct mux_stream *s, const int fd)
{
	mux_stream_do_attach_fd(s, fd);
}

uint_least16_t mux_stream_id(const struct mux_stream *s)
{
	return s->id;
}

int mux_stream_send(
	struct mux_stream *restrict s, const void *restrict buf,
	size_t *restrict len)
{
	if (!stream_can_send_data(s)) {
		errno = EINVAL;
		return -1;
	}

	const uint_fast32_t credit = stream_read_credit_avail(s);
	if (credit == 0) {
		*len = 0; /* send queue full or credit exhausted; caller waits for EV_WRITE */
		return 0;
	}
	const size_t to_send = MIN(*len, (size_t)credit);
	size_t remaining = to_send;
	const unsigned char *p = buf;

	while (remaining > 0) {
		struct mux_frame *const frame = mux_frame_get(
			&s->session->pool, s->session->max_payload);
		if (frame == NULL) {
			if (to_send == remaining) {
				/* OOM before any frame was queued. */
				LOGOOM();
				errno = EAGAIN;
				return -1;
			}
			break; /* partial success: frames already queued */
		}
		const size_t chunk = MIN(remaining, frame->cap);
		frame->len = MUX_FRAME_HEADER_SIZE + chunk;
		memcpy(frame->data + MUX_FRAME_HEADER_SIZE, p, chunk);

		/* Must go through the same bookkeeping every
		 * dequeue/free path pays back, not a hand-rolled push that
		 * skips send_buffered_frames. */
		mux_stream_queue_send(s, frame);

		p += chunk;
		remaining -= chunk;
	}

	const size_t queued = to_send - remaining;
	if (queued > 0) {
		mux_sched_wake(s->session, s);
	}
	*len = queued;
	return 0;
}

int mux_stream_recv(
	struct mux_stream *restrict s, void *restrict buf, size_t *restrict len)
{
	if (s->rst_received || s->aborted) {
		errno = ECONNRESET;
		return -1;
	}

	if (bytebuf_readable(s->recvbuf) == 0) {
		if (s->state != STREAM_CLOSE_WAIT &&
		    s->state != STREAM_CLOSING) {
			errno = EAGAIN;
			return -1;
		}
		/* CLOSE_WAIT (peer FIN) or CLOSING (both FINs): return EOF below.
		 * On CLOSING the recv buffer is drained, so close now (idempotent). */
		if (s->state == STREAM_CLOSING) {
			mux_stream_do_close(s);
		}
		*len = 0;
		return 0; /* EOF */
	}

	/* struct bytebuf is a linear sliding window, so its readable bytes form a
	 * single contiguous region; one copy of MIN(*len, readable) drains as much
	 * as the caller's buffer holds -- no accumulation loop is needed. */
	const size_t copied = MIN(*len, bytebuf_readable(s->recvbuf));
	memcpy(buf, bytebuf_read_ptr(s->recvbuf), copied);
	bytebuf_consume(s->recvbuf, copied);
	ASSERT(s->buffered_bytes >= copied);
	ASSERT(s->session->recv_buffered_bytes >= copied);
	s->buffered_bytes -= (uint_least32_t)copied;
	s->session->recv_buffered_bytes -= copied;
	COUNTER_SUB(s->session->cnt.buffers.recv_buffered_bytes, copied);

	mux_stream_check_ack(s);

	*len = copied;
	return 0;
}

void mux_stream_shutdown(struct mux_stream *s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	mux_stream_do_shutdown(s);
}

void mux_stream_close(struct mux_stream *s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	/* Detach the user watcher first so the mux_stream_do_shutdown()/mux_stream_do_close()
	 * below cannot feed it a re-entrant EV_READ/EV_WRITE callback while the
	 * caller is in the middle of relinquishing it (the mux library only ever
	 * feeds this watcher EV_READ/EV_WRITE, never EV_ERROR). */
	if (s->is_direct) {
		/* close(fd) semantics: the caller is relinquishing the stream and
		 * will not call mux_stream_recv() again, so the close paths must not
		 * keep deferring the final CLOSED transition to it. */
		s->user_closed = true;
		if (s->direct.w_io != NULL) {
			mux_stream_io_stop(
				s->direct.w_io->loop, s->direct.w_io);
		}
	}

	if (bytebuf_readable(s->recvbuf) == 0) {
		/* No unread data: initiate graceful FIN. */
		mux_stream_do_shutdown(s);
		return;
	}
	/* Unread data present: send RST (close(fd) semantics). */
	mux_stream_do_close(s);
}
