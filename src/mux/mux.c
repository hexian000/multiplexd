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
#include "mux/wire.h"

#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

size_t mux_frame_object_size(void)
{
	return sizeof(struct mux_frame);
}

struct mux_session *
mux_new(struct ev_loop *restrict loop, const struct mux_session_opts *opts)
{
	return session_new(loop, opts);
}

void mux_close(struct mux_session *ss)
{
	session_close(ss);
}

void mux_set_callbacks(struct mux_session *ss, const struct mux_callbacks *cb)
{
	ss->callbacks = *cb;
}

void mux_shutdown(struct mux_session *ss)
{
	session_initiate_shutdown(ss);
}

void mux_start(struct mux_session *ss)
{
	session_start(ss);
}

void mux_attach_fd(struct mux_session *ss, const int fd)
{
	session_attach_fd(ss, fd);
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
	switch (ss->state) {
	case SESSION_ESTABLISHED:
	case SESSION_CLOSING:
	case SESSION_CLOSE_WAIT:
		return MUX_STATE_ESTABLISHED;
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

const struct mux_config *mux_conf(const struct mux_session *ss)
{
	return &ss->conf;
}

void mux_session_stats(
	const struct mux_session *ss, struct mux_session_stats *restrict out)
{
	out->rx_window = (size_t)ss->stream_window * MUX_WINDOW_UNIT;
	out->tx_window = (size_t)ss->peer_stream_window * MUX_WINDOW_UNIT;
	out->rtt = ss->estimator.rtt;
	out->bdp_rx = ss->estimator.dir[ESTIMATOR_RX].bdp;
	out->bdp_tx = ss->estimator.dir[ESTIMATOR_TX].bdp;
}

/* --- Session mutators --- */

void mux_set_config(
	struct mux_session *ss, const struct mux_config *restrict conf)
{
	session_set_config(ss, conf);
#if WITH_TLS
	if (conf->tlsctx != NULL) {
		wire_set_tlsctx(ss, conf->tlsctx);
	}
#endif
}

void mux_drain(struct mux_session *ss)
{
	session_drain(ss);
}

/* --- Stream I/O watcher --- */

void mux_stream_io_start(struct ev_loop *loop, mux_stream_io *restrict w)
{
	stream_io_start(loop, w);
}

void mux_stream_io_modify(
	struct ev_loop *loop, mux_stream_io *restrict w, const int events)
{
	const int added = events & ~w->events;
	w->events = events;
	if (added == 0) {
		return;
	}
	/* Deliver any conditions that are already satisfied for the new events. */
	struct mux_stream *const s = w->stream;
	if (s == NULL) {
		return;
	}
	int ready = 0;
	if ((added & EV_READ) &&
	    (ringbuf_readable(s->recvbuf) > 0 ||
	     s->state == STREAM_CLOSE_WAIT || s->state == STREAM_CLOSING ||
	     s->rst_received)) {
		ready |= EV_READ;
	}
	if ((added & EV_WRITE) &&
	    (s->state == STREAM_INIT || s->state == STREAM_ESTABLISHED ||
	     s->state == STREAM_CLOSE_WAIT)) {
		if (stream_read_credit_avail(s) > 0) {
			ready |= EV_WRITE;
		}
	}
	if (ready != 0) {
		ev_feed_event(loop, w, ready);
	}
}

void mux_stream_io_stop(struct ev_loop *loop, mux_stream_io *restrict w)
{
	ev_clear_pending(loop, w);
	struct mux_stream *const s = w->stream;
	if (s != NULL) {
		s->direct.w_io = NULL;
	}
	w->stream = NULL;
	w->active = 0;
}

/* --- Stream operations --- */

struct mux_stream *mux_open_stream(struct mux_session *ss)
{
	return session_open_stream(ss);
}

void mux_stream_attach(struct mux_stream *s, const int fd)
{
	stream_attach_fd(s, fd);
}

uint_least16_t mux_stream_id(const struct mux_stream *s)
{
	return s->id;
}

int mux_stream_send(
	struct mux_stream *restrict s, const void *restrict buf,
	size_t *restrict len)
{
	if (s->state != STREAM_INIT && s->state != STREAM_ESTABLISHED &&
	    s->state != STREAM_CLOSE_WAIT) {
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
		struct mux_frame *frame = mux_frame_get(&s->session->pool);
		if (frame == NULL) {
			if (to_send == remaining) {
				/* OOM before any frame was queued. */
				LOGOOM();
				errno = EAGAIN;
				return -1;
			}
			break; /* partial success: frames already queued */
		}
		const size_t chunk = MIN(remaining, MUX_MAX_PAYLOAD_SIZE);
		frame->len = MUX_FRAME_HEADER_SIZE + chunk;
		frame->pos = 0;
		memcpy(frame->data + MUX_FRAME_HEADER_SIZE, p, chunk);

		s->queued_send_bytes += (uint_least32_t)chunk;
		mux_frame_list_push(&s->send_queue, frame);

		p += chunk;
		remaining -= chunk;
	}

	const size_t queued = to_send - remaining;
	if (queued > 0) {
		sched_wake(s->session, s);
	}
	*len = queued;
	return 0;
}

int mux_stream_recv(
	struct mux_stream *restrict s, void *restrict buf, size_t *restrict len)
{
	if (s->rst_received) {
		errno = ECONNRESET;
		return -1;
	}

	if (ringbuf_readable(s->recvbuf) == 0) {
		if (s->state != STREAM_CLOSE_WAIT &&
		    s->state != STREAM_CLOSING) {
			errno = EAGAIN;
			return -1;
		}
		/* Peer FIN received (CLOSE_WAIT) or both FINs exchanged (CLOSING):
		 * return EOF.  For CLOSING, close the stream now that the receive
		 * buffer is fully drained; stream_close is idempotent on
		 * STREAM_CLOSED.  EOF (*len=0) is returned below. */
		if (s->state == STREAM_CLOSING) {
			stream_close(s);
		}
		*len = 0;
		return 0; /* EOF */
	}

	const size_t cap = *len;
	size_t copied = 0;
	unsigned char *dst = buf;

	while (ringbuf_readable(s->recvbuf) > 0 && copied < cap) {
		const size_t take =
			MIN(cap - copied, ringbuf_readable(s->recvbuf));
		memcpy(dst + copied, ringbuf_read_ptr(s->recvbuf), take);
		ringbuf_consume(s->recvbuf, take);
		copied += take;
	}
	s->buffered_bytes -= (uint_least32_t)copied;
	s->session->recv_buffered_bytes -= copied;
	COUNTER_SUB(s->session->cnt.recv_buffered_bytes, copied);

	stream_check_ack(s);

	*len = copied;
	return 0;
}

void mux_stream_shutdown(struct mux_stream *s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	stream_shutdown(s);
}

void mux_stream_close(struct mux_stream *s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	/* Detach user watcher first so it does not receive EV_ERROR from
	 * stream_close() — the caller is the one initiating the close. */
	if (s->is_direct && s->direct.w_io != NULL) {
		mux_stream_io_stop(s->direct.w_io->loop, s->direct.w_io);
	}

	if (ringbuf_readable(s->recvbuf) == 0) {
		/* No unread data: initiate graceful FIN. */
		stream_shutdown(s);
		return;
	}
	/* Unread data present: send RST (close(fd) semantics). */
	stream_close(s);
}
