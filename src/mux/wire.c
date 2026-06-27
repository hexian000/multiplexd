/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file wire.c
 * @brief Internal mux transport I/O implementation.
 */

#include "mux/wire.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#if WITH_TLS
#include "tlsutil.h"
#endif

#include "io/io.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#if WITH_TLS
/* on_send notifier: the library staged outbound ciphertext.  Mark the
 * transport write side pending so the session schedules a flush; the
 * cleared-each-pass tx_pending makes an over-eager set self-correcting. */
static void wire_on_tls_send(void *ctx)
{
	struct mux_session *const restrict ss = ctx;
	ss->wire.tx_pending = true;
}

/* on_recv notifier: the library holds buffered plaintext readable without
 * further I/O. */
static void wire_on_tls_recv(void *ctx)
{
	struct mux_session *const restrict ss = ctx;
	ss->wire.tls_readable = true;
}

/* Drain buffered TLS ciphertext to the socket, retaining what cannot be
 * accepted yet; returns 0 when done, EAGAIN when the socket is full,
 * or another errno on a fatal error. */
static int wire_cipher_push(struct mux_session *restrict ss)
{
	for (;;) {
		/* Drain whatever ciphertext the library has staged into the rawbuf
		 * ring; tls_output returns 0 once the library buffer is empty (the
		 * on_send notifier reports when more becomes available). */
		for (;;) {
			if (ss->wire.rawbuf == NULL) {
				ss->wire.rawbuf = ringbuf_new(IO_BUFSIZE);
				if (ss->wire.rawbuf == NULL) {
					LOGOOM();
					return ENOMEM;
				}
			}
			if (ringbuf_write_space(ss->wire.rawbuf) == 0 &&
			    !ringbuf_reserve(
				    &ss->wire.rawbuf, IO_BUFSIZE, true)) {
				LOGOOM();
				return ENOMEM;
			}
			struct ringbuf *const rb = ss->wire.rawbuf;
			const size_t n = tls_output(
				ss->wire.tlsconn, ringbuf_write_ptr(rb),
				ringbuf_write_space(rb));
			if (n == 0) {
				break;
			}
			ringbuf_produce(rb, n);
		}
		struct ringbuf *const rb = ss->wire.rawbuf;
		const size_t avail = ringbuf_readable(rb);
		if (avail == 0) {
			return 0; /* fully drained */
		}
		size_t nbytes = avail;
		const int err = socket_send(
			ss->w_socket.fd, ringbuf_read_ptr(rb), &nbytes);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				return EAGAIN; /* socket full; residue retained */
			}
			LOGE_F("send [fd:%d]: (%d) %s", ss->w_socket.fd, err,
			       strerror(err));
			return err;
		}
		ringbuf_consume(rb, nbytes);
		if (nbytes < avail) {
			return EAGAIN; /* partial write; socket full */
		}
	}
}

/* Encrypt plaintext in buf and push ciphertext to the socket; *len is the
 * plaintext bytes accepted (0 while stalled); returns false on an
 * unrecoverable error. */
static bool wire_send_buffered(
	struct mux_session *restrict ss, const unsigned char *restrict buf,
	size_t *restrict len)
{
	ss->wire.tls_want = 0;
	/* Drain any retained ciphertext before encrypting more, so records reach
	 * the peer in order; if the socket is still full, take no new plaintext. */
	const int ferr = wire_cipher_push(ss);
	if (ferr == EAGAIN) {
		*len = 0;
		return true;
	}
	if (ferr != 0) {
		*len = 0;
		return false;
	}
	size_t n = *len;
	const enum tls_error err = tls_send(ss->wire.tlsconn, buf, &n);
	LOGV_F("[fd:%d] tls_send(buffered): %zu bytes, err=%d", ss->w_socket.fd,
	       n, err);
	switch (err) {
	case TLS_ERROR_NONE:
	case TLS_ERROR_WANT_WRITE:
		break;
	case TLS_ERROR_WANT_READ:
		ss->wire.tls_want = EV_READ; /* cross-direction (handshake) */
		break;
	default:
		*len = 0;
		return false;
	}
	*len = n;
	const int perr = wire_cipher_push(ss);
	return perr == 0 || perr == EAGAIN;
}

/* Buffered transport receive: read ciphertext from the socket into @p buf, feed
 * it to the TLS library, and decrypt in place back into @p buf.  Also pushes any
 * ciphertext the library produced (e.g. handshake records). */
static bool wire_recv_buffered(
	struct mux_session *restrict ss, unsigned char *restrict buf,
	size_t *restrict len)
{
	ss->wire.tls_want = 0;
	ss->wire.tls_readable = false;
	size_t clen = *len;
	const int serr = socket_recv(ss->w_socket.fd, buf, &clen);
	if (serr != 0) {
		if (serr != EAGAIN && serr != EWOULDBLOCK && serr != ENOBUFS &&
		    serr != ENOMEM) {
			LOGE_F("recv [fd:%d]: (%d) %s", ss->w_socket.fd, serr,
			       strerror(serr));
			ss->wire.rx_open = false;
			*len = 0;
			return false;
		}
		clen = 0; /* no new ciphertext; still drain decrypted data below */
	} else if (clen == 0) {
		/* TCP FIN before close_notify: treat as a graceful close. */
		LOGV_F("[fd:%d] connection closed by peer", ss->w_socket.fd);
		ss->wire.rx_open = false;
		ss->wire.tx_pending = true;
		ss->wire.rx_eof = true;
		*len = 0;
		return true;
	}
	if (clen > 0 && !tls_input(ss->wire.tlsconn, buf, clen)) {
		LOGOOM();
		ss->wire.rx_open = false;
		*len = 0;
		return false;
	}
	size_t n = *len;
	const enum tls_error err = tls_recv(ss->wire.tlsconn, buf, &n);
	LOGV_F("[fd:%d] tls_recv(buffered): %zu bytes, err=%d", ss->w_socket.fd,
	       n, err);
	switch (err) {
	case TLS_ERROR_NONE:
	case TLS_ERROR_WANT_READ:
		break;
	case TLS_ERROR_WANT_WRITE:
		ss->wire.tls_want = EV_WRITE; /* cross-direction (handshake) */
		break;
	case TLS_ERROR_ZERO_RETURN:
		LOGV_F("[fd:%d] TLS connection closed by peer",
		       ss->w_socket.fd);
		ss->wire.rx_open = false;
		ss->wire.tx_pending = true;
		ss->wire.rx_eof = true;
		*len = 0;
		(void)wire_cipher_push(ss);
		return true;
	default:
		ss->wire.rx_open = false;
		*len = 0;
		return false;
	}
	*len = n;
	/* The handshake/recv may have produced outbound records (e.g. Finished);
	 * push them and keep EV_WRITE armed if the socket could not take them. */
	const int perr = wire_cipher_push(ss);
	if (perr == EAGAIN) {
		ss->wire.tx_pending = true;
	} else if (perr != 0) {
		ss->wire.rx_open = false;
		*len = 0;
		return false;
	}
	return true;
}
#endif /* WITH_TLS */

bool wire_send(
	struct mux_session *restrict ss, const unsigned char *restrict buf,
	size_t *restrict len)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
		if (!ss->conf.tls_socket_offload) {
			return wire_send_buffered(ss, buf, len);
		}
		ss->wire.tls_want = 0;
		const enum tls_error err = tls_send(ss->wire.tlsconn, buf, len);
		LOGV_F("[fd:%d] tls_send: %zu bytes, err=%d", ss->w_socket.fd,
		       *len, err);
		switch (err) {
		case TLS_ERROR_NONE:
		case TLS_ERROR_WANT_WRITE:
			/* Same-direction: state machine handles via tx_pending. */
			break;
		case TLS_ERROR_WANT_READ:
			/* Cross-direction: override watcher events. */
			ss->wire.tls_want = EV_READ;
			break;
		default:
			return false;
		}
		return true;
	}
#endif /* WITH_TLS */

	{
		const size_t total = *len;
		size_t nbsent = 0;
		for (;;) {
			size_t nbytes = total - nbsent;
			const int err = socket_send(
				ss->w_socket.fd, buf + nbsent, &nbytes);
			if (err != 0) {
				if (err == EAGAIN || err == EWOULDBLOCK ||
				    err == ENOBUFS || err == ENOMEM) {
					break; /* wait for EV_WRITE */
				}
				LOGE_F("send [fd:%d]: (%d) %s", ss->w_socket.fd,
				       err, strerror(err));
				*len = nbsent;
				return false;
			}
			if (nbytes == 0) {
				break;
			}
			nbsent += nbytes;
			if (nbsent >= total) {
				break;
			}
		}
		*len = nbsent;
	}
	if (*len > 0) {
		LOGV_F("[fd:%d] socket_send: %zu bytes", ss->w_socket.fd, *len);
	}
	return true;
}

bool wire_recv(
	struct mux_session *restrict ss, unsigned char *restrict buf,
	size_t *len)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
		if (!ss->conf.tls_socket_offload) {
			return wire_recv_buffered(ss, buf, len);
		}
		ss->wire.tls_want = 0;
		ss->wire.tls_readable = false;
		const enum tls_error err = tls_recv(ss->wire.tlsconn, buf, len);
		LOGV_F("[fd:%d] tls_recv: %zu bytes, err=%d", ss->w_socket.fd,
		       *len, err);
		switch (err) {
		case TLS_ERROR_NONE:
		case TLS_ERROR_WANT_READ:
			/* Same-direction: state machine handles via rx_open. */
			break;
		case TLS_ERROR_WANT_WRITE:
			/* Cross-direction: override watcher events. */
			ss->wire.tls_want = EV_WRITE;
			break;
		case TLS_ERROR_ZERO_RETURN:
			LOGV_F("[fd:%d] TLS connection closed by peer",
			       ss->w_socket.fd);
			ss->wire.rx_open = false;
			ss->wire.tx_pending = true;
			ss->wire.rx_eof = true;
			return true;
		default:
			ss->wire.rx_open = false;
			return false;
		}
		return true;
	}
#endif /* WITH_TLS */

	{
		const int err = socket_recv(ss->w_socket.fd, buf, len);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				*len = 0;
				return true; /* wait for EV_READ */
			}
			LOGE_F("recv [fd:%d]: (%d) %s", ss->w_socket.fd, err,
			       strerror(err));
			ss->wire.rx_open = false;
			return false;
		}
		if (*len == 0) {
			/* TCP FIN: graceful close like close_notify.  tx_pending
			 * makes session_on_send see !rx_open and enter SESSION_CLOSING. */
			LOGV_F("[fd:%d] connection closed by peer",
			       ss->w_socket.fd);
			ss->wire.rx_open = false;
			ss->wire.tx_pending = true;
			ss->wire.rx_eof = true;
			return true;
		}
	}
	LOGV_F("[fd:%d] socket_recv: %zu bytes", ss->w_socket.fd, *len);
	return true;
}

bool wire_has_pending(const struct mux_session *restrict ss)
{
#if WITH_TLS
	/* Set by the on_recv notifier during the last tls_recv. */
	return ss->wire.tls_readable;
#else
	(void)ss;
	return false;
#endif
}

void wire_discard_buffers(struct mux_session *restrict ss)
{
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	ss->wire.sendbuf_staging = false;
	ringbuf_reset(ss->wire.recvbuf);
#if WITH_TLS
	/* Drop any outbound ciphertext staged for the (now torn-down) connection. */
	if (ss->wire.rawbuf != NULL) {
		ringbuf_reset(ss->wire.rawbuf);
	}
#endif
}

void wire_sendbuf_push(
	struct mux_session *restrict ss, struct mux_frame *restrict frame)
{
	ASSERT(frame->len > 0);
	/* Pack onto the open tail to fill the current TLS record (MUX_MAX_RECORD,
	 * bounded by tail's physical buffer); a frame fitting neither falls
	 * through to the zero-copy by-reference path below. */
	if (frame->len <= MUX_MAX_RECORD && ss->wire.sendbuf_staging) {
		struct mux_frame *const tail = ss->wire.sendbuf.tail;
		ASSERT(tail->pos == 0);
		size_t record_cap = MUX_FRAME_HEADER_SIZE + tail->cap;
		if (record_cap > MUX_MAX_RECORD) {
			record_cap = MUX_MAX_RECORD;
		}
		if (tail->len + frame->len <= record_cap) {
			memcpy(tail->data + tail->len, frame->data, frame->len);
			tail->len += frame->len;
			mux_frame_put(&ss->pool, frame);
			return;
		}
	}

	/* Otherwise append by reference (zero-copy) as the new open tail. */
	frame->pos = 0;
	mux_frame_list_push(&ss->wire.sendbuf, frame);
	ss->wire.sendbuf_staging = true;
}

enum wire_flush_result wire_flush(struct mux_session *restrict ss)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL && !ss->conf.tls_socket_offload) {
		switch (wire_cipher_push(ss)) {
		case 0:
			return WIRE_FLUSH_DONE;
		case EAGAIN:
			return WIRE_FLUSH_BLOCKED;
		default:
			return WIRE_FLUSH_ERROR;
		}
	}
#else
	(void)ss;
#endif /* WITH_TLS */
	return WIRE_FLUSH_DONE;
}

#if WITH_TLS
void wire_set_tlsctx(
	struct mux_session *restrict ss, struct tls_context *restrict tlsctx)
{
	if (ss->wire.tlsctx == tlsctx) {
		return;
	}
	ss->wire.tlsctx = tlsctx;
}

bool wire_tls_start(struct mux_session *restrict ss)
{
	if (ss->wire.tlsctx == NULL && ss->wire.tlsconn == NULL) {
		return true;
	}
	/* With socket offload the library drives the socket directly; without it
	 * the connection is memory-transport, so pass fd=-1. */
	const int tlsfd = ss->conf.tls_socket_offload ? ss->w_socket.fd : -1;
	const struct tls_callback cb = {
		.ctx = ss,
		.on_send = wire_on_tls_send,
		.on_recv = wire_on_tls_recv,
	};
	if (ss->wire.tlsconn == NULL) {
		/* Outbound: create the client connection now, then bind the notifier. */
		ss->wire.tlsconn = tls_client(ss->wire.tlsctx, tlsfd);
		if (ss->wire.tlsconn == NULL) {
			return false;
		}
	}
	/* Inbound: the accepted connection was created before this session
	 * existed (the notifier ctx).  Either way, bind the notifier now. */
	tls_set_callback(ss->wire.tlsconn, &cb);
	/* The TLS handshake is driven implicitly by the first wire_send/wire_recv
	 * of the mux hello exchange, reporting cross-direction stalls via tls_want;
	 * update_watcher already arms the right events in SESSION_HANDSHAKE. */
	return true;
}

#ifndef NDEBUG
void wire_tls_log_status(struct mux_session *restrict ss)
{
	if (ss->wire.tlsconn == NULL) {
		return;
	}
	/* The handshake already completed during the hello exchange, so this is
	 * an idempotent no-op; it exists only to trigger the backend's KTLS-status
	 * log and must return TLS_ERROR_NONE.  Debug builds only. */
	const enum tls_error err = tls_handshake(ss->wire.tlsconn);
	ASSERT(err == TLS_ERROR_NONE);
	(void)err;
}
#endif /* NDEBUG */

void wire_adopt_tlsconn(
	struct mux_session *restrict ss, struct tls_connection *restrict conn)
{
	if (ss->wire.tlsconn != NULL) {
		tls_conn_free(ss->wire.tlsconn);
	}
	ss->wire.tlsconn = conn;
	if (conn != NULL) {
		/* The connection was created for the transient session that carried
		 * the resume hello; rebind the I/O notifier to ss so it never fires
		 * on the old session (mirrors the inbound bind in wire_tls_start). */
		const struct tls_callback cb = {
			.ctx = ss,
			.on_send = wire_on_tls_send,
			.on_recv = wire_on_tls_recv,
		};
		tls_set_callback(conn, &cb);
	}
}

/* Free a detached TLS connection not owned by any session (e.g. a resume
 * transport handoff that could not be installed).  Keeps session.c off a
 * direct tlsutil dependency; tls_conn_free is NULL-safe. */
void wire_tlsconn_free(struct tls_connection *restrict conn)
{
	tls_conn_free(conn);
}
#endif /* WITH_TLS */

void wire_conn_free(struct mux_session *restrict ss)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
		tls_conn_free(ss->wire.tlsconn);
		ss->wire.tlsconn = NULL;
	}
#else
	(void)ss;
#endif
}

enum wire_shutdown_state wire_shutdown(struct mux_session *restrict ss)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
		ss->wire.tls_want = 0;
		const enum tls_error err = tls_shutdown(ss->wire.tlsconn);
		switch (err) {
		case TLS_ERROR_NONE:
			/* Our close_notify is flushed (one-way); fall through to TCP
			 * half-close; peer's close_notify is read later via
			 * wire_wait_eof; memory-transport: push alert first. */
			if (!ss->conf.tls_socket_offload) {
				switch (wire_flush(ss)) {
				case WIRE_FLUSH_DONE:
					break;
				case WIRE_FLUSH_BLOCKED:
					ss->wire.tls_want = EV_WRITE;
					return WIRE_SHUTDOWN_PENDING;
				case WIRE_FLUSH_ERROR:
					return WIRE_SHUTDOWN_ERROR;
				}
			}
			break;
		case TLS_ERROR_WANT_READ:
		case TLS_ERROR_WANT_WRITE:
			ss->wire.tls_want = (err == TLS_ERROR_WANT_READ) ?
						    EV_READ :
						    EV_WRITE;
			LOGV_F("[fd:%d] tls_shutdown: pending (want %s)",
			       ss->w_socket.fd,
			       err == TLS_ERROR_WANT_READ ? "read" : "write");
			return WIRE_SHUTDOWN_PENDING;
		default:
			return WIRE_SHUTDOWN_ERROR;
		}
	}
#endif /* WITH_TLS */
	LOGV_F("[fd:%d] shutdown: tcp", ss->w_socket.fd);
	SOCKET_SHUTDOWN_FD(ss->w_socket.fd, WR);
	return WIRE_SHUTDOWN_DONE;
}

bool wire_wait_eof(struct mux_session *restrict ss)
{
	unsigned char buf[256];
#if WITH_TLS
	if (ss->wire.tlsconn != NULL && !ss->conf.tls_socket_offload) {
		/* Memory transport: drain the socket ourselves and feed the library
		 * before checking for the peer's close_notify or stray data. */
		size_t clen = sizeof(buf);
		const int serr = socket_recv(ss->w_socket.fd, buf, &clen);
		if (serr != 0) {
			if (serr == EAGAIN || serr == EWOULDBLOCK ||
			    serr == ENOBUFS || serr == ENOMEM) {
				return true; /* nothing pending yet */
			}
			return false;
		}
		if (clen == 0) {
			return true; /* peer closed (TCP FIN) */
		}
		if (!tls_input(ss->wire.tlsconn, buf, clen)) {
			return false;
		}
		size_t nread = sizeof(buf);
		const enum tls_error err =
			tls_recv(ss->wire.tlsconn, buf, &nread);
		switch (err) {
		case TLS_ERROR_ZERO_RETURN:
		case TLS_ERROR_WANT_READ:
		case TLS_ERROR_WANT_WRITE:
			return true;
		case TLS_ERROR_NONE:
			LOGD_F("[fd:%d] unexpected data after shutdown",
			       ss->w_socket.fd);
			return false;
		default:
			LOGD_F("[fd:%d] TLS error after shutdown",
			       ss->w_socket.fd);
			return false;
		}
	}
	if (ss->wire.tlsconn != NULL) {
		size_t nread = sizeof(buf);
		const enum tls_error err =
			tls_recv(ss->wire.tlsconn, buf, &nread);
		switch (err) {
		case TLS_ERROR_ZERO_RETURN:
			/* Peer's close_notify: clean close; or tls_shutdown is one-way
			 * so WANT_READ/WANT_WRITE means it has not arrived yet;
			 * treat like a plaintext EAGAIN. */
		case TLS_ERROR_WANT_READ:
		case TLS_ERROR_WANT_WRITE:
			return true;
		case TLS_ERROR_NONE:
			/* nread > 0: unexpected application data after shutdown. */
			LOGD_F("[fd:%d] unexpected data after shutdown",
			       ss->w_socket.fd);
			return false;
		default:
			LOGD_F("[fd:%d] TLS error after shutdown",
			       ss->w_socket.fd);
			return false;
		}
	}
#endif /* WITH_TLS */
	size_t len = sizeof(buf);
	{
		const int err = socket_recv(ss->w_socket.fd, buf, &len);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				len = 0; /* no unexpected data yet */
			} else {
				return false;
			}
		}
		/* err == 0: len holds bytes received; 0 means EOF */
	}
	if (len > 0) {
		LOGD_F("[fd:%d] unexpected data after shutdown",
		       ss->w_socket.fd);
		return false;
	}
	return true;
}
