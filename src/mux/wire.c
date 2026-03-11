/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file wire.c
 * @brief Internal mux transport I/O implementation.
 */

#include "mux/wire.h"

#include "mux/frame.h"
#include "mux/session.h"
#include "tlsutil.h"

#include "os/socket.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* return false to indicate connection closed or error */
bool wire_send(struct mux_session *restrict ss, unsigned char *buf, size_t *len)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
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
			TLS_PERROR("tls_send");
			return false;
		}
		return true;
	}
#endif

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

/* return false to indicate connection closed or error */
bool wire_recv(
	struct mux_session *restrict ss, unsigned char *restrict buf,
	size_t *len)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
		ss->wire.tls_want = 0;
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
			TLS_PERROR("tls_recv");
			return false;
		}
		return true;
	}
#endif

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
			/* TCP FIN: treat as graceful close, same as TLS close_notify.
			 * Set tx_pending so send_cb detects !rx_open and
			 * enters SESSION_CLOSING rather than session_suspend. */
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

void wire_discard_buffers(struct mux_session *restrict ss)
{
	mux_frame_list_clear(&ss->wire.sendbuf, &ss->pool);
	mux_frame_list_clear(&ss->wire.oobbuf, &ss->pool);
	ringbuf_reset(ss->wire.recvbuf);
}

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
	if (ss->wire.tlsconn == NULL) {
		ss->wire.tlsconn =
			tls_connect(ss->wire.tlsctx, ss->w_socket.fd);
		if (ss->wire.tlsconn == NULL) {
			return false;
		}
	}

	bool want_read = false, want_write = false;
	const int ret =
		tls_handshake(ss->wire.tlsconn, &want_read, &want_write);
	if (ret < 0) {
		return false;
	}

	ss->wire.tls_want = 0;
	if (want_read) {
		ss->wire.tls_want |= EV_READ;
	}
	if (want_write) {
		ss->wire.tls_want |= EV_WRITE;
	}
	ss->wire.tx_pending = ss->wire.tx_pending || want_write;
	return true;
}

void wire_migrate_tlsconn(
	struct mux_session *restrict ss, struct mux_session *restrict new_ss)
{
	struct tls_connection *const new_conn = new_ss->wire.tlsconn;
	new_ss->wire.tlsconn = NULL;
	new_ss->wire.tlsctx = NULL;
	if (ss->wire.tlsconn != NULL) {
		tls_conn_free(ss->wire.tlsconn);
	}
	ss->wire.tlsconn = new_conn;
}
#endif /* WITH_TLS */

enum wire_shutdown_state wire_shutdown(struct mux_session *restrict ss)
{
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
		ss->wire.tls_want = 0;
		bool want_read = false, want_write = false;
		const int ret =
			tls_shutdown(ss->wire.tlsconn, &want_read, &want_write);
		if (ret < 0) {
			TLS_PERROR("tls_shutdown");
			return WIRE_SHUTDOWN_ERROR;
		}
		if (ret > 0) {
			LOGV_F("[fd:%d] tls_shutdown: ret=%d", ss->w_socket.fd,
			       ret);
			int event = 0;
			if (want_read) {
				event |= EV_READ;
			}
			if (want_write) {
				event |= EV_WRITE;
			}
			ss->wire.tls_want = event;
			return WIRE_SHUTDOWN_PENDING;
		}
		/* ret == 0: TLS close_notify complete; fall through to TCP half-close. */
	}
#endif
	LOGV_F("[fd:%d] shutdown: tcp", ss->w_socket.fd);
	SHUTDOWN_FD(ss->w_socket.fd, WR);
	return WIRE_SHUTDOWN_DONE;
}

bool wire_wait_eof(struct mux_session *restrict ss)
{
	unsigned char buf[256];
#if WITH_TLS
	if (ss->wire.tlsconn != NULL) {
		size_t nread = sizeof(buf);
		const enum tls_error err =
			tls_recv(ss->wire.tlsconn, buf, &nread);
		if (err != TLS_ERROR_ZERO_RETURN) {
			LOGD_F("[fd:%d] unexpected TLS state after shutdown",
			       ss->w_socket.fd);
			return false;
		}
		return true;
	}
#endif
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
