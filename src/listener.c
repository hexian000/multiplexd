/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file listener.c
 * @brief Listener implementation for accepting connections.
 */

#include "listener.h"

#include "conf.h"
#include "util.h"

#include "os/socket.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void accept_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct listener *const restrict l = w->data;
	const struct conf_socket_opts *const restrict socket_opts =
		l->socket_opts;
	uint_least64_t *const restrict num_accepted = l->num_accepted;

	for (;;) {
		union sockaddr_max addr;
		socklen_t addrlen = sizeof(addr);
		const int fd = accept(w->fd, &addr.sa, &addrlen);
		if (fd < 0) {
			const int err = errno;
			if (err == EINTR || err == ECONNABORTED) {
				continue; /* retry immediately */
			}
			if (err == EAGAIN || err == EWOULDBLOCK) {
				break; /* no more pending connections */
			}
			if (err == ENOBUFS || err == ENOMEM) {
				LOGW_F("accept: (%d) %s", err, strerror(err));
			} else {
				LOGE_F("accept: (%d) %s", err, strerror(err));
			}
			/* Avoid infinite loop on accept error */
			ev_io_stop(loop, &l->w_accept);
			ev_timer_again(loop, &l->w_timer);
			return;
		}
		if (num_accepted != NULL) {
			(*num_accepted)++;
		}

		if (LOGLEVEL(VERYVERBOSE)) {
			char addr_str[64];
			(void)sa_format(addr_str, sizeof(addr_str), &addr.sa);
			LOGVV_F("listener [fd:%d]: accepted [fd:%d] from %s",
				w->fd, fd, addr_str);
		}

		if (socket_set_cloexec(fd) != 0 ||
		    socket_set_nonblock(fd) != 0) {
			SOCKET_CLOSE_FD(fd);
			continue;
		}
		socket_set_buffer(
			fd, socket_opts->tcp_sndbuf, socket_opts->tcp_rcvbuf);
		socket_set_tcp(
			fd, socket_opts->tcp_nodelay,
			socket_opts->tcp_keepalive);
#if WITH_TCP_NOTSENT_LOWAT
		if (socket_opts->tcp_notsent_lowat > 0) {
			socket_notsent_lowat(
				fd, socket_opts->tcp_notsent_lowat);
		}
#endif

		l->serve(l, loop, fd, &addr.sa);
	}
}

static void
timer_cb(struct ev_loop *restrict loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct listener *const restrict l = watcher->data;
	ev_io_start(loop, &l->w_accept);
}

void listener_init(
	struct listener *l, const struct conf_socket_opts *socket_opts,
	listener_serve_fn serve, struct server *server,
	uint_least64_t *restrict num_accepted)
{
	l->serve = serve;
	l->srv = server;
	l->socket_opts = socket_opts;

	ev_io_init(&l->w_accept, accept_cb, -1, EV_NONE);
	l->w_accept.data = l;
	ev_timer_init(&l->w_timer, timer_cb, 0.0, 0.5);
	l->w_timer.data = l;
	l->num_accepted = num_accepted;
}

bool listener_start(
	struct listener *l, struct ev_loop *loop, const struct sockaddr *sa)
{
	const int fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: (%d) %s", err, strerror(err));
		return false;
	}

	if (socket_set_cloexec(fd) != 0 || socket_set_nonblock(fd) != 0) {
		SOCKET_CLOSE_FD(fd);
		return false;
	}

	const struct conf_socket_opts *const restrict socket_opts =
		l->socket_opts;
	socket_set_buffer(fd, socket_opts->tcp_sndbuf, socket_opts->tcp_rcvbuf);
	socket_set_tcp(
		fd, socket_opts->tcp_nodelay, socket_opts->tcp_keepalive);
	socket_set_reuseport(fd, socket_opts->tcp_reuseport);

	if (bind(fd, sa, sa_len(sa)) != 0) {
		const int err = errno;
		LOGE_F("bind: (%d) %s", err, strerror(err));
		SOCKET_CLOSE_FD(fd);
		return false;
	}

	if (listen(fd, socket_opts->backlog) != 0) {
		const int err = errno;
		LOGE_F("listen: (%d) %s", err, strerror(err));
		SOCKET_CLOSE_FD(fd);
		return false;
	}

#if WITH_TCP_FASTOPEN
	socket_set_fastopen(fd, socket_opts->backlog);
#endif

	ev_io_set(&l->w_accept, fd, EV_READ);
	ev_io_start(loop, &l->w_accept);
	return true;
}

void listener_stop(struct listener *l, struct ev_loop *loop)
{
	ev_timer_stop(loop, &l->w_timer);
	ev_io_stop(loop, &l->w_accept);
	if (l->w_accept.fd != -1) {
		SOCKET_CLOSE_FD(l->w_accept.fd);
		l->w_accept.fd = -1;
	}
}
