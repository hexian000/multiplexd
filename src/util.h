/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.h
 * @brief Common utilities, globals, and helpers.
 */

#ifndef UTIL_H
#define UTIL_H

#include "net/addr.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#if WITH_THREADS
#include <threads.h>

#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status = (expr);                                     \
		(void)status;                                                  \
		assert(status == thrd_success);                                \
	} while (0)
#else
#define THRD_ASSERT(expr) ((void)(0))
#endif

#define UNUSED(x) ((void)(x))

#define TSTAMP_NIL (-1.0)

static inline void modify_io_events(
	struct ev_loop *restrict loop, ev_io *restrict watcher,
	const int events)
{
	const int fd = watcher->fd;
	ASSERT(fd != -1);
	const int ioevents = events & (EV_READ | EV_WRITE);
	if (ioevents == EV_NONE) {
		if (ev_is_active(watcher)) {
			LOGV_F("io: [fd:%d] stop", fd);
			ev_io_stop(loop, watcher);
		}
		return;
	}
	if (ioevents != (watcher->events & (EV_READ | EV_WRITE))) {
		ev_io_stop(loop, watcher);
#ifdef ev_io_modify
		ev_io_modify(watcher, ioevents);
#else
		ev_io_set(watcher, fd, ioevents);
#endif
	}
	if (!ev_is_active(watcher)) {
		LOGV_F("io: [fd:%d] events=0x%x", fd, ioevents);
		ev_io_start(loop, watcher);
	}
}

struct socket_opts {
	bool tcp_keepalive : 1;
	bool tcp_nodelay : 1;
	bool tcp_reuseport : 1;
	int tcp_sndbuf;
	int tcp_rcvbuf;
#if WITH_TCP_NOTSENT_LOWAT
	int tcp_notsent_lowat;
#endif
	int backlog;
};

/**
 * @brief Sets TCP_NOTSENT_LOWAT on the socket; no-op on unsupported platforms.
 * @param fd The socket file descriptor.
 * @param bytes The threshold in bytes.
 */
void socket_notsent_lowat(int fd, int bytes);

/**
 * @brief Sets TCP_USER_TIMEOUT on the socket.
 * @param fd The socket file descriptor.
 * @param ms The timeout in milliseconds.
 * @return 0 on success, -1 if unsupported or setsockopt fails.
 */
int socket_user_timeout(int fd, int ms);

#define CHECK_REVENTS(revents, accept)                                         \
	do {                                                                   \
		if (((revents) & EV_ERROR) != 0) {                             \
			const int err = errno;                                 \
			LOGE_F("io error: (%d) %s", err, strerror(err));       \
		}                                                              \
		ASSERT(((revents) & ((accept) | EV_ERROR)) == (revents));      \
		if (((revents) & (accept)) == 0) {                             \
			return;                                                \
		}                                                              \
	} while (0)

void init(int argc, char *const *argv);
void loadlibs(void);
void unloadlibs(void);

bool resolve_addr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

bool resolve_bindaddr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

#endif /* UTIL_H */
