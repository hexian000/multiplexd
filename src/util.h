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

struct util_socket_opts {
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
