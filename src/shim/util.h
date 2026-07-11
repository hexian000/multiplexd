/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.h
 * @brief Common utilities, globals, and helpers.
 */

#ifndef SHIM_UTIL_H
#define SHIM_UTIL_H

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
#else /* WITH_THREADS */
#define THRD_ASSERT(expr) ((void)(0))
#endif /* WITH_THREADS */

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

/**
 * @brief Fill buf with len cryptographically secure random bytes, read from
 * the OS entropy source (/dev/urandom). Unlike math/rand.h's rand64(), this
 * is safe for security-sensitive uses such as session IDs.
 * @return false if the entropy source could not be opened or read.
 */
bool csprng_bytes(unsigned char *buf, size_t len);

bool resolve_addr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

bool resolve_bindaddr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

#endif /* SHIM_UTIL_H */
