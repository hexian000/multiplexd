/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.h
 * @brief CSPRNG bytes, address resolution, and event/thread assertion macros.
 */

#ifndef SHIM_UTIL_H
#define SHIM_UTIL_H

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

/* The local is status_, not status: the macro's own declaration comes into
 * scope before its initializer, so a plainer name would make THRD_ASSERT(f(x))
 * read the macro's indeterminate local at any call site whose argument is
 * spelled the same. A trailing underscore is unreserved in every scope, unlike
 * a thrd_ prefix, which C11 7.31.15 keeps for <threads.h> itself. */
#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status_ = (expr);                                    \
		(void)status_;                                                 \
		assert(status_ == thrd_success);                               \
	} while (0)
#else /* WITH_THREADS */
/* Still evaluate expr: the WITH_THREADS form above performs the call even under
 * NDEBUG, so discarding it here would silently drop a lock or thread operation
 * from a no-threads build. */
#define THRD_ASSERT(expr) ((void)(expr))
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

/* RFC 1035 Section 2.3.4: a fully-qualified domain name is at most 255 octets. */
#define FQDN_MAX_LENGTH ((size_t)255)

/* Longest accepted "host:port" address string, in octets excluding the NUL: a
 * 255-octet FQDN plus ":65535". This is the single source of truth for the
 * address-length limit -- conf.c's identity.listen check and every address
 * "maxLength" in conf_schema.json must match it. */
#define ADDR_MAX_STRLEN (FQDN_MAX_LENGTH + sizeof(":65535") - 1)

bool resolve_addr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

bool resolve_bindaddr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

#endif /* SHIM_UTIL_H */
