/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.c
 * @brief CSPRNG bytes, address-resolution, and ALPN list-tokenizing helpers.
 */

#include "shim/util.h"

#if WITH_TLS
#include "codec/csv.h"
#endif
#include "net/addr.h"
#include "os/socket.h"
#include "utils/slog.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

bool csprng_bytes(unsigned char *buf, const size_t len)
{
	const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("open /dev/urandom: (%d) %s", err, strerror(err));
		return false;
	}
	/* fd is a read-only /dev/urandom handle: there are no buffered writes to
	 * flush, so a close() error is not actionable -- the three (void)close(fd)
	 * below intentionally discard it. */
	size_t off = 0;
	while (off < len) {
		const ssize_t n = read(fd, buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			const int err = errno;
			LOGE_F("read /dev/urandom: (%d) %s", err,
			       strerror(err));
			(void)close(fd);
			return false;
		}
		if (n == 0) {
			LOGE("read /dev/urandom: unexpected EOF");
			(void)close(fd);
			return false;
		}
		off += (size_t)n;
	}
	(void)close(fd);
	return true;
}

/* Split addrstr into hoststr/portstr via buf (capacity buflen); false if
 * addrstr doesn't fit or has no valid host:port syntax. */
static bool split_addr(
	char *restrict buf, const size_t buflen, const char *restrict addrstr,
	char **restrict hoststr, char **restrict portstr)
{
	const size_t addrlen = strlen(addrstr);
	if (addrlen >= buflen) {
		return false;
	}
	memcpy(buf, addrstr, addrlen);
	buf[addrlen] = '\0';
	return splithostport(buf, hoststr, portstr);
}

bool resolve_addr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	const enum sa_resolve_type type)
{
	char buf[ADDR_MAX_STRLEN + 1];
	char *hoststr, *portstr;
	if (!split_addr(buf, sizeof(buf), addrstr, &hoststr, &portstr)) {
		return false;
	}
	return sa_resolve(addr, hoststr, portstr, type, PF_UNSPEC);
}

bool resolve_bindaddr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	const enum sa_resolve_type type)
{
	char buf[ADDR_MAX_STRLEN + 1];
	char *hoststr, *portstr;
	if (!split_addr(buf, sizeof(buf), addrstr, &hoststr, &portstr)) {
		return false;
	}
	return sa_resolve_bind(addr, hoststr, portstr, type);
}

bool sock_would_block(const int err)
{
	return err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
	       err == ENOMEM;
}

#if WITH_TLS
bool alpn_tokenize(
	char *restrict work, const char *restrict list, const alpn_field_fn fn,
	void *ctx)
{
	for (char *p = work; p != NULL;) {
		char *field = NULL;
		/* ALPN is a flat comma-separated list, so the delimiter kind
		 * (field vs record separator) is irrelevant; discard it. */
		char sep;
		/* csv_scanfield unescapes a quoted field in place and, for an
		 * empty quoted field ("") it later rejects, zeroes the field's
		 * first byte before returning its parse-error NULL.  Record
		 * whether any input remained before the call so the guard below
		 * cannot misread that clobbered byte as a clean end. */
		const bool had_input = (*p != '\0');
		char *const next = csv_scanfield(p, &field, &sep);
		if (next == p) {
			/* unterminated quoted field with no more data */
			LOGW_F("malformed ALPN list '%s'", list);
			return false;
		}
		if (field == NULL && next == NULL && had_input) {
			/* csv_scanfield returns NULL for both a clean end and a
			 * hard parse error (stray bytes after a closing quote,
			 * or an invalid unquoted field); input remaining before
			 * the call yet no field produced is the latter -- fail
			 * closed instead of silently truncating the list. */
			LOGW_F("malformed ALPN list '%s'", list);
			return false;
		}
		if (field != NULL) {
			const size_t len = strlen(field);
			if (len > 0 && !fn(ctx, field, len)) {
				return false;
			}
		}
		p = next;
	}
	return true;
}
#endif /* WITH_TLS */
