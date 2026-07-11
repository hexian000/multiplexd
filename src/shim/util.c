/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.c
 * @brief CSPRNG bytes and address-resolution helpers.
 */

#include "shim/util.h"

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

/* RFC 1035: Section 2.3.4 */
#define FQDN_MAX_LENGTH ((size_t)(255))
#define ADDR_MAX_LENGTH (FQDN_MAX_LENGTH + sizeof(":65535"))

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
	char buf[ADDR_MAX_LENGTH];
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
	char buf[ADDR_MAX_LENGTH];
	char *hoststr, *portstr;
	if (!split_addr(buf, sizeof(buf), addrstr, &hoststr, &portstr)) {
		return false;
	}
	return sa_resolve_bind(addr, hoststr, portstr, type);
}
