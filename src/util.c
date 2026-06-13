/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.c
 * @brief Implementation of utility routines and globals.
 */

#include "util.h"

#if WITH_TLS
#include "tlsutil.h"
#endif

#include "math/rand.h"
#include "net/addr.h"
#include "os/signal.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

void socket_notsent_lowat(const int fd, const int bytes)
{
#if WITH_TCP_NOTSENT_LOWAT
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &bytes,
		    sizeof(bytes)) != 0) {
		const int err = errno;
		LOGW_F("setsockopt [fd:%d]: TCP_NOTSENT_LOWAT (%d) %s", fd, err,
		       strerror(err));
	}
#else
	(void)fd;
	(void)bytes;
#endif
}

#if defined(WIN32)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

void init(int argc, char *const *argv)
{
	UNUSED(argc);
	UNUSED(argv);
	(void)setlocale(LC_ALL, "");
	(void)setvbuf(stdout, NULL, _IONBF, 0);
	slog_setoutput(SLOG_OUTPUT_FILE, stdout);
	{
		static char prefix[] = __FILE__;
		char *s = strrchr(prefix, PATH_SEPARATOR);
		if (s != NULL) {
			s[1] = '\0';
		}
		slog_setfileprefix(prefix);
	}
	slog_setlevel(LOG_LEVEL_VERBOSE);

	struct sigaction ignore = { .sa_handler = SIG_IGN };
	if (sigaction(SIGPIPE, &ignore, NULL) != 0) {
		const int err = errno;
		LOGF_F("sigaction: (%d) %s", err, strerror(err));
		exit(EXIT_FAILURE);
	}
	crashhandler_install();
}

void loadlibs(void)
{
	srand64((uint_fast64_t)time(NULL));

	LOGD_F("%s: %s", PROJECT_NAME, PROJECT_VER);
	LOGD_F("libev: %d.%d", ev_version_major(), ev_version_minor());
#if WITH_TLS
	LOGD_F("%s", tls_version());
#endif
}

void unloadlibs(void)
{
	LOGD("library cleanup complete");
}

/* RFC 1035: Section 2.3.4 */
#define FQDN_MAX_LENGTH ((size_t)(255))

bool resolve_addr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	const enum sa_resolve_type type)
{
	const size_t addrlen = strlen(addrstr);
	ASSERT(addrlen < FQDN_MAX_LENGTH + sizeof(":65535"));
	char buf[addrlen + 1];
	memcpy(buf, addrstr, addrlen);
	buf[addrlen] = '\0';
	char *hoststr, *portstr;
	if (!addr_splithostport(buf, &hoststr, &portstr)) {
		return false;
	}
	return sa_resolve(addr, hoststr, portstr, type, PF_UNSPEC);
}

bool resolve_bindaddr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	const enum sa_resolve_type type)
{
	const size_t addrlen = strlen(addrstr);
	ASSERT(addrlen < FQDN_MAX_LENGTH + sizeof(":65535"));
	char buf[addrlen + 1];
	memcpy(buf, addrstr, addrlen);
	buf[addrlen] = '\0';
	char *hoststr, *portstr;
	if (!addr_splithostport(buf, &hoststr, &portstr)) {
		return false;
	}
	return sa_resolve_bind(addr, hoststr, portstr, type);
}
