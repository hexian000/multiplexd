/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.c
 * @brief Implementation of utility routines and globals.
 */

#include "util.h"

#include "math/rand.h"
#include "os/clock.h"
#include "os/signal.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#if WITH_TLS
#include "tlsutil.h"
#endif
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
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

int socket_user_timeout(const int fd, const int ms)
{
#if WITH_TCP_USER_TIMEOUT
	if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &ms, sizeof(ms)) !=
	    0) {
		const int err = errno;
		LOGW_F("setsockopt [fd:%d]: TCP_USER_TIMEOUT (%d) %s", fd, err,
		       strerror(err));
		return -1;
	}
	return 0;
#else
	(void)fd;
	(void)ms;
	return -1;
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
