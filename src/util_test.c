/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "utils/testing.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdlib.h>

T_DECLARE_CASE(test_socket_notsent_lowat_no_crash)
{
	(void)_t_;
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);
	/* socket_notsent_lowat is a no-op when the platform lacks
	 * TCP_NOTSENT_LOWAT; either way it must not crash. */
	socket_notsent_lowat(fd, 4096);
	(void)close(fd);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_socket_notsent_lowat_no_crash);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
