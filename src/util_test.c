/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* util_test.c - black-box tests for util.c (socket options, address resolution,
 * identity helpers) via its public API.
 * Dependencies: links the real util.c (+ TLS backend). */

#include "util.h"

#include "os/socket.h"
#include "utils/testing.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

T_DECLARE_CASE(test_socket_notsent_lowat_sets_option)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);
#if WITH_TCP_NOTSENT_LOWAT
	socket_notsent_lowat(fd, 4096);
	int val = 0;
	socklen_t len = sizeof(val);
	T_CHECK(getsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &val, &len) ==
		0);
	T_EXPECT_EQ(val, 4096);
#else
	/* Platform lacks TCP_NOTSENT_LOWAT; only verify no crash. */
	(void)_t_;
	socket_notsent_lowat(fd, 4096);
#endif /* WITH_TCP_NOTSENT_LOWAT */
	(void)close(fd);
}

T_DECLARE_CASE(test_resolve_addr_ipv4_parses_correctly)
{
	union sockaddr_max addr;
	const bool ok = resolve_addr(&addr, "127.0.0.1:1234", SA_RESOLVE_TCP);
	T_CHECK(ok);
	if (!ok) {
		return;
	}
	T_EXPECT_EQ(addr.sa.sa_family, (sa_family_t)AF_INET);
	T_EXPECT_EQ(ntohs(addr.in.sin_port), (uint16_t)1234);
	T_EXPECT_EQ(addr.in.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
}

T_DECLARE_CASE(test_resolve_addr_ipv6_parses_correctly)
{
	union sockaddr_max addr;
	/* AI_ADDRCONFIG skips IPv6 resolution on systems without an IPv6
	 * interface; treat a false return as not-supported rather than failure. */
	const bool ok = resolve_addr(&addr, "[::1]:5678", SA_RESOLVE_TCP);
	if (!ok) {
		T_SKIPNOW();
	}
	T_EXPECT_EQ(addr.sa.sa_family, (sa_family_t)AF_INET6);
	T_EXPECT_EQ(ntohs(addr.in6.sin6_port), (uint16_t)5678);
}

T_DECLARE_CASE(test_resolve_addr_invalid_returns_false)
{
	union sockaddr_max addr;
	/* No colon: splithostport returns false, so resolve_addr returns false. */
	T_EXPECT(!resolve_addr(&addr, "127.0.0.1", SA_RESOLVE_TCP));
}

static const struct testing_suite suite[] = {
	T_CASE(test_socket_notsent_lowat_sets_option),
	T_CASE(test_resolve_addr_ipv4_parses_correctly),
	T_CASE(test_resolve_addr_ipv6_parses_correctly),
	T_CASE(test_resolve_addr_invalid_returns_false),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
