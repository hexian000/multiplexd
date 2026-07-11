/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* util_test.c - black-box tests for util.c's public API: address resolution
 * (resolve_addr, resolve_bindaddr), CSPRNG byte generation (csprng_bytes),
 * and a socket-option smoke test.
 * Dependencies: links the real util.c (+ TLS backend). */

#include "shim/util.h"

#include "os/socket.h"
#include "utils/testing.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

T_DECLARE_CASE(test_socket_notsent_lowat_sets_option)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);
#if WITH_TCP_NOTSENT_LOWAT
	(void)socket_notsent_lowat(fd, 4096);
	int val = 0;
	socklen_t len = sizeof(val);
	T_CHECK(getsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &val, &len) ==
		0);
	T_EXPECT_EQ(val, 4096);
#else /* WITH_TCP_NOTSENT_LOWAT */
	/* Platform lacks TCP_NOTSENT_LOWAT; only verify no crash. */
	(void)_t_;
	(void)socket_notsent_lowat(fd, 4096);
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

T_DECLARE_CASE(test_resolve_addr_oversized_returns_false)
{
	/* Longer than any valid FQDN+port string; the length check rejects it
	 * in every build configuration. */
	char addrstr[512];
	memset(addrstr, 'a', sizeof(addrstr) - 6);
	memcpy(addrstr + sizeof(addrstr) - 6, ":1234", 6);

	union sockaddr_max addr;
	T_EXPECT(!resolve_addr(&addr, addrstr, SA_RESOLVE_TCP));
}

T_DECLARE_CASE(test_resolve_addr_at_length_bound_rejected)
{
	/* addrlen == ADDR_MAX_LENGTH (262 = 255 + sizeof(":65535")): the
	 * smallest length the bound check must reject. An off-by-one bound
	 * regression would let this slip past the check and write one byte
	 * past the fixed-size buffer, caught by ASan. */
	char addrstr[263];
	memset(addrstr, 'a', sizeof(addrstr) - 6);
	memcpy(addrstr + sizeof(addrstr) - 6, ":1234", 6);

	union sockaddr_max addr;
	T_EXPECT(!resolve_addr(&addr, addrstr, SA_RESOLVE_TCP));
}

T_DECLARE_CASE(test_resolve_bindaddr_ipv4_parses_correctly)
{
	union sockaddr_max addr;
	const bool ok =
		resolve_bindaddr(&addr, "127.0.0.1:1234", SA_RESOLVE_TCP);
	T_CHECK(ok);
	if (!ok) {
		return;
	}
	T_EXPECT_EQ(addr.sa.sa_family, (sa_family_t)AF_INET);
	T_EXPECT_EQ(ntohs(addr.in.sin_port), (uint16_t)1234);
	T_EXPECT_EQ(addr.in.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
}

T_DECLARE_CASE(test_resolve_bindaddr_invalid_returns_false)
{
	union sockaddr_max addr;
	/* No colon: splithostport returns false, so resolve_bindaddr returns
	 * false. */
	T_EXPECT(!resolve_bindaddr(&addr, "127.0.0.1", SA_RESOLVE_TCP));
}

T_DECLARE_CASE(test_resolve_bindaddr_oversized_returns_false)
{
	/* Longer than any valid FQDN+port string; the length check rejects it
	 * in every build configuration. */
	char addrstr[512];
	memset(addrstr, 'a', sizeof(addrstr) - 6);
	memcpy(addrstr + sizeof(addrstr) - 6, ":1234", 6);

	union sockaddr_max addr;
	T_EXPECT(!resolve_bindaddr(&addr, addrstr, SA_RESOLVE_TCP));
}

/* resolve_bindaddr's defining behavior vs resolve_addr: an empty host with
 * AI_PASSIVE resolves to a wildcard bind address (INADDR_ANY / in6addr_any)
 * rather than a lookup failure. This is the sole reason resolve_bindaddr calls
 * sa_resolve_bind instead of sa_resolve, and every listener in server.c relies
 * on it, but no other case exercises the empty-host path. */
T_DECLARE_CASE(test_resolve_bindaddr_empty_host_wildcard)
{
	union sockaddr_max addr;
	const bool ok = resolve_bindaddr(&addr, ":0", SA_RESOLVE_TCP);
	T_CHECK(ok);
	if (!ok) {
		return;
	}
	/* getaddrinfo may return either family for a NULL/AI_PASSIVE node
	 * depending on the host stack; accept either wildcard. */
	if (addr.sa.sa_family == AF_INET) {
		T_EXPECT_EQ(addr.in.sin_addr.s_addr, htonl(INADDR_ANY));
	} else {
		T_EXPECT_EQ(addr.sa.sa_family, (sa_family_t)AF_INET6);
		T_EXPECT(
			memcmp(&addr.in6.sin6_addr, &in6addr_any,
			       sizeof(in6addr_any)) == 0);
	}
}

T_DECLARE_CASE(test_csprng_bytes_fills_buffer)
{
	unsigned char buf[32];
	memset(buf, 0, sizeof(buf));
	T_CHECK(csprng_bytes(buf, sizeof(buf)));

	/* Not a statistical test, just a smoke check: 32 bytes of real
	 * entropy being all-zero has probability 2^-256, i.e. never. */
	bool all_zero = true;
	for (size_t i = 0; i < sizeof(buf); i++) {
		if (buf[i] != 0) {
			all_zero = false;
			break;
		}
	}
	T_EXPECT(!all_zero);
}

T_DECLARE_CASE(test_csprng_bytes_not_repeating)
{
	/* Two consecutive fills producing an identical 16-byte sequence has
	 * probability 2^-128; a match here indicates a broken (e.g.
	 * always-zero or stuck) entropy source, not real randomness. */
	unsigned char a[16];
	unsigned char b[16];
	T_CHECK(csprng_bytes(a, sizeof(a)));
	T_CHECK(csprng_bytes(b, sizeof(b)));
	T_EXPECT(memcmp(a, b, sizeof(a)) != 0);
}

static const struct testing_suite suite[] = {
	T_CASE(test_socket_notsent_lowat_sets_option),
	T_CASE(test_resolve_addr_ipv4_parses_correctly),
	T_CASE(test_resolve_addr_ipv6_parses_correctly),
	T_CASE(test_resolve_addr_invalid_returns_false),
	T_CASE(test_resolve_addr_oversized_returns_false),
	T_CASE(test_resolve_addr_at_length_bound_rejected),
	T_CASE(test_resolve_bindaddr_ipv4_parses_correctly),
	T_CASE(test_resolve_bindaddr_invalid_returns_false),
	T_CASE(test_resolve_bindaddr_oversized_returns_false),
	T_CASE(test_resolve_bindaddr_empty_host_wildcard),
	T_CASE(test_csprng_bytes_fills_buffer),
	T_CASE(test_csprng_bytes_not_repeating),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
