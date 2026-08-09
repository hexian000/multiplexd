/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* util_test.c - black-box tests for util.c's public API: address resolution
 * (resolve_addr, resolve_bindaddr), CSPRNG byte generation (csprng_bytes),
 * MIME media-type validation (mime_check_media), and identity escaping
 * (escape_identity).
 * Dependencies: links the real util.c (+ TLS backend). */

#include "shim/util.h"

#include "os/socket.h"
#include "utils/testing.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

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
	/* addrlen == ADDR_MAX_STRLEN + 1 (262 = one past the 261-octet limit):
	 * the smallest length the bound check must reject. An off-by-one bound
	 * regression would let this slip past the check and write one byte
	 * past the fixed-size buffer, caught by ASan. */
	char addrstr[263];
	memset(addrstr, 'a', sizeof(addrstr) - 6);
	memcpy(addrstr + sizeof(addrstr) - 6, ":1234", 6);

	union sockaddr_max addr;
	T_EXPECT(!resolve_addr(&addr, addrstr, SA_RESOLVE_TCP));
}

/* addrlen == ADDR_MAX_STRLEN (261): the longest address the bound check
 * accepts, and the only length at which the copy fills buf exactly. The
 * rejecting side of the bound is covered above; this drives the accepting side,
 * where an off-by-one in the copy length writes one byte past a stack buffer.
 * Resolution then fails on the nonexistent host, so the return value says
 * nothing -- the assertion here is ASan's, under the sanitizer build. */
T_DECLARE_CASE(test_resolve_addr_at_length_bound_copies_in_bounds)
{
	char addrstr[ADDR_MAX_STRLEN + 1];
	memset(addrstr, 'a', sizeof(addrstr) - 6);
	memcpy(addrstr + sizeof(addrstr) - 6, ":1234", 6);
	T_EXPECT_EQ(strlen(addrstr), (size_t)ADDR_MAX_STRLEN);

	union sockaddr_max addr;
	(void)resolve_addr(&addr, addrstr, SA_RESOLVE_TCP);
	(void)resolve_bindaddr(&addr, addrstr, SA_RESOLVE_TCP);
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

/* csprng_bytes must return false (its documented contract) when /dev/urandom
 * cannot be opened. Lower RLIMIT_NOFILE and exhaust the table with dup() so
 * open() deterministically fails with EMFILE. The read-error/unexpected-EOF
 * branches are not provokable without dependency injection, so only the
 * open-failure branch is covered. */
T_DECLARE_CASE(test_csprng_bytes_fails_when_fd_exhausted)
{
	struct rlimit orig;
	T_CHECK(getrlimit(RLIMIT_NOFILE, &orig) == 0);
	struct rlimit low = orig;
	low.rlim_cur = 64; /* bounded exhaustion; existing fds stay open */
	T_CHECK(setrlimit(RLIMIT_NOFILE, &low) == 0);

	int dups[64];
	size_t n = 0;
	for (; n < sizeof(dups) / sizeof(dups[0]); n++) {
		const int d = dup(STDIN_FILENO);
		if (d < 0) {
			break; /* EMFILE: the table is now full */
		}
		dups[n] = d;
	}

	unsigned char buf[8] = { 0 };
	const bool ok = csprng_bytes(buf, sizeof(buf));

	for (size_t i = 0; i < n; i++) {
		(void)close(dups[i]);
	}
	T_CHECK(setrlimit(RLIMIT_NOFILE, &orig) == 0);
	T_EXPECT(!ok);
}

T_DECLARE_CASE(test_mime_check_media_ok_with_version)
{
	char buf[] = "application/x-multiplexd-config; version=1";
	const char *version = NULL;
	const enum mime_check_result r =
		mime_check_media(buf, "x-multiplexd-config", &version);
	T_EXPECT(r == MIME_CHECK_OK);
	T_EXPECT(version != NULL && strcmp(version, "1") == 0);
}

T_DECLARE_CASE(test_mime_check_media_case_and_whitespace_insensitive)
{
	/* mime_parse lowercases the type, subtype, and parameter names and trims
	 * surrounding whitespace; the parameter value is preserved verbatim. */
	char buf[] = "  Application / X-Multiplexd-Proto ; Version=7 ";
	const char *version = NULL;
	const enum mime_check_result r =
		mime_check_media(buf, "x-multiplexd-proto", &version);
	T_EXPECT(r == MIME_CHECK_OK);
	T_EXPECT(version != NULL && strcmp(version, "7") == 0);
}

T_DECLARE_CASE(test_mime_check_media_extra_params_ignored)
{
	char buf[] =
		"application/x-multiplexd-config; charset=utf-8; version=1";
	const char *version = NULL;
	const enum mime_check_result r =
		mime_check_media(buf, "x-multiplexd-config", &version);
	T_EXPECT(r == MIME_CHECK_OK);
	T_EXPECT(version != NULL && strcmp(version, "1") == 0);
}

T_DECLARE_CASE(test_mime_check_media_missing_version_is_ok)
{
	/* Absent "version" is not the helper's concern -- it returns OK with a
	 * NULL version and leaves the presence check to the caller. */
	char buf[] = "application/x-multiplexd-config";
	const char *version = NULL;
	const enum mime_check_result r =
		mime_check_media(buf, "x-multiplexd-config", &version);
	T_EXPECT(r == MIME_CHECK_OK);
	T_EXPECT(version == NULL);
}

T_DECLARE_CASE(test_mime_check_media_wrong_subtype)
{
	char buf[] = "application/x-multiplexd-proto; version=1";
	const char *version = NULL;
	const enum mime_check_result r =
		mime_check_media(buf, "x-multiplexd-config", &version);
	T_EXPECT(r == MIME_CHECK_BAD_TYPE);
}

T_DECLARE_CASE(test_mime_check_media_wrong_type)
{
	char buf[] = "text/plain; version=1";
	const char *version = NULL;
	const enum mime_check_result r =
		mime_check_media(buf, "x-multiplexd-config", &version);
	T_EXPECT(r == MIME_CHECK_BAD_TYPE);
}

T_DECLARE_CASE(test_mime_check_media_malformed_tail)
{
	/* A bare parameter name with no '=' value: mime_parseparam reports a
	 * parse error, surfaced as MIME_CHECK_MALFORMED rather than silently
	 * accepting the valid prefix. */
	char buf[] = "application/x-multiplexd-config; version";
	const char *version = NULL;
	const enum mime_check_result r =
		mime_check_media(buf, "x-multiplexd-config", &version);
	T_EXPECT(r == MIME_CHECK_MALFORMED);
}

/* Every escape class of the plaintext grammar in one identity: the two
 * verbatim escapes, the shared \n, the two ESCAPE_PLAIN-only escapes, and a
 * remaining C0 byte -- ESC, the one that drives a reader's terminal -- as an
 * inert \xNN. */
T_DECLARE_CASE(test_escape_identity_plain_escapes_every_class)
{
	char out[IDENTITY_ESCAPED_MAX];
	escape_identity(
		out, sizeof(out), "a\"b\nc\\d\te\rf\x1b[", ESCAPE_PLAIN);
	T_EXPECT_STREQ(out, "a\\\"b\\nc\\\\d\\te\\rf\\x1b[");
}

/* The same identity in the Prometheus grammar, where \\, \" and \n are the
 * only valid label-value escapes: every other C0 byte -- TAB and CR as much as
 * the terminal-driving ESC -- becomes the placeholder, since \t, \r and \xNN
 * alike would make the scrape unparseable and passing the byte through would
 * put it on the operator's terminal. */
T_DECLARE_CASE(test_escape_identity_metric_substitutes_remaining_c0)
{
	char out[IDENTITY_ESCAPED_MAX];
	escape_identity(
		out, sizeof(out), "a\"b\nc\\d\te\rf\x1b[", ESCAPE_METRIC);
	T_EXPECT_STREQ(out, "a\\\"b\\nc\\\\d?e?f?[");
}

/* Each truncation guard at its exact boundary: the result breaks at a whole
 * escape and is always NUL-terminated. The plaintext call sites escape into
 * 64-byte stack buffers, so an off-by-one here writes past one of them --
 * hence the smallest fitting size is driven too, where the buffer is exact and
 * the sanitizer sees the overflow no assertion could. */
T_DECLARE_CASE(test_escape_identity_truncates_and_terminates)
{
	/* Two-byte escape: "a\n" needs 4 bytes with the terminator. */
	{
		char out[3];
		escape_identity(out, sizeof(out), "a\nb", ESCAPE_PLAIN);
		T_EXPECT_STREQ(out, "a");
	}
	{
		char out[4];
		escape_identity(out, sizeof(out), "a\nb", ESCAPE_PLAIN);
		T_EXPECT_STREQ(out, "a\\n");
	}
	/* Four-byte hex escape: "a\x1b" needs 6 bytes with the terminator.
	 * The trailing 'z' is not a hex digit, so it ends the \x escape. */
	{
		char out[5];
		escape_identity(out, sizeof(out), "a\x1bz", ESCAPE_PLAIN);
		T_EXPECT_STREQ(out, "a");
	}
	{
		char out[6];
		escape_identity(out, sizeof(out), "a\x1bz", ESCAPE_PLAIN);
		T_EXPECT_STREQ(out, "a\\x1b");
	}
	/* Verbatim byte: one byte with the terminator. */
	{
		char out[3];
		escape_identity(out, sizeof(out), "abc", ESCAPE_PLAIN);
		T_EXPECT_STREQ(out, "ab");
	}
	/* Metric placeholder: one byte, as a verbatim byte is, but written
	 * through a guard of its own. */
	{
		char out[2];
		escape_identity(out, sizeof(out), "a\x1bz", ESCAPE_METRIC);
		T_EXPECT_STREQ(out, "a");
	}
	{
		char out[3];
		escape_identity(out, sizeof(out), "a\x1bz", ESCAPE_METRIC);
		T_EXPECT_STREQ(out, "a?");
	}
	/* Only the terminator fits. */
	{
		char out[1];
		escape_identity(out, sizeof(out), "abc", ESCAPE_PLAIN);
		T_EXPECT_STREQ(out, "");
	}
}

/* IDENTITY_ESCAPED_MAX is sized against the worst case, so a full-length
 * identity of the costliest byte -- a C0 control, 4 output bytes each -- must
 * come back whole rather than truncated. */
T_DECLARE_CASE(test_escape_identity_worst_case_fits_escaped_max)
{
	/* The longest identity the constant budgets for, derived from it. */
	enum { IDENTITY_MAX = (IDENTITY_ESCAPED_MAX - 1) / 4 };
	char in[IDENTITY_MAX + 1];
	memset(in, '\x1b', IDENTITY_MAX);
	in[IDENTITY_MAX] = '\0';

	char out[IDENTITY_ESCAPED_MAX];
	escape_identity(out, sizeof(out), in, ESCAPE_PLAIN);
	T_EXPECT_EQ(strlen(out), (size_t)(4 * IDENTITY_MAX));
}

static const struct testing_suite suite[] = {
	T_CASE(test_resolve_addr_ipv4_parses_correctly),
	T_CASE(test_resolve_addr_ipv6_parses_correctly),
	T_CASE(test_resolve_addr_invalid_returns_false),
	T_CASE(test_resolve_addr_oversized_returns_false),
	T_CASE(test_resolve_addr_at_length_bound_rejected),
	T_CASE(test_resolve_addr_at_length_bound_copies_in_bounds),
	T_CASE(test_resolve_bindaddr_ipv4_parses_correctly),
	T_CASE(test_resolve_bindaddr_invalid_returns_false),
	T_CASE(test_resolve_bindaddr_oversized_returns_false),
	T_CASE(test_resolve_bindaddr_empty_host_wildcard),
	T_CASE(test_csprng_bytes_fills_buffer),
	T_CASE(test_csprng_bytes_not_repeating),
	T_CASE(test_csprng_bytes_fails_when_fd_exhausted),
	T_CASE(test_mime_check_media_ok_with_version),
	T_CASE(test_mime_check_media_case_and_whitespace_insensitive),
	T_CASE(test_mime_check_media_extra_params_ignored),
	T_CASE(test_mime_check_media_missing_version_is_ok),
	T_CASE(test_mime_check_media_wrong_subtype),
	T_CASE(test_mime_check_media_wrong_type),
	T_CASE(test_mime_check_media_malformed_tail),
	T_CASE(test_escape_identity_plain_escapes_every_class),
	T_CASE(test_escape_identity_metric_substitutes_remaining_c0),
	T_CASE(test_escape_identity_truncates_and_terminates),
	T_CASE(test_escape_identity_worst_case_fits_escaped_max),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
