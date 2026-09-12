/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.c
 * @brief Project-wide helpers shared across the multiplexd modules.
 *
 * CSPRNG bytes, exclusive file creation and discard, address resolution,
 * socket backpressure classification, MIME media-type validation, identity
 * escaping, and, with TLS, ALPN list tokenizing and certificate identity
 * matching. The macros are header-only; see util.h.
 */

#include "util.h"

#if WITH_TLS
#include "tls.h"

#include "codec/csv.h"
#include "net/url.h"
#endif

#include "net/addr.h"
#include "net/mime.h"
#include "os/socket.h"
#include "utils/ctype_ascii.h"
#include "utils/slog.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
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

/* Best-effort: the caller is already returning an error. A removal that
 * succeeds is logged too, since the caller may already have announced the
 * file as written; without it the log would claim a file that is gone. */
void discard_file(const char *path)
{
	if (unlink(path) != 0) {
		const int err = errno;
		LOGW_F("failed to remove %s: (%d) %s", path, err,
		       strerror(err));
		return;
	}
	LOGN_F("remove %s", path);
}

FILE *create_exclusive(const char *path, mode_t mode)
{
	const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("failed to open %s: (%d) %s", path, err, strerror(err));
		return NULL;
	}
	FILE *const fp = fdopen(fd, "w");
	if (fp == NULL) {
		const int err = errno;
		LOGE_F("fdopen %s: (%d) %s", path, err, strerror(err));
		(void)close(fd);
		discard_file(path);
		return NULL;
	}
	return fp;
}

/* Split addrstr into hoststr/portstr via buf (capacity buflen); false if
 * addrstr doesn't fit or has no valid host:port syntax. */
static bool split_addr(
	char *restrict buf, const size_t buflen, const char *restrict addrstr,
	char **restrict hoststr, char **restrict portstr)
{
	/* strnlen, not strlen: it stops at buflen, so addrlen <= buflen holds by
	 * construction and the guard below leaves addrlen < buflen at the
	 * terminator store. An unbounded strlen leaves the optimizer unable to
	 * tie addrlen to buf's size, and it reports the store as overflowing on
	 * the very path the guard already excludes. */
	const size_t addrlen = strnlen(addrstr, buflen);
	if (addrlen >= buflen) {
		return false;
	}
	/* strnlen returning short of buflen means it found the terminator, so
	 * copy it along with the string: one bounded memcpy of addrlen + 1 <=
	 * buflen bytes. Storing the terminator separately at buf[addrlen] left
	 * the optimizer unable to tie the index to buf's size, and it reported
	 * that store as overflowing on the path the guard already excludes. */
	memcpy(buf, addrstr, addrlen + 1);
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

enum mime_check_result mime_check_media(
	char *const buf, const char *const subtype,
	const char **const version_out)
{
	char *media_type, *media_subtype;
	char *next = mime_parse(buf, &media_type, &media_subtype);
	if (next == NULL || strcmp(media_type, "application") != 0 ||
	    strcmp(media_subtype, subtype) != 0) {
		return MIME_CHECK_BAD_TYPE;
	}
	const char *version = NULL;
	char *key, *value;
	for (;;) {
		next = mime_parseparam(next, &key, &value);
		if (next == NULL) {
			/* mime_parseparam returns NULL only on a parse error; a
			 * clean end sets *key = NULL with a non-NULL return. */
			return MIME_CHECK_MALFORMED;
		}
		if (key == NULL) {
			break; /* clean end of parameters */
		}
		if (strcmp(key, "version") == 0) {
			version = value;
		}
	}
	*version_out = version;
	return MIME_CHECK_OK;
}

/* Length of the control character at s: 1 for a C0 byte or DEL, 2 for the
 * UTF-8 encoding of a C1 control (U+0080..U+009F, C2 80..C2 9F), which a UTF-8
 * terminal acts on as it does ESC-prefixed sequences (U+009B is CSI), and 0
 * for anything else. */
static size_t control_len(const char *s)
{
	const unsigned char c = (unsigned char)s[0];
	if (c < 0x20 || c == 0x7f) {
		return 1;
	}
	/* s[1] is readable: s[0] is not the terminator. */
	const unsigned char next = (unsigned char)s[1];
	if (c == 0xc2 && next >= 0x80 && next <= 0x9f) {
		return 2;
	}
	return 0;
}

void escape_identity(
	char *restrict out, const size_t outsize, const char *restrict in,
	const enum escape_ctx ctx)
{
	size_t o = 0;
	for (size_t i = 0; in[i] != '\0'; i++) {
		const unsigned char c = (unsigned char)in[i];
		char esc = '\0';
		switch (c) {
		case '\\':
		case '"':
			esc = (char)c;
			break;
		case '\n':
			esc = 'n';
			break;
		case '\t':
			esc = ctx == ESCAPE_PLAIN ? 't' : '\0';
			break;
		case '\r':
			esc = ctx == ESCAPE_PLAIN ? 'r' : '\0';
			break;
		default:
			break;
		}
		if (esc != '\0') {
			if (o + 2 >= outsize) {
				break;
			}
			out[o++] = '\\';
			out[o++] = esc;
			continue;
		}
		const size_t n = control_len(&in[i]);
		if (n == 0) {
			if (o + 1 >= outsize) {
				break;
			}
			out[o++] = (char)c;
		} else if (ctx == ESCAPE_PLAIN) {
			/* Any remaining control (e.g. ESC or CSI) would let a
			 * crafted identity drive terminal cursor motion; emit
			 * each of its bytes as an inert \xNN escape. */
			if (o + 4 * n >= outsize) {
				break;
			}
			for (size_t k = 0; k < n; k++) {
				out[o++] = '\\';
				out[o++] = 'x';
				tohexlower(&out[o], (unsigned char)in[i + k]);
				o += 2;
			}
			i += n - 1;
		} else {
			/* The metric grammar spells no escape for a remaining
			 * control, so substitute one inert placeholder for it. */
			if (o + 1 >= outsize) {
				break;
			}
			out[o++] = IDENTITY_METRIC_PLACEHOLDER;
			i += n - 1;
		}
	}
	out[o] = '\0';
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

/* True when one URI subjectAltName from a peer certificate names @p identity.
 *
 * The name is decoded and then compared, rather than the identity being
 * encoded and compared byte for byte: percent-encoding is not canonical, so a
 * certificate issued by other tooling may escape a different, equally valid
 * set of octets for the same identity.  Decoding to octets is what makes those
 * agree, and the aliasing it admits is harmless -- the issuing CA chose the
 * name either way.
 *
 * url_unescape_path() is reused rather than decoding by hand because it
 * rejects every control character the decode produces, %00 among them, while
 * the byte is still in hand (see unescape() in net/url.c).  Accepting the
 * prefix before an embedded NUL is the null-prefix certificate attack, and
 * that rejection is also what makes the strcmp() below sound.  csnippets does
 * deliberately decode "%%" to a literal '%' where a strict RFC 3986 decoder
 * errors (net/url.h); harmless here, since "%%" and "%25" decode alike. */
static bool
identity_uri_matches(const char *restrict uri, const char *restrict identity)
{
	const size_t scheme_len = sizeof(IDENTITY_URI_SCHEME) - 1;
	if (strncmp(uri, IDENTITY_URI_SCHEME, scheme_len) != 0) {
		return false;
	}
	const char *const encoded = uri + scheme_len;
	const size_t len = strlen(encoded);
	if (len > IDENTITY_ENCODED_MAX) {
		return false;
	}
	char buf[IDENTITY_ENCODED_MAX + 1];
	memcpy(buf, encoded, len + 1);
	if (!url_unescape_path(buf)) {
		return false;
	}
	return strcmp(buf, identity) == 0;
}

bool identity_matches_cert(
	struct tls_connection *const conn, const char *const identity)
{
	char **names = NULL;
	size_t count = 0;
	if (!tls_peer_cert_uri_sans(conn, &names, &count)) {
		return false;
	}
	bool matched = false;
	for (size_t i = 0; i < count && !matched; i++) {
		matched = identity_uri_matches(names[i], identity);
	}
	/* One allocation holds both the pointer array and the names. */
	free((void *)names);
	return matched;
}
#endif /* WITH_TLS */
