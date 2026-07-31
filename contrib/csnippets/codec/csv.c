/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "csv.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

int csv_escape(char *restrict buf, size_t maxlen, const char *restrict field)
{
	size_t w = 0;

	/* Macro to write a character to buffer, always incrementing position */
#define WRITE_CH(ch)                                                           \
	do {                                                                   \
		if (w + 1 < maxlen) {                                          \
			buf[w] = (ch);                                         \
		}                                                              \
		w++;                                                           \
	} while (0)

	/* Check if quoting is needed */
	if (strpbrk(field, "\"\r\n,") == NULL) {
		/* No quoting needed, copy directly */
		for (; *field != '\0'; field++) {
			WRITE_CH(*field);
		}
	} else {
		/* Quoting needed: add opening quote */
		WRITE_CH('"');

		/* Escape field content by doubling internal quotes */
		for (; *field != '\0'; field++) {
			const char ch = *field;
			if (ch == '"') {
				/* Double the quote */
				WRITE_CH('"');
				WRITE_CH('"');
			} else {
				WRITE_CH(ch);
			}
		}

		/* Add closing quote */
		WRITE_CH('"');
	}

	/* Null terminator */
	if (maxlen > 0) {
		const size_t pos = (w < maxlen) ? w : (maxlen - 1);
		buf[pos] = '\0';
	}

#undef WRITE_CH

	/* The int return cannot represent a count past INT_MAX; signal that with
	 * -1 rather than an implementation-defined narrowing, matching json.c's
	 * marshal_checked_int. */
	if (w > (size_t)INT_MAX) {
		return -1;
	}
	return (int)w;
}

/* Unescape a quoted CSV field in place. field[0] must be '"'. Surrounding
 * quotes are removed and doubled internal quotes are collapsed to a single
 * quote; the transformed content is NUL-terminated at the closing quote.
 * Returns a pointer to the byte just after the closing quote in the original
 * buffer (which the caller inspects for the following separator), or NULL if
 * the closing quote is missing (an incomplete quoted field).
 *
 * The closing quote is located first, before anything is written, so an
 * incomplete field (no closing quote yet) leaves the buffer byte-for-byte
 * intact: csv_scanfield hands such a buffer back to a streaming caller that
 * appends more data and retries, which only works if the retried buffer still
 * begins with the opening quote and unshifted content. Rewriting in place
 * before the field was known complete corrupted that retry. */
static char *csv_unescape_quoted(char *restrict field)
{
	size_t end = 0;
	for (size_t r = 1;; r++) {
		if (field[r] == '\0') {
			return NULL; /* ran off the buffer, no closing quote */
		}
		if (field[r] == '"') {
			if (field[r + 1] == '"') {
				r++; /* doubled quote: part of the content */
				continue;
			}
			end = r; /* lone quote: the closing quote */
			break;
		}
	}
	/* the field is known complete: collapse doubled quotes in place up to
	 * the closing quote and terminate the transformed content */
	size_t w = 0;
	for (size_t r = 1; r < end; r++) {
		if (field[r] == '"') {
			r++; /* skip the second quote of the doubled pair */
		}
		field[w++] = field[r];
	}
	field[w] = '\0';
	return &field[end + 1];
}

bool csv_unescape(char *restrict field)
{
	/* Check if field is quoted (starts with double quote) */
	if (field[0] != '"') {
		/* Unquoted field - validate it contains no special characters */
		return strpbrk(field, "\"\r\n,") == NULL;
	}
	/* Quoted field: unescape in place; the closing quote must be the last
	 * character, i.e. nothing may follow it. */
	const char *const end = csv_unescape_quoted(field);
	return end != NULL && *end == '\0';
}

char *
csv_scanfield(char *restrict buf, char **restrict field, char *restrict sep)
{
	if (!buf) {
		*field = NULL;
		*sep = '\0';
		return NULL;
	}
	/* A non-NULL but empty buffer is one empty field, not end of data: it is
	 * how a trailing field separator's following field (RFC 4180) and a lone
	 * empty record are represented. End of data is signalled by a NULL buf. */

	const bool quoted = (*buf == '"');
	bool unquoted_has_quote = false;
	char *p;
	if (quoted) {
		/* unescape in place and locate the byte after the closing quote,
		 * sharing the doubled-quote logic with csv_unescape */
		p = csv_unescape_quoted(buf);
		if (p == NULL) {
			/* incomplete quoted field, need more data */
			*field = NULL;
			*sep = '\0';
			return buf;
		}
		/* the closing quote must be followed immediately by a field or
		 * record separator (or end of data); stray bytes after it are
		 * malformed input, not a new separator */
		if (*p != '\0' && *p != ',' && *p != '\r' && *p != '\n') {
			*field = NULL;
			*sep = '\0';
			return NULL;
		}
	} else {
		/* unquoted field: stop at the first field/record separator, and in
		 * the same pass flag a stray '"'. The loop already excludes ',',
		 * '\r' and '\n', so once the field is NUL-terminated at its
		 * separator a lone '"' is the only special character it can still
		 * contain -- detecting it here spares a second full scan. */
		p = buf;
		while (*p && *p != ',' && *p != '\n' && *p != '\r') {
			if (*p == '"') {
				unquoted_has_quote = true;
			}
			p++;
		}
	}
	*field = buf;

	/* Report the terminating delimiter and where the next field begins.
	 * CRLF is a single record separator (reported as '\n'); a lone LF or CR
	 * is a record separator; ',' is a field separator; '\0' is end of data. */
	char *next;
	if (*p == '\0') {
		/* the field ran to the end of the buffer with no separator: it is
		 * the last field of the data */
		*sep = '\0';
		next = NULL;
	} else if (*p == ',') {
		/* field separator: a following field always exists per RFC 4180,
		 * even when the comma is the last byte -- then the trailing field
		 * is empty and next points at the buffer's terminator, which the
		 * follow-up call scans as one empty field */
		*sep = ',';
		*p = '\0';
		next = p + 1;
	} else if (*p == '\r' && p[1] == '\n') {
		/* record separator (CRLF): the record is complete, so an occurrence
		 * at the very end of the buffer yields no trailing empty field */
		*sep = '\n';
		*p = '\0';
		next = (p[2] == '\0') ? NULL : p + 2;
	} else {
		/* record separator (lone LF or CR): same end-of-buffer rule */
		*sep = *p;
		*p = '\0';
		next = (p[1] == '\0') ? NULL : p + 1;
	}

	/* A quoted field was already unescaped and validated above; an unquoted
	 * field is malformed only if it holds a stray '"', flagged during the
	 * scan above. */
	if (unquoted_has_quote) {
		/* clear the outputs like the quoted failure paths do; a NULL
		 * return also means end of data, so leaving them set would make
		 * a malformed last field indistinguishable from a valid one */
		*field = NULL;
		*sep = '\0';
		return NULL; /* invalid field */
	}

	return next;
}
