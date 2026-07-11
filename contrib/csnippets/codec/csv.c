/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "csv.h"

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

	return (int)w;
}

/* Unescape a quoted CSV field in place. field[0] must be '"'. Surrounding
 * quotes are removed and doubled internal quotes are collapsed to a single
 * quote; the transformed content is NUL-terminated at the closing quote.
 * Returns a pointer to the byte just after the closing quote in the original
 * buffer (which the caller inspects for the following separator), or NULL if
 * the closing quote is missing (an incomplete quoted field). */
static char *csv_unescape_quoted(char *restrict field)
{
	size_t w = 0;
	for (size_t r = 1; field[r] != '\0'; r++) {
		if (field[r] == '"') {
			if (field[r + 1] == '"') {
				/* doubled quote -> single quote */
				field[w++] = '"';
				r++;
				continue;
			}
			/* closing quote: terminate the transformed content and
			 * report where the next field begins */
			field[w] = '\0';
			return &field[r + 1];
		}
		field[w++] = field[r];
	}
	return NULL; /* ran off the buffer without a closing quote */
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
	if (!buf || !*buf) {
		*field = NULL;
		*sep = '\0';
		return NULL;
	}

	const bool quoted = (*buf == '"');
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
	} else {
		/* unquoted field: stop at the first field/record separator */
		p = buf;
		while (*p && *p != ',' && *p != '\n' && *p != '\r') {
			p++;
		}
	}
	*field = buf;

	/* Report the terminating delimiter and where the next field begins.
	 * CRLF is a single record separator (reported as '\n'); a lone LF or CR
	 * is a record separator; ',' is a field separator; '\0' is end of data. */
	char *next;
	if (*p == '\0') {
		*sep = '\0';
		next = NULL;
	} else if (*p == '\r' && p[1] == '\n') {
		*sep = '\n';
		*p = '\0';
		next = p + 2;
	} else {
		*sep = *p;
		*p = '\0';
		next = p + 1;
	}

	/* A quoted field was already unescaped and validated above; an unquoted
	 * field (now NUL-terminated at its separator) must contain no stray
	 * special characters. */
	if (!quoted && !csv_unescape(*field)) {
		return NULL; /* invalid field */
	}

	return next;
}
