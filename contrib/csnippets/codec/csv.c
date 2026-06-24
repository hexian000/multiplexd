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

bool csv_unescape(char *field)
{
	/* Check if field is quoted (starts with double quote) */
	if (field[0] != '"') {
		/* Unquoted field - validate it contains no special characters */
		return strpbrk(field, "\"\r\n,") == NULL;
	}

	/* Remove surrounding quotes and unescape doubled internal quotes */
	size_t w = 0;
	for (size_t r = 1; field[r] != '\0'; r++) {
		switch (field[r]) {
		case '"':
			/* Check if this is a doubled quote or closing quote */
			if (field[++r] == '"') {
				/* Doubled quote - unescape to single quote */
				field[w++] = '"';
				continue;
			}

			/* Closing quote - finish unescaping */
			field[w] = '\0';
			/* Validate that nothing follows the closing quote */
			return field[r] == '\0';
		default:
			/* Regular character - copy as-is */
			field[w++] = field[r];
			break;
		}
	}

	return false;
}

char *csv_scanfield(char *buf, char **field)
{
	if (!buf || !*buf) {
		*field = NULL;
		return NULL;
	}

	char *start = buf;
	char *p = buf;
	bool quoted = (*p == '"');

	if (quoted) {
		p++; /* skip opening quote */
		while (*p) {
			if (*p == '"') {
				p++;
				if (*p == '"') {
					/* doubled quote, skip the second */
					p++;
				} else {
					/* closing quote found */
					break;
				}
			} else {
				p++;
			}
		}
		if (*p == '\0') {
			/* incomplete quoted field, need more data */
			return buf;
		}
		/* p now points after closing quote */
	} else {
		/* unquoted field */
		while (*p && *p != ',' && *p != '\n' && *p != '\r') {
			p++;
		}
	}

	/* remember the separator */
	char sep = *p;
	/* null-terminate the field */
	*p = '\0';
	*field = start;

	/* unescape the field */
	if (!csv_unescape(*field)) {
		return NULL; /* invalid field */
	}

	/* return the start of next parsing */
	return (sep == '\0') ? NULL : p + 1;
}
