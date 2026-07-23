/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CODEC_CSV_H
#define CODEC_CSV_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup csv
 * @brief RFC 4180: Common Format and MIME Type for Comma-Separated Values (CSV) Files
 * @{
 */

/**
 * @brief Escape a CSV field into a separate buffer.
 *
 * The function always null-terminates the output buffer (if maxlen > 0),
 * similar to snprintf behavior.
 *
 * @param[out] buf Output buffer to write the escaped field
 * @param maxlen Size of the output buffer (including space for null terminator)
 * @param field Input field to escape (null-terminated string)
 * @return Number of characters that would be written (excluding null terminator).
 *         If the return value is >= maxlen, the output was truncated.
 */
int csv_escape(char *restrict buf, size_t maxlen, const char *restrict field);

/**
 * @brief Unescape a CSV field in-place.
 * @param[inout] field The field to unescape (modified in-place)
 * @return true if the field is valid and successfully unescaped, false otherwise
 * @note On failure, the content may be partially modified.
 */
bool csv_unescape(char *restrict field);

/**
 * @brief Scan and parse the next CSV field from the buffer.
 * @details Parses the next field from the CSV data buffer, modifying the buffer in-place
 *          by null-terminating the field and unescaping it. No memory allocations are performed.
 *          The function handles both quoted and unquoted fields according to RFC 4180.
 * @param[inout] buf Pointer to the CSV data buffer, or NULL to signal end of
 *             data. The buffer is modified in-place. A non-NULL but empty
 *             buffer is treated as a single empty field, not end of data:
 *             a field separator at the very end of the buffer yields a
 *             trailing empty field (RFC 4180: `a,` parses to `a`, ``), and
 *             a record separator at the end does not.
 * @param[out] field Pointer to store the parsed field string, or NULL when buf
 *             is NULL (end of data), more data is needed for a complete quoted
 *             field, or the data was invalid.
 * @param[out] sep The delimiter that terminated the field, so the caller can tell
 *             a field separator from a record separator: ',' for a field
 *             separator, '\n' for a record separator (a lone LF or a CRLF, which
 *             is consumed as a single unit), '\r' for a lone-CR record separator,
 *             or '\0' when the field ran to the end of the buffer (the last
 *             field) or no field was produced.
 * @return The start of the next field for continued parsing (not equal to buf).
 *         Equal to the input buf when more data is needed for a complete quoted
 *         field (with `field` NULL). NULL when no next field is returned: for
 *         the last field of the data (with `field` set) -- whether it ran to
 *         the end of the buffer or ended at a record separator that was the
 *         buffer's final byte(s) -- or when no field is produced at all --
 *         exhausted input or invalid data (both with `field` NULL). The
 *         last-field case is told apart by whether `field` was set, so a NULL
 *         return alone must not be treated as an error.
 */
char *
csv_scanfield(char *restrict buf, char **restrict field, char *restrict sep);

/** @} */

#endif /* CODEC_CSV_H */
