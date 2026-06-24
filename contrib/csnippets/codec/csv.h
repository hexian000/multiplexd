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
 * @brief Escape a CSV field in-place.
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
bool csv_unescape(char *field);

/**
 * @brief Scan and parse the next CSV field from the buffer.
 * @details Parses the next field from the CSV data buffer, modifying the buffer in-place
 *          by null-terminating the field and unescaping it. No memory allocations are performed.
 *          The function handles both quoted and unquoted fields according to RFC 4180.
 * @param[inout] buf Pointer to the CSV data buffer. The buffer is modified in-place.
 * @param[out] field Pointer to store the parsed field string, or NULL if end of data is reached.
 * @return Pointer to the start of the next field for continued parsing, or NULL if parsing failed
 *         due to invalid data. If the return value equals the input buf, more data is needed
 *         for a complete quoted field.
 */
char *csv_scanfield(char *buf, char **field);

/** @} */

#endif /* CODEC_CSV_H */
