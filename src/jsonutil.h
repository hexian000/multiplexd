/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file jsonutil.h
 * @brief Lightweight JSON parse, walk, and serialization helpers.
 */

#ifndef JSONUTIL_H
#define JSONUTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct jutil_value; /* opaque */

/**
 * @brief Parse a JSON string into an opaque value tree.
 * @param json The input JSON buffer.
 * @param length The input length in bytes.
 * @return A new JSON value tree on success, or NULL on parse failure.
 */
struct jutil_value *jutil_parse(const char *json, size_t length);

/**
 * @brief Parse a JSON file into an opaque value tree.
 * @param filename The input file path.
 * @return A new JSON value tree on success, or NULL on parse or I/O failure.
 */
struct jutil_value *jutil_parsefile(const char *filename);

/**
 * @brief Serialize a JSON value tree to a string owned by the library.
 * @param value The value to print.
 * @param len Optional output for the serialized length.
 * @param pretty When true, emit indented output.
 * @return A pointer valid until the next serialization call affecting value.
 */
const char *
jutil_print(const struct jutil_value *value, size_t *len, bool pretty);

/**
 * @brief Serialize a JSON value tree to a file.
 * @param value The value to print.
 * @param filename The destination file path.
 * @param pretty When true, emit indented output.
 * @return true on success, false on serialization or I/O failure.
 */
bool jutil_printfile(
	const struct jutil_value *value, const char *filename, bool pretty);

/**
 * @brief Release a JSON value tree returned by this API.
 * @param value The value tree to free; NULL is allowed.
 */
void jutil_free(struct jutil_value *value);

typedef bool (*jutil_walk_object_cb)(
	void *ud, const char *key, const struct jutil_value *value);

/**
 * @brief Iterate over each key-value pair of a JSON object.
 * @param ud User data passed to the callback.
 * @param obj The object to walk.
 * @param cb Callback invoked for each element; false aborts the walk.
 * @return true when the walk completes successfully, false on type or callback failure.
 */
bool jutil_walk_object(
	void *ud, const struct jutil_value *obj, jutil_walk_object_cb cb);

typedef bool (*jutil_walk_array_cb)(void *ud, const struct jutil_value *value);

/**
 * @brief Iterate over each element of a JSON array.
 * @param ud User data passed to the callback.
 * @param arr The array to walk.
 * @param cb Callback invoked for each element; false aborts the walk.
 * @return true when the walk completes successfully, false on type or callback failure.
 */
bool jutil_walk_array(
	void *ud, const struct jutil_value *arr, jutil_walk_array_cb cb);

bool jutil_get_bool(const struct jutil_value *value, bool *b);
bool jutil_get_int(const struct jutil_value *value, int *i);
bool jutil_get_uint(const struct jutil_value *value, uintmax_t *u);
bool jutil_get_double(const struct jutil_value *value, double *d);
const char *jutil_get_lstring(const struct jutil_value *value, size_t *len);
const char *jutil_get_string(const struct jutil_value *value);

char *jutil_dup_lstring(const struct jutil_value *value, size_t *len);
char *jutil_dup_string(const struct jutil_value *value);

struct jutil_value *jutil_new_object(void);
struct jutil_value *jutil_new_array(void);
struct jutil_value *jutil_new_string(const char *s);

/* Create a JSON number from its raw string form (e.g. "1e100", "42"). */
struct jutil_value *jutil_new_number(const char *s);

struct jutil_value *jutil_new_int(intmax_t val);
struct jutil_value *jutil_new_uint(uintmax_t val);
struct jutil_value *jutil_new_float(double val);

struct jutil_value *jutil_new_bool(bool b);

/* Pass val=NULL to delete the key. Takes ownership of val on success. */
bool jutil_object_set(
	struct jutil_value *obj, const char *key, struct jutil_value *val);
/* Pass val=NULL to delete the element at idx. Takes ownership of val on success. */
bool jutil_array_set(
	struct jutil_value *arr, size_t idx, struct jutil_value *val);

#endif /* JSONUTIL_H */
