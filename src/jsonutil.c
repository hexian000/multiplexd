/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file jsonutil.c
 * @brief JSON parsing utilities using json-c library.
 */

#include "jsonutil.h"

#include "utils/debug.h"
#include "utils/slog.h"

#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>
#include <json-c/json_util.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct jutil_value;

struct jutil_value *jutil_parse(const char *json, size_t length)
{
	if (length > INT_MAX) {
		return NULL;
	}
	struct json_tokener *tok = json_tokener_new();
	if (tok == NULL) {
		return NULL;
	}
	struct json_object *obj = json_tokener_parse_ex(tok, json, (int)length);
	const enum json_tokener_error err = json_tokener_get_error(tok);
	const size_t consumed = json_tokener_get_parse_end(tok);
	json_tokener_free(tok);
	if (err != json_tokener_success) {
		if (obj != NULL) {
			json_object_put(obj);
		}
		return NULL;
	}
	/* Reject trailing non-whitespace so that a truncated or garbage-appended
	 * file is detected rather than silently parsed as a valid document. */
	for (size_t i = consumed; i < length; i++) {
		const unsigned char c = (unsigned char)json[i];
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
			json_object_put(obj);
			return NULL;
		}
	}
	return (struct jutil_value *)obj;
}

/* Maximum config file size accepted by jutil_parsefile(). */
enum { JUTIL_MAX_FILE_SIZE = 16 * 1024 * 1024 };

struct jutil_value *jutil_parsefile(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		const int err = errno;
		LOGE_F("jsonutil: failed to open %s: (%d) %s", filename, err,
		       strerror(err));
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		const int err = errno;
		LOGE_F("jsonutil: fseek failed: (%d) %s", err, strerror(err));
		(void)fclose(fp);
		return NULL;
	}
	const long size = ftell(fp);
	if (size < 0) {
		const int err = errno;
		LOGE_F("jsonutil: ftell failed: (%d) %s", err, strerror(err));
		(void)fclose(fp);
		return NULL;
	}
	if ((size_t)size > JUTIL_MAX_FILE_SIZE) {
		LOGE_F("jsonutil: file too large: %s (%ld bytes, limit %d)",
		       filename, size, JUTIL_MAX_FILE_SIZE);
		(void)fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		const int err = errno;
		LOGE_F("jsonutil: fseek failed: (%d) %s", err, strerror(err));
		(void)fclose(fp);
		return NULL;
	}
	char *buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		(void)fclose(fp);
		return NULL;
	}
	const size_t n = fread(buf, 1, (size_t)size, fp);
	if (ferror(fp)) {
		const int err = errno;
		LOGE_F("jsonutil: fread failed: (%d) %s", err, strerror(err));
		free(buf);
		(void)fclose(fp);
		return NULL;
	}
	(void)fclose(fp);
	buf[n] = '\0';
	struct jutil_value *const result = jutil_parse(buf, n);
	free(buf);
	return result;
}

const char *
jutil_print(const struct jutil_value *value, size_t *len, const bool pretty)
{
	const int flags =
		pretty ? (JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED) :
			 JSON_C_TO_STRING_PLAIN;
	return json_object_to_json_string_length(
		(struct json_object *)value, flags, len);
}

bool jutil_printfile(
	const struct jutil_value *value, const char *filename,
	const bool pretty)
{
	const int flags =
		pretty ? (JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED) :
			 JSON_C_TO_STRING_PLAIN;
	return json_object_to_file_ext(
		       filename, (struct json_object *)value, flags) == 0;
}

void jutil_free(struct jutil_value *value)
{
	if (value == NULL) {
		return;
	}
	CHECK(json_object_put((struct json_object *)value));
}

bool jutil_walk_object(
	void *ud, const struct jutil_value *value, jutil_walk_object_cb cb)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_object)) {
		return false;
	}
	const struct json_object_iterator it_end = json_object_iter_end(obj);
	for (struct json_object_iterator it = json_object_iter_begin(obj);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {
		const char *k = json_object_iter_peek_name(&it);
		struct json_object *v = json_object_iter_peek_value(&it);
		if (!cb(ud, k, (struct jutil_value *)v)) {
			return false;
		}
	}
	return true;
}

bool jutil_walk_array(
	void *ud, const struct jutil_value *value, jutil_walk_array_cb cb)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_array)) {
		return false;
	}
	const size_t n = json_object_array_length(obj);
	for (size_t i = 0; i < n; i++) {
		struct json_object *v = json_object_array_get_idx(obj, i);
		if (!cb(ud, (struct jutil_value *)v)) {
			return false;
		}
	}
	return true;
}

bool jutil_get_bool(const struct jutil_value *value, bool *b)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_boolean)) {
		return false;
	}
	if (b != NULL) {
		*b = json_object_get_boolean(obj);
	}
	return true;
}

bool jutil_get_int(const struct jutil_value *value, int *i)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_int)) {
		return false;
	}
	if (i != NULL) {
		*i = json_object_get_int(obj);
	}
	return true;
}

bool jutil_get_uint(const struct jutil_value *value, uintmax_t *u)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_int)) {
		return false;
	}
	if (u != NULL) {
		*u = (uintmax_t)json_object_get_uint64(obj);
	}
	return true;
}

bool jutil_get_double(const struct jutil_value *value, double *d)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_double)) {
		return false;
	}
	if (d != NULL) {
		*d = json_object_get_double(obj);
	}
	return true;
}

const char *jutil_get_lstring(const struct jutil_value *value, size_t *len)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_string)) {
		return NULL;
	}
	if (len != NULL) {
		*len = json_object_get_string_len(obj);
	}
	return json_object_get_string(obj);
}

const char *jutil_get_string(const struct jutil_value *value)
{
	return jutil_get_lstring(value, NULL);
}

char *jutil_dup_lstring(const struct jutil_value *value, size_t *len)
{
	size_t n;
	const char *s = jutil_get_lstring(value, &n);
	if (s == NULL) {
		return NULL;
	}
	if (len != NULL) {
		*len = n;
	}
	return strndup(s, n);
}

char *jutil_dup_string(const struct jutil_value *value)
{
	size_t n;
	const char *s = jutil_get_lstring(value, &n);
	if (s == NULL) {
		return NULL;
	}
	return strndup(s, n);
}

struct jutil_value *jutil_new_object(void)
{
	return (struct jutil_value *)json_object_new_object();
}

struct jutil_value *jutil_new_array(void)
{
	return (struct jutil_value *)json_object_new_array();
}

struct jutil_value *jutil_new_string(const char *s)
{
	return (struct jutil_value *)json_object_new_string(s);
}

struct jutil_value *jutil_new_number(const char *const s)
{
	struct json_object *obj = json_object_new_int(0);
	if (obj == NULL) {
		return NULL;
	}
	char *dup = strdup(s);
	if (dup == NULL) {
		json_object_put(obj);
		return NULL;
	}
	json_object_set_serializer(
		obj, json_object_userdata_to_json_string, dup,
		json_object_free_userdata);
	return (struct jutil_value *)obj;
}

struct jutil_value *jutil_new_int(const intmax_t val)
{
	if (val >= INT64_MIN && val <= INT64_MAX) {
		return (struct jutil_value *)json_object_new_int64(
			(int64_t)val);
	}
	size_t maxlen = 20;
	while (maxlen <= 320) {
		char buf[maxlen];
		const int n = snprintf(buf, sizeof(buf), "%jd", val);
		if (n < 0) {
			return NULL;
		}
		if (n < (int)sizeof(buf)) {
			return jutil_new_number(buf);
		}
		maxlen = (size_t)n + 1;
	}
	return NULL;
}

struct jutil_value *jutil_new_uint(const uintmax_t val)
{
	if (val <= UINT64_MAX) {
		return (struct jutil_value *)json_object_new_uint64(
			(uint64_t)val);
	}
	size_t maxlen = 20;
	while (maxlen <= 320) {
		char buf[maxlen];
		const int n = snprintf(buf, sizeof(buf), "%ju", val);
		if (n < 0) {
			return NULL;
		}
		if (n < (int)sizeof(buf)) {
			return jutil_new_number(buf);
		}
		maxlen = (size_t)n + 1;
	}
	return NULL;
}

struct jutil_value *jutil_new_float(const double val)
{
	return (struct jutil_value *)json_object_new_double(val);
}

struct jutil_value *jutil_new_bool(bool b)
{
	return (struct jutil_value *)json_object_new_boolean(b);
}

bool jutil_object_set(
	struct jutil_value *obj, const char *key, struct jutil_value *val)
{
	struct json_object *o = (struct json_object *)obj;
	struct json_object *v = (struct json_object *)val;
	if (v == NULL) {
		json_object_object_del(o, key);
		return true;
	}
	if (json_object_object_add(o, key, v) != 0) {
		json_object_put(v);
		return false;
	}
	return true;
}

bool jutil_array_set(
	struct jutil_value *arr, size_t idx, struct jutil_value *val)
{
	struct json_object *a = (struct json_object *)arr;
	struct json_object *v = (struct json_object *)val;
	if (v == NULL) {
		json_object_array_del_idx(a, idx, 1);
		return true;
	}
	if (json_object_array_put_idx(a, idx, v) != 0) {
		json_object_put(v);
		return false;
	}
	return true;
}
