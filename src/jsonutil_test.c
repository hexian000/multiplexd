/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "jsonutil.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct walk_collector {
	int count;
};

static bool
walk_count_cb(void *ud, const char *key, const struct jutil_value *value)
{
	(void)key;
	(void)value;
	struct walk_collector *c = ud;
	c->count++;
	return true;
}

static bool
walk_stop_cb(void *ud, const char *key, const struct jutil_value *value)
{
	(void)key;
	(void)value;
	int *calls = ud;
	(*calls)++;
	return false;
}

static bool walk_array_count_cb(void *ud, const struct jutil_value *value)
{
	(void)value;
	int *count = ud;
	(*count)++;
	return true;
}

T_DECLARE_CASE(test_parse_empty_object)
{
	struct jutil_value *v = jutil_parse("{}", 2);
	T_CHECK(v != NULL);
	struct walk_collector col = { .count = 0 };
	T_EXPECT(jutil_walk_object(&col, v, walk_count_cb));
	T_EXPECT_EQ(col.count, 0);
	jutil_free(v);
}

T_DECLARE_CASE(test_parse_invalid_json)
{
	const char *s = "{bad";
	struct jutil_value *v = jutil_parse(s, strlen(s));
	T_EXPECT(v == NULL);
}

T_DECLARE_CASE(test_parse_trailing_garbage_rejected)
{
	const char *s = "{} x";
	struct jutil_value *v = jutil_parse(s, strlen(s));
	T_EXPECT(v == NULL);
}

T_DECLARE_CASE(test_parse_trailing_whitespace_accepted)
{
	(void)_t_;
	const char *s = "{}\n\t ";
	struct jutil_value *v = jutil_parse(s, strlen(s));
	T_CHECK(v != NULL);
	jutil_free(v);
}

T_DECLARE_CASE(test_get_string_valid)
{
	struct jutil_value *v = jutil_new_string("hello");
	T_CHECK(v != NULL);
	const char *s = jutil_get_string(v);
	T_CHECK(s != NULL);
	T_EXPECT_STREQ(s, "hello");
	jutil_free(v);
}

T_DECLARE_CASE(test_get_string_wrong_type)
{
	struct jutil_value *v = jutil_new_int(42);
	T_CHECK(v != NULL);
	T_EXPECT(jutil_get_string(v) == NULL);
	jutil_free(v);
}

T_DECLARE_CASE(test_get_int_valid)
{
	struct jutil_value *v = jutil_new_int(42);
	T_CHECK(v != NULL);
	int i = 0;
	T_EXPECT(jutil_get_int(v, &i));
	T_EXPECT_EQ(i, 42);
	jutil_free(v);
}

T_DECLARE_CASE(test_get_int_from_string_fails)
{
	struct jutil_value *v = jutil_new_string("hello");
	T_CHECK(v != NULL);
	int i = 0;
	T_EXPECT(!jutil_get_int(v, &i));
	jutil_free(v);
}

T_DECLARE_CASE(test_get_bool_true)
{
	struct jutil_value *v = jutil_new_bool(true);
	T_CHECK(v != NULL);
	bool b = false;
	T_EXPECT(jutil_get_bool(v, &b));
	T_EXPECT(b);
	jutil_free(v);
}

T_DECLARE_CASE(test_get_bool_false)
{
	struct jutil_value *v = jutil_new_bool(false);
	T_CHECK(v != NULL);
	bool b = true;
	T_EXPECT(jutil_get_bool(v, &b));
	T_EXPECT(!b);
	jutil_free(v);
}

T_DECLARE_CASE(test_get_uint_large_value)
{
	struct jutil_value *v = jutil_new_uint((uintmax_t)UINT64_MAX);
	T_CHECK(v != NULL);
	uintmax_t u = 0;
	T_EXPECT(jutil_get_uint(v, &u));
	T_EXPECT_EQ(u, (uintmax_t)UINT64_MAX);
	jutil_free(v);
}

T_DECLARE_CASE(test_get_double_valid)
{
	struct jutil_value *v = jutil_new_float(3.14);
	T_CHECK(v != NULL);
	double d = 0.0;
	T_EXPECT(jutil_get_double(v, &d));
	T_EXPECT(d > 3.13 && d < 3.15);
	jutil_free(v);
}

T_DECLARE_CASE(test_walk_object_visits_all_keys)
{
	const char *s = "{\"a\":1,\"b\":2,\"c\":3}";
	struct jutil_value *obj = jutil_parse(s, strlen(s));
	T_CHECK(obj != NULL);
	struct walk_collector col = { .count = 0 };
	T_EXPECT(jutil_walk_object(&col, obj, walk_count_cb));
	T_EXPECT_EQ(col.count, 3);
	jutil_free(obj);
}

T_DECLARE_CASE(test_walk_object_callback_false_stops)
{
	const char *s = "{\"a\":1,\"b\":2,\"c\":3}";
	struct jutil_value *obj = jutil_parse(s, strlen(s));
	T_CHECK(obj != NULL);
	int calls = 0;
	const bool ok = jutil_walk_object(&calls, obj, walk_stop_cb);
	/* Callback returned false: walk must also return false. */
	T_EXPECT(!ok);
	T_EXPECT_EQ(calls, 1);
	jutil_free(obj);
}

T_DECLARE_CASE(test_walk_array_visits_all_elements)
{
	const char *s = "[1,2,3,4,5]";
	struct jutil_value *arr = jutil_parse(s, strlen(s));
	T_CHECK(arr != NULL);
	int count = 0;
	T_EXPECT(jutil_walk_array(&count, arr, walk_array_count_cb));
	T_EXPECT_EQ(count, 5);
	jutil_free(arr);
}

T_DECLARE_CASE(test_dup_string_value)
{
	struct jutil_value *v = jutil_new_string("world");
	T_CHECK(v != NULL);
	char *dup = jutil_dup_string(v);
	T_CHECK(dup != NULL);
	T_EXPECT_STREQ(dup, "world");
	T_EXPECT((void *)dup != (void *)jutil_get_string(v));
	free(dup);
	jutil_free(v);
}

T_DECLARE_CASE(test_new_object_set_and_print)
{
	struct jutil_value *obj = jutil_new_object();
	T_CHECK(obj != NULL);
	T_EXPECT(jutil_object_set(obj, "x", jutil_new_int(7)));
	size_t len = 0;
	const char *s = jutil_print(obj, &len, false);
	T_CHECK(s != NULL);
	T_EXPECT(len > 0);
	/* Re-parse and verify "x" survives the roundtrip. */
	struct jutil_value *reparsed = jutil_parse(s, len);
	T_CHECK(reparsed != NULL);
	jutil_free(reparsed);
	jutil_free(obj);
}

T_DECLARE_CASE(test_object_set_null_deletes_key)
{
	struct jutil_value *obj = jutil_new_object();
	T_CHECK(obj != NULL);
	T_EXPECT(jutil_object_set(obj, "del", jutil_new_int(1)));
	/* NULL val → delete the key. */
	T_EXPECT(jutil_object_set(obj, "del", NULL));
	struct walk_collector col = { .count = 0 };
	T_EXPECT(jutil_walk_object(&col, obj, walk_count_cb));
	T_EXPECT_EQ(col.count, 0);
	jutil_free(obj);
}

T_DECLARE_CASE(test_new_int_roundtrip)
{
	struct jutil_value *v = jutil_new_int(-12345);
	T_CHECK(v != NULL);
	int i = 0;
	T_EXPECT(jutil_get_int(v, &i));
	T_EXPECT_EQ(i, -12345);
	jutil_free(v);
}

T_DECLARE_CASE(test_new_uint_roundtrip)
{
	struct jutil_value *v = jutil_new_uint(99999u);
	T_CHECK(v != NULL);
	uintmax_t u = 0;
	T_EXPECT(jutil_get_uint(v, &u));
	T_EXPECT_EQ(u, (uintmax_t)99999u);
	jutil_free(v);
}

T_DECLARE_CASE(test_new_bool_roundtrip)
{
	struct jutil_value *v = jutil_new_bool(true);
	T_CHECK(v != NULL);
	bool b = false;
	T_EXPECT(jutil_get_bool(v, &b));
	T_EXPECT(b);
	jutil_free(v);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_parse_empty_object);
	T_RUN_CASE(t, test_parse_invalid_json);
	T_RUN_CASE(t, test_parse_trailing_garbage_rejected);
	T_RUN_CASE(t, test_parse_trailing_whitespace_accepted);
	T_RUN_CASE(t, test_get_string_valid);
	T_RUN_CASE(t, test_get_string_wrong_type);
	T_RUN_CASE(t, test_get_int_valid);
	T_RUN_CASE(t, test_get_int_from_string_fails);
	T_RUN_CASE(t, test_get_bool_true);
	T_RUN_CASE(t, test_get_bool_false);
	T_RUN_CASE(t, test_get_uint_large_value);
	T_RUN_CASE(t, test_get_double_valid);
	T_RUN_CASE(t, test_walk_object_visits_all_keys);
	T_RUN_CASE(t, test_walk_object_callback_false_stops);
	T_RUN_CASE(t, test_walk_array_visits_all_elements);
	T_RUN_CASE(t, test_dup_string_value);
	T_RUN_CASE(t, test_new_object_set_and_print);
	T_RUN_CASE(t, test_object_set_null_deletes_key);
	T_RUN_CASE(t, test_new_int_roundtrip);
	T_RUN_CASE(t, test_new_uint_roundtrip);
	T_RUN_CASE(t, test_new_bool_roundtrip);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
