/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* conf_test.c - black-box tests for the JSON config loader in conf.c via its
 * public API. Dependencies: links the real conf.c + generated schema. */

#include "conf.h"

#include "mux/mux.h"
#include "shim/tls.h"

#include "meta/arraysize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CONF_TEST_WRAP_ALLOC
/* conf.c is linked separately, so intercept only this executable's allocation
 * calls. Arm around conf_dump alone; parsing and test-framework allocations
 * must not consume a failure or distort the cleanup counts. */
static struct {
	bool armed;
	size_t fail_at;
	size_t calls;
	size_t allocated;
	size_t freed;
} dump_alloc;

static struct config *rejection_probe_conf;
static size_t rejection_probe_frees;
#if WITH_TLS
static struct {
	bool armed;
	void *ptr;
	size_t frees;
	bool zeroed;
} dump_erase_probe;
#endif

void *test_real_malloc(size_t size) __asm__("__real_malloc");
void *test_real_calloc(size_t count, size_t size) __asm__("__real_calloc");
void test_real_free(void *ptr) __asm__("__real_free");
void *test_wrap_malloc(size_t size) __asm__("__wrap_malloc");
void *test_wrap_calloc(size_t count, size_t size) __asm__("__wrap_calloc");
void test_wrap_free(void *ptr) __asm__("__wrap_free");

static bool dump_alloc_should_fail(void)
{
	return dump_alloc.armed && ++dump_alloc.calls == dump_alloc.fail_at;
}

static void *dump_alloc_record(void *ptr)
{
	if (dump_alloc.armed && ptr != NULL) {
		dump_alloc.allocated++;
	}
	return ptr;
}

void *test_wrap_malloc(size_t size)
{
	if (dump_alloc_should_fail()) {
		return NULL;
	}
	void *const ptr = test_real_malloc(size);
#if WITH_TLS
	if (dump_erase_probe.armed && size == CONF_MAXSIZE + 1 && ptr != NULL) {
		dump_erase_probe.ptr = ptr;
		/* Include untouched capacity in the release-boundary observation. */
		memset(ptr, 0xA5, size);
	}
#endif
	return dump_alloc_record(ptr);
}

void *test_wrap_calloc(size_t count, size_t size)
{
	if (dump_alloc_should_fail()) {
		return NULL;
	}
	return dump_alloc_record(test_real_calloc(count, size));
}

void test_wrap_free(void *ptr)
{
#if WITH_TLS
	if (ptr != NULL && ptr == dump_erase_probe.ptr) {
		const unsigned char *const bytes = ptr;
		dump_erase_probe.zeroed = true;
		for (size_t i = 0; i < CONF_MAXSIZE + 1; i++) {
			if (bytes[i] != 0) {
				dump_erase_probe.zeroed = false;
				break;
			}
		}
		dump_erase_probe.ptr = NULL;
		dump_erase_probe.frees++;
	}
#endif /* WITH_TLS */
	if (ptr != NULL && ptr == rejection_probe_conf) {
		rejection_probe_conf = NULL;
		rejection_probe_frees++;
	}
	if (dump_alloc.armed && ptr != NULL) {
		dump_alloc.freed++;
	}
	test_real_free(ptr);
}
#endif /* CONF_TEST_WRAP_ALLOC */

static void
retain_cleanup(struct testing_ctx *_t_, void (*cleanup)(void *), void *data)
{
	if (data != NULL) {
		T_CLEANUP(cleanup, data);
	}
}

/* An early release disarms the matching case cleanup. This also bounds the
 * cleanup stack in cases that acquire and release resources in a loop. */
static void
release_cleanup(struct testing_ctx *t, void (*cleanup)(void *), void *data)
{
	for (int i = t->cleanup_count; i > 0; i--) {
		if (t->cleanups[i - 1].fn == cleanup &&
		    t->cleanups[i - 1].data == data) {
			memmove(&t->cleanups[i - 1], &t->cleanups[i],
				(size_t)(t->cleanup_count - i) *
					sizeof(t->cleanups[0]));
			t->cleanup_count--;
			break;
		}
	}
	cleanup(data);
}

static void cleanup_conf(void *data)
{
	conf_free(data);
}

static void cleanup_path(void *data)
{
	(void)unlink(data);
	free(data);
}

static void retain_path(struct testing_ctx *_t_, const char *path)
{
	char *const saved = strdup(path);
	T_CHECK(saved != NULL);
	T_CLEANUP(cleanup_path, saved);
}

static void release_path(struct testing_ctx *t, const char *path)
{
	for (int i = t->cleanup_count; i > 0; i--) {
		if (t->cleanups[i - 1].fn == cleanup_path &&
		    strcmp(t->cleanups[i - 1].data, path) == 0) {
			release_cleanup(
				t, cleanup_path, t->cleanups[i - 1].data);
			return;
		}
	}
	(void)unlink(path);
}

/* Write bytes to a new temp file; return -1 on failure. */
static int write_tmpfile_len(
	char *restrict tmpl, const char *restrict content, const size_t len)
{
	const int fd = mkstemp(tmpl);
	if (fd < 0) {
		return -1;
	}
	if (write(fd, content, len) != (ssize_t)len) {
		(void)close(fd);
		(void)unlink(tmpl);
		return -1;
	}
	(void)close(fd);
	return 0;
}

static int write_tmpfile(char *restrict tmpl, const char *restrict content)
{
	return write_tmpfile_len(tmpl, content, strlen(content));
}

static bool
write_conf_file(const struct config *restrict conf, const char *restrict path)
{
	size_t len;
	char *const json = conf_dump(conf, &len, NULL);
	if (json == NULL) {
		return false;
	}
	FILE *const fp = fopen(path, "w");
	if (fp == NULL) {
		free(json);
		return false;
	}
	const bool ok = fwrite(json, 1, len, fp) == len;
	(void)fclose(fp);
	free(json);
	return ok;
}

static struct config *parse_tmpconf(const char *restrict content)
{
	char tmpl[] = CONF_TEST_TMPDIR "/conf_test_XXXXXX";
	if (write_tmpfile(tmpl, content) != 0) {
		return NULL;
	}
	struct config *const conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	return conf;
}

static const struct identity_peer *
find_peer(const struct config *restrict conf, const char *restrict id)
{
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		if (strcmp(conf->identity.peers[i].id, id) == 0) {
			return &conf->identity.peers[i];
		}
	}
	return NULL;
}

struct conf_log_capture {
	char text[1024];
	size_t len;
	bool unsafe;
};

static void capture_conf_log(void *ud, const unsigned char *buf, size_t len)
{
	struct conf_log_capture *const capture = ud;
	for (size_t i = 0; i < len; i++) {
		if ((buf[i] < 0x20 && !(buf[i] == '\n' && i + 1 == len)) ||
		    buf[i] == 0x7F ||
		    (buf[i] == 0xC2 && i + 1 < len && buf[i + 1] >= 0x80 &&
		     buf[i + 1] <= 0x9F)) {
			capture->unsafe = true;
		}
	}
	const size_t available = sizeof(capture->text) - capture->len - 1;
	const size_t n = len < available ? len : available;
	memcpy(capture->text + capture->len, buf, n);
	capture->len += n;
	capture->text[capture->len] = '\0';
}

T_DECLARE_CASE(test_conf_map_diagnostics_escape_keys)
{
	static const struct {
		const char *json_key;
		const char *rendered;
	} keys[] = {
		{ "a\\u0000b", "\"a\\u0000b\"" },
		{ "a\\u0000c", "\"a\\u0000c\"" },
		{ "a\\nb", "\"a\\nb\"" },
		{ "a\\\"b", "\"a\\\"b\"" },
		{ "a.b", "\"a.b\"" },
		{ "a", "\"a\"" },
		{ "", "\"\"" },
		{ "1234567890123456789012345678901é-tail",
		  "\"1234567890123456789012345678901\"..." },
		{ "1234567890123456789012345678901\\n-tail",
		  "\"1234567890123456789012345678901\\n\"..." },
	};
	static const char *const maps[] = {
		"identity.listen",
#if WITH_TLS
		"tls.psk",
#endif
	};
	for (size_t m = 0; m < ARRAY_SIZE(maps); m++) {
		for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
			char json[512], expected[256];
			(void)snprintf(
				json, sizeof(json),
				"{\"mux_listen\":\"127.0.0.1:9000\",\"%s\":{\"%s\":{\"%s\":123}}}",
				m == 0 ? "identity" : "tls",
				m == 0 ? "listen" : "psk", keys[i].json_key);
			(void)snprintf(
				expected, sizeof(expected),
				"%s[%s]: must be a string", maps[m],
				keys[i].rendered);
			struct conf_log_capture capture = { 0 };
			const int saved_level = slog_level_;
			slog_setlevel(LOG_LEVEL_ERROR);
			slog_setoutput(
				SLOG_OUTPUT_WRITER, capture_conf_log,
				(void *)&capture);
			struct config *const conf = parse_tmpconf(json);
			slog_setoutput(SLOG_OUTPUT_DISCARD);
			slog_setlevel(saved_level);
			retain_cleanup(_t_, cleanup_conf, conf);
			T_EXPECT(conf == NULL);
			T_LOGF("expected: %s; captured: %s", expected,
			       capture.text);
			T_EXPECT(strstr(capture.text, expected) != NULL);
			release_cleanup(_t_, cleanup_conf, conf);
		}
	}
}

T_DECLARE_CASE(test_conf_validation_diagnostics_escape_text)
{
	static const struct {
		const char *fields;
		const char *expected;
		bool accepted;
	} cases[] = {
#if WITH_TLS
		{ "\"tls\":{\"psk\":{\"peer\\nFORGED\\r\\u001b\\u007f\\u009b\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"second\":\"1111111111111111111111111111111111111111111111111111111111111111\"}}",
		  "using \"peer\\nFORGED\\r\\x1b\\x7f\\xc2\\x9b\"", true },
		{ "\"tls\":{\"psk\":{\"peer\\nFORGED\\u001b\":\"00\",\"peer\\nFORGED\\u001b\":\"00\"}}",
		  "duplicate entry for identity \"peer\\nFORGED\\x1b\"",
		  false },
		{ "\"tls\":{\"psk\":{\"peer\\nFORGED\\u001b\":\"00\"}}",
		  "tls.psk.peer\\nFORGED\\x1b: expected", false },
		{ "\"tls\":{\"psk\":{\"peer\\nFORGED\\u001b\":\"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg\"}}",
		  "tls.psk.peer\\nFORGED\\x1b: not a hex string", false },
		{ "\"tls\":{\"psk\":{\"peer\\nFORGED\\u001babcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop\":\"@key\"}}",
		  "tls.psk key \"peer\\nFORGED\\x1b", false },
#endif /* WITH_TLS */
		{ "\"type\":\"bad\\nFORGED\\r\\u001b\\u007f\\u009b\"",
		  "unsupported config type: \"bad\\nFORGED\\r\\x1b\\x7f\\xc2\\x9b\"",
		  false },
		{ "\"type\":\"application/x-multiplexd-config; broken\\n\\u001b\"",
		  "malformed config type:", false },
		{ "\"type\":\"application/x-multiplexd-config; version=\\\"\\u009bFORGED\\\"\"",
		  "unsupported config version: \"\\xc2\\x9bFORGED\"", false },
		{ "\"max_startups\":\"bad\\nFORGED\\r\\u001b\"",
		  "invalid max_startups format: \"bad\\nFORGED\\r\\x1b\"",
		  false },
		{ "\"identity\":{\"claim\":\"local\",\"listen\":{\"peer\\nFORGED\\u001babcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop\":\"127.0.0.1:9001\"}}",
		  "identity.listen key \"peer\\nFORGED\\x1b", false },
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		char json[1024];
		(void)snprintf(
			json, sizeof(json),
			"{\"mux_connect\":\"127.0.0.1:9000\",%s}",
			cases[i].fields);
		struct conf_log_capture capture = { 0 };
		const int saved_level = slog_level_;
		slog_setlevel(LOG_LEVEL_WARNING);
		slog_setoutput(
			SLOG_OUTPUT_WRITER, capture_conf_log, (void *)&capture);
		struct config *const conf = parse_tmpconf(json);
		slog_setoutput(SLOG_OUTPUT_DISCARD);
		slog_setlevel(saved_level);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_LOGF("case %zu: %s", i, capture.text);
		T_EXPECT((conf != NULL) == cases[i].accepted);
		T_EXPECT(strstr(capture.text, cases[i].expected) != NULL);
		T_EXPECT(!capture.unsafe);
		release_cleanup(_t_, cleanup_conf, conf);
	}

	/* The schema rejects an oversized listen value before conf_check can
	 * emit its fallback address-limit diagnostic. Its rejection stays inert. */
	char address[2048];
	memset(address, 'a', sizeof(address) - 1);
	address[sizeof(address) - 1] = '\0';
	char json[2304];
	(void)snprintf(
		json, sizeof(json),
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"local\",\"listen\":{\"peer\\nFORGED\\u001b\":\"%s\"}}}",
		address);
	struct conf_log_capture capture = { 0 };
	const int saved_level = slog_level_;
	slog_setlevel(LOG_LEVEL_WARNING);
	slog_setoutput(SLOG_OUTPUT_WRITER, capture_conf_log, (void *)&capture);
	struct config *const conf = parse_tmpconf(json);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
	slog_setlevel(saved_level);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
	T_EXPECT(
		strstr(capture.text, "failed to process configuration") !=
		NULL);
	T_EXPECT(!capture.unsafe);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_new_default_fields)
{
	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT(conf->type == NULL);
	/* Default timeouts are positive, including the derived inactivity timeout
	 * (conf_new_default must derive it just like conf_check does). */
	T_EXPECT(conf->mux.keepalive > 0);
	T_EXPECT(conf->mux.timeout > 0);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* conf_new_default() and a parsed minimal config must resolve the same
 * defaults: both run the shared conf_normalize(), so every (transport-
 * independent) normalized field agrees. A future default (e.g. a non-zero
 * mem_pressure.hi) applied by only one path would diverge here. A bare "{}"
 * cannot be used for the parse side because conf_check rejects a config with
 * no transport, so add just a mux_connect, which does not affect these fields. */
T_DECLARE_CASE(test_conf_new_default_matches_empty_parse)
{
	struct config *const a = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, a);
	T_CHECK(a != NULL);
	struct config *const b =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
	retain_cleanup(_t_, cleanup_conf, b);
	T_CHECK(b != NULL);
	T_EXPECT_EQ(a->mux.keepalive, b->mux.keepalive);
	T_EXPECT_EQ(a->mux.timeout, b->mux.timeout);
	T_EXPECT_EQ(a->mux.send_timeout, b->mux.send_timeout);
	T_EXPECT_EQ(a->mux.connect_timeout, b->mux.connect_timeout);
	T_EXPECT_EQ(a->mux.resume_timeout, b->mux.resume_timeout);
	T_EXPECT_EQ(a->mux.idle_timeout, b->mux.idle_timeout);
	T_EXPECT_EQ(a->loglevel, b->loglevel);
	T_EXPECT_EQ(a->mux.mem_pressure_hi, b->mux.mem_pressure_hi);
	T_EXPECT_EQ(a->mux.mem_pressure_lo, b->mux.mem_pressure_lo);
	T_EXPECT_EQ(a->mux.lossymux, b->mux.lossymux);
	T_EXPECT_EQ(a->mux.lossymux_idle_timeout, b->mux.lossymux_idle_timeout);
	T_EXPECT_EQ(a->mux.lossymux_queue, b->mux.lossymux_queue);
	release_cleanup(_t_, cleanup_conf, b);
	release_cleanup(_t_, cleanup_conf, a);
}

T_DECLARE_CASE(test_conf_presence_preserves_empty_strings_and_nested_defaults)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"\"},"
		"\"tls\":{\"sni\":\"\"},\"mux\":{\"tcp\":{\"keepalive\":true}}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_CHECK(conf->identity.claim != NULL);
	T_EXPECT_STREQ(conf->identity.claim, "");
#if WITH_TLS
	T_CHECK(conf->tls_sni != NULL);
	T_EXPECT_STREQ(conf->tls_sni, "");
#endif
	T_EXPECT(conf->mux_tcp.tcp_keepalive);
	T_EXPECT_EQ(conf->mux_tcp.backlog, 16);
	T_EXPECT_EQ(conf->mux.keepalive, 7200);
	T_EXPECT(conf->mux.nodelay);
	T_EXPECT(conf->api_listen == NULL);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* mux.lossymux defaults to disabled with the schema's idle timeout and queue,
 * the same values the mux layer's fallback config carries for hand-built
 * configs. */
T_DECLARE_CASE(test_conf_lossymux_defaults)
{
	struct config *const conf =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT(!conf->mux.lossymux);
	T_EXPECT(!conf_get_mux(conf).lossymux);
	T_EXPECT_EQ(
		conf->mux.lossymux_idle_timeout,
		mux_session_config_default.lossymux_idle_timeout);
	T_EXPECT_EQ(
		conf->mux.lossymux_queue,
		mux_session_config_default.lossymux_queue);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* An explicit mux.lossymux is loaded into the session config and survives a
 * dump/reparse round trip (GET /config, --dump-config). */
T_DECLARE_CASE(test_conf_lossymux_parse_and_roundtrip)
{
	struct config *const orig = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"lossymux\":"
		"{\"enabled\":true,\"idle_timeout\":5,\"queue\":300}}}");
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	T_EXPECT(orig->mux.lossymux);
	T_EXPECT(conf_get_mux(orig).lossymux);
	T_EXPECT_EQ(orig->mux.lossymux_idle_timeout, 5);
	T_EXPECT_EQ(orig->mux.lossymux_queue, 300);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_lossymux_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));
	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT(reparsed->mux.lossymux);
	T_EXPECT_EQ(reparsed->mux.lossymux_idle_timeout, 5);
	T_EXPECT_EQ(reparsed->mux.lossymux_queue, 300);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

/* The schema bounds reject a zero (or oversized) idle timeout or queue, and
 * a non-object mux.lossymux. */
T_DECLARE_CASE(test_conf_lossymux_rejects_out_of_range)
{
	static const char *const bad[] = {
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"lossymux\":"
		"{\"idle_timeout\":0}}}",
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"lossymux\":"
		"{\"idle_timeout\":86401}}}",
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"lossymux\":"
		"{\"queue\":0}}}",
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"lossymux\":"
		"{\"queue\":65536}}}",
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"lossymux\":true}}",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		struct config *const conf = parse_tmpconf(bad[i]);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf == NULL);
		release_cleanup(_t_, cleanup_conf, conf);
	}
}

/* conf_parse() must honor len and not rely on a NUL terminator: a PUT /config
 * body is followed by whatever else sits in the receive buffer. The byte
 * after the JSON here is trailing garbage the parser would reject if it read
 * past len. */
T_DECLARE_CASE(test_conf_parse_honors_len_without_nul)
{
	char buf[] = "{\"mux_connect\":\"127.0.0.1:9000\"}X";
	struct config *const conf = conf_parse(buf, sizeof(buf) - 2);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	release_cleanup(_t_, cleanup_conf, conf);
}

/* Fill buf[0, len) with a valid config padded by trailing whitespace. */
static void fill_padded_conf(char *restrict buf, const size_t len)
{
	static const char json[] = "{\"mux_connect\":\"127.0.0.1:9000\"}";
	memset(buf, ' ', len);
	memcpy(buf, json, sizeof(json) - 1);
}

/* conf_parse() applies CONF_MAXSIZE itself, independently of the file reader:
 * a valid config padded to exactly CONF_MAXSIZE bytes parses, and the same
 * config padded one byte further is rejected. */
T_DECLARE_CASE(test_conf_parse_rejects_oversized_buffer)
{
	char *const buf = malloc(CONF_MAXSIZE + 1);
	retain_cleanup(_t_, free, buf);
	T_CHECK(buf != NULL);
	fill_padded_conf(buf, CONF_MAXSIZE);
	struct config *const conf = conf_parse(buf, CONF_MAXSIZE);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf != NULL);
	release_cleanup(_t_, cleanup_conf, conf);
	fill_padded_conf(buf, CONF_MAXSIZE + 1);
	struct config *const oversized = conf_parse(buf, CONF_MAXSIZE + 1);
	retain_cleanup(_t_, cleanup_conf, oversized);
	T_EXPECT(oversized == NULL);
	release_cleanup(_t_, free, buf);
}

T_DECLARE_CASE(test_conf_parsefile_nonexistent)
{
	struct config *const conf =
		conf_parsefile("/nonexistent/path/that/cannot/exist.json");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_json)
{
	struct config *const conf = parse_tmpconf("{bad json");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* The shared JSON string decoder must reject malformed UTF-8 in the
 * unescaped byte-copy path, not just within \uXXXX escapes. 0xC2 ('\xc2')
 * is a valid two-byte lead requiring a continuation byte in 0x80-0xBF;
 * '(' (0x28) is not one, so this is a classic invalid sequence.
 * identity.claim is freeform (no format/pattern beyond maxLength), so a
 * rejection here can only be the UTF-8 check, not some other field rule. */
T_DECLARE_CASE(test_conf_parsefile_rejects_invalid_utf8)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"\xc2(\"}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Well-formed multi-byte UTF-8 (2/3/4-byte sequences) must still decode. */
T_DECLARE_CASE(test_conf_parsefile_accepts_well_formed_utf8)
{
	/* U+00E9 (e-acute, 2 bytes), U+4E2D (CJK "middle", 3 bytes),
	 * U+1F600 (grinning face, 4 bytes). */
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":"
		"\"\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80\"}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(
		conf->identity.claim, "\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_minimal_client)
{
	struct config *const conf =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_CHECK(conf->mux_connect != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	T_EXPECT(conf->mux_listen == NULL);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_minimal_server)
{
	struct config *const conf =
		parse_tmpconf("{\"mux_listen\":\"127.0.0.1:9000\"}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_CHECK(conf->mux_listen != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	T_EXPECT(conf->mux_connect == NULL);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_dump_roundtrip)
{
	struct config *const orig = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	orig->mux_connect = strdup("127.0.0.1:7777");
	T_CHECK(orig->mux_connect != NULL);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_CHECK(reparsed->mux_connect != NULL);
	T_EXPECT_STREQ(reparsed->mux_connect, "127.0.0.1:7777");
	/* Unset optional fields must stay absent through a dump/reparse. */
	T_EXPECT(reparsed->mux_listen == NULL);
	T_EXPECT(reparsed->listen == NULL);
	T_EXPECT(reparsed->connect == NULL);
	T_EXPECT(reparsed->api_listen == NULL);
	T_EXPECT(reparsed->identity.claim == NULL);
	T_EXPECT_EQ(reparsed->identity.mux_connect_count, (size_t)0);
#if WITH_TLS
	T_EXPECT(reparsed->tls_cert == NULL);
	T_EXPECT(reparsed->tls_key == NULL);
	T_EXPECT_EQ(reparsed->tls_authcerts_count, (size_t)0);
#endif
	/* type defaults to CONF_TYPE in conf_dump when unset */
	T_EXPECT(reparsed->type != NULL);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

/* mux.max_frame_size is stored internally as max_frame_payload (the wire size
 * minus the 8-byte header) on load and re-added on dump; the two conversions
 * must stay exact inverses, or --dump-config / GET /config would report a
 * different frame size than is actually in effect.  A non-default 32768 is used
 * so the assertion fails on a dropped conversion rather than matching the
 * 16384 default regardless of parsing. */
T_DECLARE_CASE(test_conf_parsefile_mux_max_frame_size_roundtrip)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\","
		"\"mux\":{\"max_frame_size\":32768}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(
		conf->mux.max_frame_payload,
		(int)(32768 - MUX_FRAME_HEADER_SIZE));

	/* Dump and reparse: the re-added header must reproduce the same payload. */
	char tmpl[] = CONF_TEST_TMPDIR "/conf_maxframe_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(conf, tmpl));
	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ(
		reparsed->mux.max_frame_payload, conf->mux.max_frame_payload);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_identity_connect_count)
{
	/* Identity-client mode: mux_connect lists destinations; claim is
	 * required alongside mux_connect. */
	struct config *const conf = parse_tmpconf(
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\",\"127.0.0.1:9002\"]}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.mux_connect_count, 2);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_identity_verify_defaults_false)
{
	struct config *const conf =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT(!conf->identity.verify);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* identity.verify has nothing to check without a peer certificate, so it is a
 * hard error rather than being silently ignored -- in a plaintext
 * configuration under WITH_TLS, and in any configuration without it. */
T_DECLARE_CASE(test_conf_identity_verify_requires_tls)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"verify\":true}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_psk_disabled_entries_select_plaintext)
{
	static const char *const accepted[] = {
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{\"-disabled-peer\":\"not-used\"}}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{\"-first\":null,\"-second\":123,\"-third\":{}}}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{\"\\u002dpeer\":false}}}",
	};
	for (size_t i = 0; i < ARRAY_SIZE(accepted); i++) {
		struct config *const conf = parse_tmpconf(accepted[i]);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_CHECK(conf != NULL);
#if WITH_TLS
		T_EXPECT_EQ(conf->tls_psk_count, (size_t)0);
#endif
		release_cleanup(_t_, cleanup_conf, conf);
	}
}

#if !WITH_TLS
/* Nothing loads the tls object in this build, so a credential in it would
 * otherwise start the daemon in cleartext with no diagnostic: each one is a
 * hard error, while a key that selects no TLS (a tuning knob, an empty psk
 * object) stays inert exactly as in a credential-less TLS build. */
T_DECLARE_CASE(test_conf_no_tls_rejects_credentials)
{
	static const char *const rejected[] = {
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"system_trust\":true}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"@c.pem\",\"key\":\"@k.pem\",\"authcerts\":[\"@a.pem\"]}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"\"}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"key\":\"@k.pem\"}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"authcerts\":[\"@a.pem\"]}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{\"peer\":\"@p.key\"}}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":\"@p.key\"}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{\"-disabled\":null,\"peer\":\"@p.key\"}}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{\"peer\":\"@p.key\",\"-disabled\":null}}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{\"-disabled\":null,\"\":\"@p.key\"}}}",
	};
	for (size_t i = 0; i < ARRAY_SIZE(rejected); i++) {
		struct config *const conf = parse_tmpconf(rejected[i]);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf == NULL);
		release_cleanup(_t_, cleanup_conf, conf);
	}

	static const char *const accepted[] = {
		"{\"mux_listen\":\"127.0.0.1:9000\"}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"sni\":\"example.com\",\"socket_offload\":true}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{ }}}",
	};
	for (size_t i = 0; i < ARRAY_SIZE(accepted); i++) {
		struct config *const conf = parse_tmpconf(accepted[i]);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf != NULL);
		release_cleanup(_t_, cleanup_conf, conf);
	}
}
#endif /* !WITH_TLS */

T_DECLARE_CASE(test_conf_loglevel_parsed)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"loglevel\":3}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->loglevel, 3);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_requires_transport)
{
	struct config *const conf = parse_tmpconf("{}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_requires_claim_for_identity)
{
	struct config *const conf = parse_tmpconf(
		"{\"identity\":{\"mux_connect\":[\"127.0.0.1:9001\"]}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* The claim-required check has two disjuncts; the sibling above covers
 * identity.mux_connect. This covers the identity.listen (peers_count > 0)
 * disjunct: a transport is present but the claim is missing, so it must be
 * rejected -- with a positive control confirming the missing claim is the
 * specific cause. */
T_DECLARE_CASE(test_conf_parsefile_requires_claim_for_identity_listen)
{
	struct config *const rejected = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"identity\":{\"listen\":{\"peer1\":\"127.0.0.1:9002\"}}}");
	retain_cleanup(_t_, cleanup_conf, rejected);
	T_EXPECT(rejected == NULL);

	struct config *const accepted = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":{\"peer1\":\"127.0.0.1:9002\"}}}");
	retain_cleanup(_t_, cleanup_conf, accepted);
	T_CHECK(accepted != NULL);
	release_cleanup(_t_, cleanup_conf, accepted);
}

/* mux_listen and mux_connect together are legal and both take effect: the
 * daemon accepts inbound sessions and maintains the outbound one.  Asserting
 * mux_connect survives conf_check is the point -- nothing clears it, and
 * server_ensure_mux_tunnel dials it regardless of mux_listen. */
T_DECLARE_CASE(test_conf_parsefile_accepts_mux_listen_and_mux_connect)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"mux_connect\":\"127.0.0.1:9001\"}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9001");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_accepts_max_length_identity_claim)
{
	/* MUX_MAX_CLAIM_LEN bounds what this implementation claims (mux.h); the
	 * boundary value itself must still load. */
	char claim[MUX_MAX_CLAIM_LEN + 1];
	memset(claim, 'a', sizeof(claim) - 1);
	claim[sizeof(claim) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"%s\",\"mux_connect\":[\"127.0.0.1:9001\"]}}",
		claim);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)strlen(conf->identity.claim), (int)MUX_MAX_CLAIM_LEN);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_identity_claim)
{
	/* One octet past MUX_MAX_CLAIM_LEN must be rejected at load/reload time
	 * instead of being silently dropped later, deep in the handshake --
	 * where an escape-heavy claim outgrows the frame and the hello could
	 * never be built, reconnecting forever. */
	char claim[MUX_MAX_CLAIM_LEN + 2];
	memset(claim, 'a', sizeof(claim) - 1);
	claim[sizeof(claim) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"%s\",\"mux_connect\":[\"127.0.0.1:9001\"]}}",
		claim);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_accepts_max_length_listen_address)
{
	/* shim/util.h's ADDR_MAX_STRLEN (255-octet FQDN + ":65535") caps a valid
	 * address at 261 octets; the boundary value itself must still load. */
	char addr[262];
	memset(addr, 'a', sizeof(addr) - 1);
	addr[sizeof(addr) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"mux_connect\":\"127.0.0.1:9000\",\"listen\":\"%s\"}", addr);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)strlen(conf->listen), 261);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_listen_address)
{
	/* One octet past the schema's 261-octet maxLength must be rejected
	 * at parse time instead of only failing later in resolve_bindaddr
	 * (shim/util.h's ADDR_MAX_STRLEN). */
	char addr[263];
	memset(addr, 'a', sizeof(addr) - 1);
	addr[sizeof(addr) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"mux_connect\":\"127.0.0.1:9000\",\"listen\":\"%s\"}", addr);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_parses_identity_listen)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\",\"peer2\":\"127.0.0.1:9003\"}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.mux_connect_count, 1);
	T_EXPECT_EQ((int)conf->identity.peers_count, 2);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9002");
	T_CHECK(find_peer(conf, "peer2") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer2")->listen, "127.0.0.1:9003");
	release_cleanup(_t_, cleanup_conf, conf);
}

/* The map codec's comma separator between identity.listen entries fires
 * only when a config carries two or more listen peers; a dump/reparse round-trip
 * of a two-peer config exercises it (a dropped comma emits invalid JSON that
 * fails to reparse). */
T_DECLARE_CASE(test_conf_dump_identity_listen_multi_peer_roundtrip)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\",\"peer2\":\"127.0.0.1:9003\"}}}";
	struct config *const orig = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	T_CHECK((int)orig->identity.peers_count == 2);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_listen_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));
	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->identity.peers_count, 2);
	T_CHECK(find_peer(reparsed, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "peer1")->listen, "127.0.0.1:9002");
	T_CHECK(find_peer(reparsed, "peer2") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "peer2")->listen, "127.0.0.1:9003");

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

T_DECLARE_CASE(test_conf_parsefile_identity_listen_duplicate_key_last_wins)
{
	/* identity_listen_add reuses the existing peer entry on a duplicate
	 * id instead of appending a second one, matching every other field's
	 * last-value-wins semantics. */
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\",\"peer1\":\"127.0.0.1:9004\"}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.peers_count, 1);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9004");
	release_cleanup(_t_, cleanup_conf, conf);
}

/* Parsing many identity.listen peers must grow peers[] correctly across several
 * geometric reallocations (cap 0->4->8->16); every distinct peer must survive
 * with its own value. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_many_peers)
{
	enum { NPEERS = 10 };
	char json[1024];
	int off = snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"mynode\","
		"\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{");
	for (int i = 0; i < NPEERS; i++) {
		off += snprintf(
			json + off, sizeof(json) - (size_t)off,
			"%s\"peer%d\":\"127.0.0.1:%d\"", i == 0 ? "" : ",", i,
			9100 + i);
	}
	(void)snprintf(json + off, sizeof(json) - (size_t)off, "}}}");

	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.peers_count, NPEERS);
	for (int i = 0; i < NPEERS; i++) {
		char id[16], addr[24];
		(void)snprintf(id, sizeof(id), "peer%d", i);
		(void)snprintf(addr, sizeof(addr), "127.0.0.1:%d", 9100 + i);
		const struct identity_peer *const p = find_peer(conf, id);
		T_CHECK(p != NULL);
		T_EXPECT_STREQ(p->listen, addr);
	}
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_identity_listen_value)
{
	/* The codec rejects an oversized identity.listen value before it
	 * reaches address resolution in server.c. */
	char addr[263];
	memset(addr, 'a', sizeof(addr) - 1);
	addr[sizeof(addr) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"%s\"}}}",
		addr);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Build an identity.listen config whose single key is @p key_len octets. */
T_DECLARE_SUBCASE(
	identity_listen_key_json, char *restrict json, const size_t json_size,
	const size_t key_len)
{
	char key[MUX_MAX_CLAIM_LEN + 2];
	T_EXPECT(key_len < sizeof(key));
	memset(key, 'k', key_len);
	key[key_len] = '\0';
	const int n = snprintf(
		json, json_size,
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"%s\":\"127.0.0.1:9002\"}}}",
		key);
	T_EXPECT(n > 0 && (size_t)n < json_size);
}

/* identity.listen keys are peer identity strings, and no peer claims more than
 * MUX_MAX_CLAIM_LEN octets; a longer key can never match a connecting peer, so
 * conf_check must reject it (the map keys bypass the schema's generated
 * per-field checks).  The boundary value itself must still load. */
T_DECLARE_CASE(test_conf_parsefile_accepts_max_length_identity_listen_key)
{
	char json[512];
	T_CALL_SUBCASE(
		identity_listen_key_json, json, sizeof(json),
		MUX_MAX_CLAIM_LEN);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_CHECK(conf->identity.peers_count == 1);
	T_EXPECT_EQ(
		(int)conf->identity.peers[0].id_len, (int)MUX_MAX_CLAIM_LEN);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_identity_listen_key)
{
	char json[512];
	T_CALL_SUBCASE(
		identity_listen_key_json, json, sizeof(json),
		MUX_MAX_CLAIM_LEN + 1);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_identity_mux_connect)
{
	/* identity.mux_connect is a plain array_string field, so the schema's
	 * generated per-element check must reject an oversized entry, unlike
	 * identity.listen's map values above (which need conf_check's own
	 * check instead). */
	char addr[263];
	memset(addr, 'a', sizeof(addr) - 1);
	addr[sizeof(addr) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"%s\"]}}",
		addr);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Both empty and populated maps are otherwise valid with a transport. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_valid_map_control)
{
	const char *const json[] = {
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":{}}}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":{\"peer1\":\"127.0.0.1:9002\"}}}",
	};
	for (size_t i = 0; i < ARRAY_SIZE(json); i++) {
		struct config *const conf = parse_tmpconf(json[i]);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_CHECK(conf != NULL);
		T_EXPECT_EQ(conf->identity.peers_count, i);
		if (i != 0) {
			T_CHECK(find_peer(conf, "peer1") != NULL);
			T_EXPECT_STREQ(
				find_peer(conf, "peer1")->listen,
				"127.0.0.1:9002");
		}
		release_cleanup(_t_, cleanup_conf, conf);
	}
}

/* The generated typed map rejects values that are not objects. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_non_object)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":\"not-an-object\"}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* A map key without a value must be rejected by the codec. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_malformed_json)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":{\"peer1\"}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Filtering a disabled key bypasses its value's type checks, but still
 * requires well-formed JSON, including matching brackets. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_bracket_mismatch)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":{\"-old\":[{], \"ok\":\"1.2.3.4:1\"}}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* The map filter skips disabled entries before they reach the config. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_skips_comment_key)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"-disabled\":\"127.0.0.1:9099\",\"peer1\":\"127.0.0.1:9002\"}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.peers_count, 1);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9002");
	T_EXPECT(find_peer(conf, "-disabled") == NULL);
	T_EXPECT(find_peer(conf, "disabled") == NULL);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_non_string_value)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":{\"peer1\":123}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* A JSON \u0000 escape is legal and decodes to a literal
 * embedded NUL with a correct .len, but strndup() (used to materialize
 * every config string) stops at the first NUL regardless of .len -- so a
 * claim like "abc\u0000<50 more>" would silently truncate to "abc" after
 * passing the full-length maxLength check, letting the MUX_MAX_CLAIM_LEN
 * limit validate content that is never what actually gets stored or sent.
 * conf_strndup() must reject this outright instead of truncating. */
T_DECLARE_CASE(test_conf_parsefile_rejects_embedded_nul_in_identity_claim)
{
	const char *json =
		"{\"identity\":{\"claim\":\"abc\\u0000def\",\"mux_connect\":[\"127.0.0.1:9001\"]}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Two identity.listen keys differing only after an embedded NUL must not
 * be silently merged into the same peer entry by a truncating strndup();
 * the whole config must be rejected instead. */
T_DECLARE_CASE(test_conf_parsefile_rejects_embedded_nul_in_identity_listen_key)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer\\u0000a\":\"127.0.0.1:9002\"}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* The same hazard applies to an identity.listen *value* -- the fourth
 * conf_strndup call site (identity_listen_cb's p->listen), distinct from the
 * key-side call above -- so a value with an embedded NUL must be rejected too. */
T_DECLARE_CASE(test_conf_parsefile_rejects_embedded_nul_in_identity_listen_value)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer\":\"127.0.0.1\\u00009002\"}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* The same hazard applies to every strndup'd config string, not just the
 * identity fields -- covers the shared STRNDUP_FIELD macro path
 * (conf_load), distinct from the identity-specific call sites above.
 * mux_connect is freeform at parse time (address resolution is deferred to
 * connect time, not done during conf parsing), unlike log which is
 * enum-constrained and would reject this value for an unrelated reason. */
T_DECLARE_CASE(test_conf_parsefile_rejects_embedded_nul_in_mux_connect_field)
{
	const char *json = "{\"mux_connect\":\"127.0.0.1\\u00009000\"}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_format)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:20\"}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* The schema documents max_startups as strictly "^[0-9]+:[0-9]+:[0-9]+$",
 * but strtoumax() alone also accepts a leading sign or whitespace; each
 * of these forms must be rejected, not silently parsed via strtoumax()'s
 * laxer rules. */
T_DECLARE_CASE(test_conf_parsefile_max_startups_rejects_non_strict_digits)
{
	static const char *const bad[] = {
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"+10:20:30\"}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\" 10:20:30\"}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:-0:30\"}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:20:-0\"}",
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		struct config *const conf = parse_tmpconf(bad[i]);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf == NULL);
		if (conf != NULL) {
			release_cleanup(_t_, cleanup_conf, conf);
		}
	}
}

T_DECLARE_CASE(test_conf_max_startups_rejects_embedded_nul)
{
	static const char *const bad[] = {
		"0:0:0\\u0000junk", "10:20:30\\u0000junk", "10:20:30\\u0000",
		"\\u000010:20:30",  "10:20\\u0000:30",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		char json[128];
		(void)snprintf(
			json, sizeof(json),
			"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"%s\"}",
			bad[i]);
		/* Exercise both the length-delimited API used by PUT /config and
		 * the file loader; conf_parse mutates its input buffer. */
		struct config *const from_file = parse_tmpconf(json);
		retain_cleanup(_t_, cleanup_conf, from_file);
		const bool file_rejected = from_file == NULL;
		release_cleanup(_t_, cleanup_conf, from_file);
		struct config *const from_buffer =
			conf_parse(json, strlen(json));
		retain_cleanup(_t_, cleanup_conf, from_buffer);
		const bool buffer_rejected = from_buffer == NULL;
		release_cleanup(_t_, cleanup_conf, from_buffer);
		T_LOGF("max_startups=%s", bad[i]);
		T_EXPECT(file_rejected);
		T_EXPECT(buffer_rejected);
	}
}

/* parse_startups_field stores into int startup_limit_* fields, so it rejects
 * anything above INT_MAX. The cases above cover format, non-strict digits, rate
 * and ordering, but never a value past that bound -- the disjunct guarding the
 * narrowing was unverified. The first two also drive strtoumax's ERANGE path
 * (a value past UINTMAX_MAX), the third the plain v > INT_MAX comparison. */
T_DECLARE_CASE(test_conf_parsefile_max_startups_rejects_overflow)
{
	static const char *const bad[] = {
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"99999999999999999999999999:1:2\"}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"1:99999999999999999999999999:2\"}",
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"9999999999:1:2\"}",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		struct config *const conf = parse_tmpconf(bad[i]);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf == NULL);
		if (conf != NULL) {
			release_cleanup(_t_, cleanup_conf, conf);
		}
	}
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_rate)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:101:20\"}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_range)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:20:10\"}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_clamps_timeout_fields)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"keepalive\":5,\"send_timeout\":30,\"connect_timeout\":40,\"resume_timeout\":1,\"idle_timeout\":2},\"loglevel\":999}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);

	T_EXPECT_EQ(conf->mux.keepalive, 10); /* 5 → clamped up to floor 10 */
	/* timeout derives from keepalive: 10 + max(10/10, 90) = 100. */
	T_EXPECT_EQ(conf->mux.timeout, 100);
	T_EXPECT_EQ(conf->mux.send_timeout, 30); /* independent [10,86400] */
	T_EXPECT_EQ(conf->mux.connect_timeout, 40); /* independent [10,86400] */
	T_EXPECT_EQ(
		conf->mux.resume_timeout, 10); /* 1 → clamped up to floor 10 */
	T_EXPECT_EQ(conf->mux.idle_timeout, 10);
	T_EXPECT_EQ(conf->loglevel, LOG_LEVEL_VERYVERBOSE);
	T_EXPECT(conf_get_mux(conf).reject_inbound);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* connect_timeout/resume_timeout must preserve an explicit 0
 * (schema-legal: both have "minimum": 0) as "disabled", matching
 * send_timeout/idle_timeout's existing behavior, instead of silently
 * clamping it up to the floor of 10. */
T_DECLARE_CASE(test_conf_parsefile_preserves_zero_connect_resume_timeout)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"connect_timeout\":0,\"resume_timeout\":0}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);

	T_EXPECT_EQ(conf->mux.connect_timeout, 0);
	T_EXPECT_EQ(conf->mux.resume_timeout, 0);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_clamps_int_overflow_fields)
{
	/* A value past INT_MAX must clamp, not wrap negative: every use site
	 * gates a resource-exhaustion check behind "value > 0". */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\","
		"\"max_sessions\":9999999999,"
		"\"mux\":{\"max_streams\":9999999999,"
		"\"mem_pressure\":{\"hi\":9999999999,\"lo\":9999999999}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->max_sessions, INT_MAX);
	T_EXPECT_EQ(conf->mux.max_streams, INT_MAX);
	T_EXPECT_EQ(conf->mux.mem_pressure_hi, INT_MAX);
	T_EXPECT_EQ(conf->mux.mem_pressure_lo, INT_MAX);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_partial_window_config_accepted)
{
	/* stream_window set (manual), session_window absent (auto); each axis
	 * is independent so the mixed configuration is accepted as-is.
	 * 32768/16384=2 frames, clamped to the minimum of 4. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"stream_window\":32768}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.stream_window, 4);
	T_EXPECT_EQ(conf->mux.session_window, 0);
	release_cleanup(_t_, cleanup_conf, conf);
}

#if WITH_TLS
T_DECLARE_CASE(test_conf_erase_credentials_all_buffers)
{
	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	conf->tls_cert = strdup("certificate");
	conf->tls_key = strdup("private-key-with-a-longer-tail");
	conf->tls_authcerts = (char **)calloc(3, sizeof(*conf->tls_authcerts));
	conf->tls_psk = calloc(3, sizeof(*conf->tls_psk));
	T_CHECK(conf->tls_authcerts != NULL && conf->tls_psk != NULL);
	conf->tls_authcerts_count = 3;
	conf->tls_psk_count = 3;
	conf->tls_psk_cap = 3;
	conf->tls_authcerts[0] = strdup("trust-anchor-a");
	conf->tls_authcerts[2] = strdup("trust-anchor-b-with-a-tail");
	conf->tls_authcerts_bundle = strdup("trust-anchor-a\ntrust-anchor-b\n");
	conf->tls_psk[0].id = strdup("first-peer");
	conf->tls_psk[0].id_len = 10;
	conf->tls_psk[0].hex = strdup("0123456789abcdef");
	conf->tls_psk[2].id = strdup("last-peer");
	conf->tls_psk[2].id_len = 9;
	conf->tls_psk[2].hex = strdup("FEDCBA9876543210fedcba9876543210");
	T_CHECK(conf->tls_psk[0].id != NULL && conf->tls_psk[2].id != NULL);

	const char *const buffers[] = {
		conf->tls_cert,
		conf->tls_key,
		conf->tls_authcerts[0],
		conf->tls_authcerts[2],
		conf->tls_authcerts_bundle,
		conf->tls_psk[0].hex,
		conf->tls_psk[2].hex,
	};
	size_t lengths[ARRAY_SIZE(buffers)];
	for (size_t i = 0; i < ARRAY_SIZE(buffers); i++) {
		T_CHECK(buffers[i] != NULL);
		lengths[i] = strlen(buffers[i]);
	}

	/* Keep the original lengths: checking empty strings would miss a
	 * helper that clears only their first byte. Null array entries also
	 * exercise partial configuration cleanup. */
	for (size_t pass = 0; pass < 2; pass++) {
		conf_erase_credentials(conf);
		for (size_t i = 0; i < ARRAY_SIZE(buffers); i++) {
			T_LOGF("pass %zu, credential buffer %zu", pass, i);
			for (size_t j = 0; j <= lengths[i]; j++) {
				T_EXPECT_EQ(buffers[i][j], '\0');
			}
		}
		T_EXPECT_STREQ(conf->tls_psk[0].id, "first-peer");
		T_EXPECT_STREQ(conf->tls_psk[2].id, "last-peer");
	}
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_erase_credentials_absent_fields)
{
	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	conf_erase_credentials(conf);
	conf_erase_credentials(conf);
	T_EXPECT(conf->tls_cert == NULL);
	T_EXPECT(conf->tls_key == NULL);
	T_EXPECT(conf->tls_authcerts == NULL);
	T_EXPECT(conf->tls_authcerts_bundle == NULL);
	T_EXPECT(conf->tls_psk == NULL);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_partial_tls_config)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"dummy\"}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Retain an unexpectedly accepted configuration before the fatal expectation
 * transfers control back to the runner. */
T_DECLARE_SUBCASE(assert_conf_rejected, struct config *conf)
{
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Builds "{"mux_listen":..., "tls": <tls_json>}" and expects rejection. */
T_DECLARE_SUBCASE(assert_partial_tls_rejected, const char *restrict tls_json)
{
	char json[256];
	(void)snprintf(
		json, sizeof(json),
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":%s}", tls_json);
	T_CALL_SUBCASE(assert_conf_rejected, parse_tmpconf(json));
}

T_DECLARE_CASE(test_conf_system_trust_roundtrip)
{
	struct config *const defaults = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"cert\",\"key\":\"key\",\"authcerts\":[\"ca\"]}}");
	retain_cleanup(_t_, cleanup_conf, defaults);
	T_CHECK(defaults != NULL);
	T_EXPECT(!defaults->tls_system_trust);
	release_cleanup(_t_, cleanup_conf, defaults);
	for (int additive = 0; additive < 2; additive++) {
		char json[512];
		(void)snprintf(
			json, sizeof(json),
			"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"verify\":true},\"tls\":{\"cert\":\"cert\",\"key\":\"key\",\"system_trust\":true%s}}",
			additive ? ",\"authcerts\":[\"ca\"]" : "");
		struct config *const orig = parse_tmpconf(json);
		retain_cleanup(_t_, cleanup_conf, orig);
		T_CHECK(orig != NULL);
		T_EXPECT(orig->tls_system_trust);
		T_EXPECT_EQ(orig->tls_authcerts_count, (size_t)additive);
		size_t len;
		char *const dump = conf_dump(orig, &len, NULL);
		retain_cleanup(_t_, free, dump);
		T_CHECK(dump != NULL);
		struct config *const reparsed = conf_parse(dump, len);
		retain_cleanup(_t_, cleanup_conf, reparsed);
		T_CHECK(reparsed != NULL);
		T_EXPECT(reparsed->tls_system_trust);
		T_EXPECT(reparsed->identity.verify);
		T_EXPECT_EQ(reparsed->tls_authcerts_count, (size_t)additive);
		release_cleanup(_t_, cleanup_conf, reparsed);
		release_cleanup(_t_, free, dump);
		release_cleanup(_t_, cleanup_conf, orig);
	}
}

T_DECLARE_CASE(test_conf_system_trust_rejects_incomplete_or_psk)
{
	static const char *const tls[] = {
		"{\"system_trust\":true}",
		"{\"cert\":\"cert\",\"system_trust\":true}",
		"{\"key\":\"key\",\"system_trust\":true}",
		"{\"cert\":\"cert\",\"key\":\"key\",\"system_trust\":false}",
		"{\"cert\":\"cert\",\"key\":\"key\",\"system_trust\":\"true\"}",
		"{\"system_trust\":true,\"psk\":{\"peer\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}",
	};
	for (size_t i = 0; i < ARRAY_SIZE(tls); i++) {
		T_CALL_SUBCASE(assert_partial_tls_rejected, tls[i]);
	}
}

T_DECLARE_CASE(test_conf_parsefile_rejects_partial_tls_config_combinations)
{
	/* The remaining partial combinations among {cert, key, authcerts};
	 * cert-only is covered by test_conf_parsefile_rejects_partial_tls_config. */
	T_CALL_SUBCASE(assert_partial_tls_rejected, "{\"key\":\"dummy\"}");
	T_CALL_SUBCASE(
		assert_partial_tls_rejected, "{\"authcerts\":[\"dummy\"]}");
	T_CALL_SUBCASE(
		assert_partial_tls_rejected,
		"{\"cert\":\"dummy\",\"key\":\"dummy\"}");
	T_CALL_SUBCASE(
		assert_partial_tls_rejected,
		"{\"cert\":\"dummy\",\"authcerts\":[\"dummy\"]}");
	T_CALL_SUBCASE(
		assert_partial_tls_rejected,
		"{\"key\":\"dummy\",\"authcerts\":[\"dummy\"]}");
}

T_DECLARE_CASE(test_conf_parsefile_authcerts_array)
{
	/* Verify that the authcerts array is parsed and stored correctly. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"certdata\",\"key\":\"keydata\",\"authcerts\":[\"ca1.pem\",\"ca2.pem\"]}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_authcerts_count, 2);
	T_EXPECT_STREQ(conf->tls_authcerts[0], "ca1.pem");
	T_EXPECT_STREQ(conf->tls_authcerts[1], "ca2.pem");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_dump_tls_fields)
{
	/* dump/parse round-trip for tls.cert, tls.key, tls.authcerts,
	 * socket_offload, and kernel_offload; both booleans set to true so
	 * a failed serialization would reparse as false. */
	struct config *const orig = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	orig->mux_connect = strdup("127.0.0.1:7777");
	orig->tls_cert = strdup("certdata");
	orig->tls_key = strdup("keydata");
	orig->tls_authcerts = (char **)malloc(sizeof(char *));
	T_CHECK(orig->tls_authcerts != NULL);
	orig->tls_authcerts[0] = strdup("authcertdata");
	T_CHECK(orig->tls_authcerts[0] != NULL);
	orig->tls_authcerts_count = 1;
	orig->tls_socket_offload = true;
	orig->tls_kernel_offload = true;
	T_CHECK(orig->mux_connect != NULL);
	T_CHECK(orig->tls_cert != NULL);
	T_CHECK(orig->tls_key != NULL);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_tls_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_STREQ(reparsed->tls_cert, "certdata");
	T_EXPECT_STREQ(reparsed->tls_key, "keydata");
	T_EXPECT_EQ((int)reparsed->tls_authcerts_count, 1);
	T_EXPECT_STREQ(reparsed->tls_authcerts[0], "authcertdata");
	T_EXPECT(reparsed->tls_socket_offload);
	T_EXPECT(reparsed->tls_kernel_offload);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

T_DECLARE_CASE(test_conf_load_tls_kernel_offload_defaults_with_socket_offload)
{
	/* kernel_offload's schema default is true; with socket_offload also on
	 * (explicitly, here), the "requires socket_offload" clamp does not
	 * apply and the default takes effect. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"certdata\",\"key\":\"keydata\",\"authcerts\":[\"ca1.pem\"],\"socket_offload\":true}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT(conf->tls_socket_offload);
	T_EXPECT(conf->tls_kernel_offload);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_load_tls_kernel_offload_off_without_socket_offload)
{
	/* Neither field set: kernel_offload's own default is true, but
	 * socket_offload defaults false, so the "requires socket_offload"
	 * clamp silently forces kernel_offload back off -- the common case
	 * (most configs never mention either field) must not end up with KTLS
	 * "on" by accident. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"certdata\",\"key\":\"keydata\",\"authcerts\":[\"ca1.pem\"]}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT(!conf->tls_socket_offload);
	T_EXPECT(!conf->tls_kernel_offload);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_load_tls_kernel_offload_explicit_override)
{
	/* socket_offload on, kernel_offload explicitly disabled: the explicit
	 * `false` in the JSON must survive, not be overwritten back to the
	 * schema default of true. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"certdata\",\"key\":\"keydata\",\"authcerts\":[\"ca1.pem\"],\"socket_offload\":true,\"kernel_offload\":false}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT(conf->tls_socket_offload);
	T_EXPECT(!conf->tls_kernel_offload);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_inline_pem_replaces_at_path)
{
	/* conf_inline_pem must replace @path fields with the file's content. */
	char cert_tmpl[] = CONF_TEST_TMPDIR "/conf_inline_cert_XXXXXX";
	char key_tmpl[] = CONF_TEST_TMPDIR "/conf_inline_key_XXXXXX";
	T_CHECK(write_tmpfile(cert_tmpl, "CERTCONTENT") == 0);
	retain_path(_t_, cert_tmpl);
	T_CHECK(write_tmpfile(key_tmpl, "KEYCONTENT") == 0);
	retain_path(_t_, key_tmpl);

	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);

	char cert_at[256], key_at[256];
	(void)snprintf(cert_at, sizeof(cert_at), "@%s", cert_tmpl);
	(void)snprintf(key_at, sizeof(key_at), "@%s", key_tmpl);
	conf->tls_cert = strdup(cert_at);
	conf->tls_key = strdup(key_at);
	T_CHECK(conf->tls_cert != NULL);
	T_CHECK(conf->tls_key != NULL);

	T_EXPECT(conf_inline_pem(conf));
	T_EXPECT_STREQ(conf->tls_cert, "CERTCONTENT");
	T_EXPECT_STREQ(conf->tls_key, "KEYCONTENT");

	release_path(_t_, cert_tmpl);
	release_path(_t_, key_tmpl);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* conf_inline_pem must build the trusted-cert bundle by concatenating every
 * authcert (a mix of inline and @path entries) with a '\n' separator and exact
 * sizing -- exercising bundle_append's per-cert len+1 accounting, which the
 * @path replacement tests never touch. */
T_DECLARE_CASE(test_conf_inline_pem_concatenates_authcerts_bundle)
{
	char ca_tmpl[] = CONF_TEST_TMPDIR "/conf_inline_ca_XXXXXX";
	T_CHECK(write_tmpfile(ca_tmpl, "CA_FROM_FILE") == 0);
	retain_path(_t_, ca_tmpl);

	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);

	conf->tls_authcerts = (char **)malloc(3 * sizeof(char *));
	T_CHECK(conf->tls_authcerts != NULL);
	conf->tls_authcerts_count = 3;
	char ca_at[256];
	(void)snprintf(ca_at, sizeof(ca_at), "@%s", ca_tmpl);
	conf->tls_authcerts[0] = strdup("INLINE_CA_A");
	conf->tls_authcerts[1] = strdup(ca_at); /* @path -> file content */
	conf->tls_authcerts[2] = strdup("INLINE_CA_B");
	T_CHECK(conf->tls_authcerts[0] != NULL &&
		conf->tls_authcerts[1] != NULL &&
		conf->tls_authcerts[2] != NULL);

	T_EXPECT(conf_inline_pem(conf));
	/* @path entry is inlined, then all three are joined with '\n' and
	 * NUL-terminated. */
	T_EXPECT_STREQ(
		conf->tls_authcerts_bundle,
		"INLINE_CA_A\nCA_FROM_FILE\nINLINE_CA_B\n");

	release_path(_t_, ca_tmpl);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* File-backed credentials must obey the same text boundary as decoded JSON
 * strings. A valid hex prefix must not hide a NUL or the suffix after it. */
T_DECLARE_CASE(test_conf_inline_pem_rejects_embedded_nuls)
{
	static const size_t positions[] = { 64, 0, 128 };
	static const size_t fields[] = { 3, 0, 1, 2 };
	for (size_t f = 0; f < ARRAY_SIZE(fields); f++) {
		const size_t field = fields[f];
		for (size_t i = 0; i < ARRAY_SIZE(positions); i++) {
			char content[129];
			memset(content, 'a', 64);
			memset(content + 64, 'b', sizeof(content) - 64u);
			content[positions[i]] = '\0';
			char tmpl[] = CONF_TEST_TMPDIR "/conf_nul_XXXXXX";
			T_CHECK(write_tmpfile_len(
					tmpl, content, sizeof(content)) == 0);
			char reference[sizeof(tmpl) + 1u];
			(void)snprintf(
				reference, sizeof(reference), "@%s", tmpl);
			struct config *const conf = conf_new_default();
			retain_cleanup(_t_, cleanup_conf, conf);
			T_CHECK(conf != NULL);
			char **slot;
			if (field == 0) {
				slot = &conf->tls_cert;
			} else if (field == 1) {
				slot = &conf->tls_key;
			} else if (field == 2) {
				conf->tls_authcerts =
					(char **)calloc(1, sizeof(char *));
				T_CHECK(conf->tls_authcerts != NULL);
				conf->tls_authcerts_count = 1;
				slot = &conf->tls_authcerts[0];
			} else {
				conf->tls_psk =
					calloc(1, sizeof(struct psk_entry));
				T_CHECK(conf->tls_psk != NULL);
				conf->tls_psk_count = 1;
				conf->tls_psk[0].id = strdup("peer");
				T_CHECK(conf->tls_psk[0].id != NULL);
				conf->tls_psk[0].id_len = 4;
				slot = &conf->tls_psk[0].hex;
			}
			*slot = strdup(reference);
			T_CHECK(*slot != NULL);
			const bool accepted = conf_inline_pem(conf);
			const bool retained_reference =
				strcmp(*slot, reference) == 0;
			release_cleanup(_t_, cleanup_conf, conf);
			release_path(_t_, tmpl);
			T_LOGF("credential field %zu, NUL at %zu", field,
			       positions[i]);
			T_EXPECT(!accepted);
			T_EXPECT(retained_reference);
		}
	}
}

T_DECLARE_CASE(test_conf_inline_pem_fails_for_missing_file)
{
	/* conf_inline_pem must return false if an @path file does not exist. */
	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	conf->tls_cert = strdup(
		"@" CONF_TEST_TMPDIR "/conf_inline_nonexistent_XXXXXX.pem");
	conf->tls_key = strdup("plaintext");
	T_CHECK(conf->tls_cert != NULL);
	T_CHECK(conf->tls_key != NULL);

	T_EXPECT(!conf_inline_pem(conf));
	release_cleanup(_t_, cleanup_conf, conf);
}

/* A 32-octet key as hex; the value itself is irrelevant to parsing. */
#define PSK_HEX                                                                \
	"\"0101010101010101010101010101010101010101010101010101010101010101\""

T_DECLARE_CASE(test_conf_psk_parsed_in_order)
{
	/* Document order decides which key a dialing node offers, so it must
	 * survive parsing rather than being reordered or deduped away. */
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"beta\":" PSK_HEX ",\"alpha\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_psk_count, 2);
	T_EXPECT_STREQ(conf->tls_psk[0].id, "beta");
	T_EXPECT_STREQ(conf->tls_psk[1].id, "alpha");
	release_cleanup(_t_, cleanup_conf, conf);
}

/* "" is a valid identity (spec 5.2.3.2 sets no lower bound, and identity.claim
 * accepts it), so it must be a usable tls.psk key rather than being conflated
 * with "no entry" -- the same trap 2d33aea fixed for certificates. */
T_DECLARE_CASE(test_conf_psk_empty_identity)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_psk_count, 1);
	T_EXPECT_STREQ(conf->tls_psk[0].id, "");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_psk_rejects_certificate_fields)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{"
		"\"cert\":\"c\",\"key\":\"k\",\"authcerts\":[\"a\"],"
		"\"psk\":{\"peer\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* PSK mode has no certificate for a server name to select, so tls.sni --
 * whether defaulted by the schema or set explicitly -- resolves to no SNI,
 * while certificate mode keeps its default. */
T_DECLARE_CASE(test_conf_psk_omits_sni)
{
	struct config *const dflt = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"peer\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, dflt);
	T_CHECK(dflt != NULL);
	T_EXPECT(dflt->tls_sni == NULL);
	release_cleanup(_t_, cleanup_conf, dflt);

	struct config *const set = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"tls\":{"
		"\"sni\":\"host.example\",\"psk\":{\"peer\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, set);
	T_CHECK(set != NULL);
	T_EXPECT(set->tls_sni == NULL);
	release_cleanup(_t_, cleanup_conf, set);

	struct config *const cert = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"tls\":{"
		"\"cert\":\"c\",\"key\":\"k\",\"authcerts\":[\"a\"]}}");
	retain_cleanup(_t_, cleanup_conf, cert);
	T_CHECK(cert != NULL);
	T_CHECK(cert->tls_sni != NULL);
	T_EXPECT_STREQ(cert->tls_sni, "example.com");
	release_cleanup(_t_, cleanup_conf, cert);
}

T_DECLARE_CASE(test_conf_psk_rejects_identity_verify)
{
	/* PSK binds identity through the binder, so the certificate-mode
	 * switch has nothing to enable and is refused rather than ignored. */
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\","
		"\"identity\":{\"claim\":\"me\",\"verify\":true},"
		"\"tls\":{\"psk\":{\"peer\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_psk_rejects_duplicate_identity)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"peer\":" PSK_HEX ",\"peer\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

/* Build a tls.psk config with one entry: identity @p id, value @p val (a key
 * or an "@path" reference). */
T_DECLARE_SUBCASE(
	psk_conf_json, char *restrict json, const size_t json_size,
	const char *restrict id, const char *restrict val)
{
	const int n = snprintf(
		json, json_size,
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"%s\":\"%s\"}}}",
		id, val);
	T_EXPECT(n > 0 && (size_t)n < json_size);
}

/* Fill @p hex with @p octets octets of key -- 2 * @p octets copies of the
 * digit @p c -- NUL-terminated. */
static void psk_hex_fill(char *restrict hex, const size_t octets, const char c)
{
	memset(hex, c, octets * 2u);
	hex[octets * 2u] = '\0';
}

#ifdef CONF_TEST_WRAP_ALLOC
static void reset_rejection_probe(void *data)
{
	(void)data;
	conf_free(rejection_probe_conf);
	rejection_probe_conf = NULL;
	rejection_probe_frees = 0;
}

T_DECLARE_CASE(conf_rejection_with_accepted_result)
{
	T_CALL_SUBCASE(assert_conf_rejected, rejection_probe_conf);
}

T_DECLARE_CASE(test_conf_rejection_cleanup_on_failed_expectation)
{
	T_CLEANUP(reset_rejection_probe, NULL);
	rejection_probe_conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\","
		"\"tls\":{\"psk\":{\"peer\":" PSK_HEX "}}}");
	T_CHECK(rejection_probe_conf != NULL);
	T_DECLARE_CTX(inner);
	T_RUN_CASE(inner, conf_rejection_with_accepted_result);
	T_EXPECT_EQ(inner.failed, 1);
	T_EXPECT_EQ(rejection_probe_frees, (size_t)1);
	T_EXPECT(rejection_probe_conf == NULL);
}
#endif /* CONF_TEST_WRAP_ALLOC */

/* An inline key is fully visible to conf_parse, so a malformed one must fail
 * the parse itself -- which is what makes PUT /config answer 400 rather than
 * accept the body and fail the reload later. */
T_DECLARE_CASE(test_conf_psk_rejects_bad_key)
{
	char hex[(TLS_PSK_MAX_LEN + 1u) * 2u + 2u];
	char json[512];

	/* Below TLS_PSK_MIN_LEN. */
	psk_hex_fill(hex, TLS_PSK_MIN_LEN - 1u, '0');
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", hex);
	T_CALL_SUBCASE(assert_conf_rejected, parse_tmpconf(json));

	/* Above TLS_PSK_MAX_LEN. */
	psk_hex_fill(hex, TLS_PSK_MAX_LEN + 1u, '0');
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", hex);
	T_CALL_SUBCASE(assert_conf_rejected, parse_tmpconf(json));

	/* Odd number of hex digits: half an octet. */
	psk_hex_fill(hex, TLS_PSK_MIN_LEN + 1u, '0');
	hex[strlen(hex) - 1u] = '\0';
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", hex);
	T_CALL_SUBCASE(assert_conf_rejected, parse_tmpconf(json));

	/* Right length, wrong alphabet. */
	psk_hex_fill(hex, TLS_PSK_MIN_LEN, 'z');
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", hex);
	T_CALL_SUBCASE(assert_conf_rejected, parse_tmpconf(json));
}

/* Both length bounds are inclusive. */
T_DECLARE_CASE(test_conf_psk_accepts_key_length_bounds)
{
	char hex[TLS_PSK_MAX_LEN * 2u + 1u];
	char json[512];
	const size_t bounds[] = { TLS_PSK_MIN_LEN, TLS_PSK_MAX_LEN };
	for (size_t i = 0; i < ARRAY_SIZE(bounds); i++) {
		psk_hex_fill(hex, bounds[i], '0');
		T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", hex);
		struct config *const conf = parse_tmpconf(json);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_CHECK(conf != NULL);
		T_EXPECT_STREQ(conf->tls_psk[0].hex, hex);
		T_EXPECT(conf_inline_pem(conf));
		release_cleanup(_t_, cleanup_conf, conf);
	}
}

/* Whitespace around an inline key is trimmed at parse, and every byte the key
 * vacates by shifting left over the leading whitespace is erased: the
 * strlen-based credential erase stops at the new terminator, so a key tail
 * left behind it would outlive the erase. */
T_DECLARE_CASE(test_conf_psk_trim_erases_vacated_tail)
{
	enum { LEAD = 3 };
	char hex[TLS_PSK_MIN_LEN * 2u + 1u];
	psk_hex_fill(hex, TLS_PSK_MIN_LEN, 'a');
	char val[sizeof(hex) + LEAD + 2u];
	(void)snprintf(val, sizeof(val), "%*s%s\\n", LEAD, "", hex);
	char json[512];
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", val);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	/* Resolving references must leave an inline key as parse left it. */
	T_EXPECT(conf_inline_pem(conf));
	const char *const got = conf->tls_psk[0].hex;
	T_EXPECT_STREQ(got, hex);
	/* The value was stored as a strndup of the JSON string ("   <hex>\n"), so
	 * its allocation extends LEAD + 1 bytes past the trimmed terminator. */
	const size_t len = strlen(hex);
	for (size_t i = len + 1u; i <= len + LEAD + 1u; i++) {
		T_EXPECT_EQ(got[i], '\0');
	}
	release_cleanup(_t_, cleanup_conf, conf);
}

/* A key file written by --genpsk ends with a newline; "@path" loads it
 * verbatim, and conf_inline_pem must trim it before the hex check. */
T_DECLARE_CASE(test_conf_psk_at_path_trims_trailing_newline)
{
	char hex[TLS_PSK_MIN_LEN * 2u + 2u];
	psk_hex_fill(hex, TLS_PSK_MIN_LEN, 'b');
	char key_tmpl[] = CONF_TEST_TMPDIR "/conf_psk_key_XXXXXX";
	char content[sizeof(hex) + 1u];
	(void)snprintf(content, sizeof(content), "%s\n", hex);
	T_CHECK(write_tmpfile(key_tmpl, content) == 0);
	retain_path(_t_, key_tmpl);
	char ref[sizeof(key_tmpl) + 1u];
	(void)snprintf(ref, sizeof(ref), "@%s", key_tmpl);
	char json[512];
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", ref);

	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	/* Still the reference: conf_parse cannot see the key yet. */
	T_EXPECT_STREQ(conf->tls_psk[0].hex, ref);
	const bool ok = conf_inline_pem(conf);
	release_path(_t_, key_tmpl);
	T_EXPECT(ok);
	T_EXPECT_STREQ(conf->tls_psk[0].hex, hex);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* A malformed key behind "@path" passes conf_parse, which sees only the
 * reference, and is rejected once conf_inline_pem loads it. */
T_DECLARE_CASE(test_conf_psk_preserves_uppercase_hex)
{
	char hex[TLS_PSK_MIN_LEN * 2u + 1u];
	psk_hex_fill(hex, TLS_PSK_MIN_LEN, 'A');
	char json[512];
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", hex);
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	const bool inline_preserved = strcmp(conf->tls_psk[0].hex, hex) == 0;
	release_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(inline_preserved);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_psk_upper_XXXXXX";
	T_CHECK(write_tmpfile(tmpl, hex) == 0);
	retain_path(_t_, tmpl);
	char reference[sizeof(tmpl) + 1u];
	(void)snprintf(reference, sizeof(reference), "@%s", tmpl);
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", reference);
	conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	const bool accepted = conf_inline_pem(conf);
	const bool preserved = strcmp(conf->tls_psk[0].hex, hex) == 0;
	release_cleanup(_t_, cleanup_conf, conf);
	release_path(_t_, tmpl);
	T_EXPECT(accepted);
	T_EXPECT(preserved);
}

T_DECLARE_CASE(test_conf_psk_at_path_rejects_bad_key)
{
	char key_tmpl[] = CONF_TEST_TMPDIR "/conf_psk_key_XXXXXX";
	T_CHECK(write_tmpfile(key_tmpl, "0101\n") == 0);
	retain_path(_t_, key_tmpl);
	char ref[sizeof(key_tmpl) + 1u];
	(void)snprintf(ref, sizeof(ref), "@%s", key_tmpl);
	char json[512];
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), "peer", ref);

	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	const bool ok = conf_inline_pem(conf);
	release_path(_t_, key_tmpl);
	T_EXPECT(!ok);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* tls.psk identities are peer identities, bounded like identity.listen keys:
 * MUX_MAX_CLAIM_LEN octets load, one more is rejected. */
T_DECLARE_CASE(test_conf_psk_identity_length_bound)
{
	char hex[TLS_PSK_MIN_LEN * 2u + 1u];
	psk_hex_fill(hex, TLS_PSK_MIN_LEN, '0');
	char id[MUX_MAX_CLAIM_LEN + 2u];
	char json[512];

	memset(id, 'i', MUX_MAX_CLAIM_LEN);
	id[MUX_MAX_CLAIM_LEN] = '\0';
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), id, hex);
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_psk[0].id_len, (int)MUX_MAX_CLAIM_LEN);
	release_cleanup(_t_, cleanup_conf, conf);

	memset(id, 'i', MUX_MAX_CLAIM_LEN + 1u);
	id[MUX_MAX_CLAIM_LEN + 1u] = '\0';
	T_CALL_SUBCASE(psk_conf_json, json, sizeof(json), id, hex);
	T_CALL_SUBCASE(assert_conf_rejected, parse_tmpconf(json));
}

/* Typed PSK maps reject non-objects, malformed JSON and non-string values;
 * the map filter skips disabled entries before value-type validation. */
T_DECLARE_CASE(test_conf_psk_rejects_non_object)
{
	T_CALL_SUBCASE(
		assert_conf_rejected,
		parse_tmpconf(
			"{\"mux_listen\":\"127.0.0.1:9000\","
			"\"tls\":{\"psk\":\"not-an-object\"}}"));
}

T_DECLARE_CASE(test_conf_psk_rejects_malformed_json)
{
	T_CALL_SUBCASE(
		assert_conf_rejected,
		parse_tmpconf(
			"{\"mux_listen\":\"127.0.0.1:9000\","
			"\"tls\":{\"psk\":{\"peer\"}}}"));
}

T_DECLARE_CASE(test_conf_psk_rejects_non_string_value)
{
	T_CALL_SUBCASE(
		assert_conf_rejected,
		parse_tmpconf(
			"{\"mux_listen\":\"127.0.0.1:9000\","
			"\"tls\":{\"psk\":{\"peer\":123}}}"));
}

T_DECLARE_CASE(test_conf_psk_skips_comment_key)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"-old\":123,\"peer\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_psk_count, 1);
	T_EXPECT_STREQ(conf->tls_psk[0].id, "peer");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_psk_dump_roundtrip)
{
	struct config *const orig = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"peer\":" PSK_HEX "}}}");
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_psk_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->tls_psk_count, 1);
	T_EXPECT_STREQ(reparsed->tls_psk[0].id, "peer");
	T_EXPECT_STREQ(reparsed->tls_psk[0].hex, orig->tls_psk[0].hex);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

/* With TLS credentials present, identity.verify is accepted and survives a
 * dump/parse round-trip, so GET /config and --dump-config report it. */
T_DECLARE_CASE(test_conf_identity_verify_with_tls_roundtrip)
{
	struct config *const orig = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\","
		"\"identity\":{\"claim\":\"mynode\",\"verify\":true},"
		"\"tls\":{\"cert\":\"c\",\"key\":\"k\",\"authcerts\":[\"a\"]}}");
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	T_EXPECT(orig->identity.verify);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_id_verify_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT(reparsed->identity.verify);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}
#endif /* WITH_TLS */

T_DECLARE_CASE(test_conf_parsefile_ignores_comment_keys)
{
	/* Keys prefixed with '-' are a comment-out convention: they must be
	 * silently skipped at any nesting level without causing a parse error
	 * or overwriting the default field values. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"-mux_connect\":\"should-be-ignored\",\"-loglevel\":0,\"mux\":{\"send_timeout\":30,\"-send_timeout\":999,\"-nodelay\":false},\"-tcp\":{\"nodelay\":false},\"identity\":{\"claim\":\"me\",\"-claim\":\"ignored\"}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	/* mux_connect must reflect the real key, not the commented-out one. */
	T_EXPECT(strcmp(conf->mux_connect, "127.0.0.1:9000") == 0);
	/* loglevel must stay at the default (not overwritten by -loglevel). */
	T_EXPECT_EQ(conf->loglevel, LOG_LEVEL_NOTICE);
	/* mux.send_timeout must be 30, not 999 from the commented key. */
	T_EXPECT_EQ(conf->mux.send_timeout, 30);
	/* mux.nodelay default is true; -nodelay:false must be ignored. */
	T_EXPECT(conf->mux.nodelay);
	/* identity.claim must be "me", not "ignored". */
	T_EXPECT(strcmp(conf->identity.claim, "me") == 0);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_unknown_root_key)
{
	/* Unknown keys at the root level must not fail parsing. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"nosuchkey\":\"value\"}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_unknown_mux_key)
{
	/* Unknown keys inside a scope must not fail parsing. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"nosuchfield\":1}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_mem_pressure_config)
{
	/* Verify that the mux.mem_pressure sub-object is parsed correctly. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"mem_pressure\":{\"hi\":1000,\"lo\":500}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.mem_pressure_hi, 1000);
	T_EXPECT_EQ(conf->mux.mem_pressure_lo, 500);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* conf_check() must resolve "lo omitted" to hi/2 once at load time (an
 * odd hi exercises the truncating division) so every session reads an
 * already-concrete threshold instead of re-deriving it per grant. */
T_DECLARE_CASE(test_conf_parsefile_mem_pressure_lo_defaults_to_half_hi)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"mem_pressure\":{\"hi\":1001}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.mem_pressure_hi, 1001);
	T_EXPECT_EQ(conf->mux.mem_pressure_lo, 500);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* An explicitly inverted mem_pressure range (positive lo > positive hi) is
 * rejected by conf_check. */
T_DECLARE_CASE(test_conf_parsefile_rejects_inverted_mem_pressure)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"mem_pressure\":{\"hi\":500,\"lo\":1000}}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_session_window_positive)
{
	/* Setting only session_window (auto stream_window) is now valid:
	 * each axis is independent.  65536/16384=4 frames. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"session_window\":65536}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	/* session_window stored as frames; stream_window not set (auto). */
	T_EXPECT_EQ(conf->mux.session_window, 4);
	T_EXPECT_EQ(conf->mux.stream_window, 0);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_both_windows_positive)
{
	/* Both windows positive: stored as frame counts (/ MUX_WINDOW_UNIT),
	 * clamped to [4, max]. 32768/16384=2 → 4; 131072/16384=8 in range. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"stream_window\":32768,\"session_window\":131072}}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.stream_window, 4);
	T_EXPECT_EQ(conf->mux.session_window, 8);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_max_startups_valid)
{
	/* A well-formed max_startups string must be parsed into the three
	 * throttle fields. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:50:200\"}";
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->startup_limit_start, 10);
	T_EXPECT_EQ(conf->startup_limit_rate, 50);
	T_EXPECT_EQ(conf->startup_limit_full, 200);
	release_cleanup(_t_, cleanup_conf, conf);
}

/* Truncating this input at the size ceiling leaves valid JSON, so rejecting
 * it proves the reader's guard rather than the parser's syntax check. */
static bool write_padded_config(const int fd, const size_t size)
{
	static const char json[] = "{\"mux_connect\":\"127.0.0.1:9000\"}";
	if (write(fd, json, sizeof(json) - 1u) !=
	    (ssize_t)(sizeof(json) - 1u)) {
		return false;
	}
	char padding[256];
	memset(padding, ' ', sizeof(padding));
	size_t remaining = size - (sizeof(json) - 1u);
	while (remaining > 0) {
		const size_t chunk = remaining < sizeof(padding) ?
					     remaining :
					     sizeof(padding);
		const ssize_t n = write(fd, padding, chunk);
		if (n <= 0) {
			return false;
		}
		remaining -= (size_t)n;
	}
	return true;
}

T_DECLARE_CASE(test_conf_parsefile_accepts_maxsize)
{
	char tmpl[] = CONF_TEST_TMPDIR "/conf_limit_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	T_CHECK(write_padded_config(fd, CONF_MAXSIZE));
	(void)close(fd);
	struct config *const conf = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, conf);
	release_path(_t_, tmpl);
	const bool accepted = conf != NULL;
	release_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(accepted);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_file)
{
	/* conf_parsefile must reject files larger than CONF_MAXSIZE bytes. */
	char tmpl[] = CONF_TEST_TMPDIR "/conf_big_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	T_CHECK(write_padded_config(fd, CONF_MAXSIZE + 1u));
	(void)close(fd);
	struct config *const conf = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, conf);
	release_path(_t_, tmpl);
	const bool rejected = conf == NULL;
	release_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(rejected);
}

static int save_stdin(void)
{
	const int saved = dup(STDIN_FILENO);
	T_CHECK(saved >= 0 || errno == EBADF);
	return saved;
}

static void restore_stdin(void *data)
{
	const int saved = (int)(intptr_t)data;
	if (saved >= 0) {
		T_CHECK(dup2(saved, STDIN_FILENO) == STDIN_FILENO);
		(void)close(saved);
	} else {
		(void)close(STDIN_FILENO);
	}
	clearerr(stdin);
}

T_DECLARE_CASE(test_conf_parsefile_stdin_success)
{
	const int saved_stdin = save_stdin();
	T_CLEANUP(restore_stdin, (void *)(intptr_t)saved_stdin);
	/* conf_parsefile("-") must read and parse config from stdin. */
	int pipefd[2];
	T_CHECK(pipe(pipefd) == 0);
	const char *json = "{\"mux_connect\":\"127.0.0.1:9000\"}";
	const size_t len = strlen(json);
	T_CHECK(write(pipefd[1], json, len) == (ssize_t)len);
	(void)close(pipefd[1]);
	T_CHECK(dup2(pipefd[0], STDIN_FILENO) == STDIN_FILENO);
	if (pipefd[0] != STDIN_FILENO) {
		(void)close(pipefd[0]);
	}
	clearerr(stdin);
	struct config *const conf = conf_parsefile("-");
	retain_cleanup(_t_, cleanup_conf, conf);
	release_cleanup(_t_, restore_stdin, (void *)(intptr_t)saved_stdin);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_parsefile_stdin_rejects_oversized)
{
	const int saved_stdin = save_stdin();
	T_CLEANUP(restore_stdin, (void *)(intptr_t)saved_stdin);
	/* conf_parsefile("-") must reject stdin input larger than CONF_MAXSIZE. */
	char tmpl[] = CONF_TEST_TMPDIR "/conf_big_stdin_XXXXXX";
	const int tmpfd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(tmpfd >= 0);
	T_CHECK(write_padded_config(tmpfd, CONF_MAXSIZE + 1u));
	(void)close(tmpfd);
	const int filefd = open(tmpl, O_RDONLY);
	release_path(_t_, tmpl);
	T_CHECK(filefd >= 0);
	T_CHECK(dup2(filefd, STDIN_FILENO) == STDIN_FILENO);
	if (filefd != STDIN_FILENO) {
		(void)close(filefd);
	}
	/* Seed an EOF indicator on this fixture itself, independent of which
	 * other cases ran. Seeking the descriptor does not reset FILE flags. */
	T_CHECK(lseek(STDIN_FILENO, 0, SEEK_END) == (off_t)(CONF_MAXSIZE + 1));
	T_CHECK(fgetc(stdin) == EOF);
	T_CHECK(feof(stdin));
	T_CHECK(lseek(STDIN_FILENO, 0, SEEK_SET) == 0);
	T_CHECK(feof(stdin));
	clearerr(stdin);
	const bool flags_reset = !feof(stdin) && !ferror(stdin);
	struct config *const conf = conf_parsefile("-");
	retain_cleanup(_t_, cleanup_conf, conf);
	const off_t consumed = lseek(STDIN_FILENO, 0, SEEK_CUR);
	release_cleanup(_t_, restore_stdin, (void *)(intptr_t)saved_stdin);
	const bool rejected = conf == NULL;
	release_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(flags_reset);
	T_EXPECT(rejected);
	T_EXPECT_EQ(consumed, (off_t)(CONF_MAXSIZE + 1));
}

T_DECLARE_CASE(test_conf_stdin_fixtures_with_closed_descriptor_zero)
{
	const int saved = save_stdin();
	T_CLEANUP(restore_stdin, (void *)(intptr_t)saved);
	(void)close(STDIN_FILENO);
	testcase_test_conf_parsefile_stdin_success_(_t_);
	T_EXPECT(fcntl(STDIN_FILENO, F_GETFD) == -1 && errno == EBADF);
	testcase_test_conf_parsefile_stdin_rejects_oversized_(_t_);
	T_EXPECT(fcntl(STDIN_FILENO, F_GETFD) == -1 && errno == EBADF);
	release_cleanup(_t_, restore_stdin, (void *)(intptr_t)saved);
}

T_DECLARE_CASE(test_conf_dump_identity_fields)
{
	/* Verify that identity.claim and identity.mux_connect survive a
	 * dump/parse round-trip. */
	struct config *const orig = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	orig->mux_connect = strdup("127.0.0.1:7777");
	orig->identity.claim = strdup("mynode");
	T_CHECK(orig->mux_connect != NULL);
	T_CHECK(orig->identity.claim != NULL);
	orig->identity.mux_connect = (char **)malloc(sizeof(char *));
	T_CHECK(orig->identity.mux_connect != NULL);
	orig->identity.mux_connect[0] = strdup("127.0.0.1:9001");
	T_CHECK(orig->identity.mux_connect[0] != NULL);
	orig->identity.mux_connect_count = 1;

	char tmpl[] = CONF_TEST_TMPDIR "/conf_id_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_STREQ(reparsed->identity.claim, "mynode");
	T_EXPECT_EQ((int)reparsed->identity.mux_connect_count, 1);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

/* A successful dump preserves the configured identity listener. */
T_DECLARE_CASE(test_conf_dump_identity_listen_roundtrip)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\"}}}";
	struct config *const orig = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	T_EXPECT_EQ((int)orig->identity.peers_count, 1);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_listen_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->identity.peers_count, 1);
	T_CHECK(find_peer(reparsed, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "peer1")->listen, "127.0.0.1:9002");

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

T_DECLARE_CASE(test_conf_dump_into_capacity_and_length)
{
	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	conf->identity.claim = strdup("node-\"\\\n");
	T_CHECK(conf->identity.claim != NULL);
	const char *const indents[] = { NULL, "  " };
	for (size_t i = 0; i < ARRAY_SIZE(indents); i++) {
		size_t len = 0;
		char *const expected = conf_dump(conf, &len, indents[i]);
		T_CHECK(expected != NULL);
		retain_cleanup(_t_, free, expected);
		T_EXPECT_EQ(
			conf_dump_into(conf, NULL, 0, indents[i]), (int)len);
		unsigned char *const out = malloc(len + 3);
		T_CHECK(out != NULL);
		retain_cleanup(_t_, free, out);
		const size_t capacities[] = { 0, 1, len, len + 1, len + 2 };
		for (size_t j = 0; j < ARRAY_SIZE(capacities); j++) {
			const size_t cap = capacities[j];
			memset(out, 0xA5, len + 3);
			T_EXPECT_EQ(
				conf_dump_into(
					conf, (char *)out, cap, indents[i]),
				(int)len);
			T_EXPECT_EQ(out[cap], (unsigned char)0xA5);
			if (cap > len) {
				T_EXPECT_STREQ((char *)out, expected);
			} else if (cap > 0) {
				T_EXPECT_EQ(out[0], (unsigned char)0);
#if WITH_TLS
				for (size_t k = 0; k < cap; k++) {
					T_EXPECT_EQ(out[k], (unsigned char)0);
				}
#endif
			}
		}
		release_cleanup(_t_, free, out);
		release_cleanup(_t_, free, expected);
	}
}

T_DECLARE_CASE(test_conf_dump_into_output_limit_clears_capacity)
{
	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	conf->identity.claim = calloc(CONF_MAXSIZE + 1, 1);
	T_CHECK(conf->identity.claim != NULL);
#if WITH_TLS
	conf->tls_key = strdup("private-key-marker");
	T_CHECK(conf->tls_key != NULL);
#endif
	const int overhead = conf_dump_into(conf, NULL, 0, NULL);
	T_CHECK(overhead > 0 && overhead < CONF_MAXSIZE);
	const size_t claim_len = CONF_MAXSIZE - (size_t)overhead;
	memset(conf->identity.claim, 'x', claim_len);
	unsigned char *const out = malloc(CONF_MAXSIZE + 2);
	T_CHECK(out != NULL);
	retain_cleanup(_t_, free, out);
	memset(out, 0xA5, CONF_MAXSIZE + 2);
	T_EXPECT_EQ(
		conf_dump_into(conf, (char *)out, CONF_MAXSIZE + 2, NULL),
		CONF_MAXSIZE);
	T_EXPECT_EQ(out[CONF_MAXSIZE], (unsigned char)0);
	T_EXPECT_EQ(out[CONF_MAXSIZE + 1], (unsigned char)0xA5);
	conf->identity.claim[claim_len] = 'x';
	memset(out, 0xA5, CONF_MAXSIZE + 2);
	T_EXPECT_EQ(
		conf_dump_into(conf, (char *)out, CONF_MAXSIZE + 2, NULL), -1);
	T_EXPECT_EQ(out[0], (unsigned char)0);
	T_EXPECT_EQ(out[CONF_MAXSIZE + 1], (unsigned char)0xA5);
#if WITH_TLS
	for (size_t i = 0; i < CONF_MAXSIZE + 1; i++) {
		T_EXPECT_EQ(out[i], (unsigned char)0);
	}
#endif
}

#ifdef CONF_TEST_WRAP_ALLOC
T_DECLARE_SUBCASE(conf_dump_alloc_failures, const char *json, size_t allocations)
{
	struct config *const conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	size_t baseline_len = 0;
	char *const baseline = conf_dump(conf, &baseline_len, NULL);
	retain_cleanup(_t_, free, baseline);
	T_CHECK(baseline != NULL);
	for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
		dump_alloc.armed = true;
		dump_alloc.fail_at = fail_at;
		dump_alloc.calls = dump_alloc.allocated = dump_alloc.freed = 0;
		size_t len = SIZE_MAX;
		char *const failed = conf_dump(conf, &len, NULL);
		const bool rejected = failed == NULL;
		const size_t calls = dump_alloc.calls;
		const size_t allocated = dump_alloc.allocated;
		const size_t freed = dump_alloc.freed;
		free(failed);
		dump_alloc.armed = false;
		T_EXPECT(rejected);
		T_EXPECT_EQ(len, SIZE_MAX);
		T_EXPECT_EQ(calls, fail_at);
		T_EXPECT_EQ(allocated, fail_at - 1);
		T_EXPECT_EQ(freed, allocated);

		/* Recover using the same configuration: no field may have been lost. */
		dump_alloc.armed = true;
		dump_alloc.fail_at = 0;
		dump_alloc.calls = dump_alloc.allocated = dump_alloc.freed = 0;
		char *const recovered = conf_dump(conf, &len, NULL);
		const bool intact =
			recovered != NULL && strcmp(recovered, baseline) == 0;
		free(recovered);
		const size_t recovery_calls = dump_alloc.calls;
		const size_t recovery_allocated = dump_alloc.allocated;
		const size_t recovery_freed = dump_alloc.freed;
		dump_alloc.armed = false;
		T_EXPECT(intact);
		T_EXPECT_EQ(len, baseline_len);
		T_EXPECT_EQ(recovery_calls, allocations);
		T_EXPECT_EQ(recovery_allocated, allocations);
		T_EXPECT_EQ(recovery_freed, allocations);
	}
	release_cleanup(_t_, free, baseline);
	release_cleanup(_t_, cleanup_conf, conf);
}

T_DECLARE_CASE(test_conf_dump_alloc_failure_cleanup)
{
	/* Listener map, identity connect array, optional trust array, output. */
	const char *const json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"node\","
		"\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer\":\"127.0.0.1:9002\"}}"
#if WITH_TLS
		",\"tls\":{\"cert\":\"cert.pem\",\"key\":\"key.pem\",\"authcerts\":[\"ca.pem\"]}"
#endif
		"}";
#if WITH_TLS
	const size_t allocations = 4;
#else
	const size_t allocations = 3;
#endif
	T_CALL_SUBCASE(conf_dump_alloc_failures, json, allocations);
}

#if WITH_TLS
T_DECLARE_CASE(test_conf_dump_failure_erases_output_capacity)
{
	struct config *const conf = conf_new_default();
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	conf->tls_key = strdup("private-key-marker-for-failed-dump");
	conf->identity.claim = malloc(CONF_MAXSIZE + 1);
	T_CHECK(conf->tls_key != NULL && conf->identity.claim != NULL);
	memset(conf->identity.claim, 'x', CONF_MAXSIZE);
	conf->identity.claim[CONF_MAXSIZE] = '\0';

	dump_erase_probe.armed = true;
	dump_erase_probe.frees = 0;
	dump_erase_probe.zeroed = false;
	size_t len = SIZE_MAX;
	char *const out = conf_dump(conf, &len, NULL);
	dump_erase_probe.armed = false;
	const size_t frees = dump_erase_probe.frees;
	const bool zeroed = dump_erase_probe.zeroed;
	const bool rejected = out == NULL;
	free(out);
	T_EXPECT(rejected);
	T_EXPECT_EQ(len, SIZE_MAX);
	T_EXPECT_EQ(frees, (size_t)1);
	T_EXPECT(zeroed);
}

T_DECLARE_CASE(test_conf_dump_psk_alloc_failure_cleanup)
{
	/* Listener map, PSK map, identity connect array, output. */
	T_CALL_SUBCASE(
		conf_dump_alloc_failures,
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"node\","
		"\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer\":\"127.0.0.1:9002\"}},"
		"\"tls\":{\"psk\":{\"peer\":" PSK_HEX "}}}",
		(size_t)4);
}
#endif /* WITH_TLS */
#endif /* CONF_TEST_WRAP_ALLOC */

T_DECLARE_CASE(test_conf_dump_identity_listen_exact_grow_boundary)
{
	/* This map hit the former hand-built JSON buffer's 64-byte growth
	 * boundary. Keep it as a roundtrip case for the generated map codec. */
	char listen_val[59];
	memset(listen_val, 'x', sizeof(listen_val) - 1);
	listen_val[sizeof(listen_val) - 1] = '\0';
	char json[256];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"k\":\"%s\"}}}",
		listen_val);
	struct config *const orig = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	T_EXPECT_EQ((int)orig->identity.peers_count, 1);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_listen_boundary_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->identity.peers_count, 1);
	T_CHECK(find_peer(reparsed, "k") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "k")->listen, listen_val);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

T_DECLARE_CASE(test_conf_unacked_memory_limit)
{
	struct config *conf =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.unacked_memory_limit, (size_t)67108864);
	release_cleanup(_t_, cleanup_conf, conf);

	char overflow[sizeof(uintmax_t) * CHAR_BIT + 2];
	(void)snprintf(
		overflow, sizeof(overflow), "%" PRIuMAX "0", UINTMAX_MAX);
	const char *invalid[] = { "0", "-1", "1.5", "\"64MiB\"", overflow };
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		char json[160];
		(void)snprintf(
			json, sizeof(json),
			"{\"mux_connect\":\"127.0.0.1:9000\","
			"\"mux\":{\"unacked_memory_limit\":%s}}",
			invalid[i]);
		conf = parse_tmpconf(json);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf == NULL);
		release_cleanup(_t_, cleanup_conf, conf);
	}

	const size_t valid[] = { 1, 1048576, SIZE_MAX };
	for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
		char json[160];
		(void)snprintf(
			json, sizeof(json),
			"{\"mux_connect\":\"127.0.0.1:9000\","
			"\"mux\":{\"unacked_memory_limit\":%zu}}",
			valid[i]);
		conf = parse_tmpconf(json);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_CHECK(conf != NULL);
		T_EXPECT_EQ(conf->mux.unacked_memory_limit, valid[i]);
		char path[] = CONF_TEST_TMPDIR "/conf_unacked_dump_XXXXXX";
		const int fd = mkstemp(path);
		retain_path(_t_, path);
		T_CHECK(fd >= 0);
		(void)close(fd);
		T_CHECK(write_conf_file(conf, path));
		struct config *const parsed = conf_parsefile(path);
		retain_cleanup(_t_, cleanup_conf, parsed);
		release_path(_t_, path);
		T_CHECK(parsed != NULL);
		T_EXPECT_EQ(parsed->mux.unacked_memory_limit, valid[i]);
		release_cleanup(_t_, cleanup_conf, parsed);
		release_cleanup(_t_, cleanup_conf, conf);
	}
#if SIZE_MAX < UINTMAX_MAX
	char json[160];
	(void)snprintf(
		json, sizeof(json),
		"{\"mux_connect\":\"127.0.0.1:9000\","
		"\"mux\":{\"unacked_memory_limit\":%" PRIuMAX "}}",
		(uintmax_t)SIZE_MAX + 1);
	conf = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_EXPECT(conf == NULL);
	release_cleanup(_t_, cleanup_conf, conf);
#endif
}

T_DECLARE_CASE(test_conf_dump_readahead_roundtrip)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"readahead\":65536}}";
	struct config *const orig = parse_tmpconf(json);
	retain_cleanup(_t_, cleanup_conf, orig);
	T_CHECK(orig != NULL);
	T_EXPECT_EQ(orig->mux.readahead, 65536);

	char tmpl[] = CONF_TEST_TMPDIR "/conf_readahead_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	retain_path(_t_, tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	retain_cleanup(_t_, cleanup_conf, reparsed);
	release_path(_t_, tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ(reparsed->mux.readahead, 65536);

	release_cleanup(_t_, cleanup_conf, reparsed);
	release_cleanup(_t_, cleanup_conf, orig);
}

/* conf_check_type parses "type" as a MIME media type (RFC 2045), so these
 * variants -- differing only in case, whitespace, parameter order, or
 * carrying extra ignored parameters -- must all be accepted, unlike the
 * byte-exact string the old schema "const" constraint required. */
T_DECLARE_CASE(test_conf_parsefile_accepts_type_variants)
{
	static const char *const good[] = {
		"application/x-multiplexd-config; version=1",
		"Application/X-Multiplexd-Config; version=1",
		"application/x-multiplexd-config;version=1",
		"application/x-multiplexd-config ; version=1",
		"application/x-multiplexd-config; charset=utf-8; version=1",
		"application/x-multiplexd-config; version=1; extra=ignored",
	};
	for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		char json[256];
		(void)snprintf(
			json, sizeof(json),
			"{\"type\":\"%s\",\"mux_connect\":\"127.0.0.1:9000\"}",
			good[i]);
		struct config *const conf = parse_tmpconf(json);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf != NULL);
		T_EXPECT_STREQ(conf->type, good[i]);
		release_cleanup(_t_, cleanup_conf, conf);
	}
}

T_DECLARE_CASE(test_conf_parsefile_rejects_invalid_type)
{
	static const char *const bad[] = {
		"text/plain; version=1",
		"application/json; version=1",
		"application/x-multiplexd-config",
		"application/x-multiplexd-config; version=2",
		"application/x-multiplexd-config; version=",
		"not-a-mime-type",
		"",
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		char json[256];
		(void)snprintf(
			json, sizeof(json),
			"{\"type\":\"%s\",\"mux_connect\":\"127.0.0.1:9000\"}",
			bad[i]);
		struct config *const conf = parse_tmpconf(json);
		retain_cleanup(_t_, cleanup_conf, conf);
		T_EXPECT(conf == NULL);
		release_cleanup(_t_, cleanup_conf, conf);
	}
}

T_DECLARE_CASE(test_type_validation_preserves_long_owned_type)
{
	char json[8192];
	const char prefix[] =
		"{\"type\":\"application/x-multiplexd-config; version=1; extra=";
	memcpy(json, prefix, sizeof(prefix) - 1);
	memset(json + sizeof(prefix) - 1, 'x', 4096);
	const char suffix[] = "\",\"mux_connect\":\"127.0.0.1:9000\"}";
	memcpy(json + sizeof(prefix) - 1 + 4096, suffix, sizeof(suffix));
	const size_t len = sizeof(prefix) - 1 + 4096 + sizeof(suffix) - 1;
	struct config *const conf = conf_parse(json, len);
	retain_cleanup(_t_, cleanup_conf, conf);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(
		strlen(conf->type),
		strlen("application/x-multiplexd-config; version=1; extra=") +
			4096);
	T_EXPECT(strstr(conf->type, "; version=1; extra=") != NULL);
	release_cleanup(_t_, cleanup_conf, conf);
}

static const struct testing_suite suite[] = {
	T_CASE(test_type_validation_preserves_long_owned_type),
	T_CASE(test_conf_unacked_memory_limit),
	T_CASE(test_conf_stdin_fixtures_with_closed_descriptor_zero),
	T_CASE(test_conf_new_default_fields),
	T_CASE(test_conf_map_diagnostics_escape_keys),
	T_CASE(test_conf_validation_diagnostics_escape_text),
	T_CASE(test_conf_new_default_matches_empty_parse),
	T_CASE(test_conf_presence_preserves_empty_strings_and_nested_defaults),
	T_CASE(test_conf_lossymux_defaults),
	T_CASE(test_conf_lossymux_parse_and_roundtrip),
	T_CASE(test_conf_lossymux_rejects_out_of_range),
	T_CASE(test_conf_parsefile_nonexistent),
	T_CASE(test_conf_parsefile_invalid_json),
	T_CASE(test_conf_parsefile_rejects_invalid_utf8),
	T_CASE(test_conf_parsefile_accepts_well_formed_utf8),
	T_CASE(test_conf_parsefile_minimal_client),
	T_CASE(test_conf_parsefile_minimal_server),
	T_CASE(test_conf_dump_roundtrip),
	T_CASE(test_conf_dump_into_capacity_and_length),
	T_CASE(test_conf_dump_into_output_limit_clears_capacity),
	T_CASE(test_conf_parsefile_mux_max_frame_size_roundtrip),
	T_CASE(test_conf_identity_connect_count),
	T_CASE(test_conf_loglevel_parsed),
	T_CASE(test_conf_parsefile_requires_transport),
	T_CASE(test_conf_parsefile_requires_claim_for_identity),
	T_CASE(test_conf_parsefile_requires_claim_for_identity_listen),
	T_CASE(test_conf_parsefile_accepts_mux_listen_and_mux_connect),
	T_CASE(test_conf_parsefile_accepts_max_length_identity_claim),
	T_CASE(test_conf_parsefile_rejects_oversized_identity_claim),
	T_CASE(test_conf_parsefile_accepts_max_length_listen_address),
	T_CASE(test_conf_parsefile_rejects_oversized_listen_address),
	T_CASE(test_conf_parsefile_parses_identity_listen),
	T_CASE(test_conf_dump_identity_listen_multi_peer_roundtrip),
	T_CASE(test_conf_parsefile_identity_listen_duplicate_key_last_wins),
	T_CASE(test_conf_parsefile_identity_listen_many_peers),
	T_CASE(test_conf_parsefile_rejects_oversized_identity_listen_value),
	T_CASE(test_conf_parsefile_accepts_max_length_identity_listen_key),
	T_CASE(test_conf_parsefile_rejects_oversized_identity_listen_key),
	T_CASE(test_conf_parsefile_rejects_oversized_identity_mux_connect),
	T_CASE(test_conf_parsefile_identity_listen_valid_map_control),
	T_CASE(test_conf_parsefile_identity_listen_rejects_non_object),
	T_CASE(test_conf_parsefile_identity_listen_rejects_malformed_json),
	T_CASE(test_conf_parsefile_identity_listen_rejects_bracket_mismatch),
	T_CASE(test_conf_parsefile_identity_listen_skips_comment_key),
	T_CASE(test_conf_parsefile_identity_listen_rejects_non_string_value),
	T_CASE(test_conf_parsefile_rejects_embedded_nul_in_identity_claim),
	T_CASE(test_conf_parsefile_rejects_embedded_nul_in_identity_listen_key),
	T_CASE(test_conf_parsefile_rejects_embedded_nul_in_mux_connect_field),
	T_CASE(test_conf_parsefile_invalid_max_startups_format),
	T_CASE(test_conf_parsefile_max_startups_rejects_non_strict_digits),
	T_CASE(test_conf_max_startups_rejects_embedded_nul),
	T_CASE(test_conf_parsefile_max_startups_rejects_overflow),
	T_CASE(test_conf_parsefile_invalid_max_startups_rate),
	T_CASE(test_conf_parsefile_invalid_max_startups_range),
	T_CASE(test_conf_parsefile_clamps_timeout_fields),
	T_CASE(test_conf_parsefile_preserves_zero_connect_resume_timeout),
	T_CASE(test_conf_parsefile_clamps_int_overflow_fields),
	T_CASE(test_conf_parsefile_partial_window_config_accepted),
	T_CASE(test_conf_dump_readahead_roundtrip),
	T_CASE(test_conf_parsefile_accepts_type_variants),
	T_CASE(test_conf_parsefile_rejects_invalid_type),
#if WITH_TLS
	T_CASE(test_conf_erase_credentials_all_buffers),
	T_CASE(test_conf_erase_credentials_absent_fields),
	T_CASE(test_conf_parsefile_rejects_partial_tls_config),
	T_CASE(test_conf_parsefile_rejects_partial_tls_config_combinations),
	T_CASE(test_conf_parsefile_authcerts_array),
	T_CASE(test_conf_dump_tls_fields),
	T_CASE(test_conf_system_trust_roundtrip),
	T_CASE(test_conf_system_trust_rejects_incomplete_or_psk),
	T_CASE(test_conf_load_tls_kernel_offload_defaults_with_socket_offload),
	T_CASE(test_conf_load_tls_kernel_offload_off_without_socket_offload),
	T_CASE(test_conf_load_tls_kernel_offload_explicit_override),
	T_CASE(test_conf_inline_pem_replaces_at_path),
	T_CASE(test_conf_inline_pem_concatenates_authcerts_bundle),
	T_CASE(test_conf_inline_pem_rejects_embedded_nuls),
	T_CASE(test_conf_inline_pem_fails_for_missing_file),
	T_CASE(test_conf_identity_verify_with_tls_roundtrip),
	T_CASE(test_conf_psk_parsed_in_order),
	T_CASE(test_conf_psk_empty_identity),
	T_CASE(test_conf_psk_rejects_certificate_fields),
	T_CASE(test_conf_psk_omits_sni),
	T_CASE(test_conf_psk_rejects_identity_verify),
	T_CASE(test_conf_psk_rejects_duplicate_identity),
	T_CASE(test_conf_psk_rejects_bad_key),
#ifdef CONF_TEST_WRAP_ALLOC
	T_CASE(test_conf_rejection_cleanup_on_failed_expectation),
#endif
	T_CASE(test_conf_psk_accepts_key_length_bounds),
	T_CASE(test_conf_psk_trim_erases_vacated_tail),
	T_CASE(test_conf_psk_at_path_trims_trailing_newline),
	T_CASE(test_conf_psk_preserves_uppercase_hex),
	T_CASE(test_conf_psk_at_path_rejects_bad_key),
	T_CASE(test_conf_psk_identity_length_bound),
	T_CASE(test_conf_psk_rejects_non_object),
	T_CASE(test_conf_psk_rejects_malformed_json),
	T_CASE(test_conf_psk_rejects_non_string_value),
	T_CASE(test_conf_psk_skips_comment_key),
	T_CASE(test_conf_psk_dump_roundtrip),
#endif /* WITH_TLS */
	T_CASE(test_conf_parsefile_ignores_comment_keys),
	T_CASE(test_conf_parsefile_unknown_root_key),
	T_CASE(test_conf_parsefile_unknown_mux_key),
	T_CASE(test_conf_parsefile_mem_pressure_config),
	T_CASE(test_conf_parsefile_mem_pressure_lo_defaults_to_half_hi),
	T_CASE(test_conf_parsefile_rejects_inverted_mem_pressure),
	T_CASE(test_conf_parsefile_rejects_embedded_nul_in_identity_listen_value),
	T_CASE(test_conf_parsefile_session_window_positive),
	T_CASE(test_conf_parsefile_both_windows_positive),
	T_CASE(test_conf_parsefile_max_startups_valid),
	T_CASE(test_conf_dump_identity_fields),
	T_CASE(test_conf_identity_verify_defaults_false),
	T_CASE(test_conf_identity_verify_requires_tls),
	T_CASE(test_conf_psk_disabled_entries_select_plaintext),
#if !WITH_TLS
	T_CASE(test_conf_no_tls_rejects_credentials),
#endif /* !WITH_TLS */
	T_CASE(test_conf_dump_identity_listen_roundtrip),
#ifdef CONF_TEST_WRAP_ALLOC
	T_CASE(test_conf_dump_alloc_failure_cleanup),
#if WITH_TLS
	T_CASE(test_conf_dump_failure_erases_output_capacity),
	T_CASE(test_conf_dump_psk_alloc_failure_cleanup),
#endif
#endif /* CONF_TEST_WRAP_ALLOC */
	T_CASE(test_conf_dump_identity_listen_exact_grow_boundary),
	T_CASE(test_conf_parsefile_accepts_maxsize),
	T_CASE(test_conf_parsefile_rejects_oversized_file),
	T_CASE(test_conf_parsefile_stdin_success),
	T_CASE(test_conf_parsefile_stdin_rejects_oversized),
	T_CASE(test_conf_parse_honors_len_without_nul),
	T_CASE(test_conf_parse_rejects_oversized_buffer),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
