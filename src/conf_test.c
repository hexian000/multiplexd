/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "utils/slog.h"
#include "utils/testing.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Write a string to a new temp file; return -1 on failure. */
static int write_tmpfile(char *restrict tmpl, const char *restrict content)
{
	const int fd = mkstemp(tmpl);
	if (fd < 0) {
		return -1;
	}
	const size_t len = strlen(content);
	if (write(fd, content, len) != (ssize_t)len) {
		(void)close(fd);
		(void)unlink(tmpl);
		return -1;
	}
	(void)close(fd);
	return 0;
}

static struct config *parse_tmpconf(const char *restrict content)
{
	char tmpl[] = "/tmp/conf_test_XXXXXX";
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
	for (size_t i = 0; i < conf->identity_peers_count; i++) {
		if (strcmp(conf->identity_peers[i].id, id) == 0) {
			return &conf->identity_peers[i];
		}
	}
	return NULL;
}

T_DECLARE_CASE(test_conf_new_default_fields)
{
	struct config *conf = conf_new();
	T_CHECK(conf != NULL);
	/* Default type is NULL — no type annotation in a freshly created conf. */
	T_EXPECT(conf->type == NULL);
	/* Default timeouts are positive. */
	T_EXPECT(conf->mux.timeout > 0);
	T_EXPECT(conf->mux.keepalive > 0);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_nonexistent)
{
	struct config *conf =
		conf_parsefile("/nonexistent/path/that/cannot/exist.json");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_json)
{
	char tmpl[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tmpfile(tmpl, "{bad json") == 0);
	struct config *conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_minimal_client)
{
	char tmpl[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tmpfile(tmpl, "{\"mux_connect\":\"127.0.0.1:9000\"}") ==
		0);
	struct config *conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(conf != NULL);
	T_CHECK(conf->mux_connect != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	T_EXPECT(conf->mux_listen == NULL);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_minimal_server)
{
	char tmpl[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tmpfile(tmpl, "{\"mux_listen\":\"127.0.0.1:9000\"}") ==
		0);
	struct config *conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(conf != NULL);
	T_CHECK(conf->mux_listen != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	T_EXPECT(conf->mux_connect == NULL);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_dump_roundtrip)
{
	struct config *orig = conf_new();
	T_CHECK(orig != NULL);
	orig->mux_connect = strdup("127.0.0.1:7777");
	T_CHECK(orig->mux_connect != NULL);

	char tmpl[] = "/tmp/conf_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(conf_dumpfile(orig, tmpl));

	struct config *reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_CHECK(reparsed->mux_connect != NULL);
	T_EXPECT_STREQ(reparsed->mux_connect, "127.0.0.1:7777");
	/* type is set by conf_build_json when the original type is NULL */
	T_EXPECT(reparsed->type != NULL);

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_conf_identity_connect_count)
{
	char tmpl[] = "/tmp/conf_test_XXXXXX";
	/* Identity-client mode: mux_connect lists destinations; claim is
	 * required alongside mux_connect. */
	const char *json = "{"
			   "\"identity\":{\"claim\":\"mynode\","
			   "\"mux_connect\":[\"127.0.0.1:9001\","
			   "\"127.0.0.1:9002\"]}"
			   "}";
	T_CHECK(write_tmpfile(tmpl, json) == 0);
	struct config *conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity_connect_count, 2);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_loglevel_parsed)
{
	char tmpl[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tmpfile(
			tmpl, "{\"mux_connect\":\"127.0.0.1:9000\","
			      "\"loglevel\":3}") == 0);
	struct config *conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->loglevel, 3);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_requires_transport)
{
	struct config *conf = parse_tmpconf("{}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_requires_claim_for_identity)
{
	struct config *conf = parse_tmpconf(
		"{\"identity\":{\"mux_connect\":[\"127.0.0.1:9001\"]}}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_parses_identity_listen)
{
	struct config *conf =
		parse_tmpconf("{"
			      "\"identity\":{"
			      "\"claim\":\"mynode\","
			      "\"mux_connect\":[\"127.0.0.1:9001\"],"
			      "\"listen\":{"
			      "\"peer1\":\"127.0.0.1:9002\","
			      "\"peer2\":\"127.0.0.1:9003\""
			      "}"
			      "}"
			      "}");
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity_connect_count, 1);
	T_EXPECT_EQ((int)conf->identity_peers_count, 2);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9002");
	T_CHECK(find_peer(conf, "peer2") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer2")->listen, "127.0.0.1:9003");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_format)
{
	struct config *conf =
		parse_tmpconf("{\"mux_listen\":\"127.0.0.1:9000\","
			      "\"max_startups\":\"10:20\"}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_rate)
{
	struct config *conf =
		parse_tmpconf("{\"mux_listen\":\"127.0.0.1:9000\","
			      "\"max_startups\":\"10:101:20\"}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_range)
{
	struct config *conf =
		parse_tmpconf("{\"mux_listen\":\"127.0.0.1:9000\","
			      "\"max_startups\":\"10:20:10\"}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_clamps_timeout_fields)
{
	struct config *conf =
		parse_tmpconf("{"
			      "\"mux_connect\":\"127.0.0.1:9000\","
			      "\"mux\":{"
			      "\"timeout\":10,"
			      "\"keepalive\":20,"
			      "\"send_timeout\":30,"
			      "\"connect_timeout\":40,"
			      "\"resume_timeout\":1,"
			      "\"idle_timeout\":2"
			      "},"
			      "\"loglevel\":999"
			      "}");
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.timeout, 10);
	T_EXPECT_EQ(conf->mux.keepalive, 10);
	T_EXPECT_EQ(conf->mux.send_timeout, 10);
	T_EXPECT_EQ(conf->mux.connect_timeout, 10);
	T_EXPECT_EQ(conf->mux.resume_timeout, 10);
	T_EXPECT_EQ(conf->mux.idle_timeout, 5);
	T_EXPECT_EQ(conf->loglevel, LOG_LEVEL_VERYVERBOSE);
	T_EXPECT(conf->mux.reject_inbound);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_mixed_window_mode_normalized_to_auto)
{
	struct config *conf =
		parse_tmpconf("{"
			      "\"mux_connect\":\"127.0.0.1:9000\","
			      "\"mux\":{\"stream_window\":32768}"
			      "}");
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.stream_window, 0);
	T_EXPECT_EQ(conf->mux.session_window, 0);
	conf_free(conf);
}

#if WITH_TLS
T_DECLARE_CASE(test_conf_parsefile_rejects_partial_tls_config)
{
	struct config *conf = parse_tmpconf("{"
					    "\"mux_listen\":\"127.0.0.1:9000\","
					    "\"tls\":{\"cert\":\"dummy\"}"
					    "}");
	T_EXPECT(conf == NULL);
}
#endif

T_DECLARE_CASE(test_conf_parsefile_ignores_comment_keys)
{
	/* Keys prefixed with '-' are a comment-out convention: they must be
	 * silently skipped at any nesting level without causing a parse error
	 * or overwriting the default field values. */
	struct config *conf =
		parse_tmpconf("{"
			      "\"mux_connect\":\"127.0.0.1:9000\","
			      "\"-mux_connect\":\"should-be-ignored\","
			      "\"-loglevel\":0,"
			      "\"mux\":{"
			      "\"timeout\":30,"
			      "\"-timeout\":999,"
			      "\"-nodelay\":false"
			      "},"
			      "\"-tcp\":{\"nodelay\":false},"
			      "\"identity\":{"
			      "\"claim\":\"me\","
			      "\"-claim\":\"ignored\""
			      "}"
			      "}");
	T_CHECK(conf != NULL);
	/* mux_connect must reflect the real key, not the commented-out one. */
	T_EXPECT(strcmp(conf->mux_connect, "127.0.0.1:9000") == 0);
	/* loglevel must stay at the default (not overwritten by -loglevel). */
	T_EXPECT_EQ(conf->loglevel, LOG_LEVEL_NOTICE);
	/* mux.timeout must be 30, not 999 from the commented key. */
	T_EXPECT_EQ(conf->mux.timeout, 30);
	/* mux.nodelay default is true; -nodelay:false must be ignored. */
	T_EXPECT(conf->mux.nodelay);
	/* identity.claim must be "me", not "ignored". */
	T_EXPECT(strcmp(conf->identity_claim, "me") == 0);
	conf_free(conf);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_conf_new_default_fields);
	T_RUN_CASE(t, test_conf_parsefile_nonexistent);
	T_RUN_CASE(t, test_conf_parsefile_invalid_json);
	T_RUN_CASE(t, test_conf_parsefile_minimal_client);
	T_RUN_CASE(t, test_conf_parsefile_minimal_server);
	T_RUN_CASE(t, test_conf_dump_roundtrip);
	T_RUN_CASE(t, test_conf_identity_connect_count);
	T_RUN_CASE(t, test_conf_loglevel_parsed);
	T_RUN_CASE(t, test_conf_parsefile_requires_transport);
	T_RUN_CASE(t, test_conf_parsefile_requires_claim_for_identity);
	T_RUN_CASE(t, test_conf_parsefile_parses_identity_listen);
	T_RUN_CASE(t, test_conf_parsefile_invalid_max_startups_format);
	T_RUN_CASE(t, test_conf_parsefile_invalid_max_startups_rate);
	T_RUN_CASE(t, test_conf_parsefile_invalid_max_startups_range);
	T_RUN_CASE(t, test_conf_parsefile_clamps_timeout_fields);
	T_RUN_CASE(t, test_conf_parsefile_mixed_window_mode_normalized_to_auto);
#if WITH_TLS
	T_RUN_CASE(t, test_conf_parsefile_rejects_partial_tls_config);
#endif
	T_RUN_CASE(t, test_conf_parsefile_ignores_comment_keys);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
