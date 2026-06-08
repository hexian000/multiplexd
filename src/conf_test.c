/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "utils/slog.h"
#include "utils/testing.h"

#include <fcntl.h>
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

static bool
write_conf_file(const struct config *restrict conf, const char *restrict path)
{
	size_t len;
	char *json = conf_dump(conf, &len);
	if (json == NULL) {
		return false;
	}
	FILE *fp = fopen(path, "w");
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
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		if (strcmp(conf->identity.peers[i].id, id) == 0) {
			return &conf->identity.peers[i];
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
	T_EXPECT(conf->mux.ping_timeout > 0);
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
	T_CHECK(write_conf_file(orig, tmpl));

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
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\",\"127.0.0.1:9002\"]}}";
	T_CHECK(write_tmpfile(tmpl, json) == 0);
	struct config *conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.mux_connect_count, 2);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_loglevel_parsed)
{
	char tmpl[] = "/tmp/conf_test_XXXXXX";
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"loglevel\":3}";
	T_CHECK(write_tmpfile(tmpl, json) == 0);
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
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\",\"peer2\":\"127.0.0.1:9003\"}}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.mux_connect_count, 1);
	T_EXPECT_EQ((int)conf->identity.peers_count, 2);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9002");
	T_CHECK(find_peer(conf, "peer2") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer2")->listen, "127.0.0.1:9003");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_format)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:20\"}";
	struct config *conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_rate)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:101:20\"}";
	struct config *conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_range)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:20:10\"}";
	struct config *conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_clamps_timeout_fields)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"ping_timeout\":10,\"keepalive\":5,\"send_timeout\":30,\"connect_timeout\":40,\"resume_timeout\":1,\"idle_timeout\":2},\"loglevel\":999}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);

	T_EXPECT_EQ(conf->mux.ping_timeout, 10);
	T_EXPECT_EQ(conf->mux.keepalive, 10); /* 5 → clamped up to floor 10 */
	T_EXPECT_EQ(conf->mux.send_timeout, 30); /* independent [10,86400] */
	T_EXPECT_EQ(conf->mux.connect_timeout, 40); /* independent [10,86400] */
	T_EXPECT_EQ(
		conf->mux.resume_timeout, 10); /* 1 → clamped up to floor 10 */
	T_EXPECT_EQ(conf->mux.idle_timeout, 10);
	T_EXPECT_EQ(conf->loglevel, LOG_LEVEL_VERYVERBOSE);
	T_EXPECT(conf_get_mux(conf).reject_inbound);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_partial_window_config_accepted)
{
	/* stream_window set (manual), session_window absent (auto); each axis
	 * is independent so the mixed configuration is accepted as-is.
	 * 32768/16384=2 frames, clamped to the minimum of 4. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"stream_window\":32768}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.stream_window, 4);
	T_EXPECT_EQ(conf->mux.session_window, 0);
	conf_free(conf);
}

#if WITH_TLS
T_DECLARE_CASE(test_conf_parsefile_rejects_partial_tls_config)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"dummy\"}}";
	struct config *conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_authcerts_array)
{
	/* Verify that the authcerts array is parsed and stored correctly. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"certdata\",\"key\":\"keydata\",\"authcerts\":[\"ca1.pem\",\"ca2.pem\"]}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_authcerts_count, 2);
	T_EXPECT_STREQ(conf->tls_authcerts[0], "ca1.pem");
	T_EXPECT_STREQ(conf->tls_authcerts[1], "ca2.pem");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_dump_tls_fields)
{
	/* Verify that tls.cert, tls.key, and tls.authcerts survive a
	 * dump/parse round-trip, exercising dump_tls. */
	struct config *orig = conf_new();
	T_CHECK(orig != NULL);
	orig->mux_connect = strdup("127.0.0.1:7777");
	orig->tls_cert = strdup("certdata");
	orig->tls_key = strdup("keydata");
	orig->tls_authcerts = malloc(sizeof(char *));
	T_CHECK(orig->tls_authcerts != NULL);
	orig->tls_authcerts[0] = strdup("authcertdata");
	T_CHECK(orig->tls_authcerts[0] != NULL);
	orig->tls_authcerts_count = 1;
	T_CHECK(orig->mux_connect != NULL);
	T_CHECK(orig->tls_cert != NULL);
	T_CHECK(orig->tls_key != NULL);

	char tmpl[] = "/tmp/conf_tls_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_STREQ(reparsed->tls_cert, "certdata");
	T_EXPECT_STREQ(reparsed->tls_key, "keydata");
	T_EXPECT_EQ((int)reparsed->tls_authcerts_count, 1);
	T_EXPECT_STREQ(reparsed->tls_authcerts[0], "authcertdata");

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_conf_inline_pem_replaces_at_path)
{
	/* conf_inline_pem must replace @path fields with the file's content. */
	char cert_tmpl[] = "/tmp/conf_inline_cert_XXXXXX";
	char key_tmpl[] = "/tmp/conf_inline_key_XXXXXX";
	T_CHECK(write_tmpfile(cert_tmpl, "CERTCONTENT") == 0);
	T_CHECK(write_tmpfile(key_tmpl, "KEYCONTENT") == 0);

	struct config *conf = conf_new();
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

	(void)unlink(cert_tmpl);
	(void)unlink(key_tmpl);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_inline_pem_fails_for_missing_file)
{
	/* conf_inline_pem must return false if an @path file does not exist. */
	struct config *conf = conf_new();
	T_CHECK(conf != NULL);
	conf->tls_cert = strdup("@/tmp/conf_inline_nonexistent_XXXXXX.pem");
	conf->tls_key = strdup("plaintext");
	T_CHECK(conf->tls_cert != NULL);
	T_CHECK(conf->tls_key != NULL);

	T_EXPECT(!conf_inline_pem(conf));
	conf_free(conf);
}
#endif /* WITH_TLS */

T_DECLARE_CASE(test_conf_parsefile_ignores_comment_keys)
{
	/* Keys prefixed with '-' are a comment-out convention: they must be
	 * silently skipped at any nesting level without causing a parse error
	 * or overwriting the default field values. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"-mux_connect\":\"should-be-ignored\",\"-loglevel\":0,\"mux\":{\"ping_timeout\":30,\"-ping_timeout\":999,\"-nodelay\":false},\"-tcp\":{\"nodelay\":false},\"identity\":{\"claim\":\"me\",\"-claim\":\"ignored\"}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	/* mux_connect must reflect the real key, not the commented-out one. */
	T_EXPECT(strcmp(conf->mux_connect, "127.0.0.1:9000") == 0);
	/* loglevel must stay at the default (not overwritten by -loglevel). */
	T_EXPECT_EQ(conf->loglevel, LOG_LEVEL_NOTICE);
	/* mux.ping_timeout must be 30, not 999 from the commented key. */
	T_EXPECT_EQ(conf->mux.ping_timeout, 30);
	/* mux.nodelay default is true; -nodelay:false must be ignored. */
	T_EXPECT(conf->mux.nodelay);
	/* identity.claim must be "me", not "ignored". */
	T_EXPECT(strcmp(conf->identity.claim, "me") == 0);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_unknown_root_key)
{
	/* Unknown keys at the root level must be warned about but not fail. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"nosuchkey\":\"value\"}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_unknown_mux_key)
{
	/* Unknown keys inside a scope must be warned about but not fail. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"nosuchfield\":1}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_mem_pressure_config)
{
	/* Verify that the mux.mem_pressure sub-object is parsed correctly. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"mem_pressure\":{\"hi\":1000,\"lo\":500}}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.mem_pressure_hi, 1000);
	T_EXPECT_EQ(conf->mux.mem_pressure_lo, 500);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_session_window_positive)
{
	/* Setting only session_window (auto stream_window) is now valid:
	 * each axis is independent.  65536/16384=4 frames. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"session_window\":65536}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	/* session_window stored as frames; stream_window not set (auto). */
	T_EXPECT_EQ(conf->mux.session_window, 4);
	T_EXPECT_EQ(conf->mux.stream_window, 0);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_both_windows_positive)
{
	/* When both stream_window and session_window are given positive values,
	 * the parser stores them in units (divided by MUX_MAX_PAYLOAD_SIZE),
	 * clamped to [4, max].  32768/16384=2 → clamped to 4;
	 * 131072/16384=8, within range. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"stream_window\":32768,\"session_window\":131072}}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.stream_window, 4);
	T_EXPECT_EQ(conf->mux.session_window, 8);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_max_startups_valid)
{
	/* A well-formed max_startups string must be parsed into the three
	 * throttle fields. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:50:200\"}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->startup_limit_start, 10);
	T_EXPECT_EQ(conf->startup_limit_rate, 50);
	T_EXPECT_EQ(conf->startup_limit_full, 200);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_file)
{
	/* conf_parsefile must reject files larger than CONF_MAXSIZE bytes. */
	char tmpl[] = "/tmp/conf_big_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	char buf[256];
	memset(buf, 'x', sizeof(buf));
	size_t remaining = CONF_MAXSIZE + 1;
	while (remaining > 0) {
		const size_t chunk =
			remaining < sizeof(buf) ? remaining : sizeof(buf);
		const ssize_t w = write(fd, buf, chunk);
		T_CHECK(w > 0);
		remaining -= (size_t)w;
	}
	(void)close(fd);
	struct config *conf = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_stdin_success)
{
	/* conf_parsefile("-") must read and parse config from stdin. */
	int pipefd[2];
	T_CHECK(pipe(pipefd) == 0);
	const char *json = "{\"mux_connect\":\"127.0.0.1:9000\"}";
	const size_t len = strlen(json);
	T_CHECK(write(pipefd[1], json, len) == (ssize_t)len);
	(void)close(pipefd[1]);
	const int saved_stdin = dup(STDIN_FILENO);
	T_CHECK(saved_stdin >= 0);
	T_CHECK(dup2(pipefd[0], STDIN_FILENO) == STDIN_FILENO);
	(void)close(pipefd[0]);
	struct config *conf = conf_parsefile("-");
	T_CHECK(dup2(saved_stdin, STDIN_FILENO) == STDIN_FILENO);
	(void)close(saved_stdin);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_stdin_rejects_oversized)
{
	/* conf_parsefile("-") must reject stdin input larger than CONF_MAXSIZE. */
	char tmpl[] = "/tmp/conf_big_stdin_XXXXXX";
	const int tmpfd = mkstemp(tmpl);
	T_CHECK(tmpfd >= 0);
	char buf[256];
	memset(buf, 'x', sizeof(buf));
	size_t remaining = CONF_MAXSIZE + 1;
	while (remaining > 0) {
		const size_t chunk =
			remaining < sizeof(buf) ? remaining : sizeof(buf);
		const ssize_t w = write(tmpfd, buf, chunk);
		T_CHECK(w > 0);
		remaining -= (size_t)w;
	}
	(void)close(tmpfd);
	const int filefd = open(tmpl, O_RDONLY);
	(void)unlink(tmpl);
	T_CHECK(filefd >= 0);
	const int saved_stdin = dup(STDIN_FILENO);
	T_CHECK(saved_stdin >= 0);
	T_CHECK(dup2(filefd, STDIN_FILENO) == STDIN_FILENO);
	(void)close(filefd);
	struct config *conf = conf_parsefile("-");
	T_CHECK(dup2(saved_stdin, STDIN_FILENO) == STDIN_FILENO);
	(void)close(saved_stdin);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_dump_identity_fields)
{
	/* Verify that identity.claim and identity.mux_connect survive a
	 * dump/parse round-trip, exercising dump_identity_scope. */
	struct config *orig = conf_new();
	T_CHECK(orig != NULL);
	orig->mux_connect = strdup("127.0.0.1:7777");
	orig->identity.claim = strdup("mynode");
	T_CHECK(orig->mux_connect != NULL);
	T_CHECK(orig->identity.claim != NULL);
	orig->identity.mux_connect = malloc(sizeof(char *));
	T_CHECK(orig->identity.mux_connect != NULL);
	orig->identity.mux_connect[0] = strdup("127.0.0.1:9001");
	T_CHECK(orig->identity.mux_connect[0] != NULL);
	orig->identity.mux_connect_count = 1;

	char tmpl[] = "/tmp/conf_id_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_STREQ(reparsed->identity.claim, "mynode");
	T_EXPECT_EQ((int)reparsed->identity.mux_connect_count, 1);

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_identity_authcerts_parse_empty)
{
	/* Empty authcerts map is valid — no per-identity restrictions. */
	const char *json = "{"
			   "\"mux_connect\": \"127.0.0.1:9999\","
			   "\"identity\": {"
			   "  \"authcerts\": {}"
			   "}"
			   "}";
	struct config *conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.authcerts_count, 0);
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
	T_RUN_CASE(t, test_conf_parsefile_partial_window_config_accepted);
#if WITH_TLS
	T_RUN_CASE(t, test_conf_parsefile_rejects_partial_tls_config);
	T_RUN_CASE(t, test_conf_parsefile_authcerts_array);
	T_RUN_CASE(t, test_conf_dump_tls_fields);
	T_RUN_CASE(t, test_conf_inline_pem_replaces_at_path);
	T_RUN_CASE(t, test_conf_inline_pem_fails_for_missing_file);
#endif
	T_RUN_CASE(t, test_conf_parsefile_ignores_comment_keys);
	T_RUN_CASE(t, test_conf_parsefile_unknown_root_key);
	T_RUN_CASE(t, test_conf_parsefile_unknown_mux_key);
	T_RUN_CASE(t, test_conf_parsefile_mem_pressure_config);
	T_RUN_CASE(t, test_conf_parsefile_session_window_positive);
	T_RUN_CASE(t, test_conf_parsefile_both_windows_positive);
	T_RUN_CASE(t, test_conf_parsefile_max_startups_valid);
	T_RUN_CASE(t, test_conf_dump_identity_fields);
	T_RUN_CASE(t, test_conf_parsefile_rejects_oversized_file);
	T_RUN_CASE(t, test_conf_parsefile_stdin_success);
	T_RUN_CASE(t, test_conf_parsefile_stdin_rejects_oversized);
	T_RUN_CASE(t, test_identity_authcerts_parse_empty);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
