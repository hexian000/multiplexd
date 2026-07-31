/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* conf_test.c - black-box tests for the JSON config loader in conf.c via its
 * public API. Dependencies: links the real conf.c + generated schema. */

#include "conf.h"

#include "mux/mux.h"

#include "meta/arraysize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
	struct config *const conf = conf_new_default();
	T_CHECK(conf != NULL);
	T_EXPECT(conf->type == NULL);
	/* Default timeouts are positive, including the derived inactivity timeout
	 * (conf_new_default must derive it just like conf_check does). */
	T_EXPECT(conf->mux.keepalive > 0);
	T_EXPECT(conf->mux.timeout > 0);
	conf_free(conf);
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
	T_CHECK(a != NULL);
	struct config *const b =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
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
	conf_free(b);
	conf_free(a);
}

T_DECLARE_CASE(test_conf_parsefile_nonexistent)
{
	struct config *const conf =
		conf_parsefile("/nonexistent/path/that/cannot/exist.json");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_json)
{
	struct config *const conf = parse_tmpconf("{bad json");
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
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(
		conf->identity.claim, "\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_minimal_client)
{
	struct config *const conf =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
	T_CHECK(conf != NULL);
	T_CHECK(conf->mux_connect != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	T_EXPECT(conf->mux_listen == NULL);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_minimal_server)
{
	struct config *const conf =
		parse_tmpconf("{\"mux_listen\":\"127.0.0.1:9000\"}");
	T_CHECK(conf != NULL);
	T_CHECK(conf->mux_listen != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	T_EXPECT(conf->mux_connect == NULL);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_dump_roundtrip)
{
	struct config *const orig = conf_new_default();
	T_CHECK(orig != NULL);
	orig->mux_connect = strdup("127.0.0.1:7777");
	T_CHECK(orig->mux_connect != NULL);

	char tmpl[] = "/tmp/conf_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_CHECK(reparsed->mux_connect != NULL);
	T_EXPECT_STREQ(reparsed->mux_connect, "127.0.0.1:7777");
	/* type defaults to CONF_TYPE in conf_dump when unset */
	T_EXPECT(reparsed->type != NULL);

	conf_free(reparsed);
	conf_free(orig);
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
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(
		conf->mux.max_frame_payload,
		(int)(32768 - MUX_FRAME_HEADER_SIZE));

	/* Dump and reparse: the re-added header must reproduce the same payload. */
	char tmpl[] = "/tmp/conf_maxframe_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(conf, tmpl));
	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ(
		reparsed->mux.max_frame_payload, conf->mux.max_frame_payload);

	conf_free(reparsed);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_identity_connect_count)
{
	/* Identity-client mode: mux_connect lists destinations; claim is
	 * required alongside mux_connect. */
	struct config *const conf = parse_tmpconf(
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\",\"127.0.0.1:9002\"]}}");
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.mux_connect_count, 2);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_identity_verify_defaults_false)
{
	struct config *const conf =
		parse_tmpconf("{\"mux_connect\":\"127.0.0.1:9000\"}");
	T_CHECK(conf != NULL);
	T_EXPECT(!conf->identity.verify);
	conf_free(conf);
}

/* identity.verify has nothing to check without a peer certificate, so it is a
 * hard error rather than being silently ignored -- in a plaintext
 * configuration under WITH_TLS, and in any configuration without it. */
T_DECLARE_CASE(test_conf_identity_verify_requires_tls)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"verify\":true}}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_loglevel_parsed)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"loglevel\":3}");
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->loglevel, 3);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_requires_transport)
{
	struct config *const conf = parse_tmpconf("{}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_requires_claim_for_identity)
{
	struct config *const conf = parse_tmpconf(
		"{\"identity\":{\"mux_connect\":[\"127.0.0.1:9001\"]}}");
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
	T_EXPECT(rejected == NULL);

	struct config *const accepted = parse_tmpconf(
		"{\"mux_connect\":\"127.0.0.1:9000\",\"identity\":{\"claim\":\"mynode\",\"listen\":{\"peer1\":\"127.0.0.1:9002\"}}}");
	T_CHECK(accepted != NULL);
	conf_free(accepted);
}

/* mux_listen and mux_connect together are legal and both take effect: the
 * daemon accepts inbound sessions and maintains the outbound one.  Asserting
 * mux_connect survives conf_check is the point -- nothing clears it, and
 * server_reload_mux_tunnel dials it regardless of mux_listen. */
T_DECLARE_CASE(test_conf_parsefile_accepts_mux_listen_and_mux_connect)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"mux_connect\":\"127.0.0.1:9001\"}");
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9001");
	conf_free(conf);
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
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)strlen(conf->identity.claim), (int)MUX_MAX_CLAIM_LEN);
	conf_free(conf);
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
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)strlen(conf->listen), 261);
	conf_free(conf);
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
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_parses_identity_listen)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\",\"peer2\":\"127.0.0.1:9003\"}}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.mux_connect_count, 1);
	T_EXPECT_EQ((int)conf->identity.peers_count, 2);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9002");
	T_CHECK(find_peer(conf, "peer2") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer2")->listen, "127.0.0.1:9003");
	conf_free(conf);
}

/* build_listen_json's comma separator between identity.listen entries fires
 * only when a config carries two or more listen peers; a dump/reparse round-trip
 * of a two-peer config exercises it (a dropped comma emits invalid JSON that
 * fails to reparse). */
T_DECLARE_CASE(test_conf_dump_identity_listen_multi_peer_roundtrip)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\",\"peer2\":\"127.0.0.1:9003\"}}}";
	struct config *const orig = parse_tmpconf(json);
	T_CHECK(orig != NULL);
	T_CHECK((int)orig->identity.peers_count == 2);

	char tmpl[] = "/tmp/conf_listen_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));
	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->identity.peers_count, 2);
	T_CHECK(find_peer(reparsed, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "peer1")->listen, "127.0.0.1:9002");
	T_CHECK(find_peer(reparsed, "peer2") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "peer2")->listen, "127.0.0.1:9003");

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_conf_parsefile_identity_listen_duplicate_key_last_wins)
{
	/* identity_listen_add reuses the existing peer entry on a duplicate
	 * id instead of appending a second one, matching every other field's
	 * last-value-wins semantics. */
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\",\"peer1\":\"127.0.0.1:9004\"}}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.peers_count, 1);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9004");
	conf_free(conf);
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
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_identity_listen_value)
{
	/* identity.listen values bypass the schema's generated checks;
	 * conf_check's own length check must reject an oversized one
	 * instead of resolve_bindaddr failing much later in server.c. */
	char addr[263];
	memset(addr, 'a', sizeof(addr) - 1);
	addr[sizeof(addr) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"%s\"}}}",
		addr);
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

/* identity.listen keys are peer identity strings capped at 255 octets on the
 * wire; a longer key can never match a connecting peer, so conf_check must
 * reject it (the map keys bypass the schema's generated per-field checks). */
T_DECLARE_CASE(test_conf_parsefile_rejects_oversized_identity_listen_key)
{
	char key[257];
	memset(key, 'k', sizeof(key) - 1);
	key[sizeof(key) - 1] = '\0';
	char json[512];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"%s\":\"127.0.0.1:9002\"}}}",
		key);
	struct config *const conf = parse_tmpconf(json);
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
	T_EXPECT(conf == NULL);
}

/* conf_load_identity's identity.listen fragment is parsed twice: once
 * generically (as an opaque JSON_K_DYNAMIC fragment, by the schema
 * unmarshaller) and once explicitly (by conf_load_identity itself, which
 * must reject a fragment that isn't a JSON object). */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_non_object)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"listen\":\"not-an-object\"}}";
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

/* Unlike the schema-driven fields, identity.listen's own internal object
 * structure is walked by conf_load_identity by hand (json_obj_next), so a
 * malformed fragment (here: a key with no ':'/value) must be rejected
 * there instead of being silently accepted or crashing. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_malformed_json)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"listen\":{\"peer1\"}}}";
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

/* A "-"-prefixed comment key's value is accepted without being parsed as
 * well-formed JSON, so it can carry a malformed fragment.  Here the value
 * is an array holding an unmatched '{' ("[{]"): the raw-value scanner must
 * reject it on its own bracket-type mismatch (']' cannot close '{') rather
 * than mis-measuring the fragment and swallowing identity's own closing
 * brace.  Must be rejected gracefully (conf_parse -> NULL), never abort. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_bracket_mismatch)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"listen\":{\"-old\":[{], \"ok\":\"1.2.3.4:1\"}}}}";
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

/* identity.listen has no fixed key set, so identity_listen_cb must itself
 * special-case a "-"-prefixed key as a comment and skip it -- unlike a
 * known field name, the generic dispatcher's unknown-key tolerance never
 * gets a chance to apply here. */
T_DECLARE_CASE(test_conf_parsefile_identity_listen_skips_comment_key)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"-disabled\":\"127.0.0.1:9099\",\"peer1\":\"127.0.0.1:9002\"}}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->identity.peers_count, 1);
	T_CHECK(find_peer(conf, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(conf, "peer1")->listen, "127.0.0.1:9002");
	T_EXPECT(find_peer(conf, "-disabled") == NULL);
	T_EXPECT(find_peer(conf, "disabled") == NULL);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_identity_listen_rejects_non_string_value)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"listen\":{\"peer1\":123}}}";
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

/* A JSON \u0000 escape is legal and decodes to a literal
 * embedded NUL with a correct .len, but strndup() (used to materialize
 * every config string) stops at the first NUL regardless of .len -- so a
 * claim like "abc\u0000<200 more>" would silently truncate to "abc" after
 * passing the full-length maxLength check, letting the 255-octet wire
 * limit validate content that is never what actually gets stored or sent.
 * conf_strndup() must reject this outright instead of truncating. */
T_DECLARE_CASE(test_conf_parsefile_rejects_embedded_nul_in_identity_claim)
{
	const char *json =
		"{\"identity\":{\"claim\":\"abc\\u0000def\",\"mux_connect\":[\"127.0.0.1:9001\"]}}";
	struct config *const conf = parse_tmpconf(json);
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
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_format)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:20\"}";
	struct config *const conf = parse_tmpconf(json);
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
		T_EXPECT(conf == NULL);
		if (conf != NULL) {
			conf_free(conf);
		}
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
		T_EXPECT(conf == NULL);
		if (conf != NULL) {
			conf_free(conf);
		}
	}
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_rate)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:101:20\"}";
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_invalid_max_startups_range)
{
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"max_startups\":\"10:20:10\"}";
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_clamps_timeout_fields)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"keepalive\":5,\"send_timeout\":30,\"connect_timeout\":40,\"resume_timeout\":1,\"idle_timeout\":2},\"loglevel\":999}";
	struct config *const conf = parse_tmpconf(json);
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
	conf_free(conf);
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
	T_CHECK(conf != NULL);

	T_EXPECT_EQ(conf->mux.connect_timeout, 0);
	T_EXPECT_EQ(conf->mux.resume_timeout, 0);
	conf_free(conf);
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
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->max_sessions, INT_MAX);
	T_EXPECT_EQ(conf->mux.max_streams, INT_MAX);
	T_EXPECT_EQ(conf->mux.mem_pressure_hi, INT_MAX);
	T_EXPECT_EQ(conf->mux.mem_pressure_lo, INT_MAX);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_partial_window_config_accepted)
{
	/* stream_window set (manual), session_window absent (auto); each axis
	 * is independent so the mixed configuration is accepted as-is.
	 * 32768/16384=2 frames, clamped to the minimum of 4. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"stream_window\":32768}}";
	struct config *const conf = parse_tmpconf(json);
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
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

/* Builds "{"mux_listen":..., "tls": <tls_json>}" and expects rejection. */
T_DECLARE_SUBCASE(assert_partial_tls_rejected, const char *restrict tls_json)
{
	char json[256];
	(void)snprintf(
		json, sizeof(json),
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":%s}", tls_json);
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
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
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_authcerts_count, 2);
	T_EXPECT_STREQ(conf->tls_authcerts[0], "ca1.pem");
	T_EXPECT_STREQ(conf->tls_authcerts[1], "ca2.pem");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_dump_tls_fields)
{
	/* dump/parse round-trip for tls.cert, tls.key, tls.authcerts,
	 * socket_offload, and kernel_offload; both booleans set to true so
	 * a failed serialization would reparse as false. */
	struct config *const orig = conf_new_default();
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

	char tmpl[] = "/tmp/conf_tls_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_STREQ(reparsed->tls_cert, "certdata");
	T_EXPECT_STREQ(reparsed->tls_key, "keydata");
	T_EXPECT_EQ((int)reparsed->tls_authcerts_count, 1);
	T_EXPECT_STREQ(reparsed->tls_authcerts[0], "authcertdata");
	T_EXPECT(reparsed->tls_socket_offload);
	T_EXPECT(reparsed->tls_kernel_offload);

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_conf_load_tls_kernel_offload_defaults_with_socket_offload)
{
	/* kernel_offload's schema default is true; with socket_offload also on
	 * (explicitly, here), the "requires socket_offload" clamp does not
	 * apply and the default takes effect. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"certdata\",\"key\":\"keydata\",\"authcerts\":[\"ca1.pem\"],\"socket_offload\":true}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT(conf->tls_socket_offload);
	T_EXPECT(conf->tls_kernel_offload);
	conf_free(conf);
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
	T_CHECK(conf != NULL);
	T_EXPECT(!conf->tls_socket_offload);
	T_EXPECT(!conf->tls_kernel_offload);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_load_tls_kernel_offload_explicit_override)
{
	/* socket_offload on, kernel_offload explicitly disabled: the explicit
	 * `false` in the JSON must survive, not be overwritten back to the
	 * schema default of true. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"cert\":\"certdata\",\"key\":\"keydata\",\"authcerts\":[\"ca1.pem\"],\"socket_offload\":true,\"kernel_offload\":false}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT(conf->tls_socket_offload);
	T_EXPECT(!conf->tls_kernel_offload);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_inline_pem_replaces_at_path)
{
	/* conf_inline_pem must replace @path fields with the file's content. */
	char cert_tmpl[] = "/tmp/conf_inline_cert_XXXXXX";
	char key_tmpl[] = "/tmp/conf_inline_key_XXXXXX";
	T_CHECK(write_tmpfile(cert_tmpl, "CERTCONTENT") == 0);
	T_CHECK(write_tmpfile(key_tmpl, "KEYCONTENT") == 0);

	struct config *const conf = conf_new_default();
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

/* conf_inline_pem must build the trusted-cert bundle by concatenating every
 * authcert (a mix of inline and @path entries) with a '\n' separator and exact
 * sizing -- exercising bundle_append's per-cert len+1 accounting, which the
 * @path replacement tests never touch. */
T_DECLARE_CASE(test_conf_inline_pem_concatenates_authcerts_bundle)
{
	char ca_tmpl[] = "/tmp/conf_inline_ca_XXXXXX";
	T_CHECK(write_tmpfile(ca_tmpl, "CA_FROM_FILE") == 0);

	struct config *const conf = conf_new_default();
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

	(void)unlink(ca_tmpl);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_inline_pem_fails_for_missing_file)
{
	/* conf_inline_pem must return false if an @path file does not exist. */
	struct config *const conf = conf_new_default();
	T_CHECK(conf != NULL);
	conf->tls_cert = strdup("@/tmp/conf_inline_nonexistent_XXXXXX.pem");
	conf->tls_key = strdup("plaintext");
	T_CHECK(conf->tls_cert != NULL);
	T_CHECK(conf->tls_key != NULL);

	T_EXPECT(!conf_inline_pem(conf));
	conf_free(conf);
}

/* With TLS credentials present, identity.verify is accepted and survives a
 * dump/parse round-trip, so GET /config and --dump-config report it. */
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
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_psk_count, 2);
	T_EXPECT_STREQ(conf->tls_psk[0].id, "beta");
	T_EXPECT_STREQ(conf->tls_psk[1].id, "alpha");
	conf_free(conf);
}

/* "" is a valid identity (spec 5.2.3.2 sets no lower bound, and identity.claim
 * accepts it), so it must be a usable tls.psk key rather than being conflated
 * with "no entry" -- the same trap 2d33aea fixed for certificates. */
T_DECLARE_CASE(test_conf_psk_empty_identity)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"\":" PSK_HEX "}}}");
	T_CHECK(conf != NULL);
	T_EXPECT_EQ((int)conf->tls_psk_count, 1);
	T_EXPECT_STREQ(conf->tls_psk[0].id, "");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_psk_rejects_certificate_fields)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{"
		"\"cert\":\"c\",\"key\":\"k\",\"authcerts\":[\"a\"],"
		"\"psk\":{\"peer\":" PSK_HEX "}}}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_psk_rejects_identity_verify)
{
	/* PSK binds identity through the binder, so the certificate-mode
	 * switch has nothing to enable and is refused rather than ignored. */
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\","
		"\"identity\":{\"claim\":\"me\",\"verify\":true},"
		"\"tls\":{\"psk\":{\"peer\":" PSK_HEX "}}}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_psk_rejects_duplicate_identity)
{
	struct config *const conf = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"peer\":" PSK_HEX ",\"peer\":" PSK_HEX "}}}");
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_psk_rejects_bad_key)
{
	/* Length and alphabet are checked in conf_inline_pem(), once any
	 * "@path" is resolved, so drive that rather than conf_check(). */
	struct config *const shortkey = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"peer\":\"0101\"}}}");
	T_CHECK(shortkey != NULL);
	T_EXPECT(!conf_inline_pem(shortkey));
	conf_free(shortkey);

	/* Right length, wrong alphabet. */
	struct config *const nothex = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"peer\":\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"}}}");
	T_CHECK(nothex != NULL);
	T_EXPECT(!conf_inline_pem(nothex));
	conf_free(nothex);
}

T_DECLARE_CASE(test_conf_psk_dump_roundtrip)
{
	struct config *const orig = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\",\"tls\":{\"psk\":{"
		"\"peer\":" PSK_HEX "}}}");
	T_CHECK(orig != NULL);

	char tmpl[] = "/tmp/conf_psk_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->tls_psk_count, 1);
	T_EXPECT_STREQ(reparsed->tls_psk[0].id, "peer");

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_conf_identity_verify_with_tls_roundtrip)
{
	struct config *const orig = parse_tmpconf(
		"{\"mux_listen\":\"127.0.0.1:9000\","
		"\"identity\":{\"claim\":\"mynode\",\"verify\":true},"
		"\"tls\":{\"cert\":\"c\",\"key\":\"k\",\"authcerts\":[\"a\"]}}");
	T_CHECK(orig != NULL);
	T_EXPECT(orig->identity.verify);

	char tmpl[] = "/tmp/conf_id_verify_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT(reparsed->identity.verify);

	conf_free(reparsed);
	conf_free(orig);
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
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_unknown_root_key)
{
	/* Unknown keys at the root level must not fail parsing. */
	const char *json =
		"{\"mux_listen\":\"127.0.0.1:9000\",\"nosuchkey\":\"value\"}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_listen, "127.0.0.1:9000");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_unknown_mux_key)
{
	/* Unknown keys inside a scope must not fail parsing. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"nosuchfield\":1}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_STREQ(conf->mux_connect, "127.0.0.1:9000");
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_mem_pressure_config)
{
	/* Verify that the mux.mem_pressure sub-object is parsed correctly. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"mem_pressure\":{\"hi\":1000,\"lo\":500}}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.mem_pressure_hi, 1000);
	T_EXPECT_EQ(conf->mux.mem_pressure_lo, 500);
	conf_free(conf);
}

/* conf_check() must resolve "lo omitted" to hi/2 once at load time (an
 * odd hi exercises the truncating division) so every session reads an
 * already-concrete threshold instead of re-deriving it per grant. */
T_DECLARE_CASE(test_conf_parsefile_mem_pressure_lo_defaults_to_half_hi)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"mem_pressure\":{\"hi\":1001}}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	T_EXPECT_EQ(conf->mux.mem_pressure_hi, 1001);
	T_EXPECT_EQ(conf->mux.mem_pressure_lo, 500);
	conf_free(conf);
}

/* An explicitly inverted mem_pressure range (positive lo > positive hi) is
 * rejected by conf_check. */
T_DECLARE_CASE(test_conf_parsefile_rejects_inverted_mem_pressure)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"mem_pressure\":{\"hi\":500,\"lo\":1000}}}";
	struct config *const conf = parse_tmpconf(json);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_parsefile_session_window_positive)
{
	/* Setting only session_window (auto stream_window) is now valid:
	 * each axis is independent.  65536/16384=4 frames. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"session_window\":65536}}";
	struct config *const conf = parse_tmpconf(json);
	T_CHECK(conf != NULL);
	/* session_window stored as frames; stream_window not set (auto). */
	T_EXPECT_EQ(conf->mux.session_window, 4);
	T_EXPECT_EQ(conf->mux.stream_window, 0);
	conf_free(conf);
}

T_DECLARE_CASE(test_conf_parsefile_both_windows_positive)
{
	/* Both windows positive: stored as frame counts (/ MUX_WINDOW_UNIT),
	 * clamped to [4, max]. 32768/16384=2 → 4; 131072/16384=8 in range. */
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"stream_window\":32768,\"session_window\":131072}}";
	struct config *const conf = parse_tmpconf(json);
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
	struct config *const conf = parse_tmpconf(json);
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
	struct config *const conf = conf_parsefile(tmpl);
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
	struct config *const conf = conf_parsefile("-");
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
	struct config *const conf = conf_parsefile("-");
	T_CHECK(dup2(saved_stdin, STDIN_FILENO) == STDIN_FILENO);
	(void)close(saved_stdin);
	T_EXPECT(conf == NULL);
}

T_DECLARE_CASE(test_conf_dump_identity_fields)
{
	/* Verify that identity.claim and identity.mux_connect survive a
	 * dump/parse round-trip. */
	struct config *const orig = conf_new_default();
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

	char tmpl[] = "/tmp/conf_id_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_STREQ(reparsed->identity.claim, "mynode");
	T_EXPECT_EQ((int)reparsed->identity.mux_connect_count, 1);

	conf_free(reparsed);
	conf_free(orig);
}

/* Regression test: conf_dump must fail (return NULL) rather than silently
 * dropping identity.listen when build_listen_json signals failure -- this
 * pins the success path so a wrong-polarity failure signal never resurfaces. */
T_DECLARE_CASE(test_conf_dump_identity_listen_roundtrip)
{
	const char *json =
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"peer1\":\"127.0.0.1:9002\"}}}";
	struct config *const orig = parse_tmpconf(json);
	T_CHECK(orig != NULL);
	T_EXPECT_EQ((int)orig->identity.peers_count, 1);

	char tmpl[] = "/tmp/conf_listen_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->identity.peers_count, 1);
	T_CHECK(find_peer(reparsed, "peer1") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "peer1")->listen, "127.0.0.1:9002");

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_conf_dump_identity_listen_exact_grow_boundary)
{
	/* A single peer whose id+listen json_marshal_string lengths sum so
	 * build_listen_json's vbuf_grow request lands exactly on VBUF_NEW's
	 * initial capacity (64): id "k" (1 byte) + listen (58 bytes) + 5
	 * bytes of quote/colon overhead = 64. Without vbuf_grow's +1 headroom,
	 * this landed exactly on the OOM sentinel (len == cap) and made
	 * conf_dump spuriously fail (or, with 2+ peers, silently drop a
	 * separating comma) for a perfectly valid config. */
	char listen_val[59];
	memset(listen_val, 'x', sizeof(listen_val) - 1);
	listen_val[sizeof(listen_val) - 1] = '\0';
	char json[256];
	(void)snprintf(
		json, sizeof(json),
		"{\"identity\":{\"claim\":\"mynode\",\"mux_connect\":[\"127.0.0.1:9001\"],\"listen\":{\"k\":\"%s\"}}}",
		listen_val);
	struct config *const orig = parse_tmpconf(json);
	T_CHECK(orig != NULL);
	T_EXPECT_EQ((int)orig->identity.peers_count, 1);

	char tmpl[] = "/tmp/conf_listen_boundary_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ((int)reparsed->identity.peers_count, 1);
	T_CHECK(find_peer(reparsed, "k") != NULL);
	T_EXPECT_STREQ(find_peer(reparsed, "k")->listen, listen_val);

	conf_free(reparsed);
	conf_free(orig);
}

T_DECLARE_CASE(test_conf_dump_readahead_roundtrip)
{
	const char *json =
		"{\"mux_connect\":\"127.0.0.1:9000\",\"mux\":{\"readahead\":65536}}";
	struct config *const orig = parse_tmpconf(json);
	T_CHECK(orig != NULL);
	T_EXPECT_EQ(orig->mux.readahead, 65536);

	char tmpl[] = "/tmp/conf_readahead_dump_XXXXXX";
	const int fd = mkstemp(tmpl);
	T_CHECK(fd >= 0);
	(void)close(fd);
	T_CHECK(write_conf_file(orig, tmpl));

	struct config *const reparsed = conf_parsefile(tmpl);
	(void)unlink(tmpl);
	T_CHECK(reparsed != NULL);
	T_EXPECT_EQ(reparsed->mux.readahead, 65536);

	conf_free(reparsed);
	conf_free(orig);
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
		T_EXPECT(conf != NULL);
		conf_free(conf);
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
		T_EXPECT(conf == NULL);
		conf_free(conf);
	}
}

static const struct testing_suite suite[] = {
	T_CASE(test_conf_new_default_fields),
	T_CASE(test_conf_new_default_matches_empty_parse),
	T_CASE(test_conf_parsefile_nonexistent),
	T_CASE(test_conf_parsefile_invalid_json),
	T_CASE(test_conf_parsefile_rejects_invalid_utf8),
	T_CASE(test_conf_parsefile_accepts_well_formed_utf8),
	T_CASE(test_conf_parsefile_minimal_client),
	T_CASE(test_conf_parsefile_minimal_server),
	T_CASE(test_conf_dump_roundtrip),
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
	T_CASE(test_conf_parsefile_rejects_oversized_identity_listen_key),
	T_CASE(test_conf_parsefile_rejects_oversized_identity_mux_connect),
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
	T_CASE(test_conf_parsefile_rejects_partial_tls_config),
	T_CASE(test_conf_parsefile_rejects_partial_tls_config_combinations),
	T_CASE(test_conf_parsefile_authcerts_array),
	T_CASE(test_conf_dump_tls_fields),
	T_CASE(test_conf_load_tls_kernel_offload_defaults_with_socket_offload),
	T_CASE(test_conf_load_tls_kernel_offload_off_without_socket_offload),
	T_CASE(test_conf_load_tls_kernel_offload_explicit_override),
	T_CASE(test_conf_inline_pem_replaces_at_path),
	T_CASE(test_conf_inline_pem_concatenates_authcerts_bundle),
	T_CASE(test_conf_inline_pem_fails_for_missing_file),
	T_CASE(test_conf_identity_verify_with_tls_roundtrip),
	T_CASE(test_conf_psk_parsed_in_order),
	T_CASE(test_conf_psk_empty_identity),
	T_CASE(test_conf_psk_rejects_certificate_fields),
	T_CASE(test_conf_psk_rejects_identity_verify),
	T_CASE(test_conf_psk_rejects_duplicate_identity),
	T_CASE(test_conf_psk_rejects_bad_key),
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
	T_CASE(test_conf_dump_identity_listen_roundtrip),
	T_CASE(test_conf_dump_identity_listen_exact_grow_boundary),
	T_CASE(test_conf_parsefile_rejects_oversized_file),
	T_CASE(test_conf_parsefile_stdin_success),
	T_CASE(test_conf_parsefile_stdin_rejects_oversized),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
