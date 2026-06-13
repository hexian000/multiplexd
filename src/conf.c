/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.c
 * @brief Configuration file parser.
 */

#include "conf.h"

#include "conf_schema.gen.h"
#include "mux/mux.h"

#include "codec/base64.h"
#include "codec/json.h"
#include "net/mime.h"
#include "utils/buffer.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONF_MIME_TYPE "application/x-multiplexd-config"
#define CONF_VERSION "1"
#define CONF_TYPE CONF_MIME_TYPE "; version=" CONF_VERSION

static bool
conf_parse_max_startups(struct config *restrict cfg, const char *restrict s)
{
	if (s == NULL) {
		return true;
	}
	const char *nptr = s;
	char *endptr = NULL;

	const uintmax_t start = strtoumax(nptr, &endptr, 10);
	if (endptr == nptr || *endptr != ':' || start > INT_MAX) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}
	nptr = endptr + 1;

	const uintmax_t rate = strtoumax(nptr, &endptr, 10);
	if (endptr == nptr || *endptr != ':' || rate > INT_MAX) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}
	nptr = endptr + 1;

	const uintmax_t full = strtoumax(nptr, &endptr, 10);
	if (endptr == nptr || *endptr != '\0' || full > INT_MAX) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}

	cfg->startup_limit_start = (int)start;
	cfg->startup_limit_rate = (int)rate;
	cfg->startup_limit_full = (int)full;
	return true;
}

static struct identity_peer *identity_listen_add(
	struct config *restrict conf, const char *restrict id, size_t id_len)
{
	const size_t n = conf->identity.peers_count;
	if (n >= SIZE_MAX / sizeof(*conf->identity.peers)) {
		LOGOOM();
		return NULL;
	}
	struct identity_peer *restrict entries = realloc(
		conf->identity.peers, (n + 1) * sizeof(*conf->identity.peers));
	if (entries == NULL) {
		LOGOOM();
		return NULL;
	}
	conf->identity.peers = entries;
	entries[n] = (struct identity_peer){
		.id = strndup(id, id_len),
		.listen = NULL,
	};
	if (entries[n].id == NULL) {
		LOGOOM();
		return NULL;
	}
	conf->identity.peers_count = n + 1;
	return &entries[n];
}

static bool identity_listen_cb(
	struct config *restrict conf, const char *restrict key, size_t key_len,
	char *restrict val, size_t val_len)
{
	char *s;
	size_t slen;
	if (!json_parse_string(val, val_len, &s, &slen)) {
		LOGE_F("identity.listen.%s: must be a string", key);
		return false;
	}
	struct identity_peer *restrict p =
		identity_listen_add(conf, key, key_len);
	if (p == NULL) {
		return false;
	}
	free(p->listen);
	p->listen = strndup(s, slen);
	if (p->listen == NULL) {
		LOGOOM();
		return false;
	}
	return true;
}

static struct conf_identity_authcert *identity_authcert_add(
	struct config *restrict conf, const char *restrict id, size_t id_len)
{
	const size_t n = conf->identity.authcerts_count;
	if (n >= SIZE_MAX / sizeof(*conf->identity.authcerts)) {
		LOGOOM();
		return NULL;
	}
	struct conf_identity_authcert *restrict entries =
		realloc(conf->identity.authcerts,
			(n + 1) * sizeof(*conf->identity.authcerts));
	if (entries == NULL) {
		LOGOOM();
		return NULL;
	}
	conf->identity.authcerts = entries;
	entries[n] = (struct conf_identity_authcert){
		.peer = strndup(id, id_len),
		.certs = NULL,
		.certs_count = 0,
	};
	if (entries[n].peer == NULL) {
		LOGOOM();
		return NULL;
	}
	conf->identity.authcerts_count = n + 1;
	return &entries[n];
}

/* Callback for parsing a single identity.authcerts entry value (JSON array of
 * certificate strings).  val points to the raw JSON text of the array. */
static bool identity_authcert_cb(
	struct config *restrict conf, const char *restrict key, size_t key_len,
	char *restrict val, size_t val_len)
{
	size_t consumed = val_len;
	struct json_val v = json_parse(val, &consumed);
	if (v.type != JSON_ARRAY) {
		LOGE_F("identity.authcerts.%s: must be an array", key);
		return false;
	}

	struct conf_identity_authcert *restrict ac =
		identity_authcert_add(conf, key, key_len);
	if (ac == NULL) {
		return false;
	}

	/* Parse each string element in the array. */
	json_iter it = v.iter;
	char *elem;
	size_t elem_len;
	size_t count = 0;
	int r;
	while ((r = json_arr_next(val, &val_len, &it, &elem, &elem_len)) ==
	       JSON_NEXT_ITEM) {
		char *cert_str;
		size_t cert_len;
		if (!json_parse_string(elem, elem_len, &cert_str, &cert_len)) {
			LOGE_F("identity.authcerts.%s[%zu]:"
			       " must be a string",
			       key, count);
			return false;
		}
		char **new_certs = (char **)realloc(
			(void *)ac->certs, (count + 1) * sizeof(*ac->certs));
		if (new_certs == NULL) {
			LOGOOM();
			return false;
		}
		ac->certs = new_certs;
		ac->certs[count] = strndup(cert_str, cert_len);
		if (ac->certs[count] == NULL) {
			LOGOOM();
			return false;
		}
		count++;
		/* Keep the count in sync so conf_free releases every element
		 * even when a later iteration fails. */
		ac->certs_count = count;
	}
	if (r != JSON_NEXT_END) {
		LOGE_F("identity.authcerts.%s: malformed array", key);
		return false;
	}
	/* Reject trailing content after the closing ']'. */
	while (it < val_len && json_iswhitespace((unsigned char)val[it])) {
		it++;
	}
	if (it != val_len) {
		LOGE_F("identity.authcerts.%s: unexpected trailing content",
		       key);
		return false;
	}
	return true;
}

/* Load raw schema struct into application config struct.
 * Strings are strdup'd since they are zero-copy pointers into the json buffer.
 * Returns false on error. */
static bool
conf_load(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	/* Root string fields: strndup zero-copy pointers using known lengths. */
#define STRNDUP_FIELD(dst, jstr)                                               \
	do {                                                                   \
		(dst) = (jstr).str != NULL ? strndup((jstr).str, (jstr).len) : \
					     NULL;                             \
		if ((jstr).str != NULL && (dst) == NULL) {                     \
			LOGOOM();                                              \
			return false;                                          \
		}                                                              \
	} while (0)
	STRNDUP_FIELD(cfg->type, obj->type);
	STRNDUP_FIELD(cfg->api_listen, obj->api_listen);
	STRNDUP_FIELD(cfg->mux_listen, obj->mux_listen);
	STRNDUP_FIELD(cfg->mux_connect, obj->mux_connect);
	STRNDUP_FIELD(cfg->listen, obj->listen);
	STRNDUP_FIELD(cfg->connect, obj->connect);
	STRNDUP_FIELD(cfg->log, obj->log);
#undef STRNDUP_FIELD

	cfg->loglevel = (int)obj->loglevel;
	cfg->max_sessions = (int)obj->max_sessions;
	if (!conf_parse_max_startups(cfg, obj->max_startups.str)) {
		return false;
	}

#if WITH_TLS
	cfg->tls_cert = obj->tls.cert.str != NULL ?
				strndup(obj->tls.cert.str, obj->tls.cert.len) :
				NULL;
	if (obj->tls.cert.str != NULL && cfg->tls_cert == NULL) {
		LOGOOM();
		return false;
	}
	cfg->tls_key = obj->tls.key.str != NULL ?
			       strndup(obj->tls.key.str, obj->tls.key.len) :
			       NULL;
	if (obj->tls.key.str != NULL && cfg->tls_key == NULL) {
		LOGOOM();
		return false;
	}
	cfg->tls_ciphersuites = obj->tls.ciphersuites.str != NULL ?
					strndup(obj->tls.ciphersuites.str,
						obj->tls.ciphersuites.len) :
					NULL;
	if (obj->tls.ciphersuites.str != NULL &&
	    cfg->tls_ciphersuites == NULL) {
		LOGOOM();
		return false;
	}
	if (obj->tls.authcerts_count > 0) {
		cfg->tls_authcerts = (char **)malloc(
			obj->tls.authcerts_count * sizeof(*cfg->tls_authcerts));
		if (cfg->tls_authcerts == NULL) {
			LOGOOM();
			return false;
		}
		cfg->tls_authcerts_count = obj->tls.authcerts_count;
		for (size_t i = 0; i < obj->tls.authcerts_count; i++) {
			cfg->tls_authcerts[i] =
				strndup(obj->tls.authcerts[i].str,
					obj->tls.authcerts[i].len);
			if (cfg->tls_authcerts[i] == NULL) {
				LOGOOM();
				cfg->tls_authcerts_count = i;
				return false;
			}
		}
	}
#endif /* WITH_TLS */

	cfg->mux.nodelay = obj->mux.nodelay;
	cfg->mux_tcp.tcp_reuseport = obj->mux.tcp.reuseport;
	cfg->mux_tcp.tcp_keepalive = obj->mux.tcp.keepalive;
	cfg->mux_tcp.tcp_nodelay = obj->mux.tcp.nodelay;
	cfg->mux_tcp.tcp_sndbuf = (int)obj->mux.tcp.sndbuf;
	cfg->mux_tcp.tcp_rcvbuf = (int)obj->mux.tcp.rcvbuf;
#if WITH_TCP_NOTSENT_LOWAT
	cfg->mux_tcp.tcp_notsent_lowat = (int)obj->mux.tcp.notsent_lowat;
#else
	if (obj->mux.tcp.notsent_lowat != 0) {
		LOGW("unknown config: \"mux.tcp.notsent_lowat\"");
	}
#endif
	cfg->mux_tcp.backlog = (int)obj->mux.tcp.backlog;
	cfg->mux.max_halfopen = (int)obj->mux.max_halfopen;
	cfg->mux.max_streams = (int)obj->mux.max_streams;
	cfg->mux.connect_timeout = (int)obj->mux.connect_timeout;
	cfg->mux.ping_timeout = (int)obj->mux.ping_timeout;
	cfg->mux.keepalive = (int)obj->mux.keepalive;
	cfg->mux.send_timeout = (int)obj->mux.send_timeout;
	cfg->mux.idle_timeout = (int)obj->mux.idle_timeout;
	cfg->mux.resume_timeout = (int)obj->mux.resume_timeout;
	{
		const uintmax_t session_window_bytes = obj->mux.session_window;
		if (session_window_bytes == 0) {
			cfg->mux.session_window = 0;
		} else {
			const uintmax_t session_window_frames =
				session_window_bytes / MUX_WINDOW_UNIT;
			cfg->mux.session_window = (int)CLAMP(
				session_window_frames, 4, UINT16_MAX);
		}
	}
	{
		const uintmax_t stream_window_bytes = obj->mux.stream_window;
		if (stream_window_bytes == 0) {
			cfg->mux.stream_window = 0;
		} else {
			const uintmax_t stream_window_frames =
				stream_window_bytes / MUX_WINDOW_UNIT;
			cfg->mux.stream_window =
				(int)CLAMP(stream_window_frames, 4, UINT16_MAX);
		}
	}
	cfg->mux.mem_pressure_hi = (int)obj->mux.mem_pressure.hi;
	cfg->mux.mem_pressure_lo = (int)obj->mux.mem_pressure.lo;

	cfg->tcp.tcp_reuseport = obj->tcp.reuseport;
	cfg->tcp.tcp_keepalive = obj->tcp.keepalive;
	cfg->tcp.tcp_nodelay = obj->tcp.nodelay;
	cfg->tcp.tcp_sndbuf = (int)obj->tcp.sndbuf;
	cfg->tcp.tcp_rcvbuf = (int)obj->tcp.rcvbuf;
#if WITH_TCP_NOTSENT_LOWAT
	cfg->tcp.tcp_notsent_lowat = (int)obj->tcp.notsent_lowat;
#else
	if (obj->tcp.notsent_lowat != 0) {
		LOGW("unknown config: \"tcp.notsent_lowat\"");
	}
#endif
	cfg->tcp.backlog = (int)obj->tcp.backlog;

	cfg->identity.claim = obj->identity.claim.str != NULL ?
				      strndup(obj->identity.claim.str,
					      obj->identity.claim.len) :
				      NULL;
	if (obj->identity.claim.str != NULL && cfg->identity.claim == NULL) {
		LOGOOM();
		return false;
	}
	if (obj->identity.mux_connect_count > 0) {
		cfg->identity.mux_connect = (char **)malloc(
			obj->identity.mux_connect_count *
			sizeof(*cfg->identity.mux_connect));
		if (cfg->identity.mux_connect == NULL) {
			LOGOOM();
			return false;
		}
		cfg->identity.mux_connect_count =
			obj->identity.mux_connect_count;
		for (size_t i = 0; i < obj->identity.mux_connect_count; i++) {
			cfg->identity.mux_connect[i] =
				strndup(obj->identity.mux_connect[i].str,
					obj->identity.mux_connect[i].len);
			if (cfg->identity.mux_connect[i] == NULL) {
				LOGOOM();
				cfg->identity.mux_connect_count = i;
				return false;
			}
		}
	}
	/* identity.listen: raw JSON fragment pointing into the json buffer.
	 * Walk it now and strdup each peer address before json_free_conf. */
	if (obj->identity.listen_json.str != NULL) {
		size_t frag_len = obj->identity.listen_json.len;
		struct json_val parsed =
			json_parse(obj->identity.listen_json.str, &frag_len);
		if (parsed.type != JSON_OBJECT) {
			LOGE("identity.listen: must be an object");
			return false;
		}
		json_iter it = parsed.iter;
		char *key;
		size_t key_len;
		char *val;
		size_t val_len;
		int r;
		while ((r = json_obj_next(
				obj->identity.listen_json.str,
				&obj->identity.listen_json.len, &it, &key,
				&key_len, &val, &val_len)) == JSON_NEXT_ITEM) {
			if (!identity_listen_cb(
				    cfg, key, key_len, val, val_len)) {
				return false;
			}
		}
		if (r != JSON_NEXT_END) {
			LOGE("identity.listen: malformed object");
			return false;
		}
		/* Reject trailing content after the closing '}' */
		while (it < obj->identity.listen_json.len &&
		       json_iswhitespace((unsigned char)obj->identity
						 .listen_json.str[it])) {
			it++;
		}
		if (it != obj->identity.listen_json.len) {
			LOGE("identity.listen: unexpected trailing content"
			     " after object");
			return false;
		}
	}

	/* identity.authcerts: raw JSON fragment → conf_identity_authcert[] */
	if (obj->identity.authcerts_json.str != NULL) {
		size_t frag_len = obj->identity.authcerts_json.len;
		struct json_val parsed =
			json_parse(obj->identity.authcerts_json.str, &frag_len);
		if (parsed.type != JSON_OBJECT) {
			LOGE("identity.authcerts: must be an object");
			return false;
		}
		json_iter it = parsed.iter;
		char *key;
		size_t key_len;
		char *val;
		size_t val_len;
		int r;
		while ((r = json_obj_next(
				obj->identity.authcerts_json.str,
				&obj->identity.authcerts_json.len, &it, &key,
				&key_len, &val, &val_len)) == JSON_NEXT_ITEM) {
			if (!identity_authcert_cb(
				    cfg, key, key_len, val, val_len)) {
				return false;
			}
		}
		if (r != JSON_NEXT_END) {
			LOGE("identity.authcerts: malformed object");
			return false;
		}
		while (it < obj->identity.authcerts_json.len &&
		       json_iswhitespace((unsigned char)obj->identity
						 .authcerts_json.str[it])) {
			it++;
		}
		if (it != obj->identity.authcerts_json.len) {
			LOGE("identity.authcerts: unexpected trailing content"
			     " after object");
			return false;
		}
	}

	return true;
}

static bool conf_check_type(const char *restrict type)
{
	if (type == NULL) {
		return true;
	}
	const size_t len = strlen(type);
	char buf[len + 1];
	memcpy(buf, type, len + 1);

	char *media_type, *media_subtype;
	char *next = mime_parse(buf, &media_type, &media_subtype);
	if (next == NULL || strcmp(media_type, "application") != 0 ||
	    strcmp(media_subtype, "x-multiplexd-config") != 0) {
		LOGE_F("unsupported config type: \"%s\"", type);
		return false;
	}

	const char *version = NULL;
	char *key, *value;
	next = mime_parseparam(next, &key, &value);
	while (next != NULL && key != NULL) {
		if (strcmp(key, "version") == 0) {
			version = value;
		}
		next = mime_parseparam(next, &key, &value);
	}
	if (version == NULL) {
		LOGE_F("config version not specified in: \"%s\"", type);
		return false;
	}
	if (strcmp(version, CONF_VERSION) != 0) {
		LOGE_F("incompatible config version: %s", version);
		return false;
	}
	return true;
}

static bool conf_check(struct config *restrict conf)
{
	if (!conf_check_type(conf->type)) {
		return false;
	}
	/* Validate that at least one transport subsystem is configured:
	 *   - global server:   mux_listen
	 *   - global client:   mux_connect
	 *   - identity client: identity.mux_connect entries */
	const bool has_mux_listen = (conf->mux_listen != NULL);
	const bool has_mux_connect = (conf->mux_connect != NULL);
	const bool has_identity_connect =
		(conf->identity.mux_connect_count > 0);
	if (!has_mux_listen && !has_mux_connect && !has_identity_connect) {
		LOGE("invalid configuration: at least one of the following"
		     " is required:\n"
		     "  - \"mux_listen\" (server mode)\n"
		     "  - \"mux_connect\" (client mode)\n"
		     "  - \"identity.mux_connect\" entries (identity client mode)");
		return false;
	}
	/* mux_listen and mux_connect are mutually exclusive for the global
	 * subsystem; identity.mux_connect can coexist with either. */
	if (has_mux_listen && has_mux_connect) {
		LOGW("ignoring mux_connect: not used in server mode");
	}
#if WITH_TLS
	const bool has_cert = (conf->tls_cert != NULL);
	const bool has_key = (conf->tls_key != NULL);
	const bool has_authcerts =
		(conf->tls_authcerts_count > 0 ||
		 conf->identity.authcerts_count > 0);

	if (has_cert && has_key && has_authcerts) {
		/* all three set: secure mode */
	} else if (!has_cert && !has_key && !has_authcerts) {
		LOGW("running in plaintext mode: connection is NOT encrypted");
	} else {
		LOGE("incomplete TLS configuration");
		return false;
	}
#endif
	conf->mux.ping_timeout = CLAMP(conf->mux.ping_timeout, 10, 86400);
	if (conf->mux.keepalive > 0) {
		conf->mux.keepalive = CLAMP(conf->mux.keepalive, 10, 86400);
	}
	if (conf->mux.send_timeout > 0) {
		conf->mux.send_timeout =
			CLAMP(conf->mux.send_timeout, 10, 86400);
	}
	conf->mux.connect_timeout = CLAMP(conf->mux.connect_timeout, 10, 86400);
	conf->mux.resume_timeout = CLAMP(conf->mux.resume_timeout, 10, 86400);
	if (conf->mux.idle_timeout > 0) {
		conf->mux.idle_timeout =
			CLAMP(conf->mux.idle_timeout, 10, 86400);
	} else {
		conf->mux.idle_timeout = 0;
	}
	conf->loglevel =
		CLAMP(conf->loglevel, LOG_LEVEL_SILENCE, LOG_LEVEL_VERYVERBOSE);
	/* Validate max_startups throttle parameters. */
	if (conf->startup_limit_rate > 100) {
		LOGE_F("max_startups rate (%d) exceeds 100:"
		       " every connection beyond start is dropped",
		       conf->startup_limit_rate);
		return false;
	}
	if (conf->startup_limit_start > 0 && conf->startup_limit_full > 0 &&
	    conf->startup_limit_start >= conf->startup_limit_full) {
		LOGE_F("max_startups start (%d) >= full (%d):"
		       " throttle range is empty",
		       conf->startup_limit_start, conf->startup_limit_full);
		return false;
	}
	/* Require identity.claim when identity entries are configured. */
	if ((conf->identity.mux_connect_count > 0 ||
	     conf->identity.peers_count > 0) &&
	    conf->identity.claim == NULL) {
		LOGE("identity.claim is required when identity.mux_connect or"
		     " identity.listen are configured");
		return false;
	}
	if (conf->identity.authcerts_count > 0 &&
	    conf->identity.claim == NULL) {
		LOGW("identity.claim is recommended when"
		     " identity.authcerts is configured");
	}
	return true;
}

static char *read_file(const char *restrict path, size_t *restrict lenp)
{
	FILE *fp;
	if (strcmp(path, "-") == 0) {
		fp = stdin;
	} else {
		fp = fopen(path, "r");
		if (fp == NULL) {
			LOGE_F("failed to open config file: %s", path);
			return NULL;
		}
	}
	/* The +1 allocation serves double duty: oversize detection and NUL
	 * termination. Both regular files and stdin are read the same way. */
	char *buf = malloc(CONF_MAXSIZE + 1);
	if (buf == NULL) {
		LOGOOM();
		if (fp != stdin) {
			(void)fclose(fp);
		}
		return NULL;
	}
	size_t n = 0;
	size_t rem = CONF_MAXSIZE + 1;
	while (rem > 0) {
		const size_t rd = fread(buf + n, 1, rem, fp);
		if (rd == 0) {
			if (ferror(fp)) {
				LOGE_F("failed to read config: %s", path);
				free(buf);
				if (fp != stdin) {
					(void)fclose(fp);
				}
				return NULL;
			}
			break;
		}
		n += rd;
		rem -= rd;
	}
	if (fp != stdin) {
		(void)fclose(fp);
	}
	if (n > CONF_MAXSIZE) {
		LOGE_F("config exceeds maximum size of %d bytes: %s",
		       CONF_MAXSIZE, path);
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	if (lenp != NULL) {
		*lenp = n;
	}
	return buf;
}

struct config *conf_new(void)
{
	struct config *restrict conf = malloc(sizeof(struct config));
	if (conf == NULL) {
		LOGOOM();
		return NULL;
	}
	*conf = (struct config){ 0 };
	char empty[] = "{}";
	struct json_conf obj = { 0 };
	if (!json_unmarshal_conf(&obj, empty, sizeof(empty) - 1)) {
		/* Cannot fail on a well-formed empty object; treat as OOM. */
		LOGOOM();
		free(conf);
		return NULL;
	}
	const bool ok = conf_load(conf, &obj);
	json_free_conf(&obj);
	if (!ok) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

struct config *conf_parse(char *json, const size_t len)
{
	struct config *restrict conf = malloc(sizeof(struct config));
	if (conf == NULL) {
		LOGOOM();
		return NULL;
	}
	*conf = (struct config){ 0 };
	struct json_conf obj = { 0 };
	if (!json_unmarshal_conf(&obj, json, len)) {
		LOGE("failed to process configuration");
		json_free_conf(&obj);
		conf_free(conf);
		return NULL;
	}
	const bool ok = conf_load(conf, &obj);
	json_free_conf(&obj);
	if (!ok) {
		LOGE("failed to process configuration");
		conf_free(conf);
		return NULL;
	}
	if (!conf_check(conf)) {
		LOGE("configuration validation failed");
		conf_free(conf);
		return NULL;
	}
	return conf;
}

struct config *conf_parsefile(const char *path)
{
	size_t len;
	char *buf = read_file(path, &len);
	if (buf == NULL) {
		return NULL;
	}
	struct config *conf = conf_parse(buf, len);
	free(buf);
	return conf;
}

/* Build a vbuffer containing the JSON object for the identity.listen map.
 * Returns NULL when no peers have listen addresses or on allocation failure. */
static struct vbuffer *build_listen_json(const struct config *restrict conf)
{
	struct vbuffer *vbuf = VBUF_NEW(64);
	if (vbuf == NULL) {
		LOGOOM();
		return NULL;
	}
	VBUF_APPEND(vbuf, "{", 1);
	bool first = true;
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		const struct identity_peer *restrict p =
			&conf->identity.peers[i];
		if (p->listen == NULL) {
			continue;
		}
		if (!first) {
			VBUF_APPEND(vbuf, ",", 1);
		}
		const size_t id_len = strlen(p->id);
		const size_t listen_len = strlen(p->listen);
		const int r_id = json_marshal_string(NULL, 0, p->id, id_len);
		const int r_val =
			json_marshal_string(NULL, 0, p->listen, listen_len);
		if (r_id < 0 || r_val < 0) {
			VBUF_FREE(vbuf);
			return NULL;
		}
		const size_t need = (size_t)r_id + 1u + (size_t)r_val;
		vbuf = vbuf_grow(vbuf, vbuf->len + need);
		if (vbuf->cap < vbuf->len + need) {
			VBUF_FREE(vbuf);
			LOGOOM();
			return NULL;
		}
		char *wp = (char *)vbuf->data + vbuf->len;
		wp += json_marshal_string(wp, (size_t)r_id + 1, p->id, id_len);
		*wp++ = ':';
		(void)json_marshal_string(
			wp, (size_t)r_val + 1, p->listen, listen_len);
		vbuf->len += need;
		first = false;
	}
	if (first) {
		VBUF_FREE(vbuf);
		return NULL; /* no peers with listen addresses */
	}
	VBUF_APPEND(vbuf, "}", 1);
	if (VBUF_HAS_OOM(vbuf)) {
		VBUF_FREE(vbuf);
		LOGOOM();
		return NULL;
	}
	/* The reserved byte provides NUL-termination for the caller. */
	vbuf->data[vbuf->len] = '\0';
	return vbuf;
}

/* Build a vbuffer containing the JSON object for identity.authcerts.
 * Returns NULL when no per-identity authcerts are configured or on OOM. */
static struct vbuffer *build_authcerts_json(const struct config *restrict conf)
{
	struct vbuffer *vbuf = VBUF_NEW(64);
	if (vbuf == NULL) {
		LOGOOM();
		return NULL;
	}
	VBUF_APPEND(vbuf, "{", 1);
	bool first = true;
	for (size_t i = 0; i < conf->identity.authcerts_count; i++) {
		const struct conf_identity_authcert *restrict ac =
			&conf->identity.authcerts[i];
		if (ac->certs_count == 0) {
			continue;
		}
		if (!first) {
			VBUF_APPEND(vbuf, ",", 1);
		}
		/* Marshal the key (peer identity string). */
		const size_t id_len = strlen(ac->peer);
		const int r_id = json_marshal_string(NULL, 0, ac->peer, id_len);
		if (r_id < 0) {
			VBUF_FREE(vbuf);
			return NULL;
		}
		/* Compute the total size needed for the array of cert
		 * strings: "[" + marshalled_certs + "]". */
		size_t arr_len = 1; /* '[' */
		for (size_t j = 0; j < ac->certs_count; j++) {
			if (j > 0) {
				arr_len++; /* ',' */
			}
			const int r_cert = json_marshal_string(
				NULL, 0, ac->certs[j], strlen(ac->certs[j]));
			if (r_cert < 0) {
				VBUF_FREE(vbuf);
				return NULL;
			}
			arr_len += (size_t)r_cert;
		}
		arr_len++; /* ']' */

		const size_t need = (size_t)r_id + 1u + arr_len;
		vbuf = vbuf_grow(vbuf, vbuf->len + need);
		if (vbuf->cap < vbuf->len + need) {
			VBUF_FREE(vbuf);
			LOGOOM();
			return NULL;
		}
		char *wp = (char *)vbuf->data + vbuf->len;
		wp += json_marshal_string(
			wp, (size_t)r_id + 1, ac->peer, id_len);
		*wp++ = ':';
		*wp++ = '[';
		for (size_t j = 0; j < ac->certs_count; j++) {
			if (j > 0) {
				*wp++ = ',';
			}
			const size_t cert_len = strlen(ac->certs[j]);
			const int r_cert = json_marshal_string(
				NULL, 0, ac->certs[j], cert_len);
			(void)json_marshal_string(
				wp, (size_t)r_cert + 1, ac->certs[j], cert_len);
			wp += r_cert;
		}
		*wp++ = ']';
		vbuf->len += need;
		first = false;
	}
	if (first) {
		VBUF_FREE(vbuf);
		return NULL;
	}
	VBUF_APPEND(vbuf, "}", 1);
	if (VBUF_HAS_OOM(vbuf)) {
		VBUF_FREE(vbuf);
		LOGOOM();
		return NULL;
	}
	vbuf->data[vbuf->len] = '\0';
	return vbuf;
}

char *conf_dump(const struct config *restrict conf, size_t *restrict lenp)
{
	struct vbuffer *listen_vbuf = build_listen_json(conf);
	char *listen_json =
		listen_vbuf != NULL ? (char *)listen_vbuf->data : NULL;
	const size_t listen_len = listen_vbuf != NULL ? listen_vbuf->len : 0;

	struct vbuffer *authcerts_vbuf = build_authcerts_json(conf);
	char *authcerts_json =
		authcerts_vbuf != NULL ? (char *)authcerts_vbuf->data : NULL;
	const size_t authcerts_json_len =
		authcerts_vbuf != NULL ? authcerts_vbuf->len : 0;

	struct json_string *id_mc_arr = NULL;
	if (conf->identity.mux_connect_count > 0) {
		id_mc_arr = malloc(
			conf->identity.mux_connect_count * sizeof(*id_mc_arr));
		if (id_mc_arr == NULL) {
			VBUF_FREE(listen_vbuf);
			VBUF_FREE(authcerts_vbuf);
			LOGOOM();
			return NULL;
		}
		for (size_t i = 0; i < conf->identity.mux_connect_count; i++) {
			id_mc_arr[i].str = conf->identity.mux_connect[i];
			id_mc_arr[i].len =
				strlen(conf->identity.mux_connect[i]);
		}
	}

#if WITH_TLS
	struct json_string *authcerts_arr = NULL;
	if (conf->tls_authcerts_count > 0) {
		authcerts_arr = malloc(
			conf->tls_authcerts_count * sizeof(*authcerts_arr));
		if (authcerts_arr == NULL) {
			free(id_mc_arr);
			VBUF_FREE(listen_vbuf);
			VBUF_FREE(authcerts_vbuf);
			LOGOOM();
			return NULL;
		}
		for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
			authcerts_arr[i].str = conf->tls_authcerts[i];
			authcerts_arr[i].len = strlen(conf->tls_authcerts[i]);
		}
	}
#endif /* WITH_TLS */

	/* Format max_startups string when any throttle value is non-zero. */
	char startups_buf[64];
	const char *max_startups = NULL;
	size_t max_startups_len = 0;
	if (conf->startup_limit_start > 0 || conf->startup_limit_rate > 0 ||
	    conf->startup_limit_full > 0) {
		max_startups_len = (size_t)snprintf(
			startups_buf, sizeof(startups_buf), "%d:%d:%d",
			conf->startup_limit_start, conf->startup_limit_rate,
			conf->startup_limit_full);
		max_startups = startups_buf;
	}

	const uintmax_t session_window_bytes =
		conf->mux.session_window != 0 ?
			(uintmax_t)conf->mux.session_window * MUX_WINDOW_UNIT :
			0;
	const uintmax_t stream_window_bytes =
		conf->mux.stream_window != 0 ?
			(uintmax_t)conf->mux.stream_window * MUX_WINDOW_UNIT :
			0;

	const char *const type_str =
		conf->type != NULL ? conf->type : CONF_TYPE;
	const struct json_conf raw = {
		.type = { .str = (char *)type_str, .len = strlen(type_str) },
		.api_listen = {
			.str = conf->api_listen,
			.len = conf->api_listen != NULL ?
				       strlen(conf->api_listen) :
				       0,
		},
		.mux_listen = {
			.str = conf->mux_listen,
			.len = conf->mux_listen != NULL ?
				       strlen(conf->mux_listen) :
				       0,
		},
		.mux_connect = {
			.str = conf->mux_connect,
			.len = conf->mux_connect != NULL ?
				       strlen(conf->mux_connect) :
				       0,
		},
		.listen = {
			.str = conf->listen,
			.len = conf->listen != NULL ? strlen(conf->listen) : 0,
		},
		.connect = {
			.str = conf->connect,
			.len = conf->connect != NULL ? strlen(conf->connect) : 0,
		},
		.log = {
			.str = conf->log,
			.len = conf->log != NULL ? strlen(conf->log) : 0,
		},
		.loglevel = (unsigned)conf->loglevel,
		.max_sessions = (uintmax_t)conf->max_sessions,
		.max_startups = {
			.str = (char *)max_startups,
			.len = max_startups_len,
		},
#if WITH_TLS
		.tls = {
			.cert = {
				.str = conf->tls_cert,
				.len = conf->tls_cert != NULL ?
					       strlen(conf->tls_cert) :
					       0,
			},
			.key = {
				.str = conf->tls_key,
				.len = conf->tls_key != NULL ?
					       strlen(conf->tls_key) :
					       0,
			},
			.ciphersuites = {
				.str = conf->tls_ciphersuites,
				.len = conf->tls_ciphersuites != NULL ?
					       strlen(conf->tls_ciphersuites) :
					       0,
			},
			.authcerts = authcerts_arr,
			.authcerts_count = conf->tls_authcerts_count,
		},
#endif /* WITH_TLS */
		.mux = {
			.nodelay = conf->mux.nodelay,
			.tcp = {
				.reuseport = conf->mux_tcp.tcp_reuseport,
				.keepalive = conf->mux_tcp.tcp_keepalive,
				.nodelay = conf->mux_tcp.tcp_nodelay,
				.sndbuf = (uintmax_t)conf->mux_tcp.tcp_sndbuf,
				.rcvbuf = (uintmax_t)conf->mux_tcp.tcp_rcvbuf,
#if WITH_TCP_NOTSENT_LOWAT
				.notsent_lowat =
					(uintmax_t)conf->mux_tcp
						.tcp_notsent_lowat,
#endif
				.backlog = (unsigned)conf->mux_tcp.backlog,
			},
			.max_halfopen = (unsigned)conf->mux.max_halfopen,
			.max_streams = (uintmax_t)conf->mux.max_streams,
			.connect_timeout = (unsigned)conf->mux.connect_timeout,

			.ping_timeout = (unsigned)conf->mux.ping_timeout,
			.keepalive = (unsigned)conf->mux.keepalive,
			.send_timeout = (unsigned)conf->mux.send_timeout,
			.idle_timeout = (unsigned)conf->mux.idle_timeout,
			.resume_timeout = (unsigned)conf->mux.resume_timeout,
		.session_window = (unsigned)session_window_bytes,
			.stream_window = (unsigned)stream_window_bytes,
			.mem_pressure = {
				.hi = (uintmax_t)conf->mux.mem_pressure_hi,
				.lo = (uintmax_t)conf->mux.mem_pressure_lo,
			},
		},
		.tcp = {
			.reuseport = conf->tcp.tcp_reuseport,
			.keepalive = conf->tcp.tcp_keepalive,
			.nodelay = conf->tcp.tcp_nodelay,
			.sndbuf = (uintmax_t)conf->tcp.tcp_sndbuf,
			.rcvbuf = (uintmax_t)conf->tcp.tcp_rcvbuf,
#if WITH_TCP_NOTSENT_LOWAT
			.notsent_lowat = (uintmax_t)conf->tcp.tcp_notsent_lowat,
#endif
			.backlog = (unsigned)conf->tcp.backlog,
		},
		.identity = {
			.claim = {
				.str = conf->identity.claim,
				.len = conf->identity.claim != NULL ?
					       strlen(conf->identity.claim) :
					       0,
			},
			.mux_connect = id_mc_arr,
			.mux_connect_count = conf->identity.mux_connect_count,
			.listen_json = {
				.str = listen_json,
				.len = listen_len,
			},
			.authcerts_json = {
				.str = authcerts_json,
				.len = authcerts_json_len,
			},
		},
	};

	/* Two-pass marshal: measure then fill. */
	const int json_sz = json_marshal_conf(NULL, 0, &raw);
	if (json_sz <= 0) {
		VBUF_FREE(listen_vbuf);
		VBUF_FREE(authcerts_vbuf);
		free(id_mc_arr);
#if WITH_TLS
		free(authcerts_arr);
#endif
		LOGOOM();
		return NULL;
	}
	char *out = malloc((size_t)json_sz + 1);
	if (out == NULL) {
		VBUF_FREE(listen_vbuf);
		VBUF_FREE(authcerts_vbuf);
		free(id_mc_arr);
#if WITH_TLS
		free(authcerts_arr);
#endif
		LOGOOM();
		return NULL;
	}
	(void)json_marshal_conf(out, (size_t)json_sz + 1, &raw);
	out[json_sz] = '\0';

	VBUF_FREE(listen_vbuf);
	VBUF_FREE(authcerts_vbuf);
	free(id_mc_arr);
#if WITH_TLS
	free(authcerts_arr);
#endif

	if (lenp != NULL) {
		*lenp = (size_t)json_sz;
	}
	return out;
}

#if WITH_TLS
static bool inline_field(char **restrict sp, const char *restrict name)
{
	if (*sp == NULL || **sp != '@') {
		return true;
	}
	char *content = read_file(*sp + 1, NULL);
	if (content == NULL) {
		LOGE_F("failed to inline PEM field: %s", name);
		return false;
	}
	free(*sp);
	*sp = content;
	return true;
}

/**
 * @brief Decode a PEM certificate to DER format.
 * @param pem  NUL-terminated PEM certificate string.
 * @param der_len  Output: DER length in bytes.
 * @return malloc'd DER buffer, or NULL on failure.
 */
static unsigned char *pem_cert_to_der(const char *pem, size_t *der_len)
{
	if (pem == NULL || der_len == NULL) {
		return NULL;
	}
	const char *begin = strstr(pem, "-----BEGIN CERTIFICATE-----");
	const char *end = strstr(pem, "-----END CERTIFICATE-----");
	if (begin == NULL || end == NULL || end <= begin) {
		return NULL;
	}
	begin = strchr(begin, '\n');
	if (begin == NULL) {
		return NULL;
	}
	begin++; /* skip newline after header */
	const char *body_end = end;
	while (body_end > begin &&
	       (body_end[-1] == '\n' || body_end[-1] == '\r' ||
		body_end[-1] == ' ' || body_end[-1] == '\t')) {
		body_end--;
	}
	const size_t b64_len = (size_t)(body_end - begin);
	if (b64_len == 0) {
		return NULL;
	}
	size_t dlen = (b64_len * 3) / 4 + 4;
	unsigned char *der = malloc(dlen);
	if (der == NULL) {
		return NULL;
	}
	if (!base64_decode(der, &dlen, (const unsigned char *)begin, b64_len)) {
		free(der);
		return NULL;
	}
	*der_len = dlen;
	return der;
}

bool conf_inline_pem(struct config *conf)
{
	if (!inline_field(&conf->tls_cert, "tls.cert") ||
	    !inline_field(&conf->tls_key, "tls.key")) {
		return false;
	}

	/* Inline @path references in both global and per-identity certs. */
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		if (!inline_field(&conf->tls_authcerts[i], "tls.authcerts")) {
			return false;
		}
	}
	for (size_t i = 0; i < conf->identity.authcerts_count; i++) {
		for (size_t j = 0; j < conf->identity.authcerts[i].certs_count;
		     j++) {
			if (!inline_field(
				    &conf->identity.authcerts[i].certs[j],
				    "identity.authcerts")) {
				return false;
			}
		}
	}

	/* Build the concatenated PEM bundle from all certs. */
	{
		size_t total = 0;
		for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
			total += strlen(conf->tls_authcerts[i]) + 1;
		}
		for (size_t i = 0; i < conf->identity.authcerts_count; i++) {
			for (size_t j = 0;
			     j < conf->identity.authcerts[i].certs_count; j++) {
				total += strlen(conf->identity.authcerts[i]
							.certs[j]) +
					 1;
			}
		}
		char *bundle = NULL;
		if (total > 0) {
			bundle = malloc(total + 1);
			if (bundle == NULL) {
				LOGOOM();
				return false;
			}
			size_t pos = 0;
			for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
				const size_t len =
					strlen(conf->tls_authcerts[i]);
				memcpy(bundle + pos, conf->tls_authcerts[i],
				       len);
				pos += len;
				bundle[pos++] = '\n';
			}
			for (size_t i = 0; i < conf->identity.authcerts_count;
			     i++) {
				for (size_t j = 0;
				     j <
				     conf->identity.authcerts[i].certs_count;
				     j++) {
					const size_t len = strlen(
						conf->identity.authcerts[i]
							.certs[j]);
					memcpy(bundle + pos,
					       conf->identity.authcerts[i]
						       .certs[j],
					       len);
					pos += len;
					bundle[pos++] = '\n';
				}
			}
			bundle[pos] = '\0';
		}
		conf->tls_authcerts_bundle = bundle;
	}

	/* Convert per-identity PEM certs to DER. */
	for (size_t i = 0; i < conf->identity.authcerts_count; i++) {
		struct conf_identity_authcert *restrict ac =
			&conf->identity.authcerts[i];
		const size_t n = ac->certs_count;
		if (n == 0) {
			continue;
		}
		ac->certs_der =
			(unsigned char **)calloc(n, sizeof(*ac->certs_der));
		ac->certs_der_len = calloc(n, sizeof(*ac->certs_der_len));
		if (ac->certs_der == NULL || ac->certs_der_len == NULL) {
			LOGOOM();
			return false;
		}
		for (size_t j = 0; j < n; j++) {
			ac->certs_der[j] = pem_cert_to_der(
				ac->certs[j], &ac->certs_der_len[j]);
			if (ac->certs_der[j] == NULL) {
				LOGE_F("identity.authcerts.%s[%zu]:"
				       " invalid PEM certificate",
				       ac->peer, j);
				return false;
			}
		}
	}

	return true;
}
#endif /* WITH_TLS */

void conf_free(struct config *restrict conf)
{
	if (conf == NULL) {
		return;
	}
	free(conf->type);
	free(conf->api_listen);
	free(conf->mux_listen);
	free(conf->mux_connect);
	free(conf->listen);
	free(conf->connect);
	free(conf->log);
#if WITH_TLS
	free(conf->tls_cert);
	free(conf->tls_key);
	free(conf->tls_ciphersuites);
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		free(conf->tls_authcerts[i]);
	}
	free((void *)conf->tls_authcerts);
	free(conf->tls_authcerts_bundle);
#endif
	free(conf->identity.claim);
	for (size_t i = 0; i < conf->identity.mux_connect_count; i++) {
		free(conf->identity.mux_connect[i]);
	}
	free((void *)conf->identity.mux_connect);
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		free(conf->identity.peers[i].id);
		free(conf->identity.peers[i].listen);
	}
	free(conf->identity.peers);
	for (size_t i = 0; i < conf->identity.authcerts_count; i++) {
		struct conf_identity_authcert *restrict ac =
			&conf->identity.authcerts[i];
		free(ac->peer);
		for (size_t j = 0; j < ac->certs_count; j++) {
			free(ac->certs[j]);
			/* certs_der is NULL unless conf_inline_pem succeeded */
			if (ac->certs_der != NULL) {
				free(ac->certs_der[j]);
			}
		}
		free((void *)ac->certs);
		free((void *)ac->certs_der);
		free(ac->certs_der_len);
	}
	free(conf->identity.authcerts);
	free(conf);
}

struct mux_config conf_get_mux(const struct config *conf)
{
	struct mux_config mc = conf->mux;
	mc.reject_inbound = (conf->connect == NULL);
	return mc;
}
