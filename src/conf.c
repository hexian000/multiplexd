/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.c
 * @brief Configuration file parser.
 */

#include "conf.h"

#include "conf_schema.gen.h"

#include "codec/json.h"

#include "mux/mux.h"
#include "net/mime.h"
#include "utils/buffer.h"
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

static struct identity_peer *identity_listen_upsert(
	struct config *restrict conf, const char *restrict id, size_t id_len)
{
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		if (strcmp(conf->identity.peers[i].id, id) == 0) {
			return &conf->identity.peers[i];
		}
	}
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
	if (key[0] == '-') {
		return true;
	}
	struct json_val v = json_parse(val, val_len);
	if (v.type != JSON_STRING) {
		LOGE_F("identity.listen.%s: must be a string", key);
		return false;
	}
	struct identity_peer *restrict p =
		identity_listen_upsert(conf, key, key_len);
	if (p == NULL) {
		return false;
	}
	free(p->listen);
	p->listen = strndup(v.str, v.len);
	if (p->listen == NULL) {
		LOGOOM();
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
	cfg->mux.timeout = (int)obj->mux.timeout;
	cfg->mux.ping_timeout = (int)obj->mux.ping_timeout;
	cfg->mux.keepalive = (int)obj->mux.keepalive;
	cfg->mux.send_timeout = (int)obj->mux.send_timeout;
	cfg->mux.idle_timeout = (int)obj->mux.idle_timeout;
	cfg->mux.resume_timeout = (int)obj->mux.resume_timeout;
	{
		const uintmax_t v = obj->mux.session_window;
		if (v == 0) {
			cfg->mux.session_window = 0;
		} else {
			cfg->mux.session_window = (int)CLAMP(
				v / MUX_MAX_PAYLOAD_SIZE,
				MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT,
				16384);
		}
	}
	{
		const uintmax_t v = obj->mux.stream_window;
		if (v == 0) {
			cfg->mux.stream_window = 0;
		} else {
			cfg->mux.stream_window =
				(int)CLAMP(v / MUX_MAX_PAYLOAD_SIZE, 1, 1024);
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
	 * Walk it now and strdup each peer address before json_conf_free. */
	if (obj->identity.listen_json.str != NULL) {
		struct json_val parsed = json_parse(
			obj->identity.listen_json.str,
			obj->identity.listen_json.len);
		if (parsed.type != JSON_OBJECT) {
			LOGE("identity.listen: must be an object");
			return false;
		}
		json_iter it = parsed.iter;
		char *key;
		size_t key_len;
		char *val;
		size_t val_len;
		while (json_obj_next(
			obj->identity.listen_json.str,
			obj->identity.listen_json.len, &it, &key, &key_len,
			&val, &val_len)) {
			if (!identity_listen_cb(
				    cfg, key, key_len, val, val_len)) {
				return false;
			}
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
	/* Check TLS configuration */
	const bool has_cert = (conf->tls_cert != NULL);
	const bool has_key = (conf->tls_key != NULL);
	const bool has_authcerts = (conf->tls_authcerts_count > 0);

	if (has_cert && has_key && has_authcerts) {
		/* Complete TLS configuration - run in secure mode */
	} else if (!has_cert && !has_key && !has_authcerts) {
		/* No TLS configuration - run in plaintext mode */
		LOGW("running in plaintext mode: connection is NOT encrypted\n"
		     "  configure tls.cert, tls.key, and tls.authcerts for secure communication");
	} else {
		/* Partial TLS configuration is an error */
		LOGE("incomplete TLS configuration:");
		if (!has_cert) {
			LOGE("  missing: tls.cert");
		}
		if (!has_key) {
			LOGE("  missing: tls.key");
		}
		if (!has_authcerts) {
			LOGE("  missing: tls.authcerts");
		}
		return false;
	}
#endif
	conf->mux.timeout = CLAMP(conf->mux.timeout, 10, 86400);
	conf->mux.ping_timeout = CLAMP(conf->mux.ping_timeout, 10, 86400);
	if (conf->mux.keepalive > 0) {
		if (conf->mux.keepalive > conf->mux.timeout) {
			LOGW_F("mux.keepalive (%d) > mux.timeout (%d): "
			       "mux.keepalive will be clamped to mux.timeout",
			       conf->mux.keepalive, conf->mux.timeout);
		}
		conf->mux.keepalive =
			CLAMP(conf->mux.keepalive, 10, conf->mux.timeout);
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
	if (conf->mux.max_halfopen > 0) {
		conf->mux.max_halfopen = CLAMP(conf->mux.max_halfopen, 1, 4096);
	}
	if (conf->mux.stream_window > 0) {
		conf->mux.stream_window =
			CLAMP(conf->mux.stream_window, 1, 1024);
	}
	if (conf->mux.session_window > 0) {
		conf->mux.session_window =
			CLAMP(conf->mux.session_window,
			      (int)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT),
			      INT_MAX);
	}
	/* Automatic window mode requires both values to be 0; a mixed
	 * configuration (exactly one is 0) is not supported. Warn and
	 * normalize both to 0 so automatic BDP sizing is used. */
	if ((conf->mux.stream_window <= 0) != (conf->mux.session_window <= 0)) {
		LOGW("mux.stream_window and mux.session_window must both be 0 "
		     "(automatic BDP sizing) or both be > 0 (manual); "
		     "mixed configuration treated as automatic mode");
		conf->mux.stream_window = 0;
		conf->mux.session_window = 0;
	}
	conf->mux_tcp.backlog = CLAMP(conf->mux_tcp.backlog, 1, 4096);
	conf->tcp.backlog = CLAMP(conf->tcp.backlog, 1, 4096);
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
	/* Validate identity peers: no duplicate peer IDs. */
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		for (size_t j = i + 1; j < conf->identity.peers_count; j++) {
			if (strcmp(conf->identity.peers[i].id,
				   conf->identity.peers[j].id) == 0) {
				LOGE_F("duplicate identity.listen peer id: \"%s\"",
				       conf->identity.peers[i].id);
				return false;
			}
		}
	}
	/* Require identity.claim when identity entries are configured. */
	if ((conf->identity.mux_connect_count > 0 ||
	     conf->identity.peers_count > 0) &&
	    conf->identity.claim == NULL) {
		LOGE("identity.claim is required when identity.mux_connect or"
		     " identity.listen are configured");
		return false;
	}
	return true;
}

static char *read_file(const char *restrict path, size_t *restrict lenp)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		LOGE_F("failed to open file: %s", path);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		LOGE_F("failed to seek file: %s", path);
		(void)fclose(fp);
		return NULL;
	}
	const long size = ftell(fp);
	if (size < 0) {
		LOGE_F("failed to get size of file: %s", path);
		(void)fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		LOGE_F("failed to seek file: %s", path);
		(void)fclose(fp);
		return NULL;
	}
	char *buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		LOGOOM();
		(void)fclose(fp);
		return NULL;
	}
	const size_t n = fread(buf, 1, (size_t)size, fp);
	(void)fclose(fp);
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
	if (!json_conf_unmarshal(&obj, empty, sizeof(empty) - 1)) {
		/* Cannot fail on a well-formed empty object; treat as OOM. */
		LOGOOM();
		free(conf);
		return NULL;
	}
	const bool ok = conf_load(conf, &obj);
	json_conf_free(&obj);
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
	if (!json_conf_unmarshal(&obj, json, len)) {
		LOGE("failed to process configuration");
		json_conf_free(&obj);
		conf_free(conf);
		return NULL;
	}
	const bool ok = conf_load(conf, &obj);
	json_conf_free(&obj);
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

char *conf_dump(const struct config *restrict conf, size_t *restrict lenp)
{
	/* Build identity.listen JSON fragment if peers exist. */
	struct vbuffer *listen_vbuf = build_listen_json(conf);
	char *listen_json =
		listen_vbuf != NULL ? (char *)listen_vbuf->data : NULL;
	const size_t listen_len = listen_vbuf != NULL ? listen_vbuf->len : 0;

	/* Build json_string arrays for identity.mux_connect. */
	struct json_string *id_mc_arr = NULL;
	if (conf->identity.mux_connect_count > 0) {
		id_mc_arr = malloc(
			conf->identity.mux_connect_count * sizeof(*id_mc_arr));
		if (id_mc_arr == NULL) {
			VBUF_FREE(listen_vbuf);
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
	/* Build json_string arrays for tls.authcerts. */
	struct json_string *authcerts_arr = NULL;
	if (conf->tls_authcerts_count > 0) {
		authcerts_arr = malloc(
			conf->tls_authcerts_count * sizeof(*authcerts_arr));
		if (authcerts_arr == NULL) {
			free(id_mc_arr);
			VBUF_FREE(listen_vbuf);
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

	/* Convert window fields from internal frame units to bytes. */
	const uintmax_t session_window_bytes =
		conf->mux.session_window != 0 ?
			(uintmax_t)conf->mux.session_window *
				MUX_MAX_PAYLOAD_SIZE :
			0;
	const uintmax_t stream_window_bytes =
		conf->mux.stream_window != 0 ?
			(uintmax_t)conf->mux.stream_window *
				MUX_MAX_PAYLOAD_SIZE :
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
			.timeout = (unsigned)conf->mux.timeout,
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
		},
	};

	/* Two-pass marshal: measure then fill. */
	const int json_sz = json_conf_marshal(NULL, 0, &raw);
	if (json_sz <= 0) {
		VBUF_FREE(listen_vbuf);
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
		free(id_mc_arr);
#if WITH_TLS
		free(authcerts_arr);
#endif
		LOGOOM();
		return NULL;
	}
	(void)json_conf_marshal(out, (size_t)json_sz + 1, &raw);
	out[json_sz] = '\0';

	VBUF_FREE(listen_vbuf);
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

bool conf_inline_pem(struct config *conf)
{
	if (!inline_field(&conf->tls_cert, "tls.cert") ||
	    !inline_field(&conf->tls_key, "tls.key")) {
		return false;
	}
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		if (!inline_field(&conf->tls_authcerts[i], "tls.authcerts")) {
			return false;
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
#if WITH_TLS
	free(conf->tls_cert);
	free(conf->tls_key);
	free(conf->tls_ciphersuites);
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		free(conf->tls_authcerts[i]);
	}
	free((void *)conf->tls_authcerts);
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
	free(conf);
}

struct mux_config conf_get_mux(const struct config *conf)
{
	struct mux_config mc = conf->mux;
	mc.reject_inbound = (conf->connect == NULL);
	return mc;
}
