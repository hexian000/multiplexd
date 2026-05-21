/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.c
 * @brief Configuration file parser using json-c.
 */

#include "conf.h"

#include "jsonutil.h"

#include "net/mime.h"
#include "utils/arraysize.h"
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

enum field_type {
	FIELD_STRING,
	FIELD_INT,
	FIELD_BOOL,
};

struct field_desc {
	const char *key;
	enum field_type type;
	size_t offset;
};

static bool parse_one_field(
	void *restrict base, const struct field_desc *restrict desc,
	const struct jutil_value *restrict value)
{
	void *const ptr = (char *)base + desc->offset;
	switch (desc->type) {
	case FIELD_STRING: {
		char **const field = ptr;
		*field = jutil_dup_string(value);
		return *field != NULL;
	}
	case FIELD_INT: {
		int *const field = ptr;
		return jutil_get_int(value, field);
	}
	case FIELD_BOOL: {
		bool *const field = ptr;
		return jutil_get_bool(value, field);
	}
	}
	return false;
}

/* Handler for a named config key with non-trivial parsing logic. */
struct scope_handler {
	const char *key;
	bool (*fn)(void *ud, const struct jutil_value *value);
};

/* Dispatch one key-value pair within a config scope.
 *
 * Keys beginning with '-' are silently skipped (comment-out syntax).
 * `base` is the offsetof base for field table lookup (parse_one_field).
 * `ud` is passed through to scope_handler.fn calls.
 * When `scope` is NULL the root-scope warning format is used; otherwise
 * the warning reads "scope.key". */
static bool scope_dispatch(
	void *base, void *ud, const char *scope, const char *key,
	const struct jutil_value *value, const struct field_desc *fields,
	size_t nfields, const struct scope_handler *handlers, size_t nhandlers)
{
	if (key[0] == '-') {
		return true;
	}
	for (size_t i = 0; i < nfields; i++) {
		if (strcmp(key, fields[i].key) == 0) {
			return parse_one_field(base, &fields[i], value);
		}
	}
	for (size_t i = 0; i < nhandlers; i++) {
		if (strcmp(key, handlers[i].key) == 0) {
			return handlers[i].fn(ud, value);
		}
	}
	if (scope != NULL) {
		LOGW_F("unknown config: \"%s.%s\"", scope, key);
	} else {
		LOGW_F("unknown config: `%s'", key);
	}
	return true;
}

#if WITH_TLS
struct authcerts {
	char **certs;
	size_t count;
	size_t capacity;
};

static bool authcerts_array_cb(void *ud, const struct jutil_value *elem)
{
	struct authcerts *c = ud;
	char *s = jutil_dup_string(elem);
	if (s == NULL) {
		LOGE("failed to parse authcerts array element");
		return false;
	}
	if (c->count >= c->capacity) {
		size_t new_cap = 4;
		if (c->capacity != 0) {
			if (c->capacity > SIZE_MAX / 2) {
				LOGOOM();
				free(s);
				return false;
			}
			new_cap = c->capacity * 2;
		}
		if (new_cap > SIZE_MAX / sizeof(*c->certs)) {
			LOGOOM();
			free(s);
			return false;
		}
		char **new_certs =
			realloc(c->certs, new_cap * sizeof(*c->certs));
		if (new_certs == NULL) {
			LOGOOM();
			free(s);
			return false;
		}
		c->certs = new_certs;
		c->capacity = new_cap;
	}
	c->certs[c->count++] = s;
	return true;
}

static bool parse_tls_authcerts(void *ud, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	struct authcerts ctx = { NULL, 0, 0 };
	const bool ok = jutil_walk_array(&ctx, value, authcerts_array_cb);
	if (!ok) {
		LOGE("failed to parse tls.authcerts");
		for (size_t i = 0; i < ctx.count; i++) {
			free(ctx.certs[i]);
		}
		free(ctx.certs);
		return false;
	}
	conf->authcerts = ctx.certs;
	conf->authcerts_count = ctx.count;
	return true;
}

static const struct field_desc tls_field_table[] = {
	{ "cert", FIELD_STRING, offsetof(struct config, tls_cert) },
	{ "key", FIELD_STRING, offsetof(struct config, tls_key) },
	{ "ciphersuites", FIELD_STRING,
	  offsetof(struct config, tls_ciphersuites) },
};

static const struct scope_handler tls_handlers[] = {
	{ "authcerts", parse_tls_authcerts },
};

static bool
tls_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	return scope_dispatch(
		ud, ud, "tls", key, value, tls_field_table,
		ARRAY_SIZE(tls_field_table), tls_handlers,
		ARRAY_SIZE(tls_handlers));
}
#endif /* WITH_TLS */

static const struct field_desc socket_opts_table[] = {
	{ "reuseport", FIELD_BOOL,
	  offsetof(struct socket_opts, tcp_reuseport) },
	{ "keepalive", FIELD_BOOL,
	  offsetof(struct socket_opts, tcp_keepalive) },
	{ "nodelay", FIELD_BOOL, offsetof(struct socket_opts, tcp_nodelay) },
	{ "sndbuf", FIELD_INT, offsetof(struct socket_opts, tcp_sndbuf) },
	{ "rcvbuf", FIELD_INT, offsetof(struct socket_opts, tcp_rcvbuf) },
#if WITH_TCP_NOTSENT_LOWAT
	{ "notsent_lowat", FIELD_INT,
	  offsetof(struct socket_opts, tcp_notsent_lowat) },
#endif
	{ "backlog", FIELD_INT, offsetof(struct socket_opts, backlog) },
};

static bool parse_socket_scope_cb(
	struct socket_opts *restrict opts, const char *restrict scope,
	const char *restrict key, const struct jutil_value *value)
{
	return scope_dispatch(
		opts, opts, scope, key, value, socket_opts_table,
		ARRAY_SIZE(socket_opts_table), NULL, 0);
}

static const struct field_desc mem_pressure_field_table[] = {
	{ "hi", FIELD_INT, offsetof(struct mux_config, mem_pressure_hi) },
	{ "lo", FIELD_INT, offsetof(struct mux_config, mem_pressure_lo) },
};

static bool mem_pressure_scope_cb(
	void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	return scope_dispatch(
		&conf->mux, conf, "mux.mem_pressure", key, value,
		mem_pressure_field_table, ARRAY_SIZE(mem_pressure_field_table),
		NULL, 0);
}

static bool
mux_tcp_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	return parse_socket_scope_cb(&conf->mux_socket, "mux.tcp", key, value);
}

static bool parse_mux_mem_pressure(void *ud, const struct jutil_value *value)
{
	return jutil_walk_object(ud, value, mem_pressure_scope_cb);
}

static bool parse_mux_tcp(void *ud, const struct jutil_value *value)
{
	return jutil_walk_object(ud, value, mux_tcp_scope_cb);
}

static bool parse_mux_stream_window(void *ud, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	int v;
	if (!jutil_get_int(value, &v)) {
		return false;
	}
	if (v <= 0) {
		/* 0 makes stream_window follow the automatic session window. */
		conf->mux.stream_window = 0;
		return true;
	}
	conf->mux.stream_window = CLAMP(v / MUX_MAX_PAYLOAD_SIZE, 1, 1024);
	return true;
}

static bool parse_mux_session_window(void *ud, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	int v;
	if (!jutil_get_int(value, &v)) {
		return false;
	}
	if (v <= 0) {
		/* 0 opts into automatic BDP-driven session sizing. */
		conf->mux.session_window = 0;
		return true;
	}
	conf->mux.session_window =
		CLAMP(v / MUX_MAX_PAYLOAD_SIZE,
		      MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT, 16384);
	return true;
}

/* Field order matches struct mux_config declaration in mux.h. */
static const struct field_desc mux_field_table[] = {
	{ "connect_timeout", FIELD_INT,
	  offsetof(struct mux_config, connect_timeout) },
	{ "ping_timeout", FIELD_INT,
	  offsetof(struct mux_config, ping_timeout) },
	{ "keepalive", FIELD_INT, offsetof(struct mux_config, keepalive) },
	{ "send_timeout", FIELD_INT,
	  offsetof(struct mux_config, send_timeout) },
	{ "idle_timeout", FIELD_INT,
	  offsetof(struct mux_config, idle_timeout) },
	{ "resume_timeout", FIELD_INT,
	  offsetof(struct mux_config, resume_timeout) },
	{ "max_streams", FIELD_INT, offsetof(struct mux_config, max_streams) },
	{ "max_halfopen", FIELD_INT,
	  offsetof(struct mux_config, max_halfopen) },
	{ "nodelay", FIELD_BOOL, offsetof(struct mux_config, nodelay) },
};

static const struct scope_handler mux_handlers[] = {
	{ "mem_pressure", parse_mux_mem_pressure },
	{ "tcp", parse_mux_tcp },
	{ "session_window", parse_mux_session_window },
	{ "stream_window", parse_mux_stream_window },
};

static bool
mux_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	return scope_dispatch(
		&conf->mux, conf, "mux", key, value, mux_field_table,
		ARRAY_SIZE(mux_field_table), mux_handlers,
		ARRAY_SIZE(mux_handlers));
}

static bool
tcp_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	return parse_socket_scope_cb(&conf->local_socket, "tcp", key, value);
}

static bool parse_max_startups(void *ud, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	const char *s = jutil_get_string(value);
	if (s == NULL) {
		LOGE("failed to parse max_startups (must be string)");
		return false;
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

	conf->startup_limit_start = (int)start;
	conf->startup_limit_rate = (int)rate;
	conf->startup_limit_full = (int)full;

	return true;
}

static bool identity_connect_cb(void *ud, const struct jutil_value *elem)
{
	struct config *restrict conf = ud;
	const char *const s = jutil_get_string(elem);
	if (s == NULL) {
		LOGE("identity.mux_connect: element must be a string");
		return false;
	}
	const size_t n = conf->identity_connect_count;
	if (n >= SIZE_MAX / sizeof(*conf->identity_connect)) {
		LOGOOM();
		return false;
	}
	char **restrict entries =
		realloc(conf->identity_connect,
			(n + 1) * sizeof(*conf->identity_connect));
	if (entries == NULL) {
		LOGOOM();
		return false;
	}
	conf->identity_connect = entries;
	entries[n] = strdup(s);
	if (entries[n] == NULL) {
		LOGOOM();
		return false;
	}
	conf->identity_connect_count = n + 1;
	return true;
}

static struct identity_peer *
identity_listen_upsert(struct config *restrict conf, const char *restrict id)
{
	for (size_t i = 0; i < conf->identity_peers_count; i++) {
		if (strcmp(conf->identity_peers[i].id, id) == 0) {
			return &conf->identity_peers[i];
		}
	}
	const size_t n = conf->identity_peers_count;
	if (n >= SIZE_MAX / sizeof(*conf->identity_peers)) {
		LOGOOM();
		return NULL;
	}
	struct identity_peer *restrict entries = realloc(
		conf->identity_peers, (n + 1) * sizeof(*conf->identity_peers));
	if (entries == NULL) {
		LOGOOM();
		return NULL;
	}
	conf->identity_peers = entries;
	entries[n] = (struct identity_peer){
		.id = strdup(id),
		.listen = NULL,
	};
	if (entries[n].id == NULL) {
		LOGOOM();
		return NULL;
	}
	conf->identity_peers_count = n + 1;
	return &entries[n];
}

static bool
identity_listen_cb(void *ud, const char *key, const struct jutil_value *value)
{
	if (key[0] == '-') {
		return true;
	}
	struct config *restrict conf = ud;
	const char *const s = jutil_get_string(value);
	if (s == NULL) {
		LOGE_F("identity.listen.%s: must be a string", key);
		return false;
	}
	struct identity_peer *restrict p = identity_listen_upsert(conf, key);
	if (p == NULL) {
		return false;
	}
	free(p->listen);
	p->listen = strdup(s);
	if (p->listen == NULL) {
		LOGOOM();
		return false;
	}
	return true;
}

static bool parse_identity_claim(void *ud, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	const char *const s = jutil_get_string(value);
	if (s == NULL) {
		LOGE("identity.claim: must be a string");
		return false;
	}
	free(conf->identity_claim);
	conf->identity_claim = strdup(s);
	if (conf->identity_claim == NULL) {
		LOGOOM();
		return false;
	}
	return true;
}

static bool parse_identity_connect(void *ud, const struct jutil_value *value)
{
	return jutil_walk_array(ud, value, identity_connect_cb);
}

static bool parse_identity_listen(void *ud, const struct jutil_value *value)
{
	return jutil_walk_object(ud, value, identity_listen_cb);
}

static const struct scope_handler identity_handlers[] = {
	{ "claim", parse_identity_claim },
	{ "mux_connect", parse_identity_connect },
	{ "listen", parse_identity_listen },
};

static bool
identity_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	return scope_dispatch(
		ud, ud, "identity", key, value, NULL, 0, identity_handlers,
		ARRAY_SIZE(identity_handlers));
}

static const struct field_desc root_field_table[] = {
	{ "type", FIELD_STRING, offsetof(struct config, type) },
	{ "api_listen", FIELD_STRING, offsetof(struct config, api_listen) },
	{ "mux_listen", FIELD_STRING, offsetof(struct config, mux_listen) },
	{ "listen", FIELD_STRING, offsetof(struct config, listen) },
	{ "mux_connect", FIELD_STRING, offsetof(struct config, mux_connect) },
	{ "connect", FIELD_STRING, offsetof(struct config, connect) },
	{ "loglevel", FIELD_INT, offsetof(struct config, loglevel) },
	{ "max_sessions", FIELD_INT, offsetof(struct config, max_sessions) },
};

static bool parse_root_mux(void *ud, const struct jutil_value *value)
{
	return jutil_walk_object(ud, value, mux_scope_cb);
}

static bool parse_root_tcp(void *ud, const struct jutil_value *value)
{
	return jutil_walk_object(ud, value, tcp_scope_cb);
}

static bool parse_root_identity(void *ud, const struct jutil_value *value)
{
	return jutil_walk_object(ud, value, identity_scope_cb);
}

#if WITH_TLS
static bool parse_root_tls(void *ud, const struct jutil_value *value)
{
	return jutil_walk_object(ud, value, tls_scope_cb);
}
#endif

static const struct scope_handler root_handlers[] = {
#if WITH_TLS
	{ "tls", parse_root_tls },
#endif
	{ "mux", parse_root_mux },
	{ "tcp", parse_root_tcp },
	{ "max_startups", parse_max_startups },
	{ "identity", parse_root_identity },
};

static bool
main_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	return scope_dispatch(
		ud, ud, NULL, key, value, root_field_table,
		ARRAY_SIZE(root_field_table), root_handlers,
		ARRAY_SIZE(root_handlers));
}

static struct config conf_default(void)
{
	const struct config conf = {
		.type = NULL,
		.api_listen = NULL,
		.mux_listen = NULL,
		.listen = NULL,
#if WITH_TLS
		.tls_cert = NULL,
		.tls_key = NULL,
		.tls_ciphersuites = NULL,
		.authcerts = NULL,
		.authcerts_count = 0,
#endif /* WITH_TLS */

		.identity_claim = NULL,
		.identity_connect = NULL,
		.identity_connect_count = 0,
		.identity_peers = NULL,
		.identity_peers_count = 0,
		.mux = {
			.connect_timeout = 15,
			.keepalive = 300,
			.ping_timeout = 15,
			.send_timeout = 15,
			.resume_timeout = 600,
			.max_halfopen = 256,
			.stream_window = 0,
			.session_window = 0,
			.nodelay = true,
		},
		.mux_socket = {
			.tcp_keepalive = false,
			.tcp_nodelay = true,
			.tcp_reuseport = false,
#if WITH_TCP_NOTSENT_LOWAT
			.tcp_notsent_lowat = 131072,
#endif
			.backlog = 16,
		},
		.local_socket = {
			.tcp_keepalive = true,
			.tcp_nodelay = true,
			.tcp_reuseport = false,
#if WITH_TCP_NOTSENT_LOWAT
			.tcp_notsent_lowat = 0,
#endif
			.backlog = 16,
		},
		.loglevel = LOG_LEVEL_NOTICE,
	};
	return conf;
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
	const bool has_identity_connect = (conf->identity_connect_count > 0);
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
	const bool has_authcerts = (conf->authcerts_count > 0);

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
	/* Warn before clamping so the user sees the raw configured values. */
	if (conf->mux.keepalive < conf->mux.ping_timeout) {
		LOGW_F("mux.keepalive (%d) < mux.ping_timeout (%d): "
		       "mux.keepalive will be clamped to mux.ping_timeout",
		       conf->mux.keepalive, conf->mux.ping_timeout);
	}
	conf->mux.ping_timeout = CLAMP(conf->mux.ping_timeout, 4, 86400);
	conf->mux.keepalive =
		CLAMP(conf->mux.keepalive, conf->mux.ping_timeout, 86400);
	conf->mux.send_timeout =
		CLAMP(conf->mux.send_timeout, 10, conf->mux.ping_timeout);
	conf->mux.connect_timeout =
		CLAMP(conf->mux.connect_timeout, 10, conf->mux.ping_timeout);
	conf->mux.resume_timeout =
		CLAMP(conf->mux.resume_timeout, conf->mux.ping_timeout, 86400);
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
	conf->mux_socket.backlog = CLAMP(conf->mux_socket.backlog, 1, 4096);
	conf->local_socket.backlog = CLAMP(conf->local_socket.backlog, 1, 4096);
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
	for (size_t i = 0; i < conf->identity_peers_count; i++) {
		for (size_t j = i + 1; j < conf->identity_peers_count; j++) {
			if (strcmp(conf->identity_peers[i].id,
				   conf->identity_peers[j].id) == 0) {
				LOGE_F("duplicate identity.listen peer id: \"%s\"",
				       conf->identity_peers[i].id);
				return false;
			}
		}
	}
	/* Require identity.claim when identity entries are configured. */
	if ((conf->identity_connect_count > 0 ||
	     conf->identity_peers_count > 0) &&
	    conf->identity_claim == NULL) {
		LOGE("identity.claim is required when identity.mux_connect or"
		     " identity.listen are configured");
		return false;
	}
	conf->mux.reject_inbound = (conf->connect == NULL);
	return true;
}

struct config *conf_new(void)
{
	struct config *restrict conf = malloc(sizeof(struct config));
	if (conf == NULL) {
		LOGOOM();
		return NULL;
	}
	*conf = conf_default();
	return conf;
}

struct config *conf_parsefile(const char *path)
{
	struct jutil_value *obj = jutil_parsefile(path);
	if (obj == NULL) {
		LOGE_F("failed to parse configuration file: %s", path);
		return NULL;
	}
	struct config *restrict conf = malloc(sizeof(struct config));
	if (conf == NULL) {
		LOGOOM();
		jutil_free(obj);
		return NULL;
	}
	*conf = conf_default();
	const bool ok = jutil_walk_object(conf, obj, main_scope_cb);
	jutil_free(obj);
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

static bool dump_string(struct jutil_value *obj, const char *key, const char *s)
{
	if (s == NULL) {
		return true;
	}
	return jutil_object_set(obj, key, jutil_new_string(s));
}

static bool dump_int(struct jutil_value *obj, const char *key, int i)
{
	return jutil_object_set(obj, key, jutil_new_int(i));
}

static bool dump_bool(struct jutil_value *obj, const char *key, bool b)
{
	return jutil_object_set(obj, key, jutil_new_bool(b));
}

static bool dump_fields(
	struct jutil_value *restrict obj, const void *restrict base,
	const struct field_desc *restrict table, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		const void *const ptr = (const char *)base + table[i].offset;
		bool ok = false;
		switch (table[i].type) {
		case FIELD_STRING:
			ok = dump_string(
				obj, table[i].key, *(const char *const *)ptr);
			break;
		case FIELD_INT:
			ok = dump_int(obj, table[i].key, *(const int *)ptr);
			break;
		case FIELD_BOOL:
			ok = dump_bool(obj, table[i].key, *(const bool *)ptr);
			break;
		}
		if (!ok) {
			return false;
		}
	}
	return true;
}

#if WITH_TLS
static bool dump_tls(struct jutil_value *root, const struct config *conf)
{
	if (conf->tls_cert == NULL && conf->tls_key == NULL &&
	    conf->authcerts_count == 0) {
		return true;
	}
	struct jutil_value *tls = jutil_new_object();
	if (tls == NULL) {
		return false;
	}
	if (!dump_fields(
		    tls, conf, tls_field_table, ARRAY_SIZE(tls_field_table))) {
		jutil_free(tls);
		return false;
	}
	struct jutil_value *arr = jutil_new_array();
	if (arr == NULL) {
		jutil_free(tls);
		return false;
	}
	for (size_t i = 0; i < conf->authcerts_count; i++) {
		if (!jutil_array_set(
			    arr, i, jutil_new_string(conf->authcerts[i]))) {
			jutil_free(arr);
			jutil_free(tls);
			return false;
		}
	}
	/* jutil_object_set takes ownership of arr */
	if (!jutil_object_set(tls, "authcerts", arr)) {
		jutil_free(tls);
		return false;
	}
	/* jutil_object_set takes ownership of tls */
	return jutil_object_set(root, "tls", tls);
}
#endif /* WITH_TLS */

static bool dump_socket_opts(
	struct jutil_value *root, const char *key,
	const struct socket_opts *opts)
{
	struct jutil_value *obj = jutil_new_object();
	if (obj == NULL) {
		return false;
	}
	if (!dump_fields(
		    obj, opts, socket_opts_table,
		    ARRAY_SIZE(socket_opts_table))) {
		jutil_free(obj);
		return false;
	}
	/* jutil_object_set takes ownership of obj */
	return jutil_object_set(root, key, obj);
}

static bool
dump_mux_scope(struct jutil_value *root, const struct config *restrict conf)
{
	struct jutil_value *obj = jutil_new_object();
	if (obj == NULL) {
		return false;
	}
	bool ok = dump_bool(obj, "nodelay", conf->mux.nodelay);
	ok = ok && dump_socket_opts(obj, "tcp", &conf->mux_socket);
	ok = ok && dump_int(obj, "max_halfopen", conf->mux.max_halfopen);
	{
		int v = 0;
		if (conf->mux.stream_window != 0) {
			v = conf->mux.stream_window * MUX_MAX_PAYLOAD_SIZE;
		}
		ok = ok && dump_int(obj, "stream_window", v);
	}
	{
		int v = 0;
		if (conf->mux.session_window != 0) {
			v = conf->mux.session_window * MUX_MAX_PAYLOAD_SIZE;
		}
		ok = ok && dump_int(obj, "session_window", v);
	}
	if (!ok) {
		jutil_free(obj);
		return false;
	}
	/* jutil_object_set takes ownership of obj */
	return jutil_object_set(root, "mux", obj);
}

static bool dump_identity_scope(
	struct jutil_value *restrict root, const struct config *restrict conf)
{
	if (conf->identity_claim == NULL && conf->identity_connect_count == 0 &&
	    conf->identity_peers_count == 0) {
		return true;
	}
	struct jutil_value *id_obj = jutil_new_object();
	if (id_obj == NULL) {
		return false;
	}
	bool ok = true;
	if (conf->identity_claim != NULL) {
		ok = jutil_object_set(
			id_obj, "claim",
			jutil_new_string(conf->identity_claim));
	}
	/* Build mux_connect array. */
	if (ok && conf->identity_connect_count > 0) {
		struct jutil_value *arr = jutil_new_array();
		if (arr == NULL) {
			jutil_free(id_obj);
			return false;
		}
		for (size_t i = 0; i < conf->identity_connect_count && ok;
		     i++) {
			ok = jutil_array_set(
				arr, i,
				jutil_new_string(conf->identity_connect[i]));
		}
		if (ok) {
			ok = jutil_object_set(id_obj, "mux_connect", arr);
		} else {
			jutil_free(arr);
		}
	}
	/* Build listen object. */
	if (ok && conf->identity_peers_count > 0) {
		struct jutil_value *lstn = jutil_new_object();
		if (lstn == NULL) {
			jutil_free(id_obj);
			return false;
		}
		for (size_t i = 0; i < conf->identity_peers_count && ok; i++) {
			const struct identity_peer *restrict p =
				&conf->identity_peers[i];
			if (p->listen != NULL) {
				ok = jutil_object_set(
					lstn, p->id,
					jutil_new_string(p->listen));
			}
		}
		if (ok) {
			ok = jutil_object_set(id_obj, "listen", lstn);
		} else {
			jutil_free(lstn);
		}
	}
	if (!ok) {
		jutil_free(id_obj);
		return false;
	}
	return jutil_object_set(root, "identity", id_obj);
}

static struct jutil_value *conf_build_json(const struct config *restrict conf)
{
	struct jutil_value *root = jutil_new_object();
	if (root == NULL) {
		LOGOOM();
		return NULL;
	}

	const char *type = (conf->type != NULL) ? conf->type : CONF_TYPE;
	bool ok = dump_string(root, "type", type);
	ok = ok && dump_fields(
			   root, conf, root_field_table,
			   ARRAY_SIZE(root_field_table));
#if WITH_TLS
	ok = ok && dump_tls(root, conf);
#endif
	ok = ok && dump_mux_scope(root, conf);
	ok = ok && dump_socket_opts(root, "tcp", &conf->local_socket);
	if (ok &&
	    (conf->startup_limit_start > 0 || conf->startup_limit_rate > 0 ||
	     conf->startup_limit_full > 0)) {
		char buf[64];
		(void)snprintf(
			buf, sizeof(buf), "%d:%d:%d", conf->startup_limit_start,
			conf->startup_limit_rate, conf->startup_limit_full);
		ok = dump_string(root, "max_startups", buf);
	}
	/* Build the identity scope when any identity fields are set. */
	ok = ok && dump_identity_scope(root, conf);

	if (!ok) {
		jutil_free(root);
		return NULL;
	}
	return root;
}

bool conf_dumpfile(const struct config *conf, const char *path)
{
	struct jutil_value *root = conf_build_json(conf);
	if (root == NULL) {
		LOGE_F("failed to dump configuration to: %s", path);
		return false;
	}
	const bool ok = jutil_printfile(root, path, true);
	if (!ok) {
		LOGE_F("failed to dump configuration to: %s", path);
	}
	jutil_free(root);
	return ok;
}

bool conf_dump(const struct config *conf, FILE *fp)
{
	struct jutil_value *root = conf_build_json(conf);
	if (root == NULL) {
		return false;
	}
	size_t len;
	const char *s = jutil_print(root, &len, true);
	if (s == NULL) {
		jutil_free(root);
		return false;
	}
	const bool ok =
		(fwrite(s, 1, len, fp) == len) && (fputc('\n', fp) != EOF);
	jutil_free(root);
	return ok;
}

#if WITH_TLS
static char *read_file(const char *restrict path)
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
	return buf;
}

static bool inline_field(char **restrict sp, const char *restrict name)
{
	if (*sp == NULL || **sp != '@') {
		return true;
	}
	char *content = read_file(*sp + 1);
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
	for (size_t i = 0; i < conf->authcerts_count; i++) {
		if (!inline_field(&conf->authcerts[i], "tls.authcerts")) {
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
	for (size_t i = 0; i < conf->authcerts_count; i++) {
		free(conf->authcerts[i]);
	}
	free(conf->authcerts);
#endif
	free(conf->identity_claim);
	for (size_t i = 0; i < conf->identity_connect_count; i++) {
		free(conf->identity_connect[i]);
	}
	free(conf->identity_connect);
	for (size_t i = 0; i < conf->identity_peers_count; i++) {
		free(conf->identity_peers[i].id);
		free(conf->identity_peers[i].listen);
	}
	free(conf->identity_peers);
	free(conf);
}
