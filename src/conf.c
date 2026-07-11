/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.c
 * @brief Configuration file parser.
 */

#include "conf.h"

#include "conf_schema.gen.h"
#include "mux/mux.h"

#include "codec/json.h"
#include "meta/minmax.h"
#include "net/mime.h"
#include "utils/ascii.h"
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

/* strndup(), but rejects an embedded NUL instead of silently truncating
 * there. The JSON escape for U+0000 is legal and decoded by
 * scan_string_inplace into a literal NUL with a correctly-updated .len,
 * but every downstream consumer of a config string (getaddrinfo, fopen,
 * the strcmp/strlen-based identity dedup logic in this file, etc.) treats
 * it as a plain C string -- so a survived embedded NUL would silently
 * truncate here, letting a schema max/minLength check pass against the
 * pre-truncation .len while the stored value is shorter (or, for two
 * strings differing only after the NUL, identical) than what was
 * actually validated. Logs and returns NULL for either failure (embedded
 * NUL or OOM); callers already treat any NULL as fatal and don't need to
 * distinguish the two. */
static char *conf_strndup(
	const char *restrict field, const char *restrict s, const size_t len)
{
	if (memchr(s, '\0', len) != NULL) {
		LOGE_F("%s: contains an embedded NUL character", field);
		return NULL;
	}
	char *const dst = strndup(s, len);
	if (dst == NULL) {
		LOGOOM();
	}
	return dst;
}

static bool
conf_parse_max_startups(struct config *restrict cfg, const char *restrict s)
{
	if (s == NULL) {
		return true;
	}
	const char *nptr = s;
	char *endptr = NULL;

	/* strtoumax() alone would also accept a leading sign or whitespace;
	 * the schema documents this field as the strictly digit-only
	 * "^[0-9]+:[0-9]+:[0-9]+$", so reject anything else before each
	 * conversion instead of relying on strtoumax()'s laxer parsing. */
	if (!isdigit((unsigned char)*nptr)) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}
	const uintmax_t start = strtoumax(nptr, &endptr, 10);
	if (endptr == nptr || *endptr != ':' || start > INT_MAX) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}
	nptr = endptr + 1;

	if (!isdigit((unsigned char)*nptr)) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}
	const uintmax_t rate = strtoumax(nptr, &endptr, 10);
	if (endptr == nptr || *endptr != ':' || rate > INT_MAX) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}
	nptr = endptr + 1;

	if (!isdigit((unsigned char)*nptr)) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}
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
	/* Last-value-wins on a duplicate id, matching every other field's
	 * semantics: reuse an existing entry instead of appending a second
	 * one with the same id. */
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		struct identity_peer *const restrict p =
			&conf->identity.peers[i];
		if (strlen(p->id) == id_len && memcmp(p->id, id, id_len) == 0) {
			return p;
		}
	}

	const size_t n = conf->identity.peers_count;
	if (n >= SIZE_MAX / sizeof(*conf->identity.peers)) {
		LOGOOM();
		return NULL;
	}
	struct identity_peer *const restrict entries = realloc(
		conf->identity.peers, (n + 1) * sizeof(*conf->identity.peers));
	if (entries == NULL) {
		LOGOOM();
		return NULL;
	}
	conf->identity.peers = entries;
	entries[n] = (struct identity_peer){
		.id = conf_strndup("identity.listen key", id, id_len),
		.listen = NULL,
	};
	if (entries[n].id == NULL) {
		return NULL;
	}
	conf->identity.peers_count = n + 1;
	return &entries[n];
}

static bool identity_listen_cb(
	struct config *restrict conf, const char *restrict key, size_t key_len,
	char *restrict val, size_t val_len)
{
	if (key_len > 0 && key[0] == '-') {
		/* Comment-only key: json_unmarshal already ignores any
		 * unrecognized key generically (schema is non-strict), so
		 * this "-" prefix is purely a human authoring convention for
		 * marking a deliberately-disabled entry, not a rule the
		 * dispatcher itself enforces -- but identity.listen has no
		 * fixed key set for the generic dispatcher to apply that
		 * tolerance to, so this map has to skip it explicitly. */
		return true;
	}
	char *s;
	size_t slen;
	if (!json_parse_string(val, val_len, &s, &slen)) {
		LOGE_F("identity.listen.%s: must be a string", key);
		return false;
	}
	struct identity_peer *const restrict p =
		identity_listen_add(conf, key, key_len);
	if (p == NULL) {
		return false;
	}
	free(p->listen);
	p->listen = conf_strndup("identity.listen value", s, slen);
	if (p->listen == NULL) {
		return false;
	}
	return true;
}

/* Dup a json_string field into a config field, using the pointer/length
 * the schema already parsed (no re-scanning); fails only when the source
 * was present but conf_strndup itself failed (embedded NUL or OOM) -- an
 * absent source yields NULL without failing. */
#define STRNDUP_FIELD(name, dst, jstr)                                         \
	do {                                                                   \
		(dst) = (jstr).str != NULL ?                                   \
				conf_strndup((name), (jstr).str, (jstr).len) : \
				NULL;                                          \
		if ((jstr).str != NULL && (dst) == NULL) {                     \
			return false;                                          \
		}                                                              \
	} while (0)

#if WITH_TLS
static bool
conf_load_tls(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	STRNDUP_FIELD("tls.cert", cfg->tls_cert, obj->tls.cert);
	STRNDUP_FIELD("tls.key", cfg->tls_key, obj->tls.key);
	STRNDUP_FIELD(
		"tls.ciphersuites", cfg->tls_ciphersuites,
		obj->tls.ciphersuites);
	STRNDUP_FIELD("tls.sni", cfg->tls_sni, obj->tls.sni);
	STRNDUP_FIELD("tls.alpn", cfg->tls_alpn, obj->tls.alpn);
	if (obj->tls.authcerts_count > 0) {
		cfg->tls_authcerts = (char **)malloc(
			obj->tls.authcerts_count * sizeof(*cfg->tls_authcerts));
		if (cfg->tls_authcerts == NULL) {
			LOGOOM();
			return false;
		}
		cfg->tls_authcerts_count = obj->tls.authcerts_count;
		for (size_t i = 0; i < obj->tls.authcerts_count; i++) {
			cfg->tls_authcerts[i] = conf_strndup(
				"tls.authcerts[]", obj->tls.authcerts[i].str,
				obj->tls.authcerts[i].len);
			if (cfg->tls_authcerts[i] == NULL) {
				cfg->tls_authcerts_count = i;
				return false;
			}
		}
	}
	cfg->tls_socket_offload = obj->tls.socket_offload;
	/* KTLS requires the library to own the socket fd. */
	cfg->tls_kernel_offload =
		cfg->tls_socket_offload && obj->tls.kernel_offload;
	return true;
}
#endif /* WITH_TLS */

static bool
conf_load_mux(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	cfg->mux.nodelay = obj->mux.nodelay;
	cfg->mux_tcp.tcp_reuseport = obj->mux.tcp.reuseport;
	cfg->mux_tcp.tcp_keepalive = obj->mux.tcp.keepalive;
	cfg->mux_tcp.tcp_nodelay = obj->mux.tcp.nodelay;
	/* Clamp to INT_MAX: a value past it would wrap to a negative socket
	 * option. */
	cfg->mux_tcp.tcp_sndbuf =
		(int)MIN(obj->mux.tcp.sndbuf, (uintmax_t)INT_MAX);
	cfg->mux_tcp.tcp_rcvbuf =
		(int)MIN(obj->mux.tcp.rcvbuf, (uintmax_t)INT_MAX);
#if WITH_TCP_NOTSENT_LOWAT
	cfg->mux_tcp.tcp_notsent_lowat =
		(int)MIN(obj->mux.tcp.notsent_lowat, (uintmax_t)INT_MAX);
#else
	if (obj->mux.tcp.notsent_lowat != 0) {
		LOGW("unknown config: \"mux.tcp.notsent_lowat\"");
	}
#endif
	cfg->mux_tcp.backlog = (int)obj->mux.tcp.backlog;
	cfg->mux.max_halfopen = (int)obj->mux.max_halfopen;
	/* Clamp to INT_MAX: a value past it would wrap negative and silently
	 * disable the "max_streams > 0" admission check. */
	cfg->mux.max_streams =
		(int)MIN(obj->mux.max_streams, (uintmax_t)INT_MAX);
	cfg->mux.connect_timeout = (int)obj->mux.connect_timeout;
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
	{
		const uintmax_t max_frame_payload =
			obj->mux.max_frame_size - MUX_FRAME_HEADER_SIZE;
		cfg->mux.max_frame_payload = (int)CLAMP(
			max_frame_payload, MUX_MIN_FRAME_PAYLOAD,
			MUX_MAX_PAYLOAD_SIZE);
	}
	/* Schema-validated to [0, 16777216], fits int. */
	cfg->mux.readahead = (int)obj->mux.readahead;
	/* Clamp to INT_MAX: a value past it would wrap negative, silently
	 * disabling receive-buffer back-pressure ("mem_pressure_hi <= 0"). */
	cfg->mux.mem_pressure_hi =
		(int)MIN(obj->mux.mem_pressure.hi, (uintmax_t)INT_MAX);
	cfg->mux.mem_pressure_lo =
		(int)MIN(obj->mux.mem_pressure.lo, (uintmax_t)INT_MAX);
	return true;
}

static bool
conf_load_tcp(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	cfg->tcp.tcp_reuseport = obj->tcp.reuseport;
	cfg->tcp.tcp_keepalive = obj->tcp.keepalive;
	cfg->tcp.tcp_nodelay = obj->tcp.nodelay;
	cfg->tcp.tcp_sndbuf = (int)MIN(obj->tcp.sndbuf, (uintmax_t)INT_MAX);
	cfg->tcp.tcp_rcvbuf = (int)MIN(obj->tcp.rcvbuf, (uintmax_t)INT_MAX);
#if WITH_TCP_NOTSENT_LOWAT
	cfg->tcp.tcp_notsent_lowat =
		(int)MIN(obj->tcp.notsent_lowat, (uintmax_t)INT_MAX);
#else
	if (obj->tcp.notsent_lowat != 0) {
		LOGW("unknown config: \"tcp.notsent_lowat\"");
	}
#endif
	cfg->tcp.backlog = (int)obj->tcp.backlog;
	return true;
}

static bool conf_load_identity(
	struct config *restrict cfg, const struct json_conf *restrict obj)
{
	STRNDUP_FIELD(
		"identity.claim", cfg->identity.claim, obj->identity.claim);
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
			cfg->identity.mux_connect[i] = conf_strndup(
				"identity.mux_connect[]",
				obj->identity.mux_connect[i].str,
				obj->identity.mux_connect[i].len);
			if (cfg->identity.mux_connect[i] == NULL) {
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
	}
	return true;
}

/* Load schema struct into config struct (strings strdup'd).  False on error. */
static bool
conf_load(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	/* Root string fields: strndup zero-copy pointers using known lengths. */
	STRNDUP_FIELD("type", cfg->type, obj->type);
	STRNDUP_FIELD("api_listen", cfg->api_listen, obj->api_listen);
	STRNDUP_FIELD("mux_listen", cfg->mux_listen, obj->mux_listen);
	STRNDUP_FIELD("mux_connect", cfg->mux_connect, obj->mux_connect);
	STRNDUP_FIELD("listen", cfg->listen, obj->listen);
	STRNDUP_FIELD("connect", cfg->connect, obj->connect);
	STRNDUP_FIELD("log", cfg->log, obj->log);

	/* Clamp to INT_MAX: a narrowing cast of a larger value is
	 * implementation-defined, and conf_check() re-clamps loglevel to a
	 * valid range anyway, but the intermediate cast should still be
	 * well-defined regardless of input. */
	cfg->loglevel = (int)MIN(obj->loglevel, (uintmax_t)INT_MAX);
	/* Clamp to INT_MAX: a value past it would wrap to a negative limit and
	 * silently disable the "max_sessions > 0" admission check. */
	cfg->max_sessions = (int)MIN(obj->max_sessions, (uintmax_t)INT_MAX);
	if (!conf_parse_max_startups(cfg, obj->max_startups.str)) {
		return false;
	}

#if WITH_TLS
	if (!conf_load_tls(cfg, obj)) {
		return false;
	}
#endif /* WITH_TLS */
	if (!conf_load_mux(cfg, obj)) {
		return false;
	}
	if (!conf_load_tcp(cfg, obj)) {
		return false;
	}
	if (!conf_load_identity(cfg, obj)) {
		return false;
	}

	return true;
}

/* Clamp keepalive and derive the inactivity deadline:
 * max(keepalive*1.1, keepalive+90s).  keepalive == 0 disables both. */
static void conf_derive_mux_timeout(struct config *restrict conf)
{
	if (conf->mux.keepalive > 0) {
		conf->mux.keepalive = CLAMP(conf->mux.keepalive, 10, 86400);
		conf->mux.timeout =
			conf->mux.keepalive + MAX(conf->mux.keepalive / 10, 90);
	} else {
		conf->mux.timeout = 0;
	}
}

/* Validate conf->type as a MIME media type (RFC 2045), mirroring
 * proto_parse_type in mux/handshake.c: type/subtype compare
 * case-insensitively, "version" may appear alongside other (ignored)
 * parameters in any order, and surrounding whitespace is insignificant --
 * none of which a literal string comparison (as the schema's old "const"
 * constraint did) would tolerate. mime_parse tokenizes its input in place,
 * so parse a private copy and keep conf->type intact for logging. */
static bool conf_check_type(const struct config *restrict conf)
{
	if (conf->type == NULL) {
		return true;
	}
	char *const buf = strdup(conf->type);
	if (buf == NULL) {
		LOGOOM();
		return false;
	}
	bool ok = false;
	char *media_type, *media_subtype;
	char *next = mime_parse(buf, &media_type, &media_subtype);
	if (next == NULL || strcmp(media_type, "application") != 0 ||
	    strcmp(media_subtype, "x-multiplexd-config") != 0) {
		LOGE_F("unsupported config type: \"%s\"", conf->type);
		goto done;
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
	if (next == NULL) {
		LOGE_F("malformed config type: \"%s\"", conf->type);
		goto done;
	}
	if (version == NULL || strcmp(version, CONF_VERSION) != 0) {
		LOGE_F("unsupported config version: \"%s\"",
		       version != NULL ? version : "(missing)");
		goto done;
	}
	ok = true;
done:
	free(buf);
	return ok;
}

static bool conf_check(struct config *restrict conf)
{
	if (!conf_check_type(conf)) {
		return false;
	}

	/* Require at least one transport: mux_listen, mux_connect, or an
	 * identity.mux_connect entry. */
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
	const bool has_authcerts = (conf->tls_authcerts_count > 0);

	if (has_cert && has_key && has_authcerts) {
		/* all three set: secure mode */
	} else if (!has_cert && !has_key && !has_authcerts) {
		LOGW("running in plaintext mode: connection is NOT encrypted");
	} else {
		LOGE("incomplete TLS configuration");
		return false;
	}
#endif /* WITH_TLS */
	conf_derive_mux_timeout(conf);
	if (conf->mux.send_timeout > 0) {
		conf->mux.send_timeout =
			CLAMP(conf->mux.send_timeout, 10, 86400);
	}
	if (conf->mux.connect_timeout > 0) {
		conf->mux.connect_timeout =
			CLAMP(conf->mux.connect_timeout, 10, 86400);
	}
	if (conf->mux.resume_timeout > 0) {
		conf->mux.resume_timeout =
			CLAMP(conf->mux.resume_timeout, 10, 86400);
	}
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
	/* lo == 0 means "default to hi / 2", which is always < hi for hi > 0,
	 * so only a positive, explicit lo can violate the ramp's ordering.
	 * hi == 0 disables the whole mechanism. Equality is tolerated
	 * (degenerate step function, e.g. from independently clamping both
	 * fields to the same ceiling); only a clearly inverted range is
	 * rejected. */
	if (conf->mux.mem_pressure_hi > 0 && conf->mux.mem_pressure_lo > 0 &&
	    conf->mux.mem_pressure_lo > conf->mux.mem_pressure_hi) {
		LOGE_F("mem_pressure.lo (%d) > mem_pressure.hi (%d):"
		       " throttle range is inverted",
		       conf->mux.mem_pressure_lo, conf->mux.mem_pressure_hi);
		return false;
	}
	/* Resolve "lo == 0" to its final value now, so every session reads an
	 * already-concrete threshold instead of re-deriving it per grant. */
	if (conf->mux.mem_pressure_hi > 0 && conf->mux.mem_pressure_lo == 0) {
		conf->mux.mem_pressure_lo = conf->mux.mem_pressure_hi / 2;
	}
	/* identity.claim's 255-octet wire limit is already enforced by the
	 * generated schema unmarshal (conf_schema.json maxLength:255, applied to
	 * the decoded length before conf_check runs), and STRNDUP_FIELD rejects an
	 * embedded NUL, so no re-check is needed here -- unlike identity.listen
	 * below, whose map values bypass every generated per-field check. */
	/* identity.listen values are a dynamic map, invisible to the schema's
	 * generated per-field checks (see conf_schema.json); reject an
	 * oversized one here instead, since the schema already enforces the
	 * analogous length limit for claim above. */
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		const struct identity_peer *restrict p =
			&conf->identity.peers[i];
		if (p->listen == NULL) {
			continue;
		}
		const size_t listen_len = strlen(p->listen);
		if (listen_len > 261) {
			LOGE_F("identity.listen.%s (%zu octets) exceeds the"
			       " 261-octet address limit",
			       p->id, listen_len);
			return false;
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

/* Read an already-open stream (the caller retains ownership of @p fp) into a
 * heap buffer.  The +1 allocation serves double duty: oversize detection and
 * NUL termination. */
static char *read_stream(
	FILE *restrict fp, const char *restrict desc, const char *restrict path,
	size_t *restrict lenp)
{
	char *const buf = malloc(CONF_MAXSIZE + 1);
	if (buf == NULL) {
		LOGOOM();
		return NULL;
	}
	size_t n = 0;
	size_t rem = CONF_MAXSIZE + 1;
	while (rem > 0) {
		const size_t rd = fread(buf + n, 1, rem, fp);
		n += rd;
		if (rd < rem) {
			/* Short read: EOF unless the error indicator is set. */
			if (ferror(fp)) {
				LOGE_F("failed to read %s: %s", desc, path);
				free(buf);
				return NULL;
			}
			break;
		}
		rem -= rd;
	}
	if (n > CONF_MAXSIZE) {
		LOGE_F("%s exceeds maximum size of %d bytes: %s", desc,
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

static char *read_file(
	const char *restrict desc, const char *restrict path,
	size_t *restrict lenp)
{
	/* "-" reads stdin, which must not be closed; a named file is opened and
	 * closed here so read_stream stays ownership-agnostic. */
	if (strcmp(path, "-") == 0) {
		return read_stream(stdin, desc, path, lenp);
	}
	FILE *const fp = fopen(path, "r");
	if (fp == NULL) {
		LOGE_F("failed to open %s: %s", desc, path);
		return NULL;
	}
	char *const buf = read_stream(fp, desc, path, lenp);
	(void)fclose(fp);
	return buf;
}

struct config *conf_new_default(void)
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
	/* conf_new_default skips conf_check (an empty default has no
	 * transport), so derive the timeout here too; otherwise a default
	 * config would have timeout==0. */
	conf_derive_mux_timeout(conf);
	return conf;
}

struct config *conf_parse(char *json, const size_t len)
{
	/* Same ceiling conf_parsefile enforces via read_stream, applied here too
	 * so every caller (including PUT /config) sees one size limit. */
	if (len > CONF_MAXSIZE) {
		LOGE_F("config exceeds maximum size of %d bytes", CONF_MAXSIZE);
		return NULL;
	}
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
	char *const buf = read_file("config file", path, &len);
	if (buf == NULL) {
		return NULL;
	}
	struct config *const conf = conf_parse(buf, len);
	free(buf);
	return conf;
}

/* Build a vbuffer containing the JSON object for the identity.listen map
 * into *out (left NULL if no peer has a listen address). Returns false
 * only on an allocation/encoding failure. */
static bool build_listen_json(
	const struct config *restrict conf, struct vbuffer **restrict out)
{
	*out = NULL;
	struct vbuffer *vbuf = VBUF_NEW(64);
	if (vbuf == NULL) {
		LOGOOM();
		return false;
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
			LOGE_F("identity.listen.%s: value too large to encode",
			       p->id);
			return false;
		}
		const size_t need = (size_t)r_id + 1u + (size_t)r_val;
		/* 1 extra byte is reserved for detecting allocation failures,
		 * matching vbuf_append/vbuf_vappendf's own convention -- without
		 * it, an exact-fit grow leaves cap == len after this append,
		 * which VBUF_HAS_OOM and a later VBUF_APPEND both read as "a
		 * previous append already failed". */
		vbuf = vbuf_grow(vbuf, vbuf->len + need + 1);
		if (vbuf->cap < vbuf->len + need + 1) {
			VBUF_FREE(vbuf);
			LOGOOM();
			return false;
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
		return true; /* no peers with listen addresses; *out stays NULL */
	}
	VBUF_APPEND(vbuf, "}", 1);
	if (VBUF_HAS_OOM(vbuf)) {
		VBUF_FREE(vbuf);
		LOGOOM();
		return false;
	}
	/* The reserved byte provides NUL-termination for the caller. */
	vbuf->data[vbuf->len] = '\0';
	*out = vbuf;
	return true;
}

/* Build a struct json_string view of s (NULL-safe: NULL maps to {NULL, 0}). */
static struct json_string json_str(char *s)
{
	return (struct json_string){
		.str = s,
		.len = s != NULL ? strlen(s) : 0,
	};
}

/* Build an array of struct json_string views over strs[0..count) into *out
 * (left NULL when count == 0). Returns false only on allocation failure. */
static bool build_json_string_arr(
	char *const *restrict strs, size_t count,
	struct json_string **restrict out)
{
	*out = NULL;
	if (count == 0) {
		return true;
	}
	struct json_string *restrict arr = malloc(count * sizeof(*arr));
	if (arr == NULL) {
		LOGOOM();
		return false;
	}
	for (size_t i = 0; i < count; i++) {
		arr[i].str = strs[i];
		arr[i].len = strlen(strs[i]);
	}
	*out = arr;
	return true;
}

char *conf_dump(const struct config *restrict conf, size_t *restrict lenp)
{
	struct vbuffer *listen_vbuf = NULL;
	if (!build_listen_json(conf, &listen_vbuf)) {
		return NULL;
	}
	char *const listen_json =
		listen_vbuf != NULL ? (char *)listen_vbuf->data : NULL;
	const size_t listen_len = listen_vbuf != NULL ? listen_vbuf->len : 0;

	struct json_string *id_mc_arr = NULL;
	if (!build_json_string_arr(
		    conf->identity.mux_connect,
		    conf->identity.mux_connect_count, &id_mc_arr)) {
		VBUF_FREE(listen_vbuf);
		return NULL;
	}

#if WITH_TLS
	struct json_string *authcerts_arr = NULL;
	if (!build_json_string_arr(
		    conf->tls_authcerts, conf->tls_authcerts_count,
		    &authcerts_arr)) {
		free(id_mc_arr);
		VBUF_FREE(listen_vbuf);
		return NULL;
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

	/* 0 * MUX_WINDOW_UNIT == 0, so "unset" needs no separate branch. */
	const uintmax_t session_window_bytes =
		(uintmax_t)conf->mux.session_window * MUX_WINDOW_UNIT;
	const uintmax_t stream_window_bytes =
		(uintmax_t)conf->mux.stream_window * MUX_WINDOW_UNIT;

	const struct json_conf raw = {
		/* Always dump the canonical CONF_TYPE literal rather than
		 * conf->type: conf_check_type accepts equivalent variants
		 * (different case, whitespace, parameter order, or extra
		 * parameters), so the original string need not match it. */
		.type = { .str = CONF_TYPE, .len = sizeof(CONF_TYPE) - 1 },
		.api_listen = json_str(conf->api_listen),
		.mux_listen = json_str(conf->mux_listen),
		.mux_connect = json_str(conf->mux_connect),
		.listen = json_str(conf->listen),
		.connect = json_str(conf->connect),
		.log = json_str(conf->log),
		.loglevel = (unsigned)conf->loglevel,
		.max_sessions = (uintmax_t)conf->max_sessions,
		.max_startups = {
			.str = (char *)max_startups,
			.len = max_startups_len,
		},
#if WITH_TLS
		.tls = {
			.cert = json_str(conf->tls_cert),
			.key = json_str(conf->tls_key),
			.ciphersuites = json_str(conf->tls_ciphersuites),
			.sni = json_str(conf->tls_sni),
			.alpn = json_str(conf->tls_alpn),
			.authcerts = authcerts_arr,
			.authcerts_count = conf->tls_authcerts_count,
			.kernel_offload = conf->tls_kernel_offload,
			.socket_offload = conf->tls_socket_offload,
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
			.keepalive = (unsigned)conf->mux.keepalive,
			.send_timeout = (unsigned)conf->mux.send_timeout,
			.idle_timeout = (unsigned)conf->mux.idle_timeout,
			.resume_timeout = (unsigned)conf->mux.resume_timeout,
			.session_window = (unsigned)session_window_bytes,
			.stream_window = (unsigned)stream_window_bytes,
			.readahead = (unsigned)conf->mux.readahead,
			.max_frame_size = (uintmax_t)(
				(uint_least32_t)conf->mux.max_frame_payload +
				MUX_FRAME_HEADER_SIZE),
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
			.claim = json_str(conf->identity.claim),
			.mux_connect = id_mc_arr,
			.mux_connect_count = conf->identity.mux_connect_count,
			.listen_json = {
				.str = listen_json,
				.len = listen_len,
			},
		},
	};

	/* The dump is bounded by the same CONF_MAXSIZE limit applied when
	 * reading, so a single allocation avoids a measuring pass. */
	char *const out = malloc(CONF_MAXSIZE + 1);
	if (out == NULL) {
		VBUF_FREE(listen_vbuf);
		free(id_mc_arr);
#if WITH_TLS
		free(authcerts_arr);
#endif
		LOGOOM();
		return NULL;
	}
	const int json_sz =
		json_marshal_conf(out, CONF_MAXSIZE + 1, &raw, NULL);
	if (json_sz <= 0 || json_sz > CONF_MAXSIZE) {
		VBUF_FREE(listen_vbuf);
		free(id_mc_arr);
#if WITH_TLS
		free(authcerts_arr);
#endif
		free(out);
		LOGE_F("config dump failed or exceeds maximum size of %d bytes",
		       CONF_MAXSIZE);
		return NULL;
	}
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
	char *const content = read_file(name, *sp + 1, NULL);
	if (content == NULL) {
		LOGE_F("failed to inline PEM field: %s", name);
		return false;
	}
	free(*sp);
	*sp = content;
	return true;
}

/* Append cert plus a newline separator to bundle, returning the new offset. */
static size_t bundle_append(char *restrict bundle, size_t pos, const char *cert)
{
	const size_t len = strlen(cert);
	/* Copy the cert together with its terminator, then overwrite the
	 * terminator with the newline separator. */
	memcpy(bundle + pos, cert, len + 1);
	pos += len;
	bundle[pos++] = '\n';
	return pos;
}

bool conf_inline_pem(struct config *conf)
{
	if (!inline_field(&conf->tls_cert, "tls.cert") ||
	    !inline_field(&conf->tls_key, "tls.key")) {
		return false;
	}

	/* Inline @path references in the global trusted certs. */
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		if (!inline_field(&conf->tls_authcerts[i], "tls.authcerts")) {
			return false;
		}
	}

	/* Build the concatenated PEM bundle from all certs. */
	{
		size_t total = 0;
		for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
			total += strlen(conf->tls_authcerts[i]) + 1;
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
				pos = bundle_append(
					bundle, pos, conf->tls_authcerts[i]);
			}
			bundle[pos] = '\0';
		}
		conf->tls_authcerts_bundle = bundle;
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
	free(conf->tls_sni);
	free(conf->tls_alpn);
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		free(conf->tls_authcerts[i]);
	}
	free((void *)conf->tls_authcerts);
	free(conf->tls_authcerts_bundle);
#endif /* WITH_TLS */
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
#if WITH_TLS
	mc.tls_socket_offload = conf->tls_socket_offload;
#endif
	return mc;
}
