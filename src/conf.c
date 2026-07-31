/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.c
 * @brief Configuration file parser.
 */

#include "conf.h"

#include "conf_schema.gen.h"
#include "mux/mux.h"
#include "shim/tls.h"
#include "shim/util.h"

#include "codec/json.h"
#include "meta/minmax.h"
#include "utils/buffer.h"
#include "utils/ctype_ascii.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <errno.h>
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

/* Parse one strictly-digit-only field of max_startups, terminated by sep, and
 * advance *nptr past it. strtoumax() alone would also accept a leading sign or
 * whitespace; the schema documents the field as "^[0-9]+:[0-9]+:[0-9]+$", so
 * reject anything else and any value above INT_MAX. Returns false (without
 * logging -- the caller emits one message) on any malformation. */
static bool parse_startups_field(
	const char **restrict nptr, const char sep, int *restrict out)
{
	if (!isdigit((unsigned char)**nptr)) {
		return false;
	}
	char *endptr = NULL;
	const uintmax_t v = strtoumax(*nptr, &endptr, 10);
	if (endptr == *nptr || *endptr != sep || v > INT_MAX) {
		return false;
	}
	*nptr = (sep == '\0') ? endptr : endptr + 1;
	*out = (int)v;
	return true;
}

static bool
conf_parse_max_startups(struct config *restrict cfg, const char *restrict s)
{
	if (s == NULL) {
		return true;
	}
	const char *nptr = s;
	int start, rate, full;
	if (!parse_startups_field(&nptr, ':', &start) ||
	    !parse_startups_field(&nptr, ':', &rate) ||
	    !parse_startups_field(&nptr, '\0', &full)) {
		LOGE_F("invalid max_startups format: \"%s\"", s);
		return false;
	}

	cfg->startup_limit_start = start;
	cfg->startup_limit_rate = rate;
	cfg->startup_limit_full = full;
	return true;
}

static struct identity_peer *identity_listen_add(
	struct config *restrict conf, const char *restrict id, size_t id_len)
{
	/* Last-value-wins on a duplicate id, matching every other field's
	 * semantics: reuse an existing entry instead of appending a second
	 * one with the same id. The cached id_len keeps each comparison a plain
	 * length check plus memcmp, without an strlen per existing peer. */
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		struct identity_peer *const restrict p =
			&conf->identity.peers[i];
		if (p->id_len == id_len && memcmp(p->id, id, id_len) == 0) {
			return p;
		}
	}

	const size_t n = conf->identity.peers_count;
	/* Grow geometrically so parsing n peers costs O(log n) reallocations
	 * rather than one per entry. */
	if (n == conf->identity.peers_cap) {
		const size_t max_cap = SIZE_MAX / sizeof(*conf->identity.peers);
		if (n >= max_cap) {
			LOGOOM();
			return NULL;
		}
		size_t new_cap = conf->identity.peers_cap == 0 ?
					 4 :
					 conf->identity.peers_cap * 2;
		if (new_cap > max_cap || new_cap < conf->identity.peers_cap) {
			new_cap = max_cap;
		}
		struct identity_peer *const restrict entries =
			realloc(conf->identity.peers,
				new_cap * sizeof(*conf->identity.peers));
		if (entries == NULL) {
			LOGOOM();
			return NULL;
		}
		conf->identity.peers = entries;
		conf->identity.peers_cap = new_cap;
	}
	struct identity_peer *const restrict entry = &conf->identity.peers[n];
	*entry = (struct identity_peer){
		.id = conf_strndup("identity.listen key", id, id_len),
		.id_len = id_len,
		.listen = NULL,
	};
	if (entry->id == NULL) {
		return NULL;
	}
	conf->identity.peers_count = n + 1;
	return entry;
}

#if WITH_TLS
/* Append one tls.psk entry, preserving document order so the first entry is
 * well-defined as the key a dialing node offers.  Unlike identity.listen this
 * does not dedup: a repeated identity is a configuration error the caller
 * reports, not a last-value-wins field. */
static bool psk_map_cb(
	struct config *restrict conf, const char *restrict key,
	const size_t key_len, char *restrict val, const size_t val_len)
{
	if (key_len > 0 && key[0] == '-') {
		/* Comment-only key, as in identity.listen. */
		return true;
	}
	char *s;
	size_t slen;
	if (!json_parse_string(val, val_len, &s, &slen)) {
		LOGE_F("tls.psk.%s: must be a string", key);
		return false;
	}
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		const struct psk_entry *const restrict e = &conf->tls_psk[i];
		if (e->id_len == key_len && memcmp(e->id, key, key_len) == 0) {
			LOGE_F("tls.psk: duplicate entry for identity \"%.64s\"",
			       e->id);
			return false;
		}
	}
	if (conf->tls_psk_count == conf->tls_psk_cap) {
		const size_t max_cap = SIZE_MAX / sizeof(*conf->tls_psk);
		size_t new_cap =
			conf->tls_psk_cap == 0 ? 4 : conf->tls_psk_cap * 2;
		if (conf->tls_psk_cap >= max_cap) {
			LOGOOM();
			return false;
		}
		if (new_cap > max_cap || new_cap < conf->tls_psk_cap) {
			new_cap = max_cap;
		}
		struct psk_entry *const entries = realloc(
			conf->tls_psk, new_cap * sizeof(*conf->tls_psk));
		if (entries == NULL) {
			LOGOOM();
			return false;
		}
		conf->tls_psk = entries;
		conf->tls_psk_cap = new_cap;
	}
	struct psk_entry *const restrict e =
		&conf->tls_psk[conf->tls_psk_count];
	*e = (struct psk_entry){
		.id = conf_strndup("tls.psk key", key, key_len),
		.id_len = key_len,
		.hex = NULL,
	};
	if (e->id == NULL) {
		return false;
	}
	e->hex = conf_strndup("tls.psk value", s, slen);
	if (e->hex == NULL) {
		free(e->id);
		e->id = NULL;
		return false;
	}
	conf->tls_psk_count++;
	return true;
}
#endif /* WITH_TLS */

#if WITH_TLS
/* Strip surrounding whitespace from a loaded key in place.  A key file written
 * by --genpsk (or any editor) ends with a newline, and "@path" loads the file
 * verbatim, so the trailing byte would otherwise fail the hex check. */
static void psk_trim(char *restrict s)
{
	char *p = s;
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
		p++;
	}
	size_t len = strlen(p);
	while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t' ||
			   p[len - 1] == '\r' || p[len - 1] == '\n')) {
		len--;
	}
	memmove(s, p, len);
	s[len] = '\0';
}

/* Validate one resolved key: well-formed hex of a usable length.
 *
 * The length floor is on *length, not entropy*: the identity label published
 * in the ClientHello is a one-way function of the key, which hands an attacker
 * an offline oracle, so a passphrase-derived key of the right length is still
 * unsafe. sha256("hunter2") in hex passes this check and is worth about 20
 * bits. Keys must come from --genpsk. */
static bool conf_check_psk_key(const struct psk_entry *restrict e)
{
	const size_t hex_len = strlen(e->hex);
	if (hex_len % 2u != 0 || hex_len / 2u < TLS_PSK_MIN_LEN ||
	    hex_len / 2u > TLS_PSK_MAX_LEN) {
		LOGE_F("tls.psk.%s: expected %u to %u octets of hex, got %zu"
		       " characters",
		       e->id, (unsigned)TLS_PSK_MIN_LEN,
		       (unsigned)TLS_PSK_MAX_LEN, hex_len);
		return false;
	}
	for (size_t j = 0; j < hex_len; j++) {
		if (!isxdigit((unsigned char)e->hex[j])) {
			LOGE_F("tls.psk.%s: not a hex string", e->id);
			return false;
		}
	}
	return true;
}

/* Validate every tls.psk entry: identities within the same bound as
 * identity.listen keys, and keys that are well-formed hex of a usable length.
 *
 * The length floor is on *length, not entropy*: the identity label published
 * in the ClientHello is a one-way function of the key, which hands an attacker
 * an offline oracle, so a passphrase-derived key of the right length is still
 * unsafe. sha256("hunter2") in hex passes this check and is worth about 20
 * bits. Keys must come from --genpsk. */
static bool conf_check_psk(const struct config *restrict conf)
{
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		const struct psk_entry *const restrict e = &conf->tls_psk[i];
		if (e->id_len > MUX_MAX_CLAIM_LEN) {
			LOGE_F("tls.psk key \"%.64s\" (%zu octets) exceeds the"
			       " %u-octet peer identity limit",
			       e->id, e->id_len, (unsigned)MUX_MAX_CLAIM_LEN);
			return false;
		}
		/* The key itself is checked by conf_check_psk_key(), after
		 * conf_inline_pem() has resolved any "@path": at this point the
		 * value may still be the file reference rather than the key. */
	}
	/* Both TLS backends accept only one client-side PSK, so a dialing node
	 * offers the first entry. Say which, rather than let a multi-key node
	 * discover it by watching handshakes fail. */
	if (conf->tls_psk_count > 1 && (conf->mux_connect != NULL ||
					conf->identity.mux_connect_count > 0)) {
		LOGW_F("tls.psk has %zu entries but only one can be offered when"
		       " dialing; using \"%.64s\"",
		       conf->tls_psk_count, conf->tls_psk[0].id);
	}
	return true;
}
#endif /* WITH_TLS */

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

/* Load a JSON string-view array into a heap array of NUL-terminated copies (the
 * inverse of build_json_string_arr).  Sets both out params; leaves them
 * untouched for an empty source.  On a per-element failure sets *out_count to
 * the number copied so the partial array is still freed, and returns false
 * (conf_strndup already logged). */
static bool conf_load_string_arr(
	const char *restrict field, const struct json_string *restrict src,
	const size_t count, char ***restrict out, size_t *restrict out_count)
{
	if (count == 0) {
		return true;
	}
	char **const arr = (char **)malloc(count * sizeof(*arr));
	if (arr == NULL) {
		LOGOOM();
		return false;
	}
	*out = arr;
	*out_count = count;
	for (size_t i = 0; i < count; i++) {
		arr[i] = conf_strndup(field, src[i].str, src[i].len);
		if (arr[i] == NULL) {
			*out_count = i;
			return false;
		}
	}
	return true;
}

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
	if (!conf_load_string_arr(
		    "tls.authcerts[]", obj->tls.authcerts,
		    obj->tls.authcerts_count, &cfg->tls_authcerts,
		    &cfg->tls_authcerts_count)) {
		return false;
	}
	cfg->tls_socket_offload = obj->tls.socket_offload;
	/* KTLS requires the library to own the socket fd. */
	cfg->tls_kernel_offload =
		cfg->tls_socket_offload && obj->tls.kernel_offload;
	/* tls.psk: raw JSON fragment pointing into the json buffer, walked here
	 * so the entries outlive json_free_conf.  json_obj_next preserves
	 * document order, which is what makes "the first entry" well-defined. */
	if (obj->tls.psk_json.str != NULL) {
		size_t frag_len = obj->tls.psk_json.len;
		struct json_val parsed =
			json_parse(obj->tls.psk_json.str, &frag_len);
		if (parsed.type != JSON_OBJECT) {
			LOGE("tls.psk: must be an object");
			return false;
		}
		json_iter it = parsed.iter;
		char *key;
		size_t key_len;
		char *val;
		size_t val_len;
		int r;
		while ((r = json_obj_next(
				obj->tls.psk_json.str, &obj->tls.psk_json.len,
				&it, &key, &key_len, &val, &val_len)) ==
		       JSON_NEXT_ITEM) {
			if (!psk_map_cb(cfg, key, key_len, val, val_len)) {
				return false;
			}
		}
		if (r != JSON_NEXT_END) {
			LOGE("tls.psk: malformed object");
			return false;
		}
	}
	return true;
}
#endif /* WITH_TLS */

#if WITH_TCP_NOTSENT_LOWAT
#define LOAD_NOTSENT_LOWAT(dst, val)                                           \
	((dst)->tcp_notsent_lowat = (int)MIN((val), (uintmax_t)INT_MAX))
#else
/* No TCP_NOTSENT_LOWAT on this platform (non-Linux or FORCE_POSIX): the option
 * is silently ignored. It is a valid, documented key -- not "unknown" -- and its
 * schema default is non-zero for the mux transport, so a "did the user set it?"
 * warning fires on every parse; drop it rather than mislead. */
#define LOAD_NOTSENT_LOWAT(dst, val) ((void)(val))
#endif /* WITH_TCP_NOTSENT_LOWAT */

/* Load the shared TCP socket options into dst. The two JSON source objects
 * (json_conf_tcp for tcp.*, json_conf_mux_tcp for mux.tcp.*) are distinct
 * generated types with identical field names; one macro keeps both call sites
 * from drifting (which previously hid the notsent_lowat default divergence). */
#define LOAD_SOCKET_OPTS(dst, src)                                               \
	do {                                                                     \
		(dst)->tcp_reuseport = (src).reuseport;                          \
		(dst)->tcp_keepalive = (src).keepalive;                          \
		(dst)->tcp_nodelay = (src).nodelay;                              \
		/* Clamp to INT_MAX: a value past it would wrap to a negative  \
		 * socket option. */ \
		(dst)->tcp_sndbuf =                                              \
			(int)MIN((src).sndbuf, (uintmax_t)INT_MAX);              \
		(dst)->tcp_rcvbuf =                                              \
			(int)MIN((src).rcvbuf, (uintmax_t)INT_MAX);              \
		LOAD_NOTSENT_LOWAT((dst), (src).notsent_lowat);                  \
		(dst)->backlog = (int)(src).backlog;                             \
	} while (0)

static void
conf_load_mux(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	cfg->mux.nodelay = obj->mux.nodelay;
	LOAD_SOCKET_OPTS(&cfg->mux_tcp, obj->mux.tcp);
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
}

static void
conf_load_tcp(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	LOAD_SOCKET_OPTS(&cfg->tcp, obj->tcp);
}

#undef LOAD_SOCKET_OPTS
#undef LOAD_NOTSENT_LOWAT

static bool conf_load_identity(
	struct config *restrict cfg, const struct json_conf *restrict obj)
{
	STRNDUP_FIELD(
		"identity.claim", cfg->identity.claim, obj->identity.claim);
	cfg->identity.verify = obj->identity.verify;
	if (!conf_load_string_arr(
		    "identity.mux_connect[]", obj->identity.mux_connect,
		    obj->identity.mux_connect_count, &cfg->identity.mux_connect,
		    &cfg->identity.mux_connect_count)) {
		return false;
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
	conf_load_mux(cfg, obj);
	conf_load_tcp(cfg, obj);
	if (!conf_load_identity(cfg, obj)) {
		return false;
	}

	return true;
}

#undef STRNDUP_FIELD

/* Timeout fields are in seconds: 0 disables the timeout, any positive value is
 * clamped to [10, 86400].  Centralizes the shared bounds so the mux timeouts
 * cannot drift apart (schema minimum 0 rules out a negative input). */
static int clamp_timeout(const int v)
{
	return v > 0 ? CLAMP(v, 10, 86400) : 0;
}

/* Clamp keepalive and derive the inactivity deadline:
 * max(keepalive*1.1, keepalive+90s).  keepalive == 0 disables both. */
static void conf_derive_mux_timeout(struct config *restrict conf)
{
	conf->mux.keepalive = clamp_timeout(conf->mux.keepalive);
	if (conf->mux.keepalive > 0) {
		conf->mux.timeout =
			conf->mux.keepalive + MAX(conf->mux.keepalive / 10, 90);
	} else {
		conf->mux.timeout = 0;
	}
}

/* Resolve all defaults and clamp fields to their valid ranges: derive the mux
 * timeout, clamp the mux timeouts and loglevel, and resolve mem_pressure.lo's
 * "0 means hi/2" default. Pure normalization (never fails), shared by
 * conf_check and conf_new_default so both yield the identical default config.
 * mem_pressure.lo is resolved here rather than after conf_check's inversion
 * check: that check only rejects an explicit lo > hi, and hi/2 <= hi, so the
 * order is immaterial. */
static void conf_normalize(struct config *restrict conf)
{
	conf_derive_mux_timeout(conf);
	conf->mux.send_timeout = clamp_timeout(conf->mux.send_timeout);
	conf->mux.connect_timeout = clamp_timeout(conf->mux.connect_timeout);
	conf->mux.resume_timeout = clamp_timeout(conf->mux.resume_timeout);
	conf->mux.idle_timeout = clamp_timeout(conf->mux.idle_timeout);
	conf->loglevel =
		CLAMP(conf->loglevel, LOG_LEVEL_SILENCE, LOG_LEVEL_VERYVERBOSE);
	/* Resolve "lo == 0" to its final value now, so every session reads an
	 * already-concrete threshold instead of re-deriving it per grant. */
	if (conf->mux.mem_pressure_hi > 0 && conf->mux.mem_pressure_lo == 0) {
		conf->mux.mem_pressure_lo = conf->mux.mem_pressure_hi / 2;
	}
}

/* Validate conf->type as a MIME media type (RFC 2045): it must be
 * application/x-multiplexd-config carrying a matching "version" parameter, in
 * any order and tolerant of case and whitespace -- none of which a literal
 * string comparison (as the schema's old "const" constraint did) would accept.
 * mime_check_media tokenizes its input in place, so validate a private copy and
 * keep conf->type intact for logging. */
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
	const char *version = NULL;
	switch (mime_check_media(buf, "x-multiplexd-config", &version)) {
	case MIME_CHECK_OK:
		break;
	case MIME_CHECK_BAD_TYPE:
		LOGE_F("unsupported config type: \"%s\"", conf->type);
		goto done;
	case MIME_CHECK_MALFORMED:
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
	/* mux_listen and mux_connect are independent and may both be set: the
	 * daemon then accepts inbound sessions and maintains the outbound one,
	 * and server_make_tls_contexts builds a server and a client TLS context
	 * for exactly that. identity.mux_connect coexists with either. */
#if WITH_TLS
	const bool has_cert = (conf->tls_cert != NULL);
	const bool has_key = (conf->tls_key != NULL);
	const bool has_authcerts = (conf->tls_authcerts_count > 0);
	const bool has_psk = (conf->tls_psk_count > 0);

	if (has_psk && (has_cert || has_key || has_authcerts)) {
		LOGE("tls.psk is mutually exclusive with tls.cert, tls.key and"
		     " tls.authcerts: a PSK handshake sends no certificate");
		return false;
	}
	if (has_psk) {
		if (!conf_check_psk(conf)) {
			return false;
		}
	} else if (has_cert && has_key && has_authcerts) {
		/* all three set: secure mode */
	} else if (!has_cert && !has_key && !has_authcerts) {
		LOGW("running in plaintext mode: connection is NOT encrypted");
	} else {
		LOGE("incomplete TLS configuration");
		return false;
	}
	if (has_psk && conf->tls_sni != NULL) {
		/* No certificate to select, so the name has nothing to act on. */
		LOGW("ignoring tls.sni: not used with tls.psk");
	}
	if (has_psk && conf->identity.verify) {
		/* PSK binds identity intrinsically: the binder proves the peer
		 * holds the key the label names, so there is nothing for the
		 * certificate-oriented switch to turn on. */
		LOGE("identity.verify is a certificate-mode option and cannot be"
		     " combined with tls.psk, which verifies identity inherently");
		return false;
	}
	/* The all-or-nothing check above means has_cert now implies a complete
	 * TLS configuration, so its absence is plaintext mode -- where there is
	 * no peer certificate for identity.verify to check against.
	 *
	 * Rejected rather than ignored.  Unlike a performance hint such as
	 * tcp.notsent_lowat, which this file deliberately drops when the platform
	 * lacks support, this is a security control: a configuration that asks to
	 * verify while silently not verifying is worse than one that refuses to
	 * start.  Do not "fix" this inconsistency. */
	if (conf->identity.verify && !has_cert) {
		LOGE("identity.verify requires TLS:"
		     " set tls.cert, tls.key and tls.authcerts");
		return false;
	}
#else /* WITH_TLS */
	if (conf->identity.verify) {
		LOGE("identity.verify requires a TLS-enabled build");
		return false;
	}
	/* No tls.psk check here: conf_load_tls() is not compiled in, so the whole
	 * tls object is inert in this build -- tls.cert included -- and singling
	 * out one key would be the surprising behavior.  identity.verify differs
	 * because it lives outside tls and is parsed either way. */
#endif /* WITH_TLS */
	conf_normalize(conf);
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
	/* identity.claim's MUX_MAX_CLAIM_LEN limit is already enforced by the
	 * generated schema unmarshal (conf_schema.json maxLength, applied to the
	 * decoded length before conf_check runs), and STRNDUP_FIELD rejects an
	 * embedded NUL, so no re-check is needed here -- unlike identity.listen
	 * below, whose map values bypass every generated per-field check. */
	/* identity.listen values are a dynamic map, invisible to the schema's
	 * generated per-field checks (see conf_schema.json); reject an
	 * oversized one here instead, since the schema already enforces the
	 * analogous length limit for claim above. */
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		const struct identity_peer *restrict p =
			&conf->identity.peers[i];
		/* identity.listen keys are peer identity strings, and no peer
		 * claims more than MUX_MAX_CLAIM_LEN octets (identity.claim is
		 * schema-capped to it). A longer key could never table_find a
		 * connecting peer -- a listener that binds and accepts but is
		 * silently dead. The map keys bypass the schema's generated
		 * per-field checks, so reject an oversized one here. */
		if (p->id_len > MUX_MAX_CLAIM_LEN) {
			LOGE_F("identity.listen key \"%.64s\" (%zu octets) exceeds"
			       " the %u-octet peer identity limit",
			       p->id, p->id_len, (unsigned)MUX_MAX_CLAIM_LEN);
			return false;
		}
		if (p->listen == NULL) {
			continue;
		}
		/* identity.listen is a dynamic map value that bypasses the
		 * generated per-field maxLength checks, so enforce the shared
		 * address limit (shim/util.h ADDR_MAX_STRLEN, mirrored by
		 * conf_schema.json's maxLength) here instead. */
		const size_t listen_len = strlen(p->listen);
		if (listen_len > ADDR_MAX_STRLEN) {
			LOGE_F("identity.listen.%s (%zu octets) exceeds the"
			       " %zu-octet address limit",
			       p->id, listen_len, (size_t)ADDR_MAX_STRLEN);
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
				const int err = errno;
				LOGE_F("failed to read %s: %s: (%d) %s", desc,
				       path, err, strerror(err));
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
		const int err = errno;
		LOGE_F("failed to open %s: %s: (%d) %s", desc, path, err,
		       strerror(err));
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
	/* conf_new_default skips conf_check (an empty default has no transport),
	 * so run the shared normalization here so the default config resolves the
	 * same defaults (timeout, clamps, mem_pressure.lo) conf_parse("{}") does. */
	conf_normalize(conf);
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
/* Append one "key":"value" pair to a JSON object body under construction,
 * inserting the separating comma when *first is false.  Shared by the
 * identity.listen and tls.psk builders, whose only difference is which pairs
 * they emit.  On failure the buffer is freed and *vbufp set to NULL. */
static bool json_map_append(
	struct vbuffer **restrict vbufp, bool *restrict first,
	const char *restrict field, const char *restrict key,
	const char *restrict val)
{
	struct vbuffer *vbuf = *vbufp;
	if (!*first) {
		VBUF_APPEND(vbuf, ",", 1);
	}
	const size_t key_len = strlen(key);
	const size_t val_len = strlen(val);
	const int r_key = json_marshal_string(NULL, 0, key, key_len);
	const int r_val = json_marshal_string(NULL, 0, val, val_len);
	if (r_key < 0 || r_val < 0) {
		VBUF_FREE(vbuf);
		*vbufp = NULL;
		LOGE_F("%s.%s: value too large to encode", field, key);
		return false;
	}
	const size_t need = (size_t)r_key + 1u + (size_t)r_val;
	/* 1 extra byte is reserved for detecting allocation failures,
	 * matching vbuf_append/vbuf_vappendf's own convention -- without
	 * it, an exact-fit grow leaves cap == len after this append,
	 * which VBUF_HAS_OOM and a later VBUF_APPEND both read as "a
	 * previous append already failed". */
	vbuf = vbuf_grow(vbuf, vbuf->len + need + 1);
	if (vbuf->cap < vbuf->len + need + 1) {
		VBUF_FREE(vbuf);
		*vbufp = NULL;
		LOGOOM();
		return false;
	}
	char *wp = (char *)vbuf->data + vbuf->len;
	wp += json_marshal_string(wp, (size_t)r_key + 1, key, key_len);
	*wp++ = ':';
	(void)json_marshal_string(wp, (size_t)r_val + 1, val, val_len);
	vbuf->len += need;
	*first = false;
	*vbufp = vbuf;
	return true;
}

/* Close an object body built with json_map_append.  An empty map yields
 * *out == NULL, which the caller renders as an absent field. */
static bool json_map_finish(
	struct vbuffer *restrict vbuf, const bool empty,
	struct vbuffer **restrict out)
{
	if (empty) {
		VBUF_FREE(vbuf);
		return true; /* *out stays NULL */
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
		if (!json_map_append(
			    &vbuf, &first, "identity.listen", p->id,
			    p->listen)) {
			return false;
		}
	}
	return json_map_finish(vbuf, first, out);
}

#if WITH_TLS
/* tls.psk for --dump-config.  GET /config sees the erased values instead: the
 * keys are wiped once the TLS contexts hold them, exactly as for tls.key. */
static bool build_psk_json(
	const struct config *restrict conf, struct vbuffer **restrict out)
{
	*out = NULL;
	if (conf->tls_psk_count == 0) {
		return true;
	}
	struct vbuffer *vbuf = VBUF_NEW(64);
	if (vbuf == NULL) {
		LOGOOM();
		return false;
	}
	VBUF_APPEND(vbuf, "{", 1);
	bool first = true;
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		const struct psk_entry *restrict e = &conf->tls_psk[i];
		if (!json_map_append(&vbuf, &first, "tls.psk", e->id, e->hex)) {
			return false;
		}
	}
	return json_map_finish(vbuf, first, out);
}
#endif /* WITH_TLS */

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

char *conf_dump(
	const struct config *restrict conf, size_t *restrict lenp,
	const char *restrict indent)
{
	/* Three heap temporaries feed the `raw` literal below; they are released
	 * once at the cleanup label so a future addition need only be freed there.
	 * out is freed on the failure branch (NULL'd once handed to result). */
	struct vbuffer *listen_vbuf = NULL;
	struct json_string *id_mc_arr = NULL;
#if WITH_TLS
	struct json_string *authcerts_arr = NULL;
	struct vbuffer *psk_vbuf = NULL;
#endif
	char *out = NULL;
	char *result = NULL;

	if (!build_listen_json(conf, &listen_vbuf)) {
		goto cleanup;
	}
#if WITH_TLS
	if (!build_psk_json(conf, &psk_vbuf)) {
		goto cleanup;
	}
#endif
	char *const listen_json =
		listen_vbuf != NULL ? (char *)listen_vbuf->data : NULL;
	const size_t listen_len = listen_vbuf != NULL ? listen_vbuf->len : 0;

	if (!build_json_string_arr(
		    conf->identity.mux_connect,
		    conf->identity.mux_connect_count, &id_mc_arr)) {
		goto cleanup;
	}

#if WITH_TLS
	if (!build_json_string_arr(
		    conf->tls_authcerts, conf->tls_authcerts_count,
		    &authcerts_arr)) {
		goto cleanup;
	}
#endif /* WITH_TLS */

	/* Format max_startups string when any throttle value is non-zero. */
	char startups_buf[64];
	char *max_startups = NULL;
	size_t max_startups_len = 0;
	if (conf->startup_limit_start > 0 || conf->startup_limit_rate > 0 ||
	    conf->startup_limit_full > 0) {
		const int n = snprintf(
			startups_buf, sizeof(startups_buf), "%d:%d:%d",
			conf->startup_limit_start, conf->startup_limit_rate,
			conf->startup_limit_full);
		ASSERT(n > 0 && (size_t)n < sizeof(startups_buf));
		max_startups_len = (size_t)n;
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
			.str = max_startups,
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
			.psk_json = {
				.str = psk_vbuf != NULL ?
					       (char *)psk_vbuf->data :
					       NULL,
				.len = psk_vbuf != NULL ? psk_vbuf->len : 0,
			},
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
			.max_frame_size = (unsigned)(
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
			.verify = conf->identity.verify,
		},
	};

	/* The dump is bounded by the same CONF_MAXSIZE limit applied when
	 * reading, so a single allocation avoids a measuring pass. */
	out = malloc(CONF_MAXSIZE + 1);
	if (out == NULL) {
		LOGOOM();
		goto cleanup;
	}
	const int json_sz =
		json_marshal_conf(out, CONF_MAXSIZE + 1, &raw, indent);
	if (json_sz <= 0 || json_sz > CONF_MAXSIZE) {
		LOGE_F("config dump failed or exceeds maximum size of %d bytes",
		       CONF_MAXSIZE);
		goto cleanup;
	}
	out[json_sz] = '\0';
	if (lenp != NULL) {
		*lenp = (size_t)json_sz;
	}
	/* Success: hand out to the caller, then null it so cleanup leaves it. */
	result = out;
	out = NULL;

cleanup:
	VBUF_FREE(listen_vbuf);
	free(id_mc_arr);
#if WITH_TLS
	free(authcerts_arr);
	VBUF_FREE(psk_vbuf);
#endif
	free(out);
	return result;
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

	/* Same for each PSK: the file holds the hex key, not PEM, but the
	 * "@path" convention and the loader are identical.  The key can only be
	 * validated here, once the reference is resolved. */
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		struct psk_entry *const restrict e = &conf->tls_psk[i];
		if (!inline_field(&e->hex, "tls.psk")) {
			return false;
		}
		psk_trim(e->hex);
		if (!conf_check_psk_key(e)) {
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
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		free(conf->tls_psk[i].id);
		free(conf->tls_psk[i].hex);
	}
	free(conf->tls_psk);
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

struct mux_session_config conf_get_mux(const struct config *conf)
{
	struct mux_session_config mc = conf->mux;
	mc.reject_inbound = (conf->connect == NULL);
#if WITH_TLS
	mc.tls_socket_offload = conf->tls_socket_offload;
#endif
	return mc;
}
