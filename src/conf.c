/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.c
 * @brief Configuration file parser.
 */

#include "conf.h"

#include "conf_presence.gen.h"
#include "conf_schema.gen.h"
#include "mux/mux.h"
#include "shim/tls.h"
#include "shim/util.h"

#include "codec/json.h"
#include "meta/minmax.h"
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

static bool conf_parse_max_startups(
	struct config *restrict cfg, const char *restrict s, const size_t len)
{
	if (s == NULL) {
		return true;
	}
	if (memchr(s, '\0', len) != NULL) {
		LOGE("max_startups: contains an embedded NUL character");
		return false;
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

/* Grow a config array geometrically (4, then doubling) so appending n entries
 * costs O(log n) reallocations.  Returns the reallocated array and updates
 * *cap, or NULL -- logged, with the original array still valid and *cap
 * unchanged -- when *cap is already at the addressable maximum or realloc
 * fails. */
static void *
conf_grow_array(void *arr, size_t *restrict cap, const size_t elem_size)
{
	const size_t max_cap = SIZE_MAX / elem_size;
	if (*cap >= max_cap) {
		LOGOOM();
		return NULL;
	}
	size_t new_cap = *cap == 0 ? 4 : *cap * 2;
	if (new_cap > max_cap || new_cap < *cap) {
		new_cap = max_cap;
	}
	void *const grown = realloc(arr, new_cap * elem_size);
	if (grown == NULL) {
		LOGOOM();
		return NULL;
	}
	*cap = new_cap;
	return grown;
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
	if (n == conf->identity.peers_cap) {
		struct identity_peer *const entries = conf_grow_array(
			conf->identity.peers, &conf->identity.peers_cap,
			sizeof(*conf->identity.peers));
		if (entries == NULL) {
			return NULL;
		}
		conf->identity.peers = entries;
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
/* Append one tls.psk entry, preserving document order so the
 * first entry is well-defined as the key a dialing node offers.  Unlike
 * identity.listen this does not dedup: a repeated identity is a configuration
 * error the caller reports, not a last-value-wins field. */
static bool psk_map_cb(
	struct config *restrict conf, const char *restrict key,
	const size_t key_len, const char *restrict val, const size_t val_len)
{
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		const struct psk_entry *const restrict e = &conf->tls_psk[i];
		if (e->id_len == key_len && memcmp(e->id, key, key_len) == 0) {
			LOGE_F("tls.psk: duplicate entry for identity \"%.64s\"",
			       e->id);
			return false;
		}
	}
	if (conf->tls_psk_count == conf->tls_psk_cap) {
		struct psk_entry *const entries = conf_grow_array(
			conf->tls_psk, &conf->tls_psk_cap,
			sizeof(*conf->tls_psk));
		if (entries == NULL) {
			return false;
		}
		conf->tls_psk = entries;
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
	e->hex = conf_strndup("tls.psk value", val, val_len);
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
static bool psk_is_space(const char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Strip surrounding whitespace from a key in place.  A key file written by
 * --genpsk (or any editor) ends with a newline, and "@path" loads the file
 * verbatim, so the trailing byte would otherwise fail the hex check.  Every
 * byte the key vacates is erased: shifting it left over leading whitespace
 * would otherwise leave its last characters behind the new terminator, where
 * conf_erase_credentials()'s strlen-based erase never reaches. */
static void psk_trim(char *restrict s)
{
	const size_t n = strlen(s);
	size_t start = 0;
	while (start < n && psk_is_space(s[start])) {
		start++;
	}
	size_t end = n;
	while (end > start && psk_is_space(s[end - 1])) {
		end--;
	}
	const size_t len = end - start;
	memmove(s, s + start, len);
	s[len] = '\0';
	tls_secure_erase(s + len + 1, n - len);
}

/* Validate one key: well-formed hex of a usable length.
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
 * identity.listen keys, and each inline key trimmed and checked by
 * conf_check_psk_key().  An "@path" value is still the file reference here, so
 * its key is trimmed and checked by conf_inline_pem() once it is loaded. */
static bool conf_check_psk(struct config *restrict conf)
{
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		struct psk_entry *const restrict e = &conf->tls_psk[i];
		if (e->id_len > MUX_MAX_CLAIM_LEN) {
			LOGE_F("tls.psk key \"%.64s\" (%zu octets) exceeds the"
			       " %u-octet peer identity limit",
			       e->id, e->id_len, (unsigned)MUX_MAX_CLAIM_LEN);
			return false;
		}
		if (e->hex[0] == '@') {
			continue;
		}
		psk_trim(e->hex);
		if (!conf_check_psk_key(e)) {
			return false;
		}
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

/* conf_map_fn for identity.listen: record the listen address for one peer. */
static bool identity_listen_cb(
	struct config *restrict conf, const char *restrict key,
	const size_t key_len, const char *restrict val, const size_t val_len)
{
	struct identity_peer *const restrict p =
		identity_listen_add(conf, key, key_len);
	if (p == NULL) {
		return false;
	}
	free(p->listen);
	p->listen = conf_strndup("identity.listen value", val, val_len);
	if (p->listen == NULL) {
		return false;
	}
	return true;
}

static void conf_log_map_type_error(
	const char *restrict field, const char *restrict key,
	const size_t key_len)
{
	/* Bound the preview before encoding, ending at a UTF-8 boundary. Each
	 * input byte needs at most six output bytes (a JSON Unicode escape). */
	size_t len = MIN(key_len, (size_t)32);
	while (len < key_len && ((unsigned char)key[len] & 0xC0u) == 0x80u) {
		len--;
	}
	char encoded[32 * 6 + 3];
	if (json_marshal_string(encoded, sizeof(encoded), key, len) < 0) {
		LOGE_F("%s: map key cannot be encoded; value must be a string",
		       field);
		return;
	}
	LOGE_F("%s[%s%s]: must be a string", field, encoded,
	       len < key_len ? "..." : "");
}

/* Disabled map entries are filtered before the codec checks their values. */
static bool conf_map_filter(
	void *context, const struct json_path *map, const char *key,
	const size_t key_len)
{
	(void)context;
	(void)map;
	return key_len == 0 || key[0] != '-';
}

static void conf_json_error(void *context, const struct json_error *error)
{
	(void)context;
	const struct json_path *path = error->path;
	if (error->kind == JSON_E_TYPE && path != NULL &&
	    path->kind == JSON_PATH_MAP) {
		const struct json_string name = path->parent->key;
		const char *field =
			name.len == 3 && memcmp(name.str, "psk", 3) == 0 ?
				"tls.psk" :
				"identity.listen";
		conf_log_map_type_error(field, path->key.str, path->key.len);
	}
}

static const struct json_options conf_json_options = {
	.filter = conf_map_filter,
	.error = conf_json_error,
};

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
static bool conf_load_tls(
	struct config *restrict cfg, const struct json_conf *restrict obj,
	const struct present_conf_tls_psk *restrict psk)
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
	cfg->tls_system_trust = obj->tls.system_trust;
	cfg->tls_socket_offload = obj->tls.socket_offload;
	/* KTLS requires the library to own the socket fd. */
	cfg->tls_kernel_offload =
		cfg->tls_socket_offload && obj->tls.kernel_offload;
	for (size_t i = 0; i < psk->count; i++) {
		const struct present_conf_tls_psk_entry *entry =
			&psk->entries[i];
		if (!psk_map_cb(
			    cfg, entry->key.str, entry->key.len,
			    entry->value.str, entry->value.len)) {
			return false;
		}
	}
	return true;
}
#else /* WITH_TLS */
/* Reject a TLS credential in a build that cannot use it.  The whole tls object
 * is still parsed, but nothing loads it, so a configuration that asks for an
 * encrypted transport would otherwise start in cleartext without a word --
 * the same "asks for a security control, silently does not get it" case
 * conf_check refuses for identity.verify.  Only the credentials select TLS;
 * the tuning keys beside them are inert without one in either build. */
static bool
conf_check_no_tls(const struct json_conf *restrict obj, const bool has_psk)
{
	const char *field = NULL;
	if (obj->tls.cert.str != NULL) {
		field = "tls.cert";
	} else if (obj->tls.key.str != NULL) {
		field = "tls.key";
	} else if (obj->tls.authcerts_count > 0) {
		field = "tls.authcerts";
	} else if (obj->tls.system_trust) {
		field = "tls.system_trust";
	} else if (has_psk) {
		field = "tls.psk";
	}
	if (field != NULL) {
		LOGE_F("%s requires a TLS-enabled build", field);
		return false;
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

static bool
conf_load_mux(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	if (obj->mux.unacked_memory_limit == 0 ||
	    obj->mux.unacked_memory_limit > SIZE_MAX) {
		LOGE("mux.unacked_memory_limit must be a positive size_t value");
		return false;
	}
	cfg->mux.unacked_memory_limit = (size_t)obj->mux.unacked_memory_limit;
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
	cfg->mux.lossymux = obj->mux.lossymux.enabled;
	/* Schema-validated to [1, 86400] and [1, 65535], both fit int. */
	cfg->mux.lossymux_idle_timeout = (int)obj->mux.lossymux.idle_timeout;
	cfg->mux.lossymux_queue = (int)obj->mux.lossymux.queue;
	return true;
}

static void
conf_load_tcp(struct config *restrict cfg, const struct json_conf *restrict obj)
{
	LOAD_SOCKET_OPTS(&cfg->tcp, obj->tcp);
}

#undef LOAD_SOCKET_OPTS
#undef LOAD_NOTSENT_LOWAT

static bool conf_load_identity(
	struct config *restrict cfg, const struct json_conf *restrict obj,
	const struct present_conf_identity_listen *restrict listen)
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
	for (size_t i = 0; i < listen->count; i++) {
		const struct present_conf_identity_listen_entry *entry =
			&listen->entries[i];
		if (!identity_listen_cb(
			    cfg, entry->key.str, entry->key.len,
			    entry->value.str, entry->value.len)) {
			return false;
		}
	}
	return true;
}

/* Overlay explicit input on generated defaults. Missing strings without a
 * schema default stay NULL, preserving their distinction from an empty string.
 * This temporary view borrows both objects; neither allocation is transferred. */
static struct json_conf
conf_merge(const struct json_conf *defaults, const struct present_conf *input)
{
	struct json_conf obj = *defaults;
#define COPY_FIELD(dst, src, field)                                            \
	do {                                                                   \
		if ((src).has_##field) {                                       \
			(dst).field = (src).field;                             \
		}                                                              \
	} while (0)
#define COPY_STRING(dst, src, field)                                           \
	((dst).field =                                                         \
		 (src).has_##field ? (src).field : (struct json_string){ 0 })
	COPY_STRING(obj, (*input), api_listen);
	COPY_STRING(obj, (*input), connect);
	COPY_STRING(obj.identity, (*input).identity, claim);
	COPY_FIELD(obj.identity, (*input).identity, mux_connect);
	if (input->identity.has_mux_connect) {
		obj.identity.mux_connect_count =
			input->identity.mux_connect_count;
	}
	COPY_FIELD(obj.identity, (*input).identity, verify);
	COPY_STRING(obj, (*input), listen);
	COPY_STRING(obj, (*input), log);
	COPY_FIELD(obj, (*input), loglevel);
	COPY_FIELD(obj, (*input), max_sessions);
	COPY_STRING(obj, (*input), max_startups);
	COPY_FIELD(obj.mux, (*input).mux, connect_timeout);
	COPY_FIELD(obj.mux, (*input).mux, idle_timeout);
	COPY_FIELD(obj.mux, (*input).mux, keepalive);
	COPY_FIELD(obj.mux.lossymux, (*input).mux.lossymux, enabled);
	COPY_FIELD(obj.mux.lossymux, (*input).mux.lossymux, idle_timeout);
	COPY_FIELD(obj.mux.lossymux, (*input).mux.lossymux, queue);
	COPY_FIELD(obj.mux, (*input).mux, max_frame_size);
	COPY_FIELD(obj.mux, (*input).mux, max_halfopen);
	COPY_FIELD(obj.mux, (*input).mux, max_streams);
	COPY_FIELD(obj.mux.mem_pressure, (*input).mux.mem_pressure, hi);
	COPY_FIELD(obj.mux.mem_pressure, (*input).mux.mem_pressure, lo);
	COPY_FIELD(obj.mux, (*input).mux, nodelay);
	COPY_FIELD(obj.mux, (*input).mux, readahead);
	COPY_FIELD(obj.mux, (*input).mux, resume_timeout);
	COPY_FIELD(obj.mux, (*input).mux, send_timeout);
	COPY_FIELD(obj.mux, (*input).mux, session_window);
	COPY_FIELD(obj.mux, (*input).mux, unacked_memory_limit);
	COPY_FIELD(obj.mux, (*input).mux, stream_window);
	COPY_FIELD(obj.mux.tcp, (*input).mux.tcp, backlog);
	COPY_FIELD(obj.mux.tcp, (*input).mux.tcp, keepalive);
	COPY_FIELD(obj.mux.tcp, (*input).mux.tcp, nodelay);
	COPY_FIELD(obj.mux.tcp, (*input).mux.tcp, notsent_lowat);
	COPY_FIELD(obj.mux.tcp, (*input).mux.tcp, rcvbuf);
	COPY_FIELD(obj.mux.tcp, (*input).mux.tcp, reuseport);
	COPY_FIELD(obj.mux.tcp, (*input).mux.tcp, sndbuf);
	COPY_STRING(obj, (*input), mux_connect);
	COPY_STRING(obj, (*input), mux_listen);
	COPY_FIELD(obj.tcp, (*input).tcp, backlog);
	COPY_FIELD(obj.tcp, (*input).tcp, keepalive);
	COPY_FIELD(obj.tcp, (*input).tcp, nodelay);
	COPY_FIELD(obj.tcp, (*input).tcp, notsent_lowat);
	COPY_FIELD(obj.tcp, (*input).tcp, rcvbuf);
	COPY_FIELD(obj.tcp, (*input).tcp, reuseport);
	COPY_FIELD(obj.tcp, (*input).tcp, sndbuf);
	COPY_STRING(obj.tls, (*input).tls, alpn);
	COPY_FIELD(obj.tls, (*input).tls, authcerts);
	if (input->tls.has_authcerts) {
		obj.tls.authcerts_count = input->tls.authcerts_count;
	}
	COPY_STRING(obj.tls, (*input).tls, cert);
	COPY_STRING(obj.tls, (*input).tls, ciphersuites);
	COPY_FIELD(obj.tls, (*input).tls, kernel_offload);
	COPY_STRING(obj.tls, (*input).tls, key);
	COPY_FIELD(obj.tls, (*input).tls, sni);
	COPY_FIELD(obj.tls, (*input).tls, socket_offload);
	COPY_FIELD(obj.tls, (*input).tls, system_trust);
	COPY_STRING(obj, (*input), type);
#undef COPY_STRING
#undef COPY_FIELD
	return obj;
}

/* Load schema struct into config struct (strings strdup'd).  False on error. */
static bool conf_load(
	struct config *restrict cfg, const struct json_conf *defaults,
	const struct present_conf *input)
{
	const struct json_conf merged = conf_merge(defaults, input);
	const struct json_conf *obj = &merged;
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
	if (!conf_parse_max_startups(
		    cfg, obj->max_startups.str, obj->max_startups.len)) {
		return false;
	}

#if WITH_TLS
	if (!conf_load_tls(cfg, obj, &input->tls.psk)) {
		return false;
	}
#else /* WITH_TLS */
	if (!conf_check_no_tls(obj, input->tls.psk.count > 0)) {
		return false;
	}
#endif /* WITH_TLS */
	if (!conf_load_mux(cfg, obj)) {
		return false;
	}
	conf_load_tcp(cfg, obj);
	if (!conf_load_identity(cfg, obj, &input->identity.listen)) {
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
	const bool has_trust = has_authcerts || conf->tls_system_trust;

	if (has_psk && (has_cert || has_key || has_trust)) {
		LOGE("tls.psk is mutually exclusive with tls.cert, tls.key and"
		     " tls.authcerts or tls.system_trust: a PSK handshake sends no certificate");
		return false;
	}
	if (has_psk) {
		if (!conf_check_psk(conf)) {
			return false;
		}
	} else if (has_cert && has_key && has_trust) {
		/* Complete certificate credentials and at least one trust source. */
	} else if (!has_cert && !has_key && !has_trust) {
		LOGW("running in plaintext mode: connection is NOT encrypted");
	} else {
		LOGE("incomplete TLS configuration");
		return false;
	}
	if (has_psk) {
		/* No certificate to select, so the name has nothing to act on;
		 * leave it out of the ClientHello rather than send a hostname
		 * PSK mode never uses.  The schema's default fills tls.sni in
		 * whether or not the config set it, so there is no telling an
		 * explicit value apart to warn about. */
		free(conf->tls_sni);
		conf->tls_sni = NULL;
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
		     " set tls.cert, tls.key and either tls.authcerts or tls.system_trust");
		return false;
	}
#else /* WITH_TLS */
	if (conf->identity.verify) {
		LOGE("identity.verify requires a TLS-enabled build");
		return false;
	}
	/* conf_load already refused any TLS credential, so this build always
	 * runs the plaintext mode a credential-less TLS build warns about. */
	LOGW("running in plaintext mode: connection is NOT encrypted");
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

/* Free a buffer that may hold key material -- a config with an inline
 * credential, or a loaded credential file -- erasing its first @p len bytes
 * first. */
static void conf_free_sensitive(char *restrict buf, const size_t len)
{
#if WITH_TLS
	tls_secure_erase(buf, len);
#else
	/* No TLS library to erase with, and no credential is ever loaded. */
	(void)len;
#endif
	free(buf);
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
				conf_free_sensitive(buf, n);
				return NULL;
			}
			break;
		}
		rem -= rd;
	}
	if (n > CONF_MAXSIZE) {
		LOGE_F("%s exceeds maximum size of %d bytes: %s", desc,
		       CONF_MAXSIZE, path);
		conf_free_sensitive(buf, n);
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
	const struct present_conf input = { 0 };
	const bool ok = conf_load(conf, &obj, &input);
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
	struct present_conf input = { 0 };
	if (!present_unmarshal_ex_conf(&input, json, len, &conf_json_options)) {
		LOGE("failed to process configuration");
		conf_free(conf);
		return NULL;
	}
	char empty[] = "{}";
	struct json_conf defaults = { 0 };
	if (!json_unmarshal_conf(&defaults, empty, sizeof(empty) - 1)) {
		LOGOOM();
		present_free_conf(&input);
		conf_free(conf);
		return NULL;
	}
	const bool ok = conf_load(conf, &defaults, &input);
	json_free_conf(&defaults);
	present_free_conf(&input);
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
	/* The JSON is decoded in place, so an inline tls.key or tls.psk sits in
	 * buf verbatim, apart from the copies struct config erases. */
	conf_free_sensitive(buf, len);
	return conf;
}

/* Build a struct json_string view of s (NULL-safe: NULL maps to {NULL, 0}). */
static struct json_string json_str(char *s)
{
	return (struct json_string){
		.str = s,
		.len = s != NULL ? strlen(s) : 0,
	};
}

/* The generated maps borrow config strings; only the entry arrays are owned. */
static bool build_listen_map(
	const struct config *conf, struct present_conf_identity_listen *out)
{
	if (conf->identity.peers_count == 0) {
		return true;
	}
	out->entries =
		calloc(conf->identity.peers_count, sizeof(*out->entries));
	if (out->entries == NULL) {
		LOGOOM();
		return false;
	}
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		const struct identity_peer *peer = &conf->identity.peers[i];
		if (peer->listen != NULL) {
			out->entries[out->count++] =
				(struct present_conf_identity_listen_entry){
					.key = json_str(peer->id),
					.value = json_str(peer->listen),
				};
		}
	}
	return true;
}

#if WITH_TLS
static bool
build_psk_map(const struct config *conf, struct present_conf_tls_psk *out)
{
	if (conf->tls_psk_count == 0) {
		return true;
	}
	out->entries = calloc(conf->tls_psk_count, sizeof(*out->entries));
	if (out->entries == NULL) {
		LOGOOM();
		return false;
	}
	out->count = conf->tls_psk_count;
	for (size_t i = 0; i < out->count; i++) {
		out->entries[i] = (struct present_conf_tls_psk_entry){
			.key = json_str(conf->tls_psk[i].id),
			.value = json_str(conf->tls_psk[i].hex),
		};
	}
	return true;
}
#endif /* WITH_TLS */

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
	/* Heap temporaries feed the `raw` literal below; they are released
	 * once at the cleanup label so a future addition need only be freed there.
	 * out is freed on the failure branch (NULL'd once handed to result). */
	struct present_conf_identity_listen listen_map = { 0 };
	struct json_string *id_mc_arr = NULL;
#if WITH_TLS
	struct json_string *authcerts_arr = NULL;
	struct present_conf_tls_psk psk_map = { 0 };
#endif
	char *out = NULL;
	char *result = NULL;

	if (!build_listen_map(conf, &listen_map)) {
		goto cleanup;
	}
#if WITH_TLS
	if (!build_psk_map(conf, &psk_map)) {
		goto cleanup;
	}
#endif

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

	const struct present_conf raw = {
		/* Always dump the canonical CONF_TYPE literal rather than
		 * conf->type: conf_check_type accepts equivalent variants
		 * (different case, whitespace, parameter order, or extra
		 * parameters), so the original string need not match it. */
		.has_type = true,
		.type = { .str = CONF_TYPE, .len = sizeof(CONF_TYPE) - 1 },
		.has_api_listen = conf->api_listen != NULL,
		.api_listen = json_str(conf->api_listen),
		.has_mux_listen = conf->mux_listen != NULL,
		.mux_listen = json_str(conf->mux_listen),
		.has_mux_connect = conf->mux_connect != NULL,
		.mux_connect = json_str(conf->mux_connect),
		.has_listen = conf->listen != NULL,
		.listen = json_str(conf->listen),
		.has_connect = conf->connect != NULL,
		.connect = json_str(conf->connect),
		.has_log = conf->log != NULL,
		.log = json_str(conf->log),
		.has_loglevel = true,
		.loglevel = (unsigned)conf->loglevel,
		.has_max_sessions = true,
		.max_sessions = (uintmax_t)conf->max_sessions,
		.has_max_startups = max_startups != NULL,
		.max_startups = {
			.str = max_startups,
			.len = max_startups_len,
		},
#if WITH_TLS
		.has_tls = true,
		.tls = {
			.has_cert = conf->tls_cert != NULL,
			.cert = json_str(conf->tls_cert),
			.has_key = conf->tls_key != NULL,
			.key = json_str(conf->tls_key),
			.has_ciphersuites = conf->tls_ciphersuites != NULL,
			.ciphersuites = json_str(conf->tls_ciphersuites),
			.has_sni = conf->tls_sni != NULL,
			.sni = json_str(conf->tls_sni),
			.has_alpn = conf->tls_alpn != NULL,
			.alpn = json_str(conf->tls_alpn),
			.has_authcerts = conf->tls_authcerts_count > 0,
			.authcerts = authcerts_arr,
			.authcerts_count = conf->tls_authcerts_count,
			.has_system_trust = true,
			.system_trust = conf->tls_system_trust,
			.has_kernel_offload = true,
			.kernel_offload = conf->tls_kernel_offload,
			.has_socket_offload = true,
			.socket_offload = conf->tls_socket_offload,
			.has_psk = psk_map.count > 0,
			.psk = psk_map,
		},
#endif /* WITH_TLS */
		.has_mux = true,
		.mux = {
			.has_nodelay = true,
			.nodelay = conf->mux.nodelay,
			.has_tcp = true,
			.tcp = {
				.has_reuseport = true,
				.reuseport = conf->mux_tcp.tcp_reuseport,
				.has_keepalive = true,
				.keepalive = conf->mux_tcp.tcp_keepalive,
				.has_nodelay = true,
				.nodelay = conf->mux_tcp.tcp_nodelay,
				.has_sndbuf = true,
				.sndbuf = (uintmax_t)conf->mux_tcp.tcp_sndbuf,
				.has_rcvbuf = true,
				.rcvbuf = (uintmax_t)conf->mux_tcp.tcp_rcvbuf,
#if WITH_TCP_NOTSENT_LOWAT
				.has_notsent_lowat = true,
				.notsent_lowat =
					(uintmax_t)conf->mux_tcp
						.tcp_notsent_lowat,
#endif
				.has_backlog = true,
				.backlog = (unsigned)conf->mux_tcp.backlog,
			},
			.has_max_halfopen = true,
			.max_halfopen = (unsigned)conf->mux.max_halfopen,
			.has_max_streams = true,
			.max_streams = (uintmax_t)conf->mux.max_streams,
			.has_connect_timeout = true,
			.connect_timeout = (unsigned)conf->mux.connect_timeout,
			.has_keepalive = true,
			.keepalive = (unsigned)conf->mux.keepalive,
			.has_send_timeout = true,
			.send_timeout = (unsigned)conf->mux.send_timeout,
			.has_idle_timeout = true,
			.idle_timeout = (unsigned)conf->mux.idle_timeout,
			.has_resume_timeout = true,
			.resume_timeout = (unsigned)conf->mux.resume_timeout,
			.has_session_window = true,
			.session_window = (unsigned)session_window_bytes,
			.has_unacked_memory_limit = true,
			.unacked_memory_limit = (uintmax_t)conf->mux.unacked_memory_limit,
			.has_stream_window = true,
			.stream_window = (unsigned)stream_window_bytes,
			.has_readahead = true,
			.readahead = (unsigned)conf->mux.readahead,
			.has_max_frame_size = true,
			.max_frame_size = (unsigned)(
				(uint_least32_t)conf->mux.max_frame_payload +
				MUX_FRAME_HEADER_SIZE),
			.has_mem_pressure = true,
			.mem_pressure = {
				.has_hi = true,
				.hi = (uintmax_t)conf->mux.mem_pressure_hi,
				.has_lo = true,
				.lo = (uintmax_t)conf->mux.mem_pressure_lo,
			},
			.has_lossymux = true,
			.lossymux = {
				.has_enabled = true,
				.enabled = conf->mux.lossymux,
				.has_idle_timeout = true,
				.idle_timeout =
					(unsigned)conf->mux.lossymux_idle_timeout,
				.has_queue = true,
				.queue = (unsigned)conf->mux.lossymux_queue,
			},
		},
		.has_tcp = true,
		.tcp = {
			.has_reuseport = true,
			.reuseport = conf->tcp.tcp_reuseport,
			.has_keepalive = true,
			.keepalive = conf->tcp.tcp_keepalive,
			.has_nodelay = true,
			.nodelay = conf->tcp.tcp_nodelay,
			.has_sndbuf = true,
			.sndbuf = (uintmax_t)conf->tcp.tcp_sndbuf,
			.has_rcvbuf = true,
			.rcvbuf = (uintmax_t)conf->tcp.tcp_rcvbuf,
#if WITH_TCP_NOTSENT_LOWAT
			.has_notsent_lowat = true,
			.notsent_lowat = (uintmax_t)conf->tcp.tcp_notsent_lowat,
#endif
			.has_backlog = true,
			.backlog = (unsigned)conf->tcp.backlog,
		},
		.has_identity = true,
		.identity = {
			.has_claim = conf->identity.claim != NULL,
			.claim = json_str(conf->identity.claim),
			.has_mux_connect = conf->identity.mux_connect_count > 0,
			.mux_connect = id_mc_arr,
			.mux_connect_count = conf->identity.mux_connect_count,
			.has_listen = listen_map.count > 0,
			.listen = listen_map,
			.has_verify = true,
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
		present_marshal_conf(out, CONF_MAXSIZE + 1, &raw, indent);
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
	free(listen_map.entries);
	free(id_mc_arr);
#if WITH_TLS
	free(authcerts_arr);
	free(psk_map.entries);
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
	size_t len;
	char *const content = read_file(name, *sp + 1, &len);
	if (content == NULL) {
		LOGE_F("failed to inline PEM field: %s", name);
		return false;
	}
	if (memchr(content, '\0', len) != NULL) {
		LOGE_F("%s: contains an embedded NUL character", name);
		/* read_stream allocates a fixed-size buffer. Erase it all, so
		 * bytes after the invalid NUL cannot survive rejection. */
		conf_free_sensitive(content, CONF_MAXSIZE + 1);
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
	 * "@path" convention and the loader are identical.  conf_check_psk()
	 * already validated every inline key; a loaded one can only be validated
	 * here, once the reference is resolved. */
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		struct psk_entry *const restrict e = &conf->tls_psk[i];
		if (e->hex[0] != '@') {
			continue;
		}
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

void conf_erase_credentials(const struct config *restrict conf)
{
	if (conf->tls_cert != NULL) {
		tls_secure_erase(conf->tls_cert, strlen(conf->tls_cert));
	}
	if (conf->tls_key != NULL) {
		tls_secure_erase(conf->tls_key, strlen(conf->tls_key));
	}
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		if (conf->tls_authcerts[i] != NULL) {
			tls_secure_erase(
				conf->tls_authcerts[i],
				strlen(conf->tls_authcerts[i]));
		}
	}
	if (conf->tls_authcerts_bundle != NULL) {
		tls_secure_erase(
			conf->tls_authcerts_bundle,
			strlen(conf->tls_authcerts_bundle));
	}
	/* The hex form is what struct config holds, so strlen covers it; the
	 * decoded copies live in struct psk_table and are erased with it. */
	for (size_t i = 0; i < conf->tls_psk_count; i++) {
		if (conf->tls_psk[i].hex != NULL) {
			tls_secure_erase(
				conf->tls_psk[i].hex,
				strlen(conf->tls_psk[i].hex));
		}
	}
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
	conf_erase_credentials(conf);
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
