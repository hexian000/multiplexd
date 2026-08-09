/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tls_mbedtls.c
 * @brief TLS utility functions implemented with mbedTLS native API.
 */

#if WITH_TLS

#include "shim/tls.h"
#include "shim/util.h"

#include "meta/minmax.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <mbedtls/asn1.h>
#include <mbedtls/build_info.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/private_access.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

/* mbedTLS < 4.0 uses an explicit CTR-DRBG/entropy RNG; 4.x uses PSA crypto
 * and removes those APIs. Derive a feature flag once to avoid repeating the
 * version number comparison throughout this file. */
#if MBEDTLS_VERSION_NUMBER < 0x04000000
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#define MBEDTLS_LEGACY_RNG
#else
#include <psa/crypto.h>
#endif

/* Production shares one tls_ctx_impl -- and therefore one mbedtls_ssl_config --
 * across tunnel threads, which run handshakes concurrently against the
 * library's global crypto state (4.x: the PSA core; 3.x: the ctr_drbg wired via
 * mbedtls_ssl_conf_rng). mbedTLS documents that as thread-safe only when built
 * with MBEDTLS_THREADING_C, which upstream leaves off by default; without it
 * the races are undefined behavior and can reach nonce reuse. Fail the build
 * rather than ship it: no m.sh configuration pairs threads with this backend,
 * so only the unsafe combination is blocked. */
#if WITH_THREADS && !defined(MBEDTLS_THREADING_C)
#error "ENABLE_THREADS with the mbedTLS backend requires an mbedTLS built with MBEDTLS_THREADING_C"
#endif

#include <assert.h>
#include <errno.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

struct tls_ctx_impl {
	/* Reference count: mbedTLS has no library-level refcount for the parsed
	 * ssl_config, so siblings produced by tls_ctx_ref() and every live
	 * connection (tls_conn_alloc) share this struct, and the last release
	 * (tls_ctx_free / tls_conn_free) frees it.  Relaxed-atomic under threads. */
#if WITH_THREADS
	atomic_size_t refcount;
#else
	size_t refcount;
#endif
	mbedtls_ssl_config conf;
	mbedtls_x509_crt own_cert;
	mbedtls_pk_context own_key;
	mbedtls_x509_crt ca_chain;
	bool ca_chain_loaded;
	/* NULL-terminated by 0 */
	int *ciphersuites;
	/* client SNI hostname; NULL omits the extension */
	char *sni;
	/* ALPN protocol list: NULL-terminated array of heap strings retained
	 * for the lifetime of conf (mbedtls keeps the pointer). NULL = none. */
	char **alpn;
	/* External PSK credentials, replacing certificate authentication.
	 * Client role: the offered key and its derived label, both retained for
	 * conf's lifetime because mbedtls_ssl_conf_psk() keeps the pointers.
	 * Server role: the lookup that resolves a label the client offered. */
	unsigned char psk[TLS_PSK_MAX_LEN];
	size_t psk_len;
	char psk_label[TLS_PSK_LABEL_MAX + 1];
	tls_psk_lookup_fn psk_lookup;
	void *psk_lookup_ctx;
#ifdef MBEDTLS_LEGACY_RNG
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
#endif
};

struct tls_conn_impl {
	mbedtls_ssl_context ssl;
	/* Owning context: mbedtls_ssl_setup() stores a raw pointer into ctx->conf
	 * inside ssl, so the connection holds a reference (released in
	 * tls_conn_free) to keep the config alive for its whole lifetime, matching
	 * OpenSSL's SSL_new() up-ref of the SSL_CTX. */
	struct tls_ctx_impl *ctx;
	/* socket fd, or -1 for a buffered (memory-transport) connection */
	int fd;
	/* I/O event notifier; see struct tls_callback. */
	struct tls_callback cb;
	/* Buffered mode ciphertext staging (heap, owned); unused when fd >= 0.
	 * in: received ciphertext awaiting decryption (in[in_off .. in_off+in_len)).
	 * out: produced ciphertext awaiting the transport (out[out_off .. +out_len)). */
	unsigned char *in;
	size_t in_off, in_len, in_cap;
	unsigned char *out;
	size_t out_off, out_len, out_cap;
	/* PSK identity label this connection authenticated with; empty for a
	 * certificate handshake.  Recorded by the server's lookup callback as
	 * the handshake selects it, and copied from the context for a client. */
	char psk_label[TLS_PSK_LABEL_MAX + 1];
};

static struct tls_ctx_impl *tls_ctx_raw(struct tls_context *restrict ctx)
{
	return (struct tls_ctx_impl *)ctx;
}

static struct tls_conn_impl *tls_conn_raw(struct tls_connection *restrict conn)
{
	return (struct tls_conn_impl *)conn;
}

/* Fire the on_send notifier when memory-backed output ciphertext is staged. */
static void tls_fire_send(struct tls_conn_impl *restrict c)
{
	if (c->fd < 0 && c->cb.on_send != NULL && c->out_len > 0) {
		c->cb.on_send(c->cb.ctx);
	}
}

/* Fire on_recv when more plaintext is available without another socket read:
 * mbedtls_ssl_check_pending misses ciphertext staged in conn->in (buffered
 * mode pulls one record at a time), so test in_len too. */
static void tls_fire_recv(struct tls_conn_impl *restrict c)
{
	if (c->cb.on_recv == NULL) {
		return;
	}
	if (mbedtls_ssl_check_pending(&c->ssl) != 0 ||
	    (c->fd < 0 && c->in_len > 0)) {
		c->cb.on_recv(c->cb.ctx);
	}
}

#define LOG_MBEDERROR(level, s, err)                                           \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			char errbuf[160];                                      \
			mbedtls_strerror((err), errbuf, sizeof(errbuf));       \
			LOG_F(level, "%s: -0x%04x %s", (s),                    \
			      (unsigned int)-(err), errbuf);                   \
		}                                                              \
	} while (0)

const char *tls_version(void)
{
	return "mbedTLS " MBEDTLS_VERSION_STRING;
}

/* mbedtls_x509_crt_parse[_file] returns 0 on full success, a negative mbedTLS
 * error on total failure, or a positive count of certificates it could not
 * parse in an otherwise-usable bundle. Log whichever applies -- LOG_MBEDERROR
 * only renders negative codes, so a positive count must be reported directly --
 * and return true iff the parse fully succeeded. */
static bool tls_crt_parse_ok(const int ret)
{
	if (ret < 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_x509_crt_parse", ret);
		return false;
	}
	if (ret > 0) {
		LOGE_F("mbedtls_x509_crt_parse: %d certificate(s) could not be"
		       " parsed",
		       ret);
		return false;
	}
	return true;
}

/* Load a PEM blob (text). mbedTLS parsers expect the trailing NUL byte to be
 * counted in the length. */
static int
parse_cert_buffer(mbedtls_x509_crt *restrict chain, const char *restrict data)
{
	return mbedtls_x509_crt_parse(
		chain, (const unsigned char *)data, strlen(data) + 1U);
}

bool tls_load_cert(
	struct tls_context *restrict ctx, const char *restrict cert_data)
{
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	if (c == NULL) {
		LOGE("tls_load_cert: ctx is NULL");
		return false;
	}
	/* Reset to allow re-loading without appending to an existing chain. */
	mbedtls_x509_crt_free(&c->own_cert);
	mbedtls_x509_crt_init(&c->own_cert);
	int ret;
	switch (*cert_data) {
	case '\0':
		LOGE("certificate data is empty");
		return false;
	case '@':
		ret = mbedtls_x509_crt_parse_file(&c->own_cert, cert_data + 1);
		break;
	default:
		ret = parse_cert_buffer(&c->own_cert, cert_data);
		break;
	}
	return tls_crt_parse_ok(ret);
}

bool tls_load_key(
	struct tls_context *restrict ctx, const char *restrict key_data)
{
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	if (c == NULL) {
		LOGE("tls_load_key: ctx is NULL");
		return false;
	}
	/* Reset to allow re-loading: mbedtls_pk_parse_key rejects a non-empty
	 * key context. */
	mbedtls_pk_free(&c->own_key);
	mbedtls_pk_init(&c->own_key);
	int ret;
	switch (*key_data) {
	case '\0':
		LOGE("key data is empty");
		return false;
	case '@':
		ret = mbedtls_pk_parse_keyfile(
			&c->own_key, key_data + 1, NULL
#ifdef MBEDTLS_LEGACY_RNG
			,
			mbedtls_ctr_drbg_random, &c->ctr_drbg
#endif
		);
		break;
	default:
		ret = mbedtls_pk_parse_key(
			&c->own_key, (const unsigned char *)key_data,
			strlen(key_data) + 1U, NULL, 0
#ifdef MBEDTLS_LEGACY_RNG
			,
			mbedtls_ctr_drbg_random, &c->ctr_drbg
#endif
		);
		break;
	}
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_pk_parse_key", ret);
		return false;
	}
	return true;
}

bool tls_load_authcerts(
	struct tls_context *restrict ctx, char *const *restrict authcerts,
	size_t count)
{
	if (ctx == NULL) {
		LOGE("tls_load_authcerts: ctx is NULL");
		return false;
	}
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	if (authcerts == NULL || count == 0) {
		return true;
	}
	for (size_t i = 0; i < count; i++) {
		if (authcerts[i] == NULL) {
			LOGE_F("authcerts[%zu] is NULL", i);
			return false;
		}
		int ret;
		switch (*authcerts[i]) {
		case '\0':
			LOGE_F("authcerts[%zu] is empty", i);
			return false;
		case '@':
			ret = mbedtls_x509_crt_parse_file(
				&c->ca_chain, authcerts[i] + 1);
			break;
		default:
			ret = parse_cert_buffer(&c->ca_chain, authcerts[i]);
			break;
		}
		if (!tls_crt_parse_ok(ret)) {
			return false;
		}
		c->ca_chain_loaded = true;
	}
	return true;
}

/* Mutable copy for tokenizing; cap includes one terminator slot. */
static char *dup_for_tokens(
	const char *restrict list, const char delim, size_t *restrict cap)
{
	const size_t n = strlen(list);
	char *const dup = malloc(n + 1);
	if (dup == NULL) {
		return NULL;
	}
	memcpy(dup, list, n + 1);
	size_t count = 1;
	for (size_t i = 0; i < n; i++) {
		if (dup[i] == delim) {
			count++;
		}
	}
	*cap = count + 1;
	return dup;
}

/* Parse an OpenSSL-style colon-separated list of ciphersuite names into a
 * mbedTLS id array, terminated by 0. Fails closed to match OpenSSL's
 * SSL_CTX_set_ciphersuites(): returns NULL on allocation failure, an empty
 * list, or if any single name fails to resolve or isn't usable with the
 * pinned TLS-1.3-only context -- not just when every name is unusable. */
static int *parse_ciphersuites(const char *restrict list)
{
	size_t cap = 0;
	char *const dup = dup_for_tokens(list, ':', &cap);
	if (dup == NULL) {
		LOGOOM();
		return NULL;
	}

	int *const ids = malloc(sizeof(int) * cap);
	if (ids == NULL) {
		LOGOOM();
		free(dup);
		return NULL;
	}
	size_t k = 0;
	char *save = NULL;
	for (char *tok = strtok_r(dup, ":", &save); tok != NULL;
	     tok = strtok_r(NULL, ":", &save)) {
		/* from_string(), not get_ciphersuite_id(), so the applicability
		 * check below reuses this lookup instead of resolving twice. */
		const mbedtls_ssl_ciphersuite_t *const info =
			mbedtls_ssl_ciphersuite_from_string(tok);
		if (info == NULL) {
			LOGE_F("mbedtls: unknown ciphersuite '%s'", tok);
			free(ids);
			free(dup);
			return NULL;
		}
		/* No applicability check against the pinned TLS-1.3-only
		 * context (min=max=TLS1_3), unlike OpenSSL's
		 * SSL_CTX_set_ciphersuites(); reject here instead of only
		 * surfacing as an unnegotiable handshake failure later. */
		if (info->MBEDTLS_PRIVATE(min_tls_version) >
			    MBEDTLS_SSL_VERSION_TLS1_3 ||
		    info->MBEDTLS_PRIVATE(max_tls_version) <
			    MBEDTLS_SSL_VERSION_TLS1_3) {
			LOGE_F("mbedtls: ciphersuite '%s' is not usable with TLS 1.3",
			       tok);
			free(ids);
			free(dup);
			return NULL;
		}
		ids[k++] = mbedtls_ssl_ciphersuite_get_id(info);
	}
	ids[k] = 0;
	free(dup);
	if (k == 0) {
		free(ids);
		return NULL;
	}
	return ids;
}

struct alpn_collect {
	char **arr;
	size_t k;
};

/* alpn_field_fn: append a heap copy of each ALPN name to the array. */
static bool alpn_collect_field(void *ctx, const char *name, const size_t len)
{
	(void)len;
	struct alpn_collect *const a = ctx;
	char *const s = strdup(name);
	if (s == NULL) {
		LOGOOM();
		return false;
	}
	a->arr[a->k++] = s;
	return true;
}

/* Parse a comma-separated ALPN list into the NULL-terminated heap array
 * mbedtls_ssl_conf_alpn_protocols expects; uses RFC 4180 CSV so a name may
 * contain a comma when quoted.  On success sets *out (NULL for a legitimately
 * absent or all-empty list, else a heap array the caller frees) and returns
 * true; returns false on OOM or a malformed list so context creation fails
 * closed rather than silently dropping the operator's configured ALPN (matching
 * the OpenSSL backend). */
static bool parse_alpn(const char *restrict list, char ***restrict out)
{
	*out = NULL;
	if (list == NULL || list[0] == '\0') {
		return true;
	}
	/* alpn_tokenize parses the buffer in-place, so work on a mutable copy. */
	size_t cap = 0;
	char *const work = dup_for_tokens(list, ',', &cap);
	if (work == NULL) {
		LOGOOM();
		return false;
	}
	char **const arr = (char **)calloc(cap, sizeof(*arr));
	if (arr == NULL) {
		LOGOOM();
		free(work);
		return false;
	}
	struct alpn_collect a = { .arr = arr, .k = 0 };
	const bool ok = alpn_tokenize(work, list, alpn_collect_field, &a);
	free(work);
	if (!ok) {
		for (size_t i = 0; i < a.k; i++) {
			free(arr[i]);
		}
		free((void *)arr);
		return false;
	}
	if (a.k == 0) {
		/* All fields empty (e.g. ",,"): no protocols, but not an error. */
		free((void *)arr);
		return true;
	}
	arr[a.k] = NULL;
	*out = arr;
	return true;
}

static void tls_ctx_impl_init(struct tls_ctx_impl *restrict c)
{
#if WITH_THREADS
	atomic_init(&c->refcount, (size_t)1);
#else
	c->refcount = 1;
#endif
	mbedtls_ssl_config_init(&c->conf);
	mbedtls_x509_crt_init(&c->own_cert);
	mbedtls_pk_init(&c->own_key);
	mbedtls_x509_crt_init(&c->ca_chain);
	c->ca_chain_loaded = false;
	c->ciphersuites = NULL;
	c->sni = NULL;
	c->alpn = NULL;
#ifdef MBEDTLS_LEGACY_RNG
	mbedtls_ctr_drbg_init(&c->ctr_drbg);
	mbedtls_entropy_init(&c->entropy);
#endif
}

static void tls_ctx_impl_free(struct tls_ctx_impl *restrict c)
{
	/* Before freeing the config, which still points at c->psk. */
	mbedtls_platform_zeroize(c->psk, sizeof(c->psk));
	c->psk_len = 0;
	mbedtls_ssl_config_free(&c->conf);
	mbedtls_x509_crt_free(&c->own_cert);
	mbedtls_pk_free(&c->own_key);
	mbedtls_x509_crt_free(&c->ca_chain);
	free(c->ciphersuites);
	free(c->sni);
	if (c->alpn != NULL) {
		for (char **p = c->alpn; *p != NULL; p++) {
			free(*p);
		}
		free((void *)c->alpn);
	}
#ifdef MBEDTLS_LEGACY_RNG
	mbedtls_ctr_drbg_free(&c->ctr_drbg);
	mbedtls_entropy_free(&c->entropy);
#endif
	free(c);
}

/* Take a reference on the shared parsed config. tls_ctx_ref() and every live
 * connection (whose mbedtls_ssl_context holds a raw pointer into c->conf) hold
 * one; the config outlives them all. */
static void tls_ctx_impl_ref(struct tls_ctx_impl *restrict c)
{
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(&c->refcount, 1, memory_order_relaxed);
#else
	c->refcount++;
#endif
}

/* Release a reference taken by tls_ctx_impl_ref(); the last owner frees c. */
static void tls_ctx_impl_unref(struct tls_ctx_impl *restrict c)
{
#if WITH_THREADS
	if (atomic_fetch_sub_explicit(&c->refcount, 1, memory_order_acq_rel) !=
	    1) {
		return;
	}
#else /* WITH_THREADS */
	if (--c->refcount != 0) {
		return;
	}
#endif /* WITH_THREADS */
	tls_ctx_impl_free(c);
}

/* Verify callback: accept any CA-trusted certificate regardless of hostname.
 * Clears the CN-mismatch flag from the empty hostname passed to tls_client;
 * all other verification failures are preserved. */
static int tls_ca_verify(
	void *data, mbedtls_x509_crt *crt, int depth, uint32_t *restrict flags)
{
	(void)data;
	(void)crt;
	(void)depth;
	*flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
	return 0;
}

#ifndef MBEDTLS_LEGACY_RNG
/* mbedTLS 4.1.0 leaves RSA PKCS8 pub_raw empty, breaking
 * mbedtls_pk_check_pair(). DER-writing re-derives it through public API,
 * so comparing canonical public-key DER sidesteps the upstream bug. */
static bool tls_pk_pair_matches(
	const mbedtls_pk_context *restrict cert_pk,
	const mbedtls_pk_context *restrict key)
{
	unsigned char cert_der[MBEDTLS_PK_MAX_PUBKEY_RAW_LEN + 64];
	unsigned char key_der[MBEDTLS_PK_MAX_PUBKEY_RAW_LEN + 64];
	const int cert_len = mbedtls_pk_write_pubkey_der(
		cert_pk, cert_der, sizeof(cert_der));
	if (cert_len <= 0) {
		LOG_MBEDERROR(
			ERROR, "mbedtls_pk_write_pubkey_der (cert)", cert_len);
		return false;
	}
	const int key_len =
		mbedtls_pk_write_pubkey_der(key, key_der, sizeof(key_der));
	if (key_len <= 0) {
		LOG_MBEDERROR(
			ERROR, "mbedtls_pk_write_pubkey_der (key)", key_len);
		return false;
	}
	/* Both writers fill from the end of their buffer; see each function's
	 * own doc comment in mbedtls/pk.h. A genuine mismatch is diagnosed here so
	 * the caller cannot misreport an export failure as "keys differ". */
	if (cert_len != key_len ||
	    memcmp(cert_der + sizeof(cert_der) - (size_t)cert_len,
		   key_der + sizeof(key_der) - (size_t)key_len,
		   (size_t)cert_len) != 0) {
		LOGE("certificate and private key do not match");
		return false;
	}
	return true;
}
#endif /* MBEDTLS_LEGACY_RNG */

/* True when the config selects PSK rather than certificate authentication. */
static bool tls_conf_is_psk(const struct tls_config *restrict conf)
{
	return conf->psk_lookup != NULL || conf->psk_len > 0;
}

/* mbedTLS hands the callback the ssl object, not our wrapper.  tls_conn_impl
 * embeds it as its first member, so the wrapper is recoverable by cast --
 * asserted here rather than assumed. */
static_assert(
	offsetof(struct tls_conn_impl, ssl) == 0,
	"tls_conn_impl must start with its mbedtls_ssl_context");

/* Server role: resolve the label the client offered and install its key for
 * this handshake.  A non-zero return rejects the handshake; a PSK-mode context
 * has no certificate to fall back to. */
static int psk_lookup_cb(
	void *p, mbedtls_ssl_context *ssl, const unsigned char *identity,
	size_t identity_len)
{
	struct tls_ctx_impl *const restrict c = p;
	if (c->psk_lookup == NULL) {
		return -1;
	}
	/* Attacker-chosen and not NUL-terminated: bound it, and reject an
	 * embedded NUL rather than truncating to a shorter label that might
	 * resolve to a different peer's key. */
	if (identity_len > TLS_PSK_LABEL_MAX ||
	    memchr(identity, '\0', identity_len) != NULL) {
		return -1;
	}
	char label[TLS_PSK_LABEL_MAX + 1];
	memcpy(label, identity, identity_len);
	label[identity_len] = '\0';

	unsigned char key[TLS_PSK_MAX_LEN];
	size_t key_len = sizeof(key);
	if (!c->psk_lookup(c->psk_lookup_ctx, label, key, &key_len)) {
		return -1;
	}
	const int ret = mbedtls_ssl_set_hs_psk(ssl, key, key_len);
	mbedtls_platform_zeroize(key, sizeof(key));
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_ssl_set_hs_psk", ret);
		return -1;
	}
	struct tls_conn_impl *const restrict conn =
		(struct tls_conn_impl *)(void *)ssl;
	memcpy(conn->psk_label, label, identity_len + 1);
	return 0;
}

/* Install PSK credentials, replacing certificate authentication.  The client's
 * key and label are retained in the context because mbedtls_ssl_conf_psk()
 * keeps the pointers rather than copying. */
static bool tls_ctx_set_psk(
	struct tls_ctx_impl *restrict c, const struct tls_config *restrict conf,
	const bool is_server)
{
	if (is_server) {
		c->psk_lookup = conf->psk_lookup;
		c->psk_lookup_ctx = conf->psk_lookup_ctx;
		mbedtls_ssl_conf_psk_cb(&c->conf, psk_lookup_cb, c);
		return true;
	}
	if (conf->psk_len < TLS_PSK_MIN_LEN ||
	    conf->psk_len > TLS_PSK_MAX_LEN) {
		LOGE("tls.psk: key length out of range");
		return false;
	}
	memcpy(c->psk, conf->psk, conf->psk_len);
	c->psk_len = conf->psk_len;
	size_t label_len = sizeof(c->psk_label);
	if (!tls_psk_label(c->psk, c->psk_len, c->psk_label, &label_len)) {
		LOGE("tls.psk: failed to derive the identity label");
		return false;
	}
	const int ret = mbedtls_ssl_conf_psk(
		&c->conf, c->psk, c->psk_len,
		(const unsigned char *)c->psk_label, label_len);
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_ssl_conf_psk", ret);
		return false;
	}
	return true;
}

static struct tls_context *
tls_ctx_init(const struct tls_config *restrict conf, const bool is_server)
{
	/* Zero-initialized, like the connection below and both of the OpenSSL
	 * backend's allocations: the PSK credentials have no constructor of
	 * their own -- only the role that uses them fills them in, and
	 * tls_conn_alloc() reads psk_len for every connection regardless. */
	struct tls_ctx_impl *const c = calloc(1, sizeof(*c));
	if (c == NULL) {
		LOGOOM();
		return NULL;
	}
	tls_ctx_impl_init(c);
	struct tls_context *const ctx = (struct tls_context *)c;

#ifdef MBEDTLS_LEGACY_RNG
	{
		const int drbg_ret = mbedtls_ctr_drbg_seed(
			&c->ctr_drbg, mbedtls_entropy_func, &c->entropy, NULL,
			0);
		if (drbg_ret != 0) {
			LOG_MBEDERROR(ERROR, "mbedtls_ctr_drbg_seed", drbg_ret);
			tls_ctx_free(ctx);
			return NULL;
		}
	}
#else /* MBEDTLS_LEGACY_RNG */
	{
		const psa_status_t psa_ret = psa_crypto_init();
		if (psa_ret != PSA_SUCCESS) {
			LOGE_F("psa_crypto_init: %d", (int)psa_ret);
			tls_ctx_free(ctx);
			return NULL;
		}
	}
#endif /* MBEDTLS_LEGACY_RNG */

	int ret = mbedtls_ssl_config_defaults(
		&c->conf,
		is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_ssl_config_defaults", ret);
		tls_ctx_free(ctx);
		return NULL;
	}
	/* MBEDTLS_SSL_PRESET_DEFAULT leaves conf->cert_profile at
	 * mbedtls_x509_crt_profile_default (signature digest SHA-256/384/512 --
	 * the SHA-3 family was added to this profile only in mbedTLS 4.2.0, above
	 * the supported 3.6 LTS / 4.0 / 4.1 floor; RSA >= 2048 bits; curves at or
	 * above the 128-bit security level, excluding e.g. P-224), applied to the
	 * peer's chain during verification -- except the trust anchor, whose own
	 * self-signature digest is not checked. tls_verify_cert_strength_cb() in
	 * the OpenSSL backend mirrors this floor so both backends accept/reject
	 * the same certificates; keep the two in sync. */
	mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
	/* mux implements its own session resumption, so TLS 1.3 session tickets
	 * are redundant stateful surface; the OpenSSL backend disables them via
	 * SSL_OP_NO_TICKET + SSL_CTX_set_num_tickets(0). Client-side only here:
	 * mbedTLS gates server-side issuance on a ticket callback this backend
	 * never installs, so a server issues none either way. */
	mbedtls_ssl_conf_session_tickets(
		&c->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif
	mbedtls_ssl_conf_max_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	if (conf->kernel_offload) {
		LOGW("tls.kernel_offload: not supported by the mbedTLS backend; "
		     "ignored");
	}
	if (conf->readahead) {
		LOGW("mux.readahead: not supported by the mbedTLS backend; "
		     "ignored");
	}
#ifdef MBEDTLS_LEGACY_RNG
	mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->ctr_drbg);
#endif
	const bool is_psk = tls_conf_is_psk(conf);
	if (is_psk) {
		/* A PSK handshake carries no certificate in either direction, so
		 * no trust store applies and no verification callback runs. */
		mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_NONE);
		/* Ephemeral only: bare psk_ke would drop forward secrecy. */
		mbedtls_ssl_conf_tls13_key_exchange_modes(
			&c->conf,
			MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);
		if (!tls_ctx_set_psk(c, conf, is_server)) {
			tls_ctx_free(ctx);
			return NULL;
		}
	} else {
		/* See OpenSSL backend for the rationale: private CA gates transport
		 * authentication; application-level identity comes from the hello. */
		mbedtls_ssl_conf_authmode(
			&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		/* tls_client always calls mbedtls_ssl_set_hostname(); this callback clears
		 * the resulting CN-mismatch flag. */
		mbedtls_ssl_conf_verify(&c->conf, tls_ca_verify, NULL);

		if (!tls_load_cert(ctx, conf->cert)) {
			LOGE("failed to load TLS certificate");
			tls_ctx_free(ctx);
			return NULL;
		}
		if (!tls_load_key(ctx, conf->key)) {
			LOGE("failed to load TLS private key");
			tls_ctx_free(ctx);
			return NULL;
		}
		ret = mbedtls_ssl_conf_own_cert(
			&c->conf, &c->own_cert, &c->own_key);
		if (ret != 0) {
			LOG_MBEDERROR(ERROR, "mbedtls_ssl_conf_own_cert", ret);
			tls_ctx_free(ctx);
			return NULL;
		}
		/* mbedtls_ssl_conf_own_cert() only fails on allocation failure; check
		 * the cert/key pairing explicitly, mirroring the OpenSSL backend. */
#ifdef MBEDTLS_LEGACY_RNG
		ret = mbedtls_pk_check_pair(
			&c->own_cert.pk, &c->own_key, mbedtls_ctr_drbg_random,
			&c->ctr_drbg);
		if (ret != 0) {
			LOG_MBEDERROR(ERROR, "mbedtls_pk_check_pair", ret);
			tls_ctx_free(ctx);
			return NULL;
		}
#else /* MBEDTLS_LEGACY_RNG */
		if (!tls_pk_pair_matches(&c->own_cert.pk, &c->own_key)) {
			/* tls_pk_pair_matches already logged the specific cause (an
			 * export error, or a genuine cert/key mismatch). */
			tls_ctx_free(ctx);
			return NULL;
		}
#endif /* MBEDTLS_LEGACY_RNG */

		if (!tls_load_authcerts(
			    ctx, conf->authcerts, conf->authcerts_count)) {
			LOGE("failed to load authorized certificates");
			tls_ctx_free(ctx);
			return NULL;
		}
		if (c->ca_chain_loaded) {
			mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca_chain, NULL);
		}
	}

	if (conf->ciphersuites != NULL) {
		c->ciphersuites = parse_ciphersuites(conf->ciphersuites);
		if (c->ciphersuites == NULL) {
			LOGE_F("mbedtls: no usable ciphersuites in '%s'",
			       conf->ciphersuites);
			tls_ctx_free(ctx);
			return NULL;
		}
		mbedtls_ssl_conf_ciphersuites(&c->conf, c->ciphersuites);
	}

	/* ALPN list, shared by client (advertise) and server (select).  The
	 * array must outlive the config, so it is retained on the context. */
	if (!parse_alpn(conf->alpn, &c->alpn)) {
		tls_ctx_free(ctx);
		return NULL;
	}
	if (c->alpn != NULL) {
		const int alpn_ret = mbedtls_ssl_conf_alpn_protocols(
			&c->conf, (const char **)c->alpn);
		if (alpn_ret != 0) {
			LOG_MBEDERROR(
				ERROR, "mbedtls_ssl_conf_alpn_protocols",
				alpn_ret);
			tls_ctx_free(ctx);
			return NULL;
		}
	}

	/* Record the client SNI; tls_client passes it to
	 * mbedtls_ssl_set_hostname.  An empty string is treated as "no SNI".
	 * Server-role contexts never read c->sni (see tls_conn_new), so skip
	 * the allocation entirely for them. */
	if (!is_server && conf->sni != NULL && conf->sni[0] != '\0') {
		c->sni = strdup(conf->sni);
		if (c->sni == NULL) {
			LOGOOM();
			tls_ctx_free(ctx);
			return NULL;
		}
	}

	return ctx;
}

void tls_secure_erase(void *ptr, size_t len)
{
	if (ptr != NULL && len > 0) {
		mbedtls_platform_zeroize(ptr, len);
	}
}

struct tls_context *tls_ctx_server(const struct tls_config *conf)
{
	return tls_ctx_init(conf, true);
}

struct tls_context *tls_ctx_client(const struct tls_config *conf)
{
	return tls_ctx_init(conf, false);
}

struct tls_context *tls_ctx_ref(struct tls_context *restrict ctx)
{
	if (ctx == NULL) {
		return NULL;
	}
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	/* Share this parsed config; the returned handle aliases ctx but is freed
	 * independently via tls_ctx_free() (last owner releases the struct). */
	tls_ctx_impl_ref(c);
	return ctx;
}

void tls_ctx_free(struct tls_context *restrict ctx)
{
	if (ctx == NULL) {
		return;
	}
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	tls_ctx_impl_unref(c);
}

/* BIO callbacks: drive mbedtls over a non-blocking fd. */
static int tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	const int fd = (int)(intptr_t)ctx;
	ssize_t n;
	int err;
	do {
		n = send(fd, buf, len, MSG_NOSIGNAL);
		err = errno;
	} while (n < 0 && err == EINTR);
	if (n >= 0) {
		return (int)n;
	}
	/* sock_would_block is the project's single transient-backpressure
	 * predicate (it also admits ENOBUFS/ENOMEM, a full kernel buffer); every
	 * non-offload socket path uses it, and treating those as fatal here would
	 * tear down the whole TLS+mux session where plain TCP waits for EV_WRITE. */
	if (sock_would_block(err)) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	if (err == ECONNRESET || err == EPIPE) {
		return MBEDTLS_ERR_NET_CONN_RESET;
	}
	return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	const int fd = (int)(intptr_t)ctx;
	ssize_t n;
	int err;
	do {
		n = recv(fd, buf, len, 0);
		err = errno;
	} while (n < 0 && err == EINTR);
	if (n > 0) {
		return (int)n;
	}
	if (n == 0) {
		return 0;
	}
	/* Transient backpressure, per sock_would_block; see tls_bio_send. */
	if (sock_would_block(err)) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	if (err == ECONNRESET) {
		return MBEDTLS_ERR_NET_CONN_RESET;
	}
	return MBEDTLS_ERR_NET_RECV_FAILED;
}

/* Append datalen bytes to a FIFO staging buffer (buf, off, len, cap),
 * compacting any drained prefix and growing as needed. Returns false on
 * allocation failure (buffer left intact), true otherwise. */
static bool buf_fifo_push(
	unsigned char **restrict buf, size_t *restrict off,
	size_t *restrict len, size_t *restrict cap,
	const unsigned char *restrict data, const size_t datalen)
{
	if (*off > 0) {
		memmove(*buf, *buf + *off, *len);
		*off = 0;
	}
	const size_t needed = *len + datalen;
	if (needed > *cap) {
		const size_t newcap = needed < 4096u ? 4096u : needed * 2u;
		unsigned char *const p = realloc(*buf, newcap);
		if (p == NULL) {
			return false;
		}
		*buf = p;
		*cap = newcap;
	}
	memcpy(*buf + *len, data, datalen);
	*len += datalen;
	return true;
}

/* Remove up to datalen bytes from the front of a FIFO staging buffer into
 * data, advancing the read offset and resetting it once the buffer drains.
 * Returns the number of bytes copied (0 if the buffer is empty). */
static size_t buf_fifo_pop(
	unsigned char *restrict buf, size_t *restrict off, size_t *restrict len,
	unsigned char *restrict data, const size_t datalen)
{
	const size_t n = MIN(*len, datalen);
	if (n == 0) {
		return 0;
	}
	memcpy(data, buf + *off, n);
	*off += n;
	*len -= n;
	if (*len == 0) {
		*off = 0;
	}
	return n;
}

/* Memory-transport BIO callbacks for buffered connections; ctx is the owning
 * tls_conn_impl, whose in/out staging buffers carry the ciphertext. */

/* Write callback: TLS layer emits ciphertext → append to conn->out. */
static int tls_buf_send(void *ctx, const unsigned char *data, size_t len)
{
	struct tls_conn_impl *const conn = ctx;
	if (!buf_fifo_push(
		    &conn->out, &conn->out_off, &conn->out_len, &conn->out_cap,
		    data, len)) {
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;
	}
	return (int)len;
}

/* Read callback: TLS layer consumes incoming ciphertext from conn->in. */
static int tls_buf_recv(void *ctx, unsigned char *data, size_t len)
{
	struct tls_conn_impl *const conn = ctx;
	if (conn->in_len == 0) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	const size_t n =
		buf_fifo_pop(conn->in, &conn->in_off, &conn->in_len, data, len);
	return (int)n;
}

/* Allocate and ssl_setup a conn without binding any I/O callbacks. */
static struct tls_conn_impl *tls_conn_alloc(struct tls_ctx_impl *restrict c)
{
	struct tls_conn_impl *const conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		LOGOOM();
		return NULL;
	}
	mbedtls_ssl_init(&conn->ssl);
	conn->fd = -1;
	const int ret = mbedtls_ssl_setup(&conn->ssl, &c->conf);
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_ssl_setup", ret);
		mbedtls_ssl_free(&conn->ssl);
		free(conn);
		return NULL;
	}
	/* ssl now holds a raw pointer into c->conf; keep the config alive for the
	 * connection's whole lifetime (released in tls_conn_free). */
	tls_ctx_impl_ref(c);
	conn->ctx = c;
	/* Client role: the label is fixed at configuration time, so carry it onto
	 * the connection now.  A server learns it from psk_lookup_cb instead. */
	if (c->psk_len > 0) {
		memcpy(conn->psk_label, c->psk_label, sizeof(conn->psk_label));
	}
	return conn;
}

/* Create a connection; fd >= 0: library drives socket directly; fd < 0:
 * buffered in/out arrays for tls_input/tls_output shuttle.  No notifier
 * until tls_set_callback.  Client variant applies SNI. */
static struct tls_connection *tls_conn_new(
	struct tls_ctx_impl *restrict c, const bool is_server, const int fd)
{
	struct tls_conn_impl *const conn = tls_conn_alloc(c);
	if (conn == NULL) {
		return NULL;
	}
	if (fd >= 0) {
		conn->fd = fd;
		mbedtls_ssl_set_bio(
			&conn->ssl, (void *)(intptr_t)fd, tls_bio_send,
			tls_bio_recv, NULL);
	} else {
		mbedtls_ssl_set_bio(
			&conn->ssl, conn, tls_buf_send, tls_buf_recv, NULL);
	}
	if (!is_server) {
		/* mbedtls_ssl_set_hostname() must run before the handshake under
		 * VERIFY_REQUIRED.  Pass c->sni directly: NULL (no SNI configured)
		 * sets the HOSTNAME_SET flag VERIFY_REQUIRED needs yet omits the
		 * extension, whereas a non-NULL "" would emit a zero-length
		 * server_name extension (RFC 6066 violation).  tls_ca_verify clears
		 * the CN-mismatch flag. */
		const int ret = mbedtls_ssl_set_hostname(&conn->ssl, c->sni);
		if (ret != 0) {
			LOG_MBEDERROR(WARNING, "mbedtls_ssl_set_hostname", ret);
		}
	}
	return (struct tls_connection *)conn;
}

struct tls_connection *tls_server(struct tls_context *ctx, const int fd)
{
	if (ctx == NULL) {
		LOGE("tls_server: ctx is NULL");
		return NULL;
	}
	return tls_conn_new(tls_ctx_raw(ctx), true, fd);
}

struct tls_connection *tls_client(struct tls_context *ctx, const int fd)
{
	if (ctx == NULL) {
		LOGE("tls_client: ctx is NULL");
		return NULL;
	}
	return tls_conn_new(tls_ctx_raw(ctx), false, fd);
}

void tls_set_callback(
	struct tls_connection *restrict conn, const struct tls_callback *cb)
{
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	if (cb != NULL) {
		c->cb = *cb;
	} else {
		c->cb = (struct tls_callback){ 0 };
	}
}

bool tls_input(
	struct tls_connection *restrict conn, const void *restrict data,
	const size_t len)
{
	if (len == 0) {
		return true;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	return buf_fifo_push(
		&c->in, &c->in_off, &c->in_len, &c->in_cap, data, len);
}

size_t tls_output(
	struct tls_connection *restrict conn, void *restrict buf,
	const size_t len)
{
	if (len == 0) {
		return 0;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	return buf_fifo_pop(c->out, &c->out_off, &c->out_len, buf, len);
}

static enum tls_error map_io_error(const int ret, const char *op)
{
	switch (ret) {
	case 0:
		return TLS_ERROR_NONE;
	case MBEDTLS_ERR_SSL_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		return TLS_ERROR_ZERO_RETURN;
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
	case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
		/* A TLS 1.3 client is handed one of these per post-handshake
		 * NewSessionTicket. The library documents it as non-fatal (retry
		 * the read), and tls_ctx_init disables tickets so we should never
		 * see one -- but a peer that sends them anyway must not fall into
		 * the default TLS_ERROR_SSL and tear the session down. */
		return TLS_ERROR_WANT_READ;
#endif
	case MBEDTLS_ERR_NET_CONN_RESET:
	case MBEDTLS_ERR_NET_SEND_FAILED:
	case MBEDTLS_ERR_NET_RECV_FAILED:
		LOG_MBEDERROR(ERROR, op, ret);
		return TLS_ERROR_SYSCALL;
	default:
		LOG_MBEDERROR(ERROR, op, ret);
		return TLS_ERROR_SSL;
	}
}

enum tls_error tls_handshake(struct tls_connection *restrict conn)
{
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const int ret = mbedtls_ssl_handshake(&c->ssl);
	tls_fire_send(c);
	if (ret == 0) {
		return TLS_ERROR_NONE;
	}
	return map_io_error(ret, "mbedtls_ssl_handshake");
}

enum tls_error tls_send(
	struct tls_connection *conn, const void *restrict buf,
	size_t *restrict len)
{
	if (*len == 0) {
		return TLS_ERROR_NONE;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const int ret = mbedtls_ssl_write(&c->ssl, buf, *len);
	tls_fire_send(c);
	if (ret > 0) {
		*len = (size_t)ret;
		return TLS_ERROR_NONE;
	}
	*len = 0;
	return map_io_error(ret, "mbedtls_ssl_write");
}

enum tls_error tls_recv(
	struct tls_connection *restrict conn, void *restrict buf,
	size_t *restrict len)
{
	if (*len == 0) {
		return TLS_ERROR_NONE;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const int ret = mbedtls_ssl_read(&c->ssl, buf, *len);
	/* A read can drive the handshake and emit records; surface any staged
	 * ciphertext and (via check_pending) buffered/undecrypted plaintext. */
	tls_fire_send(c);
	tls_fire_recv(c);
	if (ret > 0) {
		*len = (size_t)ret;
		return TLS_ERROR_NONE;
	}
	*len = 0;
	if (ret == 0) {
		/* mbedtls_ssl_read returns exactly 0 when the read end of the
		 * underlying transport was closed without a CloseNotify (abrupt
		 * TCP close/RST or a non-conformant peer): a protocol-violating
		 * EOF, distinct from the orderly MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
		 * (which map_io_error handles as TLS_ERROR_ZERO_RETURN). Classify
		 * it as TLS_ERROR_SYSCALL and log it, so the caller tears the
		 * session down instead of busy-looping on an always-readable EOF
		 * fd. The backends differ on the code, not the outcome: OpenSSL 3.x
		 * reports this condition as SSL_ERROR_SSL with
		 * SSL_R_UNEXPECTED_EOF_WHILE_READING, hence TLS_ERROR_SSL -- the
		 * pre-3.0 SSL_ERROR_SYSCALL this once matched is gone -- and
		 * tls_test's abrupt-close case accepts either. Not routed through
		 * map_io_error's generic case 0, which is the handshake/write
		 * success case. */
		LOGE("mbedtls_ssl_read: connection closed without a proper TLS shutdown");
		return TLS_ERROR_SYSCALL;
	}
	return map_io_error(ret, "mbedtls_ssl_read");
}

enum tls_error tls_shutdown(struct tls_connection *restrict conn)
{
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const int ret = mbedtls_ssl_close_notify(&c->ssl);
	tls_fire_send(c);
	switch (ret) {
	case 0:
		return TLS_ERROR_NONE;
	case MBEDTLS_ERR_SSL_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case MBEDTLS_ERR_NET_CONN_RESET:
	case MBEDTLS_ERR_NET_SEND_FAILED:
	case MBEDTLS_ERR_NET_RECV_FAILED:
		/* Classify transport failures during close_notify as
		 * TLS_ERROR_SYSCALL, matching map_io_error() and the OpenSSL
		 * backend rather than funnelling them to TLS_ERROR_SSL. A failed
		 * shutdown is benign, so keep the DEBUG level both backends use. */
		LOG_MBEDERROR(DEBUG, "mbedtls_ssl_close_notify", ret);
		return TLS_ERROR_SYSCALL;
	default:
		LOG_MBEDERROR(DEBUG, "mbedtls_ssl_close_notify", ret);
		return TLS_ERROR_SSL;
	}
}

void tls_conn_free(struct tls_connection *conn)
{
	if (conn == NULL) {
		return;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	mbedtls_ssl_free(&c->ssl);
	free(c->in);
	free(c->out);
	/* Release the context reference taken in tls_conn_alloc() after the ssl
	 * object (which pointed into ctx->conf) is torn down. */
	tls_ctx_impl_unref(c->ctx);
	free(c);
}

bool tls_peer_cert_der(
	struct tls_connection *conn, unsigned char **out, size_t *len)
{
	if (conn == NULL || out == NULL || len == NULL) {
		return false;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const mbedtls_x509_crt *cert = mbedtls_ssl_get_peer_cert(&c->ssl);
	if (cert == NULL || cert->raw.len == 0) {
		return false;
	}
	unsigned char *der = malloc(cert->raw.len);
	if (der == NULL) {
		LOGOOM();
		return false;
	}
	memcpy(der, cert->raw.p, cert->raw.len);
	*out = der;
	*len = cert->raw.len;
	return true;
}

/* GeneralName CHOICE [6] uniformResourceIdentifier: a primitive,
 * context-specific tag.  mbedtls_x509_crt keeps every SAN entry's raw tag and
 * octets in subject_alt_names, so entries are matched on the tag here rather
 * than through mbedtls_x509_parse_subject_alt_name(), whose supported CHOICE
 * set differs across the mbedTLS versions this backend builds against. */
#define X509_SAN_TAG_URI (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6)

bool tls_peer_cert_uri_sans(
	struct tls_connection *conn, char ***out, size_t *count)
{
	if (conn == NULL || out == NULL || count == NULL) {
		return false;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const mbedtls_x509_crt *const cert = mbedtls_ssl_get_peer_cert(&c->ssl);
	if (cert == NULL) {
		return false;
	}

	/* subject_alt_names is embedded by value: with no SAN extension the head
	 * entry is zeroed, so the NULL-data check below also covers that case.
	 *
	 * Pass 1: size the block, rejecting an embedded NUL while the raw octets
	 * are in hand -- see the tls_peer_cert_uri_sans() contract in tls.h. */
	size_t n_uri = 0;
	size_t bytes = 0;
	for (const mbedtls_x509_sequence *san = &cert->subject_alt_names;
	     san != NULL; san = san->next) {
		if (san->buf.tag != X509_SAN_TAG_URI || san->buf.p == NULL) {
			continue;
		}
		if (memchr(san->buf.p, '\0', san->buf.len) != NULL) {
			LOGE("peer certificate: URI subjectAltName contains an"
			     " embedded NUL");
			return false;
		}
		n_uri++;
		bytes += san->buf.len + 1;
	}
	if (n_uri == 0) {
		*out = NULL;
		*count = 0;
		return true;
	}

	/* One block: the pointer array first (so it keeps malloc's alignment),
	 * then the NUL-terminated names, letting the caller free(*out) once. */
	char **const block = (char **)malloc(n_uri * sizeof(*block) + bytes);
	if (block == NULL) {
		LOGOOM();
		return false;
	}
	char *pos = (char *)(block + n_uri);
	size_t k = 0;
	for (const mbedtls_x509_sequence *san = &cert->subject_alt_names;
	     san != NULL; san = san->next) {
		if (san->buf.tag != X509_SAN_TAG_URI || san->buf.p == NULL) {
			continue;
		}
		ASSERT(k < n_uri);
		memcpy(pos, san->buf.p, san->buf.len);
		pos[san->buf.len] = '\0';
		block[k++] = pos;
		pos += san->buf.len + 1;
	}
	ASSERT(k == n_uri);
	*out = block;
	*count = n_uri;
	return true;
}

bool tls_peer_psk_label(
	struct tls_connection *restrict conn, char *restrict buf,
	size_t *restrict len)
{
	if (conn == NULL || buf == NULL || len == NULL ||
	    *len < TLS_PSK_LABEL_MAX + 1) {
		return false;
	}
	const struct tls_conn_impl *const c = tls_conn_raw(conn);
	const size_t label_len = strlen(c->psk_label);
	if (label_len == 0) {
		/* Certificate handshake: not an error, the caller distinguishes
		 * the two credential modes by this return. */
		return false;
	}
	memcpy(buf, c->psk_label, label_len + 1);
	*len = label_len;
	return true;
}

/* Info string for tls_psk_label()'s HKDF-Expand.  Must stay byte-identical to
 * the OpenSSL backend's PSK_LABEL_INFO: the label travels on the wire, so the
 * two backends have to derive the same one from the same key. */
#define PSK_LABEL_INFO "multiplexd psk id v1"
#define PSK_LABEL_RAW_LEN (TLS_PSK_LABEL_MAX / 2u)

/* HKDF-SHA256 with an absent (all-zero) salt, matching OpenSSL's EVP_KDF
 * default. Split on the same version boundary as the RNG: 4.x removed the
 * legacy mbedtls_hkdf() module in favour of PSA. */
static bool psk_hkdf_sha256(
	const unsigned char *restrict psk, const size_t psk_len,
	unsigned char *restrict out, const size_t out_len)
{
#ifdef MBEDTLS_LEGACY_RNG
	const mbedtls_md_info_t *const md =
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md == NULL) {
		LOGE("mbedtls: SHA-256 unavailable");
		return false;
	}
	const int ret = mbedtls_hkdf(
		md, NULL, 0, psk, psk_len,
		(const unsigned char *)PSK_LABEL_INFO,
		sizeof(PSK_LABEL_INFO) - 1, out, out_len);
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_hkdf", ret);
		return false;
	}
	return true;
#else /* MBEDTLS_LEGACY_RNG */
	/* Context-free entry point: tls_ctx_init() initialises PSA, but the key
	 * generator and config load call this with no context.  psa_crypto_init()
	 * is idempotent, so initialise defensively rather than ordering-depend. */
	psa_status_t st = psa_crypto_init();
	if (st != PSA_SUCCESS) {
		LOGE_F("psa_crypto_init: %d", (int)st);
		return false;
	}
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_bytes(
			&op, PSA_KEY_DERIVATION_INPUT_SALT, NULL, 0);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_bytes(
			&op, PSA_KEY_DERIVATION_INPUT_SECRET, psk, psk_len);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_bytes(
			&op, PSA_KEY_DERIVATION_INPUT_INFO,
			(const unsigned char *)PSK_LABEL_INFO,
			sizeof(PSK_LABEL_INFO) - 1);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_output_bytes(&op, out, out_len);
	}
	(void)psa_key_derivation_abort(&op);
	if (st != PSA_SUCCESS) {
		LOGE_F("psa HKDF-SHA256: %d", (int)st);
		return false;
	}
	return true;
#endif /* MBEDTLS_LEGACY_RNG */
}

bool tls_psk_label(
	const unsigned char *restrict psk, const size_t psk_len,
	char *restrict buf, size_t *restrict len)
{
	if (psk == NULL || buf == NULL || len == NULL ||
	    *len < TLS_PSK_LABEL_MAX + 1 || psk_len < TLS_PSK_MIN_LEN ||
	    psk_len > TLS_PSK_MAX_LEN) {
		return false;
	}
	unsigned char raw[PSK_LABEL_RAW_LEN];
	if (!psk_hkdf_sha256(psk, psk_len, raw, sizeof(raw))) {
		return false;
	}
	for (size_t i = 0; i < sizeof(raw); i++) {
		static const char hex[] = "0123456789abcdef";
		buf[i * 2] = hex[raw[i] >> 4u];
		buf[i * 2 + 1] = hex[raw[i] & 0x0fu];
	}
	buf[TLS_PSK_LABEL_MAX] = '\0';
	mbedtls_platform_zeroize(raw, sizeof(raw));
	*len = TLS_PSK_LABEL_MAX;
	return true;
}

#endif /* WITH_TLS */
