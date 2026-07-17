/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tls_mbedtls.c
 * @brief TLS utility functions implemented with mbedTLS native API.
 */

#if WITH_TLS

#include "shim/tls.h"

#include "codec/csv.h"
#include "utils/slog.h"

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

#define MBEDTLS_LEGACY_RNG
#else
#include <psa/crypto.h>
#endif

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
	bool is_server;
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
	/* csv_scanfield parses the buffer in-place, so work on a mutable copy. */
	size_t cap = 0;
	char *const work = dup_for_tokens(list, ',', &cap);
	if (work == NULL) {
		LOGOOM();
		return false;
	}
	char **const arr = calloc(cap, sizeof(*arr));
	if (arr == NULL) {
		LOGOOM();
		free(work);
		return false;
	}
	size_t k = 0;
	for (char *p = work; p != NULL;) {
		char *field = NULL;
		/* ALPN is a flat comma-separated list, so the delimiter kind
		 * (field vs record separator) is irrelevant; discard it. */
		char sep;
		/* csv_scanfield unescapes a quoted field in place and, for an
		 * empty quoted field ("") it later rejects, zeroes the field's
		 * first byte before returning its parse-error NULL.  Record
		 * whether any input remained before the call so the guard below
		 * cannot misread that clobbered byte as a clean end. */
		const bool had_input = (*p != '\0');
		char *const next = csv_scanfield(p, &field, &sep);
		if (next == p) {
			/* unterminated quoted field with no more data */
			LOGW_F("malformed ALPN list '%s'", list);
			goto fail;
		}
		if (field == NULL && next == NULL && had_input) {
			/* csv_scanfield returns NULL for both a clean end and a
			 * hard parse error (stray bytes after a closing quote,
			 * or an invalid unquoted field); input remaining before
			 * the call yet no field produced is the latter -- fail
			 * closed instead of silently truncating the list. */
			LOGW_F("malformed ALPN list '%s'", list);
			goto fail;
		}
		if (field != NULL && field[0] != '\0') {
			char *const s = strdup(field);
			if (s == NULL) {
				LOGOOM();
				goto fail;
			}
			arr[k++] = s;
		}
		p = next;
	}
	free(work);
	if (k == 0) {
		/* All fields empty (e.g. ",,"): no protocols, but not an error. */
		free(arr);
		return true;
	}
	arr[k] = NULL;
	*out = arr;
	return true;

fail:
	for (size_t i = 0; i < k; i++) {
		free(arr[i]);
	}
	free(arr);
	free(work);
	return false;
}

static void tls_ctx_impl_init(struct tls_ctx_impl *restrict c)
{
#if WITH_THREADS
	atomic_init(&c->refcount, (size_t)1);
#else
	c->refcount = 1;
#endif
	c->is_server = false;
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
		free(c->alpn);
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

static struct tls_context *
tls_ctx_init(const struct tls_config *restrict conf, const bool is_server)
{
	struct tls_ctx_impl *const c = malloc(sizeof(*c));
	if (c == NULL) {
		LOGOOM();
		return NULL;
	}
	tls_ctx_impl_init(c);
	c->is_server = is_server;
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
	/* See OpenSSL backend for the rationale: private CA gates transport
	 * authentication; application-level identity comes from the hello. */
	mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
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
	ret = mbedtls_ssl_conf_own_cert(&c->conf, &c->own_cert, &c->own_key);
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

	if (!tls_load_authcerts(ctx, conf->authcerts, conf->authcerts_count)) {
		LOGE("failed to load authorized certificates");
		tls_ctx_free(ctx);
		return NULL;
	}
	if (c->ca_chain_loaded) {
		mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca_chain, NULL);
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
	do {
		n = send(fd, buf, len, MSG_NOSIGNAL);
	} while (n < 0 && errno == EINTR);
	if (n >= 0) {
		return (int)n;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	if (errno == ECONNRESET || errno == EPIPE) {
		return MBEDTLS_ERR_NET_CONN_RESET;
	}
	return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	const int fd = (int)(intptr_t)ctx;
	ssize_t n;
	do {
		n = recv(fd, buf, len, 0);
	} while (n < 0 && errno == EINTR);
	if (n > 0) {
		return (int)n;
	}
	if (n == 0) {
		return 0;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	if (errno == ECONNRESET) {
		return MBEDTLS_ERR_NET_CONN_RESET;
	}
	return MBEDTLS_ERR_NET_RECV_FAILED;
}

/* Memory-transport BIO callbacks for buffered connections; ctx is the owning
 * tls_conn_impl, whose in/out staging buffers carry the ciphertext. */

/* Write callback: TLS layer emits ciphertext → append to conn->out. */
static int tls_buf_send(void *ctx, const unsigned char *data, size_t len)
{
	struct tls_conn_impl *const conn = ctx;
	/* Compact the drained prefix before measuring slack. */
	if (conn->out_off > 0) {
		memmove(conn->out, conn->out + conn->out_off, conn->out_len);
		conn->out_off = 0;
	}
	const size_t needed = conn->out_len + len;
	if (needed > conn->out_cap) {
		const size_t newcap = needed < 4096u ? 4096u : needed * 2u;
		unsigned char *const p = realloc(conn->out, newcap);
		if (p == NULL) {
			return MBEDTLS_ERR_SSL_ALLOC_FAILED;
		}
		conn->out = p;
		conn->out_cap = newcap;
	}
	memcpy(conn->out + conn->out_len, data, len);
	conn->out_len += len;
	return (int)len;
}

/* Read callback: TLS layer consumes incoming ciphertext from conn->in. */
static int tls_buf_recv(void *ctx, unsigned char *data, size_t len)
{
	struct tls_conn_impl *const conn = ctx;
	if (conn->in_len == 0) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	const size_t n = conn->in_len < len ? conn->in_len : len;
	memcpy(data, conn->in + conn->in_off, n);
	conn->in_off += n;
	conn->in_len -= n;
	if (conn->in_len == 0) {
		conn->in_off = 0;
	}
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
	/* Compact the consumed prefix before measuring slack. */
	if (c->in_off > 0) {
		memmove(c->in, c->in + c->in_off, c->in_len);
		c->in_off = 0;
	}
	const size_t needed = c->in_len + len;
	if (needed > c->in_cap) {
		const size_t newcap = needed < 4096u ? 4096u : needed * 2u;
		unsigned char *const p = realloc(c->in, newcap);
		if (p == NULL) {
			return false;
		}
		c->in = p;
		c->in_cap = newcap;
	}
	memcpy(c->in + c->in_len, data, len);
	c->in_len += len;
	return true;
}

size_t tls_output(
	struct tls_connection *restrict conn, void *restrict buf,
	const size_t len)
{
	if (len == 0) {
		return 0;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const size_t n = c->out_len < len ? c->out_len : len;
	if (n == 0) {
		return 0;
	}
	memcpy(buf, c->out + c->out_off, n);
	c->out_off += n;
	c->out_len -= n;
	if (c->out_len == 0) {
		c->out_off = 0;
	}
	return n;
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
		 * it as TLS_ERROR_SYSCALL and log it, matching the OpenSSL
		 * backend's SSL_ERROR_SYSCALL/ret==0 handling, so the caller tears
		 * the session down instead of busy-looping on an always-readable
		 * EOF fd. Not routed through map_io_error's generic case 0, which
		 * is the handshake/write success case. */
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
		return false;
	}
	memcpy(der, cert->raw.p, cert->raw.len);
	*out = der;
	*len = cert->raw.len;
	return true;
}

#endif /* WITH_TLS */
