/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tlsutil_mbedtls.c
 * @brief TLS utility functions implemented with mbedTLS native API.
 */

#if WITH_TLS

#include "tlsutil.h"

#include "utils/slog.h"

#include <mbedtls/build_info.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

struct tls_ctx_impl {
	bool is_server;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt own_cert;
	mbedtls_pk_context own_key;
	mbedtls_x509_crt ca_chain;
	bool ca_chain_loaded;
	int *ciphersuites; /* NULL-terminated by 0 */
#ifdef MBEDTLS_LEGACY_RNG
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
#endif
};

struct tls_conn_impl {
	mbedtls_ssl_context ssl;
	int fd;
};

static struct tls_ctx_impl *tls_ctx_raw(struct tls_context *restrict ctx)
{
	return (struct tls_ctx_impl *)ctx;
}

static struct tls_conn_impl *tls_conn_raw(struct tls_connection *restrict conn)
{
	return (struct tls_conn_impl *)conn;
}

#define LOG_MBEDERROR(level, s, err)                                           \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			char _buf[160];                                        \
			mbedtls_strerror((err), _buf, sizeof(_buf));           \
			LOG_F(level, "%s: -0x%04x %s", (s),                    \
			      (unsigned int)-(err), _buf);                     \
		}                                                              \
	} while (0)

void tls_secure_erase(void *ptr, size_t len)
{
	if (ptr != NULL && len > 0) {
		mbedtls_platform_zeroize(ptr, len);
	}
}

const char *tls_version(void)
{
	return "mbedTLS " MBEDTLS_VERSION_STRING;
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
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_x509_crt_parse", ret);
		return false;
	}
	return true;
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
		if (ret != 0) {
			LOG_MBEDERROR(ERROR, "mbedtls_x509_crt_parse", ret);
			return false;
		}
		c->ca_chain_loaded = true;
	}
	return true;
}

/* Parse an OpenSSL-style colon-separated list of ciphersuite names into a
 * mbedTLS id array, terminated by 0. Returns NULL on allocation failure or if
 * no names were resolved. */
static int *parse_ciphersuites(const char *restrict list)
{
	const size_t n = strlen(list);
	char *const dup = malloc(n + 1);
	if (dup == NULL) {
		return NULL;
	}
	memcpy(dup, list, n + 1);

	/* Upper bound: number of tokens + 1 terminator. */
	size_t cap = 1;
	for (size_t i = 0; i < n; i++) {
		if (dup[i] == ':') {
			cap++;
		}
	}
	cap++;

	int *const ids = malloc(sizeof(int) * cap);
	if (ids == NULL) {
		free(dup);
		return NULL;
	}
	size_t k = 0;
	char *save = NULL;
	for (char *tok = strtok_r(dup, ":", &save); tok != NULL;
	     tok = strtok_r(NULL, ":", &save)) {
		const int id = mbedtls_ssl_get_ciphersuite_id(tok);
		if (id == 0) {
			LOGW_F("mbedtls: unknown ciphersuite '%s'", tok);
			continue;
		}
		ids[k++] = id;
	}
	ids[k] = 0;
	free(dup);
	if (k == 0) {
		free(ids);
		return NULL;
	}
	return ids;
}

static void tls_ctx_impl_init(struct tls_ctx_impl *restrict c)
{
	c->is_server = false;
	mbedtls_ssl_config_init(&c->conf);
	mbedtls_x509_crt_init(&c->own_cert);
	mbedtls_pk_init(&c->own_key);
	mbedtls_x509_crt_init(&c->ca_chain);
	c->ca_chain_loaded = false;
	c->ciphersuites = NULL;
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
#ifdef MBEDTLS_LEGACY_RNG
	mbedtls_ctr_drbg_free(&c->ctr_drbg);
	mbedtls_entropy_free(&c->entropy);
#endif
	free(c);
}

/* Verify callback: accept any certificate trusted by the configured CA chain,
 * regardless of hostname. Our private-CA security model uses the CA itself
 * to control access; hostname matching is not applicable. Clears the
 * CN-mismatch flag that arises from the empty hostname set in tls_connect
 * (see comment there). All other verification failures are preserved. */
static int tls_ca_verify(
	void *data, mbedtls_x509_crt *crt, int depth, uint32_t *restrict flags)
{
	(void)data;
	(void)crt;
	(void)depth;
	*flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
	return 0;
}

static struct tls_context *tls_ctx_init(
	const bool is_server, const char *tls_cert, const char *tls_key,
	char *const *authcerts, const size_t authcerts_count,
	const char *tls_ciphersuites)
{
	struct tls_ctx_impl *const c = malloc(sizeof(*c));
	if (c == NULL) {
		LOGE("tls_ctx_init: allocation failed");
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
#else
	{
		const psa_status_t psa_ret = psa_crypto_init();
		if (psa_ret != PSA_SUCCESS) {
			LOGE_F("psa_crypto_init: %d", (int)psa_ret);
			tls_ctx_free(ctx);
			return NULL;
		}
	}
#endif

	int ret = mbedtls_ssl_config_defaults(
		&c->conf,
		is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_ssl_config_defaults", ret);
		tls_ctx_free(ctx);
		return NULL;
	}
	mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_max_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#ifdef MBEDTLS_LEGACY_RNG
	mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->ctr_drbg);
#endif
	/* See OpenSSL backend for the rationale: private CA gates transport
	 * authentication; application-level identity comes from the hello. */
	mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	/* mbedtls_ssl_set_hostname() is always called in tls_connect (see
	 * comment there); this callback clears the resulting CN-mismatch
	 * flag so certificate verification still succeeds. */
	mbedtls_ssl_conf_verify(&c->conf, tls_ca_verify, NULL);

	if (!tls_load_cert(ctx, tls_cert)) {
		LOGE("failed to load TLS certificate");
		tls_ctx_free(ctx);
		return NULL;
	}
	if (!tls_load_key(ctx, tls_key)) {
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

	if (!tls_load_authcerts(ctx, authcerts, authcerts_count)) {
		LOGE("failed to load authorized certificates");
		tls_ctx_free(ctx);
		return NULL;
	}
	if (c->ca_chain_loaded) {
		mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca_chain, NULL);
	}

	if (tls_ciphersuites != NULL) {
		c->ciphersuites = parse_ciphersuites(tls_ciphersuites);
		if (c->ciphersuites != NULL) {
			mbedtls_ssl_conf_ciphersuites(
				&c->conf, c->ciphersuites);
		} else {
			LOGW_F("mbedtls: no usable ciphersuites in '%s'",
			       tls_ciphersuites);
		}
	}

	return ctx;
}

struct tls_context *tls_ctx_server(
	const char *tls_cert, const char *tls_key, char *const *authcerts,
	const size_t authcerts_count, const char *tls_ciphersuites)
{
	return tls_ctx_init(
		true, tls_cert, tls_key, authcerts, authcerts_count,
		tls_ciphersuites);
}

struct tls_context *tls_ctx_client(
	const char *tls_cert, const char *tls_key, char *const *authcerts,
	const size_t authcerts_count, const char *tls_ciphersuites)
{
	return tls_ctx_init(
		false, tls_cert, tls_key, authcerts, authcerts_count,
		tls_ciphersuites);
}

void tls_ctx_free(struct tls_context *restrict ctx)
{
	if (ctx != NULL) {
		tls_ctx_impl_free(tls_ctx_raw(ctx));
	}
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

static struct tls_connection *
tls_conn_new(struct tls_ctx_impl *restrict c, const int fd)
{
	struct tls_conn_impl *const conn = malloc(sizeof(*conn));
	if (conn == NULL) {
		LOGE("tls_conn_new: allocation failed");
		return NULL;
	}
	mbedtls_ssl_init(&conn->ssl);
	conn->fd = fd;
	const int ret = mbedtls_ssl_setup(&conn->ssl, &c->conf);
	if (ret != 0) {
		LOG_MBEDERROR(ERROR, "mbedtls_ssl_setup", ret);
		mbedtls_ssl_free(&conn->ssl);
		free(conn);
		return NULL;
	}
	mbedtls_ssl_set_bio(
		&conn->ssl, (void *)(intptr_t)fd, tls_bio_send, tls_bio_recv,
		NULL);
	return (struct tls_connection *)conn;
}

struct tls_connection *tls_accept(struct tls_context *ctx, const int fd)
{
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	if (c == NULL) {
		LOGE("tls_accept: ctx is NULL");
		return NULL;
	}
	return tls_conn_new(c, fd);
}

struct tls_connection *tls_connect(struct tls_context *ctx, const int fd)
{
	if (ctx == NULL || fd < 0) {
		LOGE("invalid parameters to tls_connect");
		return NULL;
	}
	struct tls_connection *const conn = tls_conn_new(tls_ctx_raw(ctx), fd);
	if (conn != NULL) {
		/* mbedtls_ssl_set_hostname() must be called before the
		 * handshake when VERIFY_REQUIRED is set; omitting it is an
		 * error since mbedTLS 4.1.0 (upstream PR #10109), and some
		 * vendor builds (e.g. OpenWRT 3.6.6) backport that check.
		 * Pass an empty hostname—we do not use SNI—and let
		 * tls_ca_verify clear the resulting CN-mismatch flag. */
		struct tls_conn_impl *const c = tls_conn_raw(conn);
		mbedtls_ssl_set_hostname(&c->ssl, "");
	}
	return conn;
}

int tls_handshake(
	struct tls_connection *restrict conn, bool *restrict want_read,
	bool *restrict want_write)
{
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	if (want_read != NULL) {
		*want_read = false;
	}
	if (want_write != NULL) {
		*want_write = false;
	}
	const int ret = mbedtls_ssl_handshake(&c->ssl);
	if (ret == 0) {
		return 0;
	}
	switch (ret) {
	case MBEDTLS_ERR_SSL_WANT_READ:
		if (want_read != NULL) {
			*want_read = true;
		}
		return 1;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		if (want_write != NULL) {
			*want_write = true;
		}
		return 1;
	default:
		LOG_MBEDERROR(ERROR, "mbedtls_ssl_handshake", ret);
		return -1;
	}
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

enum tls_error tls_send(
	struct tls_connection *conn, const void *restrict buf,
	size_t *restrict len)
{
	if (*len == 0) {
		return TLS_ERROR_NONE;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	const int ret = mbedtls_ssl_write(&c->ssl, buf, *len);
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
	if (ret > 0) {
		*len = (size_t)ret;
		return TLS_ERROR_NONE;
	}
	*len = 0;
	return map_io_error(ret, "mbedtls_ssl_read");
}

int tls_shutdown(
	struct tls_connection *restrict conn, bool *restrict want_read,
	bool *restrict want_write)
{
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	if (want_read != NULL) {
		*want_read = false;
	}
	if (want_write != NULL) {
		*want_write = false;
	}
	const int ret = mbedtls_ssl_close_notify(&c->ssl);
	if (ret == 0) {
		return 0;
	}
	switch (ret) {
	case MBEDTLS_ERR_SSL_WANT_READ:
		if (want_read != NULL) {
			*want_read = true;
		}
		return 1;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		if (want_write != NULL) {
			*want_write = true;
		}
		return 1;
	default:
		LOG_MBEDERROR(DEBUG, "mbedtls_ssl_close_notify", ret);
		return -1;
	}
}

void tls_conn_free(struct tls_connection *conn)
{
	if (conn == NULL) {
		return;
	}
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	mbedtls_ssl_free(&c->ssl);
	free(c);
}

void tls_perror(const char *s)
{
	if (s == NULL) {
		s = "mbedtls";
	}
	LOGE_F("%s", s);
}

#endif /* WITH_TLS */
