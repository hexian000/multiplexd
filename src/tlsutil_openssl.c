/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tlsutil_openssl.c
 * @brief TLS utility functions implemented with OpenSSL.
 */

#if WITH_TLS

#include "tlsutil.h"

#include "utils/slog.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static SSL_CTX *tls_ctx_raw(struct tls_context *restrict ctx)
{
	return (SSL_CTX *)ctx;
}

static struct tls_context *tls_ctx_new(const SSL_METHOD *method)
{
	ERR_clear_error();
	SSL_CTX *const ssl_ctx = SSL_CTX_new(method);
	if (ssl_ctx == NULL) {
		const unsigned long err = ERR_get_error();
		if (err != 0) {
			char buf[256];
			ERR_error_string_n(err, buf, sizeof(buf));
			LOGE_F("SSL_CTX_new: %s", buf);
		} else {
			LOGE("SSL_CTX_new failed");
		}
		return NULL;
	}
	return (struct tls_context *)ssl_ctx;
}

#define LOG_SSLERROR(level, s)                                                 \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			ERR_clear_error();                                     \
			break;                                                 \
		}                                                              \
		for (unsigned long err = ERR_get_error(); err != 0;            \
		     err = ERR_get_error()) {                                  \
			char buf[256];                                         \
			ERR_error_string_n(err, buf, sizeof(buf));             \
			LOG_F(level, "%s: %s", (s), buf);                      \
		}                                                              \
	} while (0)

const char *tls_version(void)
{
	return "OpenSSL " OPENSSL_VERSION_STR;
}

static bool load_cert_from_bio(SSL_CTX *ctx, BIO *bio)
{
	ERR_clear_error();
	X509 *cert = NULL;
	int count = 0;
	while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		if (count == 0) {
			if (SSL_CTX_use_certificate(ctx, cert) != 1) {
				LOG_SSLERROR(ERROR, "SSL_CTX_use_certificate");
				X509_free(cert);
				return false;
			}
		} else {
			if (SSL_CTX_add1_chain_cert(ctx, cert) != 1) {
				LOG_SSLERROR(ERROR, "SSL_CTX_add1_chain_cert");
				X509_free(cert);
				return false;
			}
		}
		X509_free(cert);
		count++;
	}
	return (count > 0);
}

static bool load_cert_from_memory(SSL_CTX *ctx, const char *pem_data)
{
	ERR_clear_error();
	BIO *bio = BIO_new_mem_buf(pem_data, -1);
	if (bio == NULL) {
		LOG_SSLERROR(ERROR, "BIO_new_mem_buf");
		return false;
	}
	const bool ok = load_cert_from_bio(ctx, bio);
	BIO_free(bio);
	return ok;
}

static bool load_cert_from_file(SSL_CTX *ctx, const char *filename)
{
	ERR_clear_error();
	BIO *bio = BIO_new_file(filename, "r");
	if (bio == NULL) {
		LOG_SSLERROR(ERROR, "BIO_new_file");
		return false;
	}
	const bool ok = load_cert_from_bio(ctx, bio);
	BIO_free(bio);
	return ok;
}

static bool load_key_from_bio(SSL_CTX *ctx, BIO *bio)
{
	ERR_clear_error();
	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (pkey == NULL) {
		LOG_SSLERROR(ERROR, "PEM_read_bio_PrivateKey");
		return false;
	}
	const int ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	EVP_PKEY_free(pkey);
	if (ret != 1) {
		LOG_SSLERROR(ERROR, "SSL_CTX_use_PrivateKey");
		return false;
	}
	return true;
}

static bool load_key_from_memory(SSL_CTX *ctx, const char *pem_data)
{
	ERR_clear_error();
	BIO *bio = BIO_new_mem_buf(pem_data, -1);
	if (bio == NULL) {
		LOG_SSLERROR(ERROR, "BIO_new_mem_buf");
		return false;
	}
	const bool ok = load_key_from_bio(ctx, bio);
	BIO_free(bio);
	return ok;
}

static bool load_key_from_file(SSL_CTX *ctx, const char *filename)
{
	ERR_clear_error();
	BIO *bio = BIO_new_file(filename, "r");
	if (bio == NULL) {
		LOG_SSLERROR(ERROR, "BIO_new_file");
		return false;
	}
	const bool ok = load_key_from_bio(ctx, bio);
	BIO_free(bio);
	return ok;
}

static bool load_authcert_from_bio(SSL_CTX *ctx, BIO *bio)
{
	ERR_clear_error();
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
	if (store == NULL) {
		LOG_SSLERROR(ERROR, "SSL_CTX_get_cert_store");
		return false;
	}
	X509 *cert = NULL;
	while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		if (X509_STORE_add_cert(store, cert) != 1) {
			const unsigned long err = ERR_peek_error();
			if (ERR_GET_REASON(err) !=
			    X509_R_CERT_ALREADY_IN_HASH_TABLE) {
				LOG_SSLERROR(ERROR, "X509_STORE_add_cert");
				X509_free(cert);
				return false;
			}
		}
		X509_free(cert);
	}
	return true;
}

bool tls_load_cert(
	struct tls_context *restrict ctx, const char *restrict cert_data)
{
	SSL_CTX *ssl_ctx = tls_ctx_raw(ctx);
	if (ssl_ctx == NULL) {
		LOGE("tls_load_cert: ctx is NULL");
		return false;
	}
	bool ok;
	switch (*cert_data) {
	case '\0':
		LOGE("certificate data is empty");
		return false;
	case '@':
		ok = load_cert_from_file(ssl_ctx, cert_data + 1);
		break;
	default:
		ok = load_cert_from_memory(ssl_ctx, cert_data);
		break;
	}
	return ok;
}

bool tls_load_key(
	struct tls_context *restrict ctx, const char *restrict key_data)
{
	SSL_CTX *ssl_ctx = tls_ctx_raw(ctx);
	if (ssl_ctx == NULL) {
		LOGE("tls_load_key: ctx is NULL");
		return false;
	}
	bool ok;
	switch (*key_data) {
	case '\0':
		LOGE("key data is empty");
		return false;
	case '@':
		ok = load_key_from_file(ssl_ctx, key_data + 1);
		break;
	default:
		ok = load_key_from_memory(ssl_ctx, key_data);
		break;
	}
	return ok;
}

bool tls_load_authcerts(
	struct tls_context *restrict ctx, char *const *restrict authcerts,
	size_t count)
{
	if (ctx == NULL) {
		LOGE("tls_load_authcerts: ctx is NULL");
		return false;
	}
	SSL_CTX *ssl_ctx = tls_ctx_raw(ctx);
	if (authcerts == NULL || count == 0) {
		return true;
	}
	for (size_t i = 0; i < count; i++) {
		if (authcerts[i] == NULL) {
			LOGE_F("authcerts[%zu] is NULL", i);
			return false;
		}
		ERR_clear_error();
		BIO *bio;
		switch (*authcerts[i]) {
		case '\0':
			LOGE_F("authcerts[%zu] is empty", i);
			return false;
		case '@':
			bio = BIO_new_file(authcerts[i] + 1, "r");
			break;
		default:
			bio = BIO_new_mem_buf(authcerts[i], -1);
			break;
		}
		if (bio == NULL) {
			LOG_SSLERROR(ERROR, "BIO_new");
			return false;
		}
		const bool ok = load_authcert_from_bio(ssl_ctx, bio);
		BIO_free(bio);
		if (!ok) {
			return false;
		}
	}
	return true;
}

void tls_secure_erase(void *ptr, size_t len)
{
	if (ptr != NULL && len > 0) {
		OPENSSL_cleanse(ptr, len);
	}
}

struct tls_context *tls_ctx_server(
	const char *tls_cert, const char *tls_key, char *const *authcerts,
	size_t authcerts_count, const char *tls_ciphersuites)
{
	ERR_clear_error();
	struct tls_context *ctx = tls_ctx_new(TLS_server_method());
	if (ctx == NULL) {
		return NULL;
	}
	SSL_CTX *const ssl_ctx = tls_ctx_raw(ctx);

	if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_min_proto_version");
		tls_ctx_free(ctx);
		return NULL;
	}
	if (!SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_max_proto_version");
		tls_ctx_free(ctx);
		return NULL;
	}

	(void)SSL_CTX_set_mode(
		ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
				 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				 SSL_MODE_AUTO_RETRY);

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

	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_check_private_key");
		tls_ctx_free(ctx);
		return NULL;
	}

	if (!tls_load_authcerts(ctx, authcerts, authcerts_count)) {
		LOGE("failed to load authorized certificates");
		tls_ctx_free(ctx);
		return NULL;
	}
	SSL_CTX_set_verify(
		ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		NULL);

	if (tls_ciphersuites != NULL) {
		if (SSL_CTX_set_ciphersuites(ssl_ctx, tls_ciphersuites) != 1) {
			LOG_SSLERROR(WARNING, "SSL_CTX_set_ciphersuites");
		}
	}

	return ctx;
}

struct tls_context *tls_ctx_client(
	const char *tls_cert, const char *tls_key, char *const *authcerts,
	size_t authcerts_count, const char *tls_ciphersuites)
{
	ERR_clear_error();
	struct tls_context *ctx = tls_ctx_new(TLS_client_method());
	if (ctx == NULL) {
		return NULL;
	}
	SSL_CTX *const ssl_ctx = tls_ctx_raw(ctx);

	if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_min_proto_version");
		tls_ctx_free(ctx);
		return NULL;
	}
	if (!SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_max_proto_version");
		tls_ctx_free(ctx);
		return NULL;
	}
	(void)SSL_CTX_set_mode(
		ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
				 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				 SSL_MODE_AUTO_RETRY);

	/* Client certificate is mandatory for mutual authentication */
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

	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_check_private_key");
		tls_ctx_free(ctx);
		return NULL;
	}

	if (!tls_load_authcerts(ctx, authcerts, authcerts_count)) {
		LOGE("failed to load authorized certificates");
		tls_ctx_free(ctx);
		return NULL;
	}
	/* Verify the peer's certificate against the pinned CA store; hostname
	 * check is omitted — the private CA gates access, and application-level
	 * identity comes from the hello.  See "Deployment Notes" in README.md. */
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

	if (tls_ciphersuites != NULL) {
		if (SSL_CTX_set_ciphersuites(ssl_ctx, tls_ciphersuites) != 1) {
			LOG_SSLERROR(WARNING, "SSL_CTX_set_ciphersuites");
		}
	}

	return ctx;
}

void tls_ctx_free(struct tls_context *restrict ctx)
{
	if (ctx != NULL) {
		SSL_CTX_free(tls_ctx_raw(ctx));
	}
}

struct tls_connection *tls_accept(struct tls_context *ctx, const int fd)
{
	ERR_clear_error();
	SSL_CTX *ssl_ctx = tls_ctx_raw(ctx);
	if (ssl_ctx == NULL) {
		LOGE("tls_accept: ctx is NULL");
		return NULL;
	}
	SSL *ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		LOG_SSLERROR(ERROR, "SSL_new");
		return NULL;
	}
	SSL_set_accept_state(ssl);
	if (!SSL_set_fd(ssl, fd)) {
		LOG_SSLERROR(ERROR, "SSL_set_fd");
		SSL_free(ssl);
		return NULL;
	}
	return (struct tls_connection *)ssl;
}

struct tls_connection *tls_connect(struct tls_context *ctx, const int fd)
{
	if (ctx == NULL || fd < 0) {
		LOGE("invalid parameters to tls_connect");
		return NULL;
	}
	ERR_clear_error();
	SSL_CTX *ssl_ctx = tls_ctx_raw(ctx);
	SSL *ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		LOG_SSLERROR(ERROR, "SSL_new");
		return NULL;
	}
	SSL_set_connect_state(ssl);
	if (!SSL_set_fd(ssl, fd)) {
		LOG_SSLERROR(ERROR, "SSL_set_fd");
		SSL_free(ssl);
		return NULL;
	}
	return (struct tls_connection *)ssl;
}

int tls_handshake(
	struct tls_connection *restrict conn, bool *restrict want_read,
	bool *restrict want_write)
{
	ERR_clear_error();
	SSL *ssl = (SSL *)conn;
	if (want_read != NULL) {
		*want_read = false;
	}
	if (want_write != NULL) {
		*want_write = false;
	}

	const int ret = SSL_do_handshake(ssl);
	if (ret == 1) {
		return 0; /* handshake complete */
	}

	const int err = SSL_get_error(ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_READ:
		if (want_read != NULL) {
			*want_read = true;
		}
		return 1;
	case SSL_ERROR_WANT_WRITE:
		if (want_write != NULL) {
			*want_write = true;
		}
		return 1;
	default:
		LOG_SSLERROR(ERROR, "SSL_do_handshake");
		return -1;
	}
}

enum tls_error tls_send(
	struct tls_connection *conn, const void *restrict buf,
	size_t *restrict len)
{
	if (*len == 0) {
		return TLS_ERROR_NONE;
	}
	SSL *ssl = (SSL *)conn;
	ERR_clear_error();
	int req_len = (int)(*len > (size_t)INT_MAX ? INT_MAX : *len);
	const int ret = SSL_write(ssl, buf, req_len);
	if (ret > 0) {
		*len = (size_t)ret;
		return TLS_ERROR_NONE;
	}
	*len = 0;
	const int err = SSL_get_error(ssl, ret);
	switch (err) {
	case SSL_ERROR_NONE:
		return TLS_ERROR_NONE;
	case SSL_ERROR_SSL:
		LOG_SSLERROR(ERROR, "SSL_write");
		return TLS_ERROR_SSL;
	case SSL_ERROR_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case SSL_ERROR_SYSCALL:
		LOG_SSLERROR(ERROR, "SSL_write");
		return TLS_ERROR_SYSCALL;
	case SSL_ERROR_ZERO_RETURN:
		return TLS_ERROR_ZERO_RETURN;
	default:
		break;
	}
	LOG_SSLERROR(ERROR, "SSL_write");
	return TLS_ERROR_UNKNOWN;
}

enum tls_error tls_recv(
	struct tls_connection *restrict conn, void *restrict buf,
	size_t *restrict len)
{
	if (*len == 0) {
		return TLS_ERROR_NONE;
	}
	SSL *ssl = (SSL *)conn;
	ERR_clear_error();
	int req_len = (int)(*len > (size_t)INT_MAX ? INT_MAX : *len);
	const int ret = SSL_read(ssl, buf, req_len);
	if (ret > 0) {
		*len = (size_t)ret;
		return TLS_ERROR_NONE;
	}
	*len = 0;
	const int err = SSL_get_error(ssl, ret);
	switch (err) {
	case SSL_ERROR_NONE:
		return TLS_ERROR_NONE;
	case SSL_ERROR_SSL:
		LOG_SSLERROR(ERROR, "SSL_read");
		return TLS_ERROR_SSL;
	case SSL_ERROR_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case SSL_ERROR_SYSCALL:
		LOG_SSLERROR(ERROR, "SSL_read");
		return TLS_ERROR_SYSCALL;
	case SSL_ERROR_ZERO_RETURN:
		return TLS_ERROR_ZERO_RETURN;
	default:
		break;
	}
	LOG_SSLERROR(ERROR, "SSL_read");
	return TLS_ERROR_UNKNOWN;
}

int tls_shutdown(
	struct tls_connection *restrict conn, bool *restrict want_read,
	bool *restrict want_write)
{
	ERR_clear_error();
	SSL *ssl = (SSL *)conn;
	if (want_read != NULL) {
		*want_read = false;
	}
	if (want_write != NULL) {
		*want_write = false;
	}

	const int ret = SSL_shutdown(ssl);
	if (ret == 1) {
		return 0; /* shutdown complete */
	}
	if (ret == 0) {
		/* sent close_notify, waiting for peer */
		if (want_read != NULL) {
			*want_read = true;
		}
		return 1;
	}

	const int err = SSL_get_error(ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_READ:
		if (want_read != NULL) {
			*want_read = true;
		}
		return 1;
	case SSL_ERROR_WANT_WRITE:
		if (want_write != NULL) {
			*want_write = true;
		}
		return 1;
	default:
		LOG_SSLERROR(DEBUG, "SSL_shutdown");
		return -1;
	}
}

void tls_conn_free(struct tls_connection *conn)
{
	if (conn != NULL) {
		SSL_free((SSL *)conn);
	}
}

void tls_perror(const char *s)
{
	if (s == NULL) {
		s = "openssl";
	}
	LOG_SSLERROR(ERROR, s);
}

#endif /* WITH_TLS */
