/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tlsutil_openssl.c
 * @brief TLS utility functions implemented with OpenSSL.
 */

#if WITH_TLS

#include "tlsutil.h"

#include "codec/csv.h"
#include "utils/slog.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509err.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

/* Wrapper around the OpenSSL context that retains the per-context runtime
 * extras (SNI string, ALPN wire buffer) the bare SSL_CTX cannot hold. */
struct tls_ctx_impl {
	SSL_CTX *ssl_ctx;
	/* Client SNI hostname (heap, owned); NULL omits the extension. */
	char *sni;
	/* ALPN protocol list in wire format (1-byte length prefix per entry,
	 * heap, owned).  Used to offer (client) or select (server). */
	unsigned char *alpn;
	size_t alpn_len;
};

static struct tls_ctx_impl *tls_ctx_raw(struct tls_context *restrict ctx)
{
	return (struct tls_ctx_impl *)ctx;
}

static SSL_CTX *tls_ssl_ctx(struct tls_context *restrict ctx)
{
	return ((struct tls_ctx_impl *)ctx)->ssl_ctx;
}

/* Connection wrapper: SSL object plus I/O notifier and transport mode;
 * memory-backed uses a pair of memory BIOs (tls_input/tls_output shuttle);
 * fd-backed (fd >= 0) lets the library drive the socket directly. */
struct tls_conn_impl {
	SSL *ssl;
	struct tls_callback cb;
	bool fd_backed;
};

static struct tls_conn_impl *tls_conn_raw(struct tls_connection *restrict conn)
{
	return (struct tls_conn_impl *)conn;
}

static SSL *tls_conn_ssl(struct tls_connection *restrict conn)
{
	return ((struct tls_conn_impl *)conn)->ssl;
}

/* Fire the on_send notifier when memory-backed output ciphertext is staged. */
static void tls_fire_send(struct tls_conn_impl *restrict c)
{
	if (!c->fd_backed && c->cb.on_send != NULL &&
	    BIO_ctrl_pending(SSL_get_wbio(c->ssl)) > 0) {
		c->cb.on_send(c->cb.ctx);
	}
}

/* Fire on_recv when more plaintext is available without another read:
 * SSL_has_pending misses BIO-buffered records so also check the read BIO
 * (exists only in memory-transport mode). */
static void tls_fire_recv(struct tls_conn_impl *restrict c)
{
	if (c->cb.on_recv == NULL) {
		return;
	}
	if (SSL_has_pending(c->ssl) != 0 ||
	    (!c->fd_backed && BIO_ctrl_pending(SSL_get_rbio(c->ssl)) > 0)) {
		c->cb.on_recv(c->cb.ctx);
	}
}

/* Build an ALPN wire buffer (each protocol prefixed by a 1-byte length)
 * from a comma-separated list (RFC 4180 CSV; quoted commas allowed);
 * sets *out (heap, caller frees) and *outlen; *out=NULL for empty list. */
static bool alpn_wire_from_list(
	const char *restrict list, unsigned char **restrict out,
	size_t *restrict outlen)
{
	*out = NULL;
	*outlen = 0;
	if (list == NULL || list[0] == '\0') {
		return true;
	}
	const size_t list_len = strlen(list);
	/* csv_scanfield parses the buffer in-place, so work on a mutable copy. */
	char *const work = malloc(list_len + 1);
	if (work == NULL) {
		LOGOOM();
		return false;
	}
	memcpy(work, list, list_len + 1);
	/* Worst case is strlen(list)+1: every protocol contributes one length
	 * byte in place of its separator (the first entry adds the extra +1)
	 * and unescaping only ever shrinks a field. */
	unsigned char *const buf = malloc(list_len + 1);
	if (buf == NULL) {
		LOGOOM();
		free(work);
		return false;
	}
	size_t w = 0;
	for (char *p = work; p != NULL;) {
		char *field = NULL;
		char *const next = csv_scanfield(p, &field);
		if (next == p) {
			/* unterminated quoted field with no more data */
			LOGW_F("malformed ALPN list '%s'", list);
			free(buf);
			free(work);
			return false;
		}
		if (field != NULL) {
			const size_t tok = strlen(field);
			if (tok > 255) {
				LOGW_F("ALPN entry too long in '%s'", list);
				free(buf);
				free(work);
				return false;
			}
			if (tok > 0) {
				buf[w++] = (unsigned char)tok;
				memcpy(buf + w, field, tok);
				w += tok;
			}
		}
		p = next;
	}
	free(work);
	if (w == 0) {
		free(buf);
		return true;
	}
	*out = buf;
	*outlen = w;
	return true;
}

/* Server-side ALPN selection: pick the first configured protocol the client
 * also offered; with no common protocol, abort with a fatal
 * no_application_protocol alert. */
static int alpn_select_cb(
	SSL *ssl, const unsigned char **out, unsigned char *outlen,
	const unsigned char *in, unsigned int inlen, void *arg)
{
	(void)ssl;
	const struct tls_ctx_impl *const c = arg;
	if (SSL_select_next_proto(
		    (unsigned char **)out, outlen, c->alpn,
		    (unsigned int)c->alpn_len, in,
		    inlen) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	return SSL_TLSEXT_ERR_OK;
}

static void tls_ctx_tune(
	SSL_CTX *restrict ssl_ctx, const bool kernel_offload,
	const bool readahead)
{
	const long want_mode =
		SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY;
	const long got_mode = SSL_CTX_set_mode(ssl_ctx, want_mode);
	if ((got_mode & want_mode) != want_mode) {
		LOGW_F("SSL_CTX_set_mode: requested 0x%lx but active mode is 0x%lx",
		       (unsigned long)want_mode, (unsigned long)got_mode);
	}
	/* tls.readahead: let one socket read buffer several records.  Disabled
	 * makes the library read at most one record per socket read. */
	const int want_read_ahead = readahead ? 1 : 0;
	(void)SSL_CTX_set_read_ahead(ssl_ctx, want_read_ahead);
	if (SSL_CTX_get_read_ahead(ssl_ctx) != want_read_ahead) {
		LOGW_F("SSL_CTX_set_read_ahead: read-ahead could not be set to %d",
		       want_read_ahead);
	}
	/* tls.kernel_offload: let the kernel frame+encrypt records (KTLS).  Default
	 * off, strictly opt-in (degrades on some platforms). */
	if (kernel_offload) {
#ifdef SSL_OP_ENABLE_KTLS
		const uint64_t got_opts =
			SSL_CTX_set_options(ssl_ctx, SSL_OP_ENABLE_KTLS);
		if ((got_opts & SSL_OP_ENABLE_KTLS) == 0) {
			LOGW("tls.kernel_offload: kernel TLS could not be requested");
		}
#else
		LOGW("tls.kernel_offload: this OpenSSL build has no KTLS support");
#endif
	}
	/* mux implements its own session resumption, so TLS 1.3 session tickets
	 * are redundant stateful surface.  Disabling them also keeps the door
	 * shut on 0-RTT early-data replay should tickets ever be re-enabled. */
	(void)SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
	(void)SSL_CTX_set_num_tickets(ssl_ctx, 0);
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
	struct tls_ctx_impl *const c = calloc(1, sizeof(*c));
	if (c == NULL) {
		LOGOOM();
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}
	c->ssl_ctx = ssl_ctx;
	return (struct tls_context *)c;
}

/* Apply the configured ALPN list to a client or server context.  Returns true
 * on success (including when no ALPN is configured). */
static bool tls_ctx_set_alpn(
	struct tls_ctx_impl *restrict c, const bool is_server,
	const char *restrict alpn)
{
	if (!alpn_wire_from_list(alpn, &c->alpn, &c->alpn_len)) {
		return false;
	}
	if (c->alpn == NULL) {
		return true;
	}
	if (is_server) {
		SSL_CTX_set_alpn_select_cb(c->ssl_ctx, alpn_select_cb, c);
		return true;
	}
	/* SSL_CTX_set_alpn_protos copies the buffer and, unusually, returns 0
	 * on success. */
	if (SSL_CTX_set_alpn_protos(
		    c->ssl_ctx, c->alpn, (unsigned int)c->alpn_len) != 0) {
		LOG_SSLERROR(WARNING, "SSL_CTX_set_alpn_protos");
	}
	return true;
}

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
	if (ctx == NULL) {
		LOGE("tls_load_cert: ctx is NULL");
		return false;
	}
	SSL_CTX *const ssl_ctx = tls_ssl_ctx(ctx);
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
	if (ctx == NULL) {
		LOGE("tls_load_key: ctx is NULL");
		return false;
	}
	SSL_CTX *const ssl_ctx = tls_ssl_ctx(ctx);
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
	SSL_CTX *const ssl_ctx = tls_ssl_ctx(ctx);
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

struct tls_context *tls_ctx_server(const struct tls_config *conf)
{
	ERR_clear_error();
	struct tls_context *ctx = tls_ctx_new(TLS_server_method());
	if (ctx == NULL) {
		return NULL;
	}
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	SSL_CTX *const ssl_ctx = c->ssl_ctx;

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

	tls_ctx_tune(ssl_ctx, conf->kernel_offload, conf->readahead);

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

	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_check_private_key");
		tls_ctx_free(ctx);
		return NULL;
	}

	if (!tls_load_authcerts(ctx, conf->authcerts, conf->authcerts_count)) {
		LOGE("failed to load authorized certificates");
		tls_ctx_free(ctx);
		return NULL;
	}
	SSL_CTX_set_verify(
		ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		NULL);

	if (conf->ciphersuites != NULL) {
		if (SSL_CTX_set_ciphersuites(ssl_ctx, conf->ciphersuites) !=
		    1) {
			LOG_SSLERROR(WARNING, "SSL_CTX_set_ciphersuites");
		}
	}

	if (!tls_ctx_set_alpn(c, true, conf->alpn)) {
		tls_ctx_free(ctx);
		return NULL;
	}

	return ctx;
}

struct tls_context *tls_ctx_client(const struct tls_config *conf)
{
	ERR_clear_error();
	struct tls_context *ctx = tls_ctx_new(TLS_client_method());
	if (ctx == NULL) {
		return NULL;
	}
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	SSL_CTX *const ssl_ctx = c->ssl_ctx;

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
	tls_ctx_tune(ssl_ctx, conf->kernel_offload, conf->readahead);

	/* Client certificate is mandatory for mutual authentication */
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

	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_check_private_key");
		tls_ctx_free(ctx);
		return NULL;
	}

	if (!tls_load_authcerts(ctx, conf->authcerts, conf->authcerts_count)) {
		LOGE("failed to load authorized certificates");
		tls_ctx_free(ctx);
		return NULL;
	}
	/* Verify the peer certificate against the pinned CA store; hostname check is
	 * omitted (see "Deployment Notes" in README.md). */
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

	if (conf->ciphersuites != NULL) {
		if (SSL_CTX_set_ciphersuites(ssl_ctx, conf->ciphersuites) !=
		    1) {
			LOG_SSLERROR(WARNING, "SSL_CTX_set_ciphersuites");
		}
	}

	if (!tls_ctx_set_alpn(c, false, conf->alpn)) {
		tls_ctx_free(ctx);
		return NULL;
	}

	/* Retain the SNI; tls_client applies it per-connection via
	 * SSL_set_tlsext_host_name.  An empty string omits the extension. */
	if (conf->sni != NULL && conf->sni[0] != '\0') {
		c->sni = OPENSSL_strdup(conf->sni);
		if (c->sni == NULL) {
			LOGOOM();
			tls_ctx_free(ctx);
			return NULL;
		}
	}

	return ctx;
}

struct tls_context *tls_ctx_ref(struct tls_context *restrict ctx)
{
	if (ctx == NULL) {
		return NULL;
	}
	const struct tls_ctx_impl *const src = tls_ctx_raw(ctx);
	struct tls_ctx_impl *const c = calloc(1, sizeof(*c));
	if (c == NULL) {
		LOGOOM();
		return NULL;
	}
	/* Share the parsed SSL_CTX via OpenSSL's own atomic reference count; the
	 * wrapper below is per-owner so each owner frees independently. */
	if (!SSL_CTX_up_ref(src->ssl_ctx)) {
		LOG_SSLERROR(ERROR, "SSL_CTX_up_ref");
		free(c);
		return NULL;
	}
	c->ssl_ctx = src->ssl_ctx;
	/* sni/alpn are owned per-wrapper (freed in tls_ctx_free), so copy them. */
	if (src->sni != NULL) {
		c->sni = OPENSSL_strdup(src->sni);
		if (c->sni == NULL) {
			LOGOOM();
			tls_ctx_free((struct tls_context *)c);
			return NULL;
		}
	}
	if (src->alpn != NULL && src->alpn_len > 0) {
		c->alpn = malloc(src->alpn_len);
		if (c->alpn == NULL) {
			LOGOOM();
			tls_ctx_free((struct tls_context *)c);
			return NULL;
		}
		memcpy(c->alpn, src->alpn, src->alpn_len);
		c->alpn_len = src->alpn_len;
	}
	return (struct tls_context *)c;
}

void tls_ctx_free(struct tls_context *restrict ctx)
{
	if (ctx == NULL) {
		return;
	}
	struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	SSL_CTX_free(c->ssl_ctx);
	OPENSSL_free(c->sni);
	free(c->alpn);
	free(c);
}

/* Attach memory BIOs to ssl: read BIO fed by tls_input, write BIO drained
 * by tls_output; read BIO set to "retry" (not EOF) so empty → WANT_READ.
 * Returns false on failure; no BIO is leaked. */
static bool tls_set_mem_bio(SSL *restrict ssl)
{
	BIO *const rbio = BIO_new(BIO_s_mem());
	BIO *const wbio = BIO_new(BIO_s_mem());
	if (rbio == NULL || wbio == NULL) {
		BIO_free(rbio);
		BIO_free(wbio);
		return false;
	}
	BIO_set_mem_eof_return(rbio, -1);
	/* SSL takes ownership of both BIOs; SSL_free will release them. */
	SSL_set_bio(ssl, rbio, wbio);
	return true;
}

/* Allocate the connection wrapper around an SSL object; fd >= 0: library
 * drives socket directly; fd < 0: memory BIOs for tls_input/tls_output.
 * No notifier until tls_set_callback; on failure the SSL is freed. */
static struct tls_connection *tls_conn_new(
	struct tls_ctx_impl *restrict c, const bool is_server, const int fd)
{
	SSL *ssl = SSL_new(c->ssl_ctx);
	if (ssl == NULL) {
		LOG_SSLERROR(ERROR, "SSL_new");
		return NULL;
	}
	if (is_server) {
		SSL_set_accept_state(ssl);
	} else {
		SSL_set_connect_state(ssl);
	}
	if (fd >= 0) {
		if (SSL_set_fd(ssl, fd) != 1) {
			LOG_SSLERROR(ERROR, "SSL_set_fd");
			SSL_free(ssl);
			return NULL;
		}
	} else if (!tls_set_mem_bio(ssl)) {
		LOG_SSLERROR(ERROR, "tls_set_mem_bio");
		SSL_free(ssl);
		return NULL;
	}
	if (!is_server && c->sni != NULL &&
	    SSL_set_tlsext_host_name(ssl, c->sni) != 1) {
		LOG_SSLERROR(WARNING, "SSL_set_tlsext_host_name");
	}
	struct tls_conn_impl *const conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		LOGOOM();
		SSL_free(ssl);
		return NULL;
	}
	conn->ssl = ssl;
	conn->fd_backed = (fd >= 0);
	return (struct tls_connection *)conn;
}

struct tls_connection *tls_server(struct tls_context *ctx, const int fd)
{
	ERR_clear_error();
	if (ctx == NULL) {
		LOGE("tls_server: ctx is NULL");
		return NULL;
	}
	return tls_conn_new(tls_ctx_raw(ctx), true, fd);
}

struct tls_connection *tls_client(struct tls_context *ctx, const int fd)
{
	ERR_clear_error();
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
	BIO *const rbio = SSL_get_rbio(tls_conn_ssl(conn));
	const int ret =
		BIO_write(rbio, data, (int)(len > INT_MAX ? INT_MAX : len));
	return ret > 0;
}

size_t tls_output(
	struct tls_connection *restrict conn, void *restrict buf,
	const size_t len)
{
	if (len == 0) {
		return 0;
	}
	BIO *const wbio = SSL_get_wbio(tls_conn_ssl(conn));
	const int ret =
		BIO_read(wbio, buf, (int)(len > INT_MAX ? INT_MAX : len));
	return ret > 0 ? (size_t)ret : 0;
}

enum tls_error tls_handshake(struct tls_connection *restrict conn)
{
	ERR_clear_error();
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	SSL *const ssl = c->ssl;

	const int ret = SSL_do_handshake(ssl);
	tls_fire_send(c);
	if (ret == 1) {
		/* Report whether KTLS engaged per direction (both macros expand to
		 * 0 when the linked OpenSSL lacks KTLS support). */
		if (LOGLEVEL(DEBUG)) {
			LOGD_F("TLS handshake complete: KTLS tx=%d rx=%d",
			       BIO_get_ktls_send(SSL_get_wbio(ssl)) > 0,
			       BIO_get_ktls_recv(SSL_get_rbio(ssl)) > 0);
		}
		return TLS_ERROR_NONE; /* handshake complete */
	}

	const int err = SSL_get_error(ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case SSL_ERROR_SYSCALL:
		LOG_SSLERROR(ERROR, "SSL_do_handshake");
		return TLS_ERROR_SYSCALL;
	default:
		LOG_SSLERROR(ERROR, "SSL_do_handshake");
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
	SSL *const ssl = c->ssl;
	ERR_clear_error();
	const int req_len = (int)(*len > (size_t)INT_MAX ? INT_MAX : *len);
	const int ret = SSL_write(ssl, buf, req_len);
	tls_fire_send(c);
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
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	SSL *const ssl = c->ssl;
	ERR_clear_error();
	const int req_len = (int)(*len > (size_t)INT_MAX ? INT_MAX : *len);
	const int ret = SSL_read(ssl, buf, req_len);
	/* A read can drive the handshake and emit records (e.g. the client's
	 * Finished); surface any staged ciphertext and buffered plaintext. */
	tls_fire_send(c);
	tls_fire_recv(c);
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

enum tls_error tls_shutdown(struct tls_connection *restrict conn)
{
	ERR_clear_error();
	struct tls_conn_impl *const c = tls_conn_raw(conn);
	SSL *const ssl = c->ssl;

	const int ret = SSL_shutdown(ssl);
	tls_fire_send(c);
	if (ret >= 0) {
		/* One-way: our close_notify is flushed (ret==0) or both exchanged
		 * (ret==1); the caller reads the peer's close_notify via tls_recv. */
		return TLS_ERROR_NONE;
	}

	const int err = SSL_get_error(ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case SSL_ERROR_SYSCALL:
		LOG_SSLERROR(DEBUG, "SSL_shutdown");
		return TLS_ERROR_SYSCALL;
	default:
		LOG_SSLERROR(DEBUG, "SSL_shutdown");
		return TLS_ERROR_SSL;
	}
}

void tls_conn_free(struct tls_connection *conn)
{
	if (conn != NULL) {
		struct tls_conn_impl *const c = tls_conn_raw(conn);
		SSL_free(c->ssl);
		free(c);
	}
}

bool tls_peer_cert_der(
	struct tls_connection *conn, unsigned char **out, size_t *len)
{
	if (conn == NULL || out == NULL || len == NULL) {
		return false;
	}
	SSL *const ssl = tls_conn_ssl(conn);
	ERR_clear_error();
	X509 *const cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		return false;
	}
	const int der_len = i2d_X509(cert, NULL);
	if (der_len <= 0) {
		X509_free(cert);
		return false;
	}
	unsigned char *const der = malloc((size_t)der_len);
	if (der == NULL) {
		X509_free(cert);
		return false;
	}
	unsigned char *p = der;
	i2d_X509(cert, &p);
	X509_free(cert);
	*out = der;
	*len = (size_t)der_len;
	return true;
}

#endif /* WITH_TLS */
