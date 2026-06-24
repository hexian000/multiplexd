/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tlsutil_mbedtls.c
 * @brief TLS utility functions implemented with mbedTLS native API.
 */

#if WITH_TLS

#include "tlsutil.h"

#include "codec/csv.h"
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

/* Fire the on_recv notifier when buffered plaintext can be read without I/O. */
static void tls_fire_recv(struct tls_conn_impl *restrict c)
{
	if (c->cb.on_recv != NULL && mbedtls_ssl_check_pending(&c->ssl) != 0) {
		c->cb.on_recv(c->cb.ctx);
	}
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

/* Parse a comma-separated ALPN list into the NULL-terminated heap-string array
 * mbedtls_ssl_conf_alpn_protocols expects (empty entries skipped).  The RFC 4180
 * CSV reader is used so a protocol name may itself contain a comma when quoted.
 * Returns NULL on failure or when empty; the caller treats NULL as "no ALPN". */
static char **parse_alpn(const char *restrict list)
{
	if (list == NULL || list[0] == '\0') {
		return NULL;
	}
	const size_t list_len = strlen(list);
	/* csv_scanfield parses the buffer in-place, so work on a mutable copy. */
	char *const work = malloc(list_len + 1);
	if (work == NULL) {
		return NULL;
	}
	memcpy(work, list, list_len + 1);
	/* Upper bound: number of commas + 1 entries, plus the NULL terminator. */
	size_t cap = 2;
	for (const char *p = list; *p != '\0'; p++) {
		if (*p == ',') {
			cap++;
		}
	}
	char **const out = calloc(cap, sizeof(*out));
	if (out == NULL) {
		free(work);
		return NULL;
	}
	size_t k = 0;
	for (char *p = work; p != NULL;) {
		char *field = NULL;
		char *const next = csv_scanfield(p, &field);
		if (next == p) {
			/* unterminated quoted field with no more data */
			LOGW_F("malformed ALPN list '%s'", list);
			goto fail;
		}
		if (field != NULL && field[0] != '\0') {
			char *const s = strdup(field);
			if (s == NULL) {
				goto fail;
			}
			out[k++] = s;
		}
		p = next;
	}
	free(work);
	if (k == 0) {
		free(out);
		return NULL;
	}
	out[k] = NULL;
	return out;

fail:
	for (size_t i = 0; i < k; i++) {
		free(out[i]);
	}
	free(out);
	free(work);
	return NULL;
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

static struct tls_context *
tls_ctx_init(const struct tls_config *restrict conf, const bool is_server)
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
	mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_max_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
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
		if (c->ciphersuites != NULL) {
			mbedtls_ssl_conf_ciphersuites(
				&c->conf, c->ciphersuites);
		} else {
			LOGW_F("mbedtls: no usable ciphersuites in '%s'",
			       conf->ciphersuites);
		}
	}

	/* ALPN list, shared by client (advertise) and server (select).  The
	 * array must outlive the config, so it is retained on the context. */
	c->alpn = parse_alpn(conf->alpn);
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
	 * mbedtls_ssl_set_hostname.  An empty string is treated as "no SNI". */
	if (conf->sni != NULL && conf->sni[0] != '\0') {
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
		LOGE("tls_conn_alloc: allocation failed");
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
	return conn;
}

/* Create a connection: with @p fd >= 0 the library drives the socket directly;
 * otherwise the buffered (in/out) BIO is installed for the tls_input/tls_output
 * shuttle.  The connection starts with no notifier; install one with
 * tls_set_callback.  The client variant applies the SNI. */
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
		 * VERIFY_REQUIRED.  Pass the SNI (empty string omits the extension);
		 * tls_ca_verify clears the CN-mismatch flag. */
		const int ret = mbedtls_ssl_set_hostname(
			&conn->ssl, c->sni != NULL ? c->sni : "");
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
