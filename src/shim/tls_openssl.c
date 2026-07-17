/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tls_openssl.c
 * @brief TLS utility functions implemented with OpenSSL.
 */

#if WITH_TLS

#include "shim/tls.h"

#include "codec/csv.h"
#include "utils/slog.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pemerr.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <errno.h>
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

/* Per SSL_get_error(3): SSL_ERROR_SYSCALL's ret==0 is a protocol-violating
 * EOF (errno is stale); ret<0 is a genuine syscall failure worth logging. */
#define LOG_SSL_SYSCALL(level, label, ret, saved_errno)                        \
	do {                                                                   \
		LOG_SSLERROR(level, label);                                    \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		if ((ret) == 0) {                                              \
			LOG_F(level,                                           \
			      "%s: connection closed without a proper "        \
			      "TLS shutdown",                                  \
			      (label));                                        \
		} else {                                                       \
			LOG_F(level, "%s: syscall error: (%d) %s", (label),    \
			      (saved_errno), strerror(saved_errno));           \
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
	/* true once the server ALPN select callback is registered on ssl_ctx.
	 * Its callback argument is an SSL_CTX-lifetime struct alpn_wire (hung
	 * off ex_data), not this wrapper, so sharing ssl_ctx would no longer
	 * dangle; the flag still lets tls_ctx_ref() keep a single owner per
	 * ALPN-enabled server context, conservatively. */
	bool alpn_cb_registered;
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
			free(buf);
			free(work);
			return false;
		}
		if (field == NULL && next == NULL && had_input) {
			/* csv_scanfield returns NULL for both a clean end and a
			 * hard parse error (stray bytes after a closing quote,
			 * or an invalid unquoted field); input remaining before
			 * the call yet no field produced is the latter -- fail
			 * closed instead of silently truncating the list. */
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

/* Owns the server ALPN wire buffer read by alpn_select_cb.  Hung off the
 * SSL_CTX via ex_data (below) so its lifetime is the refcounted SSL_CTX's, not
 * the tls_ctx_impl wrapper's: SSL_new up-refs only the SSL_CTX, and tls_ctx_free
 * frees the wrapper while accepted connections may still be mid-handshake, so
 * the callback must not reach into the wrapper. */
struct alpn_wire {
	unsigned char *buf;
	size_t len;
};

/* CRYPTO_EX_free: fires when the last SSL drops its SSL_CTX ref and the
 * SSL_CTX is finally freed, after which no handshake can reference the buffer. */
static void alpn_wire_ex_free(
	void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
	void *argp)
{
	(void)parent;
	(void)ad;
	(void)idx;
	(void)argl;
	(void)argp;
	struct alpn_wire *const w = ptr;
	if (w != NULL) {
		free(w->buf);
		free(w);
	}
}

static CRYPTO_ONCE g_alpn_ex_idx_once = CRYPTO_ONCE_STATIC_INIT;
static int g_alpn_ex_idx = -1;

static void alpn_ex_idx_init(void)
{
	g_alpn_ex_idx = SSL_CTX_get_ex_new_index(
		0, NULL, NULL, NULL, alpn_wire_ex_free);
}

/* Register the process-wide SSL_CTX ex_data slot for the ALPN buffer exactly
 * once (thread-safe via OpenSSL's own once primitive). */
static bool alpn_ex_idx_ready(void)
{
	return CRYPTO_THREAD_run_once(&g_alpn_ex_idx_once, alpn_ex_idx_init) ==
		       1 &&
	       g_alpn_ex_idx >= 0;
}

/* Server-side ALPN selection: pick the first configured protocol the client
 * also offered; with no common protocol, abort with a fatal
 * no_application_protocol alert. */
static int alpn_select_cb(
	SSL *ssl, const unsigned char **out, unsigned char *outlen,
	const unsigned char *in, unsigned int inlen, void *arg)
{
	(void)ssl;
	const struct alpn_wire *const w = arg;
	if (SSL_select_next_proto(
		    (unsigned char **)out, outlen, w->buf, (unsigned int)w->len,
		    in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	return SSL_TLSEXT_ERR_OK;
}

/* Below this, an RSA key is cryptographically weak regardless of intent;
 * matches mbedtls_x509_crt_profile_default's rsa_min_bitlen (the mbedTLS
 * backend's default certificate profile). */
enum { TLS_RSA_MIN_BITS = 2048 };

/* True if pkey is an EC key on a curve at or above the 128-bit security
 * level, mirroring mbedtls_x509_crt_profile_default's curve allowlist
 * (notably excluding P-224). */
static bool tls_ec_curve_allowed(const EVP_PKEY *restrict pkey)
{
	char name[80];
	if (EVP_PKEY_get_group_name(pkey, name, sizeof(name), NULL) != 1) {
		return false;
	}
	switch (OBJ_sn2nid(name)) {
	case NID_X9_62_prime256v1: /* P-256 */
	case NID_secp384r1: /* P-384 */
	case NID_secp521r1: /* P-521 */
	case NID_brainpoolP256r1:
	case NID_brainpoolP384r1:
	case NID_brainpoolP512r1:
		return true;
	default:
		return false;
	}
}

/* True if the certificate's signature uses a message digest at or above the
 * mbedTLS default profile's floor: SHA-256/384/512
 * (mbedtls_x509_crt_profile_default's md allowlist on the supported mbedTLS 3.6
 * LTS / 4.0 / 4.1 floor; the SHA-3 family was added to that profile only in
 * 4.2.0, so it is deliberately not accepted here to keep both backends in sync
 * on every supported version). NID_undef means the scheme has no separate hash
 * (e.g. Ed25519); like the key check below, such schemes are left
 * unrestricted. */
static bool tls_cert_digest_allowed(X509 *cert)
{
	int mdnid = NID_undef;
	if (X509_get_signature_info(cert, &mdnid, NULL, NULL, NULL) != 1) {
		return false;
	}
	switch (mdnid) {
	case NID_sha256:
	case NID_sha384:
	case NID_sha512:
	case NID_undef:
		return true;
	default:
		return false;
	}
}

/* Verify callback applying a certificate-strength floor to the peer's chain
 * (every depth), matching the mbedTLS backend's default certificate profile
 * (mbedtls_x509_crt_profile_default): the signature message digest must be
 * SHA-256 or stronger, RSA/RSA-PSS keys must be >= TLS_RSA_MIN_BITS, and EC
 * keys must use an allowed curve. Other key types (e.g. Ed25519) are left
 * unrestricted, as the profile permits any PK algorithm and constrains only
 * the digest, RSA bit length, and EC curve. OpenSSL's default security level 1
 * enforces none of the digest floor (it accepts SHA-1/SHA-224), so without this
 * the OpenSSL backend accepted certificates the mbedTLS backend rejected. */
static int
tls_verify_cert_strength_cb(int preverify_ok, X509_STORE_CTX *store_ctx)
{
	if (!preverify_ok) {
		return preverify_ok;
	}
	X509 *const cert = X509_STORE_CTX_get_current_cert(store_ctx);
	const int depth = X509_STORE_CTX_get_error_depth(store_ctx);

	/* The digest floor applies to the leaf and intermediates but not the
	 * trust anchor: mbedTLS does not check a trusted root's own self-signature
	 * digest (it returns before the md check for a trusted root), so exempt a
	 * self-signed cert above the leaf to keep the two backends in step. */
	const bool is_trust_anchor =
		depth > 0 && (X509_get_extension_flags(cert) & EXFLAG_SS) != 0;
	if (!is_trust_anchor && !tls_cert_digest_allowed(cert)) {
		X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CA_MD_TOO_WEAK);
		return 0;
	}

	EVP_PKEY *const pkey = X509_get0_pubkey(cert);
	if (pkey == NULL) {
		return preverify_ok;
	}
	bool ok;
	switch (EVP_PKEY_get_id(pkey)) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		ok = EVP_PKEY_get_bits(pkey) >= TLS_RSA_MIN_BITS;
		break;
	case EVP_PKEY_EC:
		ok = tls_ec_curve_allowed(pkey);
		break;
	default:
		ok = true;
		break;
	}
	if (!ok) {
		X509_STORE_CTX_set_error(
			store_ctx, depth == 0 ? X509_V_ERR_EE_KEY_TOO_SMALL :
						X509_V_ERR_CA_KEY_TOO_SMALL);
		return 0;
	}
	return preverify_ok;
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
	/* mux.readahead: let one socket read buffer several records.  Disabled
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
	 * shut on 0-RTT early-data replay should tickets ever be re-enabled, so a
	 * silent failure here would matter -- verify both like the knobs above. */
	const uint64_t ticket_opts =
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
	if ((ticket_opts & SSL_OP_NO_TICKET) == 0) {
		LOGW("SSL_CTX_set_options: SSL_OP_NO_TICKET could not be set");
	}
	if (SSL_CTX_set_num_tickets(ssl_ctx, 0) != 1) {
		LOGW("SSL_CTX_set_num_tickets: could not disable session tickets");
	}
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
		if (!alpn_ex_idx_ready()) {
			LOGE("tls_ctx_set_alpn: no ALPN ex_data slot");
			return false;
		}
		struct alpn_wire *const w = malloc(sizeof(*w));
		if (w == NULL) {
			LOGOOM();
			return false;
		}
		/* Move the wire buffer into an SSL_CTX-lifetime object so
		 * alpn_select_cb never reads the wrapper tls_ctx_free may free
		 * out from under a still-live handshake. */
		w->buf = c->alpn;
		w->len = c->alpn_len;
		c->alpn = NULL;
		c->alpn_len = 0;
		if (SSL_CTX_set_ex_data(c->ssl_ctx, g_alpn_ex_idx, w) != 1) {
			LOG_SSLERROR(ERROR, "SSL_CTX_set_ex_data");
			free(w->buf);
			free(w);
			return false;
		}
		SSL_CTX_set_alpn_select_cb(c->ssl_ctx, alpn_select_cb, w);
		c->alpn_cb_registered = true;
		return true;
	}
	/* SSL_CTX_set_alpn_protos copies the buffer and, unusually, returns 0
	 * on success. Fail closed (matching the mbedTLS backend) instead of
	 * silently proceeding without the ALPN the caller configured. */
	if (SSL_CTX_set_alpn_protos(
		    c->ssl_ctx, c->alpn, (unsigned int)c->alpn_len) != 0) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_alpn_protos");
		return false;
	}
	return true;
}

const char *tls_version(void)
{
	return "OpenSSL " OPENSSL_VERSION_STR;
}

/* Distinguish clean PEM-scan EOF from parse errors after a NULL
 * PEM_read_bio_X509() result. */
static bool pem_scan_ended_cleanly(void)
{
	if (ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE) {
		LOG_SSLERROR(ERROR, "PEM_read_bio_X509");
		return false;
	}
	ERR_clear_error();
	return true;
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
	if (!pem_scan_ended_cleanly()) {
		return false;
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

/* Refuses to prompt: with no callback, PEM_read_bio_PrivateKey falls back to
 * OpenSSL's default UI, which blocks reading a passphrase from the
 * controlling terminal -- fatal for a single-threaded event loop, whether at
 * startup or a SIGHUP reload. A password-protected key is not supported. */
static int reject_password_cb(char *buf, int size, int rwflag, void *u)
{
	(void)buf;
	(void)size;
	(void)rwflag;
	(void)u;
	return -1;
}

static bool load_key_from_bio(SSL_CTX *ctx, BIO *bio)
{
	ERR_clear_error();
	EVP_PKEY *pkey =
		PEM_read_bio_PrivateKey(bio, NULL, reject_password_cb, NULL);
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
	int count = 0;
	while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		/* OpenSSL 3.x tolerates a duplicate cert as success (no
		 * longer fails with X509_R_CERT_ALREADY_IN_HASH_TABLE, as
		 * verified against the project's OpenSSL 3.0.2 baseline), so
		 * any failure here is a genuine error. */
		if (X509_STORE_add_cert(store, cert) != 1) {
			LOG_SSLERROR(ERROR, "X509_STORE_add_cert");
			X509_free(cert);
			return false;
		}
		X509_free(cert);
		count++;
	}
	if (!pem_scan_ended_cleanly()) {
		return false;
	}
	if (count == 0) {
		LOGE("no certificates parsed from authorized certificate data");
		return false;
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
	/* SSL_CTX_use_certificate() below only replaces the leaf; extra chain
	 * certs are purely additive via SSL_CTX_add1_chain_cert(). Clear them
	 * first so re-loading onto an existing context doesn't accumulate
	 * stale intermediates from a previous load. */
	(void)SSL_CTX_clear_chain_certs(ssl_ctx);
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

/* Apply an explicit ciphersuites list to the context, if configured. OpenSSL's
 * SSL_CTX_set_ciphersuites("") returns success but leaves the TLS 1.3 suite list
 * empty, yielding a context pinned to TLS 1.3 with zero suites that can never
 * handshake; reject an empty string up front so the misconfiguration fails at
 * startup with a clear message, matching the mbedTLS backend which rejects it at
 * context creation. */
static bool
tls_ctx_apply_ciphersuites(SSL_CTX *ssl_ctx, const char *ciphersuites)
{
	if (ciphersuites == NULL) {
		return true;
	}
	if (ciphersuites[0] == '\0') {
		LOGE("tls.ciphersuites must not be empty");
		return false;
	}
	if (SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites) != 1) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_ciphersuites");
		return false;
	}
	return true;
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
		tls_verify_cert_strength_cb);

	if (!tls_ctx_apply_ciphersuites(ssl_ctx, conf->ciphersuites)) {
		tls_ctx_free(ctx);
		return NULL;
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
	SSL_CTX_set_verify(
		ssl_ctx, SSL_VERIFY_PEER, tls_verify_cert_strength_cb);

	if (!tls_ctx_apply_ciphersuites(ssl_ctx, conf->ciphersuites)) {
		tls_ctx_free(ctx);
		return NULL;
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
	if (src->alpn_cb_registered) {
		/* The ALPN callback reads a struct alpn_wire owned by the
		 * refcounted SSL_CTX (via ex_data), so a second owner would no
		 * longer leave it dangling; refuse anyway to keep a single owner
		 * per ALPN-enabled server context. */
		LOGE("tls_ctx_ref: refusing to share an ALPN-enabled server context");
		return NULL;
	}
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
	const unsigned char *p = data;
	size_t remain = len;
	while (remain > 0) {
		const int n = BIO_write(
			rbio, p, (int)(remain > INT_MAX ? INT_MAX : remain));
		if (n <= 0) {
			return false;
		}
		p += (size_t)n;
		remain -= (size_t)n;
	}
	return true;
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
	const int saved_errno = errno;
	/* Resolve the result code before firing notifiers: SSL_get_error() must
	 * see no intervening OpenSSL calls, but a notifier is permitted to call
	 * tls_input() (BIO_write -> BIO_clear_retry_flags), which would turn a
	 * WANT_READ into a spurious SYSCALL and tear down a healthy connection. */
	const int err = SSL_get_error(ssl, ret);
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

	switch (err) {
	case SSL_ERROR_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case SSL_ERROR_SYSCALL:
		LOG_SSL_SYSCALL(ERROR, "SSL_do_handshake", ret, saved_errno);
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
	const int saved_errno = errno;
	/* Resolve the result code before firing notifiers (see tls_handshake):
	 * a notifier calling tls_input() clears the rbio retry flags SSL_get_error
	 * reads, which would misreport WANT_READ as SYSCALL. */
	const int err = SSL_get_error(ssl, ret);
	tls_fire_send(c);
	if (ret > 0) {
		*len = (size_t)ret;
		return TLS_ERROR_NONE;
	}
	*len = 0;
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
		LOG_SSL_SYSCALL(ERROR, "SSL_write", ret, saved_errno);
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
	const int saved_errno = errno;
	/* Resolve the result code before firing notifiers (see tls_handshake):
	 * a notifier calling tls_input() clears the rbio retry flags SSL_get_error
	 * reads, which would misreport WANT_READ as SYSCALL. */
	const int err = SSL_get_error(ssl, ret);
	/* A read can drive the handshake and emit records (e.g. the client's
	 * Finished); surface any staged ciphertext and buffered plaintext. */
	tls_fire_send(c);
	tls_fire_recv(c);
	if (ret > 0) {
		*len = (size_t)ret;
		return TLS_ERROR_NONE;
	}
	*len = 0;
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
		LOG_SSL_SYSCALL(ERROR, "SSL_read", ret, saved_errno);
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
	const int saved_errno = errno;
	/* Resolve the result code before firing notifiers (see tls_handshake):
	 * a notifier calling tls_input() clears the rbio retry flags SSL_get_error
	 * reads, which would misreport WANT_READ as SYSCALL. */
	const int err = SSL_get_error(ssl, ret);
	tls_fire_send(c);
	if (ret >= 0) {
		/* One-way: our close_notify is flushed (ret==0) or both exchanged
		 * (ret==1); the caller reads the peer's close_notify via tls_recv. */
		return TLS_ERROR_NONE;
	}

	switch (err) {
	case SSL_ERROR_WANT_READ:
		return TLS_ERROR_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return TLS_ERROR_WANT_WRITE;
	case SSL_ERROR_SYSCALL:
		LOG_SSL_SYSCALL(DEBUG, "SSL_shutdown", ret, saved_errno);
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
	X509 *const cert = SSL_get1_peer_certificate(ssl);
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
