/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file tls_openssl.c
 * @brief TLS utility functions implemented with OpenSSL.
 */

#if WITH_TLS

#include "shim/tls.h"
#include "shim/util.h"

#include "meta/minmax.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pemerr.h>
#include <openssl/prov_ssl.h>
#include <openssl/safestack.h>
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
#include <stdio.h>
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

struct alpn_pack {
	unsigned char *buf;
	size_t w;
	const char *list;
};

/* alpn_field_fn: pack each ALPN name into the wire buffer as a 1-byte length
 * prefix followed by the name. */
static bool alpn_pack_field(void *ctx, const char *name, const size_t len)
{
	struct alpn_pack *const a = ctx;
	if (len > 255) {
		LOGW_F("ALPN entry too long in '%s'", a->list);
		return false;
	}
	a->buf[a->w++] = (unsigned char)len;
	memcpy(a->buf + a->w, name, len);
	a->w += len;
	return true;
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
	/* alpn_tokenize parses the buffer in-place, so work on a mutable copy. */
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
	struct alpn_pack a = { .buf = buf, .w = 0, .list = list };
	const bool ok = alpn_tokenize(work, list, alpn_pack_field, &a);
	free(work);
	if (!ok) {
		free(buf);
		return false;
	}
	if (a.w == 0) {
		free(buf);
		return true;
	}
	*out = buf;
	*outlen = a.w;
	return true;
}

/* Info string for tls_psk_label()'s HKDF-Expand.  Versioned: changing the
 * derivation changes every deployment's wire labels, so a future revision must
 * bump this rather than silently reinterpret the same input. */
#define PSK_LABEL_INFO "multiplexd psk id v1"
/* Octets of HKDF output behind the hex label. */
#define PSK_LABEL_RAW_LEN (TLS_PSK_LABEL_MAX / 2u)

bool tls_psk_label(
	const unsigned char *restrict psk, const size_t psk_len,
	char *restrict buf, size_t *restrict len)
{
	if (psk == NULL || buf == NULL || len == NULL ||
	    *len < TLS_PSK_LABEL_MAX + 1 || psk_len < TLS_PSK_MIN_LEN ||
	    psk_len > TLS_PSK_MAX_LEN) {
		return false;
	}
	EVP_KDF *const kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	if (kdf == NULL) {
		LOG_SSLERROR(ERROR, "EVP_KDF_fetch(HKDF)");
		return false;
	}
	EVP_KDF_CTX *const kctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (kctx == NULL) {
		LOG_SSLERROR(ERROR, "EVP_KDF_CTX_new");
		return false;
	}
	/* Salt is deliberately absent: HKDF-Extract with an all-zero salt, so
	 * both backends agree without exchanging one. */
	char digest[] = "SHA256";
	char info[] = PSK_LABEL_INFO;
	const OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(
			OSSL_KDF_PARAM_DIGEST, digest, 0),
		OSSL_PARAM_construct_octet_string(
			OSSL_KDF_PARAM_KEY, (void *)(uintptr_t)psk, psk_len),
		OSSL_PARAM_construct_octet_string(
			OSSL_KDF_PARAM_INFO, info, sizeof(info) - 1),
		OSSL_PARAM_construct_end(),
	};
	unsigned char raw[PSK_LABEL_RAW_LEN];
	const int ret = EVP_KDF_derive(kctx, raw, sizeof(raw), params);
	EVP_KDF_CTX_free(kctx);
	if (ret <= 0) {
		LOG_SSLERROR(ERROR, "EVP_KDF_derive");
		return false;
	}
	for (size_t i = 0; i < sizeof(raw); i++) {
		static const char hex[] = "0123456789abcdef";
		buf[i * 2] = hex[raw[i] >> 4u];
		buf[i * 2 + 1] = hex[raw[i] & 0x0fu];
	}
	buf[TLS_PSK_LABEL_MAX] = '\0';
	OPENSSL_cleanse(raw, sizeof(raw));
	*len = TLS_PSK_LABEL_MAX;
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
	unsigned char *wire = NULL;
	size_t wire_len = 0;
	if (!alpn_wire_from_list(alpn, &wire, &wire_len)) {
		return false;
	}
	if (wire == NULL) {
		return true;
	}
	if (is_server) {
		if (!alpn_ex_idx_ready()) {
			LOGE("tls_ctx_set_alpn: no ALPN ex_data slot");
			free(wire);
			return false;
		}
		struct alpn_wire *const w = malloc(sizeof(*w));
		if (w == NULL) {
			LOGOOM();
			free(wire);
			return false;
		}
		/* Move the wire buffer into an SSL_CTX-lifetime object so
		 * alpn_select_cb never reads the wrapper tls_ctx_free may free
		 * out from under a still-live handshake. */
		w->buf = wire;
		w->len = wire_len;
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
	 * silently proceeding without the ALPN the caller configured.  The copy
	 * lives in the refcounted SSL_CTX every tls_ctx_ref() sibling shares, so
	 * nothing outlives this function. */
	const int ret = SSL_CTX_set_alpn_protos(
		c->ssl_ctx, wire, (unsigned int)wire_len);
	free(wire);
	if (ret != 0) {
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
	if (count == 0) {
		LOGE("no certificates parsed from certificate data");
		return false;
	}
	return true;
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

/* Open a PEM source as a BIO: a "@<path>" reference becomes a file BIO,
 * anything else a read-only memory BIO over the string. Clears the error queue
 * first and logs on failure. The caller has already rejected an empty ref. */
static BIO *tls_pem_bio(const char *ref)
{
	ERR_clear_error();
	BIO *const bio = (ref[0] == '@') ? BIO_new_file(ref + 1, "r") :
					   BIO_new_mem_buf(ref, -1);
	if (bio == NULL) {
		LOG_SSLERROR(ERROR, "BIO_new");
	}
	return bio;
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
	if (cert_data[0] == '\0') {
		LOGE("certificate data is empty");
		return false;
	}
	BIO *const bio = tls_pem_bio(cert_data);
	if (bio == NULL) {
		return false;
	}
	const bool ok = load_cert_from_bio(ssl_ctx, bio);
	BIO_free(bio);
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
	if (key_data[0] == '\0') {
		LOGE("key data is empty");
		return false;
	}
	BIO *const bio = tls_pem_bio(key_data);
	if (bio == NULL) {
		return false;
	}
	const bool ok = load_key_from_bio(ssl_ctx, bio);
	BIO_free(bio);
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
		if (authcerts[i][0] == '\0') {
			LOGE_F("authcerts[%zu] is empty", i);
			return false;
		}
		BIO *const bio = tls_pem_bio(authcerts[i]);
		if (bio == NULL) {
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

/* PSK credentials retained for the SSL_CTX's lifetime.  Hung off the SSL_CTX
 * via ex_data for the same reason as struct alpn_wire: the handshake callbacks
 * receive only an SSL, and SSL_new up-refs the SSL_CTX rather than this
 * backend's wrapper, so reaching into the wrapper could dangle. */
struct psk_conf {
	/* Client role: the offered key and its derived label. */
	unsigned char psk[TLS_PSK_MAX_LEN];
	size_t psk_len;
	char label[TLS_PSK_LABEL_MAX + 1];
	/* Server role. */
	tls_psk_lookup_fn lookup;
	void *lookup_ctx;
	/* Gives back the hold taken on lookup_ctx; NULL when it needs none. */
	void (*lookup_ctx_release)(void *ctx);
	/* Suite whose handshake hash the PSK is bound to; see psk_pick_cipher. */
	const SSL_CIPHER *cipher;
};

static void psk_conf_free(struct psk_conf *restrict pc)
{
	if (pc == NULL) {
		return;
	}
	if (pc->lookup_ctx_release != NULL) {
		pc->lookup_ctx_release(pc->lookup_ctx);
	}
	OPENSSL_cleanse(pc->psk, sizeof(pc->psk));
	free(pc);
}

static void psk_conf_ex_free(
	void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
	void *argp)
{
	(void)parent;
	(void)ad;
	(void)idx;
	(void)argl;
	(void)argp;
	psk_conf_free(ptr);
}

static CRYPTO_ONCE g_psk_ex_idx_once = CRYPTO_ONCE_STATIC_INIT;
static int g_psk_ctx_ex_idx = -1;
static int g_psk_ssl_ex_idx = -1;

/* CRYPTO_EX_free for the per-connection label: without it the string outlives
 * the SSL that owns it, which the sanitizer build reports as a leak. */
static void psk_label_ex_free(
	void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
	void *argp)
{
	(void)parent;
	(void)ad;
	(void)idx;
	(void)argl;
	(void)argp;
	OPENSSL_free(ptr);
}

static void psk_ex_idx_init(void)
{
	g_psk_ctx_ex_idx =
		SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, psk_conf_ex_free);
	/* The per-connection label is a plain heap string; freed with the SSL. */
	g_psk_ssl_ex_idx =
		SSL_get_ex_new_index(0, NULL, NULL, NULL, psk_label_ex_free);
}

static bool psk_ex_idx_ready(void)
{
	return CRYPTO_THREAD_run_once(&g_psk_ex_idx_once, psk_ex_idx_init) ==
		       1 &&
	       g_psk_ctx_ex_idx >= 0 && g_psk_ssl_ex_idx >= 0;
}

static struct psk_conf *psk_conf_of(SSL *ssl)
{
	if (!psk_ex_idx_ready()) {
		return NULL;
	}
	return SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), g_psk_ctx_ex_idx);
}

/* Record which label authenticated this connection, for tls_peer_psk_label().
 * OpenSSL exposes no getter for the negotiated PSK identity, so both callbacks
 * stash it as the handshake selects it. */
static bool psk_conn_set_label(SSL *ssl, const char *label)
{
	if (!psk_ex_idx_ready()) {
		return false;
	}
	char *const dup = OPENSSL_strdup(label);
	if (dup == NULL) {
		LOGOOM();
		return false;
	}
	OPENSSL_free(SSL_get_ex_data(ssl, g_psk_ssl_ex_idx));
	if (SSL_set_ex_data(ssl, g_psk_ssl_ex_idx, dup) != 1) {
		OPENSSL_free(dup);
		return false;
	}
	return true;
}

/* The five TLS 1.3 suites, by IANA id.  SSL_CTX_get_ciphers() also carries the
 * separate TLS 1.2 list, which pinning min=max=TLS1.3 does not remove, so the
 * suite is matched by id rather than by position. */
static bool cipher_is_tls13(const SSL_CIPHER *c)
{
	switch (SSL_CIPHER_get_id(c)) {
	case 0x03001301u: /* TLS_AES_128_GCM_SHA256 */
	case 0x03001302u: /* TLS_AES_256_GCM_SHA384 */
	case 0x03001303u: /* TLS_CHACHA20_POLY1305_SHA256 */
	case 0x03001304u: /* TLS_AES_128_CCM_SHA256 */
	case 0x03001305u: /* TLS_AES_128_CCM_8_SHA256 */
		return true;
	default:
		return false;
	}
}

/* Choose the suite whose handshake hash binds the PSK.
 *
 * A TLS 1.3 PSK is tied to one hash, so both peers must land on a suite using
 * it or the handshake cannot complete.  With an explicit tls.ciphersuites the
 * first configured suite decides, which keeps the option meaningful; with none
 * configured SHA-256 is chosen rather than OpenSSL's default preference, whose
 * first entry is TLS_AES_256_GCM_SHA384.  The caller then narrows the suite
 * list to that hash, so negotiation cannot pick a mismatching one. */
static const SSL_CIPHER *
psk_pick_cipher(SSL_CTX *ssl_ctx, const char *ciphersuites)
{
	STACK_OF(SSL_CIPHER) *const sk = SSL_CTX_get_ciphers(ssl_ctx);
	if (sk == NULL) {
		return NULL;
	}
	const int n = sk_SSL_CIPHER_num(sk);
	const SSL_CIPHER *sha256 = NULL;
	for (int i = 0; i < n; i++) {
		const SSL_CIPHER *const c = sk_SSL_CIPHER_value(sk, i);
		if (!cipher_is_tls13(c)) {
			continue;
		}
		if (ciphersuites != NULL) {
			return c; /* first configured suite wins */
		}
		if (sha256 == NULL &&
		    SSL_CIPHER_get_handshake_digest(c) == EVP_sha256()) {
			sha256 = c;
		}
	}
	return sha256;
}

/* Narrow the TLS 1.3 suite list to those sharing @p cipher's handshake hash,
 * so a PSK bound to that hash can always be used by whatever is negotiated. */
static bool
psk_restrict_ciphersuites(SSL_CTX *ssl_ctx, const SSL_CIPHER *restrict cipher)
{
	const EVP_MD *const want = SSL_CIPHER_get_handshake_digest(cipher);
	STACK_OF(SSL_CIPHER) *const sk = SSL_CTX_get_ciphers(ssl_ctx);
	char list[256];
	size_t w = 0;
	const int n = sk == NULL ? 0 : sk_SSL_CIPHER_num(sk);
	for (int i = 0; i < n; i++) {
		const SSL_CIPHER *const c = sk_SSL_CIPHER_value(sk, i);
		if (!cipher_is_tls13(c) ||
		    SSL_CIPHER_get_handshake_digest(c) != want) {
			continue;
		}
		const char *const name = SSL_CIPHER_get_name(c);
		const int len = snprintf(
			list + w, sizeof(list) - w, "%s%s", w > 0 ? ":" : "",
			name);
		if (len < 0 || (size_t)len >= sizeof(list) - w) {
			LOGE("tls.psk: ciphersuite list too long");
			return false;
		}
		w += (size_t)len;
	}
	if (w == 0) {
		LOGE("tls.psk: no TLS 1.3 ciphersuite matches the PSK hash");
		return false;
	}
	if (SSL_CTX_set_ciphersuites(ssl_ctx, list) != 1) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_ciphersuites(psk)");
		return false;
	}
	return true;
}

static SSL_SESSION *psk_session_new(
	const SSL_CIPHER *restrict cipher, const unsigned char *restrict key,
	const size_t key_len)
{
	SSL_SESSION *const sess = SSL_SESSION_new();
	if (sess == NULL) {
		LOG_SSLERROR(ERROR, "SSL_SESSION_new");
		return NULL;
	}
	if (SSL_SESSION_set1_master_key(sess, key, key_len) != 1 ||
	    SSL_SESSION_set_cipher(sess, cipher) != 1 ||
	    SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION) != 1) {
		LOG_SSLERROR(ERROR, "SSL_SESSION setup");
		SSL_SESSION_free(sess);
		return NULL;
	}
	return sess;
}

/* Server role: resolve the label the client offered.  Returning 1 with
 * *sess == NULL means "no PSK for this identity"; the handshake then fails on
 * its own, since a PSK-mode context has no certificate to fall back to. */
static int psk_find_session_cb(
	SSL *ssl, const unsigned char *identity, size_t identity_len,
	SSL_SESSION **sess)
{
	*sess = NULL;
	struct psk_conf *const pc = psk_conf_of(ssl);
	if (pc == NULL || pc->lookup == NULL) {
		return 1;
	}
	/* Attacker-chosen and not NUL-terminated: bound it, and reject an
	 * embedded NUL rather than truncating to a shorter label that might
	 * resolve to a different peer's key. */
	if (identity_len > TLS_PSK_LABEL_MAX ||
	    memchr(identity, '\0', identity_len) != NULL) {
		return 1;
	}
	char label[TLS_PSK_LABEL_MAX + 1];
	memcpy(label, identity, identity_len);
	label[identity_len] = '\0';

	unsigned char key[TLS_PSK_MAX_LEN];
	size_t key_len = sizeof(key);
	if (!pc->lookup(pc->lookup_ctx, label, key, &key_len)) {
		return 1;
	}
	SSL_SESSION *const s = psk_session_new(pc->cipher, key, key_len);
	OPENSSL_cleanse(key, sizeof(key));
	if (s == NULL) {
		return 0;
	}
	if (!psk_conn_set_label(ssl, label)) {
		SSL_SESSION_free(s);
		return 0;
	}
	*sess = s;
	return 1;
}

/* Client role: offer the single configured PSK. */
static int psk_use_session_cb(
	SSL *ssl, const EVP_MD *md, const unsigned char **id, size_t *idlen,
	SSL_SESSION **sess)
{
	*sess = NULL;
	struct psk_conf *const pc = psk_conf_of(ssl);
	if (pc == NULL || pc->psk_len == 0) {
		return 1;
	}
	/* When OpenSSL asks for a particular digest, only offer the PSK if it is
	 * the one the key is bound to. */
	if (md != NULL && SSL_CIPHER_get_handshake_digest(pc->cipher) != md) {
		return 1;
	}
	SSL_SESSION *const s =
		psk_session_new(pc->cipher, pc->psk, pc->psk_len);
	if (s == NULL) {
		return 0;
	}
	if (!psk_conn_set_label(ssl, pc->label)) {
		SSL_SESSION_free(s);
		return 0;
	}
	*id = (const unsigned char *)pc->label;
	*idlen = strlen(pc->label);
	*sess = s;
	return 1;
}

/* Install PSK credentials on a context, replacing certificate authentication.
 * Returns false on failure; the caller frees the context. */
static bool tls_ctx_set_psk(
	struct tls_ctx_impl *restrict c, const struct tls_config *restrict conf,
	const bool is_server)
{
	if (!psk_ex_idx_ready()) {
		LOGE("failed to register PSK ex_data slots");
		return false;
	}
	const SSL_CIPHER *const cipher =
		psk_pick_cipher(c->ssl_ctx, conf->ciphersuites);
	if (cipher == NULL) {
		LOGE("tls.psk: no usable TLS 1.3 ciphersuite");
		return false;
	}
	if (!psk_restrict_ciphersuites(c->ssl_ctx, cipher)) {
		return false;
	}
	struct psk_conf *const pc = calloc(1, sizeof(*pc));
	if (pc == NULL) {
		LOGOOM();
		return false;
	}
	pc->cipher = cipher;
	if (is_server) {
		pc->lookup = conf->psk_lookup;
		pc->lookup_ctx = conf->psk_lookup_ctx;
		/* Held for as long as this SSL_CTX can serve a handshake, which
		 * SSL_new() lets outlast the wrapper the caller frees. */
		pc->lookup_ctx_release = conf->psk_lookup_ctx_release;
		if (conf->psk_lookup_ctx_hold != NULL) {
			conf->psk_lookup_ctx_hold(pc->lookup_ctx);
		}
	} else {
		if (conf->psk_len < TLS_PSK_MIN_LEN ||
		    conf->psk_len > TLS_PSK_MAX_LEN) {
			LOGE("tls.psk: key length out of range");
			psk_conf_free(pc);
			return false;
		}
		memcpy(pc->psk, conf->psk, conf->psk_len);
		pc->psk_len = conf->psk_len;
		size_t label_len = sizeof(pc->label);
		if (!tls_psk_label(
			    pc->psk, pc->psk_len, pc->label, &label_len)) {
			LOGE("tls.psk: failed to derive the identity label");
			psk_conf_free(pc);
			return false;
		}
	}
	if (SSL_CTX_set_ex_data(c->ssl_ctx, g_psk_ctx_ex_idx, pc) != 1) {
		LOG_SSLERROR(ERROR, "SSL_CTX_set_ex_data(psk)");
		psk_conf_free(pc);
		return false;
	}
	if (is_server) {
		SSL_CTX_set_psk_find_session_callback(
			c->ssl_ctx, psk_find_session_cb);
	} else {
		SSL_CTX_set_psk_use_session_callback(
			c->ssl_ctx, psk_use_session_cb);
	}
	return true;
}

/* True when the config selects PSK rather than certificate authentication. */
static bool tls_conf_is_psk(const struct tls_config *restrict conf)
{
	return conf->psk_lookup != NULL || conf->psk_len > 0;
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

	const bool is_psk = tls_conf_is_psk(conf);
	if (!is_psk) {
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

		if (!tls_load_authcerts(
			    ctx, conf->authcerts, conf->authcerts_count)) {
			LOGE("failed to load authorized certificates");
			tls_ctx_free(ctx);
			return NULL;
		}
		SSL_CTX_set_verify(
			ssl_ctx,
			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			tls_verify_cert_strength_cb);
	}

	if (!tls_ctx_apply_ciphersuites(ssl_ctx, conf->ciphersuites)) {
		tls_ctx_free(ctx);
		return NULL;
	}

	/* After the suite list is applied: the PSK is bound to a hash chosen
	 * from it, and the list is then narrowed to that hash. */
	if (is_psk && !tls_ctx_set_psk(c, conf, true)) {
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

	const bool is_psk = tls_conf_is_psk(conf);
	if (!is_psk) {
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

		if (!tls_load_authcerts(
			    ctx, conf->authcerts, conf->authcerts_count)) {
			LOGE("failed to load authorized certificates");
			tls_ctx_free(ctx);
			return NULL;
		}
		/* Verify the peer certificate against the pinned CA store; hostname check is
		 * omitted (see "Deployment Notes" in README.md). */
		SSL_CTX_set_verify(
			ssl_ctx, SSL_VERIFY_PEER, tls_verify_cert_strength_cb);
	}

	if (!tls_ctx_apply_ciphersuites(ssl_ctx, conf->ciphersuites)) {
		tls_ctx_free(ctx);
		return NULL;
	}

	if (is_psk && !tls_ctx_set_psk(c, conf, false)) {
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
	/* sni is owned per-wrapper (freed in tls_ctx_free), so copy it.  The ALPN
	 * list needs no copy: SSL_CTX_set_alpn_protos() put it in the shared
	 * ssl_ctx, and a server's list lives in that ssl_ctx's ex_data. */
	if (src->sni != NULL) {
		c->sni = OPENSSL_strdup(src->sni);
		if (c->sni == NULL) {
			LOGOOM();
			tls_ctx_free((struct tls_context *)c);
			return NULL;
		}
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
		/* A configured SNI that cannot be applied (e.g. overlong input,
		 * or allocation failure) is a connection-construction failure,
		 * not an optional setter: continuing would omit or retain the
		 * wrong server name and select the wrong virtual host.  Release
		 * the SSL like the SSL_set_fd/BIO failures above. */
		LOG_SSLERROR(ERROR, "SSL_set_tlsext_host_name");
		SSL_free(ssl);
		return NULL;
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
		const int n =
			BIO_write(rbio, p, (int)MIN(remain, (size_t)INT_MAX));
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
	const int ret = BIO_read(wbio, buf, (int)MIN(len, (size_t)INT_MAX));
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
	const int req_len = (int)MIN(*len, (size_t)INT_MAX);
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
	const int req_len = (int)MIN(*len, (size_t)INT_MAX);
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
		LOG_SSLERROR(ERROR, "i2d_X509");
		X509_free(cert);
		return false;
	}
	unsigned char *const der = malloc((size_t)der_len);
	if (der == NULL) {
		LOGOOM();
		X509_free(cert);
		return false;
	}
	unsigned char *p = der;
	/* The length query above already succeeded, so this cannot fail; check
	 * anyway rather than drop the return value. */
	if (i2d_X509(cert, &p) <= 0) {
		LOG_SSLERROR(ERROR, "i2d_X509");
		free(der);
		X509_free(cert);
		return false;
	}
	X509_free(cert);
	*out = der;
	*len = (size_t)der_len;
	return true;
}

/* The raw octets of a GeneralName that is a [6] uniformResourceIdentifier, or
 * NULL for any other CHOICE.  The IA5String is not NUL-terminated, so the
 * length is returned alongside; the caller checks for an embedded NUL. */
static const unsigned char *
san_uri_octets(const GENERAL_NAME *restrict name, int *restrict len)
{
	int type = 0;
	const ASN1_IA5STRING *const uri = GENERAL_NAME_get0_value(name, &type);
	if (type != GEN_URI || uri == NULL) {
		return NULL;
	}
	const int uri_len = ASN1_STRING_length(uri);
	const unsigned char *const data = ASN1_STRING_get0_data(uri);
	if (uri_len < 0 || data == NULL) {
		return NULL;
	}
	*len = uri_len;
	return data;
}

bool tls_peer_cert_uri_sans(
	struct tls_connection *conn, char ***out, size_t *count)
{
	if (conn == NULL || out == NULL || count == NULL) {
		return false;
	}
	SSL *const ssl = tls_conn_ssl(conn);
	ERR_clear_error();
	X509 *const cert = SSL_get1_peer_certificate(ssl);
	if (cert == NULL) {
		return false;
	}
	/* X509_get_ext_d2i() decodes into an independently owned object, so the
	 * certificate is released before the names are walked. */
	GENERAL_NAMES *const names =
		X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	X509_free(cert);
	if (names == NULL) {
		/* No subjectAltName extension at all: zero names, not an error. */
		*out = NULL;
		*count = 0;
		return true;
	}
	const int num = sk_GENERAL_NAME_num(names);

	/* Pass 1: size the block, rejecting an embedded NUL while the raw octets
	 * are in hand -- see the tls_peer_cert_uri_sans() contract in tls.h. */
	size_t n_uri = 0;
	size_t bytes = 0;
	for (int i = 0; i < num; i++) {
		int len = 0;
		const unsigned char *const data =
			san_uri_octets(sk_GENERAL_NAME_value(names, i), &len);
		if (data == NULL) {
			continue;
		}
		if (memchr(data, '\0', (size_t)len) != NULL) {
			LOGE("peer certificate: URI subjectAltName contains an"
			     " embedded NUL");
			GENERAL_NAMES_free(names);
			return false;
		}
		n_uri++;
		bytes += (size_t)len + 1;
	}
	if (n_uri == 0) {
		GENERAL_NAMES_free(names);
		*out = NULL;
		*count = 0;
		return true;
	}

	/* One block: the pointer array first (so it keeps malloc's alignment),
	 * then the NUL-terminated names, letting the caller free(*out) once. */
	char **const block = (char **)malloc(n_uri * sizeof(*block) + bytes);
	if (block == NULL) {
		LOGOOM();
		GENERAL_NAMES_free(names);
		return false;
	}
	char *pos = (char *)(block + n_uri);
	size_t k = 0;
	for (int i = 0; i < num; i++) {
		int len = 0;
		const unsigned char *const data =
			san_uri_octets(sk_GENERAL_NAME_value(names, i), &len);
		if (data == NULL) {
			continue;
		}
		ASSERT(k < n_uri);
		memcpy(pos, data, (size_t)len);
		pos[len] = '\0';
		block[k++] = pos;
		pos += (size_t)len + 1;
	}
	ASSERT(k == n_uri);
	GENERAL_NAMES_free(names);
	*out = block;
	*count = n_uri;
	return true;
}

bool tls_peer_psk_label(
	struct tls_connection *restrict conn, char *restrict buf,
	size_t *restrict len)
{
	if (conn == NULL || buf == NULL || len == NULL ||
	    *len < TLS_PSK_LABEL_MAX + 1 || !psk_ex_idx_ready()) {
		return false;
	}
	const char *const label =
		SSL_get_ex_data(tls_conn_ssl(conn), g_psk_ssl_ex_idx);
	if (label == NULL) {
		/* Certificate handshake: not an error, the caller distinguishes
		 * the two credential modes by this return. */
		return false;
	}
	const size_t label_len = strlen(label);
	if (label_len > TLS_PSK_LABEL_MAX) {
		return false;
	}
	memcpy(buf, label, label_len + 1);
	*len = label_len;
	return true;
}

#endif /* WITH_TLS */
