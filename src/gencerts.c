/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file gencerts.c
 * @brief Certificate generation utility using OpenSSL.
 */

#include "gencerts.h"

#if WITH_OPENSSL

#include "shim/util.h"

#include "net/url.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_SSLERROR(s)                                                        \
	do {                                                                   \
		if (!LOGLEVEL(ERROR)) {                                        \
			ERR_clear_error();                                     \
			break;                                                 \
		}                                                              \
		for (unsigned long err = ERR_get_error(); err != 0;            \
		     err = ERR_get_error()) {                                  \
			char buf[256];                                         \
			ERR_error_string_n(err, buf, sizeof(buf));             \
			LOGE_F("%s: %s", (s), buf);                            \
		}                                                              \
	} while (0)

static bool format_pem_filename(
	char *restrict buf, const size_t buflen, const char *restrict name,
	const char *restrict suffix)
{
	const int len = snprintf(buf, buflen, "%s%s", name, suffix);
	if (len < 0 || (size_t)len >= buflen) {
		LOGE_F("path too long: %s%s", name, suffix);
		return false;
	}
	return true;
}

/* Build the subjectAltName extension value: the server name as a DNS entry,
 * plus -- when an identity is given -- the identity as a URI entry in the
 * opaque IDENTITY_URI_SCHEME form that identity.verify checks for.  Only NULL
 * omits the URI entry: "" is an identity a peer may claim (doc/spec.md
 * 5.2.3.2), not a way to ask for none.
 *
 * The identity is percent-encoded with url_escape_path_segment(), which escapes
 * every octet outside the RFC 3986 unreserved/sub-delims set, so a non-ASCII
 * (UTF-8) identity still satisfies the IA5String requirement RFC 5280 places on
 * a uniformResourceIdentifier.  Not url_escape_query(): that form encodes a
 * space as '+', which is form encoding rather than a URI. */
static bool format_subject_alt_name(
	char *restrict buf, const size_t buflen,
	const char *restrict server_name, const char *restrict identity)
{
	int len;
	if (identity == NULL) {
		len = snprintf(buf, buflen, "DNS:%s", server_name);
	} else {
		char encoded[IDENTITY_ENCODED_MAX + 1];
		const int n = url_escape_path_segment(
			encoded, sizeof(encoded), identity);
		if (n < 0 || (size_t)n >= sizeof(encoded)) {
			LOGE_F("identity too long: %s", identity);
			return false;
		}
		len = snprintf(
			buf, buflen, "DNS:%s,URI:" IDENTITY_URI_SCHEME "%s",
			server_name, encoded);
	}
	if (len < 0 || (size_t)len >= buflen) {
		LOGE_F("subjectAltName too long: %s", server_name);
		return false;
	}
	return true;
}

/* No real deployment needs more; RSA keygen time grows steeply with size,
 * so anything past this is almost certainly a mistyped --keysize rather
 * than a deliberate choice. */
enum { RSA_KEYSIZE_MAX = 16384 };
/* Below this, the key is cryptographically weak regardless of intent;
 * matches the common 2048-bit industry floor. */
enum { RSA_KEYSIZE_MIN = 2048 };

static EVP_PKEY *generate_key(const char *type, int keysize)
{
	if (type == NULL) {
		type = "rsa";
	}
	if (strcmp(type, "rsa") == 0) {
		if (keysize == 0) {
			keysize = 4096;
		}
		if (keysize < RSA_KEYSIZE_MIN || keysize > RSA_KEYSIZE_MAX) {
			LOGE_F("invalid RSA key size: %d (must be %d-%d)",
			       keysize, RSA_KEYSIZE_MIN, RSA_KEYSIZE_MAX);
			return NULL;
		}
		LOGN_F("keytype=rsa keysize=%d", keysize);
		EVP_PKEY *const pkey =
			EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)keysize);
		if (pkey == NULL) {
			LOG_SSLERROR("EVP_PKEY_Q_keygen(RSA)");
		}
		return pkey;
	}
	if (strcmp(type, "ecdsa") == 0) {
		if (keysize == 0) {
			keysize = 256;
		}
		const char *curve;
		switch (keysize) {
		case 224:
			curve = "P-224";
			break;
		case 256:
			curve = "P-256";
			break;
		case 384:
			curve = "P-384";
			break;
		case 521:
			curve = "P-521";
			break;
		default:
			LOGE_F("invalid ECDSA key size: %d", keysize);
			return NULL;
		}
		LOGN_F("keytype=ecdsa keysize=%d", keysize);
		EVP_PKEY *const pkey =
			EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve);
		if (pkey == NULL) {
			LOG_SSLERROR("EVP_PKEY_Q_keygen(EC)");
		}
		return pkey;
	}
	if (strcmp(type, "ed25519") == 0) {
		if (keysize != 0) {
			LOGE_F("ed25519 does not take a key size: %d", keysize);
			return NULL;
		}
		LOGN("keytype=ed25519");
		EVP_PKEY *const pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
		if (pkey == NULL) {
			LOG_SSLERROR("EVP_PKEY_Q_keygen(ED25519)");
		}
		return pkey;
	}
	LOGE_F("invalid key type: %s", type);
	return NULL;
}

/* Refuses to prompt: a password-protected private key is not supported by
 * this tool, so fail cleanly instead of blocking on an interactive stdin
 * prompt in a scripted/non-interactive invocation. */
static int reject_password_cb(char *buf, int size, int rwflag, void *u)
{
	(void)buf;
	(void)size;
	(void)rwflag;
	(void)u;
	return -1;
}

static bool read_keypair(const char *name, X509 **out_cert, EVP_PKEY **out_key)
{
	char cert_file[256], key_file[256];
	if (!format_pem_filename(
		    cert_file, sizeof(cert_file), name, "-cert.pem") ||
	    !format_pem_filename(key_file, sizeof(key_file), name, "-key.pem")) {
		return false;
	}

	FILE *fp = fopen(cert_file, "r");
	if (fp == NULL) {
		const int err = errno;
		LOGE_F("failed to open %s: (%d) %s", cert_file, err,
		       strerror(err));
		return false;
	}
	*out_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	(void)fclose(fp);
	if (*out_cert == NULL) {
		LOG_SSLERROR("PEM_read_X509");
		return false;
	}

	fp = fopen(key_file, "r");
	if (fp == NULL) {
		const int err = errno;
		LOGE_F("failed to open %s: (%d) %s", key_file, err,
		       strerror(err));
		X509_free(*out_cert);
		*out_cert = NULL;
		return false;
	}
	*out_key = PEM_read_PrivateKey(fp, NULL, reject_password_cb, NULL);
	(void)fclose(fp);
	if (*out_key == NULL) {
		LOG_SSLERROR("PEM_read_PrivateKey");
		X509_free(*out_cert);
		*out_cert = NULL;
		return false;
	}

	LOGN_F("read %s, %s", cert_file, key_file);
	return true;
}

/* RFC 5280 requires a positive serial number; use 128 random bits. On
 * failure the caller still owns and frees `cert` itself. */
static bool set_random_serial(X509 *restrict cert)
{
	BIGNUM *const bn = BN_new();
	if (bn == NULL) {
		LOG_SSLERROR("BN_new");
		return false;
	}
	if (BN_rand(bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 0) {
		LOG_SSLERROR("BN_rand");
		BN_free(bn);
		return false;
	}
	ASN1_INTEGER *const serial = ASN1_INTEGER_new();
	if (serial == NULL) {
		LOG_SSLERROR("ASN1_INTEGER_new");
		BN_free(bn);
		return false;
	}
	if (BN_to_ASN1_INTEGER(bn, serial) == NULL) {
		LOG_SSLERROR("BN_to_ASN1_INTEGER");
		ASN1_INTEGER_free(serial);
		BN_free(bn);
		return false;
	}
	BN_free(bn);
	if (X509_set_serialNumber(cert, serial) == 0) {
		LOG_SSLERROR("X509_set_serialNumber");
		ASN1_INTEGER_free(serial);
		return false;
	}
	ASN1_INTEGER_free(serial);
	return true;
}
/* RFC 5280 A.1 ub-common-name: OpenSSL enforces this on NID_commonName. */
#define GENCERTS_CN_MAX 64
/* Longest server name the tool accepts; the SAN buffer is sized from it. */
#define GENCERTS_NAME_MAX 255

/* Sets the subject CN to server_name. On failure the caller still owns and
 * frees `cert` itself. */
static bool
set_subject_cn(X509 *restrict cert, const char *restrict server_name)
{
	X509_NAME *const name = X509_NAME_new();
	if (name == NULL) {
		LOG_SSLERROR("X509_NAME_new");
		return false;
	}
	/* MBSTRING_ASC makes OpenSSL enforce ub_common_name (RFC 5280 A.1) on
	 * NID_commonName, so a name past 64 octets is refused outright. Verifiers
	 * key on the SAN (RFC 6125 deprecated the CN fallback), so keep the
	 * subject non-empty with as much of the name as fits rather than fail a
	 * server name the tool otherwise accepts. */
	size_t cn_len = strlen(server_name);
	if (cn_len > GENCERTS_CN_MAX) {
		LOGW_F("subject CN truncated to %d octets; the full name is in"
		       " the subjectAltName, which is what verifiers use",
		       GENCERTS_CN_MAX);
		cn_len = GENCERTS_CN_MAX;
	}
	if (X509_NAME_add_entry_by_txt(
		    name, "CN", MBSTRING_ASC,
		    (const unsigned char *)server_name, (int)cn_len, -1,
		    0) == 0) {
		LOG_SSLERROR("X509_NAME_add_entry_by_txt");
		X509_NAME_free(name);
		return false;
	}
	if (X509_set_subject_name(cert, name) == 0) {
		LOG_SSLERROR("X509_set_subject_name");
		X509_NAME_free(name);
		return false;
	}
	X509_NAME_free(name);
	return true;
}

/* Build and attach a single v3 extension; on failure the caller
 * (create_certificate) still owns and frees `cert` itself. */
static bool
add_ext(X509 *restrict cert, X509V3_CTX *v3ctx, const int nid,
	const char *restrict value)
{
	X509_EXTENSION *const ext =
		X509V3_EXT_conf_nid(NULL, v3ctx, nid, value);
	if (ext == NULL) {
		LOG_SSLERROR("X509V3_EXT_conf_nid");
		return false;
	}
	if (X509_add_ext(cert, ext, -1) == 0) {
		LOG_SSLERROR("X509_add_ext");
		X509_EXTENSION_free(ext);
		return false;
	}
	X509_EXTENSION_free(ext);
	return true;
}

static bool add_subject_alt_name_ext(
	X509 *restrict cert, X509V3_CTX *v3ctx,
	const char *restrict server_name, const char *restrict identity)
{
	const size_t server_name_len = strlen(server_name);
	/* create_certificate gates the name before reaching here; bound the VLA
	 * against that guarantee rather than taking it from the caller. */
	ASSERT(server_name_len <= GENCERTS_NAME_MAX);
	/* "DNS:" + server name + ",URI:" + scheme + the percent-encoded identity.
	 * Each sizeof carries its own NUL, so this is comfortably above the exact
	 * requirement.  Sized from server_name_len rather than GENCERTS_NAME_MAX
	 * so the length stays load-bearing: under NDEBUG the ASSERT above expands
	 * to nothing, and a constant-sized buffer would leave it unused. */
	char san_value
		[server_name_len + sizeof("DNS:") +
		 sizeof(",URI:" IDENTITY_URI_SCHEME) + IDENTITY_ENCODED_MAX];
	if (!format_subject_alt_name(
		    san_value, sizeof(san_value), server_name, identity)) {
		return false;
	}
	return add_ext(cert, v3ctx, NID_subject_alt_name, san_value);
}

static bool create_certificate(
	X509 *parent, EVP_PKEY *sign_key, const char *server_name,
	const char *identity, EVP_PKEY *pkey, X509 **out_cert)
{
	/* Gate the length once, here, before anything consumes the name: the CN
	 * entry below would otherwise refuse a 65-255 octet name on OpenSSL's own
	 * ub_common_name bound, reporting a raw error-queue dump instead of this
	 * diagnostic. */
	const size_t server_name_len = strlen(server_name);
	if (server_name_len > GENCERTS_NAME_MAX) {
		LOGE_F("server name too long: %zu bytes (limit %d)",
		       server_name_len, GENCERTS_NAME_MAX);
		return false;
	}

	X509 *const cert = X509_new();
	if (cert == NULL) {
		LOG_SSLERROR("X509_new");
		return false;
	}

	if (!set_random_serial(cert)) {
		X509_free(cert);
		return false;
	}

	/* Backdate notBefore by an hour to tolerate verifier clock skew. */
	if (X509_time_adj_ex(X509_getm_notBefore(cert), 0, -3600, NULL) ==
	    NULL) {
		LOG_SSLERROR("X509_time_adj_ex");
		X509_free(cert);
		return false;
	}
	/* 3652 days ≈ 10 years */
	if (X509_time_adj_ex(X509_getm_notAfter(cert), 3652, 0, NULL) == NULL) {
		LOG_SSLERROR("X509_time_adj_ex");
		X509_free(cert);
		return false;
	}

	if (!set_subject_cn(cert, server_name)) {
		X509_free(cert);
		return false;
	}

	X509V3_CTX v3ctx;
	X509V3_set_ctx_nodb(&v3ctx);
	const bool ca = (parent == NULL);
	if (ca) {
		parent = cert;
		sign_key = pkey;
	}
	if (X509_set_version(cert, X509_VERSION_3) == 0) {
		LOG_SSLERROR("X509_set_version");
		X509_free(cert);
		return false;
	}
	X509V3_set_ctx(&v3ctx, parent, cert, NULL, NULL, 0);

	if (X509_set_issuer_name(cert, X509_get_subject_name(parent)) == 0) {
		LOG_SSLERROR("X509_set_issuer_name");
		X509_free(cert);
		return false;
	}

	if (X509_set_pubkey(cert, pkey) == 0) {
		LOG_SSLERROR("X509_set_pubkey");
		X509_free(cert);
		return false;
	}

	/* CA certs get critical basic constraints; leaf certs get an authority
	 * key identifier pointing back at the issuer instead. */
	const int ca_ext_nid =
		ca ? NID_basic_constraints : NID_authority_key_identifier;
	const char *const ca_ext_value =
		ca ? "critical,CA:TRUE" : "keyid:always,issuer:always";
	if (!add_ext(cert, &v3ctx, NID_ext_key_usage, "serverAuth,clientAuth") ||
	    !add_ext(cert, &v3ctx, ca_ext_nid, ca_ext_value) ||
	    !add_subject_alt_name_ext(cert, &v3ctx, server_name, identity) ||
	    !add_ext(cert, &v3ctx, NID_subject_key_identifier, "hash")) {
		X509_free(cert);
		return false;
	}

	/* RFC 5280 4.2.1.3 requires a conforming CA certificate to carry keyUsage
	 * with keyCertSign; without it a strict verifier rejects the whole chain
	 * ("openssl verify -x509_strict" fails with "CA cert does not include key
	 * usage extension"). digitalSignature is asserted alongside it -- and the
	 * extended key usage above kept -- because an unsigned `--gencerts <name>`
	 * certificate is not only a CA: it is also handed straight to tls.cert as
	 * the peer's own end-entity certificate, and TLS 1.3, the only version
	 * either backend negotiates, signs the handshake with that key. A
	 * keyCertSign-only keyUsage would therefore break every self-signed
	 * certificate this tool generates, since the tool cannot know which of the
	 * two roles a given one will be used in. Leaf certificates (--sign) assert
	 * no keyUsage, which leaves them unconstrained -- permitted for end
	 * entities, and why a narrower CA keyUsage would not affect them. */
	if (ca && !add_ext(
			  cert, &v3ctx, NID_key_usage,
			  "critical,digitalSignature,keyCertSign,cRLSign")) {
		X509_free(cert);
		return false;
	}

	const EVP_MD *md = EVP_sha256();
	const int pkey_type = EVP_PKEY_get_base_id(sign_key);
	if (pkey_type == EVP_PKEY_ED25519 || pkey_type == EVP_PKEY_ED448) {
		md = NULL;
	}

	if (X509_sign(cert, sign_key, md) == 0) {
		LOG_SSLERROR("X509_sign");
		X509_free(cert);
		return false;
	}

	*out_cert = cert;
	return true;
}

static bool
write_keypair(const char *name, X509 *cert, EVP_PKEY *pkey, X509 *parent)
{
	char cert_file[256], key_file[256];
	if (!format_pem_filename(
		    cert_file, sizeof(cert_file), name, "-cert.pem") ||
	    !format_pem_filename(key_file, sizeof(key_file), name, "-key.pem")) {
		return false;
	}

	FILE *fp = create_exclusive(cert_file, 0644);
	if (fp == NULL) {
		return false;
	}
	if (PEM_write_X509(fp, cert) == 0) {
		LOG_SSLERROR("PEM_write_X509");
		(void)fclose(fp);
		discard_file(cert_file);
		return false;
	}
	if (parent != NULL) {
		/* Append the signing CA cert to form a complete chain */
		if (PEM_write_X509(fp, parent) == 0) {
			LOG_SSLERROR("PEM_write_X509");
			(void)fclose(fp);
			discard_file(cert_file);
			return false;
		}
	}
	if (fclose(fp) != 0) {
		const int err = errno;
		LOGE_F("fclose %s: (%d) %s", cert_file, err, strerror(err));
		discard_file(cert_file);
		return false;
	}

	/* Private key must be owner-readable only (mode 0600). */
	fp = create_exclusive(key_file, 0600);
	if (fp == NULL) {
		discard_file(cert_file);
		return false;
	}
	if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
		LOG_SSLERROR("PEM_write_PrivateKey");
		(void)fclose(fp);
		discard_file(key_file);
		discard_file(cert_file);
		return false;
	}
	if (fclose(fp) != 0) {
		const int err = errno;
		LOGE_F("fclose %s: (%d) %s", key_file, err, strerror(err));
		discard_file(key_file);
		discard_file(cert_file);
		return false;
	}

	LOGN_F("write %s, %s", cert_file, key_file);
	return true;
}

/* Next comma-separated field from *cursor, trimmed of surrounding spaces, or
 * NULL once the list is exhausted.  Unlike the strtok_r() used for the name
 * list, an empty field is returned as "" rather than skipped: "" is a valid
 * identity, and every field of an --identity list names one.  A certificate
 * with no identity at all is spelled by omitting --identity. */
static char *next_field(char **cursor)
{
	char *p = *cursor;
	if (p == NULL) {
		return NULL;
	}
	char *const comma = strchr(p, ',');
	if (comma != NULL) {
		*comma = '\0';
		*cursor = comma + 1;
	} else {
		*cursor = NULL;
	}
	while (*p == ' ') {
		p++;
	}
	char *end = p + strlen(p);
	while (end > p && end[-1] == ' ') {
		*--end = '\0';
	}
	return p;
}

/* Generate and write one certificate/key pair for @p name, carrying @p identity
 * as its URI subjectAltName (NULL omits it).  Owns nothing on return:
 * everything allocated here is released on every path. */
static bool generate_one(
	const char *restrict name, const char *restrict server_name,
	const char *restrict identity, X509 *const parent_cert,
	EVP_PKEY *const sign_key, const char *restrict keytype,
	const int keysize)
{
	EVP_PKEY *const pkey = generate_key(keytype, keysize);
	if (pkey == NULL) {
		LOGE_F("failed to generate key for %s", name);
		return false;
	}
	X509 *cert = NULL;
	if (!create_certificate(
		    parent_cert, sign_key, server_name, identity, pkey,
		    &cert)) {
		LOGE_F("failed to create certificate for %s", name);
		EVP_PKEY_free(pkey);
		return false;
	}
	const bool ok = write_keypair(name, cert, pkey, parent_cert);
	if (!ok) {
		LOGE_F("failed to write key pair for %s", name);
	}
	X509_free(cert);
	EVP_PKEY_free(pkey);
	return ok;
}

bool gencerts(
	const char *names, const char *server_name, const char *sign_cert,
	const char *keytype, int keysize, const char *identities)
{
	if (names == NULL) {
		LOGE("invalid options");
		return false;
	}

	X509 *parent_cert = NULL;
	EVP_PKEY *sign_key = NULL;

	if (sign_cert != NULL) {
		if (!read_keypair(sign_cert, &parent_cert, &sign_key)) {
			LOGE_F("failed to read signing certificate: %s",
			       sign_cert);
			return false;
		}
		if (X509_check_private_key(parent_cert, sign_key) != 1) {
			LOGE_F("signing certificate and key do not match: %s",
			       sign_cert);
			/* Drain any error-queue entries this pushed, so they can't
			 * bleed into a later, unrelated LOG_SSLERROR (gencerts() is a
			 * reusable entry point invoked repeatedly in one process). */
			LOG_SSLERROR("X509_check_private_key");
			X509_free(parent_cert);
			EVP_PKEY_free(sign_key);
			return false;
		}
	}

	const char *server_name_val =
		(server_name != NULL) ? server_name : "example.com";

	char *const names_copy = strdup(names);
	if (names_copy == NULL) {
		LOGOOM();
		if (parent_cert != NULL) {
			X509_free(parent_cert);
		}
		if (sign_key != NULL) {
			EVP_PKEY_free(sign_key);
		}
		return false;
	}

	/* A NULL list means "default each certificate's identity to its own
	 * name"; a non-NULL one is paired positionally with the names. */
	char *identities_copy = NULL;
	if (identities != NULL) {
		identities_copy = strdup(identities);
		if (identities_copy == NULL) {
			LOGOOM();
			free(names_copy);
			if (parent_cert != NULL) {
				X509_free(parent_cert);
			}
			if (sign_key != NULL) {
				EVP_PKEY_free(sign_key);
			}
			return false;
		}
	}
	char *id_cursor = identities_copy;

	bool success = true;
	size_t generated = 0;
	char *saveptr = NULL;
	for (char *name = strtok_r(names_copy, ",", &saveptr); name != NULL;
	     name = strtok_r(NULL, ",", &saveptr)) {
		while (*name == ' ') {
			name++;
		}
		if (*name == '\0') {
			continue;
		}
		char *end = name + strlen(name) - 1;
		while (end > name && *end == ' ') {
			*end = '\0';
			end--;
		}

		/* No --identity means no identity, never inferred from a file
		 * name.  Consumed after the empty-name skip above, so blank
		 * name fields do not shift the pairing. */
		const char *identity = NULL;
		if (identities_copy != NULL) {
			identity = next_field(&id_cursor);
			if (identity == NULL) {
				LOGE("--identity has fewer entries than"
				     " --gencerts");
				success = false;
				break;
			}
		}

		if (!generate_one(
			    name, server_name_val, identity, parent_cert,
			    sign_key, keytype, keysize)) {
			success = false;
			break;
		}
		generated++;
	}

	if (success && id_cursor != NULL) {
		LOGE("--identity has more entries than --gencerts");
		success = false;
	}

	free(names_copy);
	free(identities_copy);

	if (parent_cert != NULL) {
		X509_free(parent_cert);
	}
	if (sign_key != NULL) {
		EVP_PKEY_free(sign_key);
	}

	/* Every token was empty or blank (e.g. `--gencerts ""` from an unset
	 * shell variable): nothing was written, so reporting success would tell a
	 * provisioning script its certificates exist. */
	if (success && generated == 0) {
		LOGE_F("no certificate name in list: \"%s\"", names);
		success = false;
	}

	if (success) {
		LOGN("ok");
	}

	return success;
}

#endif /* WITH_OPENSSL */
