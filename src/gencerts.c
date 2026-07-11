/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file gencerts.c
 * @brief Certificate generation utility using OpenSSL.
 */

#include "gencerts.h"

#if WITH_OPENSSL

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
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

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

static bool format_subject_alt_name(
	char *restrict buf, const size_t buflen,
	const char *restrict server_name)
{
	const int len = snprintf(buf, buflen, "DNS:%s", server_name);
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
		LOGE_F("failed to open %s", cert_file);
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
		LOGE_F("failed to open %s", key_file);
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
	if (X509_NAME_add_entry_by_txt(
		    name, "CN", MBSTRING_ASC,
		    (const unsigned char *)server_name, -1, -1, 0) == 0) {
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
	const char *restrict server_name)
{
	const size_t server_name_len = strlen(server_name);
	if (server_name_len >= 256) {
		LOGE_F("server name too long: %zu bytes", server_name_len);
		return false;
	}
	char san_value[server_name_len + 5];
	if (!format_subject_alt_name(
		    san_value, sizeof(san_value), server_name)) {
		return false;
	}
	return add_ext(cert, v3ctx, NID_subject_alt_name, san_value);
}

static bool create_certificate(
	X509 *parent, EVP_PKEY *sign_key, const char *server_name,
	EVP_PKEY *pkey, X509 **out_cert)
{
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
	    !add_subject_alt_name_ext(cert, &v3ctx, server_name) ||
	    !add_ext(cert, &v3ctx, NID_subject_key_identifier, "hash")) {
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

/* Best-effort cleanup after a later step fails; the caller is already
 * returning an error, so a failed unlink here is only logged. */
static void discard_file(const char *path)
{
	if (unlink(path) != 0) {
		const int err = errno;
		LOGW_F("failed to remove %s: (%d) %s", path, err,
		       strerror(err));
	}
}

/* Create `path` exclusively (O_EXCL refuses to overwrite an existing file)
 * and wrap it in a stream, discarding the file if fdopen fails. mode is
 * masked by umask (POSIX semantics): an upper bound, not a guarantee. */
static FILE *create_exclusive(const char *path, mode_t mode)
{
	const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("failed to open %s: (%d) %s", path, err, strerror(err));
		return NULL;
	}
	FILE *const fp = fdopen(fd, "w");
	if (fp == NULL) {
		const int err = errno;
		LOGE_F("fdopen %s: (%d) %s", path, err, strerror(err));
		(void)close(fd);
		discard_file(path);
		return NULL;
	}
	return fp;
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

bool gencerts(
	const char *names, const char *server_name, const char *sign_cert,
	const char *keytype, int keysize)
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

	bool success = true;
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

		EVP_PKEY *const pkey = generate_key(keytype, keysize);
		if (pkey == NULL) {
			LOGE_F("failed to generate key for %s", name);
			success = false;
			break;
		}

		X509 *cert = NULL;
		if (!create_certificate(
			    parent_cert, sign_key, server_name_val, pkey,
			    &cert)) {
			LOGE_F("failed to create certificate for %s", name);
			EVP_PKEY_free(pkey);
			success = false;
			break;
		}

		if (!write_keypair(name, cert, pkey, parent_cert)) {
			LOGE_F("failed to write key pair for %s", name);
			X509_free(cert);
			EVP_PKEY_free(pkey);
			success = false;
			break;
		}

		X509_free(cert);
		EVP_PKEY_free(pkey);
	}

	free(names_copy);

	if (parent_cert != NULL) {
		X509_free(parent_cert);
	}
	if (sign_key != NULL) {
		EVP_PKEY_free(sign_key);
	}

	if (success) {
		LOGN("ok");
	}

	return success;
}

#endif /* WITH_OPENSSL */
