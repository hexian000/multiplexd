/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* tls_openssl_test.c - white-box tests for the OpenSSL backend's
 * certificate-strength floor.  The floor helpers (tls_ec_curve_allowed,
 * tls_cert_digest_allowed, tls_verify_cert_strength_cb) are static and cannot
 * be reached through the public tls.h API: OpenSSL's own security level refuses
 * to *load* a sub-floor own certificate, so no black-box handshake ever
 * presents one to the verify callback -- the handshake cases in tls_test.c hit
 * that load refusal on this backend and only exercise the mbedTLS profile
 * floor.  This TU compiles tls_openssl.c directly (its symbols are internal to
 * this file, so it must not link `shim`) to test the floor in isolation against
 * certificates and keys built at runtime. */

/* WITH_TLS comes from the force-included config.h, as in tls_openssl.c. */
#if WITH_TLS

/* Compile the backend into this TU to reach its static floor helpers. */
#include "tls_openssl.c"

#include "utils/slog.h"
#include "utils/testing.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Generate a key pair; a NULL result is a test-setup failure, not a case
 * failure, so abort via T_CHECK rather than returning it. */
static EVP_PKEY *gen_rsa(const unsigned int bits)
{
	EVP_PKEY *const key =
		EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)bits);
	T_CHECK(key != NULL);
	return key;
}

static EVP_PKEY *gen_ec(const char *const curve)
{
	EVP_PKEY *const key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve);
	T_CHECK(key != NULL);
	return key;
}

/* Build a certificate over @p key signed with @p md.  When @p issuer_cn is NULL
 * the certificate is self-signed (subject == issuer, so it carries EXFLAG_SS
 * and models a trust anchor); otherwise @p issuer_cn becomes a distinct issuer
 * name, modelling a non-self-signed intermediate.  The strength callback under
 * test inspects only the digest algorithm and public key, never verifying the
 * signature, so a self-key signature on a mismatched issuer is sufficient.
 * Returns NULL on failure. */
static X509 *make_cert(
	EVP_PKEY *const key, const EVP_MD *const md,
	const char *const issuer_cn)
{
	X509 *const x = X509_new();
	if (x == NULL) {
		return NULL;
	}
	/* Build the subject name separately and set it rather than mutating the
	 * certificate's internal name in place: OpenSSL 4.0 made
	 * X509_get_subject_name() return a const pointer, so an in-place
	 * X509_NAME_add_entry_by_txt() on its result no longer compiles.  Both
	 * X509_set_subject_name() and X509_set_issuer_name() copy the name, so
	 * this one @c subject is freed once below and also serves as the
	 * self-signed issuer.  This mirrors the @c issuer path below. */
	X509_NAME *const subject = X509_NAME_new();
	bool ok = subject != NULL &&
		  X509_NAME_add_entry_by_txt(
			  subject, "CN", MBSTRING_ASC,
			  (const unsigned char *)"strength.test", -1, -1,
			  0) == 1 &&
		  X509_set_subject_name(x, subject) == 1 &&
		  X509_set_version(x, 2L) == 1 &&
		  ASN1_INTEGER_set(X509_get_serialNumber(x), 1L) == 1 &&
		  X509_gmtime_adj(X509_getm_notBefore(x), 0) != NULL &&
		  X509_gmtime_adj(X509_getm_notAfter(x), 3600) != NULL &&
		  X509_set_pubkey(x, key) == 1;
	if (ok && issuer_cn != NULL) {
		X509_NAME *const issuer = X509_NAME_new();
		ok = issuer != NULL &&
		     X509_NAME_add_entry_by_txt(
			     issuer, "CN", MBSTRING_ASC,
			     (const unsigned char *)issuer_cn, -1, -1,
			     0) == 1 &&
		     X509_set_issuer_name(x, issuer) == 1;
		X509_NAME_free(issuer);
	} else if (ok) {
		ok = X509_set_issuer_name(x, subject) == 1;
	}
	X509_NAME_free(subject);
	if (!ok || X509_sign(x, key, md) <= 0) {
		X509_free(x);
		return NULL;
	}
	return x;
}

/* Invoke the strength callback with @p preverify_ok on @p cert at @p depth,
 * with a minimal store context carrying only the current certificate and error
 * depth the callback reads.  Returns the callback result; on rejection the
 * error it set is reported through @p out_err. */
static int run_strength_cb(
	const int preverify_ok, X509 *const cert, const int depth,
	int *const out_err)
{
	X509_STORE *const store = X509_STORE_new();
	X509_STORE_CTX *const ctx = X509_STORE_CTX_new();
	T_CHECK(store != NULL && ctx != NULL);
	T_CHECK(X509_STORE_CTX_init(ctx, store, NULL, NULL) == 1);
	X509_STORE_CTX_set_current_cert(ctx, cert);
	X509_STORE_CTX_set_error_depth(ctx, depth);
	X509_STORE_CTX_set_error(ctx, X509_V_OK);
	const int rv = tls_verify_cert_strength_cb(preverify_ok, ctx);
	if (out_err != NULL) {
		*out_err = X509_STORE_CTX_get_error(ctx);
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return rv;
}

/* The EC-curve allowlist mirrors mbedtls_x509_crt_profile_default: the NIST
 * P-256/384/521 and brainpool 256/384/512 curves are accepted, while weaker
 * curves (notably P-224, and P-192) are rejected.  The TLS-1.3-only handshake
 * cannot reach this check with a sub-floor curve, so it is only covered here. */
T_DECLARE_CASE(test_ec_curve_allowlist)
{
	static const struct {
		const char *curve;
		bool allowed;
	} cases[] = {
		{ "P-256", true },  { "P-384", true },
		{ "P-521", true },  { "brainpoolP256r1", true },
		{ "P-224", false }, { "P-192", false },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		EVP_PKEY *const key = gen_ec(cases[i].curve);
		const bool got = tls_ec_curve_allowed(key);
		EVP_PKEY_free(key);
		if (got != cases[i].allowed) {
			T_LOGF("curve %s: expected %d, got %d", cases[i].curve,
			       (int)cases[i].allowed, (int)got);
			T_FAIL();
		}
	}
}

/* The digest floor accepts SHA-256/384/512 and rejects everything below it,
 * notably SHA-1 and SHA-224.  SHA-224 matters because OpenSSL's default
 * security level accepts it, so only this floor keeps the two backends in step
 * (cf. the SHA-3 exclusion documented in tls_cert_digest_allowed). */
T_DECLARE_CASE(test_cert_digest_floor)
{
	EVP_PKEY *const key = gen_rsa(2048);

	X509 *c;
	c = make_cert(key, EVP_sha256(), NULL);
	T_CHECK(c != NULL);
	T_EXPECT(tls_cert_digest_allowed(c));
	X509_free(c);

	c = make_cert(key, EVP_sha384(), NULL);
	T_CHECK(c != NULL);
	T_EXPECT(tls_cert_digest_allowed(c));
	X509_free(c);

	c = make_cert(key, EVP_sha512(), NULL);
	T_CHECK(c != NULL);
	T_EXPECT(tls_cert_digest_allowed(c));
	X509_free(c);

	c = make_cert(key, EVP_sha1(), NULL);
	T_CHECK(c != NULL);
	T_EXPECT(!tls_cert_digest_allowed(c));
	X509_free(c);

	c = make_cert(key, EVP_sha224(), NULL);
	T_CHECK(c != NULL);
	T_EXPECT(!tls_cert_digest_allowed(c));
	X509_free(c);

	EVP_PKEY_free(key);
}

/* The integrated verify callback over a peer chain: it rejects a sub-floor RSA
 * key, a sub-floor signature digest, and a sub-floor EC curve; accepts material
 * at or above the floor; exempts a self-signed trust anchor's own digest at
 * depth > 0 while still enforcing it on a non-self-signed intermediate; and
 * passes a failed preverify straight through without upgrading it. */
T_DECLARE_CASE(test_verify_cert_strength_cb)
{
	EVP_PKEY *const rsa2048 = gen_rsa(2048);
	EVP_PKEY *const rsa1024 = gen_rsa(1024);
	EVP_PKEY *const ec256 = gen_ec("P-256");
	EVP_PKEY *const ec224 = gen_ec("P-224");

	/* want_err is checked only on a rejection (want_rv == 0); ERR_ANY skips
	 * it.  A self-signed cert (issuer_cn == NULL) at depth > 0 is a trust
	 * anchor, exempt from the digest floor; a distinct issuer_cn makes it a
	 * non-self-signed intermediate that is not exempt. */
	enum { ERR_ANY = -1 };
	const struct {
		const char *desc;
		EVP_PKEY *key;
		const EVP_MD *md;
		const char *issuer_cn;
		int preverify_ok;
		int depth;
		int want_rv;
		int want_err;
	} cases[] = {
		{ "strong RSA-2048/SHA-256 leaf", rsa2048, EVP_sha256(), NULL,
		  1, 0, 1, ERR_ANY },
		{ "RSA-1024 leaf", rsa1024, EVP_sha256(), NULL, 1, 0, 0,
		  X509_V_ERR_EE_KEY_TOO_SMALL },
		{ "SHA-1 leaf", rsa2048, EVP_sha1(), NULL, 1, 0, 0,
		  X509_V_ERR_CA_MD_TOO_WEAK },
		/* OpenSSL's own security level would accept SHA-224; only this
		 * floor catches it. */
		{ "SHA-224 leaf", rsa2048, EVP_sha224(), NULL, 1, 0, 0,
		  X509_V_ERR_CA_MD_TOO_WEAK },
		{ "self-signed SHA-1 anchor at depth 1", rsa2048, EVP_sha1(),
		  NULL, 1, 1, 1, ERR_ANY },
		{ "non-self-signed SHA-1 intermediate at depth 1", rsa2048,
		  EVP_sha1(), "issuer.test", 1, 1, 0,
		  X509_V_ERR_CA_MD_TOO_WEAK },
		{ "EC P-224 leaf", ec224, EVP_sha256(), NULL, 1, 0, 0,
		  X509_V_ERR_EE_KEY_TOO_SMALL },
		{ "EC P-256 leaf", ec256, EVP_sha256(), NULL, 1, 0, 1,
		  ERR_ANY },
		{ "failed preverify passes through", rsa2048, EVP_sha256(),
		  NULL, 0, 0, 0, ERR_ANY },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		X509 *const c = make_cert(
			cases[i].key, cases[i].md, cases[i].issuer_cn);
		T_CHECK(c != NULL);
		int err = X509_V_OK;
		const int rv = run_strength_cb(
			cases[i].preverify_ok, c, cases[i].depth, &err);
		X509_free(c);
		if (rv != cases[i].want_rv) {
			T_LOGF("%s: expected rv %d, got %d", cases[i].desc,
			       cases[i].want_rv, rv);
			T_FAIL();
			continue;
		}
		if (cases[i].want_rv == 0 && cases[i].want_err != ERR_ANY &&
		    err != cases[i].want_err) {
			T_LOGF("%s: expected err %d, got %d", cases[i].desc,
			       cases[i].want_err, err);
			T_FAIL();
		}
	}

	EVP_PKEY_free(rsa2048);
	EVP_PKEY_free(rsa1024);
	EVP_PKEY_free(ec256);
	EVP_PKEY_free(ec224);
}

/* Captures slog output so a case can assert on a diagnostic rather than only
 * on a return value. */
static char g_log_capture[1024];
static size_t g_log_capture_len;

static void
log_capture_writer(void *ud, const unsigned char *buf, const size_t len)
{
	(void)ud;
	if (g_log_capture_len + len + 1 > sizeof(g_log_capture)) {
		return;
	}
	memcpy(g_log_capture + g_log_capture_len, buf, len);
	g_log_capture_len += len;
	g_log_capture[g_log_capture_len] = '\0';
}

/* A PEM source that scans cleanly to EOF but carries no certificate -- a file
 * holding only a private key, say -- must say so. load_authcert_from_bio logs
 * the identical condition; without a message here the only trace is the
 * caller's generic "failed to load TLS certificate", hiding that the data
 * parsed fine and simply had no certificate in it. */
T_DECLARE_CASE(test_load_cert_without_certificate_logs)
{
	static const char pem[] = "# no certificate in here\n";
	BIO *const bio = BIO_new_mem_buf(pem, (int)(sizeof(pem) - 1));
	T_CHECK(bio != NULL);
	SSL_CTX *const ctx = SSL_CTX_new(TLS_client_method());
	T_CHECK(ctx != NULL);

	g_log_capture[0] = '\0';
	g_log_capture_len = 0;
	const int prev_level = slog_level_;
	slog_setlevel(LOG_LEVEL_ERROR);
	slog_setoutput(SLOG_OUTPUT_WRITER, log_capture_writer, NULL);
	const bool loaded = load_cert_from_bio(ctx, bio);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
	slog_setlevel(prev_level);

	const bool logged =
		strstr(g_log_capture, "no certificates parsed") != NULL;

	SSL_CTX_free(ctx);
	BIO_free(bio);

	T_EXPECT(!loaded);
	T_EXPECT(logged);
}

static const struct testing_suite suite[] = {
	T_CASE(test_ec_curve_allowlist),
	T_CASE(test_cert_digest_floor),
	T_CASE(test_verify_cert_strength_cb),
	T_CASE(test_load_cert_without_certificate_logs),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}

#else /* !WITH_TLS */

#include <stdlib.h>

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
