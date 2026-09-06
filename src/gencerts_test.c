/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* gencerts_test.c - black-box tests for certificate/key generation in
 * gencerts.c via its public API. Dependencies: links the real gencerts.c + TLS
 * backend (no-op when TLS disabled). */

#if WITH_OPENSSL

#include "gencerts.h"

#include "meta/arraysize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Remove a file tree recursively using only POSIX APIs; used for
 * temp-directory cleanup. */
static void rm_tmpdir(const char *path)
{
	DIR *const dir = opendir(path);
	if (dir == NULL) {
		return;
	}
	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0) {
			continue;
		}
		char subpath[PATH_MAX];
		(void)snprintf(
			subpath, sizeof(subpath), "%s/%s", path, ent->d_name);
		struct stat st;
		if (lstat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
			rm_tmpdir(subpath);
		} else {
			(void)unlink(subpath);
		}
	}
	(void)closedir(dir);
	(void)rmdir(path);
}

/* Process-exit sweep for case failures that skip leave_tmpdir().
 * rm_tmpdir() no-ops for directories already removed by a passing case. */
enum { PENDING_TMPDIRS_MAX = 64 };
static char pending_tmpdirs[PENDING_TMPDIRS_MAX][64];
static int pending_tmpdirs_count = 0;

static void sweep_pending_tmpdirs(void)
{
	for (int i = 0; i < pending_tmpdirs_count; i++) {
		rm_tmpdir(pending_tmpdirs[i]);
	}
}

static void track_tmpdir(const char *tmpl)
{
	static bool registered = false;
	if (!registered) {
		T_CHECK(atexit(sweep_pending_tmpdirs) == 0);
		registered = true;
	}
	if (pending_tmpdirs_count < PENDING_TMPDIRS_MAX) {
		(void)snprintf(
			pending_tmpdirs[pending_tmpdirs_count],
			sizeof(pending_tmpdirs[0]), "%s", tmpl);
		pending_tmpdirs_count++;
	}
}

/* Enter a fresh temp dir, filling origdir with the original cwd and tmpl
 * with the created path. */
static bool
enter_tmpdir(char *restrict tmpl, char *restrict origdir, size_t origdir_size)
{
	if (getcwd(origdir, origdir_size) == NULL) {
		return false;
	}
	if (mkdtemp(tmpl) == NULL) {
		return false;
	}
	track_tmpdir(tmpl);
	if (chdir(tmpl) != 0) {
		rm_tmpdir(tmpl);
		return false;
	}
	return true;
}

static void
leave_tmpdir(const char *restrict origdir, const char *restrict tmpl)
{
	if (chdir(origdir) != 0) {
		const int err = errno;
		LOGW_F("chdir: (%d) %s", err, strerror(err));
	}
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_gencerts_ed25519)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("testcert", "test.example", NULL, "ed25519", 0, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("testcert-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("testcert-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_ecdsa)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("ec256", "ec.example", NULL, "ecdsa", 256, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("ec256-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("ec256-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_rsa)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* Use 2048-bit RSA to keep the test reasonably fast. */
	const bool ok =
		gencerts("rsa2048", "rsa.example", NULL, "rsa", 2048, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("rsa2048-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("rsa2048-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_invalid_keytype)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts("x", "test", NULL, "nosuchthing", 0, NULL);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_invalid_ecdsa_keysize)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("ecbad", "ec.example", NULL, "ecdsa", 255, NULL);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_ed25519_rejects_keysize)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* ed25519 has no variable key size; a non-zero request (e.g. a
	 * copy-pasted RSA/ECDSA invocation) must fail, not be silently
	 * ignored. */
	const bool ok =
		gencerts("edbad", "ed.example", NULL, "ed25519", 256, NULL);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_missing_signing_cert_fails)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts(
		"server", "server.example", "missing", "ed25519", 0, NULL);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_refuses_overwrite_existing_files)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	bool ok = gencerts("dup", "dup.example", NULL, "ed25519", 0, NULL);
	T_CHECK(ok);
	ok = gencerts("dup", "dup.example", NULL, "ed25519", 0, NULL);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_multiple_names)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts(
		"alpha, beta", "multi.example", NULL, "ed25519", 0, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("alpha-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("alpha-key.pem", F_OK), 0);
		T_EXPECT_EQ(access("beta-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("beta-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_skips_all_space_name_token)
{
	/* A name token that is entirely spaces (e.g. between two commas)
	 * must be skipped without generating a cert for it, and must not
	 * disrupt the real tokens on either side. */
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts(
		"alpha, ,beta", "multi.example", NULL, "ed25519", 0, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("alpha-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("alpha-key.pem", F_OK), 0);
		T_EXPECT_EQ(access("beta-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("beta-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

/* A list that yields no usable token at all -- an empty string, or nothing but
 * separators and blanks, as `--gencerts "$NAMES"` produces when NAMES is unset
 * -- writes no files, so it must be reported as a failure. Reporting success
 * would tell a provisioning script its certificates exist. Complements
 * test_gencerts_skips_all_space_name_token, where real tokens remain. */
T_DECLARE_CASE(test_gencerts_empty_name_list_fails)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool empty_ok =
		gencerts("", "none.example", NULL, "ed25519", 0, NULL);
	const bool blank_ok =
		gencerts(" , , ", "none.example", NULL, "ed25519", 0, NULL);

	/* The false return alone would also be satisfied by a run that wrote a
	 * file and then failed for some other reason, so pin the claim this case
	 * actually makes: a blank token that slipped through would be written
	 * under the empty name. Captured before teardown, like the X509 cases. */
	const bool wrote_cert = access("-cert.pem", F_OK) == 0;
	const bool wrote_key = access("-key.pem", F_OK) == 0;

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(!empty_ok);
	T_EXPECT(!blank_ok);
	T_EXPECT(!wrote_cert);
	T_EXPECT(!wrote_key);
}

T_DECLARE_CASE(test_gencerts_with_signing_cert)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	bool ok = gencerts("ca", "ca.example", NULL, "ed25519", 0, NULL);
	T_CHECK(ok);

	ok = gencerts("server", "server.example", "ca", "ed25519", 0, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("server-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("server-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p224_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("p224", "p224.example", NULL, "ecdsa", 224, NULL);
	T_EXPECT(!ok);
	T_EXPECT(access("p224-cert.pem", F_OK) != 0);
	T_EXPECT(access("p224-key.pem", F_OK) != 0);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p384)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("p384", "p384.example", NULL, "ecdsa", 384, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("p384-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("p384-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p521)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("p521", "p521.example", NULL, "ecdsa", 521, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("p521-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("p521-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_key_write_failure_removes_cert)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* Pre-create the key file so write_keypair's O_EXCL open fails
	 * after the cert file has already been written successfully. */
	FILE *const stale = fopen("rollback-key.pem", "w");
	T_CHECK(stale != NULL);
	if (stale != NULL) {
		(void)fclose(stale);
	}

	const bool ok = gencerts(
		"first,rollback", "rollback.example", NULL, "ed25519", 0, NULL);
	T_EXPECT(!ok);
	T_EXPECT(access("first-cert.pem", F_OK) != 0);
	T_EXPECT(access("first-key.pem", F_OK) != 0);
	T_EXPECT(access("rollback-cert.pem", F_OK) != 0);
	T_EXPECT(access("rollback-key.pem", F_OK) == 0);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_sni_too_long_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* Grossly over the 256-byte bound checked before create_certificate's
	 * SAN buffer is sized; must be rejected cleanly, never crash. */
	enum { HUGE_SNI_LEN = 65536 };
	char *const long_sni = malloc(HUGE_SNI_LEN + 1);
	T_CHECK(long_sni != NULL);
	memset(long_sni, 'a', HUGE_SNI_LEN);
	long_sni[HUGE_SNI_LEN] = '\0';

	const bool ok = gencerts("toolong", long_sni, NULL, "ed25519", 0, NULL);
	free(long_sni);
	T_EXPECT(!ok);
	T_EXPECT(access("toolong-cert.pem", F_OK) != 0);

	leave_tmpdir(origdir, tmpl);
}

/* The SAN extension value is an OpenSSL comma-separated configuration list.
 * A punctuation-bearing SNI must be rejected rather than interpreted as an
 * additional URI or other SAN entry. */
T_DECLARE_CASE(test_gencerts_sni_san_injection_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts(
		"injected", "foo,URI:multiplexd:attacker", NULL, "ed25519", 0,
		NULL);
	T_EXPECT(!ok);
	T_EXPECT(access("injected-cert.pem", F_OK) != 0);
	T_EXPECT(access("injected-key.pem", F_OK) != 0);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_rsa_keysize_too_large_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("hugersa", "rsa.example", NULL, "rsa", 999999, NULL);
	T_EXPECT(!ok);
	T_EXPECT(access("hugersa-cert.pem", F_OK) != 0);

	leave_tmpdir(origdir, tmpl);
}

/* generate_key rejects an RSA key size below RSA_KEYSIZE_MIN (2048). */
T_DECLARE_CASE(test_gencerts_rsa_keysize_too_small_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("smallrsa", "rsa.example", NULL, "rsa", 1024, NULL);
	T_EXPECT(!ok);
	T_EXPECT(access("smallrsa-cert.pem", F_OK) != 0);

	leave_tmpdir(origdir, tmpl);
}

/* keysize == 0 for ECDSA takes the default-size branch (256) instead of
 * rejecting; the cert must still be generated. */
T_DECLARE_CASE(test_gencerts_ecdsa_default_keysize)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts("ecdef", "ec.example", NULL, "ecdsa", 0, NULL);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("ecdef-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("ecdef-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

/* A signing cert whose key file does not match it (content mismatch, not a
 * missing file) is rejected by gencerts()'s X509_check_private_key gate. */
T_DECLARE_CASE(test_gencerts_signing_cert_key_mismatch_fails)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	T_CHECK(gencerts("ca1", "ca1.example", NULL, "ed25519", 0, NULL));
	T_CHECK(gencerts("ca2", "ca2.example", NULL, "ed25519", 0, NULL));
	/* Replace ca1's key with ca2's so ca1-cert.pem and ca1-key.pem no longer
	 * match. */
	T_CHECK(rename("ca2-key.pem", "ca1-key.pem") == 0);

	const bool ok =
		gencerts("srv", "srv.example", "ca1", "ed25519", 0, NULL);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_file_permissions)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* gencerts requests 0644/0600 but open(2) masks the mode by the ambient
	 * umask, so a hardened inherited umask (0027/0077) would land the cert at
	 * 0640/0600 and fail the exact assertions below. Clear the umask around
	 * generation so the created modes are exactly what gencerts requested. */
	const mode_t old_umask = umask(0);
	const bool ok =
		gencerts("perms", "perms.example", NULL, "ed25519", 0, NULL);
	(void)umask(old_umask);
	T_EXPECT(ok);
	if (ok) {
		struct stat st;
		T_EXPECT_EQ(stat("perms-key.pem", &st), 0);
		T_EXPECT_EQ((unsigned int)(st.st_mode & 0777U), 0600U);
		T_EXPECT_EQ(stat("perms-cert.pem", &st), 0);
		T_EXPECT_EQ((unsigned int)(st.st_mode & 0777U), 0644U);
	}

	leave_tmpdir(origdir, tmpl);
}

/* Read a PEM certificate file (cwd-relative); caller frees with X509_free. */
static X509 *read_cert_file(const char *restrict path)
{
	FILE *const fp = fopen(path, "r");
	if (fp == NULL) {
		return NULL;
	}
	X509 *const cert = PEM_read_X509(fp, NULL, NULL, NULL);
	(void)fclose(fp);
	return cert;
}

/* Copy the first commonName text of @p name into @p buf (NUL-terminated, up to
 * @p len bytes), returning the entry's byte length or -1 when absent.  A local
 * stand-in for X509_NAME_get_text_by_NID(), which OpenSSL 4.0 deprecated, built
 * on the non-deprecated entry accessors so it compiles clean on 3.x and 4.x
 * alike; @p name is taken const because X509_get_subject_name() returns const
 * as of 4.0. */
static int
name_get_cn(const X509_NAME *const name, char *const buf, const size_t len)
{
	const int idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
	if (idx < 0) {
		return -1;
	}
	const ASN1_STRING *const data =
		X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, idx));
	if (data == NULL) {
		return -1;
	}
	const int dlen = ASN1_STRING_length(data);
	if (len > 0) {
		const size_t n = (dlen >= 0 && (size_t)dlen < len) ?
					 (size_t)dlen :
					 len - 1;
		memcpy(buf, ASN1_STRING_get0_data(data), n);
		buf[n] = '\0';
	}
	return dlen;
}

static bool cert_cn_equals(X509 *restrict cert, const char *restrict expect)
{
	char cn[256] = { 0 };
	const int n = name_get_cn(X509_get_subject_name(cert), cn, sizeof(cn));
	return n > 0 && strcmp(cn, expect) == 0;
}

static bool cert_has_dns_san(X509 *restrict cert, const char *restrict expect)
{
	GENERAL_NAMES *const san =
		X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (san == NULL) {
		return false;
	}
	bool found = false;
	const int count = sk_GENERAL_NAME_num(san);
	for (int i = 0; i < count && !found; i++) {
		const GENERAL_NAME *const gn = sk_GENERAL_NAME_value(san, i);
		if (gn->type != GEN_DNS) {
			continue;
		}
		const ASN1_IA5STRING *const dns = gn->d.dNSName;
		const int len = ASN1_STRING_length(dns);
		const unsigned char *const data = ASN1_STRING_get0_data(dns);
		if (len == (int)strlen(expect) &&
		    memcmp(data, expect, (size_t)len) == 0) {
			found = true;
		}
	}
	GENERAL_NAMES_free(san);
	return found;
}

/* Count URI subjectAltNames, optionally requiring one to equal @p expect.
 * The expected form is spelled out literally rather than built from
 * IDENTITY_URI_SCHEME, so this pins the on-certificate wire format that
 * identity.verify reads back. */
static bool cert_has_uri_san(
	X509 *restrict cert, const char *restrict expect, int *restrict n_uri)
{
	*n_uri = 0;
	GENERAL_NAMES *const san =
		X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (san == NULL) {
		return false;
	}
	bool found = false;
	const int count = sk_GENERAL_NAME_num(san);
	for (int i = 0; i < count; i++) {
		const GENERAL_NAME *const gn = sk_GENERAL_NAME_value(san, i);
		if (gn->type != GEN_URI) {
			continue;
		}
		(*n_uri)++;
		const ASN1_IA5STRING *const uri =
			gn->d.uniformResourceIdentifier;
		const int len = ASN1_STRING_length(uri);
		const unsigned char *const data = ASN1_STRING_get0_data(uri);
		if (expect != NULL && len == (int)strlen(expect) &&
		    memcmp(data, expect, (size_t)len) == 0) {
			found = true;
		}
	}
	GENERAL_NAMES_free(san);
	return found;
}

/* Without --identity a certificate carries no identity at all: an identity is a
 * deployment fact, never inferred from the certificate's file name. */
T_DECLARE_CASE(test_gencerts_identity_absent_omits_san)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts(
		"alpha,beta", "multi.example", NULL, "ed25519", 0, NULL);
	T_EXPECT(ok);
	if (ok) {
		X509 *const alpha = read_cert_file("alpha-cert.pem");
		X509 *const beta = read_cert_file("beta-cert.pem");
		T_EXPECT(alpha != NULL);
		T_EXPECT(beta != NULL);
		int n = -1;
		if (alpha != NULL) {
			T_EXPECT(!cert_has_uri_san(alpha, NULL, &n));
			T_EXPECT_EQ(n, 0);
			/* Omitting the identity must not drop the DNS name. */
			T_EXPECT(cert_has_dns_san(alpha, "multi.example"));
		}
		if (beta != NULL) {
			T_EXPECT(!cert_has_uri_san(beta, NULL, &n));
			T_EXPECT_EQ(n, 0);
		}
		X509_free(alpha);
		X509_free(beta);
	}

	leave_tmpdir(origdir, tmpl);
}

/* An explicit list is paired positionally, and an empty entry names the empty
 * identity -- a claim a peer may make (doc/spec.md 5.2.3.2), so it earns a URI
 * name of its own rather than none, which identity.verify then matches. */
T_DECLARE_CASE(test_gencerts_identity_explicit_list)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts(
		"blank,peer", "id.example", NULL, "ed25519", 0, ",east-1");
	T_EXPECT(ok);
	if (ok) {
		X509 *const blank = read_cert_file("blank-cert.pem");
		X509 *const peer = read_cert_file("peer-cert.pem");
		T_EXPECT(blank != NULL);
		T_EXPECT(peer != NULL);
		int n = -1;
		if (blank != NULL) {
			T_EXPECT(cert_has_uri_san(blank, "multiplexd:", &n));
			T_EXPECT_EQ(n, 1);
			/* The identity does not displace the DNS name. */
			T_EXPECT(cert_has_dns_san(blank, "id.example"));
		}
		if (peer != NULL) {
			T_EXPECT(cert_has_uri_san(
				peer, "multiplexd:east-1", &n));
			T_EXPECT_EQ(n, 1);
		}
		X509_free(blank);
		X509_free(peer);
	}

	leave_tmpdir(origdir, tmpl);
}

/* RFC 5280 requires the URI name to be an IA5String, so a UTF-8 identity and
 * the URI-reserved characters must be percent-encoded.  A space becomes %20,
 * not '+': that would be form encoding, not a URI. */
T_DECLARE_CASE(test_gencerts_identity_percent_encoded)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts(
		"enc", "id.example", NULL, "ed25519", 0, "caf\xC3\xA9 a/b");
	T_EXPECT(ok);
	if (ok) {
		X509 *const cert = read_cert_file("enc-cert.pem");
		T_EXPECT(cert != NULL);
		if (cert != NULL) {
			int n = 0;
			T_EXPECT(cert_has_uri_san(
				cert, "multiplexd:caf%C3%A9%20a%2Fb", &n));
			T_EXPECT_EQ(n, 1);
		}
		X509_free(cert);
	}

	leave_tmpdir(origdir, tmpl);
}

/* An --identity list that does not pair one-to-one with the names is an error
 * in both directions, rather than silently mislabelling a certificate. */
T_DECLARE_CASE(test_gencerts_identity_count_mismatch)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	T_EXPECT(!gencerts("a,b", "id.example", NULL, "ed25519", 0, "x"));
	T_EXPECT(access("a-cert.pem", F_OK) != 0);
	T_EXPECT(access("a-key.pem", F_OK) != 0);
	T_EXPECT(!gencerts("c", "id.example", NULL, "ed25519", 0, "x,y"));
	T_EXPECT(access("c-cert.pem", F_OK) != 0);
	T_EXPECT(access("c-key.pem", F_OK) != 0);

	leave_tmpdir(origdir, tmpl);
}

/* Collects the log lines gencerts() emits while registered as slog's sink. */
struct log_capture {
	size_t len;
	bool overflow;
	char buf[4096];
};

static void
log_capture_write(void *ud, const unsigned char *buf, const size_t len)
{
	struct log_capture *const restrict cap = ud;
	/* One byte is reserved for the NUL the string searches need. */
	if (cap->len + len >= sizeof(cap->buf)) {
		cap->overflow = true;
		return;
	}
	memcpy(cap->buf + cap->len, buf, len);
	cap->len += len;
	cap->buf[cap->len] = '\0';
}

/* Run gencerts() with its NOTICE-and-above output captured into @p cap. The
 * suite otherwise runs silent with no sink, which is how it is left. */
static bool gencerts_captured(
	struct log_capture *restrict cap, const char *restrict names,
	const char *restrict server_name, const char *restrict identities)
{
	cap->len = 0;
	cap->overflow = false;
	cap->buf[0] = '\0';
	slog_setoutput(SLOG_OUTPUT_WRITER, log_capture_write, cap);
	slog_setlevel(LOG_LEVEL_NOTICE);
	const bool ok =
		gencerts(names, server_name, NULL, "ed25519", 0, identities);
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
	return ok;
}

/* An invocation gencerts would refuse must be refused before any key is
 * generated or any file written, not after generating keys only to roll the
 * files back: with the default RSA-4096 that is seconds per wasted key.
 * generate_key() logs "keytype=" for every key it starts, and write_keypair()
 * logs "write" for every pair it lands, so neither may appear. */
T_DECLARE_CASE(test_gencerts_validates_before_generating)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	static const struct {
		const char *names;
		const char *server_name;
		const char *identities;
	} cases[] = {
		/* one identity too many, noticed only after the last name */
		{ "a,b,c", "id.example", "x,y,z,EXTRA" },
		/* the server name is shared by every certificate */
		{ "a,b,c", "bad_name", NULL },
		/* a bad identity paired with the last name only */
		{ "a,b,c", "id.example", "x,y,\x01" },
	};
	struct log_capture cap;
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		const bool ok = gencerts_captured(
			&cap, cases[i].names, cases[i].server_name,
			cases[i].identities);
		T_EXPECT(!ok);
		T_EXPECT(!cap.overflow);
		const bool generated = strstr(cap.buf, "keytype=") != NULL;
		const bool written = strstr(cap.buf, "write ") != NULL;
		if (generated || written) {
			T_LOGF("case %zu generated before refusing: %s", i,
			       cap.buf);
		}
		T_EXPECT(!generated);
		T_EXPECT(!written);
		T_EXPECT(access("a-cert.pem", F_OK) != 0);
		T_EXPECT(access("a-key.pem", F_OK) != 0);
	}

	leave_tmpdir(origdir, tmpl);
}

/* A pair write_keypair() announced as written and a later name's failure then
 * took back must be reported as removed, after the notice that claimed it:
 * otherwise the log asserts files exist that do not. */
T_DECLARE_CASE(test_gencerts_mid_list_failure_logs_removal)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	FILE *const stale = fopen("second-key.pem", "w");
	T_CHECK(stale != NULL);
	if (stale != NULL) {
		(void)fclose(stale);
	}
	struct log_capture cap;
	const bool ok =
		gencerts_captured(&cap, "first,second", "id.example", NULL);
	const bool left_cert = access("first-cert.pem", F_OK) == 0;
	const bool left_key = access("first-key.pem", F_OK) == 0;

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(!ok);
	T_EXPECT(!cap.overflow);
	T_EXPECT(!left_cert);
	T_EXPECT(!left_key);
	const char *const written =
		strstr(cap.buf, "write first-cert.pem, first-key.pem");
	T_EXPECT(written != NULL);
	if (written != NULL) {
		const bool removed_cert =
			strstr(written, "remove first-cert.pem") != NULL;
		const bool removed_key =
			strstr(written, "remove first-key.pem") != NULL;
		if (!removed_cert || !removed_key) {
			T_LOGF("rollback not logged: %s", cap.buf);
		}
		T_EXPECT(removed_cert);
		T_EXPECT(removed_key);
	}
}

/* A claimed identity is at most 255 octets on the wire (doc/spec.md 5.2.3.2),
 * so a longer one can never verify and is refused; exactly 255 is claimable
 * and accepted, and lands in the certificate whole. */
T_DECLARE_CASE(test_gencerts_identity_wire_limit)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* The expected URI name, whose tail is the identity itself: room for
	 * 256 identity octets after the scheme. */
	char uri[sizeof("multiplexd:") + 256] = "multiplexd:";
	char *const identity = uri + sizeof("multiplexd:") - 1;
	struct log_capture cap;

	memset(identity, 'a', 256);
	identity[256] = '\0';
	T_EXPECT(!gencerts_captured(&cap, "over", "id.example", identity));
	T_EXPECT(access("over-cert.pem", F_OK) != 0);
	T_EXPECT(access("over-key.pem", F_OK) != 0);

	identity[255] = '\0';
	const bool ok = gencerts_captured(&cap, "wire", "id.example", identity);
	T_EXPECT(ok);
	X509 *const cert = ok ? read_cert_file("wire-cert.pem") : NULL;
	T_EXPECT(cert != NULL);
	if (cert != NULL) {
		int n = 0;
		T_EXPECT(cert_has_uri_san(cert, uri, &n));
		T_EXPECT_EQ(n, 1);
	}
	X509_free(cert);

	leave_tmpdir(origdir, tmpl);
}

/* Past the 63 octets multiplexd itself claims, an identity is still written
 * -- another implementation may claim it -- but with a warning; at 63 there
 * is none. */
T_DECLARE_CASE(test_gencerts_identity_past_claim_limit_warns)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	char identity[65];
	memset(identity, 'a', sizeof(identity) - 1);
	identity[64] = '\0';
	struct log_capture cap;

	T_EXPECT(gencerts_captured(&cap, "long", "id.example", identity));
	T_EXPECT(access("long-cert.pem", F_OK) == 0);
	T_EXPECT(strstr(cap.buf, "multiplexd claims at most 63") != NULL);

	identity[63] = '\0';
	T_EXPECT(gencerts_captured(&cap, "claim", "id.example", identity));
	T_EXPECT(access("claim-cert.pem", F_OK) == 0);
	T_EXPECT(strstr(cap.buf, "claims at most") == NULL);

	leave_tmpdir(origdir, tmpl);
}

/* identity.verify decodes the URI name with url_unescape_path(), which refuses
 * any decoded control character, so a certificate naming one could never
 * match any claim.  It is refused up front, and the identity is not echoed
 * into the log, where the raw control byte would land. */
T_DECLARE_CASE(test_gencerts_identity_control_byte_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	static const char *const identities[] = {
		"a\tb",
		"a\nb",
		"\x1b[31m",
		"del\x7f",
	};
	struct log_capture cap;
	for (size_t i = 0; i < ARRAY_SIZE(identities); i++) {
		T_EXPECT(!gencerts_captured(
			&cap, "ctl", "id.example", identities[i]));
		T_EXPECT(access("ctl-cert.pem", F_OK) != 0);
		T_EXPECT(access("ctl-key.pem", F_OK) != 0);
		T_EXPECT(strstr(cap.buf, identities[i]) == NULL);
	}

	leave_tmpdir(origdir, tmpl);
}

/* A generated cert must be a usable, correct certificate, not merely a file
 * that exists: verify the leaf's CN and DNS SAN, that its issuer is the CA's
 * subject, and that its signature verifies against the CA's public key. */
T_DECLARE_CASE(test_gencerts_produces_verifiable_cert)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	bool ok = gencerts("ca", "ca.example", NULL, "ed25519", 0, NULL);
	T_CHECK(ok);
	ok = gencerts("server", "server.example", "ca", "ed25519", 0, NULL);
	T_CHECK(ok);

	X509 *const ca = read_cert_file("ca-cert.pem");
	X509 *const server = read_cert_file("server-cert.pem");

	/* Capture every result before freeing/teardown so a failing assertion
	 * cannot leak the X509 objects (they are heap copies, unaffected by
	 * leave_tmpdir removing the files). */
	const bool ca_ok = ca != NULL;
	const bool server_ok = server != NULL;
	bool cn_ok = false, san_ok = false, issuer_ok = false;
	int verify_rc = -1;
	if (ca_ok && server_ok) {
		cn_ok = cert_cn_equals(server, "server.example");
		san_ok = cert_has_dns_san(server, "server.example");
		issuer_ok = X509_NAME_cmp(
				    X509_get_issuer_name(server),
				    X509_get_subject_name(ca)) == 0;
		EVP_PKEY *const ca_pubkey = X509_get_pubkey(ca);
		verify_rc =
			ca_pubkey != NULL ? X509_verify(server, ca_pubkey) : -1;
		EVP_PKEY_free(ca_pubkey);
	}
	X509_free(server);
	X509_free(ca);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ca_ok);
	T_EXPECT(server_ok);
	T_EXPECT(cn_ok);
	T_EXPECT(san_ok);
	T_EXPECT(issuer_ok);
	T_EXPECT_EQ(verify_rc, 1);
}

/* A server name of 65-255 octets is a legal FQDN and inside this tool's own
 * documented bound, but the subject CN is built with MBSTRING_ASC, so OpenSSL
 * enforces ub_common_name (64) on it: such a name used to fail in set_subject_cn
 * with a raw error-queue dump, before the SAN builder's length gate could give
 * the intended diagnostic. The name must now generate, with the full value in
 * the subjectAltName -- which is what verifiers actually match on. */
T_DECLARE_CASE(test_gencerts_long_server_name_lands_in_san)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* 100 octets: past ub_common_name, well inside the 255 bound. */
	char sni[101];
	memset(sni, 'a', sizeof(sni) - 1);
	sni[sizeof(sni) - 1] = '\0';
	memcpy(sni, "long.", 5);

	const bool ok = gencerts("longcn", sni, NULL, "ed25519", 0, NULL);
	X509 *const cert = ok ? read_cert_file("longcn-cert.pem") : NULL;
	const bool cert_ok = cert != NULL;
	bool san_ok = false, cn_within_bound = false;
	if (cert_ok) {
		/* The full name is reachable where it matters. */
		san_ok = cert_has_dns_san(cert, sni);
		/* The subject stays non-empty and within OpenSSL's CN bound. */
		char cn[256] = { 0 };
		const int cn_len = name_get_cn(
			X509_get_subject_name(cert), cn, sizeof(cn));
		cn_within_bound = cn_len > 0 && cn_len <= 64 &&
				  strncmp(cn, sni, (size_t)cn_len) == 0;
	}
	X509_free(cert);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(cert_ok);
	T_EXPECT(san_ok);
	T_EXPECT(cn_within_bound);
}

/* write_keypair appends the signing CA to a --sign'ed leaf's cert file so the
 * file is a complete chain -- what a TLS peer needs to present the intermediate.
 * test_gencerts_with_signing_cert only access()-checks the files exist and
 * test_gencerts_produces_verifiable_cert reads a single certificate, so
 * deleting the append block passed the whole suite. Read the leaf's PEM back
 * and require two certificates, the second being the CA. */
T_DECLARE_CASE(test_gencerts_signed_cert_file_contains_chain)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	bool ok = gencerts("ca", "ca.example", NULL, "ed25519", 0, NULL);
	T_CHECK(ok);
	ok = gencerts("server", "server.example", "ca", "ed25519", 0, NULL);
	T_CHECK(ok);

	X509 *const ca = read_cert_file("ca-cert.pem");
	/* Read every certificate in the leaf's file, in order. */
	X509 *chain[4] = { NULL, NULL, NULL, NULL };
	size_t chain_len = 0;
	FILE *const fp = fopen("server-cert.pem", "re");
	if (fp != NULL) {
		while (chain_len < ARRAY_SIZE(chain)) {
			X509 *const c = PEM_read_X509(fp, NULL, NULL, NULL);
			if (c == NULL) {
				break;
			}
			chain[chain_len++] = c;
		}
		(void)fclose(fp);
	}

	const bool ca_ok = ca != NULL;
	bool leaf_is_server = false, appended_is_ca = false;
	if (ca_ok && chain_len == 2) {
		leaf_is_server = cert_cn_equals(chain[0], "server.example");
		appended_is_ca = X509_cmp(chain[1], ca) == 0;
	}
	for (size_t i = 0; i < chain_len; i++) {
		X509_free(chain[i]);
	}
	X509_free(ca);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ca_ok);
	/* Leaf plus the appended signing CA, and nothing else. */
	T_EXPECT_EQ(chain_len, (size_t)2);
	T_EXPECT(leaf_is_server);
	T_EXPECT(appended_is_ca);
}

/* reject_password_cb exists so a password-protected signing key fails cleanly
 * instead of blocking on OpenSSL's interactive prompt in a scripted run. No
 * case supplied an encrypted key, so passing NULL for the callback again --
 * which makes OpenSSL read the passphrase from the controlling TTY -- would
 * reintroduce a hang in provisioning with nothing to catch it. Write a real
 * encrypted signing key and require gencerts to fail rather than prompt. */
T_DECLARE_CASE(test_gencerts_encrypted_signing_key_fails_cleanly)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	bool ok = gencerts("ca", "ca.example", NULL, "ed25519", 0, NULL);
	T_CHECK(ok);

	/* Re-write ca-key.pem encrypted, leaving ca-cert.pem as generated. */
	EVP_PKEY *key = NULL;
	FILE *fp = fopen("ca-key.pem", "re");
	if (fp != NULL) {
		key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		(void)fclose(fp);
	}
	T_CHECK(key != NULL);
	bool rewrote = false;
	fp = fopen("ca-key.pem", "we");
	if (fp != NULL) {
		static const char passphrase[] = "test-passphrase";
		rewrote =
			PEM_write_PrivateKey(
				fp, key, EVP_aes_256_cbc(),
				(const unsigned char *)passphrase,
				(int)(sizeof(passphrase) - 1), NULL, NULL) == 1;
		(void)fclose(fp);
	}
	EVP_PKEY_free(key);
	T_CHECK(rewrote);

	/* Must return false without ever reading from the terminal. stdin is
	 * the test runner's, so a regression that prompts would block here
	 * rather than fail -- the ctest timeout is the backstop. */
	const bool signed_ok =
		gencerts("srv", "srv.example", "ca", "ed25519", 0, NULL);
	const int cert_exists = access("srv-cert.pem", F_OK);
	const int key_exists = access("srv-key.pem", F_OK);

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(!signed_ok);
	/* A failed run leaves no half-written output behind. */
	T_EXPECT_EQ(cert_exists, -1);
	T_EXPECT_EQ(key_exists, -1);
}

/* A generated CA certificate must carry keyUsage with keyCertSign, critical,
 * per RFC 5280 4.2.1.3 -- without it a strict verifier rejects every chain
 * beneath it. digitalSignature must be asserted too: the same self-signed
 * certificate is handed to tls.cert as the peer's own end-entity certificate,
 * and TLS 1.3 signs the handshake with that key, so a keyCertSign-only
 * keyUsage would break every certificate this tool generates. Presence is
 * checked via the extension itself because X509_get_key_usage() reports all
 * bits set when keyUsage is absent. */
T_DECLARE_CASE(test_gencerts_ca_key_usage)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("kuca", "ku.example", NULL, "ed25519", 0, NULL);
	X509 *const cert = ok ? read_cert_file("kuca-cert.pem") : NULL;

	/* Capture before teardown so a failing assertion cannot leak the X509. */
	const bool cert_ok = cert != NULL;
	bool ku_present = false, ku_critical = false;
	uint32_t ku = 0;
	if (cert_ok) {
		int crit = -1;
		ASN1_BIT_STRING *const ku_ext =
			X509_get_ext_d2i(cert, NID_key_usage, &crit, NULL);
		ku_present = ku_ext != NULL;
		ku_critical = crit > 0;
		ASN1_BIT_STRING_free(ku_ext);
		if (ku_present) {
			ku = X509_get_key_usage(cert);
		}
	}
	X509_free(cert);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(cert_ok);
	T_EXPECT(ku_present);
	T_EXPECT(ku_critical);
	T_EXPECT((ku & KU_KEY_CERT_SIGN) != 0);
	T_EXPECT((ku & KU_CRL_SIGN) != 0);
	T_EXPECT((ku & KU_DIGITAL_SIGNATURE) != 0);
}

/* keytype == NULL is the documented "use the default" form (gencerts.h), so
 * main() can pass an omitted --keytype straight through: generate_key() must
 * take its "rsa" branch rather than reach strcmp(NULL). Asserts the key the
 * cert actually carries is RSA, not merely that a file appeared; 2048-bit to
 * keep the test fast. */
T_DECLARE_CASE(test_gencerts_default_keytype)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("rsadef", "rsa.example", NULL, NULL, 2048, NULL);
	X509 *const cert = ok ? read_cert_file("rsadef-cert.pem") : NULL;

	/* Capture before teardown so a failing assertion cannot leak the X509. */
	const bool cert_ok = cert != NULL;
	int key_type = EVP_PKEY_NONE;
	if (cert_ok) {
		EVP_PKEY *const pubkey = X509_get_pubkey(cert);
		if (pubkey != NULL) {
			key_type = EVP_PKEY_get_base_id(pubkey);
			EVP_PKEY_free(pubkey);
		}
	}
	X509_free(cert);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(cert_ok);
	T_EXPECT_EQ(key_type, EVP_PKEY_RSA);
}

/* set_random_serial() must yield an RFC 5280 4.1.2.2 positive (nonzero)
 * serial. BN_RAND_TOP_ONE forces the most-significant of the 128 bits, so every
 * serial is in [2^127, 2^128): positive, with a bit length of exactly 128. The
 * pre-fix BN_RAND_TOP_ANY left that bit random, so a serial could (with
 * negligible probability) be zero and, across many certificates, ~half fell
 * below 128 bits. Generating a batch of ed25519 certificates (cheap keygen)
 * turns that into a deterministic distinction: a run of samples all being
 * exactly 128 bits is effectively impossible without the fix (~2^-N). */
T_DECLARE_CASE(test_gencerts_serial_is_positive_and_128_bit)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	enum { SERIAL_SAMPLES = 32 };
	bool gen_ok = true;
	bool all_positive = true;
	bool all_128_bit = true;
	int worst_bits = -1;
	for (int i = 0; i < SERIAL_SAMPLES; i++) {
		char name[32];
		(void)snprintf(name, sizeof(name), "serial%d", i);
		if (!gencerts(
			    name, "serial.example", NULL, "ed25519", 0, NULL)) {
			gen_ok = false;
			break;
		}
		char path[48];
		(void)snprintf(path, sizeof(path), "%s-cert.pem", name);
		X509 *const cert = read_cert_file(path);
		if (cert == NULL) {
			gen_ok = false;
			break;
		}
		BIGNUM *const bn =
			ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert), NULL);
		X509_free(cert);
		if (bn == NULL) {
			gen_ok = false;
			break;
		}
		if (BN_is_zero(bn) || BN_is_negative(bn)) {
			all_positive = false;
		}
		const int bits = BN_num_bits(bn);
		if (bits != 128) {
			all_128_bit = false;
			worst_bits = bits;
		}
		BN_free(bn);
	}

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(gen_ok);
	/* The RFC 5280 contract: a positive, nonzero serial. */
	T_EXPECT(all_positive);
	/* The deterministic consequence of the fix that fails against pre-fix
	 * code (BN_RAND_TOP_ANY left ~half the samples below 128 bits). */
	if (!all_128_bit) {
		T_LOGF("a serial had %d bits, expected 128 (top bit not forced)",
		       worst_bits);
	}
	T_EXPECT(all_128_bit);
}

/* Criticality of the @p nid extension on @p cert: 1 critical, 0 non-critical,
 * -1 absent. */
static int ext_criticality(const X509 *restrict cert, const int nid)
{
	const int idx = X509_get_ext_by_NID(cert, nid, -1);
	if (idx < 0) {
		return -1;
	}
	return X509_EXTENSION_get_critical(X509_get_ext(cert, idx));
}

/* Verify @p target against a store trusting only @p anchor, the way a strict
 * TLS peer would: X509_V_FLAG_X509_STRICT and the SSL @p purpose. Returns the
 * X509_V_* result, X509_V_OK on success, or -1 when the check could not run. */
static int verify_strict(X509 *anchor, X509 *target, const int purpose)
{
	X509_STORE *const store = X509_STORE_new();
	X509_STORE_CTX *const ctx = X509_STORE_CTX_new();
	int result = -1;
	if (store != NULL && ctx != NULL &&
	    X509_STORE_add_cert(store, anchor) == 1 &&
	    X509_STORE_CTX_init(ctx, store, target, NULL) == 1 &&
	    X509_STORE_CTX_set_purpose(ctx, purpose) == 1) {
		X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_X509_STRICT);
		(void)X509_verify_cert(ctx);
		result = X509_STORE_CTX_get_error(ctx);
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return result;
}

/* RFC 5280 4.1.2.6: the DN MUST be unique for each subject entity one CA
 * certifies. Every certificate from one run shares the server name, so a
 * CN-only subject gave the leaves of one --sign run a single DN between them,
 * and made each equal to its issuer's -- a self-issued certificate in every
 * verifier's eyes, chained only because the AKI keyid broke the tie. */
T_DECLARE_CASE(test_gencerts_signed_leaves_have_unique_subjects)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ca_ok =
		gencerts("ca", "dn.example", NULL, "ed25519", 0, NULL);
	const bool leaves_ok =
		ca_ok &&
		gencerts("c1,c2", "dn.example", "ca", "ed25519", 0, NULL);
	X509 *const ca = leaves_ok ? read_cert_file("ca-cert.pem") : NULL;
	X509 *const c1 = leaves_ok ? read_cert_file("c1-cert.pem") : NULL;
	X509 *const c2 = leaves_ok ? read_cert_file("c2-cert.pem") : NULL;

	/* Capture before teardown so a failing assertion cannot leak the X509. */
	const bool read_ok = ca != NULL && c1 != NULL && c2 != NULL;
	bool leaves_differ = false, c1_not_ca = false, c2_not_ca = false;
	bool c1_issued_by_ca = false, c1_not_self_issued = false;
	bool c2_not_self_issued = false, cn_kept = false;
	if (read_ok) {
		const X509_NAME *const ca_dn = X509_get_subject_name(ca);
		const X509_NAME *const c1_dn = X509_get_subject_name(c1);
		const X509_NAME *const c2_dn = X509_get_subject_name(c2);
		leaves_differ = X509_NAME_cmp(c1_dn, c2_dn) != 0;
		c1_not_ca = X509_NAME_cmp(c1_dn, ca_dn) != 0;
		c2_not_ca = X509_NAME_cmp(c2_dn, ca_dn) != 0;
		c1_issued_by_ca =
			X509_NAME_cmp(X509_get_issuer_name(c1), ca_dn) == 0;
		c1_not_self_issued =
			(X509_get_extension_flags(c1) & EXFLAG_SI) == 0;
		c2_not_self_issued =
			(X509_get_extension_flags(c2) & EXFLAG_SI) == 0;
		/* Disambiguating the DN must not displace the server name. */
		cn_kept = cert_cn_equals(c1, "dn.example") &&
			  cert_cn_equals(ca, "dn.example");
	}
	X509_free(c2);
	X509_free(c1);
	X509_free(ca);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ca_ok);
	T_EXPECT(leaves_ok);
	T_EXPECT(read_ok);
	T_EXPECT(leaves_differ);
	T_EXPECT(c1_not_ca);
	T_EXPECT(c2_not_ca);
	T_EXPECT(c1_issued_by_ca);
	T_EXPECT(c1_not_self_issued);
	T_EXPECT(c2_not_self_issued);
	T_EXPECT(cn_kept);
}

/* A leaf is not a CA: a chain under it is rejected by every verifier, so
 * --sign with one must fail locally, before writing anything, rather than
 * report "ok" and leave the failure to a remote handshake. */
T_DECLARE_CASE(test_gencerts_non_ca_signer_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	T_CHECK(gencerts("ca", "ca.example", NULL, "ed25519", 0, NULL));
	T_CHECK(gencerts("leaf", "leaf.example", "ca", "ed25519", 0, NULL));

	const bool ok =
		gencerts("a,b", "a.example", "leaf", "ed25519", 0, NULL);
	const int a_cert = access("a-cert.pem", F_OK);
	const int a_key = access("a-key.pem", F_OK);
	const int b_cert = access("b-cert.pem", F_OK);
	const int b_key = access("b-key.pem", F_OK);

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(!ok);
	T_EXPECT_EQ(a_cert, -1);
	T_EXPECT_EQ(a_key, -1);
	T_EXPECT_EQ(b_cert, -1);
	T_EXPECT_EQ(b_key, -1);
}

/* A --sign'ed leaf must verify under its CA the way a strict TLS peer checks
 * it -- X509_V_FLAG_X509_STRICT, for both the server and the client role --
 * not merely carry a signature X509_verify() accepts. This is the only
 * end-to-end check of the --sign chain: smoke_test.py uses unsigned
 * certificates only. */
T_DECLARE_CASE(test_gencerts_signed_chain_verifies_strict)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("ca", "chain.example", NULL, "ecdsa", 256, NULL) &&
		gencerts("peer", "chain.example", "ca", "ecdsa", 256, NULL);
	X509 *const ca = ok ? read_cert_file("ca-cert.pem") : NULL;
	X509 *const peer = ok ? read_cert_file("peer-cert.pem") : NULL;

	const bool read_ok = ca != NULL && peer != NULL;
	int server_rc = -1, client_rc = -1;
	if (read_ok) {
		server_rc = verify_strict(ca, peer, X509_PURPOSE_SSL_SERVER);
		client_rc = verify_strict(ca, peer, X509_PURPOSE_SSL_CLIENT);
	}
	X509_free(peer);
	X509_free(ca);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(read_ok);
	if (server_rc != X509_V_OK || client_rc != X509_V_OK) {
		T_LOGF("strict verify: server %d (%s), client %d (%s)",
		       server_rc, X509_verify_cert_error_string(server_rc),
		       client_rc, X509_verify_cert_error_string(client_rc));
	}
	T_EXPECT_EQ(server_rc, X509_V_OK);
	T_EXPECT_EQ(client_rc, X509_V_OK);
}

/* An unsigned certificate is handed to tls.authcerts as its own trust anchor
 * and to tls.cert as the end-entity certificate, so it must verify against a
 * store holding only itself under the same strict rules, in both roles. */
T_DECLARE_CASE(test_gencerts_self_signed_verifies_as_anchor)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("solo", "solo.example", NULL, "ecdsa", 256, NULL);
	X509 *const solo = ok ? read_cert_file("solo-cert.pem") : NULL;

	const bool read_ok = solo != NULL;
	bool self_signed = false;
	int server_rc = -1, client_rc = -1;
	if (read_ok) {
		self_signed = (X509_get_extension_flags(solo) & EXFLAG_SS) != 0;
		server_rc = verify_strict(solo, solo, X509_PURPOSE_SSL_SERVER);
		client_rc = verify_strict(solo, solo, X509_PURPOSE_SSL_CLIENT);
	}
	X509_free(solo);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(read_ok);
	T_EXPECT(self_signed);
	if (server_rc != X509_V_OK || client_rc != X509_V_OK) {
		T_LOGF("strict verify: server %d (%s), client %d (%s)",
		       server_rc, X509_verify_cert_error_string(server_rc),
		       client_rc, X509_verify_cert_error_string(client_rc));
	}
	T_EXPECT_EQ(server_rc, X509_V_OK);
	T_EXPECT_EQ(client_rc, X509_V_OK);
}

/* The X.509 content of a CA and a --sign'ed leaf, extension by extension with
 * its criticality: basicConstraints (critical CA:TRUE on the CA, no CA flag on
 * the leaf), extendedKeyUsage, the key identifiers -- the leaf's AKI keyid
 * naming the CA's SKI -- and the subjectAltName; v3, and the backdated
 * ten-year validity window. */
T_DECLARE_CASE(test_gencerts_ca_and_leaf_extensions)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("ca", "ext.example", NULL, "ed25519", 0, NULL) &&
		gencerts("leaf", "ext.example", "ca", "ed25519", 0, NULL);
	X509 *const ca = ok ? read_cert_file("ca-cert.pem") : NULL;
	X509 *const leaf = ok ? read_cert_file("leaf-cert.pem") : NULL;

	const bool read_ok = ca != NULL && leaf != NULL;
	const uint32_t tls_xku = XKU_SSL_SERVER | XKU_SSL_CLIENT;
	long ca_version = -1, leaf_version = -1;
	int ca_bc = -2, ca_ku = -2, ca_eku = -2, ca_ski = -2, ca_san = -2;
	int leaf_eku = -2, leaf_aki = -2, leaf_ski = -2, leaf_san = -2;
	bool ca_flag = false, leaf_ca_flag = true;
	bool ca_xku = false, leaf_xku = false;
	bool aki_names_ca = false;
	int days = -1, secs = -1;
	if (read_ok) {
		ca_version = X509_get_version(ca);
		leaf_version = X509_get_version(leaf);
		ca_bc = ext_criticality(ca, NID_basic_constraints);
		ca_ku = ext_criticality(ca, NID_key_usage);
		ca_eku = ext_criticality(ca, NID_ext_key_usage);
		ca_ski = ext_criticality(ca, NID_subject_key_identifier);
		ca_san = ext_criticality(ca, NID_subject_alt_name);
		leaf_eku = ext_criticality(leaf, NID_ext_key_usage);
		leaf_aki = ext_criticality(leaf, NID_authority_key_identifier);
		leaf_ski = ext_criticality(leaf, NID_subject_key_identifier);
		leaf_san = ext_criticality(leaf, NID_subject_alt_name);
		ca_flag = (X509_get_extension_flags(ca) & EXFLAG_CA) != 0;
		leaf_ca_flag =
			(X509_get_extension_flags(leaf) & EXFLAG_CA) != 0;
		ca_xku = (X509_get_extended_key_usage(ca) & tls_xku) == tls_xku;
		leaf_xku = (X509_get_extended_key_usage(leaf) & tls_xku) ==
			   tls_xku;
		const ASN1_OCTET_STRING *const aki =
			X509_get0_authority_key_id(leaf);
		const ASN1_OCTET_STRING *const ski =
			X509_get0_subject_key_id(ca);
		aki_names_ca = aki != NULL && ski != NULL &&
			       ASN1_OCTET_STRING_cmp(aki, ski) == 0;
		if (ASN1_TIME_diff(
			    &days, &secs, X509_get0_notBefore(leaf),
			    X509_get0_notAfter(leaf)) != 1) {
			days = secs = -1;
		}
	}
	X509_free(leaf);
	X509_free(ca);
	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(read_ok);
	T_EXPECT_EQ(ca_version, (long)X509_VERSION_3);
	T_EXPECT_EQ(leaf_version, (long)X509_VERSION_3);
	/* CA: critical CA:TRUE and keyUsage; the rest non-critical. */
	T_EXPECT_EQ(ca_bc, 1);
	T_EXPECT(ca_flag);
	T_EXPECT_EQ(ca_ku, 1);
	T_EXPECT_EQ(ca_eku, 0);
	T_EXPECT(ca_xku);
	T_EXPECT_EQ(ca_ski, 0);
	T_EXPECT_EQ(ca_san, 0);
	/* Leaf: an end entity, identifying its issuer by key. */
	T_EXPECT(!leaf_ca_flag);
	T_EXPECT_EQ(leaf_eku, 0);
	T_EXPECT(leaf_xku);
	T_EXPECT_EQ(leaf_aki, 0);
	T_EXPECT(aki_names_ca);
	T_EXPECT_EQ(leaf_ski, 0);
	T_EXPECT_EQ(leaf_san, 0);
	/* notBefore backdated an hour, notAfter 3652 days on; the two are
	 * stamped from separate clock reads, so allow a second of drift. */
	T_EXPECT_EQ(days, 3652);
	T_EXPECT(secs >= 3600 && secs <= 3601);
}

static const struct testing_suite suite[] = {
	T_CASE(test_gencerts_ed25519),
	T_CASE(test_gencerts_ecdsa),
	T_CASE(test_gencerts_rsa),
	T_CASE(test_gencerts_invalid_keytype),
	T_CASE(test_gencerts_invalid_ecdsa_keysize),
	T_CASE(test_gencerts_ed25519_rejects_keysize),
	T_CASE(test_gencerts_missing_signing_cert_fails),
	T_CASE(test_gencerts_refuses_overwrite_existing_files),
	T_CASE(test_gencerts_multiple_names),
	T_CASE(test_gencerts_skips_all_space_name_token),
	T_CASE(test_gencerts_empty_name_list_fails),
	T_CASE(test_gencerts_with_signing_cert),
	T_CASE(test_gencerts_ecdsa_p224_rejected),
	T_CASE(test_gencerts_ecdsa_p384),
	T_CASE(test_gencerts_ecdsa_p521),
	T_CASE(test_gencerts_key_write_failure_removes_cert),
	T_CASE(test_gencerts_sni_too_long_rejected),
	T_CASE(test_gencerts_sni_san_injection_rejected),
	T_CASE(test_gencerts_rsa_keysize_too_large_rejected),
	T_CASE(test_gencerts_rsa_keysize_too_small_rejected),
	T_CASE(test_gencerts_ecdsa_default_keysize),
	T_CASE(test_gencerts_default_keytype),
	T_CASE(test_gencerts_signing_cert_key_mismatch_fails),
	T_CASE(test_gencerts_file_permissions),
	T_CASE(test_gencerts_produces_verifiable_cert),
	T_CASE(test_gencerts_long_server_name_lands_in_san),
	T_CASE(test_gencerts_signed_cert_file_contains_chain),
	T_CASE(test_gencerts_encrypted_signing_key_fails_cleanly),
	T_CASE(test_gencerts_identity_absent_omits_san),
	T_CASE(test_gencerts_identity_explicit_list),
	T_CASE(test_gencerts_identity_percent_encoded),
	T_CASE(test_gencerts_identity_count_mismatch),
	T_CASE(test_gencerts_validates_before_generating),
	T_CASE(test_gencerts_mid_list_failure_logs_removal),
	T_CASE(test_gencerts_identity_wire_limit),
	T_CASE(test_gencerts_identity_past_claim_limit_warns),
	T_CASE(test_gencerts_identity_control_byte_rejected),
	T_CASE(test_gencerts_ca_key_usage),
	T_CASE(test_gencerts_serial_is_positive_and_128_bit),
	T_CASE(test_gencerts_signed_leaves_have_unique_subjects),
	T_CASE(test_gencerts_non_ca_signer_rejected),
	T_CASE(test_gencerts_signed_chain_verifies_strict),
	T_CASE(test_gencerts_self_signed_verifies_as_anchor),
	T_CASE(test_gencerts_ca_and_leaf_extensions),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}

#else /* !WITH_OPENSSL */

#include <stdlib.h>

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_OPENSSL */
