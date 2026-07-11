/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* gencerts_test.c - black-box tests for certificate/key generation in
 * gencerts.c via its public API. Dependencies: links the real gencerts.c + TLS
 * backend (no-op when TLS disabled). */

#include "gencerts.h"

#if WITH_OPENSSL

#include "utils/slog.h"
#include "utils/testing.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
		LOGW_F("chdir: (%d) %s", errno, strerror(errno));
	}
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_gencerts_ed25519)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("testcert", "test.example", NULL, "ed25519", 0);
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

	const bool ok = gencerts("ec256", "ec.example", NULL, "ecdsa", 256);
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
	const bool ok = gencerts("rsa2048", "rsa.example", NULL, "rsa", 2048);
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

	const bool ok = gencerts("x", "test", NULL, "nosuchthing", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_invalid_ecdsa_keysize)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts("ecbad", "ec.example", NULL, "ecdsa", 255);
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
	const bool ok = gencerts("edbad", "ed.example", NULL, "ed25519", 256);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_missing_signing_cert_fails)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("server", "server.example", "missing", "ed25519", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_refuses_overwrite_existing_files)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	bool ok = gencerts("dup", "dup.example", NULL, "ed25519", 0);
	T_CHECK(ok);
	ok = gencerts("dup", "dup.example", NULL, "ed25519", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_multiple_names)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok =
		gencerts("alpha, beta", "multi.example", NULL, "ed25519", 0);
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

	const bool ok =
		gencerts("alpha, ,beta", "multi.example", NULL, "ed25519", 0);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("alpha-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("alpha-key.pem", F_OK), 0);
		T_EXPECT_EQ(access("beta-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("beta-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_with_signing_cert)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	bool ok = gencerts("ca", "ca.example", NULL, "ed25519", 0);
	T_CHECK(ok);

	ok = gencerts("server", "server.example", "ca", "ed25519", 0);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("server-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("server-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p224)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts("p224", "p224.example", NULL, "ecdsa", 224);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("p224-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("p224-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p384)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts("p384", "p384.example", NULL, "ecdsa", 384);
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

	const bool ok = gencerts("p521", "p521.example", NULL, "ecdsa", 521);
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

	const bool ok =
		gencerts("rollback", "rollback.example", NULL, "ed25519", 0);
	T_EXPECT(!ok);
	T_EXPECT(access("rollback-cert.pem", F_OK) != 0);

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

	const bool ok = gencerts("toolong", long_sni, NULL, "ed25519", 0);
	free(long_sni);
	T_EXPECT(!ok);
	T_EXPECT(access("toolong-cert.pem", F_OK) != 0);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_rsa_keysize_too_large_rejected)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts("hugersa", "rsa.example", NULL, "rsa", 999999);
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

	const bool ok = gencerts("smallrsa", "rsa.example", NULL, "rsa", 1024);
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

	const bool ok = gencerts("ecdef", "ec.example", NULL, "ecdsa", 0);
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

	T_CHECK(gencerts("ca1", "ca1.example", NULL, "ed25519", 0));
	T_CHECK(gencerts("ca2", "ca2.example", NULL, "ed25519", 0));
	/* Replace ca1's key with ca2's so ca1-cert.pem and ca1-key.pem no longer
	 * match. */
	T_CHECK(rename("ca2-key.pem", "ca1-key.pem") == 0);

	const bool ok = gencerts("srv", "srv.example", "ca1", "ed25519", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
}

T_DECLARE_CASE(test_gencerts_file_permissions)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = gencerts("perms", "perms.example", NULL, "ed25519", 0);
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
	T_CASE(test_gencerts_with_signing_cert),
	T_CASE(test_gencerts_ecdsa_p224),
	T_CASE(test_gencerts_ecdsa_p384),
	T_CASE(test_gencerts_ecdsa_p521),
	T_CASE(test_gencerts_key_write_failure_removes_cert),
	T_CASE(test_gencerts_sni_too_long_rejected),
	T_CASE(test_gencerts_rsa_keysize_too_large_rejected),
	T_CASE(test_gencerts_rsa_keysize_too_small_rejected),
	T_CASE(test_gencerts_ecdsa_default_keysize),
	T_CASE(test_gencerts_signing_cert_key_mismatch_fails),
	T_CASE(test_gencerts_file_permissions),
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
