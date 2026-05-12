/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "gencerts.h"

#include "utils/testing.h"

#include <stdlib.h>

#if WITH_TLS

#include "utils/slog.h"

#include <errno.h>
#include <ftw.h>
#include <string.h>
#include <unistd.h>

/* Remove a file tree; used for temp-directory cleanup. */
static int rm_entry(
	const char *path, const struct stat *sb, int typeflag,
	struct FTW *ftwbuf)
{
	(void)sb;
	(void)ftwbuf;
	if (typeflag == FTW_F || typeflag == FTW_SL) {
		return unlink(path);
	}
	if (typeflag == FTW_DP) {
		return rmdir(path);
	}
	return 0;
}

static void rm_tmpdir(const char *path)
{
	(void)nftw(path, rm_entry, 8, FTW_DEPTH | FTW_PHYS);
}

/* Enter a fresh temp dir, returning the original dir (must be freed) and
 * filling tmpl with the created path. */
static char *enter_tmpdir(char *restrict tmpl)
{
	char *origdir = getcwd(NULL, 0);
	if (origdir == NULL) {
		return NULL;
	}
	if (mkdtemp(tmpl) == NULL) {
		free(origdir);
		return NULL;
	}
	if (chdir(tmpl) != 0) {
		rm_tmpdir(tmpl);
		free(origdir);
		return NULL;
	}
	return origdir;
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
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok =
		gencerts("testcert", "test.example", NULL, "ed25519", 0);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("testcert-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("testcert-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_ecdsa)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("ec256", "ec.example", NULL, "ecdsa", 256);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("ec256-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("ec256-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_rsa)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	/* Use 2048-bit RSA to keep the test reasonably fast. */
	const bool ok = gencerts("rsa2048", "rsa.example", NULL, "rsa", 2048);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("rsa2048-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("rsa2048-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_invalid_keytype)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("x", "test", NULL, "nosuchthing", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_invalid_ecdsa_keysize)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("ecbad", "ec.example", NULL, "ecdsa", 255);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_missing_signing_cert_fails)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok =
		gencerts("server", "server.example", "missing", "ed25519", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_refuses_overwrite_existing_files)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	bool ok = gencerts("dup", "dup.example", NULL, "ed25519", 0);
	T_CHECK(ok);
	ok = gencerts("dup", "dup.example", NULL, "ed25519", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_multiple_names)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

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
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_with_signing_cert)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	/* Generate a self-signed CA certificate. */
	bool ok = gencerts("ca", "ca.example", NULL, "ed25519", 0);
	T_CHECK(ok);

	/* Generate a server certificate signed by the CA. */
	ok = gencerts("server", "server.example", "ca", "ed25519", 0);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("server-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("server-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p224)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("p224", "p224.example", NULL, "ecdsa", 224);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("p224-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("p224-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p384)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("p384", "p384.example", NULL, "ecdsa", 384);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("p384-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("p384-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_ecdsa_p521)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("p521", "p521.example", NULL, "ecdsa", 521);
	T_EXPECT(ok);
	if (ok) {
		T_EXPECT_EQ(access("p521-cert.pem", F_OK), 0);
		T_EXPECT_EQ(access("p521-key.pem", F_OK), 0);
	}

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_gencerts_ed25519);
	T_RUN_CASE(t, test_gencerts_ecdsa);
	T_RUN_CASE(t, test_gencerts_rsa);
	T_RUN_CASE(t, test_gencerts_invalid_keytype);
	T_RUN_CASE(t, test_gencerts_invalid_ecdsa_keysize);
	T_RUN_CASE(t, test_gencerts_missing_signing_cert_fails);
	T_RUN_CASE(t, test_gencerts_refuses_overwrite_existing_files);
	T_RUN_CASE(t, test_gencerts_multiple_names);
	T_RUN_CASE(t, test_gencerts_with_signing_cert);
	T_RUN_CASE(t, test_gencerts_ecdsa_p224);
	T_RUN_CASE(t, test_gencerts_ecdsa_p384);
	T_RUN_CASE(t, test_gencerts_ecdsa_p521);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* !WITH_TLS */

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
