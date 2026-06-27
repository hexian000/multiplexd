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

/* Enter a fresh temp dir, returning the original dir (must be freed) and
 * filling tmpl with the created path. */
static char *enter_tmpdir(char *restrict tmpl)
{
	char *const origdir = getcwd(NULL, 0);
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
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("x", "test", NULL, "nosuchthing", 0);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_invalid_ecdsa_keysize)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *const origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	const bool ok = gencerts("ecbad", "ec.example", NULL, "ecdsa", 255);
	T_EXPECT(!ok);

	leave_tmpdir(origdir, tmpl);
	free(origdir);
}

T_DECLARE_CASE(test_gencerts_missing_signing_cert_fails)
{
	char tmpl[] = "/tmp/gencerts_test_XXXXXX";
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
	T_CHECK(origdir != NULL);

	bool ok = gencerts("ca", "ca.example", NULL, "ed25519", 0);
	T_CHECK(ok);

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
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
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
	char *const origdir = enter_tmpdir(tmpl);
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

static const struct testing_suite suite[] = {
	T_CASE(test_gencerts_ed25519),
	T_CASE(test_gencerts_ecdsa),
	T_CASE(test_gencerts_rsa),
	T_CASE(test_gencerts_invalid_keytype),
	T_CASE(test_gencerts_invalid_ecdsa_keysize),
	T_CASE(test_gencerts_missing_signing_cert_fails),
	T_CASE(test_gencerts_refuses_overwrite_existing_files),
	T_CASE(test_gencerts_multiple_names),
	T_CASE(test_gencerts_with_signing_cert),
	T_CASE(test_gencerts_ecdsa_p224),
	T_CASE(test_gencerts_ecdsa_p384),
	T_CASE(test_gencerts_ecdsa_p521),
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
