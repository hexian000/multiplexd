/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "tlsutil.h"

#include "utils/testing.h"

#include <stdlib.h>

#if WITH_TLS

#include "gencerts.h"
#include "utils/slog.h"

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

/* Generate a self-signed Ed25519 cert in tmpdir; build absolute @ paths.
 * Returns origdir (must be freed) or NULL on failure. */
static char *setup_cert_dir(
	char *restrict tmpl, char *restrict cert_out, const size_t cert_sz,
	char *restrict key_out, const size_t key_sz)
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
	if (!gencerts("t", "test.example", NULL, "ed25519", 0)) {
		if (chdir(origdir) != 0) {
			LOGW_F("chdir: (%d) %s", errno, strerror(errno));
		}
		rm_tmpdir(tmpl);
		free(origdir);
		return NULL;
	}
	/* Build absolute paths using the @ prefix recognised by tls_load_cert. */
	(void)snprintf(cert_out, cert_sz, "@%s/t-cert.pem", tmpl);
	(void)snprintf(key_out, key_sz, "@%s/t-key.pem", tmpl);
	if (chdir(origdir) != 0) {
		LOGW_F("chdir: (%d) %s", errno, strerror(errno));
	}
	return origdir;
}

T_DECLARE_CASE(test_tls_ctx_server_null_cert_fails)
{
	char cert[] = "";
	char key[] = "";
	struct tls_context *ctx = tls_ctx_server(cert, key, NULL, 0, NULL);
	T_EXPECT(ctx == NULL);
}

T_DECLARE_CASE(test_tls_ctx_bad_cert_fails)
{
	char cert[] = "this is not a PEM certificate at all";
	char key[] = "this is not a PEM key at all";
	struct tls_context *ctx = tls_ctx_server(cert, key, NULL, 0, NULL);
	T_EXPECT(ctx == NULL);
}

T_DECLARE_CASE(test_tls_ctx_server_created)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_server(cert_path, key_path, authcerts, 1, NULL);
	T_EXPECT(ctx != NULL);
	if (ctx != NULL) {
		tls_ctx_unref(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_ctx_client_created)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_client(cert_path, key_path, authcerts, 1, NULL);
	T_EXPECT(ctx != NULL);
	if (ctx != NULL) {
		tls_ctx_unref(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_ctx_ref_unref)
{
	(void)_t_;
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_server(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(ctx != NULL);

	/* ref increments the refcount, two unref calls should be safe. */
	tls_ctx_ref(ctx);
	tls_ctx_unref(ctx); /* drops the extra ref */
	tls_ctx_unref(ctx); /* drops the original ref */

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_key_empty_fails)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char empty[] = "";
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_client(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(ctx != NULL);
	T_EXPECT(!tls_load_key(ctx, empty));
	if (ctx != NULL) {
		tls_ctx_unref(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_cert_missing_file_fails)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char missing[] = "@/tmp/tlsutil_missing_cert.pem";
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_server(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(ctx != NULL);
	T_EXPECT(!tls_load_cert(ctx, missing));
	if (ctx != NULL) {
		tls_ctx_unref(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_authcerts_rejects_invalid_entries)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char empty[] = "";
	char *authcerts_null[] = { NULL };
	char *authcerts_empty[] = { empty };
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_client(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(ctx != NULL);
	T_EXPECT(tls_load_authcerts(ctx, NULL, 0));
	T_EXPECT(!tls_load_authcerts(ctx, authcerts_null, 1));
	T_EXPECT(!tls_load_authcerts(ctx, authcerts_empty, 1));
	if (ctx != NULL) {
		tls_ctx_unref(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_ctx_invalid_ciphersuites_are_ignored)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char ciphersuites[] = "TLS_NO_SUCH_CIPHERSUITE";
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *server =
		tls_ctx_server(cert_path, key_path, authcerts, 1, ciphersuites);
	struct tls_context *client =
		tls_ctx_client(cert_path, key_path, authcerts, 1, ciphersuites);
	T_EXPECT(server != NULL);
	T_EXPECT(client != NULL);
	if (server != NULL) {
		tls_ctx_unref(server);
	}
	if (client != NULL) {
		tls_ctx_unref(client);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_accept_and_connect_validate_inputs)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	struct tls_connection *conn = NULL;
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_server(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(ctx != NULL);
	T_EXPECT(tls_accept(NULL, -1) == NULL);
	conn = tls_accept(ctx, -1);
	T_EXPECT(conn != NULL);
	T_EXPECT(tls_connect(NULL, -1) == NULL);
	T_EXPECT(tls_connect(ctx, -1) == NULL);
	if (conn != NULL) {
		tls_conn_free(conn);
	}
	if (ctx != NULL) {
		tls_ctx_unref(ctx);
	}

	rm_tmpdir(tmpl);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_tls_ctx_server_null_cert_fails);
	T_RUN_CASE(t, test_tls_ctx_bad_cert_fails);
	T_RUN_CASE(t, test_tls_ctx_server_created);
	T_RUN_CASE(t, test_tls_ctx_client_created);
	T_RUN_CASE(t, test_tls_ctx_ref_unref);
	T_RUN_CASE(t, test_tls_load_key_empty_fails);
	T_RUN_CASE(t, test_tls_load_cert_missing_file_fails);
	T_RUN_CASE(t, test_tls_load_authcerts_rejects_invalid_entries);
	T_RUN_CASE(t, test_tls_ctx_invalid_ciphersuites_are_ignored);
	T_RUN_CASE(t, test_tls_accept_and_connect_validate_inputs);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* !WITH_TLS */

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
