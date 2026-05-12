/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "tlsutil.h"

#include "utils/testing.h"

#include <stdlib.h>

#if WITH_TLS

#include "gencerts.h"
#include "utils/slog.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

/* Read the entire contents of a file into a malloc-allocated string.
 * Returns NULL on failure. */
static char *slurp_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		(void)fclose(fp);
		return NULL;
	}
	const long size = ftell(fp);
	if (size < 0) {
		(void)fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		(void)fclose(fp);
		return NULL;
	}
	char *buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		(void)fclose(fp);
		return NULL;
	}
	const size_t n = fread(buf, 1, (size_t)size, fp);
	(void)fclose(fp);
	buf[n] = '\0';
	return buf;
}

/* Drive TLS handshake on both connections alternately until both complete.
 * Returns true on success, false on error. */
static bool drive_handshake(
	struct tls_connection *restrict srv,
	struct tls_connection *restrict cli, int max_rounds)
{
	bool srv_done = false, cli_done = false;
	for (int i = 0; i < max_rounds; i++) {
		if (!cli_done) {
			bool want_read = false, want_write = false;
			const int ret =
				tls_handshake(cli, &want_read, &want_write);
			if (ret < 0) {
				return false;
			}
			if (ret == 0) {
				cli_done = true;
			}
		}
		if (!srv_done) {
			bool want_read = false, want_write = false;
			const int ret =
				tls_handshake(srv, &want_read, &want_write);
			if (ret < 0) {
				return false;
			}
			if (ret == 0) {
				srv_done = true;
			}
		}
		if (cli_done && srv_done) {
			return true;
		}
	}
	return false;
}

/* Drive TLS shutdown on both connections alternately until both complete.
 * Returns true on clean completion, false on error. */
static bool drive_shutdown(
	struct tls_connection *restrict a, struct tls_connection *restrict b,
	int max_rounds)
{
	bool a_done = false, b_done = false;
	for (int i = 0; i < max_rounds; i++) {
		if (!a_done) {
			bool want_read = false, want_write = false;
			const int ret =
				tls_shutdown(a, &want_read, &want_write);
			if (ret == 0) {
				a_done = true;
			} else if (ret < 0) {
				return false;
			}
		}
		if (!b_done) {
			bool want_read = false, want_write = false;
			const int ret =
				tls_shutdown(b, &want_read, &want_write);
			if (ret == 0) {
				b_done = true;
			} else if (ret < 0) {
				return false;
			}
		}
		if (a_done && b_done) {
			return true;
		}
	}
	return false;
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

T_DECLARE_CASE(test_tls_load_cert_from_memory_succeeds)
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
	T_CHECK(ctx != NULL);

	/* Read the certificate PEM directly from the file (cert_path + 1 strips
	 * the '@' prefix to get the real path) and pass it without '@' to
	 * exercise the in-memory load path of tls_load_cert. */
	char *pem = slurp_file(cert_path + 1);
	T_CHECK(pem != NULL);
	T_EXPECT(tls_load_cert(ctx, pem));
	free(pem);

	tls_ctx_unref(ctx);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_key_from_memory_succeeds)
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
	T_CHECK(ctx != NULL);

	/* Read the key PEM from the file (key_path + 1 strips '@') and pass it
	 * without '@' to exercise the in-memory load path of tls_load_key. */
	char *pem = slurp_file(key_path + 1);
	T_CHECK(pem != NULL);
	T_EXPECT(tls_load_key(ctx, pem));
	free(pem);

	tls_ctx_unref(ctx);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_full_handshake_and_io)
{
	char tmpl[] = "/tmp/tlsutil_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *srv_ctx =
		tls_ctx_server(cert_path, key_path, authcerts, 1, NULL);
	struct tls_context *cli_ctx =
		tls_ctx_client(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	/* Non-blocking so the handshake can be driven cooperatively. */
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *srv_conn = tls_accept(srv_ctx, fds[0]);
	struct tls_connection *cli_conn = tls_connect(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* Round-trip: client sends, server receives. */
	unsigned char send_buf[] = "hello";
	unsigned char recv_buf[sizeof(send_buf)] = { 0 };
	size_t send_len = sizeof(send_buf) - 1;
	size_t recv_len = sizeof(recv_buf) - 1;
	T_EXPECT_EQ(tls_send(cli_conn, send_buf, &send_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(send_len, sizeof(send_buf) - 1);
	T_EXPECT_EQ(tls_recv(srv_conn, recv_buf, &recv_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(recv_len, sizeof(send_buf) - 1);
	T_EXPECT(memcmp(recv_buf, send_buf, recv_len) == 0);

	/* Exercise the TLS shutdown path: drive close_notify exchange. */
	T_EXPECT(drive_shutdown(cli_conn, srv_conn, 10));

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_unref(cli_ctx);
	tls_ctx_unref(srv_ctx);
	close(fds[0]);
	close(fds[1]);
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
	T_RUN_CASE(t, test_tls_load_cert_from_memory_succeeds);
	T_RUN_CASE(t, test_tls_load_key_from_memory_succeeds);
	T_RUN_CASE(t, test_tls_full_handshake_and_io);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* !WITH_TLS */

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
