/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "tlsutil.h"

#define UTILS_MEASURE_H
#include "io/io.h"
#include "os/clock.h"
#include "utils/testing.h"

#include <stdlib.h>

#if WITH_TLS

#if WITH_OPENSSL
#include "gencerts.h"
#endif
#include "utils/slog.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
	closedir(dir);
	(void)rmdir(path);
}

#if !WITH_OPENSSL
/* Self-signed Ed25519 certificate with subjectAltName=DNS:test.example.
 * The companion private key follows. These literals stand in for the
 * gencerts() helper, which is OpenSSL-only. */
static const char test_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBnzCCAUSgAwIBAgIUecJKZzpeqHlnY0oRsqh21j4TnWIwCgYIKoZIzj0EAwIw\n"
	"FzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCAXDTI2MDUxOTA0MTY0NloYDzIxMjYw\n"
	"NDI1MDQxNjQ2WjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwWTATBgcqhkjOPQIB\n"
	"BggqhkjOPQMBBwNCAARxDnLchFLKZemHoErdO7W1ELzqeY2vC3T/6UtoZNlg6QyO\n"
	"zK/OTtS2GhEml7xXctp17W6AYwW4rAr1/9SFFqDOo2wwajAdBgNVHQ4EFgQUhPN3\n"
	"UVEB2laNlxV8HcHyq2HogFkwHwYDVR0jBBgwFoAUhPN3UVEB2laNlxV8HcHyq2Ho\n"
	"gFkwFwYDVR0RBBAwDoIMdGVzdC5leGFtcGxlMA8GA1UdEwEB/wQFMAMBAf8wCgYI\n"
	"KoZIzj0EAwIDSQAwRgIhAPYLykNErqBlLUdJJqhqMSKlfyn7/zAbR5nPJ1l7pC0F\n"
	"AiEA4BLdR1o4TkZTakcr5TG9wcilxgYTKYwrR3Fw18gDAQw=\n"
	"-----END CERTIFICATE-----\n";

static const char test_key_pem[] =
	"-----BEGIN EC PRIVATE KEY-----\n"
	"MHcCAQEEIPdNKDBJJsEP+Wl1IXsrahoxn0MfEyCEzWHZP7akCMwMoAoGCCqGSM49\n"
	"AwEHoUQDQgAEcQ5y3IRSymXph6BK3Tu1tRC86nmNrwt0/+lLaGTZYOkMjsyvzk7U\n"
	"thoRJpe8V3Lade1ugGMFuKwK9f/UhRagzg==\n"
	"-----END EC PRIVATE KEY-----\n";

static bool write_pem_file(const char *path, const char *data)
{
	FILE *fp = fopen(path, "w");
	if (fp == NULL) {
		return false;
	}
	const size_t len = strlen(data);
	const size_t n = fwrite(data, 1, len, fp);
	const int closed = fclose(fp);
	return n == len && closed == 0;
}

static bool make_test_certs(void)
{
	if (!write_pem_file("t-cert.pem", test_cert_pem)) {
		return false;
	}
	if (!write_pem_file("t-key.pem", test_key_pem)) {
		return false;
	}
	return true;
}
#endif /* !WITH_OPENSSL */

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
#if WITH_OPENSSL
	if (!gencerts("t", "test.example", NULL, "ed25519", 0)) {
#else
	if (!make_test_certs()) {
#endif
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
		tls_ctx_free(ctx);
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
		tls_ctx_free(ctx);
	}

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
		tls_ctx_free(ctx);
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
		tls_ctx_free(ctx);
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
		tls_ctx_free(ctx);
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
		tls_ctx_free(server);
	}
	if (client != NULL) {
		tls_ctx_free(client);
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
		tls_ctx_free(ctx);
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

	tls_ctx_free(ctx);
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

	tls_ctx_free(ctx);
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
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	close(fds[0]);
	close(fds[1]);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_peer_cert_der_after_handshake)
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
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *srv_conn = tls_accept(srv_ctx, fds[0]);
	struct tls_connection *cli_conn = tls_connect(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* Both sides should be able to retrieve the peer's certificate. */
	unsigned char *srv_der = NULL;
	size_t srv_der_len = 0;
	T_EXPECT(tls_peer_cert_der(srv_conn, &srv_der, &srv_der_len));
	T_EXPECT(srv_der != NULL);
	T_EXPECT(srv_der_len > 0);

	unsigned char *cli_der = NULL;
	size_t cli_der_len = 0;
	T_EXPECT(tls_peer_cert_der(cli_conn, &cli_der, &cli_der_len));
	T_EXPECT(cli_der != NULL);
	T_EXPECT(cli_der_len > 0);

	/* Same certificate on both sides (self-signed test cert). */
	T_EXPECT(srv_der_len == cli_der_len);
	T_EXPECT(memcmp(srv_der, cli_der, srv_der_len) == 0);

	free(srv_der);
	free(cli_der);

	T_EXPECT(drive_shutdown(cli_conn, srv_conn, 10));
	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	close(fds[0]);
	close(fds[1]);
	rm_tmpdir(tmpl);
}

/* ---- throughput benchmark: plain TCP baseline ---- */

static int tcp_bench_fds[2] = { -1, -1 };

static void tcp_bench_teardown(void)
{
	if (tcp_bench_fds[0] >= 0) {
		close(tcp_bench_fds[0]);
		close(tcp_bench_fds[1]);
		tcp_bench_fds[0] = -1;
		tcp_bench_fds[1] = -1;
	}
}

static bool tcp_bench_setup(void)
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, tcp_bench_fds) != 0) {
		return false;
	}
	return true;
}

T_DECLARE_BENCH(bench_tcp_throughput)
{
	unsigned char send_buf[IO_BUFSIZE];
	unsigned char recv_buf[IO_BUFSIZE];
	memset(send_buf, 0xA5, sizeof(send_buf));

	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		size_t n = sizeof(send_buf);
		T_CHECK(send(tcp_bench_fds[1], send_buf, n, 0) == (ssize_t)n);

		n = sizeof(recv_buf);
		T_CHECK(recv(tcp_bench_fds[0], recv_buf, n, 0) == (ssize_t)n);
	}
}

/* ---- throughput benchmark: RSA 4096, production-matching TLS config ----
 *
 * Uses built-in static certificate and key so the benchmark works with
 * both OpenSSL and mbedTLS backends (no gencerts dependency).  Cert and key
 * are passed in-memory (no '@' prefix) and the same self-signed cert serves
 * as the authorized peer certificate for mutual authentication. */

static char bench_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFKjCCAxKgAwIBAgIUM70vOlOUSVk9dQ7tbW/ih/8sKCwwDQYJKoZIhvcNAQEL\n"
	"BQAwFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCAXDTI2MDYwOTAyNDQ0NVoYDzIx\n"
	"MjYwNTE2MDI0NDQ1WjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwggIiMA0GCSqG\n"
	"SIb3DQEBAQUAA4ICDwAwggIKAoICAQC+SzjGbGTgjqsKQCEGYS3hFnO1hBoy1VQ8\n"
	"zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uceOaVYLXIe3f96+TucfBJw\n"
	"Wh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXkaxOOVaayRJx79cPxqqLFr\n"
	"rDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW9tNYRrZWVoTe21m2apl6\n"
	"/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGmRNzcAnguhIIe3z8qbwDH\n"
	"1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVpmL6QLpMolNS0cznJgVo2\n"
	"eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV08tZNLeNoN3ezRXsEYE2\n"
	"/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baozaQwoGNzDO/QXffAADp/W\n"
	"F2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus2IBTNFZp+mW8mCliYWop\n"
	"zfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi0omuKHTR326KPLkG7IpW\n"
	"agolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6Rn0bwaeCR6t0or8ru7Dxs\n"
	"dq/TW93U5wIDAQABo2wwajAdBgNVHQ4EFgQU3hgHVZAn/Lh/xbRhabVaEGQbxc8w\n"
	"HwYDVR0jBBgwFoAU3hgHVZAn/Lh/xbRhabVaEGQbxc8wDwYDVR0TAQH/BAUwAwEB\n"
	"/zAXBgNVHREEEDAOggx0ZXN0LmV4YW1wbGUwDQYJKoZIhvcNAQELBQADggIBAIWF\n"
	"in4MUtRj4R6GYGtjjnWt1m9aN4I/w22kdD183G07uTJZ+i545DdFNglt8ZIO1f2F\n"
	"eQ67wQfxIeFeZrr4x6wA7B+RVwX/mRuj3aby5QXhNDVkjAp2su9GRPyIe3jXPDv/\n"
	"/quE4Oufa0kE8HuvqPIOSO6UYWkNAP81LDoyDhyoadB5+mIuxpM3+NyKh6AK2g8n\n"
	"Ran7GYKtMUrL7ryRoJyPcpFk/QyrWAMCbmO3p2Rxx5sj3RtL+6HNYTqNij5qsB+S\n"
	"zmdmX8XyAW5Bgog3hrnrTn1j1AaxNgEczsjdDmaGQiYKscyLwMe38DI8NP/rPP4X\n"
	"rMH8B/TLl+uRwY1THRtkyHI6y4ZnGzmdEBf001J/KUfBFnLxHZBrJwMYbgqLWjba\n"
	"nVXS5GXAtt7Mmz2tKQo7gCHUjgByWcnun3qMGcEoCkkTaqi0pxf2844BYyy73VRT\n"
	"XdPJnfOOHDhuwkkeOfVJbPnfYFAAd8qMpmzBQvz4Clz2q4plB7odyWPSGwvLbFYs\n"
	"sdwuTXnyLqCrB3K0uMBlKr7xeWiVHUfe5oGCwgp7TjV/2AmKUxNzdg41d3Fn7TPK\n"
	"CncDeSmMy1elKbutfBvWvl8d7C0A9viO49Vy0CVR41uQnF09bzdFTYoaOrX8c+w4\n"
	"VtiUoGP5D91X1vhTixpq4BqoHRkKVQpZ0Z/9386J\n"
	"-----END CERTIFICATE-----\n";

static char bench_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"NL+YLwobqSZhkl4iZWt2wGODitzp/aQ=\n"
	"-----END PRIVATE KEY-----\n";

static struct tls_connection *bench_srv_conn;
static struct tls_connection *bench_cli_conn;
static struct tls_context *bench_srv_ctx;
static struct tls_context *bench_cli_ctx;
static int bench_fds[2] = { -1, -1 };

static void bench_teardown(void)
{
	if (bench_cli_conn != NULL && bench_srv_conn != NULL) {
		(void)drive_shutdown(bench_cli_conn, bench_srv_conn, 20);
	}
	tls_conn_free(bench_cli_conn);
	bench_cli_conn = NULL;
	tls_conn_free(bench_srv_conn);
	bench_srv_conn = NULL;
	tls_ctx_free(bench_cli_ctx);
	bench_cli_ctx = NULL;
	tls_ctx_free(bench_srv_ctx);
	bench_srv_ctx = NULL;
	if (bench_fds[0] >= 0) {
		close(bench_fds[0]);
		close(bench_fds[1]);
		bench_fds[0] = -1;
		bench_fds[1] = -1;
	}
}

static bool bench_setup(void)
{
	char *authcerts[] = { bench_cert_pem };

	bench_srv_ctx = tls_ctx_server(
		bench_cert_pem, bench_key_pem, authcerts, 1, NULL);
	bench_cli_ctx = tls_ctx_client(
		bench_cert_pem, bench_key_pem, authcerts, 1, NULL);
	if (bench_srv_ctx == NULL || bench_cli_ctx == NULL) {
		goto fail;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, bench_fds) != 0) {
		goto fail;
	}
	if (fcntl(bench_fds[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(bench_fds[1], F_SETFL, O_NONBLOCK) != 0) {
		goto fail;
	}

	bench_srv_conn = tls_accept(bench_srv_ctx, bench_fds[0]);
	bench_cli_conn = tls_connect(bench_cli_ctx, bench_fds[1]);
	if (bench_srv_conn == NULL || bench_cli_conn == NULL) {
		goto fail;
	}
	if (!drive_handshake(bench_srv_conn, bench_cli_conn, 50)) {
		goto fail;
	}

	return true;

fail:
	bench_teardown();
	return false;
}

T_DECLARE_BENCH(bench_tls_throughput)
{
	unsigned char send_buf[IO_BUFSIZE];
	unsigned char recv_buf[IO_BUFSIZE];
	memset(send_buf, 0xA5, sizeof(send_buf));

	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		size_t n = sizeof(send_buf);
		T_CHECK(tls_send(bench_cli_conn, send_buf, &n) ==
			TLS_ERROR_NONE);
		T_CHECK(n == sizeof(send_buf));

		n = sizeof(recv_buf);
		T_CHECK(tls_recv(bench_srv_conn, recv_buf, &n) ==
			TLS_ERROR_NONE);
		T_CHECK(n == sizeof(send_buf));
	}
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_tls_ctx_server_null_cert_fails);
	T_RUN_CASE(t, test_tls_ctx_bad_cert_fails);
	T_RUN_CASE(t, test_tls_ctx_server_created);
	T_RUN_CASE(t, test_tls_ctx_client_created);
	T_RUN_CASE(t, test_tls_load_key_empty_fails);
	T_RUN_CASE(t, test_tls_load_cert_missing_file_fails);
	T_RUN_CASE(t, test_tls_load_authcerts_rejects_invalid_entries);
	T_RUN_CASE(t, test_tls_ctx_invalid_ciphersuites_are_ignored);
	T_RUN_CASE(t, test_tls_accept_and_connect_validate_inputs);
	T_RUN_CASE(t, test_tls_load_cert_from_memory_succeeds);
	T_RUN_CASE(t, test_tls_load_key_from_memory_succeeds);
	T_RUN_CASE(t, test_tls_full_handshake_and_io);
	T_RUN_CASE(t, test_tls_peer_cert_der_after_handshake);
	if (getenv("BENCH") != NULL && tcp_bench_setup()) {
		T_RUN_BENCH(t, bench_tcp_throughput);
		tcp_bench_teardown();
	}
	if (getenv("BENCH") != NULL && bench_setup()) {
		T_RUN_BENCH(t, bench_tls_throughput);
		bench_teardown();
	}
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* !WITH_TLS */

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
