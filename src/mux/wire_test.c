/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mux/frame.h"
#include "mux/session.h"
#include "mux/wire.h"

#include "utils/testing.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if WITH_TLS
#if WITH_OPENSSL
#include "gencerts.h"
#endif
#include "tlsutil.h"
#include "utils/slog.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#endif /* WITH_TLS */

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static struct mux_frame *wire_test_alloc(void *data)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(sizeof(*frame));
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void wire_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = wire_test_alloc,
		.free = wire_test_free,
		.data = ctx,
	};
}

static struct mux_session
make_session(struct frame_pool_ctx *restrict pool_ctx, const int fd)
{
	struct mux_session ss = {
		.pool = make_pool(pool_ctx),
	};
	ss.w_socket.fd = fd;
	return ss;
}

/* Build a minimal 8-byte control frame header in frame->data so tests can
 * pass a complete, well-formed frame to wire_sendbuf_push. */
static void make_ctrl_frame(
	struct mux_frame *restrict frame, const uint_least16_t stream_id)
{
	frame->pos = 0;
	frame->len = MUX_FRAME_HEADER_SIZE;
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_ACK,
		.length = 0,
		.stream_id = stream_id,
		.extra = 0,
	};
	mux_write_header(frame->data, &hdr);
}

/* Build a PUSH frame with a given payload length (payload bytes are zeroed). */
static void
make_push_frame(struct mux_frame *restrict frame, const size_t payload_len)
{
	frame->pos = 0;
	frame->len = MUX_FRAME_HEADER_SIZE + payload_len;
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = (uint_least16_t)payload_len,
		.stream_id = 2,
		.extra = 0,
	};
	mux_write_header(frame->data, &hdr);
	memset(frame->data + MUX_FRAME_HEADER_SIZE, 0, payload_len);
}

T_DECLARE_CASE(test_wire_send_plain_tcp_writes_bytes)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char payload[] = "hello";
	unsigned char recvbuf[sizeof(payload)] = { 0 };
	size_t len = sizeof(payload) - 1;

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);

	T_EXPECT(wire_send(&ss, payload, &len));
	T_EXPECT_EQ(len, sizeof(payload) - 1);
	T_EXPECT(
		read(fds[1], recvbuf, sizeof(payload) - 1) ==
		(ssize_t)(sizeof(payload) - 1));
	T_EXPECT(memcmp(recvbuf, payload, sizeof(payload) - 1) == 0);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_wire_recv_plain_tcp_reads_payload)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char sendbuf[] = "mux";
	unsigned char recvbuf[sizeof(sendbuf) - 1] = { 0 };
	size_t len = sizeof(sendbuf) - 1;

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(write(fds[1], sendbuf, sizeof(sendbuf) - 1) ==
		(ssize_t)(sizeof(sendbuf) - 1));

	T_EXPECT(wire_recv(&ss, recvbuf, &len));
	T_EXPECT_EQ(len, sizeof(sendbuf) - 1);
	T_EXPECT(memcmp(recvbuf, sendbuf, sizeof(sendbuf) - 1) == 0);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_wire_recv_eof_clears_rx_open_and_sets_tx_pending)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char recvbuf[8] = { 0 };
	size_t len = sizeof(recvbuf);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	ss.wire.rx_open = true;
	T_CHECK(shutdown(fds[1], SHUT_WR) == 0);

	T_EXPECT(wire_recv(&ss, recvbuf, &len));
	T_EXPECT_EQ(len, (size_t)0);
	T_EXPECT(!ss.wire.rx_open);
	T_EXPECT(ss.wire.tx_pending);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_ringbuf_consume_frame_preserves_remaining_bytes)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 1,
		.stream_id = 2,
		.extra = 0,
	};
	unsigned char bytes[2 * MUX_FRAME_HEADER_SIZE + 2] = { 0 };

	mux_write_header(bytes, &hdr);
	bytes[MUX_FRAME_HEADER_SIZE] = 'A';
	hdr.stream_id = 4;
	mux_write_header(bytes + MUX_FRAME_HEADER_SIZE + 1, &hdr);
	bytes[2 * MUX_FRAME_HEADER_SIZE + 1] = 'B';
	ss.wire.recvbuf = ringbuf_new(sizeof(bytes));
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), bytes, sizeof(bytes));
	ringbuf_produce(ss.wire.recvbuf, sizeof(bytes));

	ringbuf_consume(ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE + 1);
	T_EXPECT_EQ(
		ringbuf_readable(ss.wire.recvbuf),
		sizeof(bytes) - ((size_t)MUX_FRAME_HEADER_SIZE + 1));
	T_EXPECT(
		ringbuf_read_ptr(ss.wire.recvbuf)[MUX_FRAME_HEADER_SIZE] ==
		'B');
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_ringbuf_consume_advances_offset_without_copy)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	unsigned char bytes[2 * MUX_FRAME_HEADER_SIZE] = { 0 };

	ss.wire.recvbuf = ringbuf_new(sizeof(bytes));
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(ringbuf_write_ptr(ss.wire.recvbuf), bytes, sizeof(bytes));
	ringbuf_produce(ss.wire.recvbuf, sizeof(bytes));

	ringbuf_consume(ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE);
	T_EXPECT_EQ(ss.wire.recvbuf->off, (size_t)MUX_FRAME_HEADER_SIZE);
	T_EXPECT_EQ(
		ringbuf_readable(ss.wire.recvbuf),
		sizeof(bytes) - (size_t)MUX_FRAME_HEADER_SIZE);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_wire_discard_buffers_frees_all_pending_frames)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *const sb1 = mux_frame_get(&ss.pool);
	struct mux_frame *const sb2 = mux_frame_get(&ss.pool);
	struct mux_frame *const ob1 = mux_frame_get(&ss.pool);
	struct mux_frame *const ob2 = mux_frame_get(&ss.pool);
	ss.wire.recvbuf = ringbuf_new(32);
	T_CHECK(ss.wire.recvbuf != NULL);
	ss.wire.recvbuf->off = 7;
	ss.wire.recvbuf->len = 11;
	T_CHECK(sb1 != NULL);
	T_CHECK(sb2 != NULL);
	T_CHECK(ob1 != NULL);
	T_CHECK(ob2 != NULL);
	mux_frame_list_push(&ss.wire.sendbuf, sb1);
	mux_frame_list_push(&ss.wire.sendbuf, sb2);
	mux_frame_list_push(&ss.wire.oobbuf, ob1);
	mux_frame_list_push(&ss.wire.oobbuf, ob2);

	wire_discard_buffers(&ss);
	T_EXPECT_EQ(pool_ctx.free_calls, 4);
	T_EXPECT(ss.wire.sendbuf.head == NULL);
	T_EXPECT(ss.wire.sendbuf.tail == NULL);
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)0);
	T_EXPECT(ss.wire.oobbuf.head == NULL);
	T_EXPECT(ss.wire.oobbuf.tail == NULL);
	T_EXPECT_EQ(ss.wire.oobbuf.count, (size_t)0);
	T_EXPECT(ss.wire.recvbuf != NULL);
	T_EXPECT_EQ(ss.wire.recvbuf->cap, (size_t)32);
	T_EXPECT_EQ(ss.wire.recvbuf->len, (size_t)0);
	T_EXPECT_EQ(ss.wire.recvbuf->off, (size_t)0);
	ringbuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_wire_shutdown_plain_tcp_returns_done)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char recvbuf[1] = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);

	T_EXPECT_EQ(
		wire_shutdown(&ss),
		(enum wire_shutdown_state)WIRE_SHUTDOWN_DONE);
	T_EXPECT(read(fds[1], recvbuf, sizeof(recvbuf)) == 0);

	close(fds[0]);
	close(fds[1]);
}

T_DECLARE_CASE(test_wire_wait_eof_returns_true_on_clean_peer_close)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(shutdown(fds[1], SHUT_WR) == 0);

	T_EXPECT(wire_wait_eof(&ss));

	close(fds[0]);
	close(fds[1]);
}

#if WITH_TLS

static void wire_test_rm_tmpdir(const char *path)
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
			wire_test_rm_tmpdir(subpath);
		} else {
			(void)unlink(subpath);
		}
	}
	closedir(dir);
	(void)rmdir(path);
}

#if !WITH_OPENSSL
/* Self-signed Ed25519 certificate with subjectAltName=DNS:test.example.
 * Embedded fallback for non-OpenSSL backends (gencerts is OpenSSL-only). */
static const char wire_test_cert_pem[] =
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

static const char wire_test_key_pem[] =
	"-----BEGIN EC PRIVATE KEY-----\n"
	"MHcCAQEEIPdNKDBJJsEP+Wl1IXsrahoxn0MfEyCEzWHZP7akCMwMoAoGCCqGSM49\n"
	"AwEHoUQDQgAEcQ5y3IRSymXph6BK3Tu1tRC86nmNrwt0/+lLaGTZYOkMjsyvzk7U\n"
	"thoRJpe8V3Lade1ugGMFuKwK9f/UhRagzg==\n"
	"-----END EC PRIVATE KEY-----\n";

static bool wire_test_write_pem(const char *path, const char *data)
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

static bool wire_test_make_certs(void)
{
	if (!wire_test_write_pem("t-cert.pem", wire_test_cert_pem)) {
		return false;
	}
	if (!wire_test_write_pem("t-key.pem", wire_test_key_pem)) {
		return false;
	}
	return true;
}
#endif /* !WITH_OPENSSL */

/* Generate a self-signed Ed25519 cert pair in a fresh tmpdir.
 * Returns the saved working directory (caller must free), or NULL on failure.
 * On success, cert_out and key_out hold absolute '@'-prefixed paths. */
static char *wire_test_setup_cert_dir(
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
		wire_test_rm_tmpdir(tmpl);
		free(origdir);
		return NULL;
	}
#if WITH_OPENSSL
	if (!gencerts("t", "test.example", NULL, "ed25519", 0)) {
#else
	if (!wire_test_make_certs()) {
#endif
		if (chdir(origdir) != 0) {
			LOGW_F("chdir: (%d) %s", errno, strerror(errno));
		}
		wire_test_rm_tmpdir(tmpl);
		free(origdir);
		return NULL;
	}
	(void)snprintf(cert_out, cert_sz, "@%s/t-cert.pem", tmpl);
	(void)snprintf(key_out, key_sz, "@%s/t-key.pem", tmpl);
	if (chdir(origdir) != 0) {
		LOGW_F("chdir: (%d) %s", errno, strerror(errno));
	}
	return origdir;
}

/* Drive TLS handshake on both connections alternately until both complete.
 * Returns true on success, false on error. */
static bool wire_test_drive_handshake(
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

T_DECLARE_CASE(test_wire_set_tlsctx_updates_and_noop)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	/* Use the address of a local variable as a type-safe non-NULL sentinel.
	 * wire_set_tlsctx only compares pointers and never dereferences tlsctx. */
	unsigned char sentinel;
	struct tls_context *const fake =
		(struct tls_context *)(void *)&sentinel;

	/* NULL -> fake: must update. */
	wire_set_tlsctx(&ss, fake);
	T_EXPECT_EQ(ss.wire.tlsctx, fake);

	/* fake -> fake: must be a no-op (same pointer). */
	wire_set_tlsctx(&ss, fake);
	T_EXPECT_EQ(ss.wire.tlsctx, fake);

	/* fake -> NULL: must update. */
	wire_set_tlsctx(&ss, NULL);
	T_EXPECT(ss.wire.tlsctx == NULL);
}

T_DECLARE_CASE(test_wire_tls_start_noop_when_no_context)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	/* Both tlsctx and tlsconn are NULL: wire_tls_start must be a no-op. */
	T_EXPECT(wire_tls_start(&ss));
	T_EXPECT(ss.wire.tlsconn == NULL);
}

T_DECLARE_CASE(test_wire_tls_start_creates_outbound_conn)
{
	char tmpl[] = "/tmp/wire_tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2], key_path[PATH_MAX + 2];
	char *origdir = wire_test_setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *cli_ctx =
		tls_ctx_client(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, fds[1]);
	/* Set only tlsctx; wire_tls_start must create tlsconn via tls_connect. */
	ss.wire.tlsctx = cli_ctx;
	T_EXPECT(wire_tls_start(&ss));
	T_EXPECT(ss.wire.tlsconn != NULL);

	wire_conn_free(&ss);
	tls_ctx_free(cli_ctx);
	close(fds[0]);
	close(fds[1]);
	wire_test_rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_wire_conn_free_clears_tlsconn)
{
	char tmpl[] = "/tmp/wire_tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2], key_path[PATH_MAX + 2];
	char *origdir = wire_test_setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *ctx =
		tls_ctx_server(cert_path, key_path, authcerts, 1, NULL);
	T_CHECK(ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	/* tls_accept with a valid fd creates the SSL object without I/O. */
	struct tls_connection *conn = tls_accept(ctx, fds[0]);
	T_CHECK(conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	ss.wire.tlsconn = conn;
	wire_conn_free(&ss);
	T_EXPECT(ss.wire.tlsconn == NULL);

	tls_ctx_free(ctx);
	close(fds[0]);
	close(fds[1]);
	wire_test_rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_wire_tls_send_recv_data)
{
	char tmpl[] = "/tmp/wire_tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2], key_path[PATH_MAX + 2];
	char *origdir = wire_test_setup_cert_dir(
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
	T_CHECK(wire_test_drive_handshake(srv_conn, cli_conn, 20));

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;

	unsigned char send_buf[] = "hello";
	unsigned char recv_buf[sizeof(send_buf)] = { 0 };
	size_t slen = sizeof(send_buf) - 1;
	size_t rlen = sizeof(recv_buf) - 1;
	T_EXPECT(wire_send(&cli_ss, send_buf, &slen));
	T_EXPECT_EQ(slen, sizeof(send_buf) - 1);
	T_EXPECT(wire_recv(&srv_ss, recv_buf, &rlen));
	T_EXPECT_EQ(rlen, sizeof(send_buf) - 1);
	T_EXPECT(memcmp(recv_buf, send_buf, rlen) == 0);

	/* Prevent double-free: clear wire pointers before explicit conn_free. */
	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	close(fds[0]);
	close(fds[1]);
	wire_test_rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_wire_tls_shutdown_completes)
{
	char tmpl[] = "/tmp/wire_tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2], key_path[PATH_MAX + 2];
	char *origdir = wire_test_setup_cert_dir(
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
	T_CHECK(wire_test_drive_handshake(srv_conn, cli_conn, 20));

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;

	/* Drive TLS shutdown cooperatively until both sides complete. */
	bool cli_done = false, srv_done = false;
	for (int i = 0; i < 10 && !(cli_done && srv_done); i++) {
		if (!cli_done) {
			const enum wire_shutdown_state s =
				wire_shutdown(&cli_ss);
			T_EXPECT(s != WIRE_SHUTDOWN_ERROR);
			if (s == WIRE_SHUTDOWN_DONE) {
				cli_done = true;
			}
		}
		if (!srv_done) {
			const enum wire_shutdown_state s =
				wire_shutdown(&srv_ss);
			T_EXPECT(s != WIRE_SHUTDOWN_ERROR);
			if (s == WIRE_SHUTDOWN_DONE) {
				srv_done = true;
			}
		}
	}
	T_EXPECT(cli_done);
	T_EXPECT(srv_done);

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	close(fds[0]);
	close(fds[1]);
	wire_test_rm_tmpdir(tmpl);
}

#endif /* WITH_TLS */

/* Small control frame (8 B) is memcpy-packed into a new staging entry;
 * the original frame is returned to the pool. */
T_DECLARE_CASE(test_sendbuf_push_small_frame_packs_into_staging)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f = mux_frame_get(&ss.pool);
	T_CHECK(f != NULL);
	make_ctrl_frame(f, 1);

	wire_sendbuf_push(&ss, f);

	/* One staging entry was created; the original frame is returned to the pool. */
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT_EQ(ss.wire.sendbuf.tail->len, (size_t)MUX_FRAME_HEADER_SIZE);
	/* pool: 2 allocs (f + staging); f is freed directly (no spare). */
	T_EXPECT_EQ(pool_ctx.alloc_calls, 2);
	T_EXPECT_EQ(pool_ctx.free_calls, 1);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* A second small frame is memcpy-appended to the existing staging entry
 * without allocating a new frame. */
T_DECLARE_CASE(test_sendbuf_push_second_small_frame_packs_into_existing_staging)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f1 = mux_frame_get(&ss.pool);
	struct mux_frame *f2 = mux_frame_get(&ss.pool);
	T_CHECK(f1 != NULL && f2 != NULL);
	make_ctrl_frame(f1, 1);
	make_ctrl_frame(f2, 2);

	wire_sendbuf_push(&ss, f1);
	wire_sendbuf_push(&ss, f2);

	/* Still one sendbuf entry (both headers packed into the staging frame). */
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT_EQ(
		ss.wire.sendbuf.tail->len, (size_t)(2 * MUX_FRAME_HEADER_SIZE));
	/* pool: 3 allocs (f1 + f2 + staging); both f1 and f2 are freed. */
	T_EXPECT_EQ(pool_ctx.alloc_calls, 3);
	T_EXPECT_EQ(pool_ctx.free_calls, 2);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* A large frame (> MUX_CORK_APPEND_MAX) is appended by reference;
 * the frame pointer is preserved and no staging entry is created. */
T_DECLARE_CASE(test_sendbuf_push_large_frame_goes_by_reference)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f = mux_frame_get(&ss.pool);
	T_CHECK(f != NULL);
	/* payload = MUX_CORK_APPEND_MAX bytes, so total = header + threshold */
	make_push_frame(f, MUX_CORK_APPEND_MAX);

	wire_sendbuf_push(&ss, f);

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(!ss.wire.sendbuf_staging);
	/* Frame is in sendbuf by reference — no alloc, no free beyond original f. */
	T_EXPECT(ss.wire.sendbuf.head == f);
	T_EXPECT_EQ(pool_ctx.free_calls, 0);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* A large frame following a staging entry produces a second sendbuf entry
 * (count == 2) and sendbuf_staging is cleared. */
T_DECLARE_CASE(test_sendbuf_push_large_after_staging_adds_second_entry)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *small = mux_frame_get(&ss.pool);
	struct mux_frame *large = mux_frame_get(&ss.pool);
	T_CHECK(small != NULL && large != NULL);
	make_ctrl_frame(small, 1);
	make_push_frame(large, MUX_CORK_APPEND_MAX);

	wire_sendbuf_push(&ss, small); /* creates staging entry */
	wire_sendbuf_push(&ss, large); /* by-reference; count -> 2 */

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)2);
	/* sendbuf_staging is cleared because the tail is now a large ref entry. */
	T_EXPECT(!ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.tail == large);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* A retransmit copy is always appended by reference even when it fits within
 * MUX_CORK_APPEND_MAX, so session_track_sent can match it by pointer. */
T_DECLARE_CASE(test_sendbuf_push_retransmit_copy_goes_by_reference)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f = mux_frame_get(&ss.pool);
	T_CHECK(f != NULL);
	make_ctrl_frame(f, 1); /* 8 bytes — fits in staging threshold */
	ss.retransmit_copy = f; /* mark as retransmit copy */

	wire_sendbuf_push(&ss, f);

	/* Retransmit copy must be by-reference. */
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(!ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.head == f);
	T_EXPECT_EQ(pool_ctx.free_calls, 0);

	ss.retransmit_copy = NULL;
	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* wire_discard_buffers frees sendbuf frames (including staging) and resets
 * sendbuf_staging. */
T_DECLARE_CASE(test_sendbuf_discard_clears_staging)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	ss.wire.recvbuf = ringbuf_new(32);
	T_CHECK(ss.wire.recvbuf != NULL);

	/* Put one staging entry (contains two packed small frames). */
	struct mux_frame *f1 = mux_frame_get(&ss.pool);
	struct mux_frame *f2 = mux_frame_get(&ss.pool);
	T_CHECK(f1 != NULL && f2 != NULL);
	make_ctrl_frame(f1, 1);
	make_ctrl_frame(f2, 2);
	wire_sendbuf_push(&ss, f1);
	wire_sendbuf_push(&ss, f2);
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);

	wire_discard_buffers(&ss);

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)0);
	T_EXPECT(ss.wire.sendbuf.head == NULL);
	T_EXPECT(!ss.wire.sendbuf_staging);
	/* pool: 3 allocs (f1 + f2 + staging); all three are freed:
	 * f1 and f2 on push, staging in wire_discard_buffers. */
	T_EXPECT_EQ(pool_ctx.free_calls, 3);

	ringbuf_free(ss.wire.recvbuf);
}

/* wire_sendbuf_push on a small frame that exactly fills a staging entry up to
 * MUX_FRAME_SIZE leaves room == 0, so the next small frame starts a new entry. */
T_DECLARE_CASE(test_sendbuf_push_staging_full_starts_new_entry)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	/* Create a staging entry and fill it artificially. */
	struct mux_frame *seed = mux_frame_get(&ss.pool);
	T_CHECK(seed != NULL);
	make_ctrl_frame(seed, 1);
	wire_sendbuf_push(&ss, seed); /* staging created; seed freed */
	ss.wire.sendbuf.tail->len = MUX_FRAME_SIZE; /* fill it to capacity */

	pool_ctx.alloc_calls = 0;
	pool_ctx.free_calls = 0;

	/* Now append a small frame — staging is full, so a new entry must be created. */
	struct mux_frame *f2 = mux_frame_get(&ss.pool);
	T_CHECK(f2 != NULL);
	make_ctrl_frame(f2, 2);
	wire_sendbuf_push(&ss, f2);

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)2);
	/* A new staging entry was created for f2. */
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT_EQ(ss.wire.sendbuf.tail->len, (size_t)MUX_FRAME_HEADER_SIZE);
	/* pool: seed was freed on first push (before counter reset).
	 * After reset: f2 allocated (1 alloc), new staging allocated (1 alloc),
	 * f2 freed after header packed (1 free). */
	T_EXPECT_EQ(pool_ctx.alloc_calls, 2);
	T_EXPECT_EQ(pool_ctx.free_calls, 1);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_wire_send_plain_tcp_writes_bytes);
	T_RUN_CASE(t, test_wire_recv_plain_tcp_reads_payload);
	T_RUN_CASE(t, test_wire_recv_eof_clears_rx_open_and_sets_tx_pending);
	T_RUN_CASE(t, test_ringbuf_consume_frame_preserves_remaining_bytes);
	T_RUN_CASE(t, test_ringbuf_consume_advances_offset_without_copy);
	T_RUN_CASE(t, test_wire_discard_buffers_frees_all_pending_frames);
	T_RUN_CASE(t, test_wire_shutdown_plain_tcp_returns_done);
	T_RUN_CASE(t, test_wire_wait_eof_returns_true_on_clean_peer_close);
	T_RUN_CASE(t, test_sendbuf_push_small_frame_packs_into_staging);
	T_RUN_CASE(
		t,
		test_sendbuf_push_second_small_frame_packs_into_existing_staging);
	T_RUN_CASE(t, test_sendbuf_push_large_frame_goes_by_reference);
	T_RUN_CASE(t, test_sendbuf_push_large_after_staging_adds_second_entry);
	T_RUN_CASE(t, test_sendbuf_push_retransmit_copy_goes_by_reference);
	T_RUN_CASE(t, test_sendbuf_discard_clears_staging);
	T_RUN_CASE(t, test_sendbuf_push_staging_full_starts_new_entry);
#if WITH_TLS
	T_RUN_CASE(t, test_wire_set_tlsctx_updates_and_noop);
	T_RUN_CASE(t, test_wire_tls_start_noop_when_no_context);
	T_RUN_CASE(t, test_wire_tls_start_creates_outbound_conn);
	T_RUN_CASE(t, test_wire_conn_free_clears_tlsconn);
	T_RUN_CASE(t, test_wire_tls_send_recv_data);
	T_RUN_CASE(t, test_wire_tls_shutdown_completes);
#endif
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
