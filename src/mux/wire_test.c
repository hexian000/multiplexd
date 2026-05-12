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
#include "gencerts.h"
#include "tlsutil.h"
#include "utils/slog.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
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

static int wire_test_rm_entry(
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

static void wire_test_rm_tmpdir(const char *path)
{
	(void)nftw(path, wire_test_rm_entry, 8, FTW_DEPTH | FTW_PHYS);
}

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
	if (!gencerts("t", "test.example", NULL, "ed25519", 0)) {
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
	tls_ctx_unref(cli_ctx);
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

	tls_ctx_unref(ctx);
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
	tls_ctx_unref(srv_ctx);
	tls_ctx_unref(cli_ctx);
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
	tls_ctx_unref(srv_ctx);
	tls_ctx_unref(cli_ctx);
	close(fds[0]);
	close(fds[1]);
	wire_test_rm_tmpdir(tmpl);
}

#endif /* WITH_TLS */

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
