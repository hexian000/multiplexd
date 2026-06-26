/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* wire_test.c - white-box tests for wire.c (TLS/plain socket I/O and the
 * send-buffer staging/coalescing).
 * Dependencies: wire.c #included; real leaf frame.c and the TLS backend
 * (tlsutil + gencerts) linked; socket I/O via real socketpairs (csnippets).
 * wire.c is self-contained, so no sibling collaborators are mocked. */

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/wire.h"

#include "utils/testing.h"

#include <poll.h>
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

#include "mux/wire.c"

/* mock - frame pool and session fixtures */

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static struct mux_frame *wire_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
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
#if WITH_TLS
	/* Match the production default: the TLS library owns the socket fd.
	 * Memory-transport tests opt out by clearing this. */
	ss.conf.tls_socket_offload = true;
#endif
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

/* regression - targeted cases for one wire behavior each */

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

	(void)close(fds[0]);
	(void)close(fds[1]);
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

	(void)close(fds[0]);
	(void)close(fds[1]);
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

	(void)close(fds[0]);
	(void)close(fds[1]);
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

/* ringbuf_shrink reclaims a grown buffer down to the target, compacting the
 * live bytes to the front and preserving them. */
T_DECLARE_CASE(test_ringbuf_shrink_reclaims_capacity)
{
	struct ringbuf *rb = ringbuf_new(4096);
	T_CHECK(rb != NULL);
	memset(ringbuf_write_ptr(rb), 'X', 100);
	ringbuf_produce(rb, 100);
	ringbuf_consume(rb, 10); /* off=10, len=90: forces compaction */
	T_EXPECT_EQ(rb->cap, (size_t)4096);

	ringbuf_shrink(&rb, 256);

	T_EXPECT_EQ(rb->cap, (size_t)256);
	T_EXPECT_EQ(rb->off, (size_t)0);
	T_EXPECT_EQ(ringbuf_readable(rb), (size_t)90);
	const unsigned char *const p = ringbuf_read_ptr(rb);
	bool intact = true;
	for (size_t i = 0; i < 90; i++) {
		intact = intact && (p[i] == 'X');
	}
	T_EXPECT(intact);
	ringbuf_free(rb);
}

/* ringbuf_shrink never drops below the live byte count, even when the target is
 * smaller. */
T_DECLARE_CASE(test_ringbuf_shrink_keeps_live_bytes)
{
	struct ringbuf *rb = ringbuf_new(4096);
	T_CHECK(rb != NULL);
	memset(ringbuf_write_ptr(rb), 'Y', 500);
	ringbuf_produce(rb, 500); /* len=500 > target */

	ringbuf_shrink(&rb, 256);

	T_EXPECT_EQ(rb->cap, (size_t)500);
	T_EXPECT_EQ(ringbuf_readable(rb), (size_t)500);
	ringbuf_free(rb);
}

/* ringbuf_shrink is a no-op when the capacity is already at or below target. */
T_DECLARE_CASE(test_ringbuf_shrink_noop_when_small)
{
	struct ringbuf *rb = ringbuf_new(128);
	T_CHECK(rb != NULL);

	ringbuf_shrink(&rb, 256);

	T_EXPECT_EQ(rb->cap, (size_t)128);
	ringbuf_free(rb);
}

T_DECLARE_CASE(test_wire_discard_buffers_frees_all_pending_frames)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *const sb1 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const sb2 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const ob1 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const ob2 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	(void)close(fds[0]);
	(void)close(fds[1]);
}

T_DECLARE_CASE(test_wire_wait_eof_returns_true_on_clean_peer_close)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(shutdown(fds[1], SHUT_WR) == 0);

	T_EXPECT(wire_wait_eof(&ss));

	(void)close(fds[0]);
	(void)close(fds[1]);
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
	(void)closedir(dir);
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
			const enum tls_error err = tls_handshake(cli);
			if (err != TLS_ERROR_NONE &&
			    err != TLS_ERROR_WANT_READ &&
			    err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
			if (err == TLS_ERROR_NONE) {
				cli_done = true;
			}
		}
		if (!srv_done) {
			const enum tls_error err = tls_handshake(srv);
			if (err != TLS_ERROR_NONE &&
			    err != TLS_ERROR_WANT_READ &&
			    err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
			if (err == TLS_ERROR_NONE) {
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
	struct tls_context *const fake = (struct tls_context *)&sentinel;

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
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, fds[1]);
	/* Set only tlsctx; wire_tls_start must create tlsconn via tls_client. */
	ss.wire.tlsctx = cli_ctx;
	T_EXPECT(wire_tls_start(&ss));
	T_EXPECT(ss.wire.tlsconn != NULL);

	wire_conn_free(&ss);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
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
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	/* tls_server with a valid fd creates the SSL object without I/O. */
	struct tls_connection *conn = tls_server(ctx, fds[0]);
	T_CHECK(conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	ss.wire.tlsconn = conn;
	wire_conn_free(&ss);
	T_EXPECT(ss.wire.tlsconn == NULL);

	tls_ctx_free(ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
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
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *cli_conn = tls_client(cli_ctx, fds[1]);
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
	/* The peer's ciphertext may not have reached fds[0] yet: AF_UNIX
	 * socketpairs deliver synchronously on Linux but asynchronously over the
	 * loopback emulation on Windows/msys2.  Retry wire_recv, waiting on
	 * readability between attempts, until the payload arrives. */
	size_t got = 0;
	for (int i = 0; i < 20 && got == 0; i++) {
		rlen = sizeof(recv_buf) - 1;
		T_EXPECT(wire_recv(&srv_ss, recv_buf, &rlen));
		got = rlen;
		if (got == 0) {
			struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
			(void)poll(&pfd, 1, 100);
		}
	}
	T_EXPECT_EQ(got, sizeof(send_buf) - 1);
	T_EXPECT(memcmp(recv_buf, send_buf, got) == 0);

	/* Prevent double-free: clear wire pointers before explicit conn_free. */
	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
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
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *cli_conn = tls_client(cli_ctx, fds[1]);
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
	(void)close(fds[0]);
	(void)close(fds[1]);
	wire_test_rm_tmpdir(tmpl);
}

/* End-to-end memory transport (tls.socket_offload disabled): wire_send/wire_recv
 * own the socketpair while the TLS library works in memory.  Drives the full
 * mutual-auth handshake and a bidirectional payload exchange through the wire API. */
T_DECLARE_CASE(test_wire_tls_buffered_send_recv)
{
	char tmpl[] = "/tmp/wire_tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2], key_path[PATH_MAX + 2];
	char *origdir = wire_test_setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	/* Buffered connections pass fd=-1; wire.c drives the socket. */
	struct tls_connection *srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *cli_conn = tls_client(cli_ctx, -1);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;
	/* Memory transport is selected by disabling socket offload in the mux config. */
	srv_ss.conf.tls_socket_offload = false;
	cli_ss.conf.tls_socket_offload = false;

	/* Drive the handshake and exchange by pumping each side's hello plaintext
	 * through wire_send (returns 0 bytes until the handshake completes) and
	 * draining inbound records via wire_recv. */
	unsigned char cli_msg[] = "ping", srv_msg[] = "pong";
	unsigned char cli_rx[16384] = { 0 }, srv_rx[16384] = { 0 };
	size_t cli_sent = 0, srv_sent = 0, srv_got = 0, cli_got = 0;
	for (int i = 0; i < 100 && (srv_got == 0 || cli_got == 0); i++) {
		if (cli_sent == 0) {
			size_t n = sizeof(cli_msg) - 1;
			T_CHECK(wire_send(&cli_ss, cli_msg, &n));
			cli_sent = n;
		}
		if (srv_sent == 0) {
			size_t n = sizeof(srv_msg) - 1;
			T_CHECK(wire_send(&srv_ss, srv_msg, &n));
			srv_sent = n;
		}
		size_t rn = sizeof(srv_rx);
		T_CHECK(wire_recv(&srv_ss, srv_rx, &rn));
		if (rn > 0) {
			srv_got = rn;
		}
		rn = sizeof(cli_rx);
		T_CHECK(wire_recv(&cli_ss, cli_rx, &rn));
		if (rn > 0) {
			cli_got = rn;
		}
	}

	T_EXPECT_EQ(srv_got, sizeof(cli_msg) - 1);
	T_EXPECT(memcmp(srv_rx, cli_msg, srv_got) == 0);
	T_EXPECT_EQ(cli_got, sizeof(srv_msg) - 1);
	T_EXPECT(memcmp(cli_rx, srv_msg, cli_got) == 0);

	/* Buffered close: the client's close_notify must reach the socket and the
	 * server must observe a clean EOF through the buffered recv path. */
	T_EXPECT_EQ(wire_shutdown(&cli_ss), WIRE_SHUTDOWN_DONE);
	srv_ss.wire.rx_open = true;
	bool srv_eof = false;
	for (int i = 0; i < 20 && !srv_eof; i++) {
		size_t rn = sizeof(srv_rx);
		T_CHECK(wire_recv(&srv_ss, srv_rx, &rn));
		srv_eof = srv_ss.wire.rx_eof;
	}
	T_EXPECT(srv_eof);

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	ringbuf_free(srv_ss.wire.rawbuf);
	ringbuf_free(cli_ss.wire.rawbuf);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	wire_test_rm_tmpdir(tmpl);
}

#endif /* WITH_TLS */

/* A corkable frame (8 B control) with no open tail is appended by reference and
 * becomes the open tail; the frame itself is the entry (no copy, no spare
 * alloc). */
T_DECLARE_CASE(test_sendbuf_push_small_frame_by_reference)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(f != NULL);
	make_ctrl_frame(f, 1);

	wire_sendbuf_push(&ss, f);

	/* The frame is the open tail by reference: no copy, no extra alloc. */
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.head == f);
	T_EXPECT_EQ(ss.wire.sendbuf.tail->len, (size_t)MUX_FRAME_HEADER_SIZE);
	T_EXPECT_EQ(pool_ctx.alloc_calls, 1);
	T_EXPECT_EQ(pool_ctx.free_calls, 0);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* A second corkable frame is memcpy-appended onto the open tail (the first
 * frame's buffer) without allocating a new frame. */
T_DECLARE_CASE(test_sendbuf_push_second_small_frame_packs_onto_tail)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f1 = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *f2 = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(f1 != NULL && f2 != NULL);
	make_ctrl_frame(f1, 1);
	make_ctrl_frame(f2, 2);

	wire_sendbuf_push(&ss, f1);
	wire_sendbuf_push(&ss, f2);

	/* Still one entry: f2's header packed onto f1's tail; f2 is freed. */
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.tail == f1);
	T_EXPECT_EQ(
		ss.wire.sendbuf.tail->len, (size_t)(2 * MUX_FRAME_HEADER_SIZE));
	T_EXPECT_EQ(pool_ctx.alloc_calls, 2);
	T_EXPECT_EQ(pool_ctx.free_calls, 1);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* The first frame has no open tail to pack onto, so it is appended by reference
 * (zero-copy) regardless of size and becomes the open tail that later frames
 * can fill. */
T_DECLARE_CASE(test_sendbuf_push_large_frame_by_reference)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(f != NULL);
	make_push_frame(f, 1000u);

	wire_sendbuf_push(&ss, f);

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	/* By reference, yet still the open tail (its spare capacity can absorb
	 * later frames up to one record). */
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.head == f);
	T_EXPECT_EQ(pool_ctx.free_calls, 0);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* The headline behavior: a corkable frame packs onto the tail of a large
 * by-reference frame (only the small frame is copied; the large payload is
 * not), so both ride in one entry / one TLS record. */
T_DECLARE_CASE(test_sendbuf_push_corkable_packs_onto_large_tail)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *large = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *small = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(large != NULL && small != NULL);
	make_push_frame(large, 1000u); /* len 1008, opens the record */
	make_ctrl_frame(small, 1); /* 8 B */

	wire_sendbuf_push(&ss, large); /* by reference, opens tail */
	wire_sendbuf_push(&ss, small); /* packs onto large's tail */

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.tail == large);
	T_EXPECT_EQ(
		ss.wire.sendbuf.tail->len,
		(size_t)(MUX_FRAME_HEADER_SIZE + 1000u +
			 MUX_FRAME_HEADER_SIZE));
	/* Only the small frame was returned to the pool; large stays by reference. */
	T_EXPECT_EQ(pool_ctx.free_calls, 1);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* A frame larger than one TLS record cannot pack onto the open tail; it starts a
 * new by-reference entry (count == 2) that becomes the new open tail. */
T_DECLARE_CASE(test_sendbuf_push_large_after_corkable_adds_entry)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *small = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *large = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(small != NULL && large != NULL);
	make_ctrl_frame(small, 1);
	make_push_frame(large, MUX_MAX_RECORD); /* len > MUX_MAX_RECORD */

	wire_sendbuf_push(&ss, small); /* opens tail by reference */
	wire_sendbuf_push(&ss, large); /* exceeds one record; count -> 2 */

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)2);
	/* The large frame is now the open tail. */
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.tail == large);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* Medium frames that together still fit one TLS record are coalesced: the second
 * is copy-packed onto the first, leaving a single entry. */
T_DECLARE_CASE(test_sendbuf_push_medium_frames_coalesce)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *m1 = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *m2 = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(m1 != NULL && m2 != NULL);
	/* Two 4 KiB frames: 2 * (header + 4096) is well within one record. */
	make_push_frame(m1, 4096u);
	make_push_frame(m2, 4096u);

	wire_sendbuf_push(&ss, m1);
	wire_sendbuf_push(&ss, m2);

	/* One entry: m2 packed onto m1's tail; m2 is freed. */
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.head == m1);
	T_EXPECT(ss.wire.sendbuf.tail == m1);
	T_EXPECT_EQ(
		ss.wire.sendbuf.tail->len,
		(size_t)(2u * (MUX_FRAME_HEADER_SIZE + 4096u)));
	T_EXPECT_EQ(pool_ctx.free_calls, 1);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* A full-size frame (len == MUX_MAX_FRAME_SIZE) is appended by reference (zero-copy);
 * it does not fit any tail and leaves no spare capacity. */
T_DECLARE_CASE(test_sendbuf_push_full_frame_by_reference)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *f = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(f != NULL);
	make_push_frame(
		f, MUX_MAX_PAYLOAD_SIZE); /* len == MUX_MAX_FRAME_SIZE */

	wire_sendbuf_push(&ss, f);

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT_EQ(ss.wire.sendbuf.tail->len, (size_t)MUX_MAX_FRAME_SIZE);
	/* The frame is by reference, not copied. */
	T_EXPECT(ss.wire.sendbuf.head == f);
	T_EXPECT_EQ(pool_ctx.free_calls, 0);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* wire_discard_buffers frees sendbuf frames (including the packed tail) and
 * resets sendbuf_staging. */
T_DECLARE_CASE(test_sendbuf_discard_clears_staging)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	ss.wire.recvbuf = ringbuf_new(32);
	T_CHECK(ss.wire.recvbuf != NULL);

	/* One entry holding two packed corkable frames (f2 packed onto f1). */
	struct mux_frame *f1 = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *f2 = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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
	/* pool: 2 allocs (f1 + f2); both freed: f2 when packed, f1 on discard. */
	T_EXPECT_EQ(pool_ctx.free_calls, 2);

	ringbuf_free(ss.wire.recvbuf);
}

/* When the open tail already spans more than one record (len == MUX_MAX_FRAME_SIZE)
 * a further frame cannot pack; it starts a new by-reference entry. */
T_DECLARE_CASE(test_sendbuf_push_full_tail_starts_new_entry)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	/* Open a tail and fill it artificially to capacity. */
	struct mux_frame *seed = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(seed != NULL);
	make_ctrl_frame(seed, 1);
	wire_sendbuf_push(&ss, seed); /* opens tail by reference */
	ss.wire.sendbuf.tail->len =
		MUX_MAX_FRAME_SIZE; /* fill it to capacity */

	pool_ctx.alloc_calls = 0;
	pool_ctx.free_calls = 0;

	/* Append a corkable frame — the tail is full, so a new entry is created. */
	struct mux_frame *f2 = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(f2 != NULL);
	make_ctrl_frame(f2, 2);
	wire_sendbuf_push(&ss, f2);

	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)2);
	/* f2 is the new open tail, by reference (not copied). */
	T_EXPECT(ss.wire.sendbuf_staging);
	T_EXPECT(ss.wire.sendbuf.tail == f2);
	T_EXPECT_EQ(ss.wire.sendbuf.tail->len, (size_t)MUX_FRAME_HEADER_SIZE);
	/* After reset: only f2 allocated; nothing freed (f2 kept by reference). */
	T_EXPECT_EQ(pool_ctx.alloc_calls, 1);
	T_EXPECT_EQ(pool_ctx.free_calls, 0);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

/* Packing fills exactly up to one TLS record (MUX_MAX_RECORD) and no further: a
 * frame reaching the record boundary packs, but the next one opens a new entry
 * even though the tail's physical buffer (header + MUX_MAX_PAYLOAD_SIZE) still
 * has room. */
T_DECLARE_CASE(test_sendbuf_push_fills_record_then_new_entry)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	/* Open a tail and advance it to one header short of a full record. */
	struct mux_frame *seed = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(seed != NULL);
	make_ctrl_frame(seed, 1);
	wire_sendbuf_push(&ss, seed);
	ss.wire.sendbuf.tail->len = MUX_MAX_RECORD - MUX_FRAME_HEADER_SIZE;

	/* An 8 B control frame fits exactly to the record boundary: packs. */
	struct mux_frame *fit = mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(fit != NULL);
	make_ctrl_frame(fit, 2);
	wire_sendbuf_push(&ss, fit);
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT_EQ(ss.wire.sendbuf.tail->len, (size_t)MUX_MAX_RECORD);

	/* The next frame would cross the record boundary: new entry, by reference,
	 * even though the tail's buffer still has spare capacity. */
	struct mux_frame *overflow =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(overflow != NULL);
	make_ctrl_frame(overflow, 3);
	wire_sendbuf_push(&ss, overflow);
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)2);
	T_EXPECT(ss.wire.sendbuf.tail == overflow);

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
	T_RUN_CASE(t, test_ringbuf_shrink_reclaims_capacity);
	T_RUN_CASE(t, test_ringbuf_shrink_keeps_live_bytes);
	T_RUN_CASE(t, test_ringbuf_shrink_noop_when_small);
	T_RUN_CASE(t, test_wire_discard_buffers_frees_all_pending_frames);
	T_RUN_CASE(t, test_wire_shutdown_plain_tcp_returns_done);
	T_RUN_CASE(t, test_wire_wait_eof_returns_true_on_clean_peer_close);
	T_RUN_CASE(t, test_sendbuf_push_small_frame_by_reference);
	T_RUN_CASE(t, test_sendbuf_push_second_small_frame_packs_onto_tail);
	T_RUN_CASE(t, test_sendbuf_push_large_frame_by_reference);
	T_RUN_CASE(t, test_sendbuf_push_corkable_packs_onto_large_tail);
	T_RUN_CASE(t, test_sendbuf_push_large_after_corkable_adds_entry);
	T_RUN_CASE(t, test_sendbuf_push_medium_frames_coalesce);
	T_RUN_CASE(t, test_sendbuf_push_full_frame_by_reference);
	T_RUN_CASE(t, test_sendbuf_discard_clears_staging);
	T_RUN_CASE(t, test_sendbuf_push_full_tail_starts_new_entry);
	T_RUN_CASE(t, test_sendbuf_push_fills_record_then_new_entry);
#if WITH_TLS
	T_RUN_CASE(t, test_wire_set_tlsctx_updates_and_noop);
	T_RUN_CASE(t, test_wire_tls_start_noop_when_no_context);
	T_RUN_CASE(t, test_wire_tls_start_creates_outbound_conn);
	T_RUN_CASE(t, test_wire_conn_free_clears_tlsconn);
	T_RUN_CASE(t, test_wire_tls_send_recv_data);
	T_RUN_CASE(t, test_wire_tls_shutdown_completes);
	T_RUN_CASE(t, test_wire_tls_buffered_send_recv);
#endif
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
