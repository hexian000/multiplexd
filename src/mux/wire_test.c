/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* wire_test.c - white-box tests for wire.c (TLS/plain socket I/O, send-buffer
 * staging/coalescing); wire.c #included, real frame.c and TLS backend linked,
 * real socketpairs used; no sibling collaborators mocked. */

#include "mux/wire.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/wire.c"
#if WITH_TLS
#include "shim/tls.h"
#endif

#include "utils/testing.h"

#include <ev.h>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* wire_send's plain-TCP EAGAIN branch: on a nonblocking socket with a tiny send
 * buffer and no reader, a buffer larger than the socket can hold is accepted
 * only in part -- wire_send must return true with 0 <= *len < total (partial
 * write, wait for EV_WRITE), and a second call must return true with *len == 0
 * once the socket is fully congested.  The blocking single-shot send test never
 * reaches this branch. */
T_DECLARE_CASE(test_wire_send_plain_tcp_partial_then_blocked)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	/* Larger than any plausible socket send buffer; static to keep it off the
	 * stack, zero-initialised (contents are irrelevant, nothing reads them). */
	static unsigned char payload[1 << 20];

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	/* Shrink the send buffer so the large write cannot be accepted at once; the
	 * peer never reads, so once it fills, send(2) reports EAGAIN. */
	const int sndbuf = 4096;
	T_CHECK(setsockopt(
			fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
			sizeof(sndbuf)) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);

	/* First call: some bytes go out, then EAGAIN -> partial write, still true. */
	size_t len1 = sizeof(payload);
	const bool ok1 = wire_send(&ss, payload, &len1);
	const bool partial = (len1 < sizeof(payload));

	/* Second call: the buffer is already full, so nothing is accepted. */
	size_t len2 = sizeof(payload);
	const bool ok2 = wire_send(&ss, payload, &len2);

	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(ok1);
	T_EXPECT(partial);
	T_EXPECT(ok2);
	T_EXPECT_EQ(len2, (size_t)0);
}

/* wire_send's plain-TCP hard-error branch: a send on a write-shut socket fails
 * with EPIPE (SIGPIPE is ignored process-wide in main), so wire_send must
 * return false with *len reporting the bytes sent before the error (0 here). */
T_DECLARE_CASE(test_wire_send_plain_tcp_hard_error_returns_false)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char payload[] = "data";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	/* Half-close our own write side: subsequent sends fail hard with EPIPE. */
	T_CHECK(shutdown(fds[0], SHUT_WR) == 0);

	size_t len = sizeof(payload) - 1;
	const bool ok = wire_send(&ss, payload, &len);

	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(!ok);
	T_EXPECT_EQ(len, (size_t)0);
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

T_DECLARE_CASE(test_bytebuf_consume_frame_preserves_remaining_bytes)
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
	ss.wire.recvbuf = bytebuf_new(sizeof(bytes));
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), bytes, sizeof(bytes));
	bytebuf_produce(ss.wire.recvbuf, sizeof(bytes));

	bytebuf_consume(ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE + 1);
	T_EXPECT_EQ(
		bytebuf_readable(ss.wire.recvbuf),
		sizeof(bytes) - ((size_t)MUX_FRAME_HEADER_SIZE + 1));
	T_EXPECT(
		bytebuf_read_ptr(ss.wire.recvbuf)[MUX_FRAME_HEADER_SIZE] ==
		'B');
	bytebuf_free(ss.wire.recvbuf);
}

T_DECLARE_CASE(test_bytebuf_consume_advances_offset_without_copy)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	unsigned char bytes[2 * MUX_FRAME_HEADER_SIZE] = { 0 };

	ss.wire.recvbuf = bytebuf_new(sizeof(bytes));
	T_CHECK(ss.wire.recvbuf != NULL);
	memcpy(bytebuf_write_ptr(ss.wire.recvbuf), bytes, sizeof(bytes));
	bytebuf_produce(ss.wire.recvbuf, sizeof(bytes));

	bytebuf_consume(ss.wire.recvbuf, MUX_FRAME_HEADER_SIZE);
	T_EXPECT_EQ(ss.wire.recvbuf->off, (size_t)MUX_FRAME_HEADER_SIZE);
	T_EXPECT_EQ(
		bytebuf_readable(ss.wire.recvbuf),
		sizeof(bytes) - (size_t)MUX_FRAME_HEADER_SIZE);
	bytebuf_free(ss.wire.recvbuf);
}

/* bytebuf_shrink reclaims a grown buffer down to the target, compacting the
 * live bytes to the front and preserving them. */
T_DECLARE_CASE(test_bytebuf_shrink_reclaims_capacity)
{
	struct bytebuf *rb = bytebuf_new(4096);
	T_CHECK(rb != NULL);
	memset(bytebuf_write_ptr(rb), 'X', 100);
	bytebuf_produce(rb, 100);
	bytebuf_consume(rb, 10); /* off=10, len=90: forces compaction */
	T_EXPECT_EQ(rb->cap, (size_t)4096);

	bytebuf_shrink(&rb, 256);

	T_EXPECT_EQ(rb->cap, (size_t)256);
	T_EXPECT_EQ(rb->off, (size_t)0);
	T_EXPECT_EQ(bytebuf_readable(rb), (size_t)90);
	const unsigned char *const p = bytebuf_read_ptr(rb);
	bool intact = true;
	for (size_t i = 0; i < 90; i++) {
		intact = intact && (p[i] == 'X');
	}
	T_EXPECT(intact);
	bytebuf_free(rb);
}

/* bytebuf_shrink never drops below the live byte count, even when the target is
 * smaller. */
T_DECLARE_CASE(test_bytebuf_shrink_keeps_live_bytes)
{
	struct bytebuf *rb = bytebuf_new(4096);
	T_CHECK(rb != NULL);
	memset(bytebuf_write_ptr(rb), 'Y', 500);
	bytebuf_produce(rb, 500); /* len=500 > target */

	bytebuf_shrink(&rb, 256);

	T_EXPECT_EQ(rb->cap, (size_t)500);
	T_EXPECT_EQ(bytebuf_readable(rb), (size_t)500);
	bytebuf_free(rb);
}

/* bytebuf_shrink is a no-op when the capacity is already at or below target. */
T_DECLARE_CASE(test_bytebuf_shrink_noop_when_small)
{
	struct bytebuf *rb = bytebuf_new(128);
	T_CHECK(rb != NULL);

	bytebuf_shrink(&rb, 256);

	T_EXPECT_EQ(rb->cap, (size_t)128);
	bytebuf_free(rb);
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
	ss.wire.recvbuf = bytebuf_new(32);
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
	bytebuf_free(ss.wire.recvbuf);
}

/* wire_has_pending had zero test references. Its body is
 * compiled entirely differently per WITH_TLS (a field read vs. an always-false
 * stub), so exercise whichever variant this build actually has. */
T_DECLARE_CASE(test_wire_has_pending_reflects_build_variant)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

#if WITH_TLS
	ss.wire.tls_readable = false;
	T_EXPECT(!wire_has_pending(&ss));
	ss.wire.tls_readable = true;
	T_EXPECT(wire_has_pending(&ss));
#else
	T_EXPECT(!wire_has_pending(&ss));
#endif
}

/* wire_flush's WIRE_FLUSH_DONE outcome (no TLS, or TLS with
 * socket offload so the library drives the fd directly) had no direct test;
 * only the BLOCKED/ERROR memory-transport outcomes below did, indirectly. */
T_DECLARE_CASE(test_wire_flush_done_without_memory_transport_tls)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	T_EXPECT_EQ(wire_flush(&ss), WIRE_FLUSH_DONE);

#if WITH_TLS
	/* tls_socket_offload defaults true in make_session; a non-NULL tlsconn
	 * must still resolve to DONE without ever touching wire_cipher_push.
	 * Use the address of a local as a type-safe non-NULL sentinel; this path
	 * never dereferences tlsconn. */
	unsigned char sentinel;
	ss.wire.tlsconn = (struct tls_connection *)&sentinel;
	T_EXPECT_EQ(wire_flush(&ss), WIRE_FLUSH_DONE);
	ss.wire.tlsconn = NULL;
#endif /* WITH_TLS */
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

T_DECLARE_CASE(test_wire_wait_eof_confirmed_on_clean_peer_close)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(shutdown(fds[1], SHUT_WR) == 0);

	T_EXPECT_EQ(wire_wait_eof(&ss), WIRE_EOF_CONFIRMED);

	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* A spurious wakeup with nothing pending yet (EAGAIN, no
 * shutdown on the peer's side) must report WIRE_EOF_PENDING, distinguishable
 * from a confirmed close -- previously both were the same boolean true. */
T_DECLARE_CASE(test_wire_wait_eof_pending_on_eagain)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	/* Peer's socket left open and silent: fds[0] has nothing to read and no
	 * FIN, so socket_recv reports EAGAIN rather than EOF. */

	T_EXPECT_EQ(wire_wait_eof(&ss), WIRE_EOF_PENDING);

	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* Unexpected application data after the local shutdown must be reported as a
 * hard error, not confused with either a confirmed close or a pending one. */
T_DECLARE_CASE(test_wire_wait_eof_error_on_unexpected_data)
{
	int fds[2];
	struct frame_pool_ctx pool_ctx = { 0 };
	unsigned char stray[] = "oops";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(write(fds[1], stray, sizeof(stray) - 1) ==
		(ssize_t)(sizeof(stray) - 1));

	T_EXPECT_EQ(wire_wait_eof(&ss), WIRE_EOF_ERROR);

	(void)close(fds[0]);
	(void)close(fds[1]);
}

#if WITH_TLS

/* Self-signed RSA-4096 certificate (CN/subjectAltName=DNS:test.example) and its
 * private key, in memory so they work with every TLS backend; identical to the
 * embedded cert in shim/tls_test.c. */
static const char wire_test_cert_pem[] =
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

static const char wire_test_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"NL+YLwobqSZhkl4iZWt2wGODitzp/aQ=\n"
	"-----END PRIVATE KEY-----\n";

/* Build a mutual-auth TLS server context from the embedded self-signed cert/key,
 * passed inline as PEM (tls_config accepts PEM data directly); the same
 * self-signed cert is trusted as the authorized peer.  Returns NULL on failure.
 * No temp files, no process-global chdir. */
static struct tls_context *wire_test_server_ctx(void)
{
	char *authcerts[] = { (char *)wire_test_cert_pem };
	return tls_ctx_server(&(struct tls_config){
		.cert = wire_test_cert_pem,
		.key = wire_test_key_pem,
		.authcerts = authcerts,
		.authcerts_count = 1,
	});
}

/* As wire_test_server_ctx, but a client context (verifies the peer against the
 * same embedded cert). */
static struct tls_context *wire_test_client_ctx(void)
{
	char *authcerts[] = { (char *)wire_test_cert_pem };
	return tls_ctx_client(&(struct tls_config){
		.cert = wire_test_cert_pem,
		.key = wire_test_key_pem,
		.authcerts = authcerts,
		.authcerts_count = 1,
	});
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

T_DECLARE_CASE(test_wire_set_tlsctx_updates)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	/* Use the address of a local variable as a type-safe non-NULL sentinel.
	 * wire_set_tlsctx only stores the pointer and never dereferences it. */
	unsigned char sentinel;
	struct tls_context *const fake = (struct tls_context *)&sentinel;

	/* NULL -> fake: must update. */
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
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, fds[1]);
	/* Set only tlsctx; wire_tls_start must create tlsconn via tls_client. */
	ss.wire.tlsctx = cli_ctx;
	const bool started = wire_tls_start(&ss);
	const bool has_conn = (ss.wire.tlsconn != NULL);

	wire_conn_free(&ss);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(started);
	T_EXPECT(has_conn);
}

T_DECLARE_CASE(test_wire_conn_free_clears_tlsconn)
{
	struct tls_context *const ctx = wire_test_server_ctx();
	T_CHECK(ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	/* tls_server with a valid fd creates the SSL object without I/O. */
	struct tls_connection *const conn = tls_server(ctx, fds[0]);
	T_CHECK(conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, fds[0]);
	ss.wire.tlsconn = conn;
	wire_conn_free(&ss);
	const bool cleared = (ss.wire.tlsconn == NULL);

	tls_ctx_free(ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(cleared);
}

T_DECLARE_CASE(test_wire_tls_send_recv_data)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
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
	const bool send_ok = wire_send(&cli_ss, send_buf, &slen);
	/* AF_UNIX delivers synchronously on Linux but asynchronously on
	 * Windows/msys2: retry wire_recv waiting for readability until the
	 * payload arrives. */
	bool recv_ok = true;
	size_t got = 0;
	for (int i = 0; i < 20 && got == 0; i++) {
		rlen = sizeof(recv_buf) - 1;
		if (!wire_recv(&srv_ss, recv_buf, &rlen)) {
			recv_ok = false;
			break;
		}
		got = rlen;
		if (got == 0) {
			struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
			(void)poll(&pfd, 1, 100);
		}
	}
	const bool payload_ok =
		(got == sizeof(send_buf) - 1 &&
		 memcmp(recv_buf, send_buf, got) == 0);

	/* Prevent double-free: clear wire pointers before explicit conn_free. */
	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(send_ok);
	T_EXPECT_EQ(slen, sizeof(send_buf) - 1);
	T_EXPECT(recv_ok);
	T_EXPECT(payload_ok);
}

T_DECLARE_CASE(test_wire_tls_shutdown_completes)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(wire_test_drive_handshake(srv_conn, cli_conn, 20));

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;

	/* Drive TLS shutdown cooperatively until both sides complete. */
	bool cli_done = false, srv_done = false, no_error = true;
	for (int i = 0; i < 10 && !(cli_done && srv_done); i++) {
		if (!cli_done) {
			const enum wire_shutdown_state s =
				wire_shutdown(&cli_ss);
			if (s == WIRE_SHUTDOWN_ERROR) {
				no_error = false;
				break;
			}
			if (s == WIRE_SHUTDOWN_DONE) {
				cli_done = true;
			}
		}
		if (!srv_done) {
			const enum wire_shutdown_state s =
				wire_shutdown(&srv_ss);
			if (s == WIRE_SHUTDOWN_ERROR) {
				no_error = false;
				break;
			}
			if (s == WIRE_SHUTDOWN_DONE) {
				srv_done = true;
			}
		}
	}

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(no_error);
	T_EXPECT(cli_done);
	T_EXPECT(srv_done);
}

/* End-to-end memory transport (tls.socket_offload disabled): wire_send/wire_recv
 * own the socketpair while the TLS library works in memory.  Drives the full
 * mutual-auth handshake and a bidirectional payload exchange through the wire API. */
T_DECLARE_CASE(test_wire_tls_buffered_send_recv)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	/* Buffered connections pass fd=-1; wire.c drives the socket. */
	struct tls_connection *const srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, -1);
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

	/* A send issued before the handshake completes stalls cross-direction:
	 * the client has flushed its ClientHello but cannot encrypt app data
	 * until it reads the server's flight, so wire_send takes 0 plaintext
	 * bytes and records EV_READ (not EV_WRITE) in wire.tls_want for the
	 * caller to arm. Asserting the direction here guards against an
	 * EV_READ/EV_WRITE swap or a dropped assignment, which the convergent
	 * exchange loop below would otherwise still succeed through. */
	size_t probe = sizeof(cli_msg) - 1;
	T_CHECK(wire_send(&cli_ss, cli_msg, &probe));
	const bool probe_zero = (probe == 0);
	const bool probe_want_read = (cli_ss.wire.tls_want == EV_READ);

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

	const bool srv_payload_ok =
		(srv_got == sizeof(cli_msg) - 1 &&
		 memcmp(srv_rx, cli_msg, srv_got) == 0);
	const bool cli_payload_ok =
		(cli_got == sizeof(srv_msg) - 1 &&
		 memcmp(cli_rx, srv_msg, cli_got) == 0);

	/* Buffered close: the client's close_notify must reach the socket and the
	 * server must observe a clean EOF through the buffered recv path. */
	const bool shutdown_done =
		(wire_shutdown(&cli_ss) == WIRE_SHUTDOWN_DONE);
	srv_ss.wire.rx_open = true;
	bool srv_eof = false;
	for (int i = 0; i < 20 && !srv_eof; i++) {
		size_t rn = sizeof(srv_rx);
		T_CHECK(wire_recv(&srv_ss, srv_rx, &rn));
		srv_eof = srv_ss.wire.rx_eof;
	}

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	bytebuf_free(srv_ss.wire.rawbuf);
	bytebuf_free(cli_ss.wire.rawbuf);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(probe_zero);
	T_EXPECT(probe_want_read);
	T_EXPECT(srv_payload_ok);
	T_EXPECT(cli_payload_ok);
	T_EXPECT(shutdown_done);
	T_EXPECT(srv_eof);
}

/* Regression: a wire_cipher_push failure landing in the TLS_ERROR_ZERO_RETURN
 * branch (peer close_notify arriving as the transport can no longer send)
 * must be reported as a hard failure, not swallowed into a clean-close. */
T_DECLARE_CASE(test_wire_recv_buffered_zero_return_reports_push_failure)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	/* Buffered connections pass fd=-1; wire.c drives the socket. */
	struct tls_connection *const srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, -1);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;
	srv_ss.conf.tls_socket_offload = false;
	cli_ss.conf.tls_socket_offload = false;

	/* Complete the handshake (mirrors test_wire_tls_buffered_send_recv). */
	unsigned char cli_msg[] = "ping", srv_msg[] = "pong";
	unsigned char cli_rx[4096] = { 0 }, srv_rx[4096] = { 0 };
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
	T_CHECK(srv_got > 0 && cli_got > 0);

	/* Client sends its close_notify via wire_shutdown; wait until the
	 * ciphertext is queued and readable on the server's socket, without
	 * consuming it, so wire_recv_buffered itself decrypts the alert. */
	const bool shutdown_done =
		(wire_shutdown(&cli_ss) == WIRE_SHUTDOWN_DONE);
	bool readable = false;
	for (int i = 0; i < 50 && !readable; i++) {
		struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
		readable = poll(&pfd, 1, 20) > 0;
	}
	T_CHECK(readable);

	/* Arm the failure: stage unflushed ciphertext residue and shut down
	 * the server's own send direction, so the next wire_cipher_push
	 * observes a hard EPIPE instead of EAGAIN. */
	T_CHECK(srv_ss.wire.rawbuf != NULL);
	T_CHECK(bytebuf_write_space(srv_ss.wire.rawbuf) >= 16);
	memset(bytebuf_write_ptr(srv_ss.wire.rawbuf), 'x', 16);
	bytebuf_produce(srv_ss.wire.rawbuf, 16);
	T_CHECK(shutdown(fds[0], SHUT_WR) == 0);

	srv_ss.wire.rx_open = true;
	size_t rn = sizeof(srv_rx);
	const bool recv_failed = !wire_recv_buffered(&srv_ss, srv_rx, &rn);
	const bool rx_closed = !srv_ss.wire.rx_open;

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	bytebuf_free(srv_ss.wire.rawbuf);
	bytebuf_free(cli_ss.wire.rawbuf);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(shutdown_done);
	T_EXPECT(recv_failed);
	T_EXPECT(rx_closed);
	T_EXPECT_EQ(rn, (size_t)0);
}

/* wire_flush's WIRE_FLUSH_BLOCKED/WIRE_FLUSH_ERROR outcomes
 * (memory-transport TLS only -- socket-offload bypasses wire_cipher_push
 * entirely) had zero direct test references. */
T_DECLARE_CASE(test_wire_flush_blocked_on_partial_socket_write)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, -1);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;
	srv_ss.conf.tls_socket_offload = false;
	cli_ss.conf.tls_socket_offload = false;

	/* Complete the handshake (mirrors test_wire_tls_buffered_send_recv). */
	unsigned char cli_msg[] = "ping", srv_msg[] = "pong";
	unsigned char cli_rx[4096] = { 0 }, srv_rx[4096] = { 0 };
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
	T_CHECK(srv_got > 0 && cli_got > 0);

	/* Stage far more raw bytes than any realistic kernel socket buffer can
	 * accept in one send(2): wire_cipher_push's own partial-write check
	 * (wire.c: "nbytes < avail") reports this as EAGAIN without needing the
	 * peer to stop reading or the buffer to already be completely full. */
	enum { STAGE_BYTES = 8 * 1024 * 1024 };
	T_CHECK(srv_ss.wire.rawbuf != NULL);
	T_CHECK(bytebuf_reserve(&srv_ss.wire.rawbuf, STAGE_BYTES, true));
	memset(bytebuf_write_ptr(srv_ss.wire.rawbuf), 'x', STAGE_BYTES);
	bytebuf_produce(srv_ss.wire.rawbuf, STAGE_BYTES);

	const bool flush_blocked = (wire_flush(&srv_ss) == WIRE_FLUSH_BLOCKED);
	/* Residue must survive a BLOCKED outcome, to retry on the next wakeup. */
	const bool residue_kept = (bytebuf_readable(srv_ss.wire.rawbuf) > 0);

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	bytebuf_free(srv_ss.wire.rawbuf);
	bytebuf_free(cli_ss.wire.rawbuf);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(flush_blocked);
	T_EXPECT(residue_kept);
}

T_DECLARE_CASE(test_wire_flush_error_on_hard_send_failure)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, -1);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;
	srv_ss.conf.tls_socket_offload = false;
	cli_ss.conf.tls_socket_offload = false;

	/* Complete the handshake (mirrors test_wire_tls_buffered_send_recv). */
	unsigned char cli_msg[] = "ping", srv_msg[] = "pong";
	unsigned char cli_rx[4096] = { 0 }, srv_rx[4096] = { 0 };
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
	T_CHECK(srv_got > 0 && cli_got > 0);

	/* Same technique as test_wire_recv_buffered_zero_return_reports_push_failure:
	 * shut down the server's own send direction so the next attempt to write
	 * staged residue observes a hard EPIPE instead of EAGAIN. */
	T_CHECK(srv_ss.wire.rawbuf != NULL);
	T_CHECK(bytebuf_write_space(srv_ss.wire.rawbuf) >= 16);
	memset(bytebuf_write_ptr(srv_ss.wire.rawbuf), 'x', 16);
	bytebuf_produce(srv_ss.wire.rawbuf, 16);
	T_CHECK(shutdown(fds[0], SHUT_WR) == 0);

	const bool flush_error = (wire_flush(&srv_ss) == WIRE_FLUSH_ERROR);

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	bytebuf_free(srv_ss.wire.rawbuf);
	bytebuf_free(cli_ss.wire.rawbuf);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(flush_error);
}

/* wire_adopt_tlsconn (resume-handoff hook) has two obligations: free any
 * pre-existing tlsconn on the target, and rebind the TLS I/O notifier to ss so
 * it never fires on the transient session that carried the resume hello.  This
 * installs conn_old on ss, binds a second memory-backed client conn's notifier
 * to a *different* (transient) session, then adopts it onto ss.  After the swap,
 * driving conn's handshake stages its ClientHello, firing on_send: it must set
 * ss's tx_pending (the rebound target), never the transient session's.  A
 * missed rebind is a use-after-free once the transient session is torn down. */
T_DECLARE_CASE(test_wire_adopt_tlsconn_swaps_and_rebinds_notifier)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	/* Pre-existing connection on ss that adopt must free. */
	struct tls_connection *const conn_old = tls_server(srv_ctx, -1);
	/* Memory-backed client that will produce a ClientHello when driven. */
	struct tls_connection *const conn_new = tls_client(cli_ctx, -1);
	T_CHECK(conn_old != NULL);
	T_CHECK(conn_new != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);
	struct mux_session transient_ss = make_session(&pool_ctx, -1);
	ss.wire.tlsconn = conn_old;

	/* Bind conn_new's notifier to the transient session, mirroring how a
	 * resume hello's connection is created before ss exists. */
	const struct tls_callback transient_cb = {
		.ctx = &transient_ss,
		.on_send = wire_on_tls_send,
		.on_recv = wire_on_tls_recv,
	};
	tls_set_callback(conn_new, &transient_cb);

	wire_adopt_tlsconn(&ss, conn_new);
	const bool swapped = (ss.wire.tlsconn == conn_new);

	/* Fire the notifier: a memory-backed client's first handshake stages the
	 * ClientHello, which the backend reports via on_send. */
	const enum tls_error herr = tls_handshake(conn_new);
	const bool handshake_progressing =
		(herr == TLS_ERROR_WANT_READ || herr == TLS_ERROR_WANT_WRITE ||
		 herr == TLS_ERROR_NONE);
	const bool fired_on_ss = ss.wire.tx_pending;
	const bool not_fired_on_transient = !transient_ss.wire.tx_pending;

	ss.wire.tlsconn = NULL;
	tls_conn_free(conn_new);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	T_EXPECT(swapped);
	T_EXPECT(handshake_progressing);
	T_EXPECT(fired_on_ss);
	T_EXPECT(not_fired_on_transient);
}

/* wire_wait_eof memory-transport branch (tlsconn != NULL, socket_offload
 * disabled): it must drain the socket itself, feed the ciphertext to tls_input,
 * and map the peer's close_notify (tls_recv -> TLS_ERROR_ZERO_RETURN) to
 * WIRE_EOF_CONFIRMED.  Only the plain-TCP tail was covered before. */
T_DECLARE_CASE(test_wire_wait_eof_tls_buffered_confirmed)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, -1);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;
	srv_ss.conf.tls_socket_offload = false;
	cli_ss.conf.tls_socket_offload = false;

	/* Complete the handshake (mirrors test_wire_tls_buffered_send_recv). */
	unsigned char cli_msg[] = "ping", srv_msg[] = "pong";
	unsigned char cli_rx[4096] = { 0 }, srv_rx[4096] = { 0 };
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
	T_CHECK(srv_got > 0 && cli_got > 0);

	/* Send ONLY the client's close_notify record, with no TCP FIN, so the
	 * server's sole route to a confirmed EOF is wire_wait_eof decrypting the
	 * alert to TLS_ERROR_ZERO_RETURN -- not the clen==0 TCP-FIN shortcut.
	 * wire_shutdown would also half-close the socket and mask that mapping. */
	T_CHECK(tls_shutdown(cli_conn) == TLS_ERROR_NONE);
	T_CHECK(wire_flush(&cli_ss) == WIRE_FLUSH_DONE);
	enum wire_eof_result eof = WIRE_EOF_PENDING;
	for (int i = 0; i < 50 && eof == WIRE_EOF_PENDING; i++) {
		struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
		(void)poll(&pfd, 1, 20);
		eof = wire_wait_eof(&srv_ss);
	}
	const bool confirmed = (eof == WIRE_EOF_CONFIRMED);

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	bytebuf_free(srv_ss.wire.rawbuf);
	bytebuf_free(cli_ss.wire.rawbuf);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(confirmed);
}

/* wire_wait_eof socket-offload branch (tlsconn != NULL, socket_offload
 * enabled): tls_recv drives the fd directly; unexpected application data
 * arriving after the local shutdown (TLS_ERROR_NONE with nread > 0) must map to
 * WIRE_EOF_ERROR, not a confirmed or pending close. */
T_DECLARE_CASE(test_wire_wait_eof_tls_offload_error_on_appdata)
{
	struct tls_context *const srv_ctx = wire_test_server_ctx();
	struct tls_context *const cli_ctx = wire_test_client_ctx();
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	/* fd-backed connections: the library drives the socket (socket offload). */
	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(wire_test_drive_handshake(srv_conn, cli_conn, 20));

	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session srv_ss = make_session(&pool_ctx, fds[0]);
	struct mux_session cli_ss = make_session(&pool_ctx, fds[1]);
	srv_ss.wire.tlsconn = srv_conn;
	cli_ss.wire.tlsconn = cli_conn;
	/* socket offload stays enabled (the make_session default). */

	/* Client sends application data instead of a close_notify. */
	unsigned char stray[] = "surprise";
	size_t slen = sizeof(stray) - 1;
	T_CHECK(wire_send(&cli_ss, stray, &slen));

	/* Server treats this as post-shutdown data: wait for it to arrive, then
	 * wire_wait_eof (offload path) must report ERROR, not PENDING/CONFIRMED. */
	enum wire_eof_result eof = WIRE_EOF_PENDING;
	for (int i = 0; i < 50 && eof == WIRE_EOF_PENDING; i++) {
		struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
		(void)poll(&pfd, 1, 20);
		eof = wire_wait_eof(&srv_ss);
	}
	const bool is_error = (eof == WIRE_EOF_ERROR);

	srv_ss.wire.tlsconn = NULL;
	cli_ss.wire.tlsconn = NULL;
	tls_conn_free(srv_conn);
	tls_conn_free(cli_conn);
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(is_error);
}

#endif /* WITH_TLS */

/* A corkable frame (8 B control) with no open tail is appended by reference and
 * becomes the open tail; the frame itself is the entry (no copy, no spare
 * alloc). */
T_DECLARE_CASE(test_sendbuf_push_small_frame_by_reference)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	struct mux_frame *const f =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	struct mux_frame *const f1 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const f2 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	struct mux_frame *const f =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	struct mux_frame *const large =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const small =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	struct mux_frame *const small =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const large =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	struct mux_frame *const m1 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const m2 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	struct mux_frame *const f =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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
	ss.wire.recvbuf = bytebuf_new(32);
	T_CHECK(ss.wire.recvbuf != NULL);

	/* One entry holding two packed corkable frames (f2 packed onto f1). */
	struct mux_frame *const f1 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	struct mux_frame *const f2 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

	bytebuf_free(ss.wire.recvbuf);
}

/* When the open tail already spans more than one record (len == MUX_MAX_FRAME_SIZE)
 * a further frame cannot pack; it starts a new by-reference entry. */
T_DECLARE_CASE(test_sendbuf_push_full_tail_starts_new_entry)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	/* Open a tail and fill it artificially to capacity. */
	struct mux_frame *const seed =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(seed != NULL);
	make_ctrl_frame(seed, 1);
	wire_sendbuf_push(&ss, seed); /* opens tail by reference */
	ss.wire.sendbuf.tail->len =
		MUX_MAX_FRAME_SIZE; /* fill it to capacity */

	pool_ctx.alloc_calls = 0;
	pool_ctx.free_calls = 0;

	/* Append a corkable frame — the tail is full, so a new entry is created. */
	struct mux_frame *const f2 =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
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

/* Packing fills exactly one TLS record (MUX_MAX_RECORD); a frame at the
 * boundary packs, but the next opens a new entry even though the tail's
 * physical buffer still has room. */
T_DECLARE_CASE(test_sendbuf_push_fills_record_then_new_entry)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx, -1);

	/* Open a tail and advance it to one header short of a full record. */
	struct mux_frame *const seed =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(seed != NULL);
	make_ctrl_frame(seed, 1);
	wire_sendbuf_push(&ss, seed);
	ss.wire.sendbuf.tail->len = MUX_MAX_RECORD - MUX_FRAME_HEADER_SIZE;

	/* An 8 B control frame fits exactly to the record boundary: packs. */
	struct mux_frame *const fit =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(fit != NULL);
	make_ctrl_frame(fit, 2);
	wire_sendbuf_push(&ss, fit);
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)1);
	T_EXPECT_EQ(ss.wire.sendbuf.tail->len, (size_t)MUX_MAX_RECORD);

	/* The next frame would cross the record boundary: new entry, by reference,
	 * even though the tail's buffer still has spare capacity. */
	struct mux_frame *const overflow =
		mux_frame_get(&ss.pool, MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(overflow != NULL);
	make_ctrl_frame(overflow, 3);
	wire_sendbuf_push(&ss, overflow);
	T_EXPECT_EQ(ss.wire.sendbuf.count, (size_t)2);
	T_EXPECT(ss.wire.sendbuf.tail == overflow);

	mux_frame_list_clear(&ss.wire.sendbuf, &ss.pool);
}

static const struct testing_suite suite[] = {
	T_CASE(test_wire_send_plain_tcp_writes_bytes),
	T_CASE(test_wire_send_plain_tcp_partial_then_blocked),
	T_CASE(test_wire_send_plain_tcp_hard_error_returns_false),
	T_CASE(test_wire_recv_plain_tcp_reads_payload),
	T_CASE(test_wire_recv_eof_clears_rx_open_and_sets_tx_pending),
	T_CASE(test_bytebuf_consume_frame_preserves_remaining_bytes),
	T_CASE(test_bytebuf_consume_advances_offset_without_copy),
	T_CASE(test_bytebuf_shrink_reclaims_capacity),
	T_CASE(test_bytebuf_shrink_keeps_live_bytes),
	T_CASE(test_bytebuf_shrink_noop_when_small),
	T_CASE(test_wire_discard_buffers_frees_all_pending_frames),
	T_CASE(test_wire_has_pending_reflects_build_variant),
	T_CASE(test_wire_flush_done_without_memory_transport_tls),
	T_CASE(test_wire_shutdown_plain_tcp_returns_done),
	T_CASE(test_wire_wait_eof_confirmed_on_clean_peer_close),
	T_CASE(test_wire_wait_eof_pending_on_eagain),
	T_CASE(test_wire_wait_eof_error_on_unexpected_data),
	T_CASE(test_sendbuf_push_small_frame_by_reference),
	T_CASE(test_sendbuf_push_second_small_frame_packs_onto_tail),
	T_CASE(test_sendbuf_push_large_frame_by_reference),
	T_CASE(test_sendbuf_push_corkable_packs_onto_large_tail),
	T_CASE(test_sendbuf_push_large_after_corkable_adds_entry),
	T_CASE(test_sendbuf_push_medium_frames_coalesce),
	T_CASE(test_sendbuf_push_full_frame_by_reference),
	T_CASE(test_sendbuf_discard_clears_staging),
	T_CASE(test_sendbuf_push_full_tail_starts_new_entry),
	T_CASE(test_sendbuf_push_fills_record_then_new_entry),
#if WITH_TLS
	T_CASE(test_wire_set_tlsctx_updates),
	T_CASE(test_wire_tls_start_noop_when_no_context),
	T_CASE(test_wire_tls_start_creates_outbound_conn),
	T_CASE(test_wire_conn_free_clears_tlsconn),
	T_CASE(test_wire_tls_send_recv_data),
	T_CASE(test_wire_tls_shutdown_completes),
	T_CASE(test_wire_tls_buffered_send_recv),
	T_CASE(test_wire_recv_buffered_zero_return_reports_push_failure),
	T_CASE(test_wire_flush_blocked_on_partial_socket_write),
	T_CASE(test_wire_flush_error_on_hard_send_failure),
	T_CASE(test_wire_adopt_tlsconn_swaps_and_rebinds_notifier),
	T_CASE(test_wire_wait_eof_tls_buffered_confirmed),
	T_CASE(test_wire_wait_eof_tls_offload_error_on_appdata),
#endif /* WITH_TLS */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* A broken send direction (used to force a hard wire_cipher_push
	 * failure) raises SIGPIPE by default; the test process must survive it. */
	T_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	return testing_main(argc, argv, suite);
}
