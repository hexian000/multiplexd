/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* tls_mbedtls_test.c - white-box tests for the mbedTLS backend's static
 * error-classification helpers (map_io_error and the socket-offload BIO
 * callbacks tls_bio_send / tls_bio_recv), for what its opaque context retains,
 * and for its server-side PSK identity checks (psk_lookup_cb).  None is
 * reachable through the public tls.h API: the codes the helpers translate come
 * from the library or from the kernel, so no black-box handshake can present a
 * chosen one; the context layout is private; and the public API only ever
 * offers a well-formed derived PSK label, so no handshake hands psk_lookup_cb a
 * hostile identity.  Also the backend's PSA start-up, which only this TU can
 * observe: it resets the library's global PSA state so a case sees it as a
 * fresh process would, whatever ran before.  This TU compiles tls_mbedtls.c
 * directly (its symbols are internal to this file, so it must not link `shim`)
 * to exercise them in isolation.  The BIO callbacks run over a real
 * non-blocking socketpair for every errno the kernel produces on demand, and
 * through a send()/recv() seam for the ones it does not. */

/* WITH_TLS comes from the force-included config.h, as in tls_mbedtls.c. */
#if WITH_TLS

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

/* The errno the next send() or recv() the backend makes fails with, before it
 * reaches the socket; 0 lets the call through.  One-shot, so a retried call
 * reaches the real socket.  Nothing else makes a socket report ENOBUFS, ENOMEM
 * or ECONNRESET on demand, nor interrupts a non-blocking call with EINTR. */
static int bio_fault_errno;

static ssize_t
bio_fault_send(const int fd, const void *buf, const size_t len, const int flags)
{
	if (bio_fault_errno != 0) {
		errno = bio_fault_errno;
		bio_fault_errno = 0;
		return -1;
	}
	return send(fd, buf, len, flags);
}

static ssize_t
bio_fault_recv(const int fd, void *buf, const size_t len, const int flags)
{
	if (bio_fault_errno != 0) {
		errno = bio_fault_errno;
		bio_fault_errno = 0;
		return -1;
	}
	return recv(fd, buf, len, flags);
}

/* Route the backend's socket calls through the seam above.  <sys/socket.h> is
 * already included, so only the call sites below are rewritten. */
#define send(fd, buf, len, flags) bio_fault_send((fd), (buf), (len), (flags))
#define recv(fd, buf, len, flags) bio_fault_recv((fd), (buf), (len), (flags))

/* Compile the backend into this TU to reach its static helpers. */
#include "tls_mbedtls.c"

#include "meta/arraysize.h"
#include "os/socket.h"
#include "tls.h"
#include "utils/testing.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* A TLS 1.3 client is handed MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET once
 * per post-handshake NewSessionTicket.  The library documents it as non-fatal
 * -- retry the read -- so it must not fall into map_io_error's default arm,
 * which reports TLS_ERROR_SSL and makes the caller tear the session down. */
T_DECLARE_CASE(test_map_io_error_new_session_ticket_is_retriable)
{
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
	T_EXPECT_EQ(
		map_io_error(
			MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET, "test"),
		TLS_ERROR_WANT_READ);
#else
	T_LOG("mbedTLS built without client-side session tickets");
	T_SKIPNOW();
#endif
}

/* The rest of the mapping must be unchanged by the arm above. */
T_DECLARE_CASE(test_map_io_error_classifies_known_codes)
{
	T_EXPECT_EQ(map_io_error(0, "test"), TLS_ERROR_NONE);
	T_EXPECT_EQ(
		map_io_error(MBEDTLS_ERR_SSL_WANT_READ, "test"),
		TLS_ERROR_WANT_READ);
	T_EXPECT_EQ(
		map_io_error(MBEDTLS_ERR_SSL_WANT_WRITE, "test"),
		TLS_ERROR_WANT_WRITE);
	T_EXPECT_EQ(
		map_io_error(MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, "test"),
		TLS_ERROR_ZERO_RETURN);
	T_EXPECT_EQ(
		map_io_error(MBEDTLS_ERR_NET_CONN_RESET, "test"),
		TLS_ERROR_SYSCALL);
	T_EXPECT_EQ(
		map_io_error(MBEDTLS_ERR_SSL_BAD_INPUT_DATA, "test"),
		TLS_ERROR_SSL);
}

/* A connected, non-blocking AF_UNIX stream pair, as the offload BIO sees its
 * TCP socket: fds[0] is the BIO's end, fds[1] the peer's. */
static void bio_pair_open(int fds[2])
{
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(socket_set_nonblock(fds[0]) == 0);
	T_CHECK(socket_set_nonblock(fds[1]) == 0);
}

static void *bio_ctx(const int fd)
{
	return (void *)(intptr_t)fd;
}

/* Bytes pass through both callbacks unchanged, and a read of an empty socket
 * is WANT_READ: mbedTLS retries it once the loop reports the fd readable. */
T_DECLARE_CASE(test_bio_moves_bytes_and_empty_read_wants_read)
{
	int fds[2];
	bio_pair_open(fds);
	unsigned char buf[8];

	T_EXPECT_EQ(
		tls_bio_recv(bio_ctx(fds[0]), buf, sizeof(buf)),
		MBEDTLS_ERR_SSL_WANT_READ);

	static const unsigned char msg[] = "ping";
	T_EXPECT_EQ(
		tls_bio_send(bio_ctx(fds[0]), msg, sizeof(msg)),
		(int)sizeof(msg));
	T_EXPECT_EQ(recv(fds[1], buf, sizeof(buf), 0), (ssize_t)sizeof(msg));
	T_EXPECT_EQ(memcmp(buf, msg, sizeof(msg)), 0);

	T_EXPECT_EQ(send(fds[1], msg, sizeof(msg), 0), (ssize_t)sizeof(msg));
	T_EXPECT_EQ(
		tls_bio_recv(bio_ctx(fds[0]), buf, sizeof(buf)),
		(int)sizeof(msg));
	T_EXPECT_EQ(memcmp(buf, msg, sizeof(msg)), 0);

	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* A full kernel send buffer is backpressure: WANT_WRITE, never a send failure
 * that would tear the whole TLS+mux session down. */
T_DECLARE_CASE(test_bio_full_send_buffer_wants_write)
{
	int fds[2];
	bio_pair_open(fds);
	static const unsigned char chunk[4096];

	int ret = 0;
	/* Far more than any AF_UNIX send buffer holds; the bound only keeps a
	 * regression from spinning forever. */
	for (int i = 0; i < 65536 && ret >= 0; i++) {
		ret = tls_bio_send(bio_ctx(fds[0]), chunk, sizeof(chunk));
	}
	T_EXPECT_EQ(ret, MBEDTLS_ERR_SSL_WANT_WRITE);

	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* After the peer closes, a read is EOF (0) and a send fails with EPIPE -- no
 * SIGPIPE, thanks to MSG_NOSIGNAL -- which is a connection reset, not a
 * generic send failure. */
T_DECLARE_CASE(test_bio_after_peer_close_is_eof_then_reset)
{
	int fds[2];
	bio_pair_open(fds);
	(void)close(fds[1]);
	unsigned char buf[8] = { 0 };

	T_EXPECT_EQ(tls_bio_recv(bio_ctx(fds[0]), buf, sizeof(buf)), 0);
	T_EXPECT_EQ(
		tls_bio_send(bio_ctx(fds[0]), buf, sizeof(buf)),
		MBEDTLS_ERR_NET_CONN_RESET);

	(void)close(fds[0]);
}

/* An invalid descriptor (EBADF) is a plain I/O failure, not a reset. */
T_DECLARE_CASE(test_bio_bad_fd_is_io_failure)
{
	unsigned char buf[8] = { 0 };
	T_EXPECT_EQ(
		tls_bio_send(bio_ctx(-1), buf, sizeof(buf)),
		MBEDTLS_ERR_NET_SEND_FAILED);
	T_EXPECT_EQ(
		tls_bio_recv(bio_ctx(-1), buf, sizeof(buf)),
		MBEDTLS_ERR_NET_RECV_FAILED);
}

/* Every errno sock_would_block admits -- including a full kernel buffer
 * reported as ENOBUFS/ENOMEM, which no socket produces on demand -- is
 * WANT_WRITE/WANT_READ in the BIO, exactly as on every non-offload socket
 * path, so the session waits for EV_WRITE/EV_READ instead of dying. */
T_DECLARE_CASE(test_bio_transient_errnos_are_retriable)
{
	static const int k_transient[] = { EAGAIN, EWOULDBLOCK, ENOBUFS,
					   ENOMEM };
	int fds[2];
	bio_pair_open(fds);
	unsigned char buf[8] = { 0 };

	for (size_t i = 0; i < ARRAY_SIZE(k_transient); i++) {
		bio_fault_errno = k_transient[i];
		T_EXPECT_EQ(
			tls_bio_send(bio_ctx(fds[0]), buf, sizeof(buf)),
			MBEDTLS_ERR_SSL_WANT_WRITE);
		bio_fault_errno = k_transient[i];
		T_EXPECT_EQ(
			tls_bio_recv(bio_ctx(fds[0]), buf, sizeof(buf)),
			MBEDTLS_ERR_SSL_WANT_READ);
	}

	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* ECONNRESET is a reset in both directions; the receive side cannot be made to
 * see one deterministically on a socketpair, so it is injected. */
T_DECLARE_CASE(test_bio_econnreset_is_conn_reset)
{
	int fds[2];
	bio_pair_open(fds);
	unsigned char buf[8] = { 0 };

	bio_fault_errno = ECONNRESET;
	T_EXPECT_EQ(
		tls_bio_send(bio_ctx(fds[0]), buf, sizeof(buf)),
		MBEDTLS_ERR_NET_CONN_RESET);
	bio_fault_errno = ECONNRESET;
	T_EXPECT_EQ(
		tls_bio_recv(bio_ctx(fds[0]), buf, sizeof(buf)),
		MBEDTLS_ERR_NET_CONN_RESET);

	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* An interrupted call is retried, not reported: the retry reaches the socket
 * and returns what it returns. */
T_DECLARE_CASE(test_bio_eintr_is_retried)
{
	int fds[2];
	bio_pair_open(fds);
	unsigned char buf[8] = { 0 };

	bio_fault_errno = EINTR;
	T_EXPECT_EQ(
		tls_bio_send(bio_ctx(fds[0]), buf, sizeof(buf)),
		(int)sizeof(buf));
	bio_fault_errno = EINTR;
	T_EXPECT_EQ(
		tls_bio_recv(bio_ctx(fds[1]), buf, sizeof(buf)),
		(int)sizeof(buf));

	(void)close(fds[0]);
	(void)close(fds[1]);
}

#if !defined(MBEDTLS_LEGACY_RNG) || defined(MBEDTLS_PSA_CRYPTO_C)
/* Self-signed P-256/SHA-256 pair, produced with the openssl CLI.  An EC key is
 * what a 3.6 build with MBEDTLS_USE_PSA_CRYPTO parses into PSA, so it fails to
 * load while PSA is still down. */
static const char *const test_p256_cert_pem =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBgzCCASmgAwIBAgIUPPqIluQCDVk5VDt+aeIFF5L/HdwwCgYIKoZIzj0EAwIw\n"
	"FjEUMBIGA1UEAwwLcHNhLmV4YW1wbGUwIBcNMjYwOTI1MDY1OTE1WhgPMjEyNjA5\n"
	"MDEwNjU5MTVaMBYxFDASBgNVBAMMC3BzYS5leGFtcGxlMFkwEwYHKoZIzj0CAQYI\n"
	"KoZIzj0DAQcDQgAEI/4Y/y00YiqAkk4mltn3u0wNJdLHlbNzKzi6pn2T3BDTunqE\n"
	"Zo6LRkmFWGLQErteI39L7FWcj4CxHvW09Dos+qNTMFEwHQYDVR0OBBYEFITne+Fj\n"
	"vd52OGmtLsiJr1qaW1XwMB8GA1UdIwQYMBaAFITne+Fjvd52OGmtLsiJr1qaW1Xw\n"
	"MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAOb5/Jq5S430+RT1\n"
	"O/4r6dMgoewSJagnfL4VV2XzyWw9AiB91Rcx6fh5B2wDJcUklj+BhiR6cEx7TcWN\n"
	"E4Yj8YllRg==\n"
	"-----END CERTIFICATE-----\n";

static const char *const test_p256_key_pem =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLxTWG8ESC7kkddHy\n"
	"0Nlsppftwx7V5jv/ouVwk+b1Rh2hRANCAAQj/hj/LTRiKoCSTiaW2fe7TA0l0seV\n"
	"s3MrOLqmfZPcENO6eoRmjotGSYVYYtASu14jf0vsVZyPgLEe9bT0Oiz6\n"
	"-----END PRIVATE KEY-----\n";

/* psa_generate_random() answers PSA_ERROR_BAD_STATE until psa_crypto_init(). */
static bool psa_is_initialized(void)
{
	unsigned char b;
	return psa_generate_random(&b, sizeof(b)) == PSA_SUCCESS;
}
#endif

/* Context construction parses the key and calls into mbedtls_ssl before any
 * handshake, so it must bring PSA up itself: mbedTLS 3.6 requires that under
 * MBEDTLS_USE_PSA_CRYPTO, which the library's default config leaves off. */
T_DECLARE_CASE(test_ctx_init_initializes_psa)
{
#if !defined(MBEDTLS_LEGACY_RNG) || defined(MBEDTLS_PSA_CRYPTO_C)
	mbedtls_psa_crypto_free();
	struct tls_context *const ctx = tls_ctx_server(&(struct tls_config){
		.cert = test_p256_cert_pem, .key = test_p256_key_pem });
	T_EXPECT(ctx != NULL);
	T_EXPECT(psa_is_initialized());
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}
#else
	T_LOG("mbedTLS built without PSA crypto");
	T_SKIPNOW();
#endif
}

/* tls_psk_label() is reached with no context (config load, key generator), and
 * its HKDF may run through PSA, so it must bring PSA up too. */
T_DECLARE_CASE(test_psk_label_initializes_psa)
{
#if !defined(MBEDTLS_LEGACY_RNG) || defined(MBEDTLS_PSA_CRYPTO_C)
	mbedtls_psa_crypto_free();
	unsigned char psk[TLS_PSK_MIN_LEN];
	memset(psk, 0x5a, sizeof(psk));
	char label[TLS_PSK_LABEL_MAX + 1];
	size_t len = sizeof(label);
	T_EXPECT(tls_psk_label(psk, sizeof(psk), label, &len));
	T_EXPECT(psa_is_initialized());
#else
	T_LOG("mbedTLS built without PSA crypto");
	T_SKIPNOW();
#endif
}

static bool bytes_contain(
	const unsigned char *restrict hay, const size_t hay_len,
	const unsigned char *restrict needle, const size_t needle_len)
{
	for (size_t i = 0; i + needle_len <= hay_len; i++) {
		if (memcmp(hay + i, needle, needle_len) == 0) {
			return true;
		}
	}
	return false;
}

/* mbedtls_ssl_conf_psk() copies the key into conf and zeroizes that copy when
 * conf is freed, so a client context must not hold a second plaintext copy of
 * its own for as long as it and every connection over it live.  The derived
 * label, which each connection is handed, is the one credential kept. */
T_DECLARE_CASE(test_client_ctx_keeps_no_psk_copy)
{
	unsigned char key[TLS_PSK_MIN_LEN];
	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = (unsigned char)(0xa5 ^ (i * 37));
	}
	struct tls_context *const ctx = tls_ctx_client(
		&(struct tls_config){ .psk = key, .psk_len = sizeof(key) });
	T_CHECK(ctx != NULL);
	const struct tls_ctx_impl *const c = tls_ctx_raw(ctx);
	const bool holds_key = bytes_contain(
		(const unsigned char *)c, sizeof(*c), key, sizeof(key));
	char held_label[TLS_PSK_LABEL_MAX + 1];
	memcpy(held_label, c->psk_label, sizeof(held_label));
	tls_ctx_free(ctx);

	T_EXPECT(!holds_key);
	char label[TLS_PSK_LABEL_MAX + 1];
	size_t label_len = sizeof(label);
	T_CHECK(tls_psk_label(key, sizeof(key), label, &label_len));
	T_EXPECT_STREQ(held_label, label);
}

/* Records what psk_lookup_cb forwarded; always reports "unknown", so the
 * callback returns before it installs a key on the ssl object. */
struct psk_lookup_spy {
	int calls;
	char label[TLS_PSK_LABEL_MAX + 1];
};

static bool psk_spy_lookup(
	void *ctx, const char *identity, unsigned char *key, size_t *key_len)
{
	struct psk_lookup_spy *const spy = ctx;
	spy->calls++;
	(void)snprintf(spy->label, sizeof(spy->label), "%s", identity);
	memset(key, 0, *key_len);
	*key_len = 0;
	return false;
}

/* The identity is the attacker's, and arrives with no terminator.  One longer
 * than any derived label, or one holding a NUL -- which the C-string lookup
 * would read as a shorter label, possibly another peer's -- is rejected before
 * the lookup runs.  Both checks return ahead of any use of the ssl object, so
 * the callback runs here without one.  The 32-octet case is the boundary that
 * must still reach the lookup, intact. */
T_DECLARE_CASE(test_psk_lookup_cb_rejects_hostile_identity)
{
	static const char k_max[] = "0123456789abcdef0123456789abcdef";
	static const char k_over[] = "0123456789abcdef0123456789abcdef0";
	static const char k_nul_last[] = "0123456789abcdef0123456789abcde\0";
	static_assert(sizeof(k_max) - 1 == TLS_PSK_LABEL_MAX, "boundary");
	struct psk_lookup_spy spy = { 0 };
	struct tls_ctx_impl ctx = {
		.psk_lookup = psk_spy_lookup,
		.psk_lookup_ctx = &spy,
	};

	T_EXPECT_EQ(
		psk_lookup_cb(&ctx, NULL, (const unsigned char *)"ab\0cd", 5),
		-1);
	T_EXPECT_EQ(
		psk_lookup_cb(
			&ctx, NULL, (const unsigned char *)k_nul_last,
			sizeof(k_nul_last) - 1),
		-1);
	T_EXPECT_EQ(
		psk_lookup_cb(
			&ctx, NULL, (const unsigned char *)k_over,
			sizeof(k_over) - 1),
		-1);
	T_EXPECT_EQ(spy.calls, 0);

	T_EXPECT_EQ(
		psk_lookup_cb(
			&ctx, NULL, (const unsigned char *)k_max,
			sizeof(k_max) - 1),
		-1);
	T_EXPECT_EQ(spy.calls, 1);
	T_EXPECT_STREQ(spy.label, k_max);
}

static const struct testing_suite suite[] = {
	T_CASE(test_map_io_error_new_session_ticket_is_retriable),
	T_CASE(test_map_io_error_classifies_known_codes),
	T_CASE(test_bio_moves_bytes_and_empty_read_wants_read),
	T_CASE(test_bio_full_send_buffer_wants_write),
	T_CASE(test_bio_after_peer_close_is_eof_then_reset),
	T_CASE(test_bio_bad_fd_is_io_failure),
	T_CASE(test_bio_transient_errnos_are_retriable),
	T_CASE(test_bio_econnreset_is_conn_reset),
	T_CASE(test_bio_eintr_is_retried),
	T_CASE(test_ctx_init_initializes_psa),
	T_CASE(test_psk_label_initializes_psa),
	T_CASE(test_client_ctx_keeps_no_psk_copy),
	T_CASE(test_psk_lookup_cb_rejects_hostile_identity),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}

#else /* !WITH_TLS */

#include <stdlib.h>

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
