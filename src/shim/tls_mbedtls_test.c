/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* tls_mbedtls_test.c - white-box tests for the mbedTLS backend's static
 * error-classification helpers (map_io_error and the socket-offload BIO
 * callbacks).  They are static and unreachable through the public tls.h API:
 * the codes they translate come from the library or from the kernel, so no
 * black-box handshake can present a chosen one.  This TU compiles
 * tls_mbedtls.c directly (its symbols are internal to this file, so it must
 * not link `shim`) to classify codes in isolation. */

/* WITH_TLS comes from the force-included config.h, as in tls_mbedtls.c. */
#if WITH_TLS

/* Compile the backend into this TU to reach its static helpers. */
#include "tls_mbedtls.c"

#include "meta/arraysize.h"
#include "utils/testing.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

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
	T_SKIP("mbedTLS built without client-side session tickets");
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

/* The socket-offload BIO callbacks must classify transient backpressure the
 * way the rest of the project does.  sock_would_block admits ENOBUFS/ENOMEM (a
 * full kernel buffer) alongside EAGAIN/EWOULDBLOCK, and every non-offload
 * socket path retries on it; calling those fatal here would tear down the
 * whole TLS+mux session where plain TCP merely waits for EV_WRITE. */
T_DECLARE_CASE(test_bio_transient_errnos_are_retriable)
{
	static const int k_transient[] = { EAGAIN, EWOULDBLOCK, ENOBUFS,
					   ENOMEM };
	for (size_t i = 0; i < ARRAY_SIZE(k_transient); i++) {
		T_EXPECT(sock_would_block(k_transient[i]));
	}
	/* Permanent failures must stay permanent. */
	T_EXPECT(!sock_would_block(ECONNRESET));
	T_EXPECT(!sock_would_block(EPIPE));
	T_EXPECT(!sock_would_block(EBADF));
}

static const struct testing_suite suite[] = {
	T_CASE(test_map_io_error_new_session_ticket_is_retriable),
	T_CASE(test_map_io_error_classifies_known_codes),
	T_CASE(test_bio_transient_errnos_are_retriable),
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
