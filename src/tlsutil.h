/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef TLSUTIL_H
#define TLSUTIL_H

/**
 * @file tlsutil.h
 * @brief Small wrapper utilities for OpenSSL-based TLS handling.
 *
 * This header exposes a minimal, non-blocking-friendly API used across the
 * project to create TLS contexts (client/server), accept/connect TLS
 * connections and perform I/O and shutdown using OpenSSL.
 *
 * All functions operate on opaque pointers to keep OpenSSL types private to
 * the implementation. All public functions validate inputs where practical
 * and return appropriate status values on error.
 */

#if WITH_TLS

#include <stdbool.h>
#include <stddef.h>

struct tls_context; /* opaque */
struct tls_connection; /* opaque */

/** Increase the reference count of a TLS context. */
void tls_ctx_ref(struct tls_context *ctx);

/** Decrease the reference count of a TLS context. */
void tls_ctx_unref(struct tls_context *ctx);

/**
 * @brief Error codes returned by tls_send/tls_recv.
 */
enum tls_error {
	/** No error. */
	TLS_ERROR_NONE = 0,
	/** A generic OpenSSL error (see error queue). */
	TLS_ERROR_SSL,
	/** Operation would block and needs a read. */
	TLS_ERROR_WANT_READ,
	/** Operation would block and needs a write. */
	TLS_ERROR_WANT_WRITE,
	/** Underlying syscall error. */
	TLS_ERROR_SYSCALL,
	/** Peer performed an orderly shutdown (EOF). */
	TLS_ERROR_ZERO_RETURN,
	/** Unknown/unspecified error. */
	TLS_ERROR_UNKNOWN,
};

/**
 * @brief Load certificate from memory or file.
 *
 * If @p cert_data begins with '@', the rest is interpreted as a filename and
 * the certificate chain will be read from the file. Otherwise, @p cert_data
 * should point to a NUL-terminated PEM blob in memory.
 *
 * @param ctx TLS context. MUST NOT be NULL.
 * @param cert_data PEM certificate data or filename (prefixed with '@').
 * @return true on success, false on failure.
 */
bool tls_load_cert(struct tls_context *ctx, const char *cert_data);

/**
 * @brief Load private key from memory or file.
 *
 * If @p key_data begins with '@', the rest is interpreted as a filename and
 * the private key will be read from the file. Otherwise, @p key_data should
 * point to a NUL-terminated PEM blob in memory.
 *
 * @param ctx TLS context. MUST NOT be NULL.
 * @param key_data PEM private key data or filename (prefixed with '@').
 * @return true on success, false on failure.
 */
bool tls_load_key(struct tls_context *ctx, const char *key_data);

/**
 * @brief Load authorized certificates from memory or files.
 *
 * Each entry in @p authcerts is either a filename (prefixed with '@') or a
 * PEM blob in memory. If @p authcerts is NULL or @p count is zero, this
 * function succeeds (no-op).
 *
 * @param ctx TLS context. MUST NOT be NULL.
 * @param authcerts Array of PEM certificate data or filenames (prefixed with '@').
 * @param count Number of entries in the array.
 * @return true on success, false on failure.
 */
bool tls_load_authcerts(
	struct tls_context *ctx, char *const *authcerts, size_t count);

/**
 * @brief Initialize TLS server context with mutual authentication.
 *
 * The returned context enforces TLS 1.3 minimum and configures the context to
 * require a client certificate (mutual authentication). The context is tied
 * to the OpenSSL implementation and must be freed with @c tls_ctx_free().
 *
 * @param tls_cert PEM certificate data or filename (prefixed with '@'). MUST NOT be NULL.
 * @param tls_key PEM private key data or filename (prefixed with '@'). MUST NOT be NULL.
 * @param authcerts Array of authorized certificate PEM data or filenames. May be NULL.
 * @param authcerts_count Number of entries in @p authcerts.
 * @param tls_ciphersuites Colon-separated TLS 1.3 cipher suite list, or NULL for defaults.
 * @return TLS context on success, NULL on failure.
 */
struct tls_context *tls_ctx_server(
	const char *tls_cert, const char *tls_key, char *const *authcerts,
	size_t authcerts_count, const char *tls_ciphersuites);

/**
 * @brief Initialize TLS client context with mutual authentication.
 *
 * The client context enforces TLS 1.3 minimum and verifies the peer
 * certificate using the provided authorized certificates.
 *
 * @param tls_cert PEM certificate data or filename (prefixed with '@'). MUST NOT be NULL.
 * @param tls_key PEM private key data or filename (prefixed with '@'). MUST NOT be NULL.
 * @param authcerts Array of authorized certificate PEM data or filenames. May be NULL.
 * @param authcerts_count Number of entries in @p authcerts.
 * @param tls_ciphersuites Colon-separated TLS 1.3 cipher suite list, or NULL for defaults.
 * @return TLS context on success, NULL on failure.
 */
struct tls_context *tls_ctx_client(
	const char *tls_cert, const char *tls_key, char *const *authcerts,
	size_t authcerts_count, const char *tls_ciphersuites);

/**
 * @brief Release TLS context resources.
 *
 * The function is safe to call with a NULL pointer.
 *
 * @param ctx TLS context to free.
 */
void tls_ctx_free(struct tls_context *ctx);

/**
 * @brief Create a new TLS connection for server (accept mode).
 *
 * The returned connection is an opaque object representing an SSL* and must
 * be freed with @c tls_conn_free(). The function does not perform any I/O or
 * handshake; use @c tls_handshake() to continue the non-blocking handshake.
 *
 * @param ctx TLS context. MUST NOT be NULL.
 * @param fd File descriptor (socket) to associate with the TLS connection.
 *           Must be a valid, open socket descriptor.
 * @return TLS connection on success, NULL on failure.
 */
struct tls_connection *tls_accept(struct tls_context *ctx, int fd);

/**
 * @brief Create a new TLS connection for client (connect mode).
 *
 * Same semantics as @c tls_accept, but the TLS object is set to connect state.
 *
 * @param ctx TLS context. MUST NOT be NULL.
 * @param fd File descriptor (socket) to associate with the TLS connection.
 * @return TLS connection on success, NULL on failure.
 */
struct tls_connection *tls_connect(struct tls_context *ctx, int fd);

/**
 * @brief Perform non-blocking TLS handshake.
 *
 * Calling this function is optional; @c tls_send and @c tls_recv will
 * implicitly complete the handshake if it has not yet finished.
 *
 * The handshake uses non-blocking semantics. On return:
 * - 0: handshake completed successfully.
 * - 1: handshake in progress; *want_read or *want_write indicates which
 *      I/O event is required next.
 * - -1: fatal error occurred.
 *
 * @param conn TLS connection. MUST NOT be NULL.
 * @param want_read Set to true if a read is required next. May be NULL.
 * @param want_write Set to true if a write is required next. May be NULL.
 * @return 0 on success, 1 if in progress, -1 on error.
 */
int tls_handshake(
	struct tls_connection *conn, bool *want_read, bool *want_write);

/**
 * @brief Send data to TLS connection.
 *
 * @c SSL_MODE_ENABLE_PARTIAL_WRITE is active, so a @c TLS_ERROR_NONE return
 * does not guarantee all bytes were sent. The caller must inspect @p len on
 * return and retry with the remaining data if necessary.
 *
 * @param conn TLS connection. MUST NOT be NULL.
 * @param buf Buffer to write from. MUST NOT be NULL when @p len > 0.
 * @param len Input: bytes to write; Output: actual bytes written.
 * @return TLS_ERROR_NONE (0) on success, TLS_ERROR_WANT_READ/WRITE if needs I/O, or
 *         another error code on failure.
 */
enum tls_error tls_send(
	struct tls_connection *conn, const void *restrict buf,
	size_t *restrict len);

/**
 * @brief Receive data from TLS connection.
 *
 * @p len is an in/out parameter; on success it is set to the number of bytes
 * read, on error it is set to zero.
 *
 * @param conn TLS connection. MUST NOT be NULL.
 * @param buf Buffer to read into. MUST NOT be NULL when @p len > 0.
 * @param len Input: maximum bytes to read; Output: actual bytes read.
 * @return TLS_ERROR_NONE (0) on success, TLS_ERROR_WANT_READ/WRITE if needs I/O, or
 *         another error code on failure.
 */
enum tls_error tls_recv(
	struct tls_connection *restrict conn, void *restrict buf,
	size_t *restrict len);

/**
 * @brief Perform non-blocking TLS shutdown.
 *
 * Performs an orderly TLS shutdown using non-blocking semantics. Returns:
 * - 0: shutdown complete.
 * - 1: shutdown in progress; set *want_read or *want_write to indicate which
 *      I/O operation is required next.
 * - -1: fatal error occurred.
 *
 * @param conn TLS connection. MUST NOT be NULL.
 * @param want_read Pointer to a bool set to true if a read is required next.
 *                  May be NULL.
 * @param want_write Pointer to a bool set to true if a write is required next.
 *                   May be NULL.
 * @return 0 on complete shutdown, 1 if in progress, -1 on error.
 */
int tls_shutdown(struct tls_connection *conn, bool *want_read, bool *want_write);

/**
 * @brief Free TLS connection.
 *
 * Safe to call with NULL.
 *
 * @param conn TLS connection to free.
 */
void tls_conn_free(struct tls_connection *conn);

/**
 * @brief Log current OpenSSL error queue for @p s.
 *
 * This is a thin wrapper around the internal logging used by the project and
 * prints all OpenSSL errors currently present in the thread's error queue.
 *
 * @param s Context string used in the log message. May be NULL.
 */
void tls_perror(const char *s);

#define TLS_PERROR(what) tls_perror((what))

#endif /* WITH_TLS */

#endif /* TLSUTIL_H */
