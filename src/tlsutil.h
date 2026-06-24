/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef TLSUTIL_H
#define TLSUTIL_H
/**
 * @file tlsutil.h
 * @brief Backend-agnostic TLS compatibility layer.
 *
 * A minimal, non-blocking-friendly API to create TLS contexts (client/server),
 * accept/connect connections, and perform I/O and shutdown. Backend types stay
 * private behind opaque pointers.
 *
 * Conventions: unless noted, pointer parameters MUST NOT be NULL; @c bool returns
 * are true=success, false=failure; @c *_free functions accept NULL.
 */

#if WITH_TLS

#include <stdbool.h>
#include <stddef.h>

struct tls_context; /* opaque */
struct tls_connection; /* opaque */

/**
 * @defgroup tls
 * @brief Backend-agnostic TLS compatibility layer.
 * @{
 */

/**
 * @brief I/O event notifier attached to a @c tls_connection.
 *
 * Borrowed by reference (pointers copied); @c ctx and the function pointers must
 * outlive the connection. Either pointer may be NULL to ignore that event.
 * Callbacks fire synchronously inside @c tls_send / @c tls_recv / @c tls_handshake
 * / @c tls_shutdown; a handler MUST NOT re-enter those on the same connection, but
 * may call @c tls_input / @c tls_output.
 */
struct tls_callback {
	void *ctx;
	/* Outbound ciphertext staged, ready to drain with tls_output; memory-backed
	 * connections only. */
	void (*on_send)(void *ctx);
	/* Buffered plaintext is readable by tls_recv without feeding more ciphertext
	 * (or, fd-backed, without another socket read). */
	void (*on_recv)(void *ctx);
};

/**
 * @brief Runtime TLS parameters for @c tls_ctx_server / @c tls_ctx_client.
 *
 * String fields are PEM data or "@filename" (see @c tls_load_cert), only borrowed
 * for the duration of the call; the implementation copies what it retains.
 */
struct tls_config {
	/* PEM or "@filename". */
	const char *cert;
	const char *key;
	/* Authorized certificate PEMs/filenames; may be NULL. */
	char *const *authcerts;
	size_t authcerts_count;
	/* Colon-separated TLS 1.3 cipher suites, or NULL for defaults. */
	const char *ciphersuites;
	/* Comma-separated ALPN list; NULL or empty omits the extension. */
	const char *alpn;
	/* Client only: SNI server name; NULL or empty omits the extension. */
	const char *sni;
	/* OpenSSL only: request KTLS offload (kernel frames+encrypts records). */
	bool kernel_offload : 1;
};

/**
 * @brief Active TLS library name and version, e.g. "OpenSSL 3.0.13".
 * @return Static, NUL-terminated string.
 */
const char *tls_version(void);

/* Status codes from tls_send / tls_recv / tls_handshake / tls_shutdown. */
enum tls_error {
	TLS_ERROR_NONE = 0,
	/* generic TLS/SSL error (see error queue) */
	TLS_ERROR_SSL,
	/* would block; needs a read */
	TLS_ERROR_WANT_READ,
	/* would block; needs a write */
	TLS_ERROR_WANT_WRITE,
	/* underlying syscall error */
	TLS_ERROR_SYSCALL,
	/* peer performed an orderly shutdown (EOF) */
	TLS_ERROR_ZERO_RETURN,
	TLS_ERROR_UNKNOWN,
};

/**
 * @brief Load a certificate chain.
 * @param ctx Target context.
 * @param[in] cert_data "@filename" to read a file, else a NUL-terminated PEM blob.
 * @return true on success.
 */
bool tls_load_cert(struct tls_context *ctx, const char *cert_data);

/**
 * @brief Load a private key.
 * @param ctx Target context.
 * @param[in] key_data "@filename" to read a file, else a NUL-terminated PEM blob.
 * @return true on success.
 */
bool tls_load_key(struct tls_context *ctx, const char *key_data);

/**
 * @brief Load authorized certificates, each "@filename" or a PEM blob.
 * @param ctx Target context.
 * @param[in] authcerts Certificate references; may be NULL.
 * @param count Number of entries.
 * @return true on success; a no-op success when @p authcerts is NULL or @p count is 0.
 */
bool tls_load_authcerts(
	struct tls_context *ctx, char *const *authcerts, size_t count);

/**
 * @brief Zero a memory region via the TLS library.
 * @param[out] ptr Region to erase; NULL is safe.
 * @param len Length in bytes; 0 is safe.
 */
void tls_secure_erase(void *ptr, size_t len);

/**
 * @brief Create a TLS 1.3 server context requiring a client certificate (mutual auth).
 * @param[in] conf Parameters; conf->cert and conf->key MUST NOT be NULL, conf->sni is ignored.
 * @return The context, or NULL on failure.
 */
struct tls_context *tls_ctx_server(const struct tls_config *conf);

/**
 * @brief Create a TLS 1.3 client context that verifies the peer against conf->authcerts.
 * @param[in] conf Parameters; conf->cert and conf->key MUST NOT be NULL.
 * @return The context, or NULL on failure.
 */
struct tls_context *tls_ctx_client(const struct tls_config *conf);

/**
 * @brief Free a TLS context.
 * @param ctx Context to free; NULL is safe.
 */
void tls_ctx_free(struct tls_context *ctx);

/**
 * @brief New server-mode (accept) connection; performs no I/O or handshake.
 * @param ctx Server context.
 * @param fd Transport fd: >= 0 is fd-backed (the library does socket I/O;
 * tls_input/tls_output and on_send unused); < 0 is memory-backed (shuttle
 * ciphertext via tls_input/tls_output).
 * @return The connection, or NULL on failure.
 * @note No notifier is installed; call tls_set_callback() before driving
 * memory-backed I/O.
 */
struct tls_connection *tls_server(struct tls_context *ctx, int fd);

/**
 * @brief New client-mode (connect) connection; as tls_server() but in connect
 * state with the client SNI from @p ctx applied.
 * @param ctx Client context.
 * @param fd Transport fd (see tls_server()).
 * @return The connection, or NULL on failure.
 */
struct tls_connection *tls_client(struct tls_context *ctx, int fd);

/**
 * @brief Install or replace the I/O event notifier.
 * @param conn Target connection.
 * @param[in] cb Notifier (copied by reference); NULL clears it.
 */
void tls_set_callback(
	struct tls_connection *conn, const struct tls_callback *cb);

/**
 * @brief Memory-backed only: feed received ciphertext for tls_recv() / tls_handshake().
 * @param conn Target connection.
 * @param[in] data Ciphertext bytes.
 * @param len Byte count.
 * @return true on success.
 */
bool tls_input(struct tls_connection *conn, const void *data, size_t len);

/**
 * @brief Memory-backed only: drain pending outbound ciphertext.
 * @param conn Target connection.
 * @param[out] buf Destination.
 * @param len Destination capacity.
 * @return Bytes copied (0 if none); the on_send notifier reports availability.
 */
size_t tls_output(struct tls_connection *conn, void *buf, size_t len);

/**
 * @brief Drive the non-blocking handshake (optional; tls_send/tls_recv complete it lazily).
 * @param conn Target connection.
 * @return NONE when done; WANT_READ/WANT_WRITE while in progress on that
 * direction; else fatal.
 */
enum tls_error tls_handshake(struct tls_connection *conn);

/**
 * @brief Send plaintext with partial writes.
 * @param conn Target connection.
 * @param[in] buf Source bytes.
 * @param[inout] len In: bytes to write. Out: bytes committed.
 * @return NONE (advance past @p len bytes); WANT_READ/WANT_WRITE (nothing
 * committed — retry with the same @p buf and @p len); else fatal.
 */
enum tls_error tls_send(
	struct tls_connection *conn, const void *restrict buf,
	size_t *restrict len);

/**
 * @brief Receive plaintext.
 * @param conn Target connection.
 * @param[out] buf Destination.
 * @param[inout] len In: capacity. Out: bytes read (0 on error).
 * @return A ::tls_error status.
 */
enum tls_error tls_recv(
	struct tls_connection *restrict conn, void *restrict buf,
	size_t *restrict len);

/**
 * @brief Send this side's close_notify; one-way, does NOT await the peer's.
 * @param conn Target connection.
 * @return NONE when flushed; WANT_READ/WANT_WRITE to retry on that direction;
 * else fatal.
 * @note To observe the peer's close, keep calling tls_recv() until
 * TLS_ERROR_ZERO_RETURN.
 */
enum tls_error tls_shutdown(struct tls_connection *conn);

/**
 * @brief Free a TLS connection.
 * @param conn Connection to free; NULL is safe.
 */
void tls_conn_free(struct tls_connection *conn);

/**
 * @brief The peer's X.509 certificate in DER, available only after a successful handshake.
 * @param conn Target connection.
 * @param[out] out Receives a malloc'd buffer (caller frees).
 * @param[out] len Receives its length.
 * @return true on success; false when no peer certificate is available.
 */
bool tls_peer_cert_der(
	struct tls_connection *conn, unsigned char **out, size_t *len);

/** @} */

#endif /* WITH_TLS */

#endif /* TLSUTIL_H */
