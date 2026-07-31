/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SHIM_TLS_H
#define SHIM_TLS_H
/**
 * @file tls.h
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

/* External pre-shared key bounds.  RFC 9257 wants a PSK at least as long as
 * the hash output, and the label published below is a one-way function of the
 * key, so a low-entropy PSK becomes offline-crackable: the minimum is a floor
 * on *length*, not on entropy, and keys must come from a CSPRNG. */
#define TLS_PSK_MIN_LEN 32u
#define TLS_PSK_MAX_LEN 64u
/* Derived identity label: 16 octets, lowercase hex, excluding the NUL. */
#define TLS_PSK_LABEL_MAX 32u

/**
 * @brief Resolve a PSK identity offered by a client (server role).
 * @param ctx Opaque context from @c tls_config.psk_lookup_ctx.
 * @param[in] identity NUL-terminated label from the ClientHello.  Chosen by
 * the peer and therefore untrusted: already bounded at ::TLS_PSK_LABEL_MAX,
 * but never log it unescaped.
 * @param[out] key Caller-provided buffer of ::TLS_PSK_MAX_LEN octets.  Copied
 * into rather than lent, so no key outlives the call.
 * @param[inout] key_len In: capacity.  Out: octets written.
 * @return true if the identity is known; false rejects the handshake.
 */
typedef bool (*tls_psk_lookup_fn)(
	void *ctx, const char *identity, unsigned char *key, size_t *key_len);

/**
 * @brief Runtime TLS parameters for @c tls_ctx_server / @c tls_ctx_client.
 *
 * Exactly one credential set must be supplied: the certificate fields
 * (@c cert, @c key, @c authcerts) or the PSK fields.  They are mutually
 * exclusive -- a PSK handshake sends no Certificate message in either
 * direction, which is the point of offering it.
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
	/* Client role: the single PSK offered.  Both backends accept only one
	 * client-side PSK, so a node that dials several peers offers the first
	 * key it has configured.  Borrowed; the implementation copies it. */
	const unsigned char *psk;
	size_t psk_len;
	/* Server role: resolves a label the client offered.  NULL leaves PSK
	 * handshakes unsupported on this context. */
	tls_psk_lookup_fn psk_lookup;
	void *psk_lookup_ctx;
	/* Colon-separated TLS 1.3 cipher suites, or NULL for defaults. */
	const char *ciphersuites;
	/* Comma-separated ALPN list; NULL or empty omits the extension. */
	const char *alpn;
	/* Client only: SNI server name; NULL or empty omits the extension. */
	const char *sni;
	/* OpenSSL only: request KTLS offload (kernel frames+encrypts records). */
	bool kernel_offload : 1;
	/* mux.readahead > 0: enable the library read-ahead (SSL_CTX_set_read_ahead)
	 * so one socket read can buffer several records.  OpenSSL only. */
	bool readahead : 1;
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
 * @brief Derive the wire identity label for an external PSK.
 *
 * HKDF-SHA256 over the key with a fixed info string, hex-encoded.  The label
 * is public -- it travels in the ClientHello in the clear -- so it is
 * deliberately derived from the key rather than from the peer's identity,
 * which is low-entropy and would be recoverable by dictionary attack.  The
 * hash is fixed at SHA-256 regardless of the negotiated cipher suite, since
 * both peers must agree on the label without negotiating it.
 *
 * @param[in] psk Key of ::TLS_PSK_MIN_LEN to ::TLS_PSK_MAX_LEN octets.
 * @param psk_len Key length.
 * @param[out] buf Receives the NUL-terminated label.
 * @param[inout] len In: capacity, at least ::TLS_PSK_LABEL_MAX + 1.  Out:
 * label length excluding the NUL.
 * @return true on success.
 * @note Pure and context-free: usable at config load and by the key
 * generator, not only during a handshake.
 */
bool tls_psk_label(
	const unsigned char *psk, size_t psk_len, char *buf, size_t *len);

/**
 * @brief Create a TLS 1.3 server context.
 * @param[in] conf Parameters; exactly one credential set -- conf->cert with
 * conf->key (mutual certificate authentication, requiring a client
 * certificate), or conf->psk_lookup (external PSK).  conf->sni is ignored.
 * @return The context, or NULL on failure.
 */
struct tls_context *tls_ctx_server(const struct tls_config *conf);

/**
 * @brief Create a TLS 1.3 client context.
 * @param[in] conf Parameters; exactly one credential set -- conf->cert with
 * conf->key, verifying the peer against conf->authcerts, or conf->psk.
 * @return The context, or NULL on failure.
 */
struct tls_context *tls_ctx_client(const struct tls_config *conf);

/**
 * @brief Acquire an independently-owned handle that shares @p ctx's parsed
 * credentials, avoiding a re-parse.
 *
 * Lets each caller own (and free) a separate handle to the same underlying
 * credentials, so the lifetime is single-owner even though the parsed material
 * is shared: the OpenSSL backend up-references the SSL_CTX and returns a fresh
 * wrapper, while the mbedTLS backend reference-counts the shared context and
 * returns an alias.  Either way the result is released with @c tls_ctx_free and
 * the credentials live until the last owner frees its handle.
 *
 * @param ctx Context to share from; NULL returns NULL.
 * @return An owned context handle to free with @c tls_ctx_free, or NULL on
 *         failure.
 * @note Backend divergence: the OpenSSL backend refuses to share a server
 * context that registered an ALPN callback and returns NULL, where mbedTLS
 * succeeds. A portable caller must not assume a server context can be shared,
 * and must not read the NULL as an allocation failure.
 */
struct tls_context *tls_ctx_ref(struct tls_context *ctx);

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
 * @note Exception to this header's NULL convention: both backends return
 * NULL immediately when @p ctx is NULL, instead of it being undefined
 * behavior.
 */
struct tls_connection *tls_server(struct tls_context *ctx, int fd);

/**
 * @brief New client-mode (connect) connection; as tls_server() but in connect
 * state with the client SNI from @p ctx applied.
 * @param ctx Client context.
 * @param fd Transport fd (see tls_server()).
 * @return The connection, or NULL on failure.
 * @note Exception to this header's NULL convention: both backends return
 * NULL immediately when @p ctx is NULL, instead of it being undefined
 * behavior.
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
 * @note Exception to this header's NULL convention: both backends check
 * @p conn, @p out, and @p len defensively and return false if any is NULL,
 * instead of it being undefined behavior.
 */
bool tls_peer_cert_der(
	struct tls_connection *conn, unsigned char **out, size_t *len);

/**
 * @brief The peer certificate's URI subjectAltName entries (RFC 5280
 * Section 4.2.1.6 uniformResourceIdentifier, GeneralName [6]), available only
 * after a successful handshake.
 * @param conn Target connection.
 * @param[out] out Receives a malloc'd array of NUL-terminated names, or NULL
 * when the certificate carries none. One allocation: the pointer array is
 * followed by the name bytes, so a single free(*out) releases everything.
 * @param[out] count Receives the number of entries; 0 when @p *out is NULL.
 * @return true on success, including the no-URI-name case; false when no peer
 * certificate is available, on allocation failure, or when any URI name
 * contains an embedded NUL.
 * @note An embedded NUL fails the whole call rather than truncating the name.
 * A conformant IA5String identity never contains one, and silently accepting
 * the prefix before it is the null-prefix certificate attack. Neither backend
 * checks this for us: both hand out raw buffer+length.
 * @note Exception to this header's NULL convention: both backends check
 * @p conn, @p out, and @p count defensively and return false if any is NULL,
 * instead of it being undefined behavior.
 */
bool tls_peer_cert_uri_sans(
	struct tls_connection *conn, char ***out, size_t *count);

/**
 * @brief The PSK identity label this connection authenticated with.
 * @param conn Target connection, after a successful handshake.
 * @param[out] buf Receives the NUL-terminated label.
 * @param[inout] len In: capacity, at least ::TLS_PSK_LABEL_MAX + 1.  Out:
 * label length excluding the NUL.
 * @return true when the handshake used a PSK; false for a certificate
 * handshake, which is not an error -- the caller distinguishes the two
 * credential modes by this return.
 * @note The binder proves the peer holds the key for the label it offered, so
 * a true return is an authenticated statement of which configured peer this
 * is -- unlike a certificate's subjectAltName, nothing further need be
 * checked to trust it.
 */
bool tls_peer_psk_label(struct tls_connection *conn, char *buf, size_t *len);

/** @} */

#endif /* WITH_TLS */

#endif /* SHIM_TLS_H */
