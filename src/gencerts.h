/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file gencerts.h
 * @brief Certificate generation helpers.
 */

#ifndef GENCERTS_H
#define GENCERTS_H

#if WITH_OPENSSL

#include <stdbool.h>

/* Generate certificate and key pairs from a comma-separated @p names list.
 * @p sign_cert (optional) signs them. The remaining parameters each take a
 * default when omitted, so a caller can pass its unset options straight
 * through: @p server_name NULL means "example.com", @p keytype NULL means
 * "rsa" (otherwise "rsa", "ecdsa", or "ed25519"), and @p keysize 0 means the
 * key type's own default.
 *
 * @p identities controls the URI subjectAltName that identity.verify checks
 * for: NULL leaves every certificate without one, while a non-NULL
 * comma-separated list is paired positionally with the (non-blank) names and
 * must have the same number of entries. Every entry names an identity, the
 * empty one included.
 *
 * false on failure. */
bool gencerts(
	const char *names, const char *server_name, const char *sign_cert,
	const char *keytype, int keysize, const char *identities);

#endif /* WITH_OPENSSL */

#endif /* GENCERTS_H */
