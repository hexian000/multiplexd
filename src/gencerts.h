/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file gencerts.h
 * @brief Certificate generation helpers.
 */

#ifndef GENCERTS_H
#define GENCERTS_H

#if WITH_TLS

#include <stdbool.h>

/**
 * @brief Generate certificate and key pairs.
 * @param names Comma-separated list of certificate names.
 * @param server_name Server name for the certificate.
 * @param sign_cert Signing certificate name (optional).
 * @param keytype Key algorithm: "rsa", "ecdsa", or "ed25519".
 * @param keysize Size of the key.
 * @return true on success, false on failure.
 */
bool gencerts(
	const char *names, const char *server_name, const char *sign_cert,
	const char *keytype, int keysize);

#endif /* WITH_TLS */

#endif /* GENCERTS_H */
