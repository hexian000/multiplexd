/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file genpsk.h
 * @brief Pre-shared key generation for tls.psk.
 */

#ifndef GENPSK_H
#define GENPSK_H

#if WITH_TLS

#include <stdbool.h>

/* Generate one key per comma-separated name in @p names, writing each as
 * lowercase hex to "<name>.psk" with owner-only permissions.  Existing files
 * are never overwritten.  Each key's derived identity label is logged, so a
 * packet capture can be matched back to a peer.
 *
 * Unlike gencerts(), this names files only -- it never infers a peer identity.
 * The identity a key belongs to is decided by which tls.psk entry references
 * it, and a key is shared by a pair of peers, so neither end owns the name.
 *
 * false on failure. */
bool genpsk(const char *names);

#endif /* WITH_TLS */

#endif /* GENPSK_H */
