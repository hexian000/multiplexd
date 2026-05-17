/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.h
 * @brief Configuration model and parsing helpers.
 */

#ifndef CONF_H
#define CONF_H

#include "mux/mux.h"
#include "util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Per-peer listen entry inside the identity block. */
struct identity_peer {
	/* Peer-side identity used as routing key. */
	char *id;
	/* Local TCP address to accept application traffic on, or NULL. */
	char *listen;
};

struct config {
	char *type;

	char *api_listen;
	char *mux_listen;
	char *mux_connect;
	char *listen;
	/* This node's identity announced in hellos, or NULL. */
	char *identity_claim;
#if WITH_TLS
	char *tls_cert;
	char *tls_key;
	char *tls_ciphersuites;
	char **authcerts;
	size_t authcerts_count;
#endif

	/* Outbound mux addresses from identity.mux_connect (array of strings). */
	char **identity_connect;
	size_t identity_connect_count;

	/* Per-peer listen entries from identity.listen. */
	struct identity_peer *identity_peers;
	size_t identity_peers_count;

	/* Stream forwarding address: where inbound streams are forwarded, or NULL. */
	char *connect;

	struct mux_config mux;
	struct socket_opts mux_socket;
	struct socket_opts local_socket;

	int loglevel;
	int max_sessions;
	int startup_limit_start;
	int startup_limit_rate;
	int startup_limit_full;
};

/**
 * @brief Allocate a new configuration object with default values.
 * @return A heap-allocated configuration, or NULL on allocation failure.
 */
struct config *conf_new(void);

/**
 * @brief Parse, validate, and normalize a configuration file.
 * @param path Path to the JSON configuration file.
 * @return A heap-allocated configuration on success, or NULL on failure.
 */
struct config *conf_parsefile(const char *path);

/**
 * @brief Serialize a configuration to a file.
 * @param conf The configuration to dump.
 * @param path Output file path.
 * @return true on success, false on serialization or I/O failure.
 */
bool conf_dumpfile(const struct config *conf, const char *path);

/**
 * @brief Serialize a configuration to an open stream.
 * @param conf The configuration to dump.
 * @param fp The output stream.
 * @return true on success, false on serialization or I/O failure.
 */
bool conf_dump(const struct config *conf, FILE *fp);

#if WITH_TLS
/**
 * @brief Replace @path PEM references with in-memory PEM strings.
 * @param conf The configuration to rewrite in place.
 * @return true on success, false on allocation or file-loading failure.
 */
bool conf_inline_pem(struct config *conf);
#endif

/**
 * @brief Free a configuration returned by conf_new() or conf_parsefile().
 * @param conf The configuration to free; NULL is allowed.
 */
void conf_free(struct config *conf);

#endif /* CONF_H */
