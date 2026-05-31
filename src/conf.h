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

/* Maximum configuration file size in bytes. */
#define CONF_MAXSIZE 65535

/* Per-peer listen entry inside the identity block. */
struct identity_peer {
	/* Peer-side identity used as routing key. */
	char *id;
	/* Local TCP address to accept application traffic on, or NULL. */
	char *listen;
};

/* Mirrors the JSON "identity" object. */
struct conf_identity {
	/* identity.claim */
	char *claim;
	/* identity.mux_connect array. */
	char **mux_connect;
	size_t mux_connect_count;
	/* identity.listen entries, keyed by peer id. */
	struct identity_peer *peers;
	size_t peers_count;
};

struct config {
	char *type;

	char *api_listen;
	char *mux_listen;
	char *mux_connect;
	char *listen;
	char *connect;

#if WITH_TLS
	char *tls_cert;
	char *tls_key;
	char *tls_ciphersuites;
	char **tls_authcerts;
	size_t tls_authcerts_count;
#endif

	/* Mux session parameters; window fields in frame units. */
	struct mux_config mux;
	/* TCP socket options for the mux transport socket. */
	struct socket_opts mux_tcp;
	/* TCP socket options for the local application socket. */
	struct socket_opts tcp;

	struct conf_identity identity;

	int loglevel;
	int max_sessions;
	/* Parsed from the "max_startups" string field ("start:rate:full"). */
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
 * @brief Parse, validate, and normalize a configuration from a JSON buffer.
 * @param json The JSON input buffer (modified in-place; need not be NUL-terminated).
 * @param len The input length in bytes.
 * @return A heap-allocated configuration on success, or NULL on failure.
 */
struct config *conf_parse(char *json, size_t len);

/**
 * @brief Serialize a configuration to a heap-allocated JSON string.
 * @param conf The configuration to serialize.
 * @param lenp Optional output for the string length (excluding NUL).
 * @return A heap-allocated NUL-terminated JSON string; caller must free().
 *         Returns NULL on allocation or serialization failure.
 */
char *conf_dump(const struct config *conf, size_t *lenp);

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

/**
 * @brief Build a struct mux_config for the mux subsystem from the config.
 *
 * Copies conf->mux and sets reject_inbound from conf->connect.
 */
struct mux_config conf_get_mux(const struct config *conf);

#endif /* CONF_H */
