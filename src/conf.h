/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file conf.h
 * @brief Configuration model and parsing helpers.
 */

#ifndef CONF_H
#define CONF_H

#include "mux/mux.h"

#include <stdbool.h>
#include <stddef.h>

/* Maximum configuration file size in bytes. */
#define CONF_MAXSIZE 65535

struct conf_socket_opts {
	bool tcp_keepalive : 1;
	bool tcp_nodelay : 1;
	bool tcp_reuseport : 1;
	int tcp_sndbuf;
	int tcp_rcvbuf;
#if WITH_TCP_NOTSENT_LOWAT
	int tcp_notsent_lowat;
#endif
	int backlog;
};

/* Per-peer listen entry inside the identity block. */
struct identity_peer {
	/* Peer-side identity used as routing key. */
	char *id;
	/* Local TCP address to accept application traffic on, or NULL. */
	char *listen;
};

/* Mirrors the JSON "identity" object. */
struct conf_identity {
	char *claim;
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
	/* NULL or empty string omits the SNI extension. */
	char *tls_sni;
	/* Comma-separated list; NULL or empty string omits the ALPN extension. */
	char *tls_alpn;
	/* Staging: per-entry PEM strings (owned; NULLed by conf_inline_pem). */
	char **tls_authcerts;
	size_t tls_authcerts_count;
	/* Concatenated PEM bundle of trusted certificates (owned); NULL when none. */
	char *tls_authcerts_bundle;
	/* OpenSSL only: request kernel TLS (KTLS) offload so the kernel frames
	 * and encrypts records and can coalesce them into full segments. */
	bool tls_kernel_offload;
	/* Let the TLS library own the socket fd and drive record I/O directly.
	 * When false, the mux layer owns socket I/O and shuttles ciphertext through
	 * the TLS library over in-memory buffers (memory transport). */
	bool tls_socket_offload;
#endif /* WITH_TLS */

	/* Mux session parameters; window fields in frame units. */
	struct mux_config mux;
	/* TCP socket options for the mux transport socket. */
	struct conf_socket_opts mux_tcp;
	/* TCP socket options for the local application socket. */
	struct conf_socket_opts tcp;

	struct conf_identity identity;

	char *log;
	int loglevel;
	int max_sessions;
	/* Parsed from the "max_startups" string field ("start:rate:full"). */
	int startup_limit_start;
	int startup_limit_rate;
	int startup_limit_full;
};

/* New configuration with defaults; NULL on allocation failure. */
struct config *conf_new_default(void);

/* Parse, validate, and normalize config from a JSON buffer (modified in place;
 * need not be NUL-terminated). NULL on failure. */
struct config *conf_parse(char *json, size_t len);

/* Parse, validate, and normalize a JSON config file; NULL on failure. */
struct config *conf_parsefile(const char *path);

/* Serialize config to a heap JSON string (caller frees); @p lenp optionally
 * receives the length excluding NUL. NULL on failure. */
char *conf_dump(const struct config *conf, size_t *lenp);

#if WITH_TLS
/* Replace "@path" PEM references with in-memory PEM strings, in place.
 * false on allocation or file-loading failure. */
bool conf_inline_pem(struct config *conf);
#endif

/* Free a configuration; NULL is allowed. */
void conf_free(struct config *conf);

/* Build a struct mux_config from the config: copies conf->mux and sets
 * reject_inbound from conf->connect. */
struct mux_config conf_get_mux(const struct config *conf);

#endif /* CONF_H */
