/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file api_server.h
 * @brief HTTP management API listener integration.
 */

#ifndef API_SERVER_H
#define API_SERVER_H

struct listener;
struct ev_loop;
struct server;
struct sockaddr;

/* Serve one accepted management API connection; takes ownership of @p accepted_fd. */
void api_serve(
	struct listener *l, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

/* Close every management API connection @p s still holds, mid-request ones
 * included. Idempotent. */
void api_server_stop(struct server *s, struct ev_loop *loop);

#endif /* API_SERVER_H */
