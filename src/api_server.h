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
struct sockaddr;

/**
 * @brief Serve one accepted management API connection.
 * @param l The listener that accepted the connection.
 * @param loop The event loop owning the accepted socket.
 * @param accepted_fd The accepted socket; ownership transfers to this call.
 * @param accepted_sa The peer socket address for logging and request context.
 */
void api_serve(
	struct listener *l, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

#endif /* API_SERVER_H */
