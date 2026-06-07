/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file listener.h
 * @brief TCP listener abstraction and accept callback interface.
 */

#ifndef LISTENER_H
#define LISTENER_H

#include <ev.h>

#include <stdbool.h>
#include <stdint.h>

struct config;
struct ev_loop;
struct listener;
struct server;
struct util_socket_opts;
struct sockaddr;

/**
 * @brief Callback invoked for each accepted socket.
 * @param l The listener that accepted the connection.
 * @param loop The event loop owning the accepted socket.
 * @param accepted_fd The accepted socket; ownership transfers to the callback.
 * @param accepted_sa The peer socket address captured at accept time.
 */
typedef void (*listener_serve_fn)(
	struct listener *l, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

struct listener {
	ev_io w_accept;
	ev_timer w_timer;
	const struct util_socket_opts *socket_opts;
	listener_serve_fn serve;
	struct server *srv;
	/* Optional per-listener context.  identity_listener stores a
	 * back-pointer to the enclosing struct here, recovered via DOWNCAST
	 * inside identity_tcp_serve. */
	void *data;
	uint_least64_t *num_accepted;
};

/**
 * @brief Initialize a listener object before start.
 * @param l The listener to initialize.
 * @param socket_opts Socket options applied to accepted sockets.
 * @param serve Callback invoked for each accepted connection.
 * @param server Owning server instance.
 * @param num_accepted Optional counter incremented on each successful accept.
 */
void listener_init(
	struct listener *l, const struct util_socket_opts *socket_opts,
	listener_serve_fn serve, struct server *server,
	uint_least64_t *restrict num_accepted);

/**
 * @brief Bind and start accepting connections.
 * @param l The initialized listener.
 * @param loop The event loop that will drive accept callbacks.
 * @param sa The local socket address to bind.
 * @return true on success, false on bind or setup failure.
 */
bool listener_start(
	struct listener *l, struct ev_loop *loop, const struct sockaddr *sa);

/**
 * @brief Stop accepting connections and release the listening socket.
 * @param l The listener to stop.
 * @param loop The event loop that owns the listener watchers.
 */
void listener_stop(struct listener *l, struct ev_loop *loop);

#endif /* LISTENER_H */
