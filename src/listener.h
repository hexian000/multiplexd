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

struct ev_loop;
struct listener;
struct server;
struct conf_socket_opts;
struct sockaddr;

/* Callback for each accepted socket; ownership of @p accepted_fd transfers to it.
 * @p accepted_sa is the peer address captured at accept time. */
typedef void (*listener_serve_fn)(
	struct listener *l, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

struct listener {
	ev_io w_accept;
	ev_timer w_timer;
	const struct conf_socket_opts *socket_opts;
	listener_serve_fn serve;
	struct server *srv;
	uint_least64_t *num_accepted;
};

/* Initialize a listener before start. @p num_accepted is an optional counter
 * incremented on each successful accept. */
void listener_init(
	struct listener *l, const struct conf_socket_opts *socket_opts,
	listener_serve_fn serve, struct server *server,
	uint_least64_t *restrict num_accepted);

/* Bind @p sa and start accepting; false on bind or setup failure. */
bool listener_start(
	struct listener *l, struct ev_loop *loop, const struct sockaddr *sa);

/* Stop accepting and release the listening socket. */
void listener_stop(struct listener *l, struct ev_loop *loop);

#endif /* LISTENER_H */
