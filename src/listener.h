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
union sockaddr_max;

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
	uint_least64_t *num_accepted);

/* Bind @p sa and start accepting; false on bind or setup failure. */
bool listener_start(
	struct listener *l, struct ev_loop *loop, const struct sockaddr *sa);

/* Create, configure, bind, and listen on a socket without arming the listener.
 * The caller owns the returned descriptor and must either close it or pass it
 * to listener_start_fd(). */
int listener_open(
	const struct conf_socket_opts *socket_opts, const struct sockaddr *sa);

/* Arm @p l on a descriptor returned by listener_open(). Ownership transfers to
 * @p l. */
void listener_start_fd(struct listener *l, struct ev_loop *loop, int fd);

/* Store the address @p l's socket is bound to in @p sa; false when @p l holds
 * no socket (never started, or stopped). */
bool listener_get_addr(const struct listener *l, union sockaddr_max *sa);

/* Stop accepting and release the listening socket. Idempotent: safe to call on
 * an already-stopped (or never-started) listener, so callers need not guard it. */
void listener_stop(struct listener *l, struct ev_loop *loop);

#endif /* LISTENER_H */
