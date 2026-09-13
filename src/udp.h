/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file udp.h
 * @brief lossymux UDP relay (doc/spec.md 5.2.3.3): the UDP socket bound on a
 *        local listen address (server loop), and the per-tunnel flow table that
 *        maps UDP flows onto mux datagrams (tunnel loop).
 */

#ifndef UDP_H
#define UDP_H

#include "mux/mux.h"

#include "os/socket.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct hashtable;

/* A bound UDP socket shared, by reference count, between the udp_listener
 * reading it and every flow relaying replies through it, so the descriptor
 * outlives a listener stopped by a reload until its last flow expires.
 * References may be taken and dropped on any thread. */
struct udp_socket;

/* Take one more reference to sock; returns sock. */
struct udp_socket *udp_socket_ref(struct udp_socket *sock);

/* Drop one reference; the last one closes the descriptor. */
void udp_socket_unref(struct udp_socket *sock);

/* One datagram read by a udp_listener, on its way to a tunnel's flows. */
struct udp_dgram {
	/* Intrusive FIFO link for an owner carrying it across threads. */
	struct udp_dgram *next;
	/* The socket it arrived on; the datagram holds one reference. */
	struct udp_socket *sock;
	/* Its sender, zero-padded so it can serve as a flow key. */
	union sockaddr_max from;
	size_t len;
	unsigned char data[];
};

/* Drop d's socket reference and free it. */
void udp_dgram_free(struct udp_dgram *d);

/* --- Listener: one bound UDP socket, on the server loop --- */

struct udp_listener_cb {
	/* Choose the tunnel for a client address seen for the first time (or
	 * again after its route expired); NULL drops the datagram. */
	void *(*pick)(void *ctx);
	/* Hand d to target, a value pick() returned; always consumes d. */
	void (*deliver)(void *ctx, void *target, struct udp_dgram *d);
	void *ctx;
};

struct udp_listener;

/**
 * @brief Bind a UDP socket on @p sa and start reading it.
 * @param reuseport Also set SO_REUSEPORT (SO_REUSEADDR is always set).
 * @param idle_timeout Seconds a client's route to its tunnel survives without a
 * datagram from that client.
 * @param num_dropped Counts datagrams dropped before reaching a tunnel; plain,
 * since it is only touched on the server loop.
 * @return The listener, or NULL (logged) on failure.
 */
struct udp_listener *udp_listener_new(
	struct ev_loop *loop, const struct sockaddr *sa, bool reuseport,
	const struct udp_listener_cb *cb, double idle_timeout,
	uint_least64_t *num_dropped);

/* Stop reading and drop the listener's socket reference; flows still relaying
 * through the socket keep it open until they expire.  NULL is a no-op. */
void udp_listener_free(struct udp_listener *l);

/* The address the listener's socket is bound to; false if it cannot be read. */
bool udp_listener_get_addr(const struct udp_listener *l, union sockaddr_max *sa);

/* Change the route idle timeout (config reload). */
void udp_listener_set_idle_timeout(struct udp_listener *l, double idle_timeout);

/* Drop every route to @p target, a tunnel about to be freed. */
void udp_listener_forget(struct udp_listener *l, const void *target);

/* --- Flow table: one per tunnel, on the tunnel loop --- */

struct udp_flows;

/**
 * @brief Create an empty flow table for the session @p ss.
 * @param accepted The session is server-role: flows it opens take even ids,
 * the peer's odd ones (the stream-id parity rule).
 * @param num_dropped Counts datagrams the flow table drops; the same storage
 * the session counts its own drops into.
 * @param num_flows Gauge of live flows.
 * @return The table, or NULL on allocation failure.
 */
struct udp_flows *udp_flows_new(
	struct ev_loop *loop, struct mux_session *ss, bool accepted,
	mux_counter *num_dropped, mux_gauge *num_flows);

/* Free every flow without telling the peer, then the table.  NULL is a no-op. */
void udp_flows_free(struct udp_flows *f);

/* Free every flow without telling the peer: the session they belonged to is
 * gone, and a fresh one starts with none. */
void udp_flows_reset(struct udp_flows *f);

/* Relay a datagram a local client sent to a udp_listener; consumes d. */
void udp_flows_input(struct udp_flows *f, struct udp_dgram *d);

/**
 * @brief Relay a DATAGRAM the peer sent on @p flow.
 * @param forward_addr Target a flow the peer opens is relayed to; NULL refuses
 * it.  Only read when the flow is new.
 */
void udp_flows_recv(
	struct udp_flows *f, uint_least16_t flow, const unsigned char *payload,
	size_t len, const char *forward_addr);

/* The peer dropped @p flow (FLOW-CLOSE); free it here too. */
void udp_flows_recv_close(struct udp_flows *f, uint_least16_t flow);

/* Number of live flows. */
size_t udp_flows_count(const struct udp_flows *f);

#endif /* UDP_H */
