/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file udp.c
 * @brief lossymux UDP relay.  A udp_listener reads datagrams from local clients
 *        on the server loop and routes each client, stickily, to one tunnel;
 *        that tunnel's udp_flows gives the client a flow id and sends its
 *        datagrams as mux DATAGRAM frames, relaying the peer's replies back
 *        through the listener's socket.  A DATAGRAM for a flow the peer opened
 *        is relayed to the forward target through a socket connected to it.
 *        Every step is best effort: a datagram that cannot be relayed at once
 *        is dropped and counted.
 */

#include "udp.h"

#include "mux/mux.h"
#include "shim/util.h"

#include "algo/hashtable.h"
#include "os/socket.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Receive buffer size: one past the largest UDP payload, so a datagram too
 * large for any mux frame is caught by MSG_TRUNC rather than cut short. */
#define UDP_RECV_BUFSIZE 65536

/* Datagrams read per readiness callback before yielding to the loop. */
#define UDP_READ_BATCH 64

#if WITH_THREADS
#define UDP_COUNTER_ADD(p, v)                                                  \
	((void)atomic_fetch_add_explicit((p), (v), memory_order_relaxed))
#define UDP_GAUGE_SUB(p, v)                                                    \
	((void)atomic_fetch_sub_explicit((p), (v), memory_order_relaxed))
#else
#define UDP_COUNTER_ADD(p, v) ((void)(*(p) += (v)))
#define UDP_GAUGE_SUB(p, v) ((void)(*(p) -= (v)))
#endif

struct udp_socket {
#if WITH_THREADS
	atomic_size_t refs;
#else
	size_t refs;
#endif
	int fd;
};

struct udp_socket *udp_socket_ref(struct udp_socket *sock)
{
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(&sock->refs, 1, memory_order_relaxed);
#else
	sock->refs++;
#endif
	return sock;
}

void udp_socket_unref(struct udp_socket *sock)
{
#if WITH_THREADS
	/* acq_rel: every sendto() through a dropped reference happens before
	 * the close by whichever thread drops the last one. */
	if (atomic_fetch_sub_explicit(&sock->refs, 1, memory_order_acq_rel) !=
	    1) {
		return;
	}
#else
	if (--sock->refs != 0) {
		return;
	}
#endif /* WITH_THREADS */
	socket_close(sock->fd);
	free(sock);
}

void udp_dgram_free(struct udp_dgram *d)
{
	udp_socket_unref(d->sock);
	free(d);
}

/* Create a nonblocking, close-on-exec UDP socket for sa's family; -1 (logged)
 * on failure. */
static int udp_socket_open(const struct sockaddr *restrict sa)
{
	const int fd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: (%d) %s", err, strerror(err));
		return -1;
	}
	LOG_SOCKOPT("socket_set_cloexec", socket_set_cloexec(fd));
	if (socket_set_nonblock(fd) != 0) {
		const int err = errno;
		LOGE_F("socket_set_nonblock: (%d) %s", err, strerror(err));
		socket_close(fd);
		return -1;
	}
	return fd;
}

enum udp_recv_result {
	UDP_RECV_OK, /* a datagram was read; it may be empty */
	UDP_RECV_TRUNCATED, /* one too large for any frame was discarded */
	UDP_RECV_NONE, /* nothing more can be read now */
};

/* Read one datagram from fd into buf (UDP_RECV_BUFSIZE bytes), storing its
 * length in *len and, when from is non-NULL, its sender in *from. */
static enum udp_recv_result udp_recv(
	const int fd, unsigned char *restrict buf,
	union sockaddr_max *restrict from, size_t *restrict len)
{
	for (;;) {
		struct iovec iov = {
			.iov_base = buf,
			.iov_len = UDP_RECV_BUFSIZE,
		};
		struct msghdr msg = {
			.msg_name = from,
			.msg_namelen = from != NULL ? sizeof(*from) : 0,
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};
		const ssize_t n = recvmsg(fd, &msg, 0);
		if (n < 0) {
			const int err = errno;
			/* A connected socket reports an earlier send's ICMP
			 * error once; later datagrams are still readable. */
			if (err == EINTR || err == ECONNREFUSED) {
				continue;
			}
			if (!sock_would_block(err)) {
				LOGD_F("[fd:%d] recvmsg: (%d) %s", fd, err,
				       strerror(err));
			}
			return UDP_RECV_NONE;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			return UDP_RECV_TRUNCATED;
		}
		*len = (size_t)n;
		return UDP_RECV_OK;
	}
}

/* --- Listener --- */

/* A client's sticky choice of tunnel; keyed by its zero-padded address. */
struct udp_route {
	union sockaddr_max client;
	struct hashkey key;
	void *target;
	ev_tstamp last_seen;
};

struct udp_listener {
	struct ev_loop *loop;
	ev_io w_read;
	ev_timer w_sweep;
	struct udp_socket *sock;
	/* client address -> struct udp_route; NULL until the first route. */
	struct hashtable *routes;
	struct udp_listener_cb cb;
	double idle_timeout;
	uint_least64_t *num_dropped;
	unsigned char buf[UDP_RECV_BUFSIZE];
};

/* Sweep often enough that an idle entry outlives its timeout by at most half
 * of it again, and never more than once a second. */
static double sweep_interval(const double idle_timeout)
{
	return idle_timeout > 2.0 ? idle_timeout / 2.0 : 1.0;
}

static bool route_free_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	(void)data;
	free(element);
	return true;
}

static bool route_expire_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	const struct udp_listener *const restrict l = data;
	struct udp_route *const restrict r = element;
	if (ev_now(l->loop) - r->last_seen < l->idle_timeout) {
		return true;
	}
	free(r);
	return false;
}

static void
listener_sweep_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct udp_listener *const restrict l = w->data;
	l->routes = table_filter(l->routes, route_expire_cb, l);
	if (table_size(l->routes) == 0) {
		ev_timer_stop(loop, w);
	}
}

/* The route for a client seen for the first time; NULL (datagram dropped) when
 * no tunnel can take it or on allocation failure. */
static struct udp_route *listener_add_route(
	struct udp_listener *restrict l,
	const union sockaddr_max *restrict client)
{
	void *const target = l->cb.pick(l->cb.ctx);
	if (target == NULL) {
		LOGD("udp: no session to route a new client to");
		return NULL;
	}
	if (l->routes == NULL) {
		l->routes = table_new(&TABLE_OPTS_BYTES);
		if (l->routes == NULL) {
			LOGOOM();
			return NULL;
		}
	}
	struct udp_route *const restrict r = malloc(sizeof(*r));
	if (r == NULL) {
		LOGOOM();
		return NULL;
	}
	*r = (struct udp_route){
		.client = *client,
		.target = target,
	};
	r->key = (struct hashkey){
		.len = sizeof(r->client),
		.data = &r->client,
	};
	void *elem = r;
	l->routes = table_set(l->routes, &r->key, &elem);
	if (elem == r) {
		LOGOOM();
		free(r);
		return NULL;
	}
	if (!ev_is_active(&l->w_sweep)) {
		l->w_sweep.repeat = sweep_interval(l->idle_timeout);
		ev_timer_again(l->loop, &l->w_sweep);
	}
	return r;
}

/* Route one datagram read into l->buf to its client's tunnel. */
static void listener_route(
	struct udp_listener *restrict l,
	const union sockaddr_max *restrict client, const size_t len)
{
	const struct hashkey key = {
		.len = sizeof(*client),
		.data = client,
	};
	void *elem = NULL;
	struct udp_route *r = NULL;
	if (l->routes != NULL && table_find(l->routes, &key, &elem)) {
		r = elem;
	} else {
		r = listener_add_route(l, client);
	}
	struct udp_dgram *const restrict d =
		r != NULL ? malloc(sizeof(*d) + len) : NULL;
	if (d == NULL) {
		if (r != NULL) {
			LOGOOM();
		}
		(*l->num_dropped)++;
		return;
	}
	r->last_seen = ev_now(l->loop);
	d->next = NULL;
	d->sock = udp_socket_ref(l->sock);
	d->from = *client;
	d->len = len;
	(void)memcpy(d->data, l->buf, len);
	/* Last use of r: delivering can free the target tunnel, which forgets
	 * every route to it. */
	l->cb.deliver(l->cb.ctx, r->target, d);
}

static void listener_read_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	CHECK_REVENTS(revents, EV_READ);
	struct udp_listener *const restrict l = w->data;
	for (int i = 0; i < UDP_READ_BATCH; i++) {
		/* Zeroed so the padding past the address is a stable key. */
		union sockaddr_max client;
		(void)memset(&client, 0, sizeof(client));
		size_t n;
		switch (udp_recv(l->sock->fd, l->buf, &client, &n)) {
		case UDP_RECV_OK:
			listener_route(l, &client, n);
			break;
		case UDP_RECV_TRUNCATED:
			(*l->num_dropped)++;
			break;
		case UDP_RECV_NONE:
			return;
		}
	}
}

struct udp_listener *udp_listener_new(
	struct ev_loop *loop, const struct sockaddr *sa, const bool reuseport,
	const struct udp_listener_cb *cb, const double idle_timeout,
	uint_least64_t *num_dropped)
{
	struct udp_listener *const restrict l = malloc(sizeof(*l));
	struct udp_socket *const restrict sock = malloc(sizeof(*sock));
	if (l == NULL || sock == NULL) {
		LOGOOM();
		free(l);
		free(sock);
		return NULL;
	}
	const int fd = udp_socket_open(sa);
	if (fd < 0) {
		free(l);
		free(sock);
		return NULL;
	}
	/* SO_REUSEADDR lets a reload bind again while flows still hold the
	 * socket a previous listener on the same address left behind. */
	LOG_SOCKOPT(
		"socket_set_reuseport", socket_set_reuseport(fd, reuseport));
	if (bind(fd, sa, sa_len(sa)) != 0) {
		const int err = errno;
		LOGE_F("bind: (%d) %s", err, strerror(err));
		socket_close(fd);
		free(l);
		free(sock);
		return NULL;
	}
	sock->refs = 1;
	sock->fd = fd;
	l->loop = loop;
	l->sock = sock;
	l->routes = NULL;
	l->cb = *cb;
	l->idle_timeout = idle_timeout;
	l->num_dropped = num_dropped;
	ev_io_init(&l->w_read, listener_read_cb, fd, EV_READ);
	l->w_read.data = l;
	ev_timer_init(&l->w_sweep, listener_sweep_cb, 0.0, 0.0);
	l->w_sweep.data = l;
	ev_io_start(loop, &l->w_read);
	return l;
}

void udp_listener_free(struct udp_listener *l)
{
	if (l == NULL) {
		return;
	}
	ev_io_stop(l->loop, &l->w_read);
	ev_timer_stop(l->loop, &l->w_sweep);
	if (l->routes != NULL) {
		table_iterate(l->routes, route_free_cb, NULL);
		table_free(l->routes);
	}
	udp_socket_unref(l->sock);
	free(l);
}

bool udp_listener_get_addr(const struct udp_listener *l, union sockaddr_max *sa)
{
	return socket_get_addr(l->sock->fd, sa) == 0;
}

void udp_listener_set_idle_timeout(
	struct udp_listener *l, const double idle_timeout)
{
	l->idle_timeout = idle_timeout;
	/* Takes effect from the next sweep. */
	l->w_sweep.repeat = sweep_interval(idle_timeout);
}

static bool route_forget_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	struct udp_route *const restrict r = element;
	if (r->target != data) {
		return true;
	}
	free(r);
	return false;
}

void udp_listener_forget(struct udp_listener *l, const void *target)
{
	if (l->routes == NULL) {
		return;
	}
	/* table_filter's data is not const; the target is only compared. */
	l->routes = table_filter(l->routes, route_forget_cb, (void *)target);
	if (table_size(l->routes) == 0) {
		ev_timer_stop(l->loop, &l->w_sweep);
	}
}

/* --- Flow table --- */

/* An active flow's key: the listener socket it arrived on, then the client. */
enum {
	UDP_FLOW_KEY_SIZE =
		sizeof(struct udp_socket *) + sizeof(union sockaddr_max),
};

struct udp_flow {
	uint_least16_t id;
	ev_tstamp last_seen;
	/* Passive flow (the peer opened it): the socket connected to the
	 * forward target, read by w_read.  Unused on an active flow. */
	ev_io w_read;
	/* Active flow (a local client opened it): the listener socket that
	 * replies go out through, and the client they go to.  NULL sock marks a
	 * passive flow. */
	struct udp_socket *sock;
	union sockaddr_max client;
	struct hashkey key;
	unsigned char key_data[UDP_FLOW_KEY_SIZE];
	struct udp_flows *owner;
};

struct udp_flows {
	struct ev_loop *loop;
	struct mux_session *ss;
	/* flow id -> struct udp_flow, every flow; NULL until the first. */
	struct hashtable *by_id;
	/* active-flow key -> struct udp_flow; NULL until the first. */
	struct hashtable *by_client;
	ev_timer w_sweep;
	/* Next id to try for a flow this side opens. */
	uint_least16_t next_id;
	/* Parity of the ids this side opens: 1 odd, 0 even. */
	uint_least16_t parity;
	mux_counter *num_dropped;
	mux_gauge *num_flows;
	/* Passive-flow receive buffer; allocated with the first such flow. */
	unsigned char *buf;
};

static void flow_key(
	unsigned char *restrict key, const struct udp_socket *sock,
	const union sockaddr_max *restrict client)
{
	(void)memcpy(key, (const void *)&sock, sizeof(struct udp_socket *));
	(void)memcpy(
		key + sizeof(struct udp_socket *), client, sizeof(*client));
}

static void *flow_id_key(const uint_fast16_t id)
{
	return (void *)(uintptr_t)id;
}

static double flows_idle_timeout(const struct udp_flows *restrict f)
{
	return (double)mux_conf(f->ss)->lossymux_idle_timeout;
}

static void flows_drop(const struct udp_flows *restrict f)
{
	UDP_COUNTER_ADD(f->num_dropped, 1);
}

/* Release what a flow holds; the caller has already unlinked it. */
static void flow_free(struct udp_flows *restrict f, struct udp_flow *flow)
{
	if (flow->sock != NULL) {
		udp_socket_unref(flow->sock);
	} else {
		ev_io_stop(f->loop, &flow->w_read);
		socket_close(flow->w_read.fd);
	}
	UDP_GAUGE_SUB(f->num_flows, 1);
	free(flow);
}

/* Unlink flow from both tables and free it. */
static void flow_close(struct udp_flows *restrict f, struct udp_flow *flow)
{
	LOGD_F("udp: flow %" PRIuLEAST16 " closed", flow->id);
	f->by_id = table_del(f->by_id, flow_id_key(flow->id), NULL);
	if (flow->sock != NULL) {
		f->by_client = table_del(f->by_client, &flow->key, NULL);
	}
	flow_free(f, flow);
}

static bool flow_expire_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	struct udp_flows *const restrict f = data;
	struct udp_flow *const flow = element;
	if (ev_now(f->loop) - flow->last_seen < flows_idle_timeout(f)) {
		return true;
	}
	LOGD_F("udp: flow %" PRIuLEAST16 " expired", flow->id);
	if (flow->sock != NULL) {
		f->by_client = table_del(f->by_client, &flow->key, NULL);
	}
	mux_dgram_close(f->ss, flow->id);
	flow_free(f, flow);
	return false;
}

static void flows_sweep_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct udp_flows *const restrict f = w->data;
	f->by_id = table_filter(f->by_id, flow_expire_cb, f);
	if (udp_flows_count(f) == 0) {
		ev_timer_stop(loop, w);
		return;
	}
	/* Follow a reloaded idle timeout. */
	w->repeat = sweep_interval(flows_idle_timeout(f));
	ev_timer_again(loop, w);
}

/* Register a new flow under its id and start its idle clock. */
static bool
flows_add(struct udp_flows *restrict f, struct udp_flow *restrict flow)
{
	if (f->by_id == NULL) {
		f->by_id = table_new(&TABLE_OPTS_PTR);
		if (f->by_id == NULL) {
			LOGOOM();
			return false;
		}
	}
	void *elem = flow;
	f->by_id = table_set(f->by_id, flow_id_key(flow->id), &elem);
	if (elem == flow) {
		LOGOOM();
		return false;
	}
	flow->last_seen = ev_now(f->loop);
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(f->num_flows, 1, memory_order_relaxed);
#else
	(*f->num_flows)++;
#endif
	if (!ev_is_active(&f->w_sweep)) {
		f->w_sweep.repeat = sweep_interval(flows_idle_timeout(f));
		ev_timer_again(f->loop, &f->w_sweep);
	}
	return true;
}

/* A free id of this side's parity, or 0 when every one is taken. */
static uint_least16_t flows_alloc_id(struct udp_flows *restrict f)
{
	for (uint_fast32_t i = 0; i < 0x8000u; i++) {
		const uint_least16_t id = f->next_id;
		const uint_fast32_t next = (uint_fast32_t)id + 2u;
		f->next_id = next > UINT16_MAX ?
				     (uint_least16_t)(2u - f->parity) :
				     (uint_least16_t)next;
		void *elem;
		if (f->by_id == NULL ||
		    !table_find(f->by_id, flow_id_key(id), &elem)) {
			return id;
		}
	}
	return 0;
}

/* Open an active flow for a client first seen on d's socket. */
static struct udp_flow *flow_open_active(
	struct udp_flows *restrict f, const struct udp_dgram *restrict d,
	const unsigned char *restrict key)
{
	const uint_least16_t id = flows_alloc_id(f);
	if (id == 0) {
		LOGW("udp: every flow id is in use");
		return NULL;
	}
	if (f->by_client == NULL) {
		f->by_client = table_new(&TABLE_OPTS_BYTES);
		if (f->by_client == NULL) {
			LOGOOM();
			return NULL;
		}
	}
	struct udp_flow *const flow = malloc(sizeof(*flow));
	if (flow == NULL) {
		LOGOOM();
		return NULL;
	}
	*flow = (struct udp_flow){
		.id = id,
		.client = d->from,
		.owner = f,
	};
	(void)memcpy(flow->key_data, key, sizeof(flow->key_data));
	flow->key = (struct hashkey){
		.len = sizeof(flow->key_data),
		.data = flow->key_data,
	};
	void *elem = flow;
	f->by_client = table_set(f->by_client, &flow->key, &elem);
	if (elem == flow) {
		LOGOOM();
		free(flow);
		return NULL;
	}
	flow->sock = udp_socket_ref(d->sock);
	if (!flows_add(f, flow)) {
		f->by_client = table_del(f->by_client, &flow->key, NULL);
		udp_socket_unref(flow->sock);
		free(flow);
		return NULL;
	}
	if (LOGLEVEL(DEBUG)) {
		char addr_str[64];
		(void)sa_format(addr_str, sizeof(addr_str), &d->from.sa);
		LOGD_F("udp: flow %" PRIuLEAST16 " opened for %s", id,
		       addr_str);
	}
	return flow;
}

void udp_flows_input(struct udp_flows *f, struct udp_dgram *d)
{
	if (!mux_dgram_ready(f->ss)) {
		flows_drop(f);
		udp_dgram_free(d);
		return;
	}
	unsigned char key[UDP_FLOW_KEY_SIZE];
	flow_key(key, d->sock, &d->from);
	const struct hashkey hkey = { .len = sizeof(key), .data = key };
	void *elem = NULL;
	struct udp_flow *flow = NULL;
	if (f->by_client != NULL && table_find(f->by_client, &hkey, &elem)) {
		flow = elem;
	} else {
		flow = flow_open_active(f, d, key);
	}
	if (flow == NULL) {
		flows_drop(f);
		udp_dgram_free(d);
		return;
	}
	flow->last_seen = ev_now(f->loop);
	/* mux_dgram_send counts its own drops. */
	(void)mux_dgram_send(f->ss, flow->id, d->data, d->len);
	udp_dgram_free(d);
}

static void passive_read_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct udp_flow *const restrict flow = w->data;
	struct udp_flows *const restrict f = flow->owner;
	for (int i = 0; i < UDP_READ_BATCH; i++) {
		size_t n;
		switch (udp_recv(w->fd, f->buf, NULL, &n)) {
		case UDP_RECV_OK:
			flow->last_seen = ev_now(loop);
			(void)mux_dgram_send(f->ss, flow->id, f->buf, n);
			break;
		case UDP_RECV_TRUNCATED:
			flows_drop(f);
			break;
		case UDP_RECV_NONE:
			return;
		}
	}
}

/* Open a passive flow toward forward_addr for an id the peer chose. */
static struct udp_flow *flow_open_passive(
	struct udp_flows *restrict f, const uint_least16_t id,
	const char *restrict forward_addr)
{
	union sockaddr_max addr;
	if (!resolve_addr(&addr, forward_addr, SA_RESOLVE_UDP)) {
		LOGW_F("udp: flow %" PRIuLEAST16
		       ": name resolution failed for \"%.256s\"",
		       id, forward_addr);
		return NULL;
	}
	if (f->buf == NULL) {
		f->buf = malloc(UDP_RECV_BUFSIZE);
		if (f->buf == NULL) {
			LOGOOM();
			return NULL;
		}
	}
	const int fd = udp_socket_open(&addr.sa);
	if (fd < 0) {
		return NULL;
	}
	if (connect(fd, &addr.sa, sa_len(&addr.sa)) != 0) {
		const int err = errno;
		LOGW_F("udp: flow %" PRIuLEAST16 ": connect: (%d) %s", id, err,
		       strerror(err));
		socket_close(fd);
		return NULL;
	}
	struct udp_flow *const flow = malloc(sizeof(*flow));
	if (flow == NULL) {
		LOGOOM();
		socket_close(fd);
		return NULL;
	}
	*flow = (struct udp_flow){
		.id = id,
		.owner = f,
	};
	ev_io_init(&flow->w_read, passive_read_cb, fd, EV_READ);
	flow->w_read.data = flow;
	if (!flows_add(f, flow)) {
		socket_close(fd);
		free(flow);
		return NULL;
	}
	ev_io_start(f->loop, &flow->w_read);
	if (LOGLEVEL(DEBUG)) {
		char addr_str[64];
		(void)sa_format(addr_str, sizeof(addr_str), &addr.sa);
		LOGD_F("udp: flow %" PRIuLEAST16 " opened to %s [fd:%d]", id,
		       addr_str, fd);
	}
	return flow;
}

void udp_flows_recv(
	struct udp_flows *f, const uint_least16_t flow_id,
	const unsigned char *payload, const size_t len,
	const char *forward_addr)
{
	void *elem = NULL;
	struct udp_flow *flow = NULL;
	if (f->by_id != NULL &&
	    table_find(f->by_id, flow_id_key(flow_id), &elem)) {
		flow = elem;
	} else if ((flow_id & 1u) != f->parity && forward_addr != NULL) {
		flow = flow_open_passive(f, flow_id, forward_addr);
	}
	if (flow == NULL) {
		/* Ours but already gone, refused, or failed to open: tell the
		 * peer so it stops sending. */
		flows_drop(f);
		mux_dgram_close(f->ss, flow_id);
		return;
	}
	flow->last_seen = ev_now(f->loop);
	ssize_t n;
	int fd;
	if (flow->sock != NULL) {
		fd = flow->sock->fd;
		n =
			sendto(fd, payload, len, 0, &flow->client.sa,
			       sa_len(&flow->client.sa));
	} else {
		fd = flow->w_read.fd;
		n = send(fd, payload, len, 0);
	}
	if (n < 0) {
		const int err = errno;
		if (!sock_would_block(err)) {
			LOGD_F("udp: flow %" PRIuLEAST16
			       " [fd:%d] send: (%d) %s",
			       flow_id, fd, err, strerror(err));
		}
		flows_drop(f);
	}
}

void udp_flows_recv_close(struct udp_flows *f, const uint_least16_t flow_id)
{
	void *elem;
	if (f->by_id == NULL ||
	    !table_find(f->by_id, flow_id_key(flow_id), &elem)) {
		return;
	}
	flow_close(f, elem);
	if (udp_flows_count(f) == 0) {
		ev_timer_stop(f->loop, &f->w_sweep);
	}
}

struct udp_flows *udp_flows_new(
	struct ev_loop *loop, struct mux_session *ss, const bool accepted,
	mux_counter *num_dropped, mux_gauge *num_flows)
{
	struct udp_flows *const restrict f = malloc(sizeof(*f));
	if (f == NULL) {
		LOGOOM();
		return NULL;
	}
	const uint_least16_t parity = accepted ? 0u : 1u;
	*f = (struct udp_flows){
		.loop = loop,
		.ss = ss,
		.parity = parity,
		.next_id = (uint_least16_t)(2u - parity),
		.num_dropped = num_dropped,
		.num_flows = num_flows,
	};
	ev_timer_init(&f->w_sweep, flows_sweep_cb, 0.0, 0.0);
	f->w_sweep.data = f;
	return f;
}

static bool flow_free_cb(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	flow_free(data, element);
	return true;
}

void udp_flows_reset(struct udp_flows *f)
{
	ev_timer_stop(f->loop, &f->w_sweep);
	if (f->by_id != NULL) {
		table_iterate(f->by_id, flow_free_cb, f);
		table_free(f->by_id);
		f->by_id = NULL;
	}
	table_free(f->by_client);
	f->by_client = NULL;
}

void udp_flows_free(struct udp_flows *f)
{
	if (f == NULL) {
		return;
	}
	udp_flows_reset(f);
	free(f->buf);
	free(f);
}

size_t udp_flows_count(const struct udp_flows *f)
{
	return f->by_id != NULL ? table_size(f->by_id) : 0;
}
