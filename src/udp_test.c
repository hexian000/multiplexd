/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* udp_test.c - white-box tests for the lossymux UDP relay in udp.c.  The mux
 * session is replaced by a recording fake (the four mux calls udp.c makes), so
 * flows are driven directly while real loopback UDP sockets carry the local
 * side.  Dependencies: compiles udp.c into this TU; links the shim and
 * csnippets. */

#include "udp.h"

#include "mux/mux.h"
#include "shim/util.h"

#include "algo/hashtable.h"
#include "os/socket.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* --- fake mux session: records what the flow table asks of it --- */

enum { FAKE_MAX_RECORDS = 16, FAKE_MAX_LEN = 64 };

struct fake_dgram {
	uint_least16_t flow;
	size_t len;
	unsigned char data[FAKE_MAX_LEN];
};

struct mux_session {
	struct mux_session_config conf;
	bool ready;
	size_t num_sent;
	struct fake_dgram sent[FAKE_MAX_RECORDS];
	size_t num_closed;
	uint_least16_t closed[FAKE_MAX_RECORDS];
};

bool mux_dgram_ready(const struct mux_session *ss)
{
	return ss->ready;
}

bool mux_dgram_send(
	struct mux_session *ss, const uint_least16_t flow, const void *buf,
	const size_t len)
{
	if (!ss->ready || ss->num_sent >= FAKE_MAX_RECORDS) {
		return false;
	}
	struct fake_dgram *const d = &ss->sent[ss->num_sent++];
	d->flow = flow;
	d->len = len;
	(void)memcpy(d->data, buf, len < FAKE_MAX_LEN ? len : FAKE_MAX_LEN);
	return true;
}

void mux_dgram_close(struct mux_session *ss, const uint_least16_t flow)
{
	if (ss->num_closed < FAKE_MAX_RECORDS) {
		ss->closed[ss->num_closed++] = flow;
	}
}

const struct mux_session_config *mux_conf(const struct mux_session *ss)
{
	return &ss->conf;
}

/* frame.c data global the fixtures copy; stubbed here since this TU links no
 * mux code.  Keep the lossymux fields in step with frame.c. */
const struct mux_session_config mux_session_config_default = {
	.max_frame_payload = 16384 - MUX_FRAME_HEADER_SIZE,
	.readahead = 128 * 1024,
	.lossymux_idle_timeout = 60,
	.lossymux_queue = 64,
};

enum table_failure_point {
	TABLE_FAIL_NONE,
	TABLE_FAIL_ID_NEW,
	TABLE_FAIL_ID_SET,
};

static struct {
	enum table_failure_point point;
	struct udp_flows *flows;
	struct udp_socket *sock;
	size_t hits;
	size_t clients;
	size_t refs;
} table_failure;

static struct {
	bool watch;
	int fd;
	void *flow;
	size_t allocations;
	size_t frees;
	bool connected_at_failure;
	bool read_active_at_free;
} passive_allocation;

static struct {
	int fd;
	int error;
	size_t hits;
} send_failure;

static bool watch_udp_allocations;
static size_t udp_malloc_calls;

struct recv_step {
	int error;
	int flags;
	const char *data;
};

static struct {
	bool active;
	int fd;
	const struct recv_step *steps;
	size_t count;
	size_t next;
	size_t overruns;
	union sockaddr_max from;
} recv_script;

static void *test_malloc(size_t size);
static void test_free(void *ptr);
static int test_connect(int fd, const struct sockaddr *addr, socklen_t len);
static ssize_t test_send(int fd, const void *buf, size_t len, int flags);
static ssize_t test_recvmsg(int fd, struct msghdr *msg, int flags);
static ssize_t test_sendto(
	int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *addr, socklen_t addrlen);

static struct hashtable *test_table_new(const struct table_opts *opts);
static struct hashtable *
test_table_set(struct hashtable *table, const void *key, void **element);

/* Pull in the unit under test after the fakes so its references bind here. */
#define malloc test_malloc
#define free test_free
#define connect test_connect
#define send test_send
#define sendto test_sendto
#define recvmsg test_recvmsg
#define table_new test_table_new
#define table_set test_table_set
#include "udp.c"
#undef recvmsg
#undef table_new
#undef table_set
#undef connect
#undef sendto
#undef send
#undef free
#undef malloc

static void *test_malloc(const size_t size)
{
	if (watch_udp_allocations) {
		udp_malloc_calls++;
	}
	void *const ptr = malloc(size);
	if (passive_allocation.watch && size == sizeof(struct udp_flow)) {
		passive_allocation.flow = ptr;
		passive_allocation.allocations++;
	}
	return ptr;
}

static void test_free(void *ptr)
{
	if (passive_allocation.watch && ptr != NULL &&
	    ptr == passive_allocation.flow) {
		const struct udp_flow *const flow = passive_allocation.flow;
		passive_allocation.read_active_at_free =
			ev_is_active(&flow->w_read);
		passive_allocation.flow = NULL;
		passive_allocation.frees++;
	}
	free(ptr);
}

static int
test_connect(const int fd, const struct sockaddr *addr, const socklen_t len)
{
	const int result = connect(fd, addr, len);
	if (passive_allocation.watch && result == 0) {
		passive_allocation.fd = fd;
	}
	return result;
}

static bool fail_send(const int fd)
{
	if (send_failure.error == 0 || send_failure.fd != fd) {
		return false;
	}
	errno = send_failure.error;
	send_failure.hits++;
	return true;
}

static ssize_t
test_send(const int fd, const void *buf, const size_t len, const int flags)
{
	return fail_send(fd) ? -1 : send(fd, buf, len, flags);
}

static ssize_t test_sendto(
	const int fd, const void *buf, const size_t len, const int flags,
	const struct sockaddr *addr, const socklen_t addrlen)
{
	return fail_send(fd) ? -1 : sendto(fd, buf, len, flags, addr, addrlen);
}

static ssize_t test_recvmsg(const int fd, struct msghdr *msg, const int flags)
{
	if (!recv_script.active || fd != recv_script.fd) {
		return recvmsg(fd, msg, flags);
	}
	if (recv_script.next == recv_script.count) {
		recv_script.overruns++;
		errno = EIO;
		return -1;
	}
	const struct recv_step *const step =
		&recv_script.steps[recv_script.next++];
	if (step->error != 0) {
		errno = step->error;
		return -1;
	}
	const size_t len = strlen(step->data);
	(void)memcpy(msg->msg_iov[0].iov_base, step->data, len);
	msg->msg_flags = step->flags;
	if (msg->msg_name != NULL) {
		(void)memcpy(
			msg->msg_name, &recv_script.from,
			sizeof(struct sockaddr_in));
		msg->msg_namelen = sizeof(struct sockaddr_in);
	}
	return (ssize_t)len;
}

static void record_table_failure(void)
{
	table_failure.point = TABLE_FAIL_NONE;
	table_failure.hits++;
	table_failure.clients = table_size(table_failure.flows->by_client);
	table_failure.refs = table_failure.sock != NULL ?
				     (size_t)table_failure.sock->refs :
				     0;
	if (passive_allocation.watch && passive_allocation.fd >= 0) {
		union sockaddr_max peer;
		passive_allocation.connected_at_failure =
			socket_get_peer(passive_allocation.fd, &peer) == 0;
	}
}

static struct hashtable *test_table_new(const struct table_opts *opts)
{
	if (table_failure.point == TABLE_FAIL_ID_NEW &&
	    opts == &TABLE_OPTS_PTR) {
		record_table_failure();
		return NULL;
	}
	return table_new(opts);
}

static struct hashtable *
test_table_set(struct hashtable *table, const void *key, void **element)
{
	if (table_failure.point == TABLE_FAIL_ID_SET &&
	    table == table_failure.flows->by_id) {
		record_table_failure();
		return table;
	}
	return table_set(table, key, element);
}

/* --- fixture --- */

struct udp_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
	struct udp_flows *flows;
	mux_counter dropped;
	mux_gauge num_flows;
	struct udp_listener *listener;
	uint_least64_t listener_dropped;
	union sockaddr_max listener_addr;
	/* Tunnels the listener picked, counting how often pick() ran. */
	int picks;
	bool refuse_pick;
	size_t borrowed_calls;
	size_t invalid_views;
};

static void *fx_pick(void *ctx)
{
	struct udp_fixture *const fx = ctx;
	fx->picks++;
	return fx->refuse_pick ? NULL : fx->flows;
}

static void fx_deliver(void *ctx, void *target, struct udp_dgram *d)
{
	(void)ctx;
	udp_flows_input(target, d);
}

static void
fx_deliver_borrowed(void *ctx, void *target, const struct udp_dgram_view *d)
{
	struct udp_fixture *const fx = ctx;
	fx->borrowed_calls++;
	if (d->sock != fx->listener->sock || d->data != fx->listener->buf) {
		fx->invalid_views++;
	}
	udp_flows_input_borrowed(target, d);
}

static const union sockaddr_max *loopback_any_port(void)
{
	static union sockaddr_max sa;
	(void)memset(&sa, 0, sizeof(sa));
	sa.in.sin_family = AF_INET;
	sa.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.in.sin_port = 0;
	return &sa;
}

/* Flows for a dialing (odd-id) or accepting (even-id) session, plus a UDP
 * listener on 127.0.0.1 routing every client to them. */
static int
udp_fixture_setup(struct udp_fixture *restrict fx, const bool accepted)
{
	*fx = (struct udp_fixture){ 0 };
	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}
	fx->ss.conf = mux_session_config_default;
	fx->ss.ready = true;
	fx->flows = udp_flows_new(
		fx->loop, &fx->ss, accepted, &fx->dropped, &fx->num_flows);
	if (fx->flows == NULL) {
		return -1;
	}
	const struct udp_listener_cb cb = {
		.pick = fx_pick,
		.deliver = fx_deliver,
		.ctx = fx,
	};
	fx->listener = udp_listener_new(
		fx->loop, &loopback_any_port()->sa, false, &cb, 60.0,
		&fx->listener_dropped);
	if (fx->listener == NULL ||
	    !udp_listener_get_addr(fx->listener, &fx->listener_addr)) {
		return -1;
	}
	return 0;
}

static void udp_fixture_teardown(struct udp_fixture *restrict fx)
{
	udp_listener_free(fx->listener);
	fx->listener = NULL;
	udp_flows_free(fx->flows);
	fx->flows = NULL;
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* A blocking loopback UDP socket with a 1 s receive timeout, so a lost reply
 * fails the case instead of hanging it. */
static int client_socket(void)
{
	const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}
	const struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (bind(fd, &loopback_any_port()->sa, sizeof(struct sockaddr_in)) !=
	    0) {
		(void)close(fd);
		return -1;
	}
	return fd;
}

static bool
send_to(const int fd, const union sockaddr_max *restrict to, const char *msg)
{
	const ssize_t n =
		sendto(fd, msg, strlen(msg), 0, &to->sa, sa_len(&to->sa));
	return n == (ssize_t)strlen(msg);
}

/* Receive one datagram into buf as a string; false on timeout. */
static bool recv_str(const int fd, char *restrict buf, const size_t cap)
{
	const ssize_t n = recv(fd, buf, cap - 1, 0);
	if (n < 0) {
		return false;
	}
	buf[n] = '\0';
	return true;
}

static bool recv_empty(const int fd, union sockaddr_max *restrict from)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	if (poll(&pfd, 1, 1000) != 1 || !(pfd.revents & POLLIN)) {
		return false;
	}
	unsigned char buf;
	socklen_t from_len = sizeof(*from);
	return recvfrom(
		       fd, &buf, sizeof(buf), MSG_DONTWAIT, &from->sa,
		       &from_len) == 0;
}

static struct udp_route *
client_route(const struct udp_listener *restrict listener, const int fd)
{
	union sockaddr_max client = { 0 };
	if (socket_get_addr(fd, &client) != 0 || listener->routes == NULL) {
		return NULL;
	}
	const struct hashkey key = {
		.len = sizeof(client),
		.data = &client,
	};
	void *elem = NULL;
	return table_find(listener->routes, &key, &elem) ? elem : NULL;
}

static void guard_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)revents;
	*(bool *)w->data = true;
	ev_break(loop, EVBREAK_ONE);
}

/* The loop drivers take fx without restrict: callbacks dispatched inside
 * ev_run() update it through the session pointer the flow table holds and the
 * listener's callback context. */

/* Run the loop until the fake session has recorded @p want sends, or 1 s. */
static bool run_until_sent(struct udp_fixture *fx, const size_t want)
{
	bool timed_out = false;
	ev_timer guard;
	ev_timer_init(&guard, guard_timer_cb, 1.0, 0.0);
	guard.data = &timed_out;
	ev_timer_start(fx->loop, &guard);
	while (fx->ss.num_sent < want && !timed_out) {
		ev_run(fx->loop, EVRUN_ONCE);
	}
	ev_timer_stop(fx->loop, &guard);
	return fx->ss.num_sent >= want;
}

/* Run the loop until the listener has routed @p want new clients, or 1 s. */
static bool run_until_picks(struct udp_fixture *fx, const int want)
{
	bool timed_out = false;
	ev_timer guard;
	ev_timer_init(&guard, guard_timer_cb, 1.0, 0.0);
	guard.data = &timed_out;
	ev_timer_start(fx->loop, &guard);
	while (fx->picks < want && !timed_out) {
		ev_run(fx->loop, EVRUN_ONCE);
	}
	ev_timer_stop(fx->loop, &guard);
	return fx->picks >= want;
}

static bool
sent_is(const struct fake_dgram *restrict d, const uint_least16_t flow,
	const char *msg)
{
	return d->flow == flow && d->len == strlen(msg) &&
	       memcmp(d->data, msg, d->len) == 0;
}

/* --- test cases --- */

/* Flow ids follow the stream-id parity rule: a dialing session opens odd ids
 * from 1, an accepting one even ids from 2, both wrapping past 65535 without
 * ever yielding 0, and skipping ids still in use. */
T_DECLARE_CASE(test_flows_alloc_id_parity_and_wrap)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	struct mux_session ss = { .conf = mux_session_config_default };
	mux_counter dropped = 0;
	mux_gauge num_flows = 0;
	struct udp_flows *const dial =
		udp_flows_new(loop, &ss, false, &dropped, &num_flows);
	struct udp_flows *const acc =
		udp_flows_new(loop, &ss, true, &dropped, &num_flows);
	T_CHECK(dial != NULL && acc != NULL);

	const uint_least16_t d1 = flows_alloc_id(dial);
	const uint_least16_t d2 = flows_alloc_id(dial);
	const uint_least16_t a1 = flows_alloc_id(acc);
	const uint_least16_t a2 = flows_alloc_id(acc);
	dial->next_id = 65535;
	const uint_least16_t d_last = flows_alloc_id(dial);
	const uint_least16_t d_wrap = flows_alloc_id(dial);
	acc->next_id = 65534;
	const uint_least16_t a_last = flows_alloc_id(acc);
	const uint_least16_t a_wrap = flows_alloc_id(acc);
	/* An id still held by a flow is skipped. */
	dial->next_id = 5;
	dial->by_id = table_new(&TABLE_OPTS_PTR);
	T_CHECK(dial->by_id != NULL);
	void *elem = dial;
	dial->by_id = table_set(dial->by_id, flow_id_key(5), &elem);
	const uint_least16_t d_skip = flows_alloc_id(dial);
	table_free(dial->by_id);
	dial->by_id = NULL;

	udp_flows_free(dial);
	udp_flows_free(acc);
	ev_loop_destroy(loop);

	T_EXPECT_EQ(d1, (uint_least16_t)1);
	T_EXPECT_EQ(d2, (uint_least16_t)3);
	T_EXPECT_EQ(a1, (uint_least16_t)2);
	T_EXPECT_EQ(a2, (uint_least16_t)4);
	T_EXPECT_EQ(d_last, (uint_least16_t)65535);
	T_EXPECT_EQ(d_wrap, (uint_least16_t)1);
	T_EXPECT_EQ(a_last, (uint_least16_t)65534);
	T_EXPECT_EQ(a_wrap, (uint_least16_t)2);
	T_EXPECT_EQ(d_skip, (uint_least16_t)7);
}

struct udp_client_fixture {
	struct udp_fixture fx;
	int client;
};

static void udp_client_fixture_free(void *data)
{
	struct udp_client_fixture *const ef = data;
	table_failure.point = TABLE_FAIL_NONE;
	passive_allocation.watch = false;
	send_failure.error = 0;
	if (ef->client >= 0) {
		(void)close(ef->client);
	}
	udp_fixture_teardown(&ef->fx);
	free(ef);
}

static void check_flows_exhaustion(struct testing_ctx *_t_, const bool accepted)
{
	struct udp_client_fixture *const ef = calloc(1, sizeof(*ef));
	T_CHECK(ef != NULL);
	ef->client = -1;
	T_CLEANUP(udp_client_fixture_free, ef);
	struct udp_fixture *const fx = &ef->fx;
	T_EXPECT_EQ(udp_fixture_setup(fx, accepted), 0);
	ef->client = client_socket();
	T_EXPECT(ef->client >= 0);

	const uint_fast32_t first = accepted ? 2u : 1u;
	const size_t capacity = accepted ? 32767u : 32768u;
	/* Fill the occupied-id table directly, sharing the listener socket
	 * without creating thousands of clients or kernel descriptors. */
	for (uint_fast32_t id = first; id <= UINT16_MAX; id += 2u) {
		struct udp_flow *const flow = calloc(1, sizeof(*flow));
		T_CHECK(flow != NULL);
		flow->id = (uint_least16_t)id;
		flow->owner = fx->flows;
		flow->sock = udp_socket_ref(fx->listener->sock);
		if (!flows_add(fx->flows, flow)) {
			udp_socket_unref(flow->sock);
			free(flow);
			T_FATAL("flows_add failed");
			return;
		}
	}
	T_EXPECT_EQ(udp_flows_count(fx->flows), capacity);
	T_EXPECT_EQ((size_t)fx->num_flows, capacity);
	T_EXPECT_EQ(flows_alloc_id(fx->flows), (uint_least16_t)0);
	const size_t refs = (size_t)fx->listener->sock->refs;

	T_EXPECT(send_to(ef->client, &fx->listener_addr, "full"));
	T_EXPECT(run_until_picks(fx, 1));
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	T_EXPECT_EQ(fx->ss.num_sent, (size_t)0);
	T_EXPECT_EQ(fx->ss.num_closed, (size_t)0);
	T_EXPECT_EQ(udp_flows_count(fx->flows), capacity);
	T_EXPECT_EQ((size_t)fx->num_flows, capacity);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs);
	T_EXPECT(fx->flows->by_client == NULL);
	void *elem = NULL;
	T_EXPECT(!table_find(fx->flows->by_id, flow_id_key(0), &elem));
	for (uint_fast32_t id = first; id <= UINT16_MAX; id += 2u) {
		T_EXPECT(table_find(fx->flows->by_id, flow_id_key(id), &elem));
		const struct udp_flow *const flow = elem;
		T_EXPECT_EQ(flow->id, (uint_least16_t)id);
		T_EXPECT(flow->owner == fx->flows);
		T_EXPECT(flow->sock == fx->listener->sock);
	}

	const uint_least16_t released = accepted ? 65534u : 65535u;
	udp_flows_recv_close(fx->flows, released);
	T_EXPECT_EQ(udp_flows_count(fx->flows), capacity - 1u);
	T_EXPECT_EQ((size_t)fx->num_flows, capacity - 1u);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs - 1u);
	T_EXPECT_EQ(flows_alloc_id(fx->flows), released);
	/* Restart at the beginning so the input path must find the one free
	 * slot, including wraparound, rather than immediately hitting it. */
	fx->flows->next_id = (uint_least16_t)first;
	T_EXPECT(send_to(ef->client, &fx->listener_addr, "recovered"));
	T_EXPECT(run_until_sent(fx, 1));
	T_EXPECT(sent_is(&fx->ss.sent[0], released, "recovered"));
	T_EXPECT_EQ(udp_flows_count(fx->flows), capacity);
	T_EXPECT_EQ((size_t)fx->num_flows, capacity);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs);
	T_EXPECT_EQ(flows_alloc_id(fx->flows), (uint_least16_t)0);
	/* An existing client remains usable even with no free identifiers. */
	T_EXPECT(send_to(ef->client, &fx->listener_addr, "again"));
	T_EXPECT(run_until_sent(fx, 2));
	T_EXPECT(sent_is(&fx->ss.sent[1], released, "again"));
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	T_EXPECT_EQ((size_t)fx->num_flows, capacity);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs);
	udp_flows_reset(fx->flows);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)0);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)0);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, (size_t)1);
	T_EXPECT(!ev_is_active(&fx->flows->w_sweep));
}

T_DECLARE_CASE(test_flows_odd_id_exhaustion_and_recovery)
{
	check_flows_exhaustion(_t_, false);
}

T_DECLARE_CASE(test_flows_even_id_exhaustion_and_recovery)
{
	check_flows_exhaustion(_t_, true);
}

static void check_active_insert_rollback(
	struct testing_ctx *_t_, const enum table_failure_point point)
{
	struct udp_client_fixture *const cf = calloc(1, sizeof(*cf));
	T_CHECK(cf != NULL);
	cf->client = -1;
	T_CLEANUP(udp_client_fixture_free, cf);
	struct udp_fixture *const fx = &cf->fx;
	T_EXPECT_EQ(udp_fixture_setup(fx, false), 0);
	cf->client = client_socket();
	T_EXPECT(cf->client >= 0);
	union sockaddr_max client = { 0 };
	T_EXPECT_EQ(socket_get_addr(cf->client, &client), 0);
	unsigned char key_data[UDP_FLOW_KEY_SIZE];
	flow_key(key_data, fx->listener->sock, &client);
	const struct hashkey key = {
		.len = sizeof(key_data),
		.data = key_data,
	};
	const size_t refs = (size_t)fx->listener->sock->refs;
	table_failure.point = point;
	table_failure.flows = fx->flows;
	table_failure.sock = fx->listener->sock;
	table_failure.hits = 0;

	T_EXPECT(send_to(cf->client, &fx->listener_addr, "fail"));
	T_EXPECT(run_until_picks(fx, 1));
	/* Both failures occur after the client index and socket reference
	 * have been acquired, with the datagram holding another reference. */
	T_EXPECT_EQ(table_failure.hits, (size_t)1);
	T_EXPECT_EQ(table_failure.clients, (size_t)1);
	T_EXPECT_EQ(table_failure.refs, refs + 2u);
	T_EXPECT_EQ(table_size(fx->flows->by_client), (size_t)0);
	T_EXPECT_EQ(table_size(fx->flows->by_id), (size_t)0);
	T_EXPECT_EQ(fx->flows->by_id == NULL, point == TABLE_FAIL_ID_NEW);
	void *elem = NULL;
	T_EXPECT(!table_find(fx->flows->by_client, &key, &elem));
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)0);
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	T_EXPECT_EQ(fx->listener_dropped, (uint_least64_t)0);
	T_EXPECT_EQ(fx->ss.num_sent, (size_t)0);
	T_EXPECT_EQ(fx->ss.num_closed, (size_t)0);
	T_EXPECT(!ev_is_active(&fx->flows->w_sweep));

	T_EXPECT(send_to(cf->client, &fx->listener_addr, "retry"));
	T_EXPECT(run_until_sent(fx, 1));
	T_EXPECT(sent_is(&fx->ss.sent[0], 3, "retry"));
	T_EXPECT_EQ(table_size(fx->flows->by_client), (size_t)1);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)1);
	T_EXPECT(table_find(fx->flows->by_client, &key, &elem));
	struct udp_flow *const flow = elem;
	T_EXPECT(table_find(fx->flows->by_id, flow_id_key(3), &elem));
	T_EXPECT(elem == flow);
	T_EXPECT(flow->sock == fx->listener->sock);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)1);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs + 1u);
	T_EXPECT(ev_is_active(&fx->flows->w_sweep));
	T_EXPECT(send_to(cf->client, &fx->listener_addr, "again"));
	T_EXPECT(run_until_sent(fx, 2));
	T_EXPECT(sent_is(&fx->ss.sent[1], 3, "again"));
	T_EXPECT_EQ(table_failure.hits, (size_t)1);
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)1);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs + 1u);
	udp_flows_reset(fx->flows);
	T_EXPECT_EQ(table_size(fx->flows->by_client), (size_t)0);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)0);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)0);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs);
	T_EXPECT(!ev_is_active(&fx->flows->w_sweep));
}

T_DECLARE_CASE(test_flows_active_id_creation_rollback)
{
	check_active_insert_rollback(_t_, TABLE_FAIL_ID_NEW);
}

T_DECLARE_CASE(test_flows_active_id_insertion_rollback)
{
	check_active_insert_rollback(_t_, TABLE_FAIL_ID_SET);
}

static void check_passive_insert_rollback(
	struct testing_ctx *_t_, const enum table_failure_point point)
{
	struct udp_client_fixture *const cf = calloc(1, sizeof(*cf));
	T_CHECK(cf != NULL);
	cf->client = -1;
	T_CLEANUP(udp_client_fixture_free, cf);
	struct udp_fixture *const fx = &cf->fx;
	T_EXPECT_EQ(udp_fixture_setup(fx, false), 0);
	cf->client = client_socket();
	T_EXPECT(cf->client >= 0);
	union sockaddr_max target;
	T_EXPECT_EQ(socket_get_addr(cf->client, &target), 0);
	char forward[64];
	(void)sa_format(forward, sizeof(forward), &target.sa);
	table_failure.point = point;
	table_failure.flows = fx->flows;
	table_failure.sock = NULL;
	table_failure.hits = 0;
	passive_allocation.watch = true;
	passive_allocation.fd = -1;
	passive_allocation.flow = NULL;
	passive_allocation.allocations = 0;
	passive_allocation.frees = 0;
	passive_allocation.connected_at_failure = false;
	passive_allocation.read_active_at_free = false;
	static const unsigned char failed[] = "failed";
	udp_flows_recv(fx->flows, 2, failed, sizeof(failed) - 1, forward);
	passive_allocation.watch = false;
	const bool closed = passive_allocation.fd >= 0 &&
			    fcntl(passive_allocation.fd, F_GETFD) == -1 &&
			    errno == EBADF;
	const size_t freed = passive_allocation.frees;
	/* Keep failure diagnostics clean even if the rollback under test leaks. */
	if (table_failure.hits == 1) {
		if (!closed && passive_allocation.fd >= 0) {
			(void)close(passive_allocation.fd);
		}
		free(passive_allocation.flow);
		passive_allocation.flow = NULL;
	}
	T_EXPECT_EQ(table_failure.hits, (size_t)1);
	T_EXPECT(passive_allocation.connected_at_failure);
	T_EXPECT_EQ(passive_allocation.allocations, (size_t)1);
	T_EXPECT_EQ(freed, (size_t)1);
	T_EXPECT(!passive_allocation.read_active_at_free);
	T_EXPECT(closed);
	T_EXPECT_EQ(table_size(fx->flows->by_id), (size_t)0);
	T_EXPECT_EQ(fx->flows->by_id == NULL, point == TABLE_FAIL_ID_NEW);
	T_EXPECT(fx->flows->by_client == NULL);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)0);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)0);
	T_EXPECT(!ev_is_active(&fx->flows->w_sweep));
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	T_EXPECT_EQ(fx->listener_dropped, (uint_least64_t)0);
	T_EXPECT_EQ(fx->ss.num_closed, (size_t)1);
	T_EXPECT_EQ(fx->ss.closed[0], (uint_least16_t)2);
	T_EXPECT_EQ(fx->ss.num_sent, (size_t)0);

	static const unsigned char retry[] = "retry";
	udp_flows_recv(fx->flows, 2, retry, sizeof(retry) - 1, forward);
	char got[32] = { 0 };
	union sockaddr_max from;
	socklen_t from_len = sizeof(from);
	const ssize_t received = recvfrom(
		cf->client, got, sizeof(got) - 1, 0, &from.sa, &from_len);
	T_EXPECT_EQ(received, (ssize_t)(sizeof(retry) - 1));
	T_EXPECT_STREQ(got, "retry");
	T_EXPECT_EQ(
		sendto(cf->client, "answer", 6, 0, &from.sa, from_len),
		(ssize_t)6);
	T_EXPECT(run_until_sent(fx, 1));
	T_EXPECT(sent_is(&fx->ss.sent[0], 2, "answer"));
	void *entry = NULL;
	T_EXPECT(table_find(fx->flows->by_id, flow_id_key(2), &entry));
	struct udp_flow *const flow = entry;
	T_EXPECT(flow->sock == NULL);
	T_EXPECT(ev_is_active(&flow->w_read));
	T_EXPECT(ev_is_active(&fx->flows->w_sweep));
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)1);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)1);
	T_EXPECT_EQ(fx->ss.num_closed, (size_t)1);
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	udp_flows_reset(fx->flows);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)0);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)0);
	T_EXPECT(!ev_is_active(&fx->flows->w_sweep));
}

T_DECLARE_CASE(test_flows_passive_id_creation_rollback)
{
	check_passive_insert_rollback(_t_, TABLE_FAIL_ID_NEW);
}

T_DECLARE_CASE(test_flows_passive_id_insertion_rollback)
{
	check_passive_insert_rollback(_t_, TABLE_FAIL_ID_SET);
}

static void check_local_send_failure(
	struct testing_ctx *_t_, const bool active, const int error)
{
	struct udp_client_fixture *const cf = calloc(1, sizeof(*cf));
	T_CHECK(cf != NULL);
	cf->client = -1;
	T_CLEANUP(udp_client_fixture_free, cf);
	struct udp_fixture *const fx = &cf->fx;
	T_EXPECT_EQ(udp_fixture_setup(fx, false), 0);
	cf->client = client_socket();
	T_EXPECT(cf->client >= 0);
	const uint_least16_t id = active ? 1 : 2;
	if (active) {
		T_EXPECT(send_to(cf->client, &fx->listener_addr, "open"));
		T_EXPECT(run_until_sent(fx, 1));
		T_EXPECT(sent_is(&fx->ss.sent[0], id, "open"));
	} else {
		union sockaddr_max target;
		T_EXPECT_EQ(socket_get_addr(cf->client, &target), 0);
		char forward[64];
		(void)sa_format(forward, sizeof(forward), &target.sa);
		static const unsigned char open[] = "open";
		udp_flows_recv(fx->flows, id, open, sizeof(open) - 1, forward);
		char got[32];
		T_EXPECT(recv_str(cf->client, got, sizeof(got)));
		T_EXPECT_STREQ(got, "open");
	}
	void *entry = NULL;
	T_EXPECT(table_find(fx->flows->by_id, flow_id_key(id), &entry));
	struct udp_flow *const flow = entry;
	T_EXPECT_EQ(flow->sock != NULL, active);
	const int fd = active ? flow->sock->fd : flow->w_read.fd;
	const size_t refs = (size_t)fx->listener->sock->refs;
	T_EXPECT_EQ(refs, active ? (size_t)2 : (size_t)1);
	const size_t sent = fx->ss.num_sent;

	send_failure.fd = fd;
	send_failure.error = error;
	send_failure.hits = 0;
	static const unsigned char failed[] = "failed";
	udp_flows_recv(fx->flows, id, failed, sizeof(failed) - 1, NULL);
	send_failure.error = 0;
	T_EXPECT_EQ(send_failure.hits, (size_t)1);
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	T_EXPECT_EQ(fx->listener_dropped, (uint_least64_t)0);
	T_EXPECT_EQ(fx->ss.num_closed, (size_t)0);
	T_EXPECT_EQ(fx->ss.num_sent, sent);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)1);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)1);
	T_EXPECT(table_find(fx->flows->by_id, flow_id_key(id), &entry));
	T_EXPECT(entry == flow);
	T_EXPECT_EQ(
		table_size(fx->flows->by_client),
		active ? (size_t)1 : (size_t)0);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs);
	T_EXPECT(fcntl(fd, F_GETFD) >= 0);
	if (active) {
		T_EXPECT(flow->sock == fx->listener->sock);
	} else {
		T_EXPECT(ev_is_active(&flow->w_read));
		T_EXPECT_EQ(flow->w_read.fd, fd);
		union sockaddr_max peer;
		T_EXPECT_EQ(socket_get_peer(fd, &peer), 0);
	}
	T_EXPECT(ev_is_active(&fx->flows->w_sweep));
	char got[32];
	T_EXPECT_EQ(
		recv(cf->client, got, sizeof(got), MSG_DONTWAIT), (ssize_t)-1);
	T_EXPECT(sock_would_block(errno));

	static const unsigned char retry[] = "retry";
	udp_flows_recv(fx->flows, id, retry, sizeof(retry) - 1, NULL);
	T_EXPECT(recv_str(cf->client, got, sizeof(got)));
	T_EXPECT_STREQ(got, "retry");
	T_EXPECT(table_find(fx->flows->by_id, flow_id_key(id), &entry));
	T_EXPECT(entry == flow);
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)1);
	T_EXPECT_EQ(fx->ss.num_closed, (size_t)0);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)1);
	T_EXPECT_EQ((size_t)fx->num_flows, (size_t)1);
	T_EXPECT_EQ((size_t)fx->listener->sock->refs, refs);
}

T_DECLARE_CASE(test_flows_active_send_would_block)
{
	check_local_send_failure(_t_, true, EAGAIN);
}

T_DECLARE_CASE(test_flows_active_send_permanent_error)
{
	check_local_send_failure(_t_, true, EACCES);
}

T_DECLARE_CASE(test_flows_passive_send_would_block)
{
	check_local_send_failure(_t_, false, EAGAIN);
}

T_DECLARE_CASE(test_flows_passive_send_permanent_error)
{
	check_local_send_failure(_t_, false, EACCES);
}

static void check_receive_results(struct testing_ctx *_t_, const bool passive)
{
	struct udp_client_fixture *const cf = calloc(1, sizeof(*cf));
	T_CHECK(cf != NULL);
	cf->client = -1;
	T_CLEANUP(udp_client_fixture_free, cf);
	struct udp_fixture *const fx = &cf->fx;
	T_EXPECT_EQ(udp_fixture_setup(fx, false), 0);
	cf->client = client_socket();
	T_EXPECT(cf->client >= 0);
	union sockaddr_max client = { 0 };
	T_EXPECT_EQ(socket_get_addr(cf->client, &client), 0);
	ev_io *watcher = &fx->listener->w_read;
	const uint_least16_t id = passive ? 2 : 1;
	if (passive) {
		char forward[64];
		(void)sa_format(forward, sizeof(forward), &client.sa);
		static const unsigned char open[] = "open";
		udp_flows_recv(fx->flows, id, open, sizeof(open) - 1, forward);
		char got[32];
		T_EXPECT(recv_str(cf->client, got, sizeof(got)));
		T_EXPECT_STREQ(got, "open");
		void *entry = NULL;
		T_EXPECT(table_find(fx->flows->by_id, flow_id_key(id), &entry));
		struct udp_flow *const flow = entry;
		watcher = &flow->w_read;
	}
	void (*const read_cb)(struct ev_loop *, ev_io *, int) =
		passive ? passive_read_cb : listener_read_cb;
	static const struct recv_step steps[] = {
		{ .error = EINTR },
		{ .error = ECONNREFUSED },
		{ .data = "after errors" },
		{ .error = EAGAIN },
		{ .data = "after block" },
		{ .flags = MSG_TRUNC, .data = "partial" },
		{ .error = EWOULDBLOCK },
		{ .data = "after trunc" },
		{ .error = EAGAIN },
	};
	recv_script.active = true;
	recv_script.fd = watcher->fd;
	recv_script.steps = steps;
	recv_script.count = sizeof(steps) / sizeof(steps[0]);
	recv_script.next = 0;
	recv_script.overruns = 0;
	recv_script.from = client;
	read_cb(fx->loop, watcher, EV_READ);
	recv_script.active = false;
	T_EXPECT_EQ(recv_script.next, (size_t)4);
	T_EXPECT_EQ(fx->ss.num_sent, (size_t)1);
	T_EXPECT(sent_is(&fx->ss.sent[0], id, "after errors"));
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)0);
	T_EXPECT_EQ(fx->listener_dropped, (uint_least64_t)0);

	recv_script.active = true;
	read_cb(fx->loop, watcher, EV_READ);
	recv_script.active = false;
	T_EXPECT_EQ(recv_script.next, (size_t)7);
	T_EXPECT_EQ(fx->ss.num_sent, (size_t)2);
	T_EXPECT(sent_is(&fx->ss.sent[1], id, "after block"));
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)passive);
	T_EXPECT_EQ(fx->listener_dropped, (uint_least64_t)!passive);

	recv_script.active = true;
	read_cb(fx->loop, watcher, EV_READ);
	recv_script.active = false;
	T_EXPECT_EQ(recv_script.next, recv_script.count);
	T_EXPECT_EQ(recv_script.overruns, (size_t)0);
	T_EXPECT_EQ(fx->ss.num_sent, (size_t)3);
	T_EXPECT(sent_is(&fx->ss.sent[2], id, "after trunc"));
	T_EXPECT_EQ((uint_least64_t)fx->dropped, (uint_least64_t)passive);
	T_EXPECT_EQ(fx->listener_dropped, (uint_least64_t)!passive);
	T_EXPECT_EQ(udp_flows_count(fx->flows), (size_t)1);
	T_EXPECT_EQ(fx->ss.num_closed, (size_t)0);
}

T_DECLARE_CASE(test_listener_receive_recovery_and_truncation)
{
	check_receive_results(_t_, false);
}

T_DECLARE_CASE(test_passive_receive_recovery_and_truncation)
{
	check_receive_results(_t_, true);
}

/* A local client's datagrams become a flow of the local parity, stickily: the
 * same client keeps its flow (and its route), a second client gets the next
 * id, and the peer's replies on a flow go back to that flow's client through
 * the listener's socket. */
T_DECLARE_CASE(test_flows_active_roundtrip)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c1 = client_socket();
	const int c2 = client_socket();
	T_CHECK(c1 >= 0 && c2 >= 0);

	const bool s1 =
		send_to(c1, &fx.listener_addr, "one") && run_until_sent(&fx, 1);
	const bool s2 =
		send_to(c1, &fx.listener_addr, "two") && run_until_sent(&fx, 2);
	const bool s3 = send_to(c2, &fx.listener_addr, "three") &&
			run_until_sent(&fx, 3);
	const bool order_ok = s1 && s2 && s3 &&
			      sent_is(&fx.ss.sent[0], 1, "one") &&
			      sent_is(&fx.ss.sent[1], 1, "two") &&
			      sent_is(&fx.ss.sent[2], 3, "three");

	static const unsigned char r1[] = "back-to-1";
	static const unsigned char r2[] = "back-to-2";
	udp_flows_recv(fx.flows, 1, r1, sizeof(r1) - 1, NULL);
	udp_flows_recv(fx.flows, 3, r2, sizeof(r2) - 1, NULL);
	char got1[32] = { 0 };
	char got2[32] = { 0 };
	const bool g1 = recv_str(c1, got1, sizeof(got1));
	const bool g2 = recv_str(c2, got2, sizeof(got2));
	const int picks = fx.picks;
	const size_t flows = udp_flows_count(fx.flows);
	const size_t gauge = (size_t)fx.num_flows;

	(void)close(c1);
	(void)close(c2);
	udp_fixture_teardown(&fx);

	T_EXPECT(order_ok);
	T_EXPECT(g1);
	T_EXPECT_STREQ(got1, "back-to-1");
	T_EXPECT(g2);
	T_EXPECT_STREQ(got2, "back-to-2");
	T_EXPECT_EQ(picks, 2);
	T_EXPECT_EQ(flows, (size_t)2);
	T_EXPECT_EQ(gauge, (size_t)2);
}

/* A synchronous view borrows listener storage, while an active flow takes its
 * own socket reference and remains usable after the listener is closed. */
T_DECLARE_CASE(test_listener_borrowed_delivery_storage_and_socket_lifetime)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	fx.listener->cb.deliver_borrowed = fx_deliver_borrowed;
	const int client = client_socket();
	T_CHECK(client >= 0);
	const bool warm = send_to(client, &fx.listener_addr, "warm") &&
			  run_until_sent(&fx, 1);
	udp_malloc_calls = 0;
	watch_udp_allocations = true;
	const bool borrowed = send_to(client, &fx.listener_addr, "borrowed") &&
			      run_until_sent(&fx, 2) &&
			      send_to(client, &fx.listener_addr, "") &&
			      run_until_sent(&fx, 3);
	watch_udp_allocations = false;
	const size_t borrowed_allocations = udp_malloc_calls;
	const bool copied_into_mux = borrowed &&
				     sent_is(&fx.ss.sent[1], 1, "borrowed") &&
				     sent_is(&fx.ss.sent[2], 1, "");
	/* The retained owned path supplies a comparison with the same warmed flow. */
	fx.listener->cb.deliver_borrowed = NULL;
	udp_malloc_calls = 0;
	watch_udp_allocations = true;
	const bool owned = send_to(client, &fx.listener_addr, "owned") &&
			   run_until_sent(&fx, 4);
	watch_udp_allocations = false;
	const size_t owned_allocations = udp_malloc_calls;
	fx.listener->cb.deliver_borrowed = fx_deliver_borrowed;
	fx.ss.ready = false;
	union sockaddr_max from = { 0 };
	T_CHECK(socket_get_addr(client, &from) == 0);
	memcpy(fx.listener->buf, "drop", sizeof("drop"));
	udp_malloc_calls = 0;
	watch_udp_allocations = true;
	listener_route(fx.listener, &from, sizeof("drop") - 1);
	watch_udp_allocations = false;
	const size_t dropped_allocations = udp_malloc_calls;
	const size_t dropped = (size_t)fx.dropped;
	const size_t borrowed_calls = fx.borrowed_calls;
	const size_t invalid_views = fx.invalid_views;
	const size_t refs = (size_t)fx.listener->sock->refs;
	fx.ss.ready = true;
	udp_listener_free(fx.listener);
	fx.listener = NULL;
	static const unsigned char reply[] = "after listener close";
	udp_flows_recv(fx.flows, 1, reply, sizeof(reply) - 1, NULL);
	char received[64] = { 0 };
	const bool replied = recv_str(client, received, sizeof(received));
	(void)close(client);
	udp_fixture_teardown(&fx);

	T_EXPECT(warm && borrowed && owned && copied_into_mux);
	T_EXPECT_EQ(borrowed_allocations, (size_t)0);
	T_EXPECT_EQ(owned_allocations, (size_t)1);
	T_EXPECT_EQ(dropped_allocations, (size_t)0);
	T_EXPECT_EQ(dropped, (size_t)1);
	T_EXPECT_EQ(borrowed_calls, (size_t)4);
	T_EXPECT_EQ(invalid_views, (size_t)0);
	T_EXPECT_EQ(refs, (size_t)2);
	T_EXPECT(replied);
	T_EXPECT_STREQ(received, (const char *)reply);
}

/* A DATAGRAM on a flow the peer opened is relayed to the forward target from a
 * socket connected to it, and the target's replies come back on that flow. */
T_DECLARE_CASE(test_flows_passive_roundtrip)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int target = client_socket();
	T_CHECK(target >= 0);
	union sockaddr_max target_addr;
	T_CHECK(socket_get_addr(target, &target_addr) == 0);
	char forward[64];
	(void)snprintf(
		forward, sizeof(forward), "127.0.0.1:%u",
		(unsigned)ntohs(target_addr.in.sin_port));

	static const unsigned char q[] = "query";
	/* 2 is even: the (accepting) peer's parity for a dialing session. */
	udp_flows_recv(fx.flows, 2, q, sizeof(q) - 1, forward);
	char got[32] = { 0 };
	union sockaddr_max from;
	socklen_t from_len = sizeof(from);
	const ssize_t n =
		recvfrom(target, got, sizeof(got) - 1, 0, &from.sa, &from_len);
	const bool reply_sent = n > 0 && sendto(target, "answer", 6, 0,
						&from.sa, from_len) == 6;
	const bool relayed = reply_sent && run_until_sent(&fx, 1);
	const bool reply_ok = relayed && sent_is(&fx.ss.sent[0], 2, "answer");
	const size_t flows = udp_flows_count(fx.flows);

	(void)close(target);
	udp_fixture_teardown(&fx);

	T_EXPECT(n == (ssize_t)(sizeof(q) - 1));
	T_EXPECT_STREQ(got, "query");
	T_EXPECT(reply_ok);
	T_EXPECT_EQ(flows, (size_t)1);
}

/* Empty datagrams create and reuse an active flow, and replies arrive as a
 * readable socket returning zero bytes, rather than disappearing as EOF. */
T_DECLARE_CASE(test_flows_active_empty_roundtrip)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c = client_socket();
	T_CHECK(c >= 0);
	const bool sent =
		send_to(c, &fx.listener_addr, "") && run_until_sent(&fx, 1);
	const bool empty_sent = sent && sent_is(&fx.ss.sent[0], 1, "");
	static const unsigned char empty[] = "";
	udp_flows_recv(fx.flows, 1, empty, 0, NULL);
	union sockaddr_max from;
	const bool received = recv_empty(c, &from);
	const bool from_listener =
		received && sa_equals(&from.sa, &fx.listener_addr.sa);
	/* A following nonempty datagram uses the same route and flow. */
	const bool sent_after = send_to(c, &fx.listener_addr, "after") &&
				run_until_sent(&fx, 2);
	const bool after_ok = sent_after && sent_is(&fx.ss.sent[1], 1, "after");
	static const unsigned char reply[] = "reply";
	udp_flows_recv(fx.flows, 1, reply, sizeof(reply) - 1, NULL);
	char got[16];
	const bool reply_ok =
		recv_str(c, got, sizeof(got)) && strcmp(got, "reply") == 0;
	const int picks = fx.picks;
	const size_t flows = udp_flows_count(fx.flows);
	const size_t gauge = (size_t)fx.num_flows;
	const uint_least64_t dropped = (uint_least64_t)fx.dropped;
	const uint_least64_t unrouted = fx.listener_dropped;
	const size_t closed = fx.ss.num_closed;
	(void)close(c);
	udp_fixture_teardown(&fx);

	T_EXPECT(empty_sent);
	T_EXPECT(received);
	T_EXPECT(from_listener);
	T_EXPECT(after_ok);
	T_EXPECT(reply_ok);
	T_EXPECT_EQ(picks, 1);
	T_EXPECT_EQ(flows, (size_t)1);
	T_EXPECT_EQ(gauge, (size_t)1);
	T_EXPECT_EQ(dropped, (uint_least64_t)0);
	T_EXPECT_EQ(unrouted, (uint_least64_t)0);
	T_EXPECT_EQ(closed, (size_t)0);
}

/* The passive socket forwards an empty peer datagram and relays an empty
 * target reply, then continues serving nonempty traffic on the same flow. */
T_DECLARE_CASE(test_flows_passive_empty_roundtrip)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int target = client_socket();
	T_CHECK(target >= 0);
	union sockaddr_max target_addr;
	T_CHECK(socket_get_addr(target, &target_addr) == 0);
	char forward[64];
	(void)snprintf(
		forward, sizeof(forward), "127.0.0.1:%u",
		(unsigned)ntohs(target_addr.in.sin_port));
	static const unsigned char empty[] = "";
	udp_flows_recv(fx.flows, 2, empty, 0, forward);
	union sockaddr_max from;
	const bool received = recv_empty(target, &from);
	const bool replied = received && sendto(target, empty, 0, 0, &from.sa,
						sa_len(&from.sa)) == 0;
	const bool relayed = replied && run_until_sent(&fx, 1);
	const bool empty_reply = relayed && sent_is(&fx.ss.sent[0], 2, "");

	static const unsigned char query[] = "query";
	udp_flows_recv(fx.flows, 2, query, sizeof(query) - 1, forward);
	char got[16];
	const bool query_ok =
		recv_str(target, got, sizeof(got)) && strcmp(got, "query") == 0;
	const bool replied_after =
		received &&
		sendto(target, "answer", 6, 0, &from.sa, sa_len(&from.sa)) == 6;
	const bool relayed_after = replied_after && run_until_sent(&fx, 2);
	const bool reply_ok =
		relayed_after && sent_is(&fx.ss.sent[1], 2, "answer");
	const size_t flows = udp_flows_count(fx.flows);
	const size_t gauge = (size_t)fx.num_flows;
	const uint_least64_t dropped = (uint_least64_t)fx.dropped;
	const size_t closed = fx.ss.num_closed;
	(void)close(target);
	udp_fixture_teardown(&fx);

	T_EXPECT(received);
	T_EXPECT(empty_reply);
	T_EXPECT(query_ok);
	T_EXPECT(reply_ok);
	T_EXPECT_EQ(flows, (size_t)1);
	T_EXPECT_EQ(gauge, (size_t)1);
	T_EXPECT_EQ(dropped, (uint_least64_t)0);
	T_EXPECT_EQ(closed, (size_t)0);
}

/* A DATAGRAM this side cannot relay is dropped and answered with FLOW-CLOSE:
 * an unknown flow of its own parity (already gone here), or a new peer flow
 * with no forward target configured. */
T_DECLARE_CASE(test_flows_unrelayable_datagram_closes_flow)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, true) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	static const unsigned char p[] = "x";
	/* Accepting side: even ids are its own, odd ones the peer's. */
	udp_flows_recv(fx.flows, 4, p, 1, "127.0.0.1:9");
	udp_flows_recv(fx.flows, 5, p, 1, NULL);
	const size_t closed = fx.ss.num_closed;
	const uint_least16_t c0 = fx.ss.closed[0];
	const uint_least16_t c1 = fx.ss.closed[1];
	const uint_least64_t dropped = (uint_least64_t)fx.dropped;
	const size_t flows = udp_flows_count(fx.flows);
	udp_fixture_teardown(&fx);

	T_EXPECT_EQ(closed, (size_t)2);
	T_EXPECT_EQ(c0, (uint_least16_t)4);
	T_EXPECT_EQ(c1, (uint_least16_t)5);
	T_EXPECT_EQ(dropped, (uint_least64_t)2);
	T_EXPECT_EQ(flows, (size_t)0);
}

/* A FLOW-CLOSE frees the flow here without answering; an unknown one is
 * ignored. */
T_DECLARE_CASE(test_flows_recv_close_frees_flow)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c = client_socket();
	T_CHECK(c >= 0);
	const bool sent =
		send_to(c, &fx.listener_addr, "hi") && run_until_sent(&fx, 1);
	const size_t before = udp_flows_count(fx.flows);
	udp_flows_recv_close(fx.flows, 1);
	udp_flows_recv_close(fx.flows, 99);
	const size_t after = udp_flows_count(fx.flows);
	const size_t gauge = (size_t)fx.num_flows;
	const size_t closed = fx.ss.num_closed;
	const bool sweep_stopped = !ev_is_active(&fx.flows->w_sweep);

	(void)close(c);
	udp_fixture_teardown(&fx);

	T_EXPECT(sent);
	T_EXPECT_EQ(before, (size_t)1);
	T_EXPECT_EQ(after, (size_t)0);
	T_EXPECT_EQ(gauge, (size_t)0);
	T_EXPECT_EQ(closed, (size_t)0);
	T_EXPECT(sweep_stopped);
}

/* A flow idle past mux.lossymux.idle_timeout is freed by the sweep and the peer
 * told with FLOW-CLOSE; a fresh one survives.  last_seen is aged directly
 * rather than waiting out the timeout. */
T_DECLARE_CASE(test_flows_sweep_expires_idle_flow)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c1 = client_socket();
	const int c2 = client_socket();
	T_CHECK(c1 >= 0 && c2 >= 0);
	const bool sent =
		send_to(c1, &fx.listener_addr, "a") && run_until_sent(&fx, 1) &&
		send_to(c2, &fx.listener_addr, "b") && run_until_sent(&fx, 2);
	const bool armed = ev_is_active(&fx.flows->w_sweep);
	void *elem = NULL;
	T_CHECK(table_find(fx.flows->by_id, flow_id_key(1), &elem));
	((struct udp_flow *)elem)->last_seen =
		ev_now(fx.loop) - (double)fx.ss.conf.lossymux_idle_timeout;
	flows_sweep_cb(fx.loop, &fx.flows->w_sweep, EV_TIMER);
	const size_t flows = udp_flows_count(fx.flows);
	const size_t closed = fx.ss.num_closed;
	const uint_least16_t closed_id = fx.ss.closed[0];
	const bool still_armed = ev_is_active(&fx.flows->w_sweep);
	/* The expired client's next datagram opens a new flow. */
	const bool resent =
		send_to(c1, &fx.listener_addr, "c") && run_until_sent(&fx, 3);
	const bool new_flow = resent && sent_is(&fx.ss.sent[2], 5, "c");

	(void)close(c1);
	(void)close(c2);
	udp_fixture_teardown(&fx);

	T_EXPECT(sent);
	T_EXPECT(armed);
	T_EXPECT_EQ(flows, (size_t)1);
	T_EXPECT_EQ(closed, (size_t)1);
	T_EXPECT_EQ(closed_id, (uint_least16_t)1);
	T_EXPECT(still_armed);
	T_EXPECT(new_flow);
}

/* A datagram the session cannot take right now (lossymux not ready) is dropped
 * and counted without opening a flow. */
T_DECLARE_CASE(test_flows_input_drops_when_not_ready)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	fx.ss.ready = false;
	const int c = client_socket();
	T_CHECK(c >= 0);
	/* Routing the new client is the listener's read of it. */
	const bool sent = send_to(c, &fx.listener_addr, "lost") &&
			  run_until_picks(&fx, 1);
	const uint_least64_t dropped = (uint_least64_t)fx.dropped;
	const size_t flows = udp_flows_count(fx.flows);

	(void)close(c);
	udp_fixture_teardown(&fx);

	T_EXPECT(sent);
	T_EXPECT_EQ(dropped, (uint_least64_t)1);
	T_EXPECT_EQ(flows, (size_t)0);
}

/* With no tunnel to route to, the listener drops the datagram and counts it;
 * a forgotten target's clients are routed afresh. */
T_DECLARE_CASE(test_listener_routes_and_forgets)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c = client_socket();
	T_CHECK(c >= 0);
	fx.refuse_pick = true;
	const bool sent0 = send_to(c, &fx.listener_addr, "none") &&
			   run_until_picks(&fx, 1);
	const uint_least64_t unrouted = fx.listener_dropped;
	fx.refuse_pick = false;
	const bool sent1 =
		send_to(c, &fx.listener_addr, "a") && run_until_sent(&fx, 1);
	const bool sent2 =
		send_to(c, &fx.listener_addr, "b") && run_until_sent(&fx, 2);
	const int picks_sticky = fx.picks;
	udp_listener_forget(fx.listener, fx.flows);
	const bool sweep_stopped = !ev_is_active(&fx.listener->w_sweep);
	const bool sent3 =
		send_to(c, &fx.listener_addr, "c") && run_until_sent(&fx, 3);
	const int picks_after = fx.picks;

	(void)close(c);
	udp_fixture_teardown(&fx);

	T_EXPECT(sent0);
	T_EXPECT_EQ(unrouted, (uint_least64_t)1);
	T_EXPECT(sent1);
	T_EXPECT(sent2);
	/* The refused pick counts too: one per first datagram of a route. */
	T_EXPECT_EQ(picks_sticky, 2);
	T_EXPECT(sweep_stopped);
	T_EXPECT(sent3);
	T_EXPECT_EQ(picks_after, 3);
}

/* Route expiry is independent of flow expiry: a timed-out client is picked
 * again, a younger route remains sticky, and the last expiry stops the timer. */
T_DECLARE_CASE(test_listener_sweep_expires_idle_routes)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c1 = client_socket();
	const int c2 = client_socket();
	T_CHECK(c1 >= 0 && c2 >= 0);
	T_CHECK(send_to(c1, &fx.listener_addr, "a") && run_until_sent(&fx, 1));
	T_CHECK(send_to(c2, &fx.listener_addr, "b") && run_until_sent(&fx, 2));
	struct udp_route *r1 = client_route(fx.listener, c1);
	struct udp_route *r2 = client_route(fx.listener, c2);
	T_CHECK(r1 != NULL && r2 != NULL);
	const bool armed = ev_is_active(&fx.listener->w_sweep);
	r1->last_seen = ev_now(fx.loop) - 60.0;
	r2->last_seen = ev_now(fx.loop) - 59.0;
	listener_sweep_cb(fx.loop, &fx.listener->w_sweep, EV_TIMER);
	const bool expired = client_route(fx.listener, c1) == NULL;
	const bool retained = client_route(fx.listener, c2) != NULL;
	const size_t remaining = table_size(fx.listener->routes);
	const bool still_armed = ev_is_active(&fx.listener->w_sweep);
	const bool resent =
		send_to(c1, &fx.listener_addr, "c") && run_until_sent(&fx, 3);
	const int picks_after_expiry = fx.picks;
	const bool sticky =
		send_to(c2, &fx.listener_addr, "d") && run_until_sent(&fx, 4);
	const int picks_after_reuse = fx.picks;
	r1 = client_route(fx.listener, c1);
	r2 = client_route(fx.listener, c2);
	T_CHECK(r1 != NULL && r2 != NULL);
	r1->last_seen = ev_now(fx.loop) - 60.0;
	r2->last_seen = ev_now(fx.loop) - 60.0;
	listener_sweep_cb(fx.loop, &fx.listener->w_sweep, EV_TIMER);
	const size_t after = table_size(fx.listener->routes);
	const bool stopped = !ev_is_active(&fx.listener->w_sweep);
	const size_t flows = udp_flows_count(fx.flows);
	const size_t closed = fx.ss.num_closed;
	(void)close(c1);
	(void)close(c2);
	udp_fixture_teardown(&fx);

	T_EXPECT(armed);
	T_EXPECT(expired);
	T_EXPECT(retained);
	T_EXPECT_EQ(remaining, (size_t)1);
	T_EXPECT(still_armed);
	T_EXPECT(resent);
	T_EXPECT_EQ(picks_after_expiry, 3);
	T_EXPECT(sticky);
	T_EXPECT_EQ(picks_after_reuse, 3);
	T_EXPECT_EQ(after, (size_t)0);
	T_EXPECT(stopped);
	T_EXPECT_EQ(flows, (size_t)2);
	T_EXPECT_EQ(closed, (size_t)0);
}

/* Reloaded timeouts apply to existing routes on the next sweep; changing an
 * empty listener's timeout leaves its timer disarmed until the next route. */
T_DECLARE_CASE(test_listener_idle_timeout_reload)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c = client_socket();
	T_CHECK(c >= 0);
	T_CHECK(send_to(c, &fx.listener_addr, "a") && run_until_sent(&fx, 1));
	struct udp_route *r = client_route(fx.listener, c);
	T_CHECK(r != NULL);
	r->last_seen = ev_now(fx.loop) - 60.0;
	udp_listener_set_idle_timeout(fx.listener, 120.0);
	const double longer = fx.listener->idle_timeout;
	const double longer_repeat = fx.listener->w_sweep.repeat;
	listener_sweep_cb(fx.loop, &fx.listener->w_sweep, EV_TIMER);
	const bool retained = client_route(fx.listener, c) != NULL;
	const bool armed = ev_is_active(&fx.listener->w_sweep);
	const bool reused =
		send_to(c, &fx.listener_addr, "b") && run_until_sent(&fx, 2);
	const int picks_reused = fx.picks;
	r = client_route(fx.listener, c);
	T_CHECK(r != NULL);
	r->last_seen = ev_now(fx.loop) - 10.0;
	udp_listener_set_idle_timeout(fx.listener, 10.0);
	const double shorter = fx.listener->idle_timeout;
	const double shorter_repeat = fx.listener->w_sweep.repeat;
	listener_sweep_cb(fx.loop, &fx.listener->w_sweep, EV_TIMER);
	const size_t expired = table_size(fx.listener->routes);
	const bool stopped = !ev_is_active(&fx.listener->w_sweep);
	udp_listener_set_idle_timeout(fx.listener, 2.0);
	const bool stayed_stopped = !ev_is_active(&fx.listener->w_sweep);
	const double minimum_repeat = fx.listener->w_sweep.repeat;
	const bool repicked =
		send_to(c, &fx.listener_addr, "c") && run_until_sent(&fx, 3);
	const int picks_after = fx.picks;
	const bool rearmed = ev_is_active(&fx.listener->w_sweep);
	r = client_route(fx.listener, c);
	T_CHECK(r != NULL);
	r->last_seen = ev_now(fx.loop) - 2.0;
	listener_sweep_cb(fx.loop, &fx.listener->w_sweep, EV_TIMER);
	const size_t final_routes = table_size(fx.listener->routes);
	const bool finally_stopped = !ev_is_active(&fx.listener->w_sweep);
	(void)close(c);
	udp_fixture_teardown(&fx);

	T_EXPECT(longer == 120.0);
	T_EXPECT(longer_repeat == 60.0);
	T_EXPECT(retained);
	T_EXPECT(armed);
	T_EXPECT(reused);
	T_EXPECT_EQ(picks_reused, 1);
	T_EXPECT(shorter == 10.0);
	T_EXPECT(shorter_repeat == 5.0);
	T_EXPECT_EQ(expired, (size_t)0);
	T_EXPECT(stopped);
	T_EXPECT(stayed_stopped);
	T_EXPECT(minimum_repeat == 1.0);
	T_EXPECT(repicked);
	T_EXPECT_EQ(picks_after, 2);
	T_EXPECT(rearmed);
	T_EXPECT_EQ(final_routes, (size_t)0);
	T_EXPECT(finally_stopped);
}

/* A flow keeps its listener socket open after the listener is freed (a reload
 * stopping it), so replies still reach the client from the same address. */
T_DECLARE_CASE(test_flow_outlives_listener)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c = client_socket();
	T_CHECK(c >= 0);
	const bool sent =
		send_to(c, &fx.listener_addr, "hi") && run_until_sent(&fx, 1);
	udp_listener_free(fx.listener);
	fx.listener = NULL;

	static const unsigned char r[] = "still here";
	udp_flows_recv(fx.flows, 1, r, sizeof(r) - 1, NULL);
	char got[32] = { 0 };
	union sockaddr_max from;
	socklen_t from_len = sizeof(from);
	const ssize_t n =
		recvfrom(c, got, sizeof(got) - 1, 0, &from.sa, &from_len);
	const bool from_listener =
		n > 0 && sa_equals(&from.sa, &fx.listener_addr.sa);

	(void)close(c);
	udp_fixture_teardown(&fx);

	T_EXPECT(sent);
	T_EXPECT(n == (ssize_t)(sizeof(r) - 1));
	T_EXPECT_STREQ(got, "still here");
	T_EXPECT(from_listener);
}

/* udp_flows_reset frees every flow silently (no FLOW-CLOSE) and stops the
 * sweep. */
T_DECLARE_CASE(test_flows_reset_is_silent)
{
	struct udp_fixture fx;
	if (udp_fixture_setup(&fx, false) != 0) {
		udp_fixture_teardown(&fx);
		T_FATAL("udp_fixture_setup failed");
		return;
	}
	const int c = client_socket();
	T_CHECK(c >= 0);
	const bool sent =
		send_to(c, &fx.listener_addr, "hi") && run_until_sent(&fx, 1);
	udp_flows_reset(fx.flows);
	const size_t flows = udp_flows_count(fx.flows);
	const size_t gauge = (size_t)fx.num_flows;
	const size_t closed = fx.ss.num_closed;
	const bool sweep_stopped = !ev_is_active(&fx.flows->w_sweep);

	(void)close(c);
	udp_fixture_teardown(&fx);

	T_EXPECT(sent);
	T_EXPECT_EQ(flows, (size_t)0);
	T_EXPECT_EQ(gauge, (size_t)0);
	T_EXPECT_EQ(closed, (size_t)0);
	T_EXPECT(sweep_stopped);
}

static const struct testing_suite suite[] = {
	T_CASE(test_listener_borrowed_delivery_storage_and_socket_lifetime),
	T_CASE(test_flows_alloc_id_parity_and_wrap),
	T_CASE(test_flows_odd_id_exhaustion_and_recovery),
	T_CASE(test_flows_even_id_exhaustion_and_recovery),
	T_CASE(test_flows_active_id_creation_rollback),
	T_CASE(test_flows_active_id_insertion_rollback),
	T_CASE(test_flows_passive_id_creation_rollback),
	T_CASE(test_flows_passive_id_insertion_rollback),
	T_CASE(test_flows_active_send_would_block),
	T_CASE(test_flows_active_send_permanent_error),
	T_CASE(test_flows_passive_send_would_block),
	T_CASE(test_flows_passive_send_permanent_error),
	T_CASE(test_listener_receive_recovery_and_truncation),
	T_CASE(test_passive_receive_recovery_and_truncation),
	T_CASE(test_flows_active_roundtrip),
	T_CASE(test_flows_passive_roundtrip),
	T_CASE(test_flows_active_empty_roundtrip),
	T_CASE(test_flows_passive_empty_roundtrip),
	T_CASE(test_flows_unrelayable_datagram_closes_flow),
	T_CASE(test_flows_recv_close_frees_flow),
	T_CASE(test_flows_sweep_expires_idle_flow),
	T_CASE(test_flows_input_drops_when_not_ready),
	T_CASE(test_listener_routes_and_forgets),
	T_CASE(test_listener_sweep_expires_idle_routes),
	T_CASE(test_listener_idle_timeout_reload),
	T_CASE(test_flow_outlives_listener),
	T_CASE(test_flows_reset_is_silent),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
