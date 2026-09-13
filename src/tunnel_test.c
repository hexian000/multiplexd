/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* tunnel_test.c - white-box tests for tunnel lifecycle, reconnect, reload,
 * resume and identity handling.  tunnel.c is #included, so cases call its
 * static functions directly and read or write tunnel and mux session
 * internals; a refactor of those internals can break the suite.  The real
 * util/conf/listener/server/api_server code and the mux library are linked. */

#include "tunnel.h"

#include "conf.h"
#include "mux/mux.h"
#include "mux/session.h"
#include "mux/stream.h"
#include "server.h"

#include "meta/arraysize.h"
#include "os/socket.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/task.h"
#endif
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#if WITH_TCP_NOTSENT_LOWAT
#include <netinet/tcp.h>
#endif
#include <poll.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#if WITH_THREADS
#include <threads.h>
#include <time.h>
#endif
#include <unistd.h>

#if WITH_THREADS
static bool
ring_probe_dispatcher_invoke(struct dispatcher *d, struct task task);

/* Observe enqueue refusal inside tunnel_post without replacing the real ring. */
#define dispatcher_invoke ring_probe_dispatcher_invoke
#endif /* WITH_THREADS */
static const char *capacity_fail_strdup;
static char *capacity_test_strdup(const char *text)
{
	if (text == capacity_fail_strdup) {
		capacity_fail_strdup = NULL;
		errno = ENOMEM;
		return NULL;
	}
	return strdup(text);
}

#define strdup capacity_test_strdup
#include "tunnel.c"
#undef strdup
#if WITH_THREADS
#undef dispatcher_invoke
#endif /* WITH_THREADS */

static const struct mux_session_config g_conf = {
	.timeout = 30,
	.keepalive = 1,
	.send_timeout = 1,
	.connect_timeout = 1,
	.max_streams = 8,
	.stream_window = 2,
	.session_window = 2,
	.max_frame_payload = 16384 - MUX_FRAME_HEADER_SIZE,
};

static const struct conf_socket_opts g_mux_socket = { .backlog = 1 };
static const struct conf_socket_opts g_local_socket = { .backlog = 1 };

static const struct tunnel_callbacks g_empty_cbs = { 0 };

/* Collects every log record slog emits while registered as its writer sink. */
struct log_capture {
	size_t len;
	bool overflow;
	char buf[4096];
};

static void
log_capture_write(void *ud, const unsigned char *buf, const size_t len)
{
	struct log_capture *const restrict cap = ud;
	/* One byte is reserved for the NUL the string searches need. */
	if (cap->len + len >= sizeof(cap->buf)) {
		cap->overflow = true;
		return;
	}
	memcpy(cap->buf + cap->len, buf, len);
	cap->len += len;
	cap->buf[cap->len] = '\0';
}

/* The suite runs at LOG_LEVEL_SILENCE with no sink; log_capture_stop puts it
 * back that way. */
static void log_capture_start(struct log_capture *restrict cap)
{
	slog_setoutput(SLOG_OUTPUT_WRITER, log_capture_write, cap);
	slog_setlevel(LOG_LEVEL_VERBOSE);
}

static void log_capture_stop(void)
{
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
}

#if WITH_THREADS
struct resume_lookup_probe {
	struct tunnel *old_t;
	size_t unpins;
};

static struct tunnel *test_resume_lookup(
	void *data, struct tunnel *new_t, const unsigned char *session_id)
{
	(void)new_t;
	(void)session_id;
	return ((struct resume_lookup_probe *)data)->old_t;
}

static void test_resume_unpin(void *data, struct tunnel *new_t)
{
	(void)new_t;
	((struct resume_lookup_probe *)data)->unpins++;
}
#endif /* WITH_THREADS */

/* Frame allocator and callback table for the bare mux session that stands in
 * for the peer of an accepted tunnel. */
static struct mux_frame *test_frame_alloc(void *data, const size_t size)
{
	(void)data;
	return malloc(size);
}

static void test_frame_free(void *data, struct mux_frame *frame)
{
	(void)data;
	free(frame);
}

static const struct mux_callbacks g_peer_mux_cbs = { 0 };

/* ── tunnel_context helpers for tests ────────────────────────────────── */

#if WITH_THREADS
static bool test_post_task(void *user, struct task task)
{
	struct server *const restrict s = user;
	if (!dispatcher_invoke(s->disp, task)) {
		return false;
	}
	ev_async_send(s->loop, &s->w_async);
	return true;
}

static void test_flush_tasks(void *user)
{
	dispatcher_tick(((struct server *)user)->disp);
}
#endif /* WITH_THREADS */

static bool test_verify_peer(void *user, const char *peer_identity)
{
	(void)user;
	(void)peer_identity;
	return false;
}

static uint_least64_t test_alloc_index(void *user)
{
	return ++((struct server *)user)->next_tunnel_index;
}

static struct tunnel_session_counters
test_make_tunnel_counters(struct server *restrict srv)
{
	return (struct tunnel_session_counters){
		.num_session_created = &srv->counters.num_session_created,
		.num_session_connect = &srv->counters.num_session_connect,
		.num_session_connected = &srv->counters.num_session_connected,
		.num_session_disconnected =
			&srv->counters.num_session_disconnected,
		.num_session_finalized = &srv->counters.num_session_finalized,
		.num_sessions = &srv->counters.num_sessions,
		.num_session_halfopen = &srv->counters.num_session_halfopen,
	};
}

static struct tunnel_context
test_make_tunnel_context(struct server *restrict srv)
{
	return (struct tunnel_context){
#if WITH_THREADS
		.post_task = test_post_task,
		.flush_tasks = test_flush_tasks,
#endif
		.verify_peer = test_verify_peer,
		.alloc_index = test_alloc_index,
		.user = srv,
#if !WITH_THREADS
		.loop = srv->loop,
#endif
	};
}

/* ─────────────────────────────────────────────────────────────────────── */

static const unsigned char g_zero_id[MUX_SESSION_ID_LEN];

static uint_least64_t test_num_reconnects(const struct tunnel *t)
{
	struct tunnel_stats snap;
	tunnel_stats(t, &snap);
	return snap.num_reconnects;
}

static void reconnect_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)loop;
	(void)revents;
	*(bool *)w->data = true;
}

#if !WITH_THREADS
static bool wait_for_reconnects(
	struct ev_loop *loop, const struct tunnel *t, uint_least64_t minimum)
{
	/* Drive the shared event loop with EVRUN_ONCE so no sleep is needed;
	 * a 10-second guard prevents an infinite hang if no reconnect fires. */
	bool timed_out = false;
	ev_timer tw;
	tw.data = &timed_out;
	ev_timer_init(&tw, reconnect_timeout_cb, 10.0, 0.0);
	ev_timer_start(loop, &tw);
	while (!timed_out && test_num_reconnects(t) < minimum) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &tw);
	return !timed_out && test_num_reconnects(t) >= minimum;
}
#endif /* !WITH_THREADS */

/* Capacity callbacks run only on these unstarted tunnels' test-owned loops. */
static bool capacity_test_reserve(void *user)
{
	struct server *const srv = user;
	if (srv->session_slots >= srv->session_limit) {
		return false;
	}
	srv->session_slots++;
	return true;
}

static void capacity_test_release(void *user)
{
	struct server *const srv = user;
	srv->session_slots--;
	srv->counters.num_rejected++;
}

T_DECLARE_CASE(test_tunnel_capacity_creation_failure_and_teardown)
{
	struct server srv = { .session_limit = 1 };
#if !WITH_THREADS
	srv.loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(srv.loop != NULL);
#endif
	const struct tunnel_session_counters cnt =
		test_make_tunnel_counters(&srv);
	struct tunnel_context ctx = test_make_tunnel_context(&srv);
	ctx.reserve_session = capacity_test_reserve;
	ctx.release_session = capacity_test_release;
	static const char target[] = "127.0.0.1:1";
	struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.mux_conf = &g_conf,
		.fd = -1,
		.id = g_zero_id,
		.cnt = &cnt,
		.connect_addr = target,
	};
	capacity_fail_strdup = target;
	struct tunnel *const failed = tunnel_new(&ctx, &opts);
	capacity_fail_strdup = NULL;
	T_EXPECT(failed == NULL);
	if (failed != NULL) {
		tunnel_close(failed);
	}
	T_EXPECT_EQ(srv.session_slots, (size_t)0);
	T_EXPECT_EQ(srv.counters.num_rejected, (uint_least64_t)1);
	struct tunnel *const outbound = tunnel_new(&ctx, &opts);
	T_CHECK(outbound != NULL);
	T_EXPECT_EQ(srv.session_slots, (size_t)1);
	struct tunnel *const blocked = tunnel_new(&ctx, &opts);
	const int blocked_error = errno;
	if (blocked != NULL) {
		tunnel_close(blocked);
	}
	T_EXPECT(blocked == NULL);
	T_EXPECT_EQ(blocked_error, ENOSPC);
	T_EXPECT(tunnel_admit_session(outbound));
	T_EXPECT_EQ(srv.session_slots, (size_t)1);
	tunnel_close(outbound);
	T_EXPECT_EQ(srv.session_slots, (size_t)0);
	T_EXPECT_EQ(srv.counters.num_rejected, (uint_least64_t)2);
#if !WITH_THREADS
	ev_loop_destroy(srv.loop);
#endif
}

T_DECLARE_CASE(test_tunnel_new_close_no_start)
{
	(void)_t_;
	/* Verify that a tunnel can be destroyed before tunnel_start() without
	 * crashing or leaking resources. */
	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	/* A zero-initialised server is safe for the no-start close path:
	 * tunnel_close never touches srv->disp/loop when !t->started, and stats
	 * are read via pre-captured pointers. */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	/* Without threads the tunnel borrows srv->loop; give it a real one
	 * so that ev_*_stop calls in session_stop are safe. */
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif /* !WITH_THREADS */

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* fds[0] is owned by the tunnel; close only the other end. */
	(void)close(fds[1]);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif
}

T_DECLARE_CASE(test_tunnel_accessors_after_new)
{
	/* Verify that accessors return correct values after tunnel_new()
	 * and before tunnel_start(). */
	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	(void)close(fds[1]);

	/* Capture the accessor reads before teardown frees the tunnel, so a
	 * failed assertion cannot longjmp out with the tunnel still live. */
	const bool accepted = tunnel_is_accepted(t);
	const int fd = tunnel_fd(t);
	const bool has_session = tunnel_session(t) != NULL;

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	/* An accepted tunnel (fd >= 0) must be flagged as accepted. */
	T_EXPECT(accepted);
	/* tunnel_fd must return the fd passed at creation. */
	T_EXPECT_EQ(fd, fds[0]);
	/* Session accessor must return a non-NULL session. */
	T_EXPECT(has_session);
}

/* A resume handoff may fail before its attach task reaches the suspended
 * tunnel: the per-tunnel dispatcher ring can be full, and allocation of the
 * task argument can also fail.  Such a transient must be reported unhandled so
 * the mux layer keeps it alive as a fresh connection instead of tearing it down
 * as a successfully handled resume -- and reporting it unhandled is only sound
 * while the transient still owns the transport the handshake continues on. */
T_DECLARE_CASE(test_tunnel_resume_handoff_failure_keeps_transport)
{
#if !WITH_THREADS
	(void)_t_;
	T_SKIPNOW();
#else
	struct server srv;
	memset(&srv, 0, sizeof(srv));

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	int old_fds[2];
	int new_fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, old_fds) == 0);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, new_fds) == 0);

	const struct tunnel_callbacks old_cbs = { 0 };
	const struct tunnel_opts old_opts = {
		.cb = &old_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = old_fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const old_t = tunnel_new(&ctx, &old_opts);
	T_CHECK(old_t != NULL);
	old_fds[0] = -1;

	struct resume_lookup_probe probe = { .old_t = old_t };
	const struct tunnel_callbacks new_cbs = {
		.on_resume_lookup = test_resume_lookup,
		.on_resume_unpin = test_resume_unpin,
	};
	const struct tunnel_opts new_opts = {
		.cb = &new_cbs,
		.data = &probe,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = new_fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const new_t = tunnel_new(&ctx, &new_opts);
	T_CHECK(new_t != NULL);
	new_fds[0] = -1;

	/* Keep the match in the suspended state while making its task ring full. */
	old_t->ss->state = SESSION_SUSPENDED;
	PUB_STORE(old_t->ss->_pub_state, SESSION_SUSPENDED);
	enum { RING_CAPACITY = 16 };
	for (int i = 0; i < RING_CAPACITY; i++) {
		tunnel_drop_transport(old_t);
	}

	/* The failure is reported from new_t's thread while old_t's own thread
	 * -- busy, which is why its ring is full -- may be rewriting its working
	 * tag between tunnel_set_tag and publishing it.  Stand in for that
	 * mid-rewrite state: the record must carry old_t's published tag, never
	 * read the working buffer another thread owns. */
	char pub_tag[TUNNEL_TAG_SIZE];
	(void)memcpy(pub_tag, old_t->pub.tag, sizeof(pub_tag));
	static const char working_tag[] = "owner-thread-working-tag";
	(void)snprintf(old_t->tag, sizeof(old_t->tag), "%s", working_tag);

	struct log_capture cap = { 0 };
	log_capture_start(&cap);
	const bool handled = tunnel_on_resume(new_t, new_t->ss, g_zero_id, 0);
	log_capture_stop();
	const int transient_fd = mux_fd(new_t->ss);

	/* Close both tunnels before asserting so a failed check cannot leave
	 * detached transports or dispatcher tasks alive. */
	tunnel_close(new_t);
	tunnel_close(old_t);
	(void)close(old_fds[1]);
	(void)close(new_fds[1]);

	T_EXPECT(!handled);
	/* The failed hand-off gave the transport back: an unhandled resume whose
	 * session lost its transport cannot be served fresh. */
	T_EXPECT(transient_fd >= 0);
	T_EXPECT_EQ(probe.unpins, (size_t)1);

	char want[TUNNEL_TAG_SIZE + 64];
	(void)snprintf(
		want, sizeof(want), "%s: failed to dispatch resume attach",
		pub_tag);
	T_EXPECT(!cap.overflow);
	T_EXPECT(strstr(cap.buf, want) != NULL);
	T_EXPECT(strstr(cap.buf, working_tag) == NULL);
#endif /* WITH_THREADS */
}

/* The same hand-off failure, driven through the real handshake instead of a
 * direct call: a resume ClientHello arrives on an accepted tunnel, the lookup
 * matches a suspended tunnel whose task ring is full, and the attach cannot be
 * dispatched.  The peer must come up as a fresh session on the very transport
 * the hand-off attempt borrowed.  Reporting the resume handled would tear the
 * transient session down and leave the peer with a dead connection; reporting
 * it unhandled after taking its transport away is worse still -- the handshake
 * continues and re-arms the session watcher on a closed fd. */
#if WITH_THREADS
static struct mux_frame *capacity_fail_hello_alloc(void *data, size_t size)
{
	(void)data;
	(void)size;
	return NULL;
}
#endif

T_DECLARE_SUBCASE(resume_handoff_capacity, bool at_capacity, bool fail_hello)
{
#if !WITH_THREADS
	(void)_t_;
	(void)at_capacity;
	(void)fail_hello;
	/* Without threads the attach runs inline and cannot be refused. */
	T_SKIPNOW();
#else
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	struct tunnel_context ctx = test_make_tunnel_context(&srv);
	if (at_capacity || fail_hello) {
		srv.session_limit = 1;
		ctx.reserve_session = capacity_test_reserve;
		ctx.release_session = capacity_test_release;
	}
	int old_fds[2];
	int new_fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, old_fds) == 0);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, new_fds) == 0);
	T_CHECK(socket_set_nonblock(new_fds[0]) == 0);
	T_CHECK(socket_set_nonblock(new_fds[1]) == 0);

	const struct tunnel_callbacks old_cbs = { 0 };
	const struct tunnel_opts old_opts = {
		.cb = &old_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = old_fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const old_t = tunnel_new(&ctx, &old_opts);
	T_CHECK(old_t != NULL);
	old_fds[0] = -1;
	if (at_capacity) {
		T_CHECK(tunnel_admit_session(old_t));
	}

	struct resume_lookup_probe probe = { .old_t = old_t };
	const struct tunnel_callbacks new_cbs = {
		.on_resume_lookup = test_resume_lookup,
		.on_resume_unpin = test_resume_unpin,
	};
	const struct tunnel_opts new_opts = {
		.cb = &new_cbs,
		.data = &probe,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = new_fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const new_t = tunnel_new(&ctx, &new_opts);
	T_CHECK(new_t != NULL);
	new_fds[0] = -1;
	if (fail_hello) {
		new_t->ss->pool.alloc = capacity_fail_hello_alloc;
	}

	/* Keep the match in the suspended state while making its task ring full. */
	old_t->ss->state = SESSION_SUSPENDED;
	PUB_STORE(old_t->ss->_pub_state, SESSION_SUSPENDED);
	enum { RING_CAPACITY = 16 };
	for (int i = 0; i < RING_CAPACITY; i++) {
		tunnel_drop_transport(old_t);
	}

	/* The peer end of the accepted tunnel: a client session claiming a session
	 * id of its own, which is what makes its hello a resume request.  It shares
	 * the tunnel's loop, whose thread is deliberately not started, so this test
	 * drives both sides itself. */
	unsigned char peer_id[MUX_SESSION_ID_LEN];
	memset(peer_id, 0x5a, sizeof(peer_id));
	const struct mux_session_opts peer_opts = {
		.callbacks = &g_peer_mux_cbs,
		.conf = &g_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = -1,
		.id = peer_id,
		.tag = "[peer]:",
	};
	struct mux_session *const peer = mux_new(new_t->loop, &peer_opts);
	T_CHECK(peer != NULL);
	peer->handshake.has_session_id = true;

	mux_start(new_t->ss);
	mux_attach_fd(peer, new_fds[1]);
	new_fds[1] = -1;

	/* Both sessions run on this loop, so polling it without blocking drives the
	 * whole exchange; the bound turns a stalled handshake into a failed check
	 * rather than a hang. */
	enum { MAX_POLLS = 1000 };
	bool established = false;
	bool rejected = false;
	for (int i = 0; i < MAX_POLLS && !established && !rejected; i++) {
		ev_run(new_t->loop, EVRUN_NOWAIT);
		established = mux_state(peer) == MUX_STATE_ESTABLISHED &&
			      mux_state(new_t->ss) == MUX_STATE_ESTABLISHED;
		rejected = mux_state(new_t->ss) == MUX_STATE_CLOSED &&
			   mux_state(peer) == MUX_STATE_SUSPENDED;
	}
	const int transient_fd = mux_fd(new_t->ss);
	const size_t unpins = probe.unpins;
	const enum mux_state old_state = mux_state(old_t->ss);

	mux_close(peer);
	tunnel_close(new_t);
	tunnel_close(old_t);
	(void)close(old_fds[1]);
	dispatcher_destroy(srv.disp);

	/* The refused hand-off was attempted exactly once... */
	T_EXPECT_EQ(unpins, (size_t)1);
	/* ...it left the suspended tunnel to its own resume timeout... */
	T_EXPECT(old_state == MUX_STATE_SUSPENDED);
	/* ...and the peer got a working fresh session on the same transport. */
	if (at_capacity || fail_hello) {
		T_EXPECT(rejected);
		T_EXPECT(!established);
		T_EXPECT(transient_fd < 0);
		T_EXPECT_EQ(srv.session_slots, (size_t)0);
		T_EXPECT_EQ(srv.counters.num_rejected, (uint_least64_t)1);
	} else {
		T_EXPECT(established);
		T_EXPECT(transient_fd >= 0);
	}
#endif /* WITH_THREADS */
}

T_DECLARE_CASE(test_tunnel_resume_handoff_failure_completes_fresh_handshake)
{
	T_CALL_SUBCASE(resume_handoff_capacity, false, false);
}

T_DECLARE_CASE(test_tunnel_resume_handoff_failure_obeys_capacity)
{
	T_CALL_SUBCASE(resume_handoff_capacity, true, false);
}

T_DECLARE_CASE(test_tunnel_capacity_failed_hello_releases_reservation)
{
	T_CALL_SUBCASE(resume_handoff_capacity, false, true);
}

T_DECLARE_CASE(test_tunnel_reconnect_rearms_after_failed_retry)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* Drive the initial connect and one timer callback directly.  This test
	 * covers the retry re-arm path; no tunnel thread or scheduler timing is
	 * needed to exercise it. */
	tunnel_initial_connect_task(t);
	tunnel_reconnect_cb(t->loop, &t->w_reconnect, EV_TIMER);
	/* The initial dial is not a reconnect; the timer's dial is. */
	const uint_least64_t num_reconnects = test_num_reconnects(t);
	const bool rearmed = ev_is_active(&t->w_reconnect);

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT_EQ(num_reconnects, (uint_least64_t)1);
	T_EXPECT(rearmed);
}

/* tunnel_schedule_reconnect jitters every rung by a factor in [0.8, 1.2). */
static bool jittered_from(const double delay, const double rung)
{
	return delay >= rung * 0.8 && delay < rung * 1.2;
}

/* The ladder used to be driven by attempt count alone, so a dial that failed
 * because the local path is gone was paced exactly like one the peer refused:
 * its first rungs put eight attempts in the opening minute, every one of them
 * futile, and on a mobile link every one a radio wakeup.  A connect(2) errno
 * from the no-route family now enters the ladder at its first 15s rung. */
T_DECLARE_CASE(test_tunnel_reconnect_backoff_skips_fast_rungs_when_unreachable)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	/* Deliberately not started: tunnel_new leaves the loop and the backoff
	 * timer initialised, and with no thread behind them the backoff state is
	 * this thread's alone to drive and read. */
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* A peer that answers with RST is reachable, so the fast rung stands. */
	tunnel_schedule_reconnect(t, ECONNREFUSED);
	const double refused_delay = t->w_reconnect.repeat;
	const int refused_count = t->reconnect_count;

	static const int no_route[] = { ENETDOWN, ENETUNREACH, EHOSTUNREACH };
	double jumped_delay[ARRAY_SIZE(no_route)];
	int jumped_count[ARRAY_SIZE(no_route)];
	for (size_t i = 0; i < ARRAY_SIZE(no_route); i++) {
		t->reconnect_count = 0;
		tunnel_schedule_reconnect(t, no_route[i]);
		jumped_delay[i] = t->w_reconnect.repeat;
		jumped_count[i] = t->reconnect_count;
	}

	/* Having jumped, the ladder keeps climbing on the next failure instead
	 * of dropping back to the rungs it just skipped. */
	t->reconnect_count = 0;
	tunnel_schedule_reconnect(t, ENETUNREACH);
	tunnel_schedule_reconnect(t, ECONNREFUSED);
	const double next_delay = t->w_reconnect.repeat;
	const int next_count = t->reconnect_count;

	const double fast_rung = tunnel_reconnect_delays[0];
	const double no_route_rung =
		tunnel_reconnect_delays[TUNNEL_RECONNECT_UNREACHABLE_IDX];

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	/* TUNNEL_RECONNECT_UNREACHABLE_IDX must still name a rung worth jumping to:
	 * the first one at or above 15s. */
	T_EXPECT(no_route_rung >= 15.0);
	T_EXPECT(
		tunnel_reconnect_delays[TUNNEL_RECONNECT_UNREACHABLE_IDX - 1] <
		15.0);

	T_LOGF("refused: %.3fs (rung %.1fs)", refused_delay, fast_rung);
	T_EXPECT(jittered_from(refused_delay, fast_rung));
	T_EXPECT_EQ(refused_count, 1);

	for (size_t i = 0; i < ARRAY_SIZE(no_route); i++) {
		T_LOGF("errno %d: %.3fs (rung %.1fs)", no_route[i],
		       jumped_delay[i], no_route_rung);
		T_EXPECT(jittered_from(jumped_delay[i], no_route_rung));
		T_EXPECT_EQ(
			jumped_count[i], TUNNEL_RECONNECT_UNREACHABLE_IDX + 1);
	}

	T_EXPECT(next_delay >= no_route_rung * 0.8);
	T_EXPECT_EQ(next_count, TUNNEL_RECONNECT_UNREACHABLE_IDX + 2);
}

/* Only a failure the routing table settles comes back on connect(2) itself; a
 * no-route error raised after the SYN went out arrives asynchronously and
 * reaches the tunnel solely as MUX_EVENT_CLOSED.  While that event carried no
 * errno the ladder had nothing to classify and restarted at 0.2 s, giving the
 * offline case the very burst the synchronous path already avoids. */
T_DECLARE_CASE(test_tunnel_reconnect_backoff_reads_closed_event_errno)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	/* Never started, so the close handler and the backoff state it drives are
	 * this thread's alone; g_conf leaves idle_timeout at 0, which is the mode
	 * that arms the ladder from a close. */
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	tunnel_on_event(
		t, t->ss, MUX_EVENT_CLOSED,
		(union mux_event_data){ .closed.err = ECONNREFUSED });
	const double refused_delay = t->w_reconnect.repeat;
	const int refused_count = t->reconnect_count;

	t->reconnect_count = 0;
	tunnel_on_event(
		t, t->ss, MUX_EVENT_CLOSED,
		(union mux_event_data){ .closed.err = ENETUNREACH });
	const double jumped_delay = t->w_reconnect.repeat;
	const int jumped_count = t->reconnect_count;

	/* A close that names no errno keeps the fast rung: a clean peer FIN or a
	 * timeout says nothing about the path. */
	t->reconnect_count = 0;
	tunnel_on_event(
		t, t->ss, MUX_EVENT_CLOSED, (union mux_event_data){ 0 });
	const double silent_delay = t->w_reconnect.repeat;

	const double fast_rung = tunnel_reconnect_delays[0];
	const double no_route_rung =
		tunnel_reconnect_delays[TUNNEL_RECONNECT_UNREACHABLE_IDX];

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_LOGF("refused: %.3fs | unreachable: %.3fs | silent: %.3fs",
	       refused_delay, jumped_delay, silent_delay);
	T_EXPECT(jittered_from(refused_delay, fast_rung));
	T_EXPECT_EQ(refused_count, 1);
	T_EXPECT(jittered_from(jumped_delay, no_route_rung));
	T_EXPECT_EQ(jumped_count, TUNNEL_RECONNECT_UNREACHABLE_IDX + 1);
	T_EXPECT(jittered_from(silent_delay, fast_rung));
}

/* A resume attempt that fails leaves the session SUSPENDED and emits no
 * MUX_EVENT_CLOSED, so its MUX_EVENT_CONNECT_FAILED is the only signal that
 * paces the next attempt: it must arm the backoff ladder with the attempt's
 * errno.  A CONNECT_FAILED on a session that closed must not, since the CLOSED
 * that follows it schedules the retry itself. */
T_DECLARE_CASE(test_tunnel_reconnect_backoff_after_failed_resume_attempt)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	/* Never started, so the session and the backoff state are this
	 * thread's alone. */
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	t->ss->state = SESSION_CLOSED;
	PUB_STORE(t->ss->_pub_state, SESSION_CLOSED);
	tunnel_on_event(
		t, t->ss, MUX_EVENT_CONNECT_FAILED,
		(union mux_event_data){ .connect_failed.err = ECONNREFUSED });
	const bool armed_on_close = ev_is_active(&t->w_reconnect);
	const int close_count = t->reconnect_count;

	t->ss->state = SESSION_SUSPENDED;
	PUB_STORE(t->ss->_pub_state, SESSION_SUSPENDED);
	tunnel_on_event(
		t, t->ss, MUX_EVENT_CONNECT_FAILED,
		(union mux_event_data){ .connect_failed.err = ENETUNREACH });
	const bool armed = ev_is_active(&t->w_reconnect);
	const double delay = t->w_reconnect.repeat;
	const int count = t->reconnect_count;

	t->ss->state = SESSION_CLOSED;
	PUB_STORE(t->ss->_pub_state, SESSION_CLOSED);
	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	const double no_route_rung =
		tunnel_reconnect_delays[TUNNEL_RECONNECT_UNREACHABLE_IDX];
	T_LOGF("suspended: armed=%d delay=%.3fs count=%d", armed, delay, count);
	T_EXPECT(!armed_on_close);
	T_EXPECT_EQ(close_count, 0);
	T_EXPECT(armed);
	T_EXPECT(jittered_from(delay, no_route_rung));
	T_EXPECT_EQ(count, TUNNEL_RECONNECT_UNREACHABLE_IDX + 1);
}

/* An on-demand tunnel's idle close runs the graceful shutdown exchange, so the
 * session sits in CLOSING until the peer answers.  A local connection arriving
 * then cannot be served and the session cannot take a new fd yet; the demand
 * must still redial once the close completes rather than being lost, or the
 * next connection meets a closed session with no dial under way.  The
 * connection itself is the first one after idle, so it waits for that redial
 * like any other: parked through the close and the dial, closed only once the
 * attempt ends without a session. */
T_DECLARE_CASE(test_tunnel_on_demand_redials_after_close_in_flight)
{
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 1) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	char connect_addr[32];
	(void)snprintf(
		connect_addr, sizeof(connect_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));

	struct server srv;
	memset(&srv, 0, sizeof(srv));
#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	struct mux_session_config conf = g_conf;
	conf.idle_timeout = 1;
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
		.cnt = &cnts,
	};
	/* Never started: the session and its close handler are this thread's
	 * alone, so the states can be set directly. */
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	int local[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, local) == 0);
	t->ss->state = SESSION_CLOSING;
	PUB_STORE(t->ss->_pub_state, SESSION_CLOSING);
	tunnel_open_fd(t, local[0]);
	struct pollfd lpfd = { .fd = local[1], .events = POLLIN };
	const bool parked = t->park_head != NULL && poll(&lpfd, 1, 0) == 0;
	/* A lifecycle event while still closing must not give up on it. */
	tunnel_settle_parked(t);
	const bool parked_through_close =
		t->park_head != NULL && poll(&lpfd, 1, 0) == 0;
	struct pollfd pfd = { .fd = lfd, .events = POLLIN };
	const bool dialed_while_closing = poll(&pfd, 1, 0) > 0;

	/* The close completes. */
	t->ss->state = SESSION_CLOSED;
	PUB_STORE(t->ss->_pub_state, SESSION_CLOSED);
	tunnel_on_event(
		t, t->ss, MUX_EVENT_CLOSED, (union mux_event_data){ 0 });
	const enum mux_state after_closed = mux_state(t->ss);
	const bool dialed = poll(&pfd, 1, 5000) > 0;
	if (dialed) {
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			(void)close(cfd);
		}
	}
	tunnel_settle_parked(t);
	const bool parked_through_dial =
		t->park_head != NULL && poll(&lpfd, 1, 0) == 0;

	/* One-shot: a later close with no new demand behind it stays down
	 * until the next connection asks for the tunnel. */
	t->ss->state = SESSION_CLOSED;
	PUB_STORE(t->ss->_pub_state, SESSION_CLOSED);
	tunnel_on_event(
		t, t->ss, MUX_EVENT_CLOSED, (union mux_event_data){ 0 });
	const bool redialed_again = poll(&pfd, 1, 0) > 0;
	/* That attempt ended without a session: the parked connection is closed. */
	tunnel_settle_parked(t);
	char byte;
	const bool closed_after_attempt = t->park_head == NULL &&
					  poll(&lpfd, 1, 0) > 0 &&
					  read(local[1], &byte, 1) == 0;
	(void)close(local[1]);

	tunnel_close(t);
	(void)close(lfd);
#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT(parked);
	T_EXPECT(parked_through_close);
	T_EXPECT(!dialed_while_closing);
	T_EXPECT_EQ(after_closed, MUX_STATE_CONNECT);
	T_EXPECT(dialed);
	T_EXPECT(parked_through_dial);
	T_EXPECT(!redialed_again);
	T_EXPECT(closed_after_attempt);
}

/* tunnel.h documents update_connect_addr with a NULL address as "clears and
 * disables reconnect", but reload_task only cleared it -- a backoff timer armed
 * before the reload then fired into tunnel_do_connect with no address, and that
 * is the one reconnect entry point with no NULL guard, so resolve_addr walked
 * into strlen(NULL). Drive exactly the documented usage: arm the reconnect
 * timer, clear the address through reload_task, then verify the timer is gone
 * and that a tick already due when the reload ran dials nothing. */
T_DECLARE_CASE(test_tunnel_reload_null_addr_disables_reconnect)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	/* Let the initial connect fail and arm the backoff timer directly.  The
	 * tunnel.c white-box inclusion makes the timer state deterministic without
	 * starting a worker thread. */
	tunnel_initial_connect_task(t);
	const bool armed = ev_is_active(&t->w_reconnect);

	/* The documented "clears and disables reconnect" form. */
	struct reload_arg *const reload = calloc(1, sizeof(*reload));
	T_CHECK(reload != NULL);
	*reload = (struct reload_arg){
		.t = t,
		.ss = t->ss,
		.conf = g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.update_connect_addr = true,
	};
	reload_task(reload);
	/* Verify that reload_task stopped the pending timer rather than relying on
	 * elapsed wall time to let a surviving timer fire. */
	const bool timer_stopped = !ev_is_active(&t->w_reconnect);
	/* A tick that was already due when the reload ran still reaches the
	 * callback: model it directly.  It must neither dial the cleared address
	 * nor schedule another attempt. */
	const uint_least64_t before = test_num_reconnects(t);
	tunnel_reconnect_cb(t->loop, &t->w_reconnect, EV_TIMER);
	const uint_least64_t after = test_num_reconnects(t);
	const bool rearmed = ev_is_active(&t->w_reconnect);
	const int fd_after_tick = mux_fd(t->ss);

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT(armed);
	T_EXPECT(timer_stopped);
	/* The late tick dialed nothing and left reconnect disabled. */
	T_EXPECT_EQ(after, before);
	T_EXPECT(!rearmed);
	T_EXPECT_EQ(fd_after_tick, -1);
}

/* num_reconnects counts dials, not schedulings: a backoff that a shutdown or a
 * reload-disabled reconnect cancels before it fires never dialed anything. */
T_DECLARE_CASE(test_tunnel_reconnect_count_skips_cancelled_backoff)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};

	/* Cancelled by tunnel_shutdown's task. */
	struct tunnel *const t_shut = tunnel_new(&ctx, &opts);
	T_CHECK(t_shut != NULL);
	tunnel_initial_connect_task(t_shut);
	const bool shut_armed = ev_is_active(&t_shut->w_reconnect);
	task_shutdown(t_shut);
	const bool shut_stopped = !ev_is_active(&t_shut->w_reconnect);
	const uint_least64_t shut_count = test_num_reconnects(t_shut);
	tunnel_close(t_shut);

	/* Cancelled by a reload that disables reconnect. */
	struct tunnel *const t_reload = tunnel_new(&ctx, &opts);
	T_CHECK(t_reload != NULL);
	tunnel_initial_connect_task(t_reload);
	const bool reload_armed = ev_is_active(&t_reload->w_reconnect);
	struct reload_arg *const reload = calloc(1, sizeof(*reload));
	T_CHECK(reload != NULL);
	*reload = (struct reload_arg){
		.t = t_reload,
		.ss = t_reload->ss,
		.conf = g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.disable_reconnect = true,
	};
	reload_task(reload);
	const bool reload_stopped = !ev_is_active(&t_reload->w_reconnect);
	const uint_least64_t reload_count = test_num_reconnects(t_reload);
	tunnel_close(t_reload);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT(shut_armed);
	T_EXPECT(shut_stopped);
	T_EXPECT_EQ(shut_count, (uint_least64_t)0);
	T_EXPECT(reload_armed);
	T_EXPECT(reload_stopped);
	T_EXPECT_EQ(reload_count, (uint_least64_t)0);
}

/* An idle_timeout tunnel has no backoff timer after a close: the next local
 * connection redials it from tunnel_open_fd, and that dial is a reconnect like
 * any other. */
T_DECLARE_CASE(test_tunnel_reconnect_count_includes_demand_redial)
{
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 4) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	char connect_addr[32];
	(void)snprintf(
		connect_addr, sizeof(connect_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	struct mux_session_config conf = g_conf;
	conf.idle_timeout = 60;
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
		.cnt = &cnts,
	};

	/* Never started, so its loop is this thread's to drive. */
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* Initial dial; the listener takes it and hangs up, which closes the
	 * session with no backoff armed (idle_timeout mode). */
	tunnel_initial_connect_task(t);
	struct pollfd pfd = { .fd = lfd, .events = POLLIN };
	const bool first_ready = poll(&pfd, 1, 5000) > 0;
	if (first_ready) {
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			(void)close(cfd);
		}
	}
	bool timed_out = false;
	ev_timer tw;
	tw.data = &timed_out;
	ev_timer_init(&tw, reconnect_timeout_cb, 10.0, 0.0);
	ev_timer_start(t->loop, &tw);
	while (!timed_out && first_ready &&
	       mux_state(t->ss) != MUX_STATE_CLOSED &&
	       mux_state(t->ss) != MUX_STATE_SUSPENDED) {
		ev_run(t->loop, EVRUN_ONCE);
	}
	ev_timer_stop(t->loop, &tw);
	const bool closed = !timed_out && first_ready;
	const bool unarmed = !ev_is_active(&t->w_reconnect);
	const uint_least64_t before = test_num_reconnects(t);

	/* A local connection arrives: no session to open it on, so it is closed
	 * and the tunnel redials. */
	int sp[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	tunnel_open_fd(t, sp[1]);
	(void)close(sp[0]);
	pfd = (struct pollfd){ .fd = lfd, .events = POLLIN };
	const bool redialed = poll(&pfd, 1, 5000) > 0;
	const uint_least64_t after = test_num_reconnects(t);

	tunnel_close(t);
	(void)close(lfd);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT(closed);
	T_EXPECT(unarmed);
	T_EXPECT_EQ(before, (uint_least64_t)0);
	T_EXPECT(redialed);
	T_EXPECT_EQ(after, (uint_least64_t)1);
}

T_DECLARE_CASE(test_tunnel_reconnect_on_transport_lost)
{
	/* MUX_EVENT_CLOSED must schedule a reconnect even with no relay on_event
	 * callback — a regression where tunnel_on_event was not registered when
	 * cb->on_event was NULL. */
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 1) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	char connect_addr[32];
	(void)snprintf(
		connect_addr, sizeof(connect_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	T_CHECK(tunnel_start(t));

	/* Accept the initial connection and immediately close it. */
#if WITH_THREADS
	bool accept_ready;
#endif
	{
#if !WITH_THREADS
		/* tunnel_do_connect ran inline in tunnel_start; the TCP connection
		 * is already in the accept queue before we reach this point. */
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			(void)close(cfd);
		}
#else /* WITH_THREADS */
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };
		accept_ready = poll(&pfd, 1, 1000) > 0;
		/* lfd is a blocking listen socket, so only accept once poll has
		 * reported a pending connection; on a poll timeout (loaded host,
		 * or the connect failure this test probes) skip the accept and
		 * let the T_EXPECT(accept_ready) below fail cleanly instead of
		 * blocking forever. */
		if (accept_ready) {
			const int cfd = accept(lfd, NULL, NULL);
			if (cfd >= 0) {
				(void)close(cfd);
			}
		}
#endif /* WITH_THREADS */
	}

	/* MUX_EVENT_CLOSED fires: tunnel_on_event schedules a reconnect.  Observe
	 * the next TCP connection directly rather than polling the tunnel's stats
	 * with scheduler-dependent sleeps. */
	bool reconnected = false;
#if WITH_THREADS
	struct pollfd reconnect_pfd = { .fd = lfd, .events = POLLIN };
	if (poll(&reconnect_pfd, 1, 10000) > 0) {
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd >= 0) {
			(void)close(cfd);
			reconnected = test_num_reconnects(t) >= 1;
		}
	}
#else /* !WITH_THREADS */
	reconnected = wait_for_reconnects(srv.loop, t, 1);
#endif /* WITH_THREADS */
	(void)close(lfd);

	tunnel_close(t);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
	T_EXPECT(accept_ready);
#else
	ev_loop_destroy(loop);
#endif
	T_EXPECT(reconnected);
}

T_DECLARE_CASE(test_tunnel_reconnect_after_connect_timeout)
{
	/* connect_timeout must cover the whole CONNECT+HANDSHAKE phase: the
	 * server accepts TCP but never sends the hello, so the timeout fires,
	 * delivers MUX_EVENT_CLOSED, and drives backoff.  Asserts >= 2 reconnects. */
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 4) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	char connect_addr[32];
	(void)snprintf(
		connect_addr, sizeof(connect_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));
	{
		const int flags = fcntl(lfd, F_GETFL, 0);
		T_CHECK(flags >= 0);
		T_CHECK(fcntl(lfd, F_SETFL, flags | O_NONBLOCK) == 0);
	}

	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if WITH_THREADS
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#else
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	T_CHECK(tunnel_start(t));

	/* Accept and hold incoming connections without replying; connect_timeout
	 * (1 s) fires, triggering MUX_EVENT_CLOSED and reconnect backoff. */
	int held_fds[8];
	int num_held = 0;
	bool ok = false;
#if WITH_THREADS
	/* Each accepted connection is held until connect_timeout fires.  The third
	 * listener event proves that two timeout-driven reconnects were scheduled,
	 * without polling a shared counter or sleeping between attempts. */
	while (num_held < 3) {
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };
		if (poll(&pfd, 1, 10000) <= 0) {
			break;
		}
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0) {
			break;
		}
		if (num_held < (int)ARRAY_SIZE(held_fds)) {
			held_fds[num_held++] = cfd;
		} else {
			(void)close(cfd);
		}
	}
	ok = num_held >= 3 && test_num_reconnects(t) >= 2;
#else /* !WITH_THREADS */
	{
		/* Drive the event loop one event at a time; accept between steps so
		 * each TCP connect is captured before the next timer fires.  The
		 * 10-second guard prevents an infinite hang if connect_timeout or
		 * the reconnect timer never fires. */
		bool timed_out = false;
		ev_timer tw;
		tw.data = &timed_out;
		ev_timer_init(&tw, reconnect_timeout_cb, 10.0, 0.0);
		ev_timer_start(srv.loop, &tw);
		while (!timed_out && test_num_reconnects(t) < 2) {
			const int cfd = accept(lfd, NULL, NULL);
			if (cfd >= 0) {
				if (num_held < (int)ARRAY_SIZE(held_fds)) {
					held_fds[num_held++] = cfd;
				} else {
					(void)close(cfd);
				}
			}
			ev_run(srv.loop, EVRUN_ONCE);
		}
		ev_timer_stop(srv.loop, &tw);
		ok = !timed_out && test_num_reconnects(t) >= 2;
	}
#endif /* WITH_THREADS */
	/* ok was captured above while the tunnel thread was live; join the thread
	 * via tunnel_close and release the fixture before asserting, so a failed
	 * assertion cannot longjmp out with the thread still running. */
	tunnel_close(t);

	for (int i = 0; i < num_held; i++) {
		(void)close(held_fds[i]);
	}
	(void)close(lfd);

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
#else
	ev_loop_destroy(loop);
#endif

	T_EXPECT(ok);
}

T_DECLARE_CASE(test_tunnel_stream_connect_applies_notsent_lowat)
{
#if !WITH_TCP_NOTSENT_LOWAT
	(void)_t_;
	T_SKIPNOW();
#else
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 1) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	const int lfd_flags = fcntl(lfd, F_GETFL, 0);
	T_CHECK(lfd_flags >= 0);
	T_CHECK(fcntl(lfd, F_SETFL, lfd_flags | O_NONBLOCK) == 0);
	char forward_addr[32];
	(void)snprintf(
		forward_addr, sizeof(forward_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));

	struct server srv;
	memset(&srv, 0, sizeof(srv));
#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	struct conf_socket_opts local_socket = g_local_socket;
	local_socket.tcp_notsent_lowat = 12345;
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = local_socket,
		.fd = -1,
		.id = g_zero_id,
		.forward_addr = forward_addr,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	struct mux_stream *const stream = mux_stream_new(t->ss, 2, false);
	T_CHECK(stream != NULL);

	const bool accepted = tunnel_on_accept(t, t->ss, stream);
	const int stream_fd = stream->socket.w_io.fd;
	const int accepted_fd = accept(lfd, NULL, NULL);
	int lowat = 0;
	socklen_t lowat_len = sizeof(lowat);
	const bool option_read =
		accepted && stream_fd >= 0 &&
		getsockopt(
			stream_fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat,
			&lowat_len) == 0;

	mux_stream_free(stream);
	tunnel_close(t);
	if (accepted_fd >= 0) {
		(void)close(accepted_fd);
	}
	(void)close(lfd);
#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT(accepted);
	T_EXPECT(option_read);
	if (option_read) {
		T_EXPECT_EQ(lowat, local_socket.tcp_notsent_lowat);
	}
#endif /* WITH_TCP_NOTSENT_LOWAT */
}

T_DECLARE_CASE(test_tunnel_state_returns_connecting_after_new)
{
	/* Freshly created outbound tunnel (fd=-1, not started) must report
	 * MUX_STATE_CONNECT. */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* Capture the state before teardown frees the tunnel. */
	const enum mux_state state = tunnel_state(t);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT_EQ(state, (enum mux_state)MUX_STATE_CONNECT);
}

T_DECLARE_CASE(test_tunnel_stats_initial_zero)
{
	/* All stream/traffic counters must be zero after tunnel_new()
	 * and before tunnel_start(). */
	struct server srv;
	memset(&srv, 0, sizeof(srv));

#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.cnt = &cnts,
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* tunnel_stats snapshots into the local stats, so it is safe to tear the
	 * tunnel down before asserting on the captured copy. */
	struct tunnel_stats stats;
	tunnel_stats(t, &stats);

	tunnel_close(t);

#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT_EQ(stats.num_streams, (size_t)0);
	T_EXPECT_EQ(stats.num_stream_opened, (uint_least64_t)0);
	T_EXPECT_EQ(stats.byt_mux_recv, (uint_least64_t)0);
	T_EXPECT_EQ(stats.byt_mux_sent, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_reconnects, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_rst_sent, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_rst_recv, (uint_least64_t)0);
	T_EXPECT_EQ(stats.num_stream_errors, (uint_least64_t)0);
	T_EXPECT_EQ(stats.recv_buffered_bytes, (size_t)0);
	T_EXPECT_EQ(stats.send_buffered_frames, (size_t)0);
	T_EXPECT_EQ(stats.unacked_frames, (size_t)0);
}

T_DECLARE_CASE(test_tunnel_open_stream_burst_not_dropped)
{
#if !WITH_THREADS
	(void)_t_;
	/* Without threads tunnel_open_stream opens inline; there is no bounded task
	 * ring to overflow, so the drop this pins cannot occur. */
	T_SKIPNOW();
#else
	/* A burst of concurrent opens larger than the tunnel's task-ring capacity
	 * (16) must not drop any accepted connection.  Create an accepted tunnel but
	 * do NOT start its thread, so nothing drains the queue, then hand it a burst
	 * well above the ring capacity and confirm every accepted connection is
	 * still open (held for later service), not closed.  Pre-fix, each open was
	 * posted onto the 16-slot ring and the fd was closed once the ring filled,
	 * dropping the burst's tail; the peer end then saw EOF. */
	enum { BURST = 64 };
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	int tpair[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, tpair) == 0);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = tpair[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	(void)close(tpair[1]);

	/* ours[] is the end we keep (to observe closure); sp[1] is handed to the
	 * tunnel, which now owns and eventually closes it. */
	int ours[BURST];
	int made = 0;
	for (; made < BURST; made++) {
		int sp[2];
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
			break;
		}
		ours[made] = sp[0];
		tunnel_open_stream(t, sp[1]);
	}

	/* Probe every handed-off connection via the retained peer while the tunnel
	 * is still live -- immune to fd-number reuse, unlike probing the handed-off
	 * descriptor directly.  A closed (dropped) peer reads EOF (recv == 0); a
	 * held one would block, so recv returns -1/EAGAIN. */
	int dropped = 0;
	for (int i = 0; i < made; i++) {
		char b;
		if (recv(ours[i], &b, 1, MSG_DONTWAIT) == 0) {
			dropped++;
		}
	}

	tunnel_close(t); /* flushes and closes any still-queued opens */
	for (int i = 0; i < made; i++) {
		(void)close(ours[i]);
	}
	dispatcher_destroy(srv.disp);

	/* The whole burst was issued, and none of it was dropped. */
	T_EXPECT_EQ(made, (int)BURST);
	T_EXPECT_EQ(dropped, 0);
#endif /* WITH_THREADS */
}

/* The owner side of a relay: the events on_event received, in order. */
struct relay_probe {
	enum mux_event events[4];
	size_t num_events;
};

static void relay_probe_on_event(
	void *data, struct tunnel *t, const enum mux_event event,
	const union mux_event_data edata)
{
	(void)t;
	(void)edata;
	struct relay_probe *const restrict probe = data;
	if (probe->num_events < ARRAY_SIZE(probe->events)) {
		probe->events[probe->num_events] = event;
	}
	probe->num_events++;
}

#if WITH_THREADS
static void relay_filler_task(void *p)
{
	(void)p;
}

static void
relay_owner_async_cb(struct ev_loop *loop, ev_async *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void relay_guard_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)revents;
	*(bool *)w->data = true;
}
#endif /* WITH_THREADS */

/* The owner's task ring is bounded and shared by every tunnel, so a burst of
 * session events can fill it.  An event the full ring refuses must be retried,
 * not dropped: a lost CLOSED leaves the owner holding a dead tunnel for good.
 * It must also still reach the owner ahead of the events relayed after it.
 * Events the owner does not act on are not relayed at all. */
T_DECLARE_CASE(test_tunnel_relay_retries_events_a_full_ring_refused)
{
#if !WITH_THREADS
	(void)_t_;
	/* Without threads events are delivered inline; there is no ring. */
	T_SKIPNOW();
#else
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(srv.loop != NULL);
	ev_async_init(&srv.w_async, relay_owner_async_cb);
	ev_async_start(srv.loop, &srv.w_async);
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	struct relay_probe probe = { .num_events = 0 };
	const struct tunnel_callbacks cbs = {
		.on_event = relay_probe_on_event,
	};
	int tpair[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, tpair) == 0);
	const struct tunnel_opts opts = {
		.cb = &cbs,
		.data = &probe,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = tpair[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	/* An accepted tunnel, so its CLOSED is the terminal one it relays.  Its
	 * thread is not started: this test plays both loops itself. */
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	const union mux_event_data none = { 0 };
	tunnel_on_event(t, t->ss, MUX_EVENT_CONNECT, none);
	dispatcher_tick(srv.disp);
	const size_t after_connect = probe.num_events;

	/* Fill the ring, relay LOST into it, then make room before CLOSED. */
	enum { MAX_FILL = 1024 };
	for (int i = 0; i < MAX_FILL; i++) {
		if (!dispatcher_invoke(
			    srv.disp,
			    (struct task){ relay_filler_task, NULL })) {
			break;
		}
	}
	tunnel_on_event(t, t->ss, MUX_EVENT_LOST, none);
	dispatcher_tick(srv.disp);
	tunnel_on_event(t, t->ss, MUX_EVENT_CLOSED, none);
	dispatcher_tick(srv.disp);
	const size_t before_retry = probe.num_events;

	/* Run the tunnel's loop so its retry re-posts what the ring refused. */
	bool timed_out = false;
	ev_timer guard;
	ev_timer_init(&guard, relay_guard_cb, 5.0, 0.0);
	guard.data = &timed_out;
	ev_timer_start(t->loop, &guard);
	while (!timed_out && probe.num_events < 2) {
		ev_run(t->loop, EVRUN_ONCE);
		dispatcher_tick(srv.disp);
	}
	ev_timer_stop(t->loop, &guard);

	tunnel_close(t);
	(void)close(tpair[1]);
	dispatcher_destroy(srv.disp);
	ev_async_stop(srv.loop, &srv.w_async);
	ev_loop_destroy(srv.loop);

	T_EXPECT_EQ(after_connect, (size_t)0);
	/* CLOSED found the ring free, but it waits behind the refused LOST. */
	T_EXPECT_EQ(before_retry, (size_t)0);
	T_EXPECT(!timed_out);
	T_EXPECT_EQ(probe.num_events, (size_t)2);
	T_EXPECT_EQ((int)probe.events[0], (int)MUX_EVENT_LOST);
	T_EXPECT_EQ((int)probe.events[1], (int)MUX_EVENT_CLOSED);
#endif /* WITH_THREADS */
}

/* A reload that turns reconnect off for a dialed tunnel waiting out its backoff
 * must end it and relay its CLOSED: the session is idle -- CLOSED after a
 * failed dial, or never started after a failed resolve -- so it has no
 * transition of its own left, and the owner would otherwise keep the dead
 * tunnel for good.  Pinned for both ways a reload retires a tunnel (its slot
 * dropped, or its connect address cleared) and for both idle states. */
T_DECLARE_CASE(test_tunnel_reload_retiring_idle_tunnel_relays_closed)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(srv.loop != NULL);
#if WITH_THREADS
	ev_async_init(&srv.w_async, relay_owner_async_cb);
	ev_async_start(srv.loop, &srv.w_async);
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_callbacks cbs = {
		.on_event = relay_probe_on_event,
	};
	static const struct {
		bool closed;
		bool disable_reconnect;
	} modes[] = {
		{ .closed = false, .disable_reconnect = true },
		{ .closed = false, .disable_reconnect = false },
		{ .closed = true, .disable_reconnect = true },
		{ .closed = true, .disable_reconnect = false },
	};
	struct relay_probe probes[ARRAY_SIZE(modes)];
	bool in_backoff[ARRAY_SIZE(modes)];
	size_t before[ARRAY_SIZE(modes)];
	for (size_t i = 0; i < ARRAY_SIZE(modes); i++) {
		probes[i] = (struct relay_probe){ .num_events = 0 };
		const struct tunnel_opts opts = {
			.cb = &cbs,
			.data = &probes[i],
			.mux_conf = &g_conf,
			.mux_socket = g_mux_socket,
			.local_socket = g_local_socket,
			.fd = -1,
			.id = g_zero_id,
			.connect_addr = "invalid",
			.cnt = &cnts,
		};
		struct tunnel *const t = tunnel_new(&ctx, &opts);
		T_CHECK(t != NULL);
		/* The failed resolve leaves the session unstarted and arms the
		 * backoff timer. */
		tunnel_initial_connect_task(t);
		if (modes[i].closed) {
			/* A close while reconnect is on stays local and re-arms
			 * the backoff, as a failed dial's does. */
			mux_shutdown(t->ss);
		}
		in_backoff[i] = ev_is_active(&t->w_reconnect) &&
				(mux_state(t->ss) == MUX_STATE_CLOSED) ==
					modes[i].closed;
		before[i] = probes[i].num_events;

		struct reload_arg *const reload = calloc(1, sizeof(*reload));
		T_CHECK(reload != NULL);
		*reload = (struct reload_arg){
			.t = t,
			.ss = t->ss,
			.conf = g_conf,
			.mux_socket = g_mux_socket,
			.local_socket = g_local_socket,
			.disable_reconnect = modes[i].disable_reconnect,
			.update_connect_addr = !modes[i].disable_reconnect,
		};
		reload_task(reload);
#if WITH_THREADS
		dispatcher_tick(srv.disp);
#endif
		tunnel_close(t);
	}

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
	ev_async_stop(srv.loop, &srv.w_async);
#endif
	ev_loop_destroy(srv.loop);

	for (size_t i = 0; i < ARRAY_SIZE(modes); i++) {
		T_EXPECT(in_backoff[i]);
		T_EXPECT_EQ(before[i], (size_t)0);
		T_EXPECT_EQ(probes[i].num_events, (size_t)1);
		T_EXPECT_EQ((int)probes[i].events[0], (int)MUX_EVENT_CLOSED);
	}
}

/* Fires when the tunnel's loop has had its chance to run what was due. */
static void retire_guard_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	(void)loop;
	(void)revents;
	*(bool *)w->data = true;
}

/* A dialed tunnel a reload retires can never resume again: only the dialing
 * side resumes, and it no longer dials.  So a session left suspended must be
 * ended and its CLOSED relayed, or the owner holds the dead tunnel until
 * resume_timeout -- for good when that is 0, as g_conf leaves it.  Three ways
 * a retired session ends up suspended with no backoff armed to find it: an
 * on-demand tunnel whose transport was lost (it waits for demand, not a
 * timer), a resume attempt in flight at the reload that then fails, and a
 * session live at the reload (draining) that then loses its transport.  The
 * first must end at the reload itself; the others once they suspend, from
 * the loop rather than inside the session's own transition.  Each is pinned
 * for both ways a reload retires a tunnel. */
T_DECLARE_CASE(test_tunnel_reload_retiring_suspended_tunnel_relays_closed)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(srv.loop != NULL);
#if WITH_THREADS
	ev_async_init(&srv.w_async, relay_owner_async_cb);
	ev_async_start(srv.loop, &srv.w_async);
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);
#endif

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_callbacks cbs = {
		.on_event = relay_probe_on_event,
	};
	enum retire_at {
		RETIRE_SUSPENDED, /* on-demand, suspended with no transport */
		RETIRE_IN_FLIGHT, /* a resume attempt that then fails */
		RETIRE_LIVE, /* established, then its transport is lost */
	};
	static const struct {
		enum retire_at at;
		bool disable_reconnect;
	} modes[] = {
		{ .at = RETIRE_SUSPENDED, .disable_reconnect = true },
		{ .at = RETIRE_SUSPENDED, .disable_reconnect = false },
		{ .at = RETIRE_IN_FLIGHT, .disable_reconnect = true },
		{ .at = RETIRE_IN_FLIGHT, .disable_reconnect = false },
		{ .at = RETIRE_LIVE, .disable_reconnect = true },
		{ .at = RETIRE_LIVE, .disable_reconnect = false },
	};
	struct relay_probe probes[ARRAY_SIZE(modes)];
	size_t at_reload[ARRAY_SIZE(modes)];
	size_t at_failure[ARRAY_SIZE(modes)];
	enum mux_state end_state[ARRAY_SIZE(modes)];
	bool timed_out[ARRAY_SIZE(modes)];
	for (size_t i = 0; i < ARRAY_SIZE(modes); i++) {
		probes[i] = (struct relay_probe){ .num_events = 0 };
		struct mux_session_config conf = g_conf;
		conf.idle_timeout = (modes[i].at == RETIRE_SUSPENDED) ? 1 : 0;
		if (modes[i].at == RETIRE_LIVE) {
			/* An established session arms these on reload; this
			 * one has no peer to keep alive. */
			conf.timeout = 0;
			conf.keepalive = 0;
		}
		const struct tunnel_opts opts = {
			.cb = &cbs,
			.data = &probes[i],
			.mux_conf = &conf,
			.mux_socket = g_mux_socket,
			.local_socket = g_local_socket,
			.fd = -1,
			.id = g_zero_id,
			.connect_addr = "invalid",
			.cnt = &cnts,
		};
		/* Never started: the session is this thread's alone, so its
		 * states can be set directly. */
		struct tunnel *const t = tunnel_new(&ctx, &opts);
		T_CHECK(t != NULL);
		int sp[2];
		T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
		switch (modes[i].at) {
		case RETIRE_SUSPENDED:
			t->ss->state = SESSION_SUSPENDED;
			PUB_STORE(t->ss->_pub_state, SESSION_SUSPENDED);
			break;
		case RETIRE_IN_FLIGHT:
			/* A resume attempt: its transport is attached. */
			t->ss->w_socket.fd = sp[0];
			t->ss->state = SESSION_CONNECT;
			PUB_STORE(t->ss->_pub_state, SESSION_CONNECT);
			break;
		case RETIRE_LIVE:
			t->ss->w_socket.fd = sp[0];
			t->ss->state = SESSION_ESTABLISHED;
			PUB_STORE(t->ss->_pub_state, SESSION_ESTABLISHED);
			break;
		}

		struct reload_arg *const reload = calloc(1, sizeof(*reload));
		T_CHECK(reload != NULL);
		*reload = (struct reload_arg){
			.t = t,
			.ss = t->ss,
			.conf = conf,
			.mux_socket = g_mux_socket,
			.local_socket = g_local_socket,
			.disable_reconnect = modes[i].disable_reconnect,
			.update_connect_addr = !modes[i].disable_reconnect,
		};
		reload_task(reload);
#if WITH_THREADS
		dispatcher_tick(srv.disp);
#endif
		at_reload[i] = probes[i].num_events;

		if (modes[i].at != RETIRE_SUSPENDED) {
			/* The attempt fails, or the live transport is lost, and
			 * the session (re-)suspends, as mux_session_suspend()
			 * leaves it. */
			t->ss->w_socket.fd = -1;
			t->ss->state = SESSION_SUSPENDED;
			PUB_STORE(t->ss->_pub_state, SESSION_SUSPENDED);
			if (modes[i].at == RETIRE_IN_FLIGHT) {
				tunnel_on_event(
					t, t->ss, MUX_EVENT_CONNECT_FAILED,
					(union mux_event_data){
						.connect_failed.err =
							ECONNREFUSED });
			} else {
				tunnel_on_event(
					t, t->ss, MUX_EVENT_SUSPENDED,
					(union mux_event_data){ 0 });
			}
#if WITH_THREADS
			dispatcher_tick(srv.disp);
#endif
		}
		at_failure[i] = probes[i].num_events;

		/* Give the tunnel's loop its turn at whatever came due. */
		timed_out[i] = false;
		ev_timer guard;
		ev_timer_init(&guard, retire_guard_cb, 0.5, 0.0);
		guard.data = &timed_out[i];
		ev_timer_start(t->loop, &guard);
		while (!timed_out[i] && probes[i].num_events == 0) {
			ev_run(t->loop, EVRUN_ONCE);
#if WITH_THREADS
			dispatcher_tick(srv.disp);
#endif
		}
		ev_timer_stop(t->loop, &guard);
		end_state[i] = mux_state(t->ss);

		if (end_state[i] != MUX_STATE_CLOSED) {
			t->ss->state = SESSION_CLOSED;
			PUB_STORE(t->ss->_pub_state, SESSION_CLOSED);
		}
		tunnel_close(t);
		(void)close(sp[0]);
		(void)close(sp[1]);
	}

#if WITH_THREADS
	dispatcher_destroy(srv.disp);
	ev_async_stop(srv.loop, &srv.w_async);
#endif
	ev_loop_destroy(srv.loop);

	for (size_t i = 0; i < ARRAY_SIZE(modes); i++) {
		T_LOGF("mode %zu: at_reload=%zu at_failure=%zu events=%zu "
		       "state=%d timed_out=%d",
		       i, at_reload[i], at_failure[i], probes[i].num_events,
		       (int)end_state[i], timed_out[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(modes); i++) {
		if (modes[i].at != RETIRE_SUSPENDED) {
			/* Neither the reload nor the suspending event itself
			 * ends it: the transport was attached, and the end is
			 * deferred. */
			T_EXPECT_EQ(at_reload[i], (size_t)0);
			T_EXPECT_EQ(at_failure[i], (size_t)0);
		} else {
			T_EXPECT_EQ(at_reload[i], (size_t)1);
		}
		T_EXPECT(!timed_out[i]);
		T_EXPECT_EQ(end_state[i], MUX_STATE_CLOSED);
		T_EXPECT_EQ(probes[i].num_events, (size_t)1);
		T_EXPECT_EQ((int)probes[i].events[0], (int)MUX_EVENT_CLOSED);
	}
}

#if WITH_THREADS
/* Stands in for the owner's PSK table, which the tunnel only ever sees as an
 * opaque resolver context: it counts the holds handed back through it. */
struct psk_hold_probe {
	size_t releases;
};

static const char *psk_probe_identity_of(void *ctx, const char *label)
{
	(void)ctx;
	(void)label;
	return NULL;
}

static void psk_probe_release(void *ctx)
{
	((struct psk_hold_probe *)ctx)->releases++;
}
#endif /* WITH_THREADS */

T_DECLARE_CASE(test_tunnel_psk_dispatch_holds_resolver_until_adopted)
{
#if !WITH_THREADS
	(void)_t_;
	/* Without threads a dispatch runs inline, so it is never queued and the
	 * window this pins does not exist. */
	T_SKIPNOW();
#else
	/* A repoint the tunnel has been sent but not yet run names the resolver
	 * while the tunnel itself still reports the previous one, so asking the
	 * tunnel is not enough to tell whether the resolver has a reader left: the
	 * dispatch must hold it, and give the hold back only once the tunnel
	 * reports it.  Pre-fix the dispatch carried no hold, so an owner that
	 * freed on the tunnel's answer alone freed a table this dispatch was about
	 * to install. */
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "invalid",
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* Queued with no thread to run it yet. */
	struct psk_hold_probe probe = { 0 };
	T_CHECK(tunnel_set_psk(
		t, psk_probe_identity_of, &probe, psk_probe_release));
	const size_t releases_queued = probe.releases;

	/* The thread drains the ring in order and tunnel_close() queues its
	 * teardown behind the repoint, so the join it performs orders the count
	 * read below after the repoint has run. */
	T_CHECK(tunnel_start(t));
	tunnel_close(t);
	const size_t releases_adopted = probe.releases;

	dispatcher_destroy(srv.disp);

	/* Held for as long as the dispatch is queued... */
	T_EXPECT_EQ(releases_queued, (size_t)0);
	/* ...and handed back once the tunnel has the resolver itself. */
	T_EXPECT_EQ(releases_adopted, (size_t)1);
#endif /* WITH_THREADS */
}

T_DECLARE_CASE(test_tunnel_psk_dispatch_returns_hold_when_dropped)
{
#if !WITH_THREADS
	(void)_t_;
	/* Without threads a dispatch runs inline and cannot be refused. */
	T_SKIPNOW();
#else
	/* A dispatch the ring refuses must give its hold back rather than take it
	 * along: the owner is left holding the resolver on the tunnel's behalf
	 * forever otherwise.  Nothing drains an unstarted tunnel's ring, so fill
	 * it exactly with dispatches that carry no heap payload -- the ones left
	 * queued at close are discarded, and only a payload-free one can be. */
	enum { RING_CAPACITY = 16 };
	struct server srv;
	memset(&srv, 0, sizeof(srv));

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	int tpair[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, tpair) == 0);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = tpair[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	(void)close(tpair[1]);

	for (int i = 0; i < RING_CAPACITY; i++) {
		tunnel_drop_transport(t);
	}
	struct psk_hold_probe probe = { 0 };
	const bool queued = tunnel_set_psk(
		t, psk_probe_identity_of, &probe, psk_probe_release);
	const size_t releases = probe.releases;

	tunnel_close(t);

	/* The ring was full, so the repoint never reached the tunnel.  A failure
	 * here means the ring grew past RING_CAPACITY, not that the dispatch was
	 * accepted when it should not have been. */
	T_EXPECT(!queued);
	/* The hold went back to the caller rather than with the dispatch. */
	T_EXPECT_EQ(releases, (size_t)1);
#endif /* WITH_THREADS */
}

/* An identity rejection names the transport it happened on.  On a dialed
 * tunnel the check also runs client-side, on the ServerHello, before the
 * session is established -- when the tunnel's published fd is still the -1 it
 * was created with (or, after a reconnect, the previous transport's, possibly
 * already reused).  The record must carry the live transport's fd and the
 * tunnel tag, like every other record of this session. */
T_DECLARE_CASE(test_tunnel_verify_identity_logs_live_transport)
{
	struct sockaddr_in laddr;
	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(lfd >= 0);
	T_CHECK(bind(lfd, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	T_CHECK(listen(lfd, 1) == 0);
	socklen_t laddrlen = sizeof(laddr);
	T_CHECK(getsockname(lfd, (struct sockaddr *)&laddr, &laddrlen) == 0);
	char connect_addr[32];
	(void)snprintf(
		connect_addr, sizeof(connect_addr), "127.0.0.1:%" PRIu16,
		ntohs(laddr.sin_port));

	struct server srv;
	memset(&srv, 0, sizeof(srv));
#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	/* identity.verify on a plaintext session: the check fails closed (or,
	 * built without TLS, cannot run at all) and logs the rejection. */
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = connect_addr,
		.verify_identity = true,
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* Never started, so the dial runs here rather than on a tunnel thread;
	 * the handshake never has to progress for the check to be reached. */
	int err;
	const bool dialed = tunnel_do_connect(t, &err);
	const int live_fd = mux_fd(t->ss);
	char tag[TUNNEL_TAG_SIZE];
	(void)memcpy(tag, t->tag, sizeof(tag));

	struct log_capture cap = { 0 };
	log_capture_start(&cap);
	const bool accepted = tunnel_on_verify_identity(t, t->ss, "alice");
	log_capture_stop();

	tunnel_close(t);
	(void)close(lfd);
#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT(dialed);
	T_EXPECT(live_fd >= 0);
	T_EXPECT(!accepted);
	char want[TUNNEL_TAG_SIZE + 64];
	(void)snprintf(
		want, sizeof(want),
		"%s: [fd:%d] identity \"alice\" cannot be verified", tag,
		live_fd);
	T_EXPECT(!cap.overflow);
	T_EXPECT(strstr(cap.buf, want) != NULL);
	T_EXPECT(strstr(cap.buf, "[fd:-1]") == NULL);
}

/* A resume refused for an identity mismatch is logged from the transient
 * session's own thread, so it carries that session's tag and transport fd. */
T_DECLARE_CASE(test_tunnel_resume_identity_mismatch_logs_tag)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));
#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	int old_fds[2];
	int new_fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, old_fds) == 0);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, new_fds) == 0);

	const struct tunnel_opts old_opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = old_fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const old_t = tunnel_new(&ctx, &old_opts);
	T_CHECK(old_t != NULL);
	const struct tunnel_opts new_opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = new_fds[0],
		.id = g_zero_id,
		.verify_identity = true,
		.cnt = &cnts,
	};
	struct tunnel *const new_t = tunnel_new(&ctx, &new_opts);
	T_CHECK(new_t != NULL);

	/* The resuming peer claims an identity the suspended session never
	 * carried. */
	new_t->ss->handshake.peer_identity = strdup("alice");
	T_CHECK(new_t->ss->handshake.peer_identity != NULL);
	const int live_fd = mux_fd(new_t->ss);
	char tag[TUNNEL_TAG_SIZE];
	(void)memcpy(tag, new_t->tag, sizeof(tag));

	struct log_capture cap = { 0 };
	log_capture_start(&cap);
	const bool ok = tunnel_resume_identity_ok(new_t, new_t->ss, old_t);
	log_capture_stop();

	tunnel_close(new_t);
	tunnel_close(old_t);
	(void)close(old_fds[1]);
	(void)close(new_fds[1]);
#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT(!ok);
	char want[TUNNEL_TAG_SIZE + 64];
	(void)snprintf(
		want, sizeof(want), "%s: [fd:%d] resume rejected", tag,
		live_fd);
	T_EXPECT(!cap.overflow);
	T_EXPECT(strstr(cap.buf, want) != NULL);
}

/* Stands in for a PSK table: its presence alone puts a tunnel in PSK mode.
 * The resume check never calls it, the claim having been bound to the PSK
 * label at hello time. */
static const char *test_psk_identity_none(void *ctx, const char *label)
{
	(void)ctx;
	(void)label;
	return NULL;
}

/* Sets the identity new_t's transport claims and the one old_t's suspended
 * session published, NULL meaning none.  False on OOM. */
static bool test_set_resume_identities(
	struct tunnel *restrict new_t, struct tunnel *restrict old_t,
	const char *restrict claimed, const char *restrict resumed)
{
	struct mux_session *const restrict ss = new_t->ss;
	free(ss->handshake.peer_identity);
	ss->handshake.peer_identity = claimed != NULL ? strdup(claimed) : NULL;
	free(old_t->peer_identity);
	old_t->peer_identity = resumed != NULL ? strdup(resumed) : NULL;
	tunnel_publish_pub(old_t);
	return (claimed == NULL || ss->handshake.peer_identity != NULL) &&
	       (resumed == NULL || old_t->peer_identity != NULL);
}

/* A resume must keep the session's identity continuous under either binding
 * mechanism.  PSK mode binds identity with verify_identity clear, so a check
 * keyed on verify_identity alone would let a transport that authenticated as
 * one principal resume another's session.  Equal claims, or none on either
 * side, pass; a different claim, one the session never carried, or one the
 * resume hello dropped fails.  With neither mechanism there is no identity to
 * keep, and any pairing passes. */
T_DECLARE_CASE(test_tunnel_resume_identity_continuity)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));
#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	int old_fds[2];
	int new_fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, old_fds) == 0);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, new_fds) == 0);

	const struct tunnel_opts old_opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = old_fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const old_t = tunnel_new(&ctx, &old_opts);
	T_CHECK(old_t != NULL);
	const struct tunnel_opts new_opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = new_fds[0],
		.id = g_zero_id,
		.psk_identity_of = test_psk_identity_none,
		.cnt = &cnts,
	};
	struct tunnel *const new_t = tunnel_new(&ctx, &new_opts);
	T_CHECK(new_t != NULL);
	struct mux_session *const new_ss = new_t->ss;

	/* PSK mode. */
	T_CHECK(test_set_resume_identities(new_t, old_t, "alice", "alice"));
	const bool psk_equal = tunnel_resume_identity_ok(new_t, new_ss, old_t);
	T_CHECK(test_set_resume_identities(new_t, old_t, "bob", "alice"));
	const bool psk_different =
		tunnel_resume_identity_ok(new_t, new_ss, old_t);
	T_CHECK(test_set_resume_identities(new_t, old_t, NULL, "alice"));
	const bool psk_dropped =
		tunnel_resume_identity_ok(new_t, new_ss, old_t);
	T_CHECK(test_set_resume_identities(new_t, old_t, "alice", NULL));
	const bool psk_added = tunnel_resume_identity_ok(new_t, new_ss, old_t);
	T_CHECK(test_set_resume_identities(new_t, old_t, NULL, NULL));
	const bool psk_absent = tunnel_resume_identity_ok(new_t, new_ss, old_t);

	/* Certificate mode with identity.verify. */
	new_t->psk_identity_of = NULL;
	new_t->verify_identity = true;
	T_CHECK(test_set_resume_identities(new_t, old_t, "alice", "alice"));
	const bool verify_equal =
		tunnel_resume_identity_ok(new_t, new_ss, old_t);
	T_CHECK(test_set_resume_identities(new_t, old_t, NULL, "alice"));
	const bool verify_dropped =
		tunnel_resume_identity_ok(new_t, new_ss, old_t);

	/* Neither mechanism. */
	new_t->verify_identity = false;
	T_CHECK(test_set_resume_identities(new_t, old_t, "bob", "alice"));
	const bool unbound_different =
		tunnel_resume_identity_ok(new_t, new_ss, old_t);

	tunnel_close(new_t);
	tunnel_close(old_t);
	(void)close(old_fds[1]);
	(void)close(new_fds[1]);
#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT(psk_equal);
	T_EXPECT(!psk_different);
	T_EXPECT(!psk_dropped);
	T_EXPECT(!psk_added);
	T_EXPECT(psk_absent);
	T_EXPECT(verify_equal);
	T_EXPECT(!verify_dropped);
	T_EXPECT(unbound_different);
}

/* A dialed tunnel is reused across reconnects.  When the session to a peer
 * that claimed an identity is replaced by one to a peer claiming none, the tag
 * (and its published copy) names the dialed address again rather than the
 * earlier peer's claim. */
T_DECLARE_CASE(test_tunnel_reconnect_unclaimed_peer_retags)
{
	struct server srv;
	memset(&srv, 0, sizeof(srv));
#if !WITH_THREADS
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	srv.loop = loop;
#endif
	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = -1,
		.id = g_zero_id,
		.connect_addr = "127.0.0.1:9",
		.identity = "cli",
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	/* Never started, so the connected handler runs here rather than on a
	 * tunnel thread. */
	handle_connected(
		t, t->ss,
		(union mux_event_data){ .connected.peer_identity = "alice" });
	char claimed_tag[TUNNEL_TAG_SIZE];
	(void)memcpy(claimed_tag, t->tag, sizeof(claimed_tag));
	handle_connected(
		t, t->ss,
		(union mux_event_data){ .connected.peer_identity = NULL });
	char tag[TUNNEL_TAG_SIZE];
	(void)memcpy(tag, t->tag, sizeof(tag));
	char pub_tag[TUNNEL_TAG_SIZE];
	(void)memcpy(pub_tag, t->pub.tag, sizeof(pub_tag));

	tunnel_close(t);
#if !WITH_THREADS
	ev_loop_destroy(loop);
#endif

	T_EXPECT_STREQ(claimed_tag, "cli => alice");
	T_EXPECT_STREQ(tag, "cli => 127.0.0.1:9");
	T_EXPECT_STREQ(pub_tag, "cli => 127.0.0.1:9");
}

#if WITH_THREADS
/* Parks the tunnel thread until the caller has actually tried and failed to
 * enqueue its teardown behind a full ring. Every wait has a failure deadline. */
struct ring_stall {
	struct tunnel *t;
	mtx_t mu;
	cnd_t progress;
	bool running;
	bool teardown_refused;
	bool released;
	atomic_size_t fillers_run;
};

/* Set before starting the thread, cleared after close joins it. */
static struct ring_stall *g_ring_stall;

static bool ring_probe_dispatcher_invoke(struct dispatcher *d, struct task task)
{
	const bool accepted = dispatcher_invoke(d, task);
	struct ring_stall *const st = g_ring_stall;
	if (st != NULL && d == st->t->disp &&
	    task.func == task_tunnel_teardown && !accepted) {
		THRD_CHECK(mtx_lock(&st->mu));
		st->teardown_refused = true;
		THRD_CHECK(cnd_signal(&st->progress));
		THRD_CHECK(mtx_unlock(&st->mu));
	}
	return accepted;
}

/* The caller holds mu; the predicate is protected by that same mutex. */
static void ring_stall_wait(struct ring_stall *st, const bool *ready)
{
	struct timespec deadline;
	T_CHECK(timespec_get(&deadline, TIME_UTC) == TIME_UTC);
	deadline.tv_sec += 5;
	while (!*ready) {
		THRD_CHECK(cnd_timedwait(&st->progress, &st->mu, &deadline));
	}
}

static void ring_stall_task(void *p)
{
	struct ring_stall *const restrict st = p;
	THRD_CHECK(mtx_lock(&st->mu));
	st->running = true;
	THRD_CHECK(cnd_signal(&st->progress));
	ring_stall_wait(st, &st->teardown_refused);
	st->released = true;
	THRD_CHECK(mtx_unlock(&st->mu));
}

static void ring_filler_task(void *p)
{
	struct ring_stall *const restrict st = p;
	(void)atomic_fetch_add(&st->fillers_run, 1);
}
#endif /* WITH_THREADS */

T_DECLARE_CASE(test_tunnel_close_final_waits_out_a_full_ring)
{
#if !WITH_THREADS
	(void)_t_;
	/* Without threads the teardown runs inline; there is no ring to fill. */
	T_SKIPNOW();
#else
	/* A full task ring only means the tunnel thread is behind; the close must
	 * wait for it to drain rather than give up and leave the thread running on
	 * a tunnel its owner has forgotten.  Park the started thread in one task,
	 * fill the ring behind it, and close: the close may only return once the
	 * parked task and every queued one have run and the thread is joined. */
	struct ring_stall st = { 0 };
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.disp = dispatcher_create(4);
	T_CHECK(srv.disp != NULL);

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	int tpair[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, tpair) == 0);
	const struct tunnel_opts opts = {
		.cb = &g_empty_cbs,
		.data = NULL,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = tpair[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);
	st.t = t;
	THRD_CHECK(mtx_init(&st.mu, mtx_plain));
	THRD_CHECK(cnd_init(&st.progress));
	atomic_init(&st.fillers_run, 0);
	g_ring_stall = &st;
	T_CHECK(tunnel_start(t));

	T_CHECK(tunnel_post(t, (struct task){ ring_stall_task, &st }));
	THRD_CHECK(mtx_lock(&st.mu));
	ring_stall_wait(&st, &st.running);
	THRD_CHECK(mtx_unlock(&st.mu));
	size_t filled = 0;
	while (tunnel_post(t, (struct task){ ring_filler_task, &st })) {
		filled++;
	}

	tunnel_close(t);
	g_ring_stall = NULL;
	const bool released = st.released;
	const bool teardown_refused = st.teardown_refused;
	const size_t fillers_run = atomic_load(&st.fillers_run);

	cnd_destroy(&st.progress);
	mtx_destroy(&st.mu);
	(void)close(tpair[1]);
	dispatcher_destroy(srv.disp);

	T_EXPECT(filled > 0);
	T_EXPECT(teardown_refused);
	/* The close outlasted the stall instead of abandoning the thread... */
	T_EXPECT(released);
	/* ...and the queued tasks all ran before the teardown behind them. */
	T_EXPECT_EQ(fillers_run, filled);
#endif /* WITH_THREADS */
}

#if !WITH_THREADS
struct relay_event_probe {
	size_t events;
};

static void relay_event_probe_on_event(
	void *data, struct tunnel *t, const enum mux_event event,
	const union mux_event_data edata)
{
	(void)t;
	(void)event;
	(void)edata;
	((struct relay_event_probe *)data)->events++;
}
#endif /* !WITH_THREADS */

T_DECLARE_CASE(test_tunnel_close_relays_no_event_of_its_own)
{
#if WITH_THREADS
	(void)_t_;
	/* The threads build disconnects the relay before any teardown, so no
	 * event could reach the owner through it either way. */
	T_SKIPNOW();
#else
	/* Force-closing a live session must not report its loss to the owner
	 * that is closing it: the owner has already let go of the tunnel.  Bring
	 * an accepted tunnel up against a peer session on the shared loop, then
	 * close it and count what reaches the owner's on_event. */
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	struct server srv;
	memset(&srv, 0, sizeof(srv));
	srv.loop = loop;

	const struct tunnel_session_counters cnts =
		test_make_tunnel_counters(&srv);
	const struct tunnel_context ctx = test_make_tunnel_context(&srv);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(socket_set_nonblock(fds[0]) == 0);
	T_CHECK(socket_set_nonblock(fds[1]) == 0);

	struct relay_event_probe probe = { 0 };
	const struct tunnel_callbacks cbs = {
		.on_event = relay_event_probe_on_event,
	};
	const struct tunnel_opts opts = {
		.cb = &cbs,
		.data = &probe,
		.mux_conf = &g_conf,
		.mux_socket = g_mux_socket,
		.local_socket = g_local_socket,
		.fd = fds[0],
		.id = g_zero_id,
		.cnt = &cnts,
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	T_CHECK(t != NULL);

	unsigned char peer_id[MUX_SESSION_ID_LEN];
	memset(peer_id, 0x5a, sizeof(peer_id));
	const struct mux_session_opts peer_opts = {
		.callbacks = &g_peer_mux_cbs,
		.conf = &g_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = -1,
		.id = peer_id,
		.tag = "[peer]:",
	};
	struct mux_session *const peer = mux_new(loop, &peer_opts);
	T_CHECK(peer != NULL);

	T_CHECK(tunnel_start(t));
	mux_attach_fd(peer, fds[1]);

	/* Both sessions run on this loop; the bound turns a stalled handshake
	 * into a failed check rather than a hang. */
	enum { MAX_POLLS = 1000 };
	bool established = false;
	for (int i = 0; i < MAX_POLLS && !established; i++) {
		ev_run(loop, EVRUN_NOWAIT);
		established = mux_state(peer) == MUX_STATE_ESTABLISHED &&
			      mux_state(t->ss) == MUX_STATE_ESTABLISHED;
	}

	probe.events = 0;
	tunnel_close(t);
	const size_t events = probe.events;

	mux_close(peer);
	ev_loop_destroy(loop);

	T_EXPECT(established);
	T_EXPECT_EQ(events, (size_t)0);
#endif /* WITH_THREADS */
}

static const struct testing_suite suite[] = {
	T_CASE(test_tunnel_new_close_no_start),
	T_CASE(test_tunnel_capacity_creation_failure_and_teardown),
	T_CASE(test_tunnel_capacity_failed_hello_releases_reservation),
	T_CASE(test_tunnel_resume_handoff_failure_obeys_capacity),
	T_CASE(test_tunnel_accessors_after_new),
	T_CASE(test_tunnel_resume_handoff_failure_keeps_transport),
	T_CASE(test_tunnel_resume_handoff_failure_completes_fresh_handshake),
	T_CASE(test_tunnel_reconnect_rearms_after_failed_retry),
	T_CASE(test_tunnel_reconnect_backoff_skips_fast_rungs_when_unreachable),
	T_CASE(test_tunnel_reconnect_backoff_reads_closed_event_errno),
	T_CASE(test_tunnel_reconnect_backoff_after_failed_resume_attempt),
	T_CASE(test_tunnel_on_demand_redials_after_close_in_flight),
	T_CASE(test_tunnel_reload_null_addr_disables_reconnect),
	T_CASE(test_tunnel_reconnect_count_skips_cancelled_backoff),
	T_CASE(test_tunnel_reconnect_count_includes_demand_redial),
	T_CASE(test_tunnel_reconnect_on_transport_lost),
	T_CASE(test_tunnel_reconnect_after_connect_timeout),
	T_CASE(test_tunnel_stream_connect_applies_notsent_lowat),
	T_CASE(test_tunnel_state_returns_connecting_after_new),
	T_CASE(test_tunnel_stats_initial_zero),
	T_CASE(test_tunnel_open_stream_burst_not_dropped),
	T_CASE(test_tunnel_relay_retries_events_a_full_ring_refused),
	T_CASE(test_tunnel_reload_retiring_idle_tunnel_relays_closed),
	T_CASE(test_tunnel_reload_retiring_suspended_tunnel_relays_closed),
	T_CASE(test_tunnel_psk_dispatch_holds_resolver_until_adopted),
	T_CASE(test_tunnel_psk_dispatch_returns_hold_when_dropped),
	T_CASE(test_tunnel_verify_identity_logs_live_transport),
	T_CASE(test_tunnel_resume_identity_mismatch_logs_tag),
	T_CASE(test_tunnel_resume_identity_continuity),
	T_CASE(test_tunnel_reconnect_unclaimed_peer_retags),
	T_CASE(test_tunnel_close_final_waits_out_a_full_ring),
	T_CASE(test_tunnel_close_relays_no_event_of_its_own),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
