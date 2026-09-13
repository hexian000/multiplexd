/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file server.c
 * @brief Server implementation: the listeners and their accept paths, the
 *        registry of live tunnels and the per-identity pools they are routed
 *        through, TLS/PSK credential setup, and the single-pass config reload.
 */

#include "server.h"

#include "api_server.h"
#include "conf.h"
#include "listener.h"
#include "mux/mux.h"
#include "shim/tls.h"
#include "shim/util.h"
#include "tunnel.h"
#include "udp.h"

#include "algo/hashtable.h"
#include "hash/cityhash.h"
#include "math/rand.h"
#include "meta/arraysize.h"
#include "meta/class.h"
#include "meta/minmax.h"
#include "os/clock.h"
#include "os/daemon.h"
#include "os/signal.h"
#include "os/socket.h"
#include "strings/format.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/shared_mutex.h"
#include "sync/task.h"
#endif
#include "utils/ctype_ascii.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#if WITH_THREADS
#include <stdatomic.h>
#include <threads.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

static uint_fast32_t sid_hash(const void *key, const uint_fast32_t seed)
{
	return cityhash64low_32(key, MUX_SESSION_ID_LEN, seed);
}

static bool sid_eq(const void *a, const void *b)
{
	return memcmp(a, b, MUX_SESSION_ID_LEN) == 0;
}

/* ── tunnel_context callbacks ──────────────────────────────────────────── */

#if WITH_THREADS
static bool server_post_task(void *user, struct task task)
{
	struct server *const restrict s = user;
	if (!dispatcher_invoke(s->disp, task)) {
		/* Still wake the loop: the tunnel retries a refused relay event
		 * until this drain makes room for it. */
		ev_async_send(s->loop, &s->w_async);
		return false;
	}
	ev_async_send(s->loop, &s->w_async);
	return true;
}

static void server_flush_tasks(void *user)
{
	dispatcher_tick(((struct server *)user)->disp);
}
#endif /* WITH_THREADS */

static bool server_verify_peer(void *user, const char *peer_identity)
{
	struct server *const restrict s = user;
#if WITH_THREADS
	THRD_ASSERT(smtx_sharedlock(&s->accepted_mu));
#endif
	const bool matched = table_find(s->identities, peer_identity, NULL);
#if WITH_THREADS
	THRD_ASSERT(smtx_sharedunlock(&s->accepted_mu));
#endif
	return matched;
}

static uint_least64_t server_alloc_index(void *user)
{
	return ++((struct server *)user)->next_tunnel_index;
}

static struct tunnel_session_counters
server_make_tunnel_counters(struct server *restrict s)
{
	return (struct tunnel_session_counters){
		.num_session_created = &s->counters.num_session_created,
		.num_session_connect = &s->counters.num_session_connect,
		.num_session_connected = &s->counters.num_session_connected,
		.num_session_disconnected =
			&s->counters.num_session_disconnected,
		.num_session_finalized = &s->counters.num_session_finalized,
		.num_sessions = &s->counters.num_sessions,
		.num_session_halfopen = &s->counters.num_session_halfopen,
	};
}

static bool server_reserve_session(void *user)
{
	struct server *const s = user;
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	const bool available =
		s->session_limit == 0 || s->session_slots < s->session_limit;
	if (available) {
		s->session_slots++;
	}
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
	return available;
}

static void server_release_session(void *user)
{
	struct server *const s = user;
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	ASSERT(s->session_slots > 0);
	s->session_slots--;
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
}

static struct tunnel_context
server_make_tunnel_context(struct server *restrict s)
{
	return (struct tunnel_context){
#if WITH_THREADS
		.post_task = server_post_task,
		.flush_tasks = server_flush_tasks,
#endif
		.reserve_session = server_reserve_session,
		.release_session = server_release_session,
		.verify_peer = server_verify_peer,
		.alloc_index = server_alloc_index,
		.user = s,
#if !WITH_THREADS
		.loop = s->loop,
#endif
	};
}

/* ─────────────────────────────────────────────────────────────────────── */

static const struct table_opts SESSION_TABLE_OPTS = {
	.hash = sid_hash,
	.eq = sid_eq,
	.flags = 0,
};

/* Iterate over all tunnel objects owned by a server.  Zero-initialize before
 * the first call; returns NULL when done. */
struct tunnel_iter {
	/* 0 = mux_tunnel, 1 = identities, 2 = identity_tunnels, 3 = accepted */
	size_t phase;
	/* opaque cursor for table_next (identities in phase 1, accepted in phase 3) */
	size_t sub;
	/* index within cur_sl->tunnels[] (phase 1) or identity_tunnels[] (phase 2) */
	size_t sub2;
	/* identity listener being drained (phase 1); NULL = fetch next via table_next */
	struct identity_listener *cur_sl;
};

/* True if t is already in sl's pool. Callers must check this before
 * identity_listener_add: on_established may fire more than once for the
 * same tunnel (tunnel.h: "resume rejected -> fresh session"), and adding
 * a duplicate leaves two entries pointing at the same tunnel; removal
 * only clears the first match, so the second becomes a dangling pointer
 * identity_listener_pick can return after the tunnel is freed. */
static bool identity_listener_contains(
	const struct identity_listener *restrict sl,
	const struct tunnel *restrict t)
{
	for (size_t i = 0; i < sl->num_tunnels; i++) {
		if (sl->tunnels[i] == t) {
			return true;
		}
	}
	return false;
}

/* Add tunnel t to service listener sl's pool.
 * Returns false on OOM (already logged); caller may continue. */
static bool identity_listener_add(
	struct identity_listener *restrict sl, struct tunnel *restrict t)
{
	if (sl->num_tunnels >= sl->cap_tunnels) {
		const size_t new_cap =
			sl->cap_tunnels > 0 ? sl->cap_tunnels * 2 : 4;
		struct tunnel **arr = (struct tunnel **)realloc(
			(void *)sl->tunnels, new_cap * sizeof(struct tunnel *));
		if (arr == NULL) {
			LOGOOM();
			return false;
		}
		sl->tunnels = arr;
		sl->cap_tunnels = new_cap;
	}
	sl->tunnels[sl->num_tunnels++] = t;
	return true;
}

/* Remove tunnel t from service listener sl's pool (swap-remove).
 * Returns true if the tunnel was found and removed. */
static bool identity_listener_remove(
	struct identity_listener *restrict sl, struct tunnel *restrict t)
{
	for (size_t i = 0; i < sl->num_tunnels; i++) {
		if (sl->tunnels[i] != t) {
			continue;
		}
		sl->tunnels[i] = sl->tunnels[--sl->num_tunnels];
		if (sl->rr_next >= sl->num_tunnels) {
			sl->rr_next = 0;
		}
		return true;
	}
	return false;
}

/* Drop t from every identity pool except @p keep (NULL removes it from all).
 *
 * A tunnel belongs to at most one pool: the one matching the peer identity it
 * currently announces. Re-establishment can change that identity -- a dialed
 * tunnel re-enters MUX_EVENT_ESTABLISHED on every fresh reconnect, and the peer
 * may claim something else by then -- so the stale membership has to go, or the
 * old pool keeps round-robining connections to a tunnel that is no longer its
 * peer and, once the tunnel is closed and freed, to freed memory. */
/* keep is deliberately not restrict: it always points into srv->identities, so
 * it aliases what the walk below reaches through srv. */
static void identity_pools_remove_except(
	struct server *restrict srv, struct tunnel *restrict t,
	const struct identity_listener *keep)
{
	size_t cursor = 0;
	void *elem;
	while (table_next(srv->identities, &cursor, NULL, &elem)) {
		if (elem == keep) {
			continue;
		}
		(void)identity_listener_remove(elem, t);
	}
}

/* Drop every lossymux route to t, a tunnel about to be freed. */
static void
server_udp_forget(struct server *restrict srv, const struct tunnel *restrict t)
{
	if (srv->udp_local != NULL) {
		udp_listener_forget(srv->udp_local, t);
	}
	size_t cursor = 0;
	void *elem;
	while (table_next(srv->identities, &cursor, NULL, &elem)) {
		const struct identity_listener *const restrict sl = elem;
		if (sl->udp != NULL) {
			udp_listener_forget(sl->udp, t);
		}
	}
}

/* Pick the next tunnel from sl's pool by round-robin, skipping any that cannot
 * carry a stream right now: a pooled tunnel stays in the pool through reconnect
 * backoff and suspension, and an open handed to one is closed.  One lap from
 * the cursor finds the first established tunnel; only when none is does the
 * plain round-robin pick stand, so an on-demand tunnel still receives the open
 * that redials it.  Returns NULL when the pool is empty. */
static struct tunnel *
identity_listener_pick(struct identity_listener *restrict sl)
{
	const size_t n = sl->num_tunnels;
	if (n == 0) {
		return NULL;
	}
	if (sl->rr_next >= n) {
		sl->rr_next = 0;
	}
	size_t pick = sl->rr_next;
	for (size_t i = 0; i < n; i++) {
		const size_t idx = (sl->rr_next + i) % n;
		if (tunnel_state(sl->tunnels[idx]) == MUX_STATE_ESTABLISHED) {
			pick = idx;
			break;
		}
	}
	sl->rr_next = (pick + 1) % n;
	return sl->tunnels[pick];
}

/* Close t and fold its monotonic counters into the server-wide base (see struct
 * server_counters' "closed" note).  tunnel_close_final() samples them after the
 * tunnel thread is joined, so the increments teardown itself makes -- one
 * num_stream_failed per stream still open -- are folded too; a tunnel_stats()
 * taken before the close would drop every one of them.  Gauges are excluded:
 * the closing session drains them to zero, so a fold would leave the totals
 * permanently overstated.  Server-thread only, as is server_stats(), so the two
 * never interleave.
 *
 * srv is not restrict, nor is it in any function that can reach a tunnel close:
 * tunnel_close_final()'s dispatcher flush runs other tunnels' queued relay
 * tasks, whose handlers (handle_closed, and a nested fold here) update this
 * server through each tunnel's callback_data. */
static void server_close_and_fold(struct server *srv, struct tunnel *restrict t)
{
	/* Before the close: its dispatcher flush can reenter a sweep that must
	 * already see t as gone. A no-op outside a sweep (sweep_live NULL). */
	srv->sweep_live = table_del(srv->sweep_live, t, NULL);
	server_udp_forget(srv, t);
	struct tunnel_final_counters fin;
	tunnel_close_final(t, &fin);
	struct server_counters *const restrict c = &srv->counters;
	c->closed.num_stream_opened += fin.num_stream_opened;
	c->closed.num_stream_accepted += fin.num_stream_accepted;
	c->closed.num_stream_fastopen += fin.num_stream_fastopen;
	c->closed.num_stream_established += fin.num_stream_established;
	c->closed.num_stream_succeeded += fin.num_stream_succeeded;
	c->closed.num_stream_failed += fin.num_stream_failed;
	c->closed.num_reconnects += fin.num_reconnects;
	c->closed.num_rst_sent += fin.num_rst_sent;
	c->closed.num_rst_recv += fin.num_rst_recv;
	c->closed.num_stream_errors += fin.num_stream_errors;
	c->closed.num_stream_establish_samples += fin.stream_establish_count;
	c->closed.traffic_byt_mux_recv += fin.byt_mux_recv;
	c->closed.traffic_byt_mux_sent += fin.byt_mux_sent;
	c->closed.traffic_byt_push_recv += fin.byt_push_recv;
	c->closed.traffic_byt_push_sent += fin.byt_push_sent;
	c->closed.pkt_dgram_sent += fin.pkt_dgram_sent;
	c->closed.pkt_dgram_recv += fin.pkt_dgram_recv;
	c->closed.pkt_dgram_dropped += fin.pkt_dgram_dropped;
	c->closed.byt_dgram_sent += fin.byt_dgram_sent;
	c->closed.byt_dgram_recv += fin.byt_dgram_recv;
}

/* Every accepted_tunnels mutation must hold accepted_mu exclusive against
 * server_on_resume_lookup's shared readers: table_set/table_del can rehash and
 * free, racing them otherwise. These two wrappers are the single place that
 * invariant lives. */
static void
server_accepted_del(struct server *restrict s, struct tunnel *restrict t)
{
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	s->accepted_tunnels =
		table_del(s->accepted_tunnels, tunnel_session_id(t), NULL);
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
}

/* Insert t keyed by its session id; returns table_set's prior element for the
 * key (NULL on a fresh insert, or t itself when the allocation failed). */
static void *
server_accepted_set(struct server *restrict s, struct tunnel *restrict t)
{
	void *elem = t;
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	s->accepted_tunnels =
		table_set(s->accepted_tunnels, tunnel_session_id(t), &elem);
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
	return elem;
}

static struct tunnel *tunnel_iter_next(
	const struct server *restrict s, struct tunnel_iter *restrict it)
{
	if (it->phase == 0) {
		it->phase = 1;
		if (s->mux_tunnel != NULL) {
			return s->mux_tunnel;
		}
	}
	if (it->phase == 1) {
		for (;;) {
			if (it->cur_sl != NULL) {
				if (it->sub2 < it->cur_sl->num_tunnels) {
					return it->cur_sl->tunnels[it->sub2++];
				}
				it->cur_sl = NULL;
				it->sub2 = 0;
			}
			void *elem = NULL;
			if (!table_next(s->identities, &it->sub, NULL, &elem)) {
				break;
			}
			it->cur_sl = elem;
		}
		it->phase = 2;
		/* it->sub2 == 0 after the loop above */
	}
	if (it->phase == 2) {
		while (it->sub2 < s->num_identity_tunnels) {
			struct tunnel *t = s->identity_tunnels[it->sub2++];
			if (t != NULL) {
				return t;
			}
		}
		it->phase = 3;
		it->sub = 0;
	}
	/* phase 3: accepted_tunnels */
	void *elem = NULL;
	if (table_next(s->accepted_tunnels, &it->sub, NULL, &elem)) {
		return elem;
	}
	return NULL;
}

/* True if @p t is still registered in any of the server's tunnel tables.
 * Compares pointers only and never dereferences t: the caller uses this exactly
 * when t may already have been freed by a reentrant handle_closed. O(n) in the
 * live tunnel count, so a sweep uses it only when its sweep_live set could not
 * be allocated. */
static bool server_tunnel_is_registered(
	const struct server *restrict srv, const struct tunnel *restrict t)
{
	struct tunnel_iter it = { 0 };
	for (const struct tunnel *cur = tunnel_iter_next(srv, &it); cur != NULL;
	     cur = tunnel_iter_next(srv, &it)) {
		if (cur == t) {
			return true;
		}
	}
	return false;
}

/* Start a force-close sweep over the n distinct tunnels in ts[]: publish them
 * as srv->sweep_live, from which server_close_and_fold() deletes each tunnel it
 * frees. On OOM sweep_live stays NULL and server_sweep_is_live() falls back to
 * the registry walk. */
static void server_sweep_begin(
	struct server *restrict srv, struct tunnel *const *restrict ts,
	const size_t n)
{
	ASSERT(srv->sweep_live == NULL);
	if (n == 0) {
		return;
	}
	struct hashtable *set = table_new(&TABLE_OPTS_PTR);
	if (set == NULL) {
		LOGOOM();
		return;
	}
	set = table_reserve(set, n);
	for (size_t i = 0; i < n; i++) {
		/* ts[] is distinct, so a non-NULL elem back is an OOM. */
		void *elem = ts[i];
		set = table_set(set, ts[i], &elem);
		if (elem != NULL) {
			LOGOOM();
			table_free(set);
			return;
		}
	}
	srv->sweep_live = set;
}

/* End the sweep server_sweep_begin() started. */
static void server_sweep_end(struct server *restrict srv)
{
	table_free(srv->sweep_live);
	srv->sweep_live = NULL;
}

/* True if the running sweep has not seen @p t freed. Compares pointers only and
 * never dereferences t, which may already be freed. Without a sweep_live set
 * (OOM) it asks server_tunnel_is_registered() instead -- the same answer at O(n)
 * per call: every live sweep entry is also registered in some table, and
 * handle_closed unregisters a tunnel from all of them before freeing it. */
static bool server_sweep_is_live(
	const struct server *restrict srv, const struct tunnel *restrict t)
{
	if (srv->sweep_live != NULL) {
		return table_find(srv->sweep_live, t, NULL);
	}
	return server_tunnel_is_registered(srv, t);
}

/* Stop sl's listener and close every tunnel in its pool, then free it.
 * Used by a config reload on every listener that leaves the identity table:
 * a peer the new config removed, whose pooled sessions are closed at once
 * rather than drained, and a listener created for a reload that is then
 * rejected (its pool is still empty). Once s->identities no longer holds sl,
 * it is unreachable via tunnel_iter/handle_closed pool removal, so its
 * listener and tunnels must be torn down explicitly here instead of
 * leaking as a "ghost" that keeps serving into a pool nothing can find
 * anymore. A pooled tunnel can also be live in srv->accepted_tunnels or be
 * srv->mux_tunnel (server_on_established wires it into both without
 * unregistering either), so each is unregistered here too -- mirroring
 * handle_closed's full removal scope -- before the tunnel is closed and freed;
 * otherwise a stale pointer would survive in a table a resume lookup or
 * tcp_serve still consults. */
static void identity_listener_discard(
	struct server *srv, struct identity_listener *restrict sl)
{
	listener_stop(&sl->listener, srv->loop);
	udp_listener_free(sl->udp);
	sl->udp = NULL;
	/* A pool holds each tunnel once (identity_listener_add is guarded by
	 * identity_listener_contains), so tunnels[] is a valid sweep set. */
	server_sweep_begin(srv, sl->tunnels, sl->num_tunnels);
	for (size_t j = 0; j < sl->num_tunnels; j++) {
		struct tunnel *const t = sl->tunnels[j];
		/* Closing an earlier member flushes the shared dispatcher
		 * (tunnel_close_final's epilogue drains the whole queue), which
		 * can run another tunnel's queued MUX_EVENT_CLOSED through
		 * handle_closed and free it. That path cannot purge this pool --
		 * sl is already out of srv->identities, so
		 * identity_pools_remove_except never reaches it -- leaving a
		 * dangling entry here. Re-validate by pointer before touching t:
		 * the fold that freed it also dropped it from sweep_live. */
		if (!server_sweep_is_live(srv, t)) {
			continue;
		}
		if (tunnel_is_accepted(t)) {
			server_accepted_del(srv, t);
		} else if (t == srv->mux_tunnel) {
			srv->mux_tunnel = NULL;
		}
		for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
			if (srv->identity_tunnels[i] == t) {
				srv->identity_tunnels[i] = NULL;
				break;
			}
		}
		server_close_and_fold(srv, t);
	}
	server_sweep_end(srv);
	free((void *)sl->tunnels);
	free(sl);
}

/* Upper bound on the distinct tunnels server_snapshot_tunnels() can yield, for
 * sizing its output buffer: the one dialed mux_tunnel (the +1), every
 * identity_listener's whole tunnels[] pool (round-robin, more than one tunnel
 * per peer -- so the sum of num_tunnels, not table_size(identities)), every
 * identity_tunnels[] slot, and every accepted session. Counting every phase
 * at its full size (the +1 and each slot even when NULL) makes this at least
 * the raw yield count of tunnel_iter_next(), duplicates included, so every
 * snapshot call site must size its buffer from this one function, never from
 * a copy of the sum. The count is a size_t sized from the live tables; the
 * live tunnel count is unbounded in principle (max_sessions defaults to
 * unlimited and accepts values above any fixed cap), so this imposes no
 * arbitrary ceiling of its own. */
static size_t server_snapshot_cap(const struct server *restrict s)
{
	size_t identity_pool_tunnels = 0;
	size_t cursor = 0;
	void *elem;
	while (table_next(s->identities, &cursor, NULL, &elem)) {
		const struct identity_listener *const restrict sl = elem;
		identity_pool_tunnels += sl->num_tunnels;
	}
	return (s->accepted_tunnels != NULL ? table_size(s->accepted_tunnels) :
					      0) +
	       1 + identity_pool_tunnels + s->num_identity_tunnels;
}

/* Total order on tunnel pointers for the snapshot dedup. Compares the
 * converted uintptr_t values -- relational operators on pointers into distinct
 * objects are not well defined, but the integer conversions are. */
static int cmp_tunnel_ptr(const void *a, const void *b)
{
	const uintptr_t va = (uintptr_t)*(struct tunnel *const *)a;
	const uintptr_t vb = (uintptr_t)*(struct tunnel *const *)b;
	return (va > vb) - (va < vb);
}

/* Snapshot every distinct tunnel (accepted + identity-pooled), deduped since
 * tunnel_iter yields a pooled tunnel a second time via its identity_tunnels
 * slot or accepted_tunnels. cap must be at least the caller's precomputed upper
 * bound -- which is at least the raw yield count (it sums every phase's full
 * size), so the with-duplicates sequence collected below always fits.
 *
 * Collect the raw sequence, then sort-and-dedup by pointer: O(n log n) on the
 * server loop, and robust to any yield multiplicity without depending on which
 * phases can overlap. */
static size_t server_snapshot_tunnels(
	struct server *restrict s, struct tunnel **restrict out,
	const size_t cap)
{
	size_t count = 0;
	struct tunnel_iter it = { 0 };
	struct tunnel *t;
	while ((t = tunnel_iter_next(s, &it)) != NULL) {
		ASSERT(count < cap);
		if (count >= cap) {
			/* Cannot happen: cap is derived from the same live tables
			 * just before the snapshot. Guard anyway against a future
			 * sizing mistake becoming a buffer overflow. */
			break;
		}
		out[count++] = t;
	}
	qsort((void *)out, count, sizeof(struct tunnel *), cmp_tunnel_ptr);
	size_t distinct = 0;
	for (size_t i = 0; i < count; i++) {
		if (i == 0 || out[i] != out[i - 1]) {
			out[distinct++] = out[i];
		}
	}
	return distinct;
}

/* Log session establishment/close with peer address formatting. The identity is
 * peer-supplied and the event log is rendered verbatim into the /stats body, so
 * it is escaped before it goes in. */
#define SESSION_EVLOGF(srv, t, fmt, ...)                                       \
	do {                                                                   \
		char id_buf_[256];                                             \
		const char *id_ = tunnel_peer_identity_copy(                   \
					  (t), id_buf_, sizeof(id_buf_)) ?     \
					  id_buf_ :                            \
					  NULL;                                \
		if (id_ != NULL) {                                             \
			char id_esc_[IDENTITY_ESCAPED_MAX];                    \
			escape_identity(                                       \
				id_esc_, sizeof(id_esc_), id_, ESCAPE_PLAIN);  \
			server_evlogf(                                         \
				(srv), "`%s' " fmt, id_esc_, __VA_ARGS__);     \
			break;                                                 \
		}                                                              \
		union sockaddr_max peer_;                                      \
		if (tunnel_peer_addr_copy(t, &peer_.sa, sizeof(peer_))) {      \
			char addr_str[72];                                     \
			(void)sa_format(                                       \
				addr_str, sizeof(addr_str), &peer_.sa);        \
			server_evlogf(                                         \
				(srv), "%s " fmt, addr_str, __VA_ARGS__);      \
			break;                                                 \
		}                                                              \
		server_evlogf(                                                 \
			(srv), "[fd:%d] " fmt, tunnel_fd(t), __VA_ARGS__);     \
	} while (0)
#define SESSION_EVLOG(srv, t, message) SESSION_EVLOGF(srv, t, "%s", message)

static void
server_evlogf(struct server *restrict srv, const char *restrict fmt, ...)
{
	struct server_evlog *const restrict evlog = &srv->evlog;
	const size_t evlog_size = ARRAY_SIZE(evlog->entries);
	const time_t now = time(NULL);

	/* Format into a local buffer first: entries[pos] is the oldest still-live
	 * entry when the ring is full, and formatting straight into it (then
	 * merging into the previous entry and returning) would corrupt it -- new
	 * message text paired with a stale timestamp/count -- until it is
	 * naturally evicted. */
	char message[sizeof(evlog->entries[0].message)] = { 0 };
	va_list ap;
	va_start(ap, fmt);
	const int fmtlen = vsnprintf(message, sizeof(message), fmt, ap);
	va_end(ap);
	if (fmtlen < 0) {
		message[0] = '\0';
	}

	/* Merge into the previous entry if the message is identical. */
	if (evlog->len > 0) {
		const size_t prev = (evlog->pos + evlog_size - 1) % evlog_size;
		struct server_evlog_entry *const restrict last =
			&evlog->entries[prev];
		if (strncmp(last->message, message, sizeof(last->message)) ==
		    0) {
			last->timestamp = now;
			last->count++;
			return;
		}
	}

	struct server_evlog_entry *const restrict entry =
		&evlog->entries[evlog->pos];
	memcpy(entry->message, message, sizeof(entry->message));
	entry->timestamp = now;
	entry->count = 1;
	evlog->pos = (evlog->pos + 1) % evlog_size;
	if (evlog->len < evlog_size) {
		evlog->len++;
	}
}

static void session_on_connected(
	struct server *restrict srv, struct tunnel *t,
	const char *restrict verb, int_fast64_t lat_ns)
{
	char lat_str[16];
	(void)format_duration(
		lat_str, sizeof(lat_str), make_duration_nanos(lat_ns));
	SESSION_EVLOGF(srv, t, "session %s (setup: %s)", verb, lat_str);
}

/* Establishment and resumption both publish a peer claim before this runs.
 * Keep the tunnel in exactly its current claim's pool, including when an
 * unbound resumed session changes its claim. Dial-out staging slots remain
 * populated for the tunnel's whole lifetime, independently of pool membership. */
static void server_update_identity_pool(
	struct server *restrict srv, struct tunnel *restrict t)
{
	char peer_id_buf[256];
	const char *const peer_id =
		tunnel_peer_identity_copy(t, peer_id_buf, sizeof(peer_id_buf)) ?
			peer_id_buf :
			NULL;
	struct identity_listener *sl = NULL;
	void *elem;
	if (peer_id != NULL && table_find(srv->identities, peer_id, &elem)) {
		sl = elem;
	}
	identity_pools_remove_except(srv, t, sl);
	if (sl == NULL) {
		/* Plain mux_connect needs no identity pool. An identity dial-out
		 * without a matching listener stays reachable through its slot. */
		if (!tunnel_is_accepted(t) && t != srv->mux_tunnel) {
			char esc[IDENTITY_ESCAPED_MAX];
			const char *shown = "(none)";
			if (peer_id != NULL) {
				escape_identity(
					esc, sizeof(esc), peer_id,
					ESCAPE_PLAIN);
				shown = esc;
			}
			LOGW_F("[fd:%d] dialed session identity \"%s\" matches"
			       " no configured identity.listen entry; tunnel"
			       " stays reachable only through its staging slot",
			       tunnel_fd(t), shown);
		}
		return;
	}
	if (!identity_listener_contains(sl, t)) {
		/* OOM leaves it reachable through its slot or accepted registry;
		 * a later establishment or resumption retries the pool add. */
		(void)identity_listener_add(sl, t);
	}
}

static void server_on_established(
	void *data, struct tunnel *restrict t, int_fast64_t lat_ns)
{
	struct server *const restrict srv = data;
	LOGN_F("[fd:%d] %s session established", tunnel_fd(t),
	       tunnel_is_accepted(t) ? "server" : "client");
	session_on_connected(srv, t, "established", lat_ns);
	server_update_identity_pool(srv, t);
}

static void
server_on_resumed(void *data, struct tunnel *restrict t, int_fast64_t lat_ns)
{
	struct server *const restrict srv = data;
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session resumed", tunnel_fd(t),
	       is_server ? "server" : "client");
	session_on_connected(srv, t, "resumed", lat_ns);
	server_update_identity_pool(srv, t);
}

static void
handle_disconnected(struct server *restrict srv, struct tunnel *restrict t)
{
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session disconnected", tunnel_fd(t),
	       is_server ? "server" : "client");
	SESSION_EVLOG(srv, t, "session disconnected");
}

/* Unregister t from every pool it may be live in -- accepted_tunnels, the
 * mux_tunnel slot, the identity listener pools, and the identity_tunnels[]
 * staging array -- then fold its traffic into the server counters and close it
 * (tunnel_close joins the tunnel thread). Shared by handle_closed and the
 * force-close sweep; identity_listener_discard and server_force_close_snapshot
 * deliberately cover a narrower scope and stay separate. */
static void
server_remove_and_close_tunnel(struct server *srv, struct tunnel *restrict t)
{
	if (tunnel_is_accepted(t)) {
		server_accepted_del(srv, t);
	} else if (t == srv->mux_tunnel) {
		srv->mux_tunnel = NULL;
	}
	/* Every pool, not just the first match: server_force_close_one_by_one()
	 * rescans from scratch after each call and would otherwise find t again
	 * through a pool this missed, closing an already-freed tunnel. */
	identity_pools_remove_except(srv, t, NULL);
	for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
		if (srv->identity_tunnels[i] == t) {
			srv->identity_tunnels[i] = NULL;
			break;
		}
	}
	server_close_and_fold(srv, t);
}

/* True if any session is still draining: an identity listener pool with a live
 * tunnel, or an identity.mux_connect dial-out occupying an identity_tunnels[]
 * staging slot (non-NULL for a live dial-out's whole lifetime, handshaking or
 * established). The graceful-shutdown "can we exit now?" checks combine this
 * with their own accepted_tunnels/mux_tunnel guards. */
static bool server_has_live_peer(const struct server *restrict s)
{
	size_t cursor = 0;
	void *elem;
	while (table_next(s->identities, &cursor, NULL, &elem)) {
		if (((const struct identity_listener *)elem)->num_tunnels > 0) {
			return true;
		}
	}
	for (size_t i = 0; i < s->num_identity_tunnels; i++) {
		if (s->identity_tunnels[i] != NULL) {
			return true;
		}
	}
	return false;
}

/* Arm the maintenance tick.  Every site that leaves deferred work behind calls
 * this; the tick itself stops once a pass finds nothing left, so between them
 * an idle server holds no timer at all.  A no-op while shutting down, where the
 * watcher is the force-exit deadline instead. */
static void server_maintenance_kick(struct server *restrict srv)
{
	if (srv->shutting_down || ev_is_active(&srv->w_maintenance)) {
		return;
	}
	ev_timer_again(srv->loop, &srv->w_maintenance);
}

static void handle_closed(
	struct server *srv, struct tunnel *restrict t,
	const union mux_event_data edata)
{
	LOGN_F("[fd:%d] session closed", tunnel_fd(t));
	if (edata.closed.expired) {
		SESSION_EVLOG(srv, t, "suspended session expired");
	}

	/* t's loop keeps running after CLOSED, so the teardown that
	 * server_remove_and_close_tunnel() posts to it runs promptly and the join
	 * there does not block. */
	server_remove_and_close_tunnel(srv, t);

	/* During graceful shutdown, exit when no accepted or dialed sessions remain. */
	if (srv->shutting_down && table_size(srv->accepted_tunnels) == 0 &&
	    srv->mux_tunnel == NULL && !server_has_live_peer(srv)) {
		ev_timer_stop(srv->loop, &srv->w_maintenance);
		ev_break(srv->loop, EVBREAK_ALL);
		return;
	}

	/* This is the one place an identity slot empties, so it is also where
	 * the re-dial that maintenance owns becomes outstanding. */
	server_maintenance_kick(srv);
}

static void server_relay_event(
	void *data, struct tunnel *t, const enum mux_event event,
	const union mux_event_data edata)
{
	struct server *const srv = data;
	switch (event) {
	case MUX_EVENT_ESTABLISHED:
	case MUX_EVENT_RESUMED:
		/* Routed to on_established / on_resumed instead. */
	case MUX_EVENT_CONNECT:
	case MUX_EVENT_CONNECT_FAILED:
	case MUX_EVENT_SUSPENDED:
	case MUX_EVENT_STREAM_ESTABLISHED:
		/* Consumed by the tunnel layer and never relayed. */
		break;
	case MUX_EVENT_LOST:
		handle_disconnected(srv, t);
		break;
	case MUX_EVENT_CLOSED:
		handle_closed(srv, t, edata);
		break;
	}
}

/* Locate a suspended/established session matching session_id (spec §5.8);
 * takes accepted_mu (shared) and holds it on return; released by
 * server_on_resume_unpin (paired one-to-one). */
static struct tunnel *server_on_resume_lookup(
	void *data, struct tunnel *new_t, const unsigned char *session_id)
{
	(void)new_t;
	struct server *const restrict srv = data;

#if WITH_THREADS
	THRD_ASSERT(smtx_sharedlock(&srv->accepted_mu));
#endif
	void *elem = NULL;
	struct tunnel *candidate = NULL;
	if (table_find(srv->accepted_tunnels, session_id, &elem)) {
		candidate = elem;
		const enum mux_state st = tunnel_state(candidate);
		/* MUX_STATE_CLOSING is excluded here: session_resume_attach
		 * silently drops a handoff to a shutting-down session, and the
		 * single consume point in mux_resume_attach would then close the
		 * peer's fresh transport with no ServerHello sent. */
		if ((st != MUX_STATE_SUSPENDED &&
		     st != MUX_STATE_ESTABLISHED) ||
		    !tunnel_is_accepted(candidate)) {
			/* Never resume a client-mode session: only server-mode
			 * sessions maintain stable address state. */
			candidate = NULL;
		} else if (st == MUX_STATE_ESTABLISHED) {
			LOGW_F("[fd:%d] resume matched ESTABLISHED session,"
			       " suspending old transport",
			       tunnel_fd(candidate));
		}
	}
#if WITH_THREADS
	if (candidate == NULL) {
		/* No match: nothing to pin, release immediately (the paired
		 * server_on_resume_unpin only runs for a non-NULL return). */
		THRD_ASSERT(smtx_sharedunlock(&srv->accepted_mu));
	}
	/* Otherwise the lock stays held; server_on_resume_unpin releases it once
	 * the handoff to the matched tunnel has been enqueued. */
#endif
	return candidate;
}

/* Release the accepted_mu shared lock taken by server_on_resume_lookup, once the
 * resume handoff has been enqueued. */
static void server_on_resume_unpin(void *data, struct tunnel *new_t)
{
	(void)new_t;
	struct server *const restrict srv = data;
#if WITH_THREADS
	THRD_ASSERT(smtx_sharedunlock(&srv->accepted_mu));
#else
	(void)srv;
#endif
}

static void identity_tcp_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	(void)loop;
	(void)sa;
	struct identity_listener *const sl = DOWNCAST(
		struct listener, struct identity_listener, listener, l);
	struct tunnel *const restrict t = identity_listener_pick(sl);
	if (t == NULL) {
		char esc[IDENTITY_ESCAPED_MAX];
		escape_identity(
			esc, sizeof(esc), sl->peer_identity, ESCAPE_PLAIN);
		LOGD_F("[fd:%d] no session for identity \"%s\","
		       " closing",
		       fd, esc);
		socket_close(fd);
		return;
	}
	l->srv->counters.num_served_tcp++;
	tunnel_open_stream(t, fd);
}

/* Advance srv->accepted_rr_cursor to the next accepted tunnel, wrapping once it
 * runs off the end.  Returns NULL when the table is empty. */
static struct tunnel *accepted_tunnels_next(struct server *restrict srv)
{
	void *elem = NULL;
	if (!table_next(
		    srv->accepted_tunnels, &srv->accepted_rr_cursor, NULL,
		    &elem)) {
		srv->accepted_rr_cursor = 0;
		(void)table_next(
			srv->accepted_tunnels, &srv->accepted_rr_cursor, NULL,
			&elem);
	}
	return elem;
}

/* Round-robin over accepted_tunnels, skipping any that cannot carry a stream
 * right now: every accepted connection is registered before its handshake and
 * stays registered while suspended, and an open handed to one is closed.  One
 * lap from the cursor finds the first established tunnel; when none is, the
 * plain round-robin pick stands.  Returns NULL when the table is empty. */
static struct tunnel *accepted_tunnels_pick(struct server *restrict srv)
{
	struct tunnel *const first = accepted_tunnels_next(srv);
	if (first == NULL || tunnel_state(first) == MUX_STATE_ESTABLISHED) {
		return first;
	}
	const size_t after_first = srv->accepted_rr_cursor;
	const size_t n = table_size(srv->accepted_tunnels);
	for (size_t i = 1; i < n; i++) {
		struct tunnel *const t = accepted_tunnels_next(srv);
		if (tunnel_state(t) == MUX_STATE_ESTABLISHED) {
			return t;
		}
	}
	srv->accepted_rr_cursor = after_first;
	return first;
}

/* The tunnel the top-level listen address forwards over: the dialed
 * mux_tunnel, else the next accepted tunnel round-robin; NULL when none. */
static struct tunnel *server_pick_local(struct server *restrict srv)
{
	struct tunnel *restrict t = srv->mux_tunnel;
	if (t == NULL && srv->accepted_tunnels != NULL) {
		t = accepted_tunnels_pick(srv);
	}
	return t;
}

static void tcp_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	(void)loop;
	(void)sa;
	struct server *const srv = l->srv;
	struct tunnel *const restrict t = server_pick_local(srv);
	if (t == NULL) {
		LOGD_F("[fd:%d] no active session, closing", fd);
		socket_close(fd);
		return;
	}

	srv->counters.num_served_tcp++;
	tunnel_open_stream(t, fd);
}

/* lossymux routing for the top-level listen address: its UDP clients go where
 * its TCP connections do. */
static void *udp_local_pick(void *ctx)
{
	return server_pick_local(ctx);
}

static void udp_local_deliver(void *ctx, void *target, struct udp_dgram *d)
{
	const struct server *const restrict srv = ctx;
	tunnel_send_dgram(target, d, (size_t)srv->conf->mux.lossymux_queue);
}

/* lossymux routing for an identity.listen address, over that peer's pool. */
static void *udp_identity_pick(void *ctx)
{
	return identity_listener_pick(ctx);
}

static void udp_identity_deliver(void *ctx, void *target, struct udp_dgram *d)
{
	const struct identity_listener *const restrict sl = ctx;
	tunnel_send_dgram(
		target, d, (size_t)sl->listener.srv->conf->mux.lossymux_queue);
}

/* Bring the lossymux UDP socket in *slot in line with its TCP listener: bound
 * to the very address tcp holds (so a port-0 listen shares its port) while
 * lossymux is enabled, absent otherwise.  A socket already bound there is kept,
 * its routes with it.  Returns false (logged) when a needed bind fails. */
static bool server_sync_udp_listener(
	struct server *restrict s, const struct listener *restrict tcp,
	struct udp_listener **restrict slot,
	const struct udp_listener_cb *restrict cb)
{
	const struct config *const restrict conf = s->conf;
	const double idle_timeout = (double)conf->mux.lossymux_idle_timeout;
	union sockaddr_max sa;
	if (!conf->mux.lossymux || !listener_get_addr(tcp, &sa)) {
		udp_listener_free(*slot);
		*slot = NULL;
		return true;
	}
	if (*slot != NULL) {
		union sockaddr_max cur;
		if (udp_listener_get_addr(*slot, &cur) &&
		    sa_equals(&cur.sa, &sa.sa)) {
			udp_listener_set_idle_timeout(*slot, idle_timeout);
			return true;
		}
		udp_listener_free(*slot);
		*slot = NULL;
	}
	char str[64];
	(void)sa_format(str, sizeof(str), &sa.sa);
	*slot = udp_listener_new(
		s->loop, &sa.sa, conf->tcp.tcp_reuseport, cb, idle_timeout,
		&s->counters.num_dgram_unrouted);
	if (*slot == NULL) {
		LOGE_F("failed to start UDP listener on %s", str);
		return false;
	}
	LOGN_F("listening on %s (UDP)", str);
	return true;
}

/* Sync every lossymux UDP socket with its TCP listener; see
 * server_sync_udp_listener.  Every listener is synced even after a failure. */
static bool server_sync_udp_listeners(struct server *restrict s)
{
	const struct udp_listener_cb local_cb = {
		.pick = udp_local_pick,
		.deliver = udp_local_deliver,
		.ctx = s,
	};
	bool ok = server_sync_udp_listener(
		s, &s->local_listener, &s->udp_local, &local_cb);
	size_t cursor = 0;
	void *elem;
	while (table_next(s->identities, &cursor, NULL, &elem)) {
		struct identity_listener *const restrict sl = elem;
		const struct udp_listener_cb cb = {
			.pick = udp_identity_pick,
			.deliver = udp_identity_deliver,
			.ctx = sl,
		};
		ok = server_sync_udp_listener(
			     s, &sl->listener, &sl->udp, &cb) &&
		     ok;
	}
	return ok;
}

/* Stop every lossymux UDP socket (shutdown). */
static void server_stop_udp_listeners(struct server *restrict s)
{
	udp_listener_free(s->udp_local);
	s->udp_local = NULL;
	size_t cursor = 0;
	void *elem;
	while (table_next(s->identities, &cursor, NULL, &elem)) {
		struct identity_listener *const restrict sl = elem;
		udp_listener_free(sl->udp);
		sl->udp = NULL;
	}
}

static bool is_startup_limited(const struct server *restrict srv)
{
	const struct config *const restrict conf = srv->conf;
	const struct server_counters *const restrict stats = &srv->counters;
#if WITH_THREADS
	const size_t n_halfopen = atomic_load_explicit(
		&stats->num_session_halfopen, memory_order_relaxed);
#else
	const size_t n_halfopen = stats->num_session_halfopen;
#endif

	if (conf->startup_limit_full > 0 &&
	    n_halfopen >= (size_t)conf->startup_limit_full) {
		LOGVV("full startup limit exceeded, rejecting new connection");
		return true;
	}

	/* No "start > 0" gate: start == 0 is a valid, explicit "throttle from
	 * the first connection" configuration, not "disabled". The
	 * unconfigured default (start=rate=full=0) still never rejects here
	 * because rate == 0 makes the probability check below always false,
	 * regardless of n_halfopen. */
	if (n_halfopen >= (size_t)conf->startup_limit_start) {
		if (frand() * 100.0 < conf->startup_limit_rate) {
			LOGVV("startup limit reached, rejecting new connection");
			return true;
		}
	}
	return false;
}

/* Session resumption (spec 5.8) authenticates a reconnecting transport by
 * session-id match, so IDs must be unguessable; rand64() (math/rand.h) is
 * explicitly not cryptographically secure, so this goes straight to the OS
 * entropy source instead. */
static bool proto_session_id_new(unsigned char *const id)
{
	return csprng_bytes(id, MUX_SESSION_ID_LEN);
}

static bool
server_new_session_id(const struct server *restrict s, unsigned char *sid)
{
	do {
		if (!proto_session_id_new(sid)) {
			return false;
		}
	} while (table_find(s->accepted_tunnels, sid, NULL));
	return true;
}

static bool server_register_session(struct server *s, struct tunnel *t)
{
	void *const elem = server_accepted_set(s, t);
	if (elem == t) {
		LOGOOM();
		tunnel_close(t);
		return false;
	}
	ASSERT(elem == NULL);
	return true;
}

#if WITH_TLS
/* tunnel_opts.psk_identity_of adapter: the table is opaque there, so the
 * typed accessor is reached through a void * context. */
static const char *server_psk_identity_cb(void *ctx, const char *label)
{
	return server_psk_identity_of(ctx, label);
}
#endif /* WITH_TLS */

static void mux_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	(void)loop;
	struct server *const srv = l->srv;
	if (LOGLEVEL(DEBUG)) {
		char addr_str[64];
		(void)sa_format(addr_str, sizeof(addr_str), sa);
#if WITH_THREADS
		const size_t n_sessions = atomic_load_explicit(
			&srv->counters.num_sessions, memory_order_relaxed);
		const size_t n_halfopen = atomic_load_explicit(
			&srv->counters.num_session_halfopen,
			memory_order_relaxed);
#else /* WITH_THREADS */
		const size_t n_sessions = srv->counters.num_sessions;
		const size_t n_halfopen = srv->counters.num_session_halfopen;
#endif /* WITH_THREADS */
		LOGD_F("accepting from: `%s'; established=%zu, halfopen=%zu",
		       addr_str, n_sessions, n_halfopen);
	}

	if (is_startup_limited(srv)) {
		srv->counters.num_rejected++;
		socket_close(fd);
		return;
	}

#if WITH_TLS
	struct tls_connection *conn = NULL;
	if (srv->server_tlsctx != NULL) {
		/* With socket offload the library drives the socket; otherwise it is
		 * memory-transport (fd=-1).  The session binds the I/O notifier later. */
		conn = tls_server(
			srv->server_tlsctx,
			srv->conf->tls_socket_offload ? fd : -1);
		if (conn == NULL) {
			LOGE_F("[fd:%d] TLS accept failed", fd);
			srv->counters.num_tls_failures++;
			socket_close(fd);
			return;
		}
	}
#endif /* WITH_TLS */

	struct mux_session_config mux_conf = conf_get_mux(srv->conf);
	const struct tunnel_callbacks callbacks = {
		.on_event = server_relay_event,
		.on_established = server_on_established,
		.on_resumed = server_on_resumed,
		.on_resume_lookup = server_on_resume_lookup,
		.on_resume_unpin = server_on_resume_unpin,
	};
	unsigned char sid[MUX_SESSION_ID_LEN];
	if (!server_new_session_id(srv, sid)) {
		LOGE_F("[fd:%d] failed to generate a session id", fd);
		socket_close(fd);
#if WITH_TLS
		tls_conn_free(conn);
#endif
		return;
	}
	const struct tunnel_session_counters cnts =
		server_make_tunnel_counters(srv);
	const struct tunnel_context ctx = server_make_tunnel_context(srv);
	const struct tunnel_opts opts = {
		.cb = &callbacks,
		.data = srv,
		.mux_conf = &mux_conf,
		.mux_socket = srv->conf->mux_tcp,
		.local_socket = srv->conf->tcp,
		.fd = fd,
		.id = sid,
		.connect_addr = NULL,
		.forward_addr = srv->conf->connect,
		.identity = srv->conf->identity.claim,
		.cnt = &cnts,
		.verify_identity = srv->conf->identity.verify,
#if WITH_TLS
		.psk_identity_of =
			srv->psk != NULL ? server_psk_identity_cb : NULL,
		.psk_ctx = srv->psk,
		.tlsctx = NULL,
		.conn = conn,
#endif
	};

	struct tunnel *const t = tunnel_new(&ctx, &opts);
	if (t == NULL) {
		/* tunnel_new() owns fd and conn on every path, including failure
		 * (see its doc comment); closing/freeing them here too would
		 * double-close fd (a live descriptor number could already have been
		 * reused by another thread's accept()) or double-free conn. */
		LOGE_F("[fd:%d] failed to create tunnel", fd);
		return;
	}

	if (!server_register_session(srv, t)) {
		return;
	}

	/* mux_start() starts libev watchers on the tunnel's loop; dispatch
	 * to the tunnel thread. */
	if (!tunnel_start(t)) {
		/* Thread never started: unregister and tear down (tunnel_close
		 * releases the mux session, closing fd) rather than leave a dead
		 * tunnel in accepted_tunnels, and do not count it as served. */
		server_accepted_del(srv, t);
		tunnel_close(t);
		LOGE_F("[fd:%d] failed to start accepted mux connection", fd);
		return;
	}
	srv->counters.num_served++;
	LOGI_F("[fd:%d] accepted mux connection", fd);
}

/* NULL-safe string equality: returns true iff both strings are identical
 * (including both NULL). */
static bool strnull_eq(const char *a, const char *b)
{
	if (a == NULL && b == NULL) {
		return true;
	}
	if (a == NULL || b == NULL) {
		return false;
	}
	return strcmp(a, b) == 0;
}

static const struct tunnel_callbacks client_callbacks = {
	.on_event = server_relay_event,
	.on_established = server_on_established,
	.on_resumed = server_on_resumed,
};

#if WITH_TLS
/* tls_psk_lookup_fn: resolve a label the client offered to its key. */
static bool server_psk_lookup(
	void *ctx, const char *identity, unsigned char *key, size_t *key_len)
{
	const struct psk_table *const restrict t = ctx;
	for (size_t i = 0; i < t->count; i++) {
		const struct psk_table_entry *const restrict e = &t->entries[i];
		if (strcmp(e->label, identity) != 0) {
			continue;
		}
		if (*key_len < e->key_len) {
			return false;
		}
		memcpy(key, e->key, e->key_len);
		*key_len = e->key_len;
		return true;
	}
	return false;
}

/* tls_config.psk_lookup_ctx_hold/_release adapters: the table is opaque to the
 * TLS backend, which holds it for as long as a context registered with it can
 * still be reached by a handshake. */
static void server_psk_hold_cb(void *ctx)
{
	server_psk_table_hold(ctx);
}

static void server_psk_release_cb(void *ctx)
{
	server_psk_table_release(ctx);
}

/* Build fresh server and client TLS contexts from conf; shared by startup and
 * reload. True on success, false on failure (any partial context freed).
 * Each context built takes a hold on psk, released when it is freed.
 * conf's plaintext credentials are erased before returning either way. */
static bool server_make_tls_contexts(
	const struct config *restrict conf, struct psk_table *restrict psk,
	struct tls_context **restrict out_server,
	struct tls_context **restrict out_client)
{
	*out_server = NULL;
	*out_client = NULL;
	const bool is_psk = psk != NULL;
	if (!is_psk && (conf->tls_cert == NULL || conf->tls_key == NULL)) {
		return true;
	}
	char *authcerts_arr[1] = { conf->tls_authcerts_bundle };
	const size_t authcerts_count =
		conf->tls_authcerts_bundle != NULL ? 1 : 0;
	const struct tls_config tls_conf = {
		.cert = conf->tls_cert,
		.key = conf->tls_key,
		.authcerts = authcerts_arr,
		.authcerts_count = authcerts_count,
		/* Only one client-side PSK is possible, so a dialing node offers
		 * the first configured entry; conf_check_psk warns when there is
		 * more than one to choose from. */
		.psk = is_psk ? psk->entries[0].key : NULL,
		.psk_len = is_psk ? psk->entries[0].key_len : 0,
		.psk_lookup = is_psk ? server_psk_lookup : NULL,
		.psk_lookup_ctx = psk,
		.psk_lookup_ctx_hold = is_psk ? server_psk_hold_cb : NULL,
		.psk_lookup_ctx_release = is_psk ? server_psk_release_cb : NULL,
		.ciphersuites = conf->tls_ciphersuites,
		.alpn = conf->tls_alpn,
		.sni = conf->tls_sni,
		.kernel_offload = conf->tls_kernel_offload,
		/* Without socket offload mux.readahead sizes the session receive
		 * ring instead; the library never reads the socket itself. */
		.readahead =
			conf->tls_socket_offload && conf->mux.readahead > 0,
	};
	bool ok = true;
	if (conf->mux_listen != NULL) {
		*out_server = tls_ctx_server(&tls_conf);
		if (*out_server == NULL) {
			LOGE("failed to create server TLS context");
			ok = false;
		}
	}
	if (ok && (conf->mux_connect != NULL ||
		   conf->identity.mux_connect_count > 0)) {
		*out_client = tls_ctx_client(&tls_conf);
		if (*out_client == NULL) {
			LOGE("failed to create client TLS context");
			ok = false;
		}
	}
	conf_erase_credentials(conf);
	if (!ok) {
		tls_ctx_free(*out_server);
		*out_server = NULL;
		tls_ctx_free(*out_client);
		*out_client = NULL;
		return false;
	}
	return true;
}
#endif /* WITH_TLS */

/* Set opts' connect/reconnect fields for tunnel t per the config delta. */
static void tunnel_set_reload_connect(
	struct tunnel_reload_opts *restrict opts, struct server *restrict s,
	const struct tunnel *restrict t, const struct config *restrict old_conf,
	const struct config *restrict new_conf, const size_t old_ni,
	const size_t new_ni)
{
	if (t == s->mux_tunnel) {
		if (strnull_eq(old_conf->mux_connect, new_conf->mux_connect)) {
			return;
		}
		if (old_conf->mux_connect != NULL &&
		    new_conf->mux_connect != NULL) {
			opts->update_connect_addr = true;
			opts->connect_addr = new_conf->mux_connect;
		} else {
			/* Removed now, or re-added while a tunnel an earlier
			 * reload retired still drains: keep draining, never
			 * repoint -- a retired tunnel may already have relayed
			 * its CLOSED.  maintenance_pass() dials a fresh one
			 * once the slot is free. */
			opts->disable_reconnect = true;
		}
		return;
	}
	for (size_t i = 0; i < old_ni; i++) {
		if (s->identity_tunnels[i] != t) {
			continue;
		}
		/* old_ni is num_identity_tunnels, the identity_tunnels[] high-water
		 * mark (it only grows), so a slot may outlive the config that
		 * created it: a tunnel still draining from an earlier, larger
		 * config occupies slot i >= old_conf's mux_connect_count. Guard the
		 * old_conf array index by its own count -- old_conf->...[i] would
		 * otherwise be a heap OOB read whose garbage feeds strnull_eq. */
		if (i >= new_ni || i >= old_conf->identity.mux_connect_count) {
			/* Slot removed in the new config, or a stale draining slot
			 * past the old config's count: keep draining, never
			 * repoint. */
			opts->disable_reconnect = true;
		} else if (!strnull_eq(
				   old_conf->identity.mux_connect[i],
				   new_conf->identity.mux_connect[i])) {
			opts->update_connect_addr = true;
			opts->connect_addr = new_conf->identity.mux_connect[i];
		}
		return;
	}
}

/* Snapshot the live tunnels (deduped) and invoke fn(t, ctx) for each. Owns the
 * server_snapshot_cap/malloc/server_snapshot_tunnels/free scaffolding, so the
 * cap-to-count sizing invariant lives in one place. On allocation failure it
 * logs and skips the pass, returning false; a caller that needs an OOM
 * fallback (server_stop) keeps its own scaffolding.
 * Returns whether every live tunnel was visited -- a caller that draws a
 * conclusion from the absence of a match (the PSK reload barrier) must not
 * mistake a skipped pass for an empty one. */
static bool server_for_each_tunnel(
	struct server *s, void (*fn)(struct tunnel *t, void *ctx), void *ctx)
{
	/* Heap-allocated (not a VLA): the live tunnel count is unbounded in
	 * principle. */
	const size_t n = server_snapshot_cap(s);
	struct tunnel **const snapshot =
		(struct tunnel **)malloc(n * sizeof(struct tunnel *));
	if (snapshot == NULL) {
		LOGOOM();
		return false;
	}
	const size_t count = server_snapshot_tunnels(s, snapshot, n);
	for (size_t i = 0; i < count; i++) {
		fn(snapshot[i], ctx);
	}
	free((void *)snapshot);
	return true;
}

#if WITH_TLS
/* Context for psk_barrier_cb over server_for_each_tunnel. */
struct psk_barrier_ctx {
	struct server *s;
	/* Live tunnels not yet resolving through s->psk. */
	size_t stale;
};

static void psk_barrier_cb(struct tunnel *t, void *ctx)
{
	struct psk_barrier_ctx *const restrict c = ctx;
	struct server *const restrict s = c->s;
	const void *const cur = tunnel_psk_ctx(t);
	if (cur == s->psk) {
		return;
	}
	c->stale++;
	/* Whichever retired table it is still on has to outlive this sweep. */
	for (struct psk_table *p = s->retired_psk; p != NULL;
	     p = p->retired_next) {
		if (p == cur) {
			p->retired_in_use = true;
			break;
		}
	}
	/* Nothing else will move this tunnel forward: the reload it was sent
	 * never reached its queue (full, or its argument could not be
	 * allocated), so re-offer the resolver alone until one lands. */
	server_psk_table_hold(s->psk);
	if (!tunnel_set_psk(
		    t, s->psk != NULL ? server_psk_identity_cb : NULL, s->psk,
		    server_psk_release_cb)) {
		LOGD("failed to dispatch a psk repoint; retrying next tick");
	}
}

/* Acquire, pairing with the release in server_psk_table_release(). */
static bool psk_table_held(const struct psk_table *restrict t)
{
#if WITH_THREADS
	return atomic_load_explicit(&t->holds, memory_order_acquire) > 0;
#else
	return t->holds > 0;
#endif
}

/* Free every retired table nothing names any more, and re-dispatch the current
 * resolver to the tunnels that still name an older one.  Runs on the
 * maintenance tick and costs nothing while the retired list is empty, which is
 * every moment outside the window a reload opens. */
static void server_psk_release_retired(struct server *restrict s)
{
	if (s->retired_psk == NULL) {
		return;
	}
	/* Holds first, tunnels second, and never the other way round: a tunnel
	 * gives back the hold on a repoint only after publishing the resolver it
	 * carried, so a table this pass finds unheld is one the next loop is
	 * guaranteed to see reported if the tunnel is on it. */
	for (struct psk_table *p = s->retired_psk; p != NULL;
	     p = p->retired_next) {
		p->retired_in_use = psk_table_held(p);
	}
	struct psk_barrier_ctx ctx = { .s = s, .stale = 0 };
	if (!server_for_each_tunnel(s, psk_barrier_cb, &ctx)) {
		/* No tunnel was visited, so no table may be assumed unused. */
		return;
	}
	if (ctx.stale > 0) {
		LOGD_F("psk reload barrier: %zu tunnel(s) not yet repointed",
		       ctx.stale);
	}
	struct psk_table **link = &s->retired_psk;
	while (*link != NULL) {
		struct psk_table *const p = *link;
		if (p->retired_in_use) {
			link = &p->retired_next;
			continue;
		}
		*link = p->retired_next;
		p->retired_next = NULL;
		server_psk_table_free(p);
	}
}

/* Hand a table replaced by a reload to the barrier rather than freeing it: the
 * reload only *dispatches* the new one to each tunnel, and every tunnel keeps
 * resolving labels through this table on its own thread until that dispatch
 * runs -- or forever, if it was dropped. */
static void
server_retire_psk(struct server *restrict s, struct psk_table *restrict old)
{
	if (old == NULL) {
		return;
	}
	old->retired_next = s->retired_psk;
	s->retired_psk = old;
	/* The barrier can only be re-polled, not waited on, so retiring a table
	 * is what puts maintenance back on the clock until the list drains. */
	server_maintenance_kick(s);
}
#endif /* WITH_TLS */

/* Context for drain_tunnel_cb over server_for_each_tunnel. */
struct drain_ctx {
	struct server *s;
	const struct config *old_conf;
	const struct config *new_conf;
	struct mux_session_config drain_conf;
	bool forward_changed;
	bool preserve_sessions;
	size_t old_ni;
	size_t new_ni;
#if WITH_TLS
	struct tls_context *new_client_tlsctx;
	struct psk_table *new_psk;
#endif
};

static void drain_tunnel_cb(struct tunnel *t, void *ctx)
{
	struct drain_ctx *const d = ctx;
	struct tunnel_reload_opts opts = {
		.conf = d->drain_conf,
		.drain = !d->preserve_sessions,
		.mux_socket = d->new_conf->mux_tcp,
		.local_socket = d->new_conf->tcp,
		.update_forward_addr = d->forward_changed,
		.forward_addr = d->new_conf->connect,
		.verify_identity = d->new_conf->identity.verify,
#if WITH_TLS
		/* Refreshed with the config: the table this replaces is retired
		 * at the end of server_apply_config, and released once no tunnel
		 * reports it any more. */
		.psk_identity_of =
			d->new_psk != NULL ? server_psk_identity_cb : NULL,
		.psk_ctx = d->new_psk,
		.psk_ctx_release = server_psk_release_cb,
#endif
	};
#if WITH_TLS
	/* Held for the dispatch, which gives it back when it runs or is dropped:
	 * until then this table is named by nothing else -- the tunnel still
	 * reports the previous one, and a reload after this one would retire this
	 * table while the dispatch is still in the ring. */
	server_psk_table_hold(d->new_psk);
	/* Per-dialed-tunnel TLS handle (ownership transferred to tunnel_reload);
	 * on OOM the tunnel keeps its current context. */
	if (!tunnel_is_accepted(t) && d->new_client_tlsctx != NULL) {
		opts.tlsctx = tls_ctx_ref(d->new_client_tlsctx);
	}
#endif /* WITH_TLS */
	tunnel_set_reload_connect(
		&opts, d->s, t, d->old_conf, d->new_conf, d->old_ni, d->new_ni);
	if (opts.disable_reconnect) {
		opts.drain = true;
	}
	tunnel_reload(t, &opts);
}

/* Single-pass reload: update addresses and config per tunnel. Unless a capacity
 * reduction preserves them, sessions drain when their last stream closes;
 * retained outbound tunnels then reconnect with the fresh config. */
static void server_drain_tunnels(
	struct server *s, const struct config *restrict old_conf,
	const struct config *restrict new_conf
#if WITH_TLS
	,
	struct tls_context *new_client_tlsctx, struct psk_table *new_psk
#endif
)
{
	const bool forward_changed =
		!strnull_eq(old_conf->connect, new_conf->connect);
	/* drain_conf.tlsctx stays NULL here; each dialed tunnel gets its own
	 * handle below, while accepted tunnels keep none (they hold a
	 * tls_connection, not a client context). */
	const struct mux_session_config drain_conf = conf_get_mux(new_conf);
	const size_t old_ni = s->num_identity_tunnels;
	const size_t new_ni = new_conf->identity.mux_connect_count;

	/* Snapshot and dedupe first (inside server_for_each_tunnel) so each live
	 * tunnel is reloaded exactly once; on OOM it skips this reload pass rather
	 * than failing the whole reload, leaving live sessions on their old
	 * settings. */
	struct drain_ctx dctx = {
		.s = s,
		.old_conf = old_conf,
		.new_conf = new_conf,
		.drain_conf = drain_conf,
		.forward_changed = forward_changed,
		/* A capacity reduction must not evict the sessions holding slots.
		 * Explicitly retired tunnels still end through their reload options. */
		.preserve_sessions =
			new_conf->max_sessions > 0 &&
			(old_conf->max_sessions == 0 ||
			 new_conf->max_sessions < old_conf->max_sessions),
		.old_ni = old_ni,
		.new_ni = new_ni,
#if WITH_TLS
		.new_client_tlsctx = new_client_tlsctx,
		.new_psk = new_psk,
#endif
	};
	(void)server_for_each_tunnel(s, drain_tunnel_cb, &dctx);
}

/* Resolve addr, optionally warn if it is a non-local (public) bind address,
 * start l on it, and log a NOTICE. reload only varies the error-message
 * wording (the config path is already validated, so a failure here on reload is
 * worth flagging as such). %.256s bounds the parse-error log: conf_schema.json
 * caps listen/mux_listen/api_listen at 261 octets, so it guards the log line,
 * not an attacker-sized string. Returns false (logged) on resolve/start
 * failure. */
static bool server_bind_and_log(
	struct listener *restrict l, struct ev_loop *restrict loop,
	const char *addr, const char *conf_key, const char *kind,
	const bool warn_if_public, const bool reload)
{
	union sockaddr_max sa;
	if (!resolve_bindaddr(&sa, addr, SA_RESOLVE_TCP)) {
		if (reload) {
			LOGE_F("failed to parse %s address on reload: %.256s",
			       conf_key, addr);
		} else {
			LOGE_F("failed to parse %s address: %.256s", conf_key,
			       addr);
		}
		return false;
	}
	if (warn_if_public) {
		const enum ipclass cls = sa_ipclassify(&sa.sa);
		if (cls != IPCLASS_LOOPBACK && cls != IPCLASS_LINKLOCAL &&
		    cls != IPCLASS_SITELOCAL) {
			LOGW("binding API server to non-local address may be insecure");
		}
	}
	if (!listener_start(l, loop, &sa.sa)) {
		if (reload) {
			LOGE_F("failed to restart %s listener on reload: %s",
			       conf_key, addr);
		} else {
			LOGE_F("failed to start %s listener", conf_key);
		}
		return false;
	}
	if (LOGLEVEL(NOTICE)) {
		char str[64];
		(void)sa_format(str, sizeof(str), &sa.sa);
		LOGN_F("listening on %s (%s)", str, kind);
	}
	return true;
}

/* The identity.listen entry conf has for peer id, or NULL if it has none. */
static const struct identity_peer *
conf_identity_peer(const struct config *restrict conf, const char *restrict id)
{
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		const struct identity_peer *const restrict p =
			&conf->identity.peers[i];
		if (strcmp(p->id, id) == 0) {
			return p;
		}
	}
	return NULL;
}

/* True if peer p of one config listens on the very same address in other:
 * other names the same peer with an identical listen string (both NULL
 * included). Such a listener's socket survives a reload untouched. */
static bool identity_peer_listen_kept(
	const struct identity_peer *restrict p,
	const struct config *restrict other)
{
	const struct identity_peer *const restrict q =
		conf_identity_peer(other, p->id);
	return q != NULL && strnull_eq(q->listen, p->listen);
}

/* The listener in old_tbl of old-config peer p when a reload to new_conf
 * releases its socket (p's listen changed or p was removed), else NULL. */
static struct identity_listener *identity_listener_released(
	const struct hashtable *restrict old_tbl,
	const struct identity_peer *restrict p,
	const struct config *restrict new_conf)
{
	void *elem;
	if (p->listen == NULL || identity_peer_listen_kept(p, new_conf) ||
	    !table_find(old_tbl, p->id, &elem)) {
		return NULL;
	}
	return elem;
}

/* A listening socket prepared for a reload but not yet armed: the bound
 * descriptor together with the address it was bound to. Carrying the resolved
 * address forward lets the commit step name the socket it actually installed
 * without resolving the configured string a second time -- a second resolve
 * can fail, or (for a name with several records) answer with a different
 * address than the one bound. */
struct server_prepared_listener {
	int fd;
	union sockaddr_max sa;
	/* The new address resolved to the one the live socket is already bound
	 * to, so that socket is kept and there is nothing to commit. */
	bool unchanged;
	/* The live socket had to be closed to bind fd; old_sa is the address it
	 * held, which an abandoned reload binds it to again. */
	bool released;
	union sockaddr_max old_sa;
};

struct server_released_identity {
	struct identity_listener *listener;
	union sockaddr_max sa;
};

struct server_listener_reload {
	struct server_prepared_listener local;
	struct server_prepared_listener mux;
	struct server_prepared_listener api;
	struct server_released_identity *identities;
	size_t num_identities;
};

#define SERVER_LISTENER_RELOAD_INIT                                            \
	((struct server_listener_reload){                                      \
		.local = { .fd = -1 },                                         \
		.mux = { .fd = -1 },                                           \
		.api = { .fd = -1 },                                           \
	})

/* Bind l again on the address a reload released it from. */
static void server_restore_listener(
	struct listener *restrict l, struct ev_loop *restrict loop,
	const union sockaddr_max *restrict sa, const char *conf_key)
{
	if (listener_start(l, loop, &sa->sa)) {
		return;
	}
	char str[64];
	(void)sa_format(str, sizeof(str), &sa->sa);
	LOGE_F("failed to restore %s listener on %s", conf_key, str);
}

/* Close every replacement before restoring any old socket: a replacement
 * may hold another role's former address. */
static void server_listener_reload_abort(
	struct server *restrict s,
	struct server_listener_reload *restrict reload)
{
	struct server_prepared_listener *prepared[] = {
		&reload->local,
		&reload->mux,
		&reload->api,
	};
	struct listener *live[] = {
		&s->local_listener,
		&s->mux_listener,
		&s->api_listener,
	};
	const char *keys[] = { "listen", "mux_listen", "api_listen" };
	for (size_t i = 0; i < ARRAY_SIZE(prepared); i++) {
		if (prepared[i]->fd >= 0) {
			socket_close(prepared[i]->fd);
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(prepared); i++) {
		if (prepared[i]->released) {
			server_restore_listener(
				live[i], s->loop, &prepared[i]->old_sa,
				keys[i]);
		}
	}
	for (size_t i = 0; i < reload->num_identities; i++) {
		const struct server_released_identity *const saved =
			&reload->identities[i];
		if (saved->listener != NULL &&
		    saved->sa.sa.sa_family != AF_UNSPEC) {
			server_restore_listener(
				&saved->listener->listener, s->loop, &saved->sa,
				"identity");
		}
	}
	free(reload->identities);
	*reload = SERVER_LISTENER_RELOAD_INIT;
}

/* Resolve a changed top-level address and release its old socket unless
 * the resolved address is unchanged. The whole batch is released before any
 * replacement binds, including removals and transfers between listener roles. */
static bool server_release_listener(
	struct server_prepared_listener *restrict prepared,
	struct listener *restrict live, struct ev_loop *restrict loop,
	const char *addr, const char *conf_key, const bool warn_if_public)
{
	if (addr != NULL) {
		if (!resolve_bindaddr(&prepared->sa, addr, SA_RESOLVE_TCP)) {
			LOGE_F("failed to parse %s address on reload: %.256s",
			       conf_key, addr);
			return false;
		}
		if (warn_if_public) {
			const enum ipclass cls =
				sa_ipclassify(&prepared->sa.sa);
			if (cls != IPCLASS_LOOPBACK &&
			    cls != IPCLASS_LINKLOCAL &&
			    cls != IPCLASS_SITELOCAL) {
				LOGW("binding API server to non-local address may be insecure");
			}
		}
	}
	if (!listener_get_addr(live, &prepared->old_sa)) {
		return true;
	}
	if (addr != NULL && sa_equals(&prepared->sa.sa, &prepared->old_sa.sa)) {
		prepared->unchanged = true;
		return true;
	}
	prepared->released = true;
	listener_stop(live, loop);
	return true;
}

static bool server_prepare_listener(
	struct server_prepared_listener *restrict prepared,
	const struct conf_socket_opts *restrict socket_opts, const char *addr,
	const char *conf_key)
{
	if (addr == NULL || prepared->unchanged) {
		return true;
	}
	prepared->fd = listener_open(socket_opts, &prepared->sa.sa);
	if (prepared->fd < 0) {
		LOGE_F("failed to restart %s listener on reload: %s", conf_key,
		       addr);
		return false;
	}
	return true;
}

/* Bind the replacement sockets for every listener whose address changed, so a
 * failure is reported with every live listener serving as before.  The local
 * and mux listeners take their options from @p new_conf, which is what
 * server_apply_config repoints them to; the API listener keeps the dedicated
 * profile server_new() gave it, which no reload replaces, so binding its
 * replacement with the listener's own options keeps the socket and its
 * listener describing the same thing. */
static bool server_prepare_listeners(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf,
	struct server_listener_reload *restrict reload)
{
	*reload = SERVER_LISTENER_RELOAD_INIT;
	const size_t n = old_conf->identity.peers_count;
	if (n > 0) {
		reload->identities = calloc(n, sizeof(reload->identities[0]));
		if (reload->identities == NULL) {
			LOGOOM();
			return false;
		}
		reload->num_identities = n;
	}
	if (!strnull_eq(old_conf->listen, new_conf->listen) &&
	    !server_release_listener(
		    &reload->local, &s->local_listener, s->loop,
		    new_conf->listen, "listen", false)) {
		goto fail;
	}
	if (!strnull_eq(old_conf->mux_listen, new_conf->mux_listen) &&
	    !server_release_listener(
		    &reload->mux, &s->mux_listener, s->loop,
		    new_conf->mux_listen, "mux_listen", false)) {
		goto fail;
	}
	if (!strnull_eq(old_conf->api_listen, new_conf->api_listen) &&
	    !server_release_listener(
		    &reload->api, &s->api_listener, s->loop,
		    new_conf->api_listen, "api_listen", true)) {
		goto fail;
	}
	for (size_t i = 0; i < n; i++) {
		struct server_released_identity *const saved =
			&reload->identities[i];
		saved->listener = identity_listener_released(
			s->identities, &old_conf->identity.peers[i], new_conf);
		if (saved->listener == NULL) {
			continue;
		}
		if (!listener_get_addr(&saved->listener->listener, &saved->sa)) {
			saved->sa.sa.sa_family = AF_UNSPEC;
		}
		listener_stop(&saved->listener->listener, s->loop);
	}
	if (!strnull_eq(old_conf->listen, new_conf->listen) &&
	    !server_prepare_listener(
		    &reload->local, &new_conf->tcp, new_conf->listen,
		    "listen")) {
		goto fail;
	}
	if (!strnull_eq(old_conf->mux_listen, new_conf->mux_listen) &&
	    !server_prepare_listener(
		    &reload->mux, &new_conf->mux_tcp, new_conf->mux_listen,
		    "mux_listen")) {
		goto fail;
	}
	if (!strnull_eq(old_conf->api_listen, new_conf->api_listen) &&
	    !server_prepare_listener(
		    &reload->api, s->api_listener.socket_opts,
		    new_conf->api_listen, "api_listen")) {
		goto fail;
	}
	return true;

fail:
	server_listener_reload_abort(s, reload);
	return false;
}

static void server_commit_listener(
	struct listener *restrict listener, struct ev_loop *restrict loop,
	struct server_prepared_listener *restrict prepared,
	const char *new_addr, const char *kind)
{
	if (prepared->unchanged) {
		return;
	}
	listener_stop(listener, loop);
	if (new_addr == NULL) {
		return;
	}
	listener_start_fd(listener, loop, prepared->fd);
	prepared->fd = -1;
	if (LOGLEVEL(NOTICE)) {
		char str[64];
		(void)sa_format(str, sizeof(str), &prepared->sa.sa);
		LOGN_F("listening on %s (%s)", str, kind);
	}
}

/* Replace tcp, mux, and api listeners only after every changed address has a
 * live prepared socket. */
static void server_reload_listeners(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf,
	struct server_listener_reload *restrict reload)
{
	struct ev_loop *const loop = s->loop;
	if (!strnull_eq(old_conf->listen, new_conf->listen)) {
		server_commit_listener(
			&s->local_listener, loop, &reload->local,
			new_conf->listen, "TCP");
	}
	if (!strnull_eq(old_conf->mux_listen, new_conf->mux_listen)) {
		server_commit_listener(
			&s->mux_listener, loop, &reload->mux,
			new_conf->mux_listen, "mux");
	}
	if (!strnull_eq(old_conf->api_listen, new_conf->api_listen)) {
		server_commit_listener(
			&s->api_listener, loop, &reload->api,
			new_conf->api_listen, "API server");
	}
}

/* Resolve listen, start sl's identity listener, and log a NOTICE tagged with
 * id. reload only varies the error-message wording. Returns false (logged) on a
 * resolve/start failure. */
static bool identity_bind_and_log(
	struct identity_listener *restrict sl, struct ev_loop *loop,
	const char *restrict listen, const char *restrict id, const bool reload)
{
	union sockaddr_max addr;
	if (!resolve_bindaddr(&addr, listen, SA_RESOLVE_TCP)) {
		if (reload) {
			LOGE_F("failed to parse identity listen address on reload: %.256s",
			       listen);
		} else {
			LOGE_F("failed to parse identity listen address: %.256s",
			       listen);
		}
		return false;
	}
	char esc[IDENTITY_ESCAPED_MAX];
	escape_identity(esc, sizeof(esc), id, ESCAPE_PLAIN);
	if (!listener_start(&sl->listener, loop, &addr.sa)) {
		if (reload) {
			LOGE_F("failed to restart identity listener for \"%s\" on reload",
			       esc);
		} else {
			LOGE_F("failed to start identity listener for \"%s\" at %s",
			       esc, listen);
		}
		return false;
	}
	if (LOGLEVEL(NOTICE)) {
		char str[64];
		(void)sa_format(str, sizeof(str), &addr.sa);
		LOGN_F("identity \"%s\" listening on %s (TCP)", esc, str);
	}
	return true;
}

/* Resolve listen and (re)start sl's identity listener, logging the outcome. */
static bool identity_listener_start(
	struct identity_listener *restrict sl, struct ev_loop *loop,
	const char *restrict listen, const char *restrict id)
{
	return identity_bind_and_log(sl, loop, listen, id, true);
}

/* Allocate the identity listener for peer id with an empty pool and no socket
 * yet; accepted connections take their options from conf. NULL on OOM
 * (logged). */
static struct identity_listener *identity_listener_new(
	struct server *restrict s, const struct config *restrict conf,
	const char *id)
{
	struct identity_listener *const restrict sl = malloc(sizeof(*sl));
	if (sl == NULL) {
		LOGOOM();
		return NULL;
	}
	sl->peer_identity = id;
	sl->udp = NULL;
	sl->tunnels = NULL;
	sl->num_tunnels = 0;
	sl->cap_tunnels = 0;
	sl->rr_next = 0;
	listener_init(
		&sl->listener, &conf->tcp, identity_tcp_serve, s,
		&s->counters.num_accepted_tcp);
	return sl;
}

/* Stop the listener of every identity pool in s->identities. */
static void
server_stop_identity_listeners(struct server *restrict s, struct ev_loop *loop)
{
	size_t cursor = 0;
	void *elem;
	while (table_next(s->identities, &cursor, NULL, &elem)) {
		listener_stop(
			&((struct identity_listener *)elem)->listener, loop);
	}
}

/* Discard the replacement table and stop every retained identity listener
 * whose address changed. The caller restores the released sockets together
 * with the top-level listeners after closing all prepared replacements. */
static void server_reload_identities_abort(
	struct server *s, const struct config *restrict old_conf,
	const struct config *restrict new_conf, struct hashtable *new_tbl)
{
	struct hashtable *const old_tbl = s->identities;
	size_t cursor = 0;
	const void *key;
	void *elem;
	while (table_next(new_tbl, &cursor, &key, &elem)) {
		void *old_elem;
		if (!table_find(old_tbl, key, &old_elem)) {
			identity_listener_discard(s, elem);
		}
	}
	table_free(new_tbl);
	for (size_t i = 0; i < old_conf->identity.peers_count; i++) {
		const struct identity_peer *const p =
			&old_conf->identity.peers[i];
		if (identity_peer_listen_kept(p, new_conf) ||
		    !table_find(old_tbl, p->id, &elem)) {
			continue;
		}
		struct identity_listener *const sl = elem;
		listener_stop(&sl->listener, s->loop);
		sl->listener.socket_opts = &old_conf->tcp;
	}
}

/* Rebuild s->identities for new_conf, touching only the listeners whose
 * address changes. The caller has released every changed top-level and
 * identity socket as one batch. A retained peer keeps its listener and pool;
 * unchanged addresses keep their sockets. New peers get empty listeners, and
 * removed peers are discarded after publishing the new table. On failure the
 * running table is retained and replacement sockets are stopped; the caller
 * restores the old addresses and rejects the reload. */
static bool server_reload_identities(
	struct server *s, const struct config *restrict old_conf,
	const struct config *restrict new_conf)
{
	struct hashtable *const old_tbl = s->identities;
	const size_t new_np = new_conf->identity.peers_count;
	/* Build the replacement table before touching any listener. */
	struct hashtable *new_tbl = NULL;
	if (new_np > 0) {
		new_tbl = table_new(&(struct table_opts){
			.hash = TABLE_OPTS_STR.hash,
			.eq = TABLE_OPTS_STR.eq,
			.flags = TABLE_FAST,
		});
		if (new_tbl == NULL) {
			LOGOOM();
			return false;
		}
	}
	for (size_t i = 0; i < new_np; i++) {
		const struct identity_peer *restrict p =
			&new_conf->identity.peers[i];
		void *elem;
		struct identity_listener *restrict sl;
		const bool retained = table_find(old_tbl, p->id, &elem);
		if (retained) {
			sl = elem;
		} else {
			sl = identity_listener_new(s, new_conf, p->id);
			if (sl == NULL) {
				goto fail;
			}
		}
		void *slot = sl;
		new_tbl = table_set(new_tbl, p->id, &slot);
		if (slot == sl) {
			if (!retained) {
				free(sl);
			}
			LOGOOM();
			goto fail;
		}
		ASSERT(slot == NULL);
	}

	for (size_t i = 0; i < new_np; i++) {
		const struct identity_peer *restrict p =
			&new_conf->identity.peers[i];
		void *elem;
		if (p->listen == NULL ||
		    identity_peer_listen_kept(p, old_conf) ||
		    !table_find(new_tbl, p->id, &elem)) {
			continue;
		}
		struct identity_listener *const restrict sl = elem;
		sl->listener.socket_opts = &new_conf->tcp;
		if (!identity_listener_start(sl, s->loop, p->listen, p->id)) {
			server_reload_identities_abort(
				s, old_conf, new_conf, new_tbl);
			return false;
		}
	}

	/* Publish the rebuilt table BEFORE discarding the removed peers.
	 * identity_listener_discard() closes each removed peer's tunnels, and a
	 * close can synchronously flush the shared dispatcher and run another
	 * tunnel's queued handle_closed(), reaching identity_pools_remove_except()
	 * or (when discard's sweep_live set could not be allocated)
	 * server_tunnel_is_registered() -- both traverse s->identities. Freeing
	 * a listener while it is still reachable through s->identities would leave
	 * those reentrant traversals (and a concurrent session-thread lookup)
	 * dereferencing freed memory. Swapping first keeps every traversal on the
	 * new table, which holds no removed listener.
	 *
	 * Session threads read s->identities under accepted_mu (shared) in tunnel
	 * handle_connected; hold it exclusive across the swap so a concurrent
	 * lookup never observes a half-swapped table. The old table has no reader
	 * once the swap is published, so it is discarded and freed after. */
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	s->identities = new_tbl;
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
	/* old_conf is freed once this reload returns, so every listener now
	 * names its peer through the new table's key, which points into
	 * new_conf, and takes new_conf's accepted-connection options. */
	{
		size_t cursor = 0;
		const void *key;
		void *elem;
		while (table_next(new_tbl, &cursor, &key, &elem)) {
			struct identity_listener *const restrict sl = elem;
			sl->peer_identity = key;
			sl->listener.socket_opts = &new_conf->tcp;
		}
	}
	{
		size_t cursor = 0;
		const void *key;
		void *elem;
		while (table_next(old_tbl, &cursor, &key, &elem)) {
			if (!table_find(new_tbl, key, NULL)) {
				identity_listener_discard(s, elem);
			}
		}
	}
	table_free(old_tbl);
	return true;

fail:
	server_reload_identities_abort(s, old_conf, new_conf, new_tbl);
	return false;
}

/* Create a new outbound (client-mode) tunnel with the given connect address.
 * Every other setting comes from the server's current config and the TLS/PSK
 * state built from it, which server_apply_config() swaps together, so one
 * tunnel never mixes two configs. Returns NULL on allocation or session-id
 * generation failure or capacity exhaustion. */
static struct tunnel *
server_new_client_tunnel(struct server *restrict s, const char *connect_addr)
{
	errno = 0;
	const struct config *const restrict conf = s->conf;
	struct mux_session_config mux_conf = conf_get_mux(conf);
	unsigned char sid[MUX_SESSION_ID_LEN];
	if (!proto_session_id_new(sid)) {
		LOGE("failed to generate a session id");
		return NULL;
	}
	const struct tunnel_session_counters cnts =
		server_make_tunnel_counters(s);
	const struct tunnel_context ctx = server_make_tunnel_context(s);
#if WITH_TLS
	/* Each dialed tunnel owns its own client TLS handle, sharing the parsed
	 * base credentials via tls_ctx_ref(); the tunnel frees it at close. */
	struct tls_context *tlsctx = NULL;
	if (s->client_tlsctx != NULL) {
		tlsctx = tls_ctx_ref(s->client_tlsctx);
		if (tlsctx == NULL) {
			LOGOOM();
			return NULL;
		}
	}
#endif /* WITH_TLS */
	const struct tunnel_opts opts = {
		.cb = &client_callbacks,
		.data = s,
		.mux_conf = &mux_conf,
		.mux_socket = conf->mux_tcp,
		.local_socket = conf->tcp,
		.fd = -1,
		.id = sid,
		.connect_addr = connect_addr,
		.forward_addr = conf->connect,
		.identity = conf->identity.claim,
		.cnt = &cnts,
		.verify_identity = conf->identity.verify,
#if WITH_TLS
		.psk_identity_of =
			s->psk != NULL ? server_psk_identity_cb : NULL,
		.psk_ctx = s->psk,
		.tlsctx = tlsctx,
		.conn = NULL,
#endif
	};
	errno = 0;
	struct tunnel *const t = tunnel_new(&ctx, &opts);
	const int create_error = errno;
#if WITH_TLS
	if (t == NULL) {
		/* tunnel_new failed before adopting the handle; release it here. */
		tls_ctx_free(tlsctx);
	}
#endif
	errno = create_error;
	return t;
}

/* Create a new mux_connect tunnel if one is configured but not yet live: after
 * a reload, and from maintenance once the slot empties.  A slot still held by
 * a draining tunnel a reload retired is skipped; maintenance dials it once
 * that tunnel closes.  Best-effort: on create or start failure the slot is
 * left NULL and maintenance retries. */
static void
server_ensure_mux_tunnel(struct server *s, const struct config *restrict conf)
{
	if (s->mux_tunnel != NULL || conf->mux_connect == NULL) {
		return;
	}
	struct tunnel *const t = server_new_client_tunnel(s, conf->mux_connect);
	if (t == NULL) {
		if (errno != ENOSPC) {
			LOGE("failed to create mux tunnel");
		}
		server_maintenance_kick(s);
		return;
	}
	s->mux_tunnel = t;
	if (!tunnel_start(t)) {
		/* Thread never started; clear the slot so maintenance can
		 * recreate it (this early-returns while mux_tunnel != NULL). */
		s->mux_tunnel = NULL;
		tunnel_close(t);
		server_maintenance_kick(s);
	}
}

/* Dial a fresh identity tunnel for the (currently NULL) slot i and store it in
 * identity_tunnels[i]. Best-effort: on create or start failure the slot is left
 * NULL so a later reload or maintenance pass can retry. */
static void server_start_identity_tunnel(
	struct server *s, const struct config *restrict conf, const size_t i)
{
	struct tunnel *const t =
		server_new_client_tunnel(s, conf->identity.mux_connect[i]);
	if (t == NULL) {
		if (errno != ENOSPC) {
			LOGE_F("failed to create identity tunnel[%zu]", i);
		}
		server_maintenance_kick(s);
		return;
	}
	s->identity_tunnels[i] = t;
	if (!tunnel_start(t)) {
		/* Thread never started; clear the slot so a later reload or
		 * maintenance pass can recreate it (a NULL slot reads as
		 * "closed"). */
		s->identity_tunnels[i] = NULL;
		tunnel_close(t);
		server_maintenance_kick(s);
	}
}

/* Replace closed identity_connect slots and extend the array when the count
 * grows; live slots are left untouched. */
static void server_reload_identity_tunnels(
	struct server *s, const struct config *restrict new_conf)
{
	const size_t old_ni = s->num_identity_tunnels;
	const size_t new_ni = new_conf->identity.mux_connect_count;
	const size_t common_ni = old_ni < new_ni ? old_ni : new_ni;

	/* Replace slots where the previous tunnel has already closed. Only
	 * handle_closed nulls a slot (establishment keeps it pointing at the
	 * live tunnel), so a NULL slot here unambiguously means "closed" -- a
	 * live-but-established tunnel is never mistaken for one, which would
	 * otherwise dial an unbounded stream of duplicates. A slot still held by
	 * a draining orphan is skipped here; maintenance_cb re-dials it once the
	 * orphan finally closes and frees the slot. */
	for (size_t i = 0; i < common_ni; i++) {
		if (s->identity_tunnels[i] != NULL) {
			/* Tunnel is still live; server_drain_tunnels()
			 * already repointed its connect_addr
			 * (tunnel_set_reload_connect). */
			continue;
		}
		server_start_identity_tunnel(s, new_conf, i);
	}

	/* Extend the array for new entries beyond the old count. */
	if (new_ni <= old_ni) {
		return;
	}
	struct tunnel **new_arr = (struct tunnel **)realloc(
		(void *)s->identity_tunnels, new_ni * sizeof(struct tunnel *));
	if (new_arr == NULL) {
		LOGOOM();
		server_maintenance_kick(s);
		return;
	}
	s->identity_tunnels = new_arr;
	/* Zero new slots before starting any tunnel so server_stop() sees a
	 * clean array even if a subsequent tunnel_new() fails. */
	for (size_t i = old_ni; i < new_ni; i++) {
		s->identity_tunnels[i] = NULL;
	}
	s->num_identity_tunnels = new_ni;
	for (size_t i = old_ni; i < new_ni; i++) {
		server_start_identity_tunnel(s, new_conf, i);
	}
}

bool server_apply_config(struct server *s, struct config *new_conf)
{
	/* Graceful shutdown has stopped every listener and told every tunnel to
	 * shut down; a reload now would rebind listeners and dial tunnels that
	 * nothing ever stops, so shutdown could only end at the force-exit
	 * deadline.  The API connections outlive the signal, so PUT /config can
	 * still arrive here. */
	if (s->shutting_down) {
		LOGW("config reload rejected: server is shutting down");
		conf_free(new_conf);
		return false;
	}
#if WITH_TLS
	/* Resolve @path certificate references and (re)build the authcerts trust
	 * bundle, as startup does in main(). */
	if (!conf_inline_pem(new_conf)) {
		LOGE("failed to load PEM references during reload");
		conf_free(new_conf);
		return false;
	}
	struct tls_context *new_server_tlsctx = NULL;
	struct tls_context *new_client_tlsctx = NULL;
	/* Rebuilt from the new config: the keys, and therefore their labels,
	 * may have changed. */
	struct psk_table *new_psk = NULL;
	if (new_conf->tls_psk_count > 0) {
		new_psk = server_psk_table_new(new_conf);
		if (new_psk == NULL) {
			conf_free(new_conf);
			return false;
		}
	}
	if (!server_make_tls_contexts(
		    new_conf, new_psk, &new_server_tlsctx,
		    &new_client_tlsctx)) {
		server_psk_table_free(new_psk);
		conf_free(new_conf);
		return false;
	}
#endif /* WITH_TLS */

	struct server_listener_reload listener_reload;
	if (!server_prepare_listeners(s, s->conf, new_conf, &listener_reload)) {
#if WITH_TLS
		if (new_server_tlsctx != NULL) {
			tls_ctx_free(new_server_tlsctx);
		}
		if (new_client_tlsctx != NULL) {
			tls_ctx_free(new_client_tlsctx);
		}
		server_psk_table_free(new_psk);
#endif
		conf_free(new_conf);
		return false;
	}

	struct config *const old_conf = s->conf;
	if (!server_reload_identities(s, old_conf, new_conf)) {
		server_listener_reload_abort(s, &listener_reload);
#if WITH_TLS
		if (new_server_tlsctx != NULL) {
			tls_ctx_free(new_server_tlsctx);
		}
		if (new_client_tlsctx != NULL) {
			tls_ctx_free(new_client_tlsctx);
		}
		server_psk_table_free(new_psk);
#endif
		conf_free(new_conf);
		return false;
	}

	server_drain_tunnels(
		s, old_conf, new_conf
#if WITH_TLS
		,
		new_client_tlsctx, new_psk
#endif
	);

	/* Swap config and TLS contexts before starting any new tunnels. */
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	s->session_limit = (size_t)new_conf->max_sessions;
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
	s->conf = new_conf;
	s->local_listener.socket_opts = &new_conf->tcp;
	s->mux_listener.socket_opts = &new_conf->mux_tcp;

#if WITH_TLS
	struct tls_context *const old_server_tlsctx = s->server_tlsctx;
	struct tls_context *const old_client_tlsctx = s->client_tlsctx;
	struct psk_table *const old_psk = s->psk;
	s->server_tlsctx = new_server_tlsctx;
	s->client_tlsctx = new_client_tlsctx;
	/* Freed after the contexts below: their lookup callback holds it. */
	s->psk = new_psk;
#endif

	server_reload_listeners(s, old_conf, new_conf, &listener_reload);
	free(listener_reload.identities);
	server_ensure_mux_tunnel(s, new_conf);
	server_reload_identity_tunnels(s, new_conf);
	/* After the TCP listeners settle, whose addresses the UDP sockets follow.
	 * UDP is best effort, so a failed bind is logged but fails no reload. */
	(void)server_sync_udp_listeners(s);

#if WITH_TLS
	if (old_server_tlsctx != NULL) {
		tls_ctx_free(old_server_tlsctx);
	}
	if (old_client_tlsctx != NULL) {
		tls_ctx_free(old_client_tlsctx);
	}
	/* Not freed here: server_drain_tunnels above only *dispatched* the new
	 * table to each tunnel, and every one of them keeps resolving labels
	 * through this one -- on its own thread -- until that dispatch runs.
	 * The barrier releases it once no tunnel reports it any more. */
	server_retire_psk(s, old_psk);
#endif /* WITH_TLS */

	/* An explicit --loglevel (loglevel_override >= 0) wins over the config's
	 * loglevel across reloads, matching main()'s boot-path choice; conf_check
	 * always materializes conf->loglevel, so it cannot itself signal "unset". */
	slog_setlevel(
		s->loglevel_override >= 0 ? s->loglevel_override :
					    new_conf->loglevel);
	conf_free(old_conf);

	LOGN("config reloaded");
	server_evlogf(s, "config reloaded");
	return true;
}

static void server_reload(struct server *s)
{
	const char *const conf_path = s->conf_path;
	if (conf_path == NULL || strcmp(conf_path, "-") == 0) {
		LOGW("config reload is not supported when reading from stdin");
		return;
	}
	LOGI_F("reloading config: %s", conf_path);
	(void)systemd_notify(DAEMON_SYSTEMD_STATE_RELOADING);

	struct config *const new_conf = conf_parsefile(conf_path);
	if (new_conf == NULL) {
		LOGE_F("failed to reload config: %s", conf_path);
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);
		return;
	}

	if (!server_apply_config(s, new_conf)) {
		LOGE_F("failed to reload config: %s", conf_path);
	}
	(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);
}

/* Clock disagreement larger than this (seconds) is treated as resume from
 * system suspend. */
#define SUSPEND_JUMP_S 15
/* Loop-time spacing between suspend checks, in seconds. */
#define SUSPEND_CHECK_INTERVAL 1.0
/* Force-exit deadline once a shutdown signal has been handled, in seconds. */
#define SHUTDOWN_DEADLINE 2.0
/* Retry spacing while a maintenance task still has outstanding work. */
#define MAINTENANCE_INTERVAL 1.0

static void drop_transport_cb(struct tunnel *t, void *ctx)
{
	(void)ctx;
	tunnel_drop_transport(t);
}

/* Read a clock that keeps running across system suspend, preferring the boot
 * clock and falling back to the wall clock. */
static bool
read_elapsed(struct server *restrict srv, int_fast64_t *restrict out)
{
	struct timespec ts;
	if (srv->check_uses_boottime) {
		if (clock_boot(&ts)) {
			*out = TIMESPEC_NANO(ts);
			return true;
		}
		/* CLOCK_BOOTTIME is a Linux extension; stop probing it once it
		 * proves unavailable. */
		srv->check_uses_boottime = false;
	}
	if (!clock_unix(&ts)) {
		return false;
	}
	*out = TIMESPEC_NANO(ts);
	return true;
}

/* Detect resume from system suspend and reconnect every transport.  Runs on
 * loop iterations that happen anyway, so an idle server never wakes for it;
 * a suspend leaves the timers that would wake it overdue, and the first
 * iteration after resume is where this notices. */
static void suspend_cb(struct ev_loop *loop, ev_check *w, const int revents)
{
	CHECK_REVENTS(revents, EV_CHECK);
	struct server *const restrict srv = w->data;

	/* ev_now is the loop time libev already refreshed this iteration, so
	 * throttling on it costs no clock read.  It follows the wall clock, so
	 * a suspend opens the gate at once; a backward step opens it too rather
	 * than stalling the check until the clock catches up. */
	const ev_tstamp now = ev_now(loop);
	const ev_tstamp since = now - srv->last_check_at;
	if (since >= 0.0 && since < SUSPEND_CHECK_INTERVAL) {
		return;
	}
	srv->last_check_at = now;

	const int_fast64_t mono_ns = clock_monotonic_ns();
	int_fast64_t elapsed_ns;
	if (mono_ns < 0 || !read_elapsed(srv, &elapsed_ns)) {
		LOGE("suspend check: no usable clock");
		return;
	}
	const int_fast64_t mono_delta = mono_ns - srv->last_check_mono_ns;
	const int_fast64_t elapsed_delta =
		elapsed_ns - srv->last_check_elapsed_ns;
	srv->last_check_mono_ns = (int_least64_t)mono_ns;
	srv->last_check_elapsed_ns = (int_least64_t)elapsed_ns;

	/* The monotonic clock stands still across suspend while the boot (or
	 * wall) clock keeps advancing, so their disagreement is the suspended
	 * duration.  Comparing the two deltas -- rather than one absolute gap --
	 * is what lets this run on an irregular cadence. */
	const int_fast64_t jump_ns = elapsed_delta - mono_delta;
	if (jump_ns <= (int_fast64_t)SUSPEND_JUMP_S * INT64_C(1000000000)) {
		return;
	}
	LOGW_F("system suspend of %" PRIdFAST64
	       "s detected, dropping all transports",
	       jump_ns / INT64_C(1000000000));
	/* On OOM server_for_each_tunnel skips this round; the baselines have
	 * already advanced, so only a later suspend retries. */
	(void)server_for_each_tunnel(srv, drop_transport_cb, NULL);
}

/* Run the deferred work the kick sites arm this timer for, reporting whether
 * any of it is still outstanding. */
static bool maintenance_pass(struct server *srv)
{
	bool more = false;
#if WITH_TLS
	/* Release the PSK tables a reload retired, once no tunnel is resolving
	 * through them, and re-offer the current one to any tunnel whose reload
	 * dispatch was dropped. */
	server_psk_release_retired(srv);
	more = srv->retired_psk != NULL;
#endif

	/* Re-dial any configured identity slot left empty. A slot goes NULL only
	 * when its tunnel permanently closes (handle_closed); if the current
	 * config still wants a tunnel there -- e.g. a slot freed by a drained
	 * orphan that had shadowed a reconfigured target, or a start that failed
	 * on reload -- dial it now instead of waiting for the next reload.
	 * The array high-water mark bounds the index; conf may configure fewer. */
	const struct config *const restrict conf = srv->conf;
	/* Likewise the mux_connect tunnel, whose slot a reload leaves held by a
	 * retired tunnel until it drains, even when it re-adds mux_connect. */
	server_ensure_mux_tunnel(srv, conf);
	more = more || (srv->mux_tunnel == NULL && conf->mux_connect != NULL);
	server_reload_identity_tunnels(srv, conf);
	more = more ||
	       srv->num_identity_tunnels < conf->identity.mux_connect_count;
	for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
		if (i < conf->identity.mux_connect_count &&
		    conf->identity.mux_connect[i] != NULL) {
			more = more || srv->identity_tunnels[i] == NULL;
		}
	}
	return more;
}

static void maintenance_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct server *const srv = w->data;

	/* While shutting down this watcher is the force-exit deadline rather
	 * than the maintenance tick, and reaching it is the whole event. */
	if (srv->shutting_down) {
		LOGW("shutdown timeout: forcing exit");
		ev_break(loop, EVBREAK_ALL);
		return;
	}

	srv->maintenance_passes++;
	if (!maintenance_pass(srv)) {
		ev_timer_stop(loop, w);
	}
}

#if WITH_THREADS
static void relay_async_cb(struct ev_loop *loop, ev_async *w, const int revents)
{
	CHECK_REVENTS(revents, EV_ASYNC);
	(void)loop;
	struct server *const srv = w->data;
	dispatcher_tick(srv->disp);
}
#endif /* WITH_THREADS */

static void shutdown_cb(struct tunnel *t, void *ctx)
{
	(void)ctx;
	tunnel_shutdown(t);
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, const int revents)
{
	CHECK_REVENTS(revents, EV_SIGNAL);
	struct server *const s = w->data;
	const int signo = w->signum;

	switch (signo) {
	case SIGHUP:
		server_reload(s);
		break;
	case SIGINT:
	case SIGTERM:
		LOGI_F("received (%d) %s, initiating shutdown", signo,
		       os_strsignal(signo));
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_STOPPING);

		/* Stop accepting new connections and incoming signals. */
		ev_signal_stop(loop, &s->w_sighup);
		ev_signal_stop(loop, &s->w_sigint);
		ev_signal_stop(loop, &s->w_sigterm);
		/* Set before anything else runs: the API connections stay open,
		 * so a PUT /config may still be dispatched -- even within this
		 * loop iteration after an ev_break below -- and must be
		 * refused. */
		s->shutting_down = true;

		listener_stop(&s->local_listener, loop);
		listener_stop(&s->mux_listener, loop);
		listener_stop(&s->api_listener, loop);
		server_stop_identity_listeners(s, loop);
		server_stop_udp_listeners(s);

		/* Gracefully shut down every active session (snapshot first:
		 * CLOSED handling mutates accepted_tunnels/identities and would
		 * invalidate a live iterator). On OOM server_for_each_tunnel skips
		 * graceful dispatch this pass; server_stop()'s force-close loop
		 * still guarantees every session gets closed. */
		(void)server_for_each_tunnel(s, shutdown_cb, NULL);

		if (s->mux_tunnel == NULL &&
		    (s->accepted_tunnels == NULL ||
		     table_size(s->accepted_tunnels) == 0) &&
		    !server_has_live_peer(s)) {
			ev_break(loop, EVBREAK_ALL);
			break;
		}

		/* Keep the event loop running until all sessions close or the
		 * shutdown deadline fires.  From here w_maintenance is that
		 * deadline, so re-arm it as a one-shot whatever it was doing. */
		ev_timer_stop(loop, &s->w_maintenance);
		ev_timer_set(&s->w_maintenance, SHUTDOWN_DEADLINE, 0.0);
		ev_timer_start(loop, &s->w_maintenance);
		break;
	default:
		break;
	}
}

struct server *server_new(struct ev_loop *loop, struct config *conf)
{
	struct server *srv = malloc(sizeof(struct server));
	if (srv == NULL) {
		LOGOOM();
		return NULL;
	}
	*srv = (struct server){
		.loop = loop,
		.conf = conf,
		.session_limit = (size_t)conf->max_sessions,
		.identities = NULL,
		/* -1 until main() plumbs an explicit --loglevel; see server.h. */
		.loglevel_override = -1,
	};
	listener_init(
		&srv->local_listener, &conf->tcp, tcp_serve, srv,
		&srv->counters.num_accepted_tcp);
	listener_init(
		&srv->mux_listener, &conf->mux_tcp, mux_serve, srv,
		&srv->counters.num_accepted);
	static const struct conf_socket_opts api_socket_opts = {
		.tcp_nodelay = true,
		.tcp_keepalive = false,
		.backlog = 16,
	};
	listener_init(
		&srv->api_listener, &api_socket_opts, api_serve, srv,
		&srv->counters.num_accepted_api);
	srv->started = (int_least64_t)clock_monotonic_ns();

#if WITH_THREADS
	if (smtx_init(&srv->accepted_mu) != thrd_success) {
		LOGOOM();
		free(srv);
		return NULL;
	}
#endif

	srv->accepted_tunnels = table_new(&SESSION_TABLE_OPTS);
	if (srv->accepted_tunnels == NULL) {
		LOGOOM();
		server_free(srv);
		return NULL;
	}

#if WITH_TLS
	/* Shared with server_apply_config().  server_make_tls_contexts() erases
	 * conf's plaintext credentials on both its success and failure path; a
	 * failure before it leaves conf to the caller, whose conf_free() erases
	 * them. */
	if (conf->tls_psk_count > 0) {
		srv->psk = server_psk_table_new(conf);
		if (srv->psk == NULL) {
			server_free(srv);
			return NULL;
		}
	}
	if (!server_make_tls_contexts(
		    conf, srv->psk, &srv->server_tlsctx, &srv->client_tlsctx)) {
		server_free(srv);
		return NULL;
	}
#endif /* WITH_TLS */

	/* Initialised here rather than in server_start so that a start failing
	 * partway can already kick it; it stays stopped until something does. */
	ev_timer_init(
		&srv->w_maintenance, maintenance_cb, MAINTENANCE_INTERVAL,
		MAINTENANCE_INTERVAL);
	srv->w_maintenance.data = srv;

	ev_signal_init(&srv->w_sighup, signal_cb, SIGHUP);
	srv->w_sighup.data = srv;
	ev_set_priority(&srv->w_sighup, EV_MAXPRI);

	ev_signal_init(&srv->w_sigint, signal_cb, SIGINT);
	srv->w_sigint.data = srv;
	ev_set_priority(&srv->w_sigint, EV_MAXPRI);

	ev_signal_init(&srv->w_sigterm, signal_cb, SIGTERM);
	srv->w_sigterm.data = srv;
	ev_set_priority(&srv->w_sigterm, EV_MAXPRI);

#if WITH_THREADS
	srv->disp = dispatcher_create(16);
	if (srv->disp == NULL) {
		LOGOOM();
		server_free(srv);
		return NULL;
	}
	ev_async_init(&srv->w_async, relay_async_cb);
	srv->w_async.data = srv;
	/* Armed here rather than in server_start(): server_apply_config() creates
	 * and starts tunnels on its own, so signalling threads can exist before
	 * (or without) the server ever starting. ev_async_start is also what makes
	 * libev arm the loop's internal pipe watcher, and ev_async_send onto an
	 * unarmed one aborts the next ev_run(). Nothing below can fail, so this
	 * needs no unwind; server_stop() pairs the stop, and server_free() covers a
	 * server that was never stopped. */
	ev_async_start(srv->loop, &srv->w_async);
#endif /* WITH_THREADS */

	return srv;
}

/* Start a single listener bound to addr.  If warn_if_public is true, emit
 * a security warning when the resolved address is not loopback/link-local/
 * site-local.  Returns false on failure (error already logged). */
static bool server_start_one_listener(
	struct listener *restrict l, struct ev_loop *restrict loop,
	const char *addr, const char *conf_key, const char *kind,
	const bool warn_if_public)
{
	return server_bind_and_log(
		l, loop, addr, conf_key, kind, warn_if_public, false);
}

static bool server_start_listeners(struct server *restrict s)
{
	struct ev_loop *const restrict loop = s->loop;
	const struct config *const restrict conf = s->conf;

	if (conf->listen != NULL &&
	    !server_start_one_listener(
		    &s->local_listener, loop, conf->listen, "listen", "TCP",
		    false)) {
		return false;
	}
	if (conf->mux_listen != NULL &&
	    !server_start_one_listener(
		    &s->mux_listener, loop, conf->mux_listen, "mux_listen",
		    "mux", false)) {
		return false;
	}
	if (conf->api_listen != NULL &&
	    !server_start_one_listener(
		    &s->api_listener, loop, conf->api_listen, "api_listen",
		    "API server", true)) {
		return false;
	}
	return true;
}

static bool server_start_mux_tunnel(struct server *s)
{
	const struct config *const restrict conf = s->conf;
	if (conf->mux_connect == NULL) {
		return true;
	}
	struct tunnel *const t = server_new_client_tunnel(s, conf->mux_connect);
	if (t == NULL) {
		if (errno == ENOSPC) {
			LOGW("session capacity exhausted; deferring configured mux tunnel");
			server_maintenance_kick(s);
			return true;
		}
		LOGE("failed to create tunnel for mux session");
		return false;
	}
	s->mux_tunnel = t;
	if (!tunnel_start(t)) {
		s->mux_tunnel = NULL;
		tunnel_close(t);
		return false;
	}
	return true;
}

/* Identity listeners: one per identity.listen entry; tunnels are wired at
 * handshake time, keyed by the peer's announced identity. */
static bool server_start_identity_listeners(struct server *restrict s)
{
	struct ev_loop *const restrict loop = s->loop;
	const struct config *const restrict conf = s->conf;
	const size_t n = conf->identity.peers_count;
	if (n == 0) {
		return true;
	}
	s->identities = table_new(&(struct table_opts){
		.hash = TABLE_OPTS_STR.hash,
		.eq = TABLE_OPTS_STR.eq,
		.flags = TABLE_FAST,
	});
	if (s->identities == NULL) {
		LOGOOM();
		return false;
	}
	for (size_t i = 0; i < n; i++) {
		const struct identity_peer *restrict p =
			&conf->identity.peers[i];
		struct identity_listener *restrict sl =
			identity_listener_new(s, conf, p->id);
		if (sl == NULL) {
			return false;
		}
		void *elem = sl;
		s->identities = table_set(s->identities, p->id, &elem);
		if (elem == sl) {
			free(sl);
			LOGOOM();
			return false;
		}
		ASSERT(elem == NULL);
		if (p->listen == NULL) {
			continue;
		}
		if (!identity_bind_and_log(sl, loop, p->listen, p->id, false)) {
			return false;
		}
	}
	return true;
}

/* Create one dedicated mux session per identity.mux_connect address.
 * Sessions are wired to the matching identity listener in server_on_established. */
static bool server_start_identity_tunnels(struct server *s)
{
	const struct config *const restrict conf = s->conf;
	const size_t n = conf->identity.mux_connect_count;
	if (n == 0) {
		return true;
	}
	s->identity_tunnels =
		(struct tunnel **)malloc(n * sizeof(struct tunnel *));
	if (s->identity_tunnels == NULL) {
		LOGOOM();
		return false;
	}
	/* Zero the array before starting any tunnel (no stale pointers on
	 * partial init). */
	for (size_t i = 0; i < n; i++) {
		s->identity_tunnels[i] = NULL;
	}
	s->num_identity_tunnels = n;
	for (size_t i = 0; i < n; i++) {
		struct tunnel *const t = server_new_client_tunnel(
			s, conf->identity.mux_connect[i]);
		if (t == NULL) {
			if (errno == ENOSPC) {
				LOGW_F("session capacity exhausted; deferring configured identity tunnel[%zu]",
				       i);
				server_maintenance_kick(s);
				continue;
			}
			LOGE_F("failed to create tunnel for identity"
			       " mux_connect[%zu]",
			       i);
			return false;
		}
		if (!tunnel_start(t)) {
			tunnel_close(t);
			return false;
		}
		s->identity_tunnels[i] = t;
	}
	return true;
}

bool server_start(struct server *s)
{
	struct ev_loop *const restrict loop = s->loop;
	const struct config *const restrict conf = s->conf;

	if (conf->connect != NULL) {
		union sockaddr_max connect_addr;
		if (!resolve_addr(
			    &connect_addr, conf->connect, SA_RESOLVE_TCP)) {
			LOGE_F("failed to resolve connect address: %.256s",
			       conf->connect);
			return false;
		}
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			(void)sa_format(
				addr_str, sizeof(addr_str), &connect_addr.sa);
			LOGN_F("connect target: %s", addr_str);
		}
	}

	if (!server_start_listeners(s) || !server_start_mux_tunnel(s) ||
	    !server_start_identity_listeners(s) ||
	    !server_start_identity_tunnels(s) ||
	    !server_sync_udp_listeners(s)) {
		return false;
	}

	ev_signal_start(loop, &s->w_sighup);
	ev_signal_start(loop, &s->w_sigint);
	ev_signal_start(loop, &s->w_sigterm);

	s->check_uses_boottime = true;
	s->last_check_at = ev_now(loop);
	s->last_check_mono_ns = (int_least64_t)clock_monotonic_ns();
	{
		int_fast64_t elapsed_ns;
		if (read_elapsed(s, &elapsed_ns)) {
			s->last_check_elapsed_ns = (int_least64_t)elapsed_ns;
		} else {
			LOGE("suspend check: no usable clock");
		}
	}
	ev_check_init(&s->w_suspend, suspend_cb);
	s->w_suspend.data = s;
	ev_check_start(loop, &s->w_suspend);
	/* A hook on iterations driven by other watchers; it must not be what
	 * keeps the loop alive. */
	ev_unref(loop);

	LOGN("server started");
	return true;
}

/* Force-close every tunnel in snapshot[0..count), used by server_stop()'s
 * shutdown-deadline sweep. Mirrors handle_closed(): remove each tunnel
 * under the exclusive lock before tearing it down, so a concurrent resume
 * lookup can never dispatch to a tunnel being concurrently freed. */
static void server_force_close_snapshot(
	struct server *srv, struct tunnel *const *restrict snapshot,
	const size_t count)
{
	server_sweep_begin(srv, snapshot, count);
	for (size_t i = 0; i < count; i++) {
		struct tunnel *const t = snapshot[i];
		/* Closing an earlier entry flushes the shared dispatcher
		 * (tunnel_close_final's epilogue drains the whole queue), which
		 * can run a still-live tunnel's queued MUX_EVENT_CLOSED through
		 * handle_closed -- freeing a tunnel still ahead in snapshot[].
		 * relay_disconnected only suppresses events of the tunnel being
		 * closed, so re-validate by pointer before touching t, giving
		 * this fast path the same rescan semantics that make
		 * server_force_close_one_by_one immune. Every fold drops its
		 * tunnel from sweep_live, so a reentrantly-freed tunnel is absent
		 * from it; the snapshot is deduped, so an entry this sweep
		 * already closed is never revisited. */
		if (!server_sweep_is_live(srv, t)) {
			continue;
		}
		if (tunnel_is_accepted(t)) {
			server_accepted_del(srv, t);
		}
		server_close_and_fold(srv, t);
	}
	server_sweep_end(srv);
}

/* OOM fallback for the force-close sweep below: process one tunnel at a
 * time via a fresh tunnel_iter_next scan instead of snapshotting all of
 * them into a buffer, so it needs no allocation at all (the heap snapshot
 * just failed). server_remove_and_close_tunnel() removes t from every pool it
 * could be found in -- the same full scope handle_closed uses, unlike
 * server_force_close_snapshot above which only removes from accepted_tunnels
 * because its caller bulk-clears the other pools right after the sweep -- so a
 * fresh scan on the next iteration can never find t again. tunnel_close()
 * joins t's thread and is not safe to call twice on the same tunnel, so this
 * exhaustive removal is what makes repeated fresh scans safe without tracking
 * which tunnels were already seen. */
static void server_force_close_one_by_one(struct server *srv)
{
	for (;;) {
		struct tunnel_iter it = { 0 };
		struct tunnel *const t = tunnel_iter_next(srv, &it);
		if (t == NULL) {
			break;
		}
		server_remove_and_close_tunnel(srv, t);
	}
}

void server_stop(struct server *srv)
{
	if (srv == NULL) {
		return;
	}
	LOGN("stopping server");
	struct ev_loop *const loop = srv->loop;

	ev_signal_stop(loop, &srv->w_sighup);
	ev_signal_stop(loop, &srv->w_sigint);
	ev_signal_stop(loop, &srv->w_sigterm);
	/* Set before the timer stops, and kept: the dispatcher flushes below
	 * run CLOSED handlers, and each would otherwise re-arm the maintenance
	 * tick on a server that is about to be freed. */
	srv->shutting_down = true;
	ev_timer_stop(loop, &srv->w_maintenance);
	if (ev_is_active(&srv->w_suspend)) {
		/* Balances the ev_unref that kept it from holding the loop open. */
		ev_ref(loop);
		ev_check_stop(loop, &srv->w_suspend);
	}
#if WITH_THREADS
	ev_async_stop(loop, &srv->w_async);
	dispatcher_tick(srv->disp);
#endif

	listener_stop(&srv->local_listener, loop);
	listener_stop(&srv->mux_listener, loop);
	listener_stop(&srv->api_listener, loop);
	api_server_stop(srv, loop);
	server_stop_identity_listeners(srv, loop);
	server_stop_udp_listeners(srv);

	/* Drain close notifications queued before relay stopped; avoids
	 * force-closing a session whose tunnel thread has already exited. */
#if WITH_THREADS
	dispatcher_tick(srv->disp);
#endif

	/* Force-close any sessions that did not finish their shutdown handshake
	 * within the deadline.  tunnel_iter yields a pool-registered tunnel more
	 * than once; dedupe so each is closed (and freed) exactly once. */
	{
		const size_t n = server_snapshot_cap(srv);
		struct tunnel **const heap_snapshot =
			(struct tunnel **)malloc(n * sizeof(struct tunnel *));
		if (heap_snapshot != NULL) {
			const size_t count =
				server_snapshot_tunnels(srv, heap_snapshot, n);
			server_force_close_snapshot(srv, heap_snapshot, count);
			free((void *)heap_snapshot);
		} else {
			/* No later fallback pass can pick up a skipped tunnel
			 * during shutdown, and an n-sized VLA here would put an
			 * unbounded amount of stack on the line exactly when
			 * memory is already tight; process tunnels one at a
			 * time instead, which needs no allocation at all. */
			LOGOOM();
			server_force_close_one_by_one(srv);
		}
	}
	srv->mux_tunnel = NULL;
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(srv->identities, &cursor, NULL, &elem)) {
			struct identity_listener *restrict sl = elem;
			free((void *)sl->tunnels);
			sl->tunnels = NULL;
			sl->num_tunnels = 0;
			sl->cap_tunnels = 0;
		}
	}
	free((void *)srv->identity_tunnels);
	srv->identity_tunnels = NULL;
	srv->num_identity_tunnels = 0;
	if (srv->accepted_tunnels != NULL) {
		table_free(srv->accepted_tunnels);
		srv->accepted_tunnels = NULL;
	}
}

void server_free(struct server *srv)
{
	if (srv == NULL) {
		return;
	}
#if WITH_THREADS
	/* Hands back the loop registration server_new() took; a no-op once
	 * server_stop() has already released it. */
	ev_async_stop(srv->loop, &srv->w_async);
#endif
	/* Likewise a no-op after server_stop(); it guarantees the loop never
	 * keeps a freed server's timer, whichever path last armed it. */
	ev_timer_stop(srv->loop, &srv->w_maintenance);
#if WITH_TLS
	if (srv->server_tlsctx != NULL) {
		tls_ctx_free(srv->server_tlsctx);
	}
	if (srv->client_tlsctx != NULL) {
		tls_ctx_free(srv->client_tlsctx);
	}
	/* After the contexts: their PSK lookup callback reads this table, and
	 * destroying the last of them is what gives back the hold on it. */
	server_psk_table_free(srv->psk);
	/* Every tunnel has been closed by now, so whatever the barrier was still
	 * holding for them has no reader left -- including a repoint the tunnel
	 * never ran, whose hold went with it. */
	while (srv->retired_psk != NULL) {
		struct psk_table *const p = srv->retired_psk;
		srv->retired_psk = p->retired_next;
		p->retired_next = NULL;
		server_psk_table_free(p);
	}
#endif /* WITH_TLS */
	table_free(srv->accepted_tunnels);
#if WITH_THREADS
	smtx_destroy(&srv->accepted_mu);
#endif
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(srv->identities, &cursor, NULL, &elem)) {
			struct identity_listener *sl = elem;
			udp_listener_free(sl->udp);
			free((void *)sl->tunnels);
			free(sl);
		}
	}
	table_free(srv->identities);
	udp_listener_free(srv->udp_local);
#if WITH_THREADS
	if (srv->disp != NULL) {
		dispatcher_destroy(srv->disp);
	}
#endif
	free(srv);
}

static int cmp_intfast64(const void *a, const void *b)
{
	const int_fast64_t va = *(const int_fast64_t *)a;
	const int_fast64_t vb = *(const int_fast64_t *)b;
	if (va < vb) {
		return -1;
	}
	if (va > vb) {
		return 1;
	}
	return 0;
}

/* True if t currently sits in the identity pool keyed by its announced peer
 * identity, i.e. server_stats()' identity-pool pass already emits it. */
static bool
tunnel_is_pooled(const struct server *restrict s, struct tunnel *restrict t)
{
	char peer_id_buf[256];
	if (!tunnel_peer_identity_copy(t, peer_id_buf, sizeof(peer_id_buf))) {
		return false;
	}
	void *elem = NULL;
	if (!table_find(s->identities, peer_id_buf, &elem)) {
		return false;
	}
	return identity_listener_contains(elem, t);
}

/* Context for snapshotting accepted tunnels not in any identity pool. */
struct unmatched_accepted_ctx {
	const struct server *s;
	struct server_stats *out;
	size_t val; /* next out->tunnels[] write index */
	size_t cap; /* out->tunnels[] capacity */
};

/* table_iterate callback: snapshot accepted tunnels that are not currently in
 * any identity pool (peer identity absent, not configured, or a pool insertion
 * that failed under memory pressure). Runs in a single pass bounded by cap, so a
 * peer identity flipping mid-scan (the session thread can rewrite
 * has_peer_identity) can never write past out->tunnels[]. */
static bool collect_unmatched_accepted(
	const struct hashtable *table, const void *key, void *element,
	void *data)
{
	(void)table;
	(void)key;
	struct unmatched_accepted_ctx *const ctx = data;
	/* Skip only when this tunnel is actually pooled -- the identity pool pass
	 * emits it there. A configured identity whose identity_listener_add()
	 * OOM'd left the accepted tunnel matched but unpooled; emit it here so the
	 * aggregate counters below do not drop it. */
	if (tunnel_is_pooled(ctx->s, element)) {
		return true;
	}
	ASSERT(ctx->val < ctx->cap);
	if (ctx->val >= ctx->cap) {
		/* Cannot happen: cap counts every accepted tunnel. Guard anyway so
		 * a future sizing mistake cannot become a buffer overflow. */
		return true;
	}
	struct tunnel_stats *ts = &ctx->out->tunnels[ctx->val++];
	ts->peer_identity = NULL;
	ts->num_tunnels = 1;
	tunnel_stats(element, ts);
	return true;
}

struct latency_percentiles {
	int_least64_t p50;
	int_least64_t p90;
	int_least64_t p99;
	int_least64_t pmax;
};

/* Sort samples[0..n) in place and fill *out from it; n must be non-zero. */
static void percentiles_from_samples(
	int_fast64_t *restrict samples, const size_t n,
	struct latency_percentiles *restrict out)
{
	ASSERT(n > 0);
	qsort(samples, n, sizeof(samples[0]), cmp_intfast64);
	const size_t i50 = (50 * n) / 100;
	const size_t i90 = (90 * n) / 100;
	const size_t i99 = (99 * n) / 100;
	out->p50 = samples[i50 < n ? i50 : n - 1];
	out->p90 = samples[i90 < n ? i90 : n - 1];
	out->p99 = samples[i99 < n ? i99 : n - 1];
	out->pmax = samples[n - 1];
}

/* Fill each tunnel's own p50/p90/p99 fields from its latency ring.  The ring is
 * fixed-size, so this needs no allocation and cannot fail. */
static void calc_tunnel_percentiles(struct server_stats *restrict out)
{
	for (size_t i = 0; i < out->num_tunnels; i++) {
		struct tunnel_stats *const restrict ts = &out->tunnels[i];
		const size_t ring = ARRAY_SIZE(ts->stream_establish_ns);
		const size_t n = MIN(ts->stream_establish_count, ring);
		if (n == 0) {
			continue;
		}
		int_fast64_t samples[TUNNEL_ESTABLISH_RING_SIZE];
		for (size_t j = 0; j < n; j++) {
			const size_t idx =
				(ts->stream_establish_count - j - 1) % ring;
			samples[j] = ts->stream_establish_ns[idx];
		}
		struct latency_percentiles p;
		percentiles_from_samples(samples, n, &p);
		ts->stream_establish_p50 = p.p50;
		ts->stream_establish_p90 = p.p90;
		ts->stream_establish_p99 = p.p99;
	}
}

/* Fill the p50/p90/p99/pmax percentile fields in *out by merging the latency
 * rings of every tunnel in out->tunnels[], accepted ones included -- they carry
 * active opens too.  Returns the sample count. */
static size_t calc_stream_percentiles(struct server_stats *restrict out)
{
	size_t total = 0;
	for (size_t i = 0; i < out->num_tunnels; i++) {
		total +=
			MIN(out->tunnels[i].stream_establish_count,
			    ARRAY_SIZE(out->tunnels[i].stream_establish_ns));
	}
	if (total == 0) {
		return 0;
	}
	int_fast64_t *const samples = malloc(total * sizeof(*samples));
	if (samples == NULL) {
		LOGOOM();
		return 0;
	}
	/* Gathered inline: the write bound is the same MIN() total was summed
	 * from, so samples[] cannot overrun. */
	size_t n = 0;
	for (size_t i = 0; i < out->num_tunnels; i++) {
		const struct tunnel_stats *const restrict ts = &out->tunnels[i];
		const size_t ring = ARRAY_SIZE(ts->stream_establish_ns);
		const size_t count = MIN(ts->stream_establish_count, ring);
		for (size_t j = 0; j < count; j++) {
			const size_t idx =
				(ts->stream_establish_count - j - 1) % ring;
			samples[n++] = ts->stream_establish_ns[idx];
		}
	}
	struct latency_percentiles p;
	percentiles_from_samples(samples, n, &p);
	out->stream_establish_p50 = p.p50;
	out->stream_establish_p90 = p.p90;
	out->stream_establish_p99 = p.p99;
	out->stream_establish_pmax = p.pmax;
	free(samples);
	return n;
}

struct server_stats *
server_stats(const struct server *restrict s, const bool want_tunnel_latency)
{
	/* Upper bound on tunnels[]: mux_tunnel (0 or 1) + every identity-pool
	 * member + every identity_tunnels[] staging slot + every accepted tunnel.
	 * Using table_size for the accepted side rather than a classify pass avoids
	 * a two-pass race: the session thread can flip a peer identity between a
	 * count pass and a populate pass, reclassifying a tunnel as unmatched and
	 * overflowing tunnels[]. A few over-allocated slots (pooled accepted or
	 * pooled dialed tunnels never re-emitted here) are harmless; num_tunnels
	 * below reflects the actual fill. */
	size_t n = (s->mux_tunnel != NULL ? 1 : 0) + s->num_identity_tunnels;
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(s->identities, &cursor, NULL, &elem)) {
			n += ((struct identity_listener *)elem)->num_tunnels;
		}
	}
	if (s->accepted_tunnels != NULL) {
		n += table_size(s->accepted_tunnels);
	}

	struct server_stats *out =
		calloc(1, sizeof(*out) + n * sizeof(out->tunnels[0]));
	if (out == NULL) {
		LOGOOM();
		return NULL;
	}

	const struct server_counters *const restrict c = &s->counters;
	out->num_accepted = c->num_accepted;
	out->num_served = c->num_served;
	out->num_accepted_tcp = c->num_accepted_tcp;
	out->num_served_tcp = c->num_served_tcp;
	out->num_accepted_api = c->num_accepted_api;
	out->num_served_api = c->num_served_api;
	out->num_rejected = c->num_rejected;
#if WITH_TLS
	out->num_tls_failures = c->num_tls_failures;
#endif

#if WITH_THREADS
	out->num_session_created = (uint_least64_t)atomic_load_explicit(
		&c->num_session_created, memory_order_relaxed);
	out->num_session_connect = (uint_least64_t)atomic_load_explicit(
		&c->num_session_connect, memory_order_relaxed);
	out->num_session_connected = (uint_least64_t)atomic_load_explicit(
		&c->num_session_connected, memory_order_relaxed);
	out->num_session_disconnected = (uint_least64_t)atomic_load_explicit(
		&c->num_session_disconnected, memory_order_relaxed);
	out->num_session_finalized = (uint_least64_t)atomic_load_explicit(
		&c->num_session_finalized, memory_order_relaxed);
	out->num_sessions = (size_t)atomic_load_explicit(
		&c->num_sessions, memory_order_relaxed);
	out->num_session_halfopen = (size_t)atomic_load_explicit(
		&c->num_session_halfopen, memory_order_relaxed);
#else /* WITH_THREADS */
	out->num_session_created = c->num_session_created;
	out->num_session_connect = c->num_session_connect;
	out->num_session_connected = c->num_session_connected;
	out->num_session_disconnected = c->num_session_disconnected;
	out->num_session_finalized = c->num_session_finalized;
	out->num_sessions = c->num_sessions;
	out->num_session_halfopen = c->num_session_halfopen;
#endif /* WITH_THREADS */

	/* Seed the per-tunnel monotonic totals with what closed tunnels left
	 * behind; the loop below adds every live tunnel on top. */
	out->num_stream_opened = c->closed.num_stream_opened;
	out->num_stream_accepted = c->closed.num_stream_accepted;
	out->num_stream_fastopen = c->closed.num_stream_fastopen;
	out->num_stream_established = c->closed.num_stream_established;
	out->num_stream_succeeded = c->closed.num_stream_succeeded;
	out->num_stream_failed = c->closed.num_stream_failed;
	out->num_reconnects = c->closed.num_reconnects;
	out->num_rst_sent = c->closed.num_rst_sent;
	out->num_rst_recv = c->closed.num_rst_recv;
	out->num_stream_errors = c->closed.num_stream_errors;
	out->num_stream_establish_samples =
		c->closed.num_stream_establish_samples;
	out->traffic_byt_mux_recv = c->closed.traffic_byt_mux_recv;
	out->traffic_byt_mux_sent = c->closed.traffic_byt_mux_sent;
	out->traffic_byt_push_recv = c->closed.traffic_byt_push_recv;
	out->traffic_byt_push_sent = c->closed.traffic_byt_push_sent;
	out->pkt_dgram_sent = c->closed.pkt_dgram_sent;
	out->pkt_dgram_recv = c->closed.pkt_dgram_recv;
	out->pkt_dgram_dropped =
		c->closed.pkt_dgram_dropped + c->num_dgram_unrouted;
	out->byt_dgram_sent = c->closed.byt_dgram_sent;
	out->byt_dgram_recv = c->closed.byt_dgram_recv;

	/* Populate dialed tunnels first; stream aggregation reads their snapshots. */
	size_t idx = 0;
	if (s->mux_tunnel != NULL) {
		struct tunnel_stats *ts = &out->tunnels[idx];
		ts->peer_identity = NULL;
		ts->num_tunnels = 1;
		tunnel_stats(s->mux_tunnel, ts);
		idx++;
	}
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(s->identities, &cursor, NULL, &elem)) {
			const struct identity_listener *const restrict sl =
				elem;
			for (size_t j = 0; j < sl->num_tunnels; j++) {
				/* mux_tunnel can also match a configured
				 * identity.listen key and be pooled; it is
				 * already emitted above as the standalone
				 * mux_tunnel entry, so skip it here to avoid
				 * double-counting its streams/traffic/latency. */
				if (sl->tunnels[j] == s->mux_tunnel) {
					continue;
				}
				struct tunnel_stats *ts = &out->tunnels[idx];
				ts->peer_identity = sl->peer_identity;
				ts->num_tunnels = sl->num_tunnels;
				tunnel_stats(sl->tunnels[j], ts);
				idx++;
			}
		}
	}
	/* Append identity dial-outs still reachable only through their staging
	 * slot: one that has not been pooled -- not yet established, or announcing
	 * an identity no identity.listen entry names -- is invisible to every pass
	 * above, and its reconnect attempts are exactly what the totals must show. */
	for (size_t j = 0; j < s->num_identity_tunnels; j++) {
		struct tunnel *const t = s->identity_tunnels[j];
		if (t == NULL || tunnel_is_pooled(s, t)) {
			continue;
		}
		ASSERT(idx < n);
		if (idx >= n) {
			break;
		}
		struct tunnel_stats *ts = &out->tunnels[idx];
		ts->peer_identity = NULL;
		ts->num_tunnels = 1;
		tunnel_stats(t, ts);
		idx++;
	}
	/* Append accepted tunnels not wired into any identity pool. */
	if (s->accepted_tunnels != NULL) {
		struct unmatched_accepted_ctx unmatched_ctx = {
			.s = s, .out = out, .val = idx, .cap = n
		};
		table_iterate(
			s->accepted_tunnels, collect_unmatched_accepted,
			&unmatched_ctx);
		idx = unmatched_ctx.val;
	}
	out->num_tunnels = idx;

	/* Aggregate stream and traffic counters over every snapshotted tunnel.
	 * Every accepted tunnel is already in out->tunnels[] (as a pool member or
	 * an unmatched-accepted entry), so the totals are summed from it rather
	 * than by sampling tunnels again: each tunnel_stats call copies the ~2 KB
	 * snapshot incl. the 256-entry latency ring, and summing the rows keeps
	 * the totals consistent with them. */
	for (size_t i = 0; i < out->num_tunnels; i++) {
		const struct tunnel_stats *const ts = &out->tunnels[i];
		out->num_streams += ts->num_streams;
		out->num_stream_halfopen += ts->num_stream_halfopen;
		out->num_stream_opened += ts->num_stream_opened;
		out->num_stream_accepted += ts->num_stream_accepted;
		out->num_stream_fastopen += ts->num_stream_fastopen;
		out->num_stream_established += ts->num_stream_established;
		out->num_stream_succeeded += ts->num_stream_succeeded;
		out->num_stream_failed += ts->num_stream_failed;
		out->num_reconnects += ts->num_reconnects;
		out->num_rst_sent += ts->num_rst_sent;
		out->num_rst_recv += ts->num_rst_recv;
		out->num_stream_errors += ts->num_stream_errors;
		out->num_stream_establish_samples += ts->stream_establish_count;
		out->recv_buffered_bytes += ts->recv_buffered_bytes;
		out->send_buffered_frames += ts->send_buffered_frames;
		out->unacked_frames += ts->unacked_frames;
		out->traffic_byt_mux_recv += ts->byt_mux_recv;
		out->traffic_byt_mux_sent += ts->byt_mux_sent;
		out->traffic_byt_push_recv += ts->byt_push_recv;
		out->traffic_byt_push_sent += ts->byt_push_sent;
		out->pkt_dgram_sent += ts->pkt_dgram_sent;
		out->pkt_dgram_recv += ts->pkt_dgram_recv;
		out->pkt_dgram_dropped += ts->pkt_dgram_dropped;
		out->byt_dgram_sent += ts->byt_dgram_sent;
		out->byt_dgram_recv += ts->byt_dgram_recv;
		out->num_flows += ts->num_flows;
	}

	if (want_tunnel_latency) {
		calc_tunnel_percentiles(out);
	}
	out->stream_establish_count = calc_stream_percentiles(out);
	out->evlog = &s->evlog;

	return out;
}

/* True if at least one tunnel in the pool is established and thus usable for
 * forwarding right now. */
static bool listener_has_live_tunnel(
	struct tunnel *const *const restrict tunnels, const size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (tunnel_state(tunnels[i]) == MUX_STATE_ESTABLISHED) {
			return true;
		}
	}
	return false;
}

/* True if this pool contains a dialed tunnel whose destination remains
 * configured. Passive sessions and removed dial-outs cannot redial on demand. */
static bool identity_listener_has_dialout(
	const struct server *restrict s,
	const struct identity_listener *restrict sl)
{
	for (size_t i = 0; i < sl->num_tunnels; i++) {
		const struct tunnel *const t = sl->tunnels[i];
		if (t == s->mux_tunnel && s->conf->mux_connect != NULL) {
			return true;
		}
		const size_t n =
			MIN(s->num_identity_tunnels,
			    s->conf->identity.mux_connect_count);
		for (size_t j = 0; j < n; j++) {
			if (s->identity_tunnels[j] == t &&
			    s->conf->identity.mux_connect[j] != NULL) {
				return true;
			}
		}
	}
	return false;
}

size_t server_offline_listeners(
	const struct server *restrict s,
	void (*cb)(void *data, const char *identifier), void *data)
{
	const struct config *const restrict conf = s->conf;
	size_t offline = 0;

	/* The top-level local listener forwards over mux_tunnel, falling back to
	 * any accepted tunnel (mirrors tcp_serve). */
	if (conf->listen != NULL) {
		bool live;
		if (conf->mux.idle_timeout != 0 && conf->mux_connect != NULL) {
			/* On-demand mux_tunnel intentionally disconnects when
			 * idle, so a missing/non-established tunnel here is
			 * expected rather than an error -- but only for a
			 * listener actually backed by one (mux_connect != NULL).
			 * Applying this unconditionally silenced a genuinely
			 * dead accepted-tunnel-only listener on a mixed
			 * mux_listen (server mode) + identity.mux_connect
			 * (on-demand) deployment, where idle_timeout is set for
			 * the unrelated identity peers. */
			live = true;
		} else {
			live = s->mux_tunnel != NULL &&
			       tunnel_state(s->mux_tunnel) ==
				       MUX_STATE_ESTABLISHED;
			if (!live && s->accepted_tunnels != NULL) {
				size_t cursor = 0;
				void *elem;
				while (table_next(
					s->accepted_tunnels, &cursor, NULL,
					&elem)) {
					if (tunnel_state(elem) ==
					    MUX_STATE_ESTABLISHED) {
						live = true;
						break;
					}
				}
			}
		}
		if (!live) {
			offline++;
			if (cb != NULL) {
				cb(data, conf->listen);
			}
		}
	}

	/* A routing-only peer has no forwarding listener to check. A listening
	 * pool may contain passive sessions, dial-outs, or both; only a
	 * configured dial-out in that pool makes idle disconnects healthy. */
	for (size_t i = 0; i < conf->identity.peers_count; i++) {
		const struct identity_peer *const peer =
			&conf->identity.peers[i];
		if (peer->listen == NULL) {
			continue;
		}
		void *elem;
		if (table_find(s->identities, peer->id, &elem)) {
			const struct identity_listener *const sl = elem;
			if (listener_has_live_tunnel(
				    sl->tunnels, sl->num_tunnels) ||
			    (conf->mux.idle_timeout != 0 &&
			     identity_listener_has_dialout(s, sl))) {
				continue;
			}
		}
		offline++;
		if (cb != NULL) {
			cb(data, peer->id);
		}
	}
	return offline;
}

#if WITH_TLS
/* Decode the configured hex keys and derive each one's wire label.  The table
 * outlives the TLS contexts (it backs the server's lookup callback) and is the
 * same map the tunnel layer uses to turn an authenticated label back into a
 * peer identity, so it is built once and owned by struct server. */
struct psk_table *server_psk_table_new(const struct config *restrict conf)
{
	if (conf->tls_psk_count == 0) {
		return NULL;
	}
	struct psk_table *const t = calloc(
		1, sizeof(*t) + conf->tls_psk_count * sizeof(t->entries[0]));
	if (t == NULL) {
		LOGOOM();
		return NULL;
	}
#if WITH_THREADS
	atomic_init(&t->holds, (size_t)0);
#else
	t->holds = 0;
#endif
	t->count = conf->tls_psk_count;
	for (size_t i = 0; i < t->count; i++) {
		const struct psk_entry *const restrict src = &conf->tls_psk[i];
		struct psk_table_entry *const restrict e = &t->entries[i];
		const size_t hex_len = strlen(src->hex);
		/* conf_parse (an inline key) or conf_inline_pem (a loaded one)
		 * already validated length, parity and alphabet. */
		e->key_len = hex_len / 2u;
		for (size_t j = 0; j < e->key_len; j++) {
			const int hi = unhex(src->hex[j * 2]);
			const int lo = unhex(src->hex[j * 2 + 1]);
			ASSERT(hi >= 0 && lo >= 0);
			e->key[j] = (unsigned char)((hi << 4) | lo);
		}
		size_t label_len = sizeof(e->label);
		if (!tls_psk_label(e->key, e->key_len, e->label, &label_len)) {
			LOGE_F("tls.psk.%s: failed to derive the identity label",
			       src->id);
			server_psk_table_free(t);
			return NULL;
		}
		(void)snprintf(e->identity, sizeof(e->identity), "%s", src->id);
	}
	return t;
}

void server_psk_table_free(struct psk_table *restrict t)
{
	if (t == NULL) {
		return;
	}
	for (size_t i = 0; i < t->count; i++) {
		tls_secure_erase(t->entries[i].key, sizeof(t->entries[i].key));
	}
	free(t);
}

void server_psk_table_hold(struct psk_table *restrict t)
{
	if (t == NULL) {
		return;
	}
#if WITH_THREADS
	/* Relaxed: every hold is taken on the server thread, the same one that
	 * reads them. */
	(void)atomic_fetch_add_explicit(
		&t->holds, (size_t)1, memory_order_relaxed);
#else
	t->holds++;
#endif
}

void server_psk_table_release(struct psk_table *restrict t)
{
	if (t == NULL) {
		return;
	}
#if WITH_THREADS
	/* Release, paired with the sweep's acquire load: whatever the holder did
	 * before giving the hold back -- a tunnel publishing the resolver it just
	 * adopted, a TLS context finishing its last handshake -- is visible to the
	 * sweep that sees the count reach zero. */
	(void)atomic_fetch_sub_explicit(
		&t->holds, (size_t)1, memory_order_release);
#else
	t->holds--;
#endif /* WITH_THREADS */
}

const char *server_psk_identity_of(
	const struct psk_table *restrict t, const char *restrict label)
{
	if (t == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < t->count; i++) {
		if (strcmp(t->entries[i].label, label) == 0) {
			return t->entries[i].identity;
		}
	}
	return NULL;
}
#endif /* WITH_TLS */
