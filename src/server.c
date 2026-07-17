/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "api_server.h"
#include "conf.h"
#include "listener.h"
#include "mux/mux.h"
#include "shim/tls.h"
#include "shim/util.h"
#include "tunnel.h"

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
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/shared_mutex.h"
#include "sync/task.h"
#endif
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/slog.h"

#include <ev.h>

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

static bool server_verify_peer(void *user, const char *peer_id)
{
	struct server *const restrict s = user;
#if WITH_THREADS
	THRD_ASSERT(smtx_sharedlock(&s->accepted_mu));
#endif
	const bool matched = table_find(s->identities, peer_id, NULL);
#if WITH_THREADS
	THRD_ASSERT(smtx_sharedunlock(&s->accepted_mu));
#endif
	return matched;
}

static uint_least64_t server_alloc_index(void *user)
{
	return ++((struct server *)user)->next_tunnel_index;
}

static void server_inc_reconnect(void *user)
{
#if WITH_THREADS
	(void)atomic_fetch_add_explicit(
		&((struct server *)user)->counters.num_reconnects,
		(uint_least64_t)1, memory_order_relaxed);
#else
	((struct server *)user)->counters.num_reconnects++;
#endif
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
		.num_rst_sent = &s->counters.num_rst_sent,
		.num_rst_recv = &s->counters.num_rst_recv,
		.num_stream_errors = &s->counters.num_stream_errors,
		.recv_buffered_bytes = &s->counters.recv_buffered_bytes,
		.send_buffered_frames = &s->counters.send_buffered_frames,
		.unacked_frames = &s->counters.unacked_frames,
	};
}

static struct tunnel_context
server_make_tunnel_context(struct server *restrict s)
{
	return (struct tunnel_context){
#if WITH_THREADS
		.post_task = server_post_task,
		.flush_tasks = server_flush_tasks,
#endif
		.verify_peer = server_verify_peer,
		.alloc_index = server_alloc_index,
		.inc_reconnect = server_inc_reconnect,
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

/* Pick the next tunnel from sl's pool using round-robin.
 * Returns NULL when the pool is empty. */
static struct tunnel *
identity_listener_pick(struct identity_listener *restrict sl)
{
	if (sl->num_tunnels == 0) {
		return NULL;
	}
	if (sl->rr_next >= sl->num_tunnels) {
		sl->rr_next = 0;
	}
	struct tunnel *t = sl->tunnels[sl->rr_next];
	sl->rr_next = (sl->rr_next + 1) % sl->num_tunnels;
	return t;
}

/* Fold a closing tunnel's cumulative traffic into the server-wide totals before
 * tunnel_close() frees it and that per-tunnel data is gone (see struct
 * server_counters' "Traffic bytes for closed tunnels" note). */
static void fold_closed_tunnel_traffic(
	struct server *restrict srv, struct tunnel *restrict t)
{
	struct tunnel_stats snap;
	tunnel_stats(t, &snap);
	srv->counters.traffic_byt_mux_recv += snap.byt_mux_recv;
	srv->counters.traffic_byt_mux_sent += snap.byt_mux_sent;
	srv->counters.traffic_byt_push_recv += snap.byt_push_recv;
	srv->counters.traffic_byt_push_sent += snap.byt_push_sent;
}

/* Stop sl's listener and close every tunnel in its pool, then free it.
 * Used when sl fails to survive a config-reload identity-table rebuild
 * (OOM): once s->identities is swapped to the new table, an sl left out
 * of it is unreachable via tunnel_iter/handle_closed pool removal, so its
 * listener and tunnels must be torn down explicitly here instead of
 * leaking as a "ghost" that keeps serving into a pool nothing can find
 * anymore. A pooled tunnel can also be live in srv->accepted_tunnels or be
 * srv->mux_tunnel (server_on_established wires it into both without
 * unregistering either), so each is unregistered here too -- mirroring
 * handle_closed's full removal scope -- before tunnel_close() frees it;
 * otherwise a stale pointer would survive in a table a resume lookup or
 * tcp_serve still consults. */
static void identity_listener_discard(
	struct server *restrict srv, struct identity_listener *restrict sl)
{
	listener_stop(&sl->listener, srv->loop);
	for (size_t j = 0; j < sl->num_tunnels; j++) {
		struct tunnel *const t = sl->tunnels[j];
		if (tunnel_is_accepted(t)) {
#if WITH_THREADS
			THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
			srv->accepted_tunnels = table_del(
				srv->accepted_tunnels, tunnel_session_id(t),
				NULL);
#if WITH_THREADS
			THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
		} else if (t == srv->mux_tunnel) {
			srv->mux_tunnel = NULL;
		}
		for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
			if (srv->identity_tunnels[i] == t) {
				srv->identity_tunnels[i] = NULL;
				break;
			}
		}
		fold_closed_tunnel_traffic(srv, t);
		tunnel_close(t);
	}
	free((void *)sl->tunnels);
	free(sl);
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

/* Upper bound on the distinct tunnels server_snapshot_tunnels() can yield, for
 * sizing its output buffer: the one dialed mux_tunnel (the +1), every
 * identity_listener's whole tunnels[] pool (round-robin, more than one tunnel
 * per peer -- so the sum of num_tunnels, not table_size(identities)), every
 * identity_tunnels[] slot, and every accepted session. Single-sourced for all
 * four snapshot call sites: a drift between copies previously undersized the
 * buffer (the P0 fixed in f333738c). The ASSERT bounds one malloc() against the
 * 16-bit stream-ID space. */
static size_t server_snapshot_cap(const struct server *restrict s)
{
	size_t identity_pool_tunnels = 0;
	size_t cursor = 0;
	void *elem;
	while (table_next(s->identities, &cursor, NULL, &elem)) {
		const struct identity_listener *const restrict sl = elem;
		identity_pool_tunnels += sl->num_tunnels;
	}
	const size_t n =
		(s->accepted_tunnels != NULL ? table_size(s->accepted_tunnels) :
					       0) +
		1 + identity_pool_tunnels + s->num_identity_tunnels;
	ASSERT(n <= 65536);
	return n;
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
 * bound -- which equals the raw yield count (it sums every phase's size), so
 * the with-duplicates sequence collected below always fits.
 *
 * Collect the raw sequence, then sort-and-dedup by pointer: O(n log n) instead
 * of the previous O(n^2) membership scan (worst case ~2e9 comparisons on the
 * server loop at the 65536-tunnel bound), and robust to any yield multiplicity
 * without depending on which phases can overlap. */
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

/* Log session establishment/close with peer address formatting */
#define SESSION_EVLOGF(srv, t, fmt, ...)                                       \
	do {                                                                   \
		char id_buf_[256];                                             \
		const char *id_ = tunnel_peer_identity_copy(                   \
					  (t), id_buf_, sizeof(id_buf_)) ?     \
					  id_buf_ :                            \
					  NULL;                                \
		if (id_ == NULL) {                                             \
			id_ = tunnel_peer_id(t);                               \
		}                                                              \
		if (id_ != NULL) {                                             \
			server_evlogf((srv), "`%s' " fmt, id_, __VA_ARGS__);   \
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

static void server_on_established(
	void *data, struct tunnel *restrict t, int_fast64_t lat_ns)
{
	struct server *const restrict srv = data;
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session established", tunnel_fd(t),
	       is_server ? "server" : "client");
	session_on_connected(srv, t, "established", lat_ns);

	if (!is_server) {
		/* Wire the dialed session into the matching identity pool (guard
		 * against duplicate wiring on re-ESTABLISHED). The staging slot
		 * is deliberately left pointing at the tunnel for its whole life
		 * (see below), not cleared here. */
		char peer_id_buf[256];
		const char *const peer_id =
			tunnel_peer_identity_copy(
				t, peer_id_buf, sizeof(peer_id_buf)) ?
				peer_id_buf :
				NULL;
		struct identity_listener *sl = NULL;
		if (peer_id != NULL) {
			void *elem = NULL;
			if (table_find(srv->identities, peer_id, &elem)) {
				sl = elem;
			}
		}
		if (sl == NULL) {
			/* s->mux_tunnel (plain client mode: mux_connect only, no
			 * identity) is reached via tcp_serve, not an identity pool, so
			 * having no matching identity.listen entry is normal for it --
			 * warning would fire on every establishment and reconnect, and
			 * its "staging slot" remediation is wrong for a tunnel that has
			 * none. Restrict the warning to identity dial-outs, which are
			 * the dialed tunnels that do occupy an identity_tunnels[] slot. */
			if (t != srv->mux_tunnel) {
				LOGW_F("[fd:%d] dialed session identity \"%s\" matches"
				       " no configured identity.listen entry; tunnel"
				       " stays reachable only through its staging slot",
				       tunnel_fd(t),
				       peer_id != NULL ? peer_id : "(none)");
			}
			return;
		}
		if (!identity_listener_contains(sl, t)) {
			/* OOM here leaves the tunnel unpooled this pass; it
			 * stays reachable through its staging slot and a later
			 * re-ESTABLISHED retries the add. */
			(void)identity_listener_add(sl, t);
		}
		/* Deliberately keep identity_tunnels[i] pointing at the tunnel
		 * for its whole life. Config reload finds the live dialed tunnel
		 * by slot (server_reload_identity_tunnels treats a NULL slot as
		 * "closed" and tunnel_set_reload_connect matches by slot); nulling
		 * it here on establishment made reload mistake the still-live
		 * pooled tunnel for a closed slot and dial an unbounded stream of
		 * duplicates. tunnel_iter_next now yields the tunnel via both its
		 * pool and its slot, which every consumer already dedupes -- an
		 * accepted tunnel likewise appears in both a pool and
		 * accepted_tunnels. */
		return;
	}
	char peer_identity_buf[256];
	const char *const peer_identity =
		tunnel_peer_identity_copy(
			t, peer_identity_buf, sizeof(peer_identity_buf)) ?
			peer_identity_buf :
			NULL;
	if (peer_identity != NULL) {
		void *elem = NULL;
		if (table_find(srv->identities, peer_identity, &elem) &&
		    !identity_listener_contains(elem, t)) {
			(void)identity_listener_add(elem, t);
		}
	}
}

static void
server_on_resumed(void *data, struct tunnel *restrict t, int_fast64_t lat_ns)
{
	struct server *const restrict srv = data;
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session resumed", tunnel_fd(t),
	       is_server ? "server" : "client");
	session_on_connected(srv, t, "resumed", lat_ns);
}

static void
handle_disconnected(struct server *restrict srv, struct tunnel *restrict t)
{
	const bool is_server = tunnel_is_accepted(t);
	LOGN_F("[fd:%d] %s session disconnected", tunnel_fd(t),
	       is_server ? "server" : "client");
	SESSION_EVLOG(srv, t, "session disconnected");
}

static void handle_closed(
	struct server *restrict srv, struct tunnel *restrict t,
	const union mux_event_data edata)
{
	LOGN_F("[fd:%d] session closed", tunnel_fd(t));
	if (edata.closed.expired) {
		SESSION_EVLOG(srv, t, "suspended session expired");
	}

	if (tunnel_is_accepted(t)) {
#if WITH_THREADS
		THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
		srv->accepted_tunnels = table_del(
			srv->accepted_tunnels, tunnel_session_id(t), NULL);
#if WITH_THREADS
		THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
	} else if (t == srv->mux_tunnel) {
		srv->mux_tunnel = NULL;
	}
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(srv->identities, &cursor, NULL, &elem)) {
			if (identity_listener_remove(elem, t)) {
				break;
			}
		}
	}
	for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
		if (srv->identity_tunnels[i] == t) {
			srv->identity_tunnels[i] = NULL;
			break;
		}
	}

	/* Join the tunnel thread; the relay stopped it before dispatching
	 * this event, so ev_run() has already returned by now. */
	fold_closed_tunnel_traffic(srv, t);
	tunnel_close(t);

	/* During graceful shutdown, exit when no accepted or dialed sessions remain. */
	if (srv->shutting_down && table_size(srv->accepted_tunnels) == 0 &&
	    srv->mux_tunnel == NULL) {
		bool any_peer = false;
		{
			size_t cursor = 0;
			void *elem;
			while (table_next(
				srv->identities, &cursor, NULL, &elem)) {
				if (((struct identity_listener *)elem)
					    ->num_tunnels > 0) {
					any_peer = true;
					break;
				}
			}
		}
		/* identity.mux_connect dial-outs live in the identity_tunnels[]
		 * staging array for their whole lifetime (a non-NULL slot means a
		 * live dial-out, handshaking or established); they must keep the
		 * graceful-shutdown drain alive too. */
		for (size_t i = 0; !any_peer && i < srv->num_identity_tunnels;
		     i++) {
			if (srv->identity_tunnels[i] != NULL) {
				any_peer = true;
			}
		}
		if (!any_peer) {
			ev_timer_stop(srv->loop, &srv->w_maintenance);
			ev_break(srv->loop, EVBREAK_ALL);
		}
	}
}

static void server_relay_event(
	void *data, struct tunnel *t, const enum mux_event event,
	const union mux_event_data edata)
{
	struct server *const restrict srv = data;
	switch (event) {
	case MUX_EVENT_CONNECT:
	case MUX_EVENT_ESTABLISHED:
		/* Routed to on_established; not fired through on_event. */
	case MUX_EVENT_CONNECT_FAILED:
	case MUX_EVENT_SUSPENDED:
		/* Handled by the tunnel layer; no server-level action needed. */
	case MUX_EVENT_RESUMED:
		/* Routed to on_resumed; not fired through on_event. */
		break;
	case MUX_EVENT_LOST:
		handle_disconnected(srv, t);
		break;
	case MUX_EVENT_STREAM_ESTABLISHED:
		/* Consumed by the tunnel layer before reaching the relay. */
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
	struct identity_listener *const restrict sl = DOWNCAST(
		struct listener, struct identity_listener, listener, l);
	struct tunnel *const restrict t = identity_listener_pick(sl);
	if (t == NULL) {
		LOGD_F("[fd:%d] no session for identity \"%s\","
		       " closing",
		       fd, sl->peer_identity);
		socket_close(fd);
		return;
	}
	l->srv->counters.num_served_tcp++;
	tunnel_open_stream(t, fd);
}

static void tcp_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	(void)loop;
	(void)sa;
	struct server *const restrict srv = l->srv;
	struct tunnel *restrict t = srv->mux_tunnel;
	if (t == NULL && srv->accepted_tunnels != NULL) {
		/* Round-robin over accepted_tunnels: resume from the cursor
		 * left by the previous call, wrapping once it runs off the end. */
		void *elem = NULL;
		if (!table_next(
			    srv->accepted_tunnels, &srv->accepted_rr_cursor,
			    NULL, &elem)) {
			srv->accepted_rr_cursor = 0;
			(void)table_next(
				srv->accepted_tunnels, &srv->accepted_rr_cursor,
				NULL, &elem);
		}
		t = elem;
	}
	if (t == NULL) {
		LOGD_F("[fd:%d] no active session, closing", fd);
		socket_close(fd);
		return;
	}

	srv->counters.num_served_tcp++;
	tunnel_open_stream(t, fd);
}

static bool is_startup_limited(const struct server *restrict srv)
{
	const struct config *const restrict conf = srv->conf;
	const struct server_counters *const restrict stats = &srv->counters;
#if WITH_THREADS
	const size_t n_sessions = atomic_load_explicit(
		&stats->num_sessions, memory_order_relaxed);
	const size_t n_halfopen = atomic_load_explicit(
		&stats->num_session_halfopen, memory_order_relaxed);
#else
	const size_t n_sessions = stats->num_sessions;
	const size_t n_halfopen = stats->num_session_halfopen;
#endif

	/* n_sessions/n_halfopen are the counts before this connection is
	 * admitted, so the boundary itself (count == limit) is still one too
	 * many once this one is added -- reject at the boundary, not past it
	 * (matches the README's "the first N are accepted freely" and
	 * doc/impl.md's "hard cap ... excess connections are rejected"
	 * wording, both of which mean count N is already full). */
	if (conf->max_sessions > 0 &&
	    n_sessions >= (size_t)conf->max_sessions) {
		LOGVV("session limit exceeded, rejecting new connection");
		return true;
	}

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

static struct mux_config server_make_mux_config(struct server *restrict srv)
{
	return conf_get_mux(srv->conf);
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

static bool server_register_session(struct server *restrict s, struct tunnel *t)
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
	if (elem == t) {
		LOGOOM();
		tunnel_close(t);
		return false;
	}
	ASSERT(elem == NULL);
	return true;
}

static void mux_serve(
	struct listener *l, struct ev_loop *loop, const int fd,
	const struct sockaddr *sa)
{
	(void)loop;
	struct server *const restrict srv = l->srv;
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

	struct mux_config mux_conf = server_make_mux_config(srv);
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
		.peer_id = NULL,
		.cnt = &cnts,
#if WITH_TLS
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
		 * tunnel in accepted_tunnels, and do not count it as served.
		 * table_del can rehash/free, so it must hold accepted_mu against
		 * concurrent shared-lock readers (server_on_resume_lookup), as
		 * every other accepted_tunnels mutation does. */
#if WITH_THREADS
		THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
		srv->accepted_tunnels = table_del(
			srv->accepted_tunnels, tunnel_session_id(t), NULL);
#if WITH_THREADS
		THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
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
/* Zero every plaintext TLS credential staged in conf: the private key, each
 * trust-anchor entry, and the concatenated authcerts_bundle (a separate
 * allocation from the per-entry tls_authcerts[] strings). */
static void server_cleanse_tls_config(const struct config *restrict conf)
{
	if (conf->tls_cert != NULL) {
		tls_secure_erase(conf->tls_cert, strlen(conf->tls_cert));
	}
	if (conf->tls_key != NULL) {
		tls_secure_erase(conf->tls_key, strlen(conf->tls_key));
	}
	for (size_t i = 0; i < conf->tls_authcerts_count; i++) {
		if (conf->tls_authcerts[i] != NULL) {
			tls_secure_erase(
				conf->tls_authcerts[i],
				strlen(conf->tls_authcerts[i]));
		}
	}
	if (conf->tls_authcerts_bundle != NULL) {
		tls_secure_erase(
			conf->tls_authcerts_bundle,
			strlen(conf->tls_authcerts_bundle));
	}
}

/* Build fresh server and client TLS contexts from conf; shared by startup and
 * reload. True on success, false on failure (any partial context freed).
 * conf's plaintext credentials are erased before returning either way. */
static bool server_make_tls_contexts(
	const struct config *restrict conf,
	struct tls_context **restrict out_server,
	struct tls_context **restrict out_client)
{
	*out_server = NULL;
	*out_client = NULL;
	if (conf->tls_cert == NULL || conf->tls_key == NULL) {
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
		.ciphersuites = conf->tls_ciphersuites,
		.alpn = conf->tls_alpn,
		.sni = conf->tls_sni,
		.kernel_offload = conf->tls_kernel_offload,
		.readahead = conf->mux.readahead > 0,
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
	server_cleanse_tls_config(conf);
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

/* Single-pass reload: update addresses and apply drain config per tunnel.
 * Sessions drain when their last stream closes; outbound tunnels then
 * reconnect with the fresh config. */
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
		if (new_conf->mux_connect != NULL) {
			opts->update_connect_addr = true;
			opts->connect_addr = new_conf->mux_connect;
		} else {
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

static void server_drain_tunnels(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf
#if WITH_TLS
	,
	struct tls_context *new_client_tlsctx
#endif
)
{
	const bool forward_changed =
		!strnull_eq(old_conf->connect, new_conf->connect);
	/* drain_conf.tlsctx stays NULL here; each dialed tunnel gets its own
	 * handle below, while accepted tunnels keep none (they hold a
	 * tls_connection, not a client context). */
	const struct mux_config drain_conf = conf_get_mux(new_conf);
	const size_t old_ni = s->num_identity_tunnels;
	const size_t new_ni = new_conf->identity.mux_connect_count;

	/* Snapshot and dedupe first so each live tunnel is drained exactly
	 * once. Heap-allocated (not a VLA): the live tunnel count is
	 * unbounded in principle. */
	const size_t n = server_snapshot_cap(s);
	struct tunnel **const snapshot =
		(struct tunnel **)malloc(n * sizeof(struct tunnel *));
	if (snapshot == NULL) {
		/* Best-effort: skip draining this reload pass rather than fail
		 * the whole reload; live sessions keep running on their old
		 * settings. */
		LOGOOM();
		return;
	}
	const size_t count = server_snapshot_tunnels(s, snapshot, n);
	for (size_t i = 0; i < count; i++) {
		struct tunnel *const t = snapshot[i];
		struct tunnel_reload_opts opts = {
			.conf = drain_conf,
			.drain = true,
			.mux_socket = new_conf->mux_tcp,
			.local_socket = new_conf->tcp,
			.update_forward_addr = forward_changed,
			.forward_addr = new_conf->connect,
		};
#if WITH_TLS
		/* Per-dialed-tunnel TLS handle (ownership transferred to
		 * tunnel_reload); on OOM the tunnel keeps its current context. */
		if (!tunnel_is_accepted(t) && new_client_tlsctx != NULL) {
			opts.conf.tlsctx = tls_ctx_ref(new_client_tlsctx);
		}
#endif
		tunnel_set_reload_connect(
			&opts, s, t, old_conf, new_conf, old_ni, new_ni);
		tunnel_reload(t, &opts);
	}
	free((void *)snapshot);
}

/* Stop l if running, then start it at new_addr if non-NULL. conf_key names
 * the config field used in error messages; warn_if_public logs a warning
 * when the resolved address is not loopback/link-local/site-local. */
static void server_restart_listener(
	struct listener *restrict l, struct ev_loop *restrict loop,
	const char *new_addr, const char *conf_key, const char *kind,
	const bool warn_if_public)
{
	listener_stop(l, loop);
	if (new_addr == NULL) {
		return;
	}
	union sockaddr_max addr;
	if (!resolve_bindaddr(&addr, new_addr, SA_RESOLVE_TCP)) {
		/* %.256s: schema maxLength now bounds listen/mux_listen/
		 * api_listen to 261 octets (conf_schema.json), so this only
		 * guards the log line, not an actual attacker-sized string. */
		LOGE_F("failed to parse %s address on reload: %.256s", conf_key,
		       new_addr);
		return;
	}
	if (warn_if_public) {
		const enum ipclass cls = sa_ipclassify(&addr.sa);
		if (cls != IPCLASS_LOOPBACK && cls != IPCLASS_LINKLOCAL &&
		    cls != IPCLASS_SITELOCAL) {
			LOGW("binding API server to non-local address may be insecure");
		}
	}
	if (!listener_start(l, loop, &addr.sa)) {
		LOGE_F("failed to restart %s listener on reload: %s", conf_key,
		       new_addr);
		return;
	}
	if (LOGLEVEL(NOTICE)) {
		char str[64];
		(void)sa_format(str, sizeof(str), &addr.sa);
		LOGN_F("listening on %s (%s)", str, kind);
	}
}

/* Stop and restart tcp, mux, and api listeners whose bind addresses changed. */
static void server_reload_listeners(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf)
{
	struct ev_loop *const loop = s->loop;
	if (!strnull_eq(old_conf->listen, new_conf->listen)) {
		server_restart_listener(
			&s->local_listener, loop, new_conf->listen, "listen",
			"TCP", false);
	}
	if (!strnull_eq(old_conf->mux_listen, new_conf->mux_listen)) {
		server_restart_listener(
			&s->mux_listener, loop, new_conf->mux_listen,
			"mux_listen", "mux", false);
	}
	if (!strnull_eq(old_conf->api_listen, new_conf->api_listen)) {
		server_restart_listener(
			&s->api_listener, loop, new_conf->api_listen,
			"api_listen", "API server", true);
	}
}

/* Rebuild the identity-listener hashtable for a changed peer table: stop old
 * listeners, migrate matching tunnel pools, start new ones, replace
 * s->identities. */
/* Resolve listen and (re)start sl's identity listener, logging the outcome. */
static void identity_listener_start(
	struct identity_listener *restrict sl, struct ev_loop *loop,
	const char *restrict listen, const char *restrict id)
{
	union sockaddr_max addr;
	if (!resolve_bindaddr(&addr, listen, SA_RESOLVE_TCP)) {
		LOGE_F("failed to parse identity listen address on reload: %.256s",
		       listen);
		return;
	}
	if (!listener_start(&sl->listener, loop, &addr.sa)) {
		LOGE_F("failed to restart identity listener for \"%s\" on reload",
		       id);
		return;
	}
	if (LOGLEVEL(NOTICE)) {
		char str[64];
		(void)sa_format(str, sizeof(str), &addr.sa);
		LOGN_F("identity \"%s\" listening on %s (TCP)", id, str);
	}
}

static void server_reload_identities_changed(
	struct server *restrict s, const struct config *restrict new_conf,
	const size_t new_np)
{
	/* Stop old identity listeners. */
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(s->identities, &cursor, NULL, &elem)) {
			struct identity_listener *restrict sl = elem;
			listener_stop(&sl->listener, s->loop);
		}
	}

	struct hashtable *new_tbl = NULL;
	if (new_np > 0) {
		new_tbl = table_new(&(struct table_opts){
			.hash = TABLE_OPTS_STR.hash,
			.eq = TABLE_OPTS_STR.eq,
			.flags = TABLE_FAST,
		});
		if (new_tbl == NULL) {
			LOGOOM();
		}
	}

	if (new_tbl != NULL) {
		for (size_t i = 0; i < new_np; i++) {
			const struct identity_peer *restrict p =
				&new_conf->identity.peers[i];
			struct identity_listener *restrict sl =
				malloc(sizeof(*sl));
			if (sl == NULL) {
				LOGOOM();
				break;
			}
			sl->peer_identity = p->id;
			sl->tunnels = NULL;
			sl->num_tunnels = 0;
			sl->cap_tunnels = 0;
			sl->rr_next = 0;
			/* Migrate live tunnel pool if peer_identity matches. */
			if (p->id != NULL) {
				void *old_elem = NULL;
				if (table_find(
					    s->identities, p->id, &old_elem)) {
					struct identity_listener
						*restrict old_sl = old_elem;
					sl->tunnels = old_sl->tunnels;
					sl->num_tunnels = old_sl->num_tunnels;
					sl->cap_tunnels = old_sl->cap_tunnels;
					sl->rr_next = old_sl->rr_next;
					old_sl->tunnels = NULL;
					old_sl->num_tunnels = 0;
					old_sl->cap_tunnels = 0;
				}
			}
			listener_init(
				&sl->listener, &new_conf->tcp,
				identity_tcp_serve, s,
				&s->counters.num_accepted_tcp);
			if (p->listen != NULL) {
				identity_listener_start(
					sl, s->loop, p->listen, p->id);
			}
			void *slot = sl;
			new_tbl = table_set(new_tbl, sl->peer_identity, &slot);
			if (slot == sl) {
				/* OOM: sl not inserted. Discard it (stopping the
				 * listener and closing every tunnel already
				 * migrated into it), or they are orphaned and
				 * permanently unreachable. */
				identity_listener_discard(s, sl);
				LOGOOM();
			} else {
				ASSERT(slot == NULL);
			}
		}
	}

	/* Free orphaned old entries: identity_listener_discard() closes and
	 * unregisters any tunnel a removed peer's sl still owns; a migrated
	 * sl's tunnels[] is already empty, so this just frees it. */
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(s->identities, &cursor, NULL, &elem)) {
			struct identity_listener *restrict sl = elem;
			identity_listener_discard(s, sl);
		}
	}
	/* Session threads read s->identities under accepted_mu (shared) in
	 * tunnel handle_connected; hold it exclusive across the free+swap so a
	 * concurrent lookup never observes a freed or half-swapped table. */
#if WITH_THREADS
	THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
	table_free(s->identities);
	s->identities = new_tbl;
#if WITH_THREADS
	THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
}

/* Rebuild the identity-listener hashtable if the peer table changed; else fix
 * peer_identity and socket_opts pointers into the new config. */
static void server_reload_identities(
	struct server *restrict s, const struct config *restrict old_conf,
	const struct config *restrict new_conf)
{
	const size_t old_np = old_conf->identity.peers_count;
	const size_t new_np = new_conf->identity.peers_count;
	bool peers_changed = (old_np != new_np);
	for (size_t i = 0; !peers_changed && i < new_np; i++) {
		if (!strnull_eq(
			    old_conf->identity.peers[i].id,
			    new_conf->identity.peers[i].id) ||
		    !strnull_eq(
			    old_conf->identity.peers[i].listen,
			    new_conf->identity.peers[i].listen)) {
			peers_changed = true;
		}
	}
	if (!peers_changed) {
		/* Same peer table: fix peer_identity pointers into new_conf, then
		 * rebuild the hashtable since the key data pointers changed. */
		struct hashtable *new_tbl = table_new(&(struct table_opts){
			.hash = TABLE_OPTS_STR.hash,
			.eq = TABLE_OPTS_STR.eq,
			.flags = TABLE_FAST,
		});
		if (new_tbl == NULL) {
			LOGOOM();
			/* The cheap in-place rebuild is impossible without the new
			 * table. Returning here would leave s->identities' keys and
			 * every sl->peer_identity dangling into old_conf, which
			 * server_apply_config frees unconditionally right after -- a
			 * use-after-free on the next lookup. Fall back to the full
			 * path, which rebuilds s->identities from new_conf (or, on a
			 * further OOM, discards every listener and leaves it NULL). */
			server_reload_identities_changed(s, new_conf, new_np);
			return;
		}
		for (size_t i = 0; i < new_np; i++) {
			const struct identity_peer *restrict p =
				&new_conf->identity.peers[i];
			void *elem = NULL;
			if (!table_find(s->identities, p->id, &elem)) {
				continue;
			}
			struct identity_listener *restrict sl = elem;
			sl->peer_identity = p->id;
			sl->listener.socket_opts = &new_conf->tcp;
			void *slot = sl;
			new_tbl = table_set(new_tbl, sl->peer_identity, &slot);
			if (slot == sl) {
				/* OOM: sl not inserted into the rebuilt table.
				 * Discard it (stopping the listener and closing
				 * its tunnels), or it becomes an unreachable
				 * "ghost" once s->identities is swapped below. */
				identity_listener_discard(s, sl);
				LOGOOM();
			} else {
				ASSERT(slot == NULL);
			}
		}
		/* See server_reload_identities_changed: pin under accepted_mu so a
		 * concurrent session-thread lookup never sees a freed table. */
#if WITH_THREADS
		THRD_ASSERT(smtx_lock(&s->accepted_mu));
#endif
		table_free(s->identities);
		s->identities = new_tbl;
#if WITH_THREADS
		THRD_ASSERT(smtx_unlock(&s->accepted_mu));
#endif
		return;
	}
	server_reload_identities_changed(s, new_conf, new_np);
}

/* Create a new outbound (client-mode) tunnel with the given connect address.
 * Returns NULL on allocation or session-id generation failure. */
static struct tunnel *server_new_client_tunnel(
	struct server *restrict s, const struct config *restrict conf,
	const char *connect_addr)
{
	struct mux_config mux_conf = server_make_mux_config(s);
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
		.peer_id = NULL,
		.cnt = &cnts,
#if WITH_TLS
		.tlsctx = tlsctx,
		.conn = NULL,
#endif
	};
	struct tunnel *const t = tunnel_new(&ctx, &opts);
#if WITH_TLS
	if (t == NULL) {
		/* tunnel_new failed before adopting the handle; release it here. */
		tls_ctx_free(tlsctx);
	}
#endif
	return t;
}

/* Create a new mux_connect tunnel if one is configured but not yet live. */
static void server_reload_mux_tunnel(
	struct server *restrict s, const struct config *restrict new_conf)
{
	if (s->mux_tunnel != NULL || new_conf->mux_connect == NULL) {
		return;
	}
	struct tunnel *const t =
		server_new_client_tunnel(s, new_conf, new_conf->mux_connect);
	if (t == NULL) {
		LOGE("failed to create mux tunnel on reload");
		return;
	}
	s->mux_tunnel = t;
	if (!tunnel_start(t)) {
		/* Thread never started; drop the slot so a later reload can retry
		 * (server_reload_mux_tunnel early-returns while mux_tunnel != NULL). */
		s->mux_tunnel = NULL;
		tunnel_close(t);
	}
}

/* Dial a fresh identity tunnel for the (currently NULL) slot i and store it in
 * identity_tunnels[i]. Best-effort: on create or start failure the slot is left
 * NULL so a later reload or maintenance pass can retry. */
static void server_start_identity_tunnel(
	struct server *restrict s, const struct config *restrict conf,
	const size_t i)
{
	struct tunnel *const t = server_new_client_tunnel(
		s, conf, conf->identity.mux_connect[i]);
	if (t == NULL) {
		LOGE_F("failed to create identity tunnel[%zu]", i);
		return;
	}
	s->identity_tunnels[i] = t;
	if (!tunnel_start(t)) {
		/* Thread never started; clear the slot so a later reload or
		 * maintenance pass can recreate it (a NULL slot reads as
		 * "closed"). */
		s->identity_tunnels[i] = NULL;
		tunnel_close(t);
	}
}

/* Replace closed identity_connect slots and extend the array when the count
 * grows; live slots are left untouched. */
static void server_reload_identity_tunnels(
	struct server *restrict s, const struct config *restrict new_conf)
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
			/* Tunnel is still live; connect_addr was already
			 * updated in the pre-drain step above. */
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

bool server_apply_config(struct server *restrict s, struct config *new_conf)
{
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
	if (!server_make_tls_contexts(
		    new_conf, &new_server_tlsctx, &new_client_tlsctx)) {
		conf_free(new_conf);
		return false;
	}
#endif /* WITH_TLS */

	struct config *const old_conf = s->conf;

	server_drain_tunnels(
		s, old_conf, new_conf
#if WITH_TLS
		,
		new_client_tlsctx
#endif
	);

	/* Swap config and TLS contexts before starting any new tunnels or
	 * listeners. */
	s->conf = new_conf;
	s->local_listener.socket_opts = &new_conf->tcp;
	s->mux_listener.socket_opts = &new_conf->mux_tcp;
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(s->identities, &cursor, NULL, &elem)) {
			((struct identity_listener *)elem)
				->listener.socket_opts = &new_conf->tcp;
		}
	}

#if WITH_TLS
	struct tls_context *const old_server_tlsctx = s->server_tlsctx;
	struct tls_context *const old_client_tlsctx = s->client_tlsctx;
	s->server_tlsctx = new_server_tlsctx;
	s->client_tlsctx = new_client_tlsctx;
#endif

	server_reload_listeners(s, old_conf, new_conf);
	server_reload_identities(s, old_conf, new_conf);
	server_reload_mux_tunnel(s, new_conf);
	server_reload_identity_tunnels(s, new_conf);

#if WITH_TLS
	if (old_server_tlsctx != NULL) {
		tls_ctx_free(old_server_tlsctx);
	}
	if (old_client_tlsctx != NULL) {
		tls_ctx_free(old_client_tlsctx);
	}
#endif

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

static void server_reload(struct server *restrict s)
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
		return;
	}

	(void)server_apply_config(s, new_conf);
	(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);
}

/* Wall-clock jump larger than this (seconds) is treated as resume from system
 * suspend. */
#define MAINTENANCE_WALLCLOCK_JUMP_S 15

static void maintenance_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct server *const restrict srv = w->data;

	/* Task 1 (highest priority): shutdown deadline polling.
	 * When shutting_down, check the force-exit deadline and return. */
	if (srv->shutting_down) {
		const int_fast64_t elapsed_ns =
			clock_monotonic_ns() - srv->shutdown_start_ns;
		if (elapsed_ns >= (int_fast64_t)2000000000) {
			LOGW("shutdown timeout: forcing exit");
			ev_break(loop, EVBREAK_ALL);
		}
		return;
	}

	/* Task 2: detect system suspend via a wall-clock jump (CLOCK_REALTIME
	 * advances across suspend, CLOCK_MONOTONIC does not); drop all
	 * transports to reconnect. */
	struct timespec now_ts;
	if (clock_unix(&now_ts)) {
		const time_t now_wall = now_ts.tv_sec;
		const time_t delta = now_wall - srv->last_maintenance_wall;
		srv->last_maintenance_wall = now_wall;
		if (delta > (time_t)MAINTENANCE_WALLCLOCK_JUMP_S) {
			LOGW_F("wall-clock jump of %" PRIdFAST64
			       "s detected, dropping all transports",
			       (int_fast64_t)delta);
			/* Heap-allocated (not a VLA): the live tunnel count is
			 * unbounded in principle. On OOM, skip this cycle; the
			 * next tick re-evaluates the wall clock. */
			const size_t n = server_snapshot_cap(srv);
			struct tunnel **const snapshot =
				(struct tunnel **)malloc(
					n * sizeof(struct tunnel *));
			if (snapshot == NULL) {
				LOGOOM();
			} else {
				const size_t count = server_snapshot_tunnels(
					srv, snapshot, n);
				for (size_t i = 0; i < count; i++) {
					tunnel_drop_transport(snapshot[i]);
				}
				free((void *)snapshot);
			}
		}
	} else {
		LOGE("clock_unix failed");
	}

	/* Task 3: re-dial any configured identity slot left empty. A slot goes
	 * NULL only when its tunnel permanently closes (handle_closed); if the
	 * current config still wants a tunnel there -- e.g. a slot freed by a
	 * drained orphan that had shadowed a reconfigured target, or a start that
	 * failed on reload -- dial it now instead of waiting for the next reload.
	 * The array high-water mark bounds the index; conf may configure fewer. */
	{
		const struct config *const restrict conf = srv->conf;
		for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
			if (srv->identity_tunnels[i] != NULL) {
				continue;
			}
			if (i < conf->identity.mux_connect_count &&
			    conf->identity.mux_connect[i] != NULL) {
				server_start_identity_tunnel(srv, conf, i);
			}
		}
	}
}

#if WITH_THREADS
static void relay_async_cb(struct ev_loop *loop, ev_async *w, const int revents)
{
	CHECK_REVENTS(revents, EV_ASYNC);
	(void)loop;
	struct server *const restrict srv = w->data;
	dispatcher_tick(srv->disp);
}
#endif

static void signal_cb(struct ev_loop *loop, ev_signal *w, const int revents)
{
	CHECK_REVENTS(revents, EV_SIGNAL);
	struct server *const restrict s = w->data;
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

		listener_stop(&s->local_listener, loop);
		listener_stop(&s->mux_listener, loop);
		listener_stop(&s->api_listener, loop);
		{
			size_t cursor = 0;
			void *elem;
			while (table_next(s->identities, &cursor, NULL, &elem)) {
				struct listener *restrict l =
					&((struct identity_listener *)elem)
						 ->listener;
				listener_stop(l, loop);
			}
		}

		/* Gracefully shut down every active session. Snapshot first:
		 * CLOSED handling mutates accepted_tunnels/identities and would
		 * invalidate a live iterator. */
		{
			const size_t n = server_snapshot_cap(s);
			struct tunnel **const snapshot =
				(struct tunnel **)malloc(
					n * sizeof(struct tunnel *));
			if (snapshot == NULL) {
				/* Best-effort: skip graceful dispatch this pass;
				 * server_stop()'s force-close loop still
				 * guarantees every session gets closed. */
				LOGOOM();
			} else {
				const size_t count =
					server_snapshot_tunnels(s, snapshot, n);
				/* mux_shutdown() writes session internals; dispatch
				 * to each session's tunnel thread. */
				for (size_t i = 0; i < count; i++) {
					tunnel_shutdown(snapshot[i]);
				}
				free((void *)snapshot);
			}
		}

		if (s->mux_tunnel == NULL &&
		    (s->accepted_tunnels == NULL ||
		     table_size(s->accepted_tunnels) == 0)) {
			bool any = false;
			{
				size_t cursor = 0;
				void *elem;
				while (table_next(
					s->identities, &cursor, NULL, &elem)) {
					if (((struct identity_listener *)elem)
						    ->num_tunnels > 0) {
						any = true;
						break;
					}
				}
			}
			/* identity.mux_connect dial-outs sit in the
			 * identity_tunnels[] staging array for their whole
			 * lifetime (a non-NULL slot means a live dial-out,
			 * handshaking or established); they must still get the
			 * graceful drain window. */
			for (size_t i = 0; !any && i < s->num_identity_tunnels;
			     i++) {
				if (s->identity_tunnels[i] != NULL) {
					any = true;
				}
			}
			if (!any) {
				ev_break(loop, EVBREAK_ALL);
				break;
			}
		}

		/* Keep the event loop running until all sessions close or the
		 * shutdown deadline fires. */
		s->shutting_down = true;
		s->shutdown_start_ns = (int_least64_t)clock_monotonic_ns();
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
	/* Shared with server_apply_config(); erases conf's plaintext credentials
	 * unconditionally, on both the success and failure path. */
	if (!server_make_tls_contexts(
		    conf, &srv->server_tlsctx, &srv->client_tlsctx)) {
		server_free(srv);
		return NULL;
	}
#endif /* WITH_TLS */

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
	union sockaddr_max sa;
	if (!resolve_bindaddr(&sa, addr, SA_RESOLVE_TCP)) {
		LOGE_F("failed to parse %s address: %.256s", conf_key, addr);
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
		LOGE_F("failed to start %s listener", conf_key);
		return false;
	}
	if (LOGLEVEL(NOTICE)) {
		char str[64];
		(void)sa_format(str, sizeof(str), &sa.sa);
		LOGN_F("listening on %s (%s)", str, kind);
	}
	return true;
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

static bool server_start_mux_tunnel(struct server *restrict s)
{
	const struct config *const restrict conf = s->conf;
	if (conf->mux_connect == NULL) {
		return true;
	}
	struct tunnel *const t =
		server_new_client_tunnel(s, conf, conf->mux_connect);
	if (t == NULL) {
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
		struct identity_listener *restrict sl = malloc(sizeof(*sl));
		if (sl == NULL) {
			LOGOOM();
			return false;
		}
		sl->peer_identity = p->id;
		sl->tunnels = NULL;
		sl->num_tunnels = 0;
		sl->cap_tunnels = 0;
		sl->rr_next = 0;
		listener_init(
			&sl->listener, &conf->tcp, identity_tcp_serve, s,
			&s->counters.num_accepted_tcp);
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
		union sockaddr_max addr;
		if (!resolve_bindaddr(&addr, p->listen, SA_RESOLVE_TCP)) {
			LOGE_F("failed to parse identity listen address: %.256s",
			       p->listen);
			return false;
		}
		if (!listener_start(&sl->listener, loop, &addr.sa)) {
			LOGE_F("failed to start identity listener for \"%s\" at %s",
			       p->id, p->listen);
			return false;
		}
		if (LOGLEVEL(NOTICE)) {
			char resolved[64];
			(void)sa_format(resolved, sizeof(resolved), &addr.sa);
			LOGN_F("identity \"%s\" listening on %s (TCP)", p->id,
			       resolved);
		}
	}
	return true;
}

/* Create one dedicated mux session per identity.mux_connect address.
 * Sessions are wired to the matching identity listener in server_on_established. */
static bool server_start_identity_tunnels(struct server *restrict s)
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
			s, conf, conf->identity.mux_connect[i]);
		if (t == NULL) {
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

bool server_start(struct server *restrict s)
{
	struct ev_loop *const restrict loop = s->loop;
	const struct config *const restrict conf = s->conf;

#if WITH_THREADS
	ev_async_start(s->loop, &s->w_async);
#endif

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
	    !server_start_identity_tunnels(s)) {
		return false;
	}

	ev_signal_start(loop, &s->w_sighup);
	ev_signal_start(loop, &s->w_sigint);
	ev_signal_start(loop, &s->w_sigterm);

	s->last_maintenance_wall = time(NULL);
	ev_timer_init(&s->w_maintenance, maintenance_cb, 1.0, 1.0);
	s->w_maintenance.data = s;
	ev_timer_start(loop, &s->w_maintenance);

	LOGN("server started");
	return true;
}

/* Force-close every tunnel in snapshot[0..count), used by server_stop()'s
 * shutdown-deadline sweep. Mirrors handle_closed(): remove each tunnel
 * under the exclusive lock before tearing it down, so a concurrent resume
 * lookup can never dispatch to a tunnel being concurrently freed. */
static void server_force_close_snapshot(
	struct server *restrict srv, struct tunnel *const *restrict snapshot,
	const size_t count)
{
	for (size_t i = 0; i < count; i++) {
		struct tunnel *const t = snapshot[i];
		if (tunnel_is_accepted(t)) {
#if WITH_THREADS
			THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
			srv->accepted_tunnels = table_del(
				srv->accepted_tunnels, tunnel_session_id(t),
				NULL);
#if WITH_THREADS
			THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
		}
		fold_closed_tunnel_traffic(srv, t);
		tunnel_close(t);
	}
}

/* OOM fallback for the force-close sweep below: process one tunnel at a
 * time via a fresh tunnel_iter_next scan instead of snapshotting all of
 * them into a buffer, so it needs no allocation at all (the heap snapshot
 * just failed). Removes t from every pool it could be found in -- mirrors
 * handle_closed()'s full removal scope, unlike server_force_close_snapshot
 * above which only removes from accepted_tunnels because its caller bulk-
 * clears the other pools right after the sweep -- so a fresh scan on the
 * next iteration can never find t again. tunnel_close() joins t's thread
 * and is not safe to call twice on the same tunnel, so this exhaustive
 * removal is what makes repeated fresh scans safe without tracking which
 * tunnels were already seen. */
static void server_force_close_one_by_one(struct server *restrict srv)
{
	for (;;) {
		struct tunnel_iter it = { 0 };
		struct tunnel *const t = tunnel_iter_next(srv, &it);
		if (t == NULL) {
			break;
		}
		if (tunnel_is_accepted(t)) {
#if WITH_THREADS
			THRD_ASSERT(smtx_lock(&srv->accepted_mu));
#endif
			srv->accepted_tunnels = table_del(
				srv->accepted_tunnels, tunnel_session_id(t),
				NULL);
#if WITH_THREADS
			THRD_ASSERT(smtx_unlock(&srv->accepted_mu));
#endif
		} else if (t == srv->mux_tunnel) {
			srv->mux_tunnel = NULL;
		}
		{
			size_t cursor = 0;
			void *elem;
			while (table_next(
				srv->identities, &cursor, NULL, &elem)) {
				if (identity_listener_remove(elem, t)) {
					break;
				}
			}
		}
		for (size_t i = 0; i < srv->num_identity_tunnels; i++) {
			if (srv->identity_tunnels[i] == t) {
				srv->identity_tunnels[i] = NULL;
				break;
			}
		}
		fold_closed_tunnel_traffic(srv, t);
		tunnel_close(t);
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
	ev_timer_stop(loop, &srv->w_maintenance);
#if WITH_THREADS
	ev_async_stop(loop, &srv->w_async);
	dispatcher_tick(srv->disp);
#endif

	listener_stop(&srv->local_listener, loop);
	listener_stop(&srv->mux_listener, loop);
	listener_stop(&srv->api_listener, loop);
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(srv->identities, &cursor, NULL, &elem)) {
			struct identity_listener *restrict sl = elem;
			listener_stop(&sl->listener, loop);
		}
	}

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
#if WITH_TLS
	if (srv->server_tlsctx != NULL) {
		tls_ctx_free(srv->server_tlsctx);
	}
	if (srv->client_tlsctx != NULL) {
		tls_ctx_free(srv->client_tlsctx);
	}
#endif
	table_free(srv->accepted_tunnels);
#if WITH_THREADS
	smtx_destroy(&srv->accepted_mu);
#endif
	{
		size_t cursor = 0;
		void *elem;
		while (table_next(srv->identities, &cursor, NULL, &elem)) {
			struct identity_listener *sl = elem;
			free((void *)sl->tunnels);
			free(sl);
		}
	}
	table_free(srv->identities);
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
	char peer_id_buf[256];
	const char *const peer_id =
		tunnel_peer_identity_copy(
			element, peer_id_buf, sizeof(peer_id_buf)) ?
			peer_id_buf :
			NULL;
	if (peer_id != NULL) {
		void *elem = NULL;
		/* Skip only when this tunnel is actually pooled -- the identity
		 * pool pass emits it there. A configured identity whose
		 * identity_listener_add() OOM'd left the accepted tunnel matched
		 * but unpooled; emit it here so the aggregate counters below do
		 * not drop it. */
		if (table_find(ctx->s->identities, peer_id, &elem) &&
		    identity_listener_contains(elem, element)) {
			return true;
		}
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

/* Fill the p50/p90/p99/pmax percentile fields in *out by merging the latency
 * rings of all dialed tunnels in out->tunnels[].  Returns the sample count. */
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
	size_t n = 0;
	for (size_t i = 0; i < out->num_tunnels; i++) {
		const struct tunnel_stats *const ts = &out->tunnels[i];
		const size_t ring = ARRAY_SIZE(ts->stream_establish_ns);
		const size_t count = MIN(ts->stream_establish_count, ring);
		for (size_t j = 0; j < count; j++) {
			const size_t idx =
				(ts->stream_establish_count - j - 1) % ring;
			samples[n++] = ts->stream_establish_ns[idx];
		}
	}
	qsort(samples, n, sizeof(samples[0]), cmp_intfast64);
	const size_t i50 = (50 * n) / 100;
	const size_t i90 = (90 * n) / 100;
	const size_t i99 = (99 * n) / 100;
	out->stream_establish_p50 = samples[i50 < n ? i50 : n - 1];
	out->stream_establish_p90 = samples[i90 < n ? i90 : n - 1];
	out->stream_establish_p99 = samples[i99 < n ? i99 : n - 1];
	out->stream_establish_pmax = samples[n - 1];
	free(samples);
	return n;
}

struct server_stats *server_stats(const struct server *restrict s)
{
	/* Upper bound on tunnels[]: mux_tunnel (0 or 1) + every identity-pool
	 * member + every accepted tunnel. Using table_size for the accepted side
	 * rather than a classify pass avoids a two-pass race: the session thread
	 * can flip a peer identity between a count pass and a populate pass,
	 * reclassifying a tunnel as unmatched and overflowing tunnels[]. A few
	 * over-allocated slots (pooled accepted tunnels never re-emitted here) are
	 * harmless; num_tunnels below reflects the actual fill. */
	size_t n = (s->mux_tunnel != NULL ? 1 : 0);
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
	out->num_rst_sent = (uint_least64_t)atomic_load_explicit(
		&c->num_rst_sent, memory_order_relaxed);
	out->num_rst_recv = (uint_least64_t)atomic_load_explicit(
		&c->num_rst_recv, memory_order_relaxed);
	out->num_stream_errors = (uint_least64_t)atomic_load_explicit(
		&c->num_stream_errors, memory_order_relaxed);
	out->num_reconnects = (uint_least64_t)atomic_load_explicit(
		&c->num_reconnects, memory_order_relaxed);
	out->traffic_byt_mux_recv = c->traffic_byt_mux_recv;
	out->traffic_byt_mux_sent = c->traffic_byt_mux_sent;
	out->traffic_byt_push_recv = c->traffic_byt_push_recv;
	out->traffic_byt_push_sent = c->traffic_byt_push_sent;
	out->recv_buffered_bytes = (size_t)atomic_load_explicit(
		&c->recv_buffered_bytes, memory_order_relaxed);
	out->send_buffered_frames = (size_t)atomic_load_explicit(
		&c->send_buffered_frames, memory_order_relaxed);
	out->unacked_frames = (size_t)atomic_load_explicit(
		&c->unacked_frames, memory_order_relaxed);
#else /* WITH_THREADS */
	out->num_session_created = c->num_session_created;
	out->num_session_connect = c->num_session_connect;
	out->num_session_connected = c->num_session_connected;
	out->num_session_disconnected = c->num_session_disconnected;
	out->num_session_finalized = c->num_session_finalized;
	out->num_sessions = c->num_sessions;
	out->num_session_halfopen = c->num_session_halfopen;
	out->num_rst_sent = c->num_rst_sent;
	out->num_rst_recv = c->num_rst_recv;
	out->num_stream_errors = c->num_stream_errors;
	out->num_reconnects = c->num_reconnects;
	out->traffic_byt_mux_recv = c->traffic_byt_mux_recv;
	out->traffic_byt_mux_sent = c->traffic_byt_mux_sent;
	out->traffic_byt_push_recv = c->traffic_byt_push_recv;
	out->traffic_byt_push_sent = c->traffic_byt_push_sent;
	out->recv_buffered_bytes = c->recv_buffered_bytes;
	out->send_buffered_frames = c->send_buffered_frames;
	out->unacked_frames = c->unacked_frames;
#endif /* WITH_THREADS */

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
	 * an unmatched-accepted entry), so summing from it here -- rather than a
	 * second table_iterate that re-ran tunnel_stats on each accepted tunnel,
	 * taking the pub mutex and copying the ~2 KB snapshot incl. the 256-entry
	 * latency ring -- avoids a redundant O(n) pass and keeps the totals
	 * consistent with the per-tunnel rows. */
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
		out->traffic_byt_mux_recv += ts->byt_mux_recv;
		out->traffic_byt_mux_sent += ts->byt_mux_sent;
		out->traffic_byt_push_recv += ts->byt_push_recv;
		out->traffic_byt_push_sent += ts->byt_push_sent;
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

	/* Each identity listener forwards over its own tunnel pool (mirrors
	 * identity_tcp_serve), always dialed on-demand -- unlike conf->listen,
	 * there is no accepted-tunnel fallback to consider, so the idle_timeout
	 * exemption applies unconditionally here. */
	if (conf->mux.idle_timeout == 0 && s->identities != NULL) {
		size_t cursor = 0;
		void *elem;
		while (table_next(s->identities, &cursor, NULL, &elem)) {
			const struct identity_listener *const restrict sl =
				elem;
			if (listener_has_live_tunnel(
				    sl->tunnels, sl->num_tunnels)) {
				continue;
			}
			offline++;
			if (cb != NULL) {
				cb(data, sl->peer_identity);
			}
		}
	}
	return offline;
}
