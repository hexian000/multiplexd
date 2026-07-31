/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file stream.c
 * @brief Internal mux stream state machine implementation.
 */

#include "mux/stream.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/sched.h"
#include "mux/send.h"
#include "mux/session.h"
#include "mux/stream_io.h"
#include "shim/util.h"

#include "meta/minmax.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define STREAM_LOG_F(level, s, format, ...)                                    \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char stream_tag_[256];                                         \
		(void)mux_stream_format_tag(                                   \
			stream_tag_, sizeof(stream_tag_), (s));                \
		LOG_F(level, "%s " format, stream_tag_, __VA_ARGS__);          \
	} while (0)
#define STREAM_LOG(level, s, message) STREAM_LOG_F(level, s, "%s", message)

static const char *const stream_state_str[] = {
	[STREAM_INIT] = "INIT",
	[STREAM_SYN_SENT] = "SYN_SENT",
	[STREAM_SYN_RECEIVED] = "SYN_RECEIVED",
	[STREAM_ESTABLISHED] = "ESTABLISHED",
	[STREAM_FIN_WAIT] = "FIN_WAIT",
	[STREAM_CLOSE_WAIT] = "CLOSE_WAIT",
	[STREAM_CLOSING] = "CLOSING",
	[STREAM_CLOSED] = "CLOSED",
};

/* Minimum window-grant scale at/above the high pressure watermark; grants
 * decay linearly from 1.0 down to this floor across [lo, hi]. */
#define MUX_PRESSURE_MIN_SCALE 0.125

/* Scale window grants by session receive-buffer pressure: 1.0 below s_lo,
 * linear decay to MUX_PRESSURE_MIN_SCALE across [s_lo, s_hi], floored beyond.
 * Disabled (1.0) when mem_pressure_hi <= 0 or nothing is buffered. */
static double session_pressure_scale(const struct mux_session *restrict ss)
{
	if (ss->conf.mem_pressure_hi <= 0) {
		return 1.0;
	}
	if (ss->recv_buffered_bytes == 0) {
		return 1.0;
	}
	const double buffered = (double)ss->recv_buffered_bytes;
	const double s_high = (double)ss->conf.mem_pressure_hi;
	/* conf_check() already resolved lo == 0 to hi / 2. */
	const double s_low = (double)ss->conf.mem_pressure_lo;
	if (buffered <= s_low) {
		return 1.0;
	}
	if (buffered >= s_high) {
		return MUX_PRESSURE_MIN_SCALE;
	}
	return 1.0 - (buffered - s_low) / (s_high - s_low) *
			     (1.0 - MUX_PRESSURE_MIN_SCALE);
}

/* Compute the window increment to grant the peer (in MUX_WINDOW_UNIT units).
 * Scales by session_pressure_scale(); floors at one unit to avoid starvation. */
uint_fast32_t mux_stream_grant_inc(const struct mux_stream *restrict s)
{
	const uint_fast32_t grantable = stream_grantable_bytes(s);
	/* Sub-unit grantable cannot be expressed on the wire (spec §6.4); the
	 * safety floor below would over-grant past the window, violating §6.3. */
	if (grantable < (uint_fast32_t)MUX_WINDOW_UNIT) {
		return 0;
	}
	const double scale = session_pressure_scale(s->session);
	const uint_fast32_t scaled = (uint_fast32_t)((double)grantable * scale);
	/* Safety floor: always grant at least one unit when grantable allows
	 * so no stream is starved and the flow-control loop cannot deadlock. */
	const uint_fast32_t effective =
		MAX(scaled, (uint_fast32_t)MUX_WINDOW_UNIT);
	const uint_fast32_t grant =
		MIN(effective / (uint_fast32_t)MUX_WINDOW_UNIT,
		    (uint_fast32_t)UINT16_MAX);
	if (scale < 1.0) {
		STREAM_LOG_F(
			VERBOSE, s,
			"memory pressure: scale=%.3f grantable=%" PRIuFAST32
			" grant=%" PRIuFAST32,
			scale, grantable, grant);
	}
	return grant;
}

static void stream_set_state(
	struct mux_stream *restrict s, const enum stream_state newstate)
{
	const enum stream_state oldstate = s->state;
	const bool new_halfopen = newstate == STREAM_INIT ||
				  newstate == STREAM_SYN_SENT ||
				  newstate == STREAM_SYN_RECEIVED;

	if (!s->halfopen_counted && new_halfopen) {
		s->session->num_halfopen++;
		s->halfopen_counted = true;
		COUNTER_ADD(s->session->cnt.stream.num_stream_halfopen, 1);
	} else if (s->halfopen_counted && !new_halfopen) {
		ASSERT(s->session->num_halfopen > 0);
		s->session->num_halfopen--;
		s->halfopen_counted = false;
		COUNTER_SUB(s->session->cnt.stream.num_stream_halfopen, 1);
	}
	if (oldstate == newstate) {
		return;
	}
	STREAM_LOG_F(
		DEBUG, s, "state: %s -> %s", stream_state_str[oldstate],
		stream_state_str[newstate]);
	s->state = newstate;
	if (newstate == STREAM_ESTABLISHED) {
		COUNTER_ADD(s->session->cnt.stream.num_stream_established, 1);
	}
}

static void stream_stop(struct mux_stream *s)
{
	/* mux_stream_free and lifecycle-queue cleanup both pass through here. */
	ev_timer_stop(s->session->loop, &s->w_tombstone);
	if (s->delay_pending) {
		mux_sched_delay_remove(s->session, s);
	}
	/* drr_active is off-FIFO while spending its round budget, so a teardown
	 * reached from outside mux_sched_next_data (RST/abort while this stream
	 * held the budget) would otherwise leave a stale self-reference:
	 * mux_sched_wake's enqueue guards treat "s == drr_active" as "already
	 * owned," so the eventual tombstone-driven mux_sched_wake silently no-ops
	 * instead of routing the stream to mux_stream_free, stranding it. */
	if (s->session->sched.drr_active == s) {
		s->session->sched.drr_active = NULL;
	}
	if (s->is_direct) {
		return;
	}
	struct ev_loop *const loop = s->session->loop;
	ev_io_stop(loop, &s->socket.w_io);
	ev_timer_stop(loop, &s->socket.w_timeout);
}

/* Discard the stream's payload storage and hand its bytes back to the session
 * gauges (spec §4.3.4 requires dropping pending outbound data on an abortive
 * close; a tombstone needs only the stream ID). Idempotent: the paths that
 * already reset the receive buffer leave nothing for this to subtract. */
static void stream_release_buffers(struct mux_stream *restrict s)
{
	struct mux_session *const restrict ss = s->session;
	ASSERT(ss->send_buffered_frames >= s->send_queue.count);
	ss->send_buffered_frames -= s->send_queue.count;
	COUNTER_SUB(ss->cnt.buffers.send_buffered_frames, s->send_queue.count);
	mux_frame_list_clear(&s->send_queue, &ss->pool);
	s->queued_send_bytes = 0;
	ASSERT(ss->recv_buffered_bytes >= s->recvbuf->len);
	ss->recv_buffered_bytes -= s->recvbuf->len;
	COUNTER_SUB(ss->cnt.buffers.recv_buffered_bytes, s->recvbuf->len);
	bytebuf_reset(s->recvbuf);
	s->buffered_bytes = 0;
	/* Release capacity grown for oversized frames; nothing writes to a
	 * CLOSED stream's receive buffer, so no regrowth follows. */
	mux_bytebuf_shrink(&s->recvbuf, 0);
}

static inline void stream_mark_closed(struct mux_stream *restrict s)
{
	const bool was_init = (s->state == STREAM_INIT);
	stream_stop(s);
	/* Before the check_no_active_streams cascade below, which may free s. */
	stream_release_buffers(s);
	/* The tombstone only needs the stream ID for late-frame suppression. */
	if (!s->is_direct && s->socket.w_io.fd != -1) {
		socket_close(s->socket.w_io.fd);
		s->socket.w_io.fd = -1;
	}
	/* From the caller's perspective the stream is already dead. Count
	 * s->aborted as a failure too: with the OOM-safe rst_sent latch above, an
	 * aborted stream whose RST could not be enqueued now has rst_sent == false
	 * and would otherwise be miscounted as a success. */
	if (s->rst_received || s->rst_sent || s->aborted) {
		COUNTER_ADD(s->session->cnt.stream.num_stream_failed, 1);
	} else {
		COUNTER_ADD(s->session->cnt.stream.num_stream_succeeded, 1);
	}
	stream_set_state(s, STREAM_CLOSED);
	if (!was_init) {
		/* Late-frame suppression lingers until tombstone_cb hands cleanup back. */
		s->session->sched.num_tombstones++;
		ev_timer_set(&s->w_tombstone, MUX_TOMBSTONE_PERIOD_S, 0.0);
		ev_timer_start(s->session->loop, &s->w_tombstone);
		/* Evaluate right away whether this was the last active stream,
		 * rather than waiting up to MUX_TOMBSTONE_PERIOD_S for
		 * tombstone_cb -> mux_sched_drain_lp -> sched_remove_stream to
		 * notice the same condition on its own delayed schedule. */
		mux_sched_check_no_active_streams(s->session);
	} else {
		/* No SYN left the host, so there is no peer-visible state to linger. */
		mux_sched_wake(s->session, s);
	}
}

static inline bool
stream_can_shutdown_write_now(const struct mux_stream *restrict s)
{
	return s->is_direct || s->socket.connected;
}

static void stream_shutdown_local_write(struct mux_stream *restrict s)
{
	if (s->tx_shutdown) {
		return;
	}
	if (!s->is_direct) {
		(void)socket_shutdown(s->socket.w_io.fd, SHUT_WR);
	}
	s->tx_shutdown = true;
}

/* The recv buffer is drained on a socket-mode stream mid-close: half-close the
 * local write side (SHUT_WR) if the socket is connected and it has not been
 * already, then -- once both FINs are exchanged (STREAM_CLOSING) -- complete the
 * stream. An in-progress connect can neither be shut down nor closed yet; it
 * defers to stream_flush_local, which runs when the socket connects. Direct mode
 * has no local socket and defers its final close to mux_stream_recv, so it never
 * calls this. Returns true if the stream was closed, in which case s may already
 * be freed (last active stream + a drain in progress cascades into
 * mux_session_initiate_shutdown -> mux_sched_free_streams) and must not be touched. */
static bool stream_finish_drained_write(struct mux_stream *restrict s)
{
	ASSERT(!s->is_direct);
	ASSERT(bytebuf_readable(s->recvbuf) == 0);
	if (!stream_can_shutdown_write_now(s)) {
		return false;
	}
	if (!s->tx_shutdown) {
		STREAM_LOG(VERBOSE, s, "shutdown local send");
		stream_shutdown_local_write(s);
	}
	if (s->state == STREAM_CLOSING) {
		stream_mark_closed(s);
		return true;
	}
	return false;
}

static void update_watcher(struct mux_stream *restrict s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	if (s->socket.w_io.fd == -1) {
		/* Socket-mode stream not yet attached (it can reach SYN_SENT
		 * unattached; mux_stream_do_attach_fd sanctions it). modify_io_events
		 * below ASSERTs fd != -1 -- compiled out under NDEBUG -- so guard
		 * here rather than drive ev_io with -1 in a release build. */
		return;
	}
	if (!s->socket.connected) {
		modify_io_events(s->session->loop, &s->socket.w_io, EV_WRITE);
		return;
	}

	const int prev_events = s->socket.w_io.events & (EV_READ | EV_WRITE);
	int events = 0;
	uint_fast32_t read_credit = 0;
	/* STREAM_INIT may queue only one fast-open payload before SYN leaves. */
	if (!s->rx_eof &&
	    (s->state == STREAM_ESTABLISHED || s->state == STREAM_CLOSE_WAIT ||
	     (s->state == STREAM_INIT && s->send_queue.head == NULL))) {
		/* stream_read_credit_avail also subtracts queued bytes. */
		read_credit = stream_read_credit_avail(s);
		if (read_credit != 0) {
			events |= EV_READ;
		}
	}
	if (bytebuf_readable(s->recvbuf) > 0) {
		events |= EV_WRITE;
	}
	if ((prev_events & EV_READ) == 0 && (events & EV_READ) != 0) {
		STREAM_LOG_F(
			DEBUG, s,
			"local read resumed: state=%s credit=%" PRIuFAST32
			" queued=%" PRIuLEAST32,
			stream_state_str[s->state], read_credit,
			s->queued_send_bytes);
	} else if (
		(prev_events & EV_READ) != 0 && (events & EV_READ) == 0 &&
		!s->rx_eof && stream_can_send_data(s)) {
		STREAM_LOG_F(
			DEBUG, s,
			"local read gated: state=%s credit=%" PRIuFAST32
			" queued=%" PRIuLEAST32,
			stream_state_str[s->state], stream_read_credit_avail(s),
			s->queued_send_bytes);
	}
	modify_io_events(s->session->loop, &s->socket.w_io, events);
}

/* Detach the user watcher from the stream without invoking any callback. */
static void stream_detach_user(struct mux_stream *restrict s)
{
	if (!s->is_direct) {
		return;
	}
	struct mux_stream_io *const w = s->direct.w_io;
	if (w == NULL) {
		return;
	}
	ev_clear_pending(w->loop, w);
	w->stream = NULL;
	w->active = 0;
	s->direct.w_io = NULL;
}

static void stream_rst_notify_direct(struct mux_stream *restrict s)
{
	struct mux_stream_io *const w = s->direct.w_io;
	if (w == NULL) {
		return;
	}
	ev_clear_pending(w->loop, w);
	ev_invoke(w->loop, w, EV_READ);
}

/* Abort the stream locally and emit one peer-visible RST. */
void mux_stream_abort(struct mux_stream *restrict s, const enum mux_status code)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	STREAM_LOG(DEBUG, s, "aborting (RST)");
	COUNTER_ADD(s->session->cnt.errors.num_stream_errors, 1);
	s->aborted = true;
	mux_session_discard_stream_frames(s->session, s->id);
	if (!s->rst_sent) {
		/* Only latch rst_sent when the RST was actually enqueued: on
		 * frame-pool OOM mux_session_send_ctrl returns false without sending,
		 * and a latched rst_sent would gate off every later retry (and
		 * recv.c's late-frame handler, which also keys on !rst_sent),
		 * leaving the peer's PUSH frames to the dead stream unanswered for
		 * the whole tombstone window. */
		s->rst_sent = mux_session_send_ctrl(
			s->session, s->id, MUX_FLAG_RST, code);
	}
	if (s->is_direct) {
		/* Fire EV_READ before detach so the callback sees `aborted`; it may
		 * call mux_stream_close(). On the last active stream of a draining
		 * session that cascades into mux_session_initiate_shutdown ->
		 * mux_sched_free_streams and frees s (the session object survives), so
		 * capture it and stop touching s -- the plain STREAM_CLOSED read
		 * below would otherwise be a use-after-free -- once the free shows. */
		struct mux_session *const restrict ss = s->session;
		stream_rst_notify_direct(s);
		if (session_streams_freed(ss) || s->state == STREAM_CLOSED) {
			return;
		}
		stream_detach_user(s);
	}
	stream_mark_closed(s);
}

/* Update the send-side timeout after a flush (socket mode): stop when the
 * recv queue is empty, else re-arm on progress or when first blocked. */
static void
update_send_timeout(struct mux_stream *restrict s, const bool progress)
{
	if (s->socket.w_timeout.repeat <= 0.0) {
		return;
	}
	if (bytebuf_readable(s->recvbuf) == 0) {
		ev_timer_stop(s->session->loop, &s->socket.w_timeout);
		return;
	}
	if (!ev_is_active(&s->socket.w_timeout) || progress) {
		ev_timer_again(s->session->loop, &s->socket.w_timeout);
	}
}

/* Write to the local socket fd, handling partial writes and EAGAIN.  Returns
 * bytes written (0 on EAGAIN).  On hard error calls mux_stream_abort and returns 0;
 * caller must check s->state afterwards. */
static size_t stream_local_write(
	struct mux_stream *restrict s, const unsigned char *restrict data,
	const size_t len)
{
	const int sfd = s->socket.w_io.fd;
	size_t nwrite = 0;
	while (nwrite < len) {
		size_t nbytes = len - nwrite;
		const int err = socket_send(sfd, data + nwrite, &nbytes);
		if (err != 0) {
			if (sock_would_block(err)) {
				break;
			}
			LOGE_F("send [fd:%d]: (%d) %s", sfd, err,
			       strerror(err));
			mux_stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
			return 0;
		}
		if (nbytes == 0) {
			break;
		}
		nwrite += nbytes;
	}
	return nwrite;
}

static void stream_flush_local(struct mux_stream *s)
{
	bool made_progress = false;
	/* stream_local_write may mux_stream_abort on a hard error, which on the last
	 * active stream of a draining session frees s via the drain cascade; the
	 * session survives, so capture it and check the free before touching s. */
	struct mux_session *const restrict ss = s->session;
	while (bytebuf_readable(s->recvbuf) > 0) {
		const size_t len = bytebuf_readable(s->recvbuf);
		const unsigned char *const data = bytebuf_read_ptr(s->recvbuf);
		const size_t nwrite = stream_local_write(s, data, len);
		if (nwrite == 0) {
			/* nwrite == 0 is either EAGAIN (re-arm the send timeout) or a
			 * hard error that stream_local_write already turned into a
			 * mux_stream_abort (STREAM_CLOSED, fd closed, timer stopped, and
			 * possibly freed). Don't re-arm a torn-down stream's timer --
			 * matching update_watcher's own STREAM_CLOSED guard. */
			if (!session_streams_freed(ss) &&
			    s->state != STREAM_CLOSED) {
				update_send_timeout(s, made_progress);
			}
			return;
		}

		made_progress = true;
		bytebuf_consume(s->recvbuf, nwrite);
		ASSERT(s->buffered_bytes >= nwrite);
		ASSERT(s->session->recv_buffered_bytes >= nwrite);
		s->buffered_bytes -= nwrite;
		s->session->recv_buffered_bytes -= nwrite;
		COUNTER_SUB(
			s->session->cnt.buffers.recv_buffered_bytes, nwrite);
		STREAM_LOG_F(
			VERBOSE, s,
			"local send: %zu bytes, buffered=%" PRIuLEAST32, nwrite,
			s->buffered_bytes);

		mux_stream_check_ack(s);
	}

	update_send_timeout(s, false);
	if ((s->state == STREAM_CLOSE_WAIT || s->state == STREAM_CLOSING) &&
	    bytebuf_readable(s->recvbuf) == 0) {
		/* Drained mid-close: half-close the write side and, under CLOSING
		 * (both FINs exchanged), complete. s may be freed by the close, but
		 * the function returns immediately after. */
		(void)stream_finish_drained_write(s);
	}
}

/* Deliver @p revents to the direct-I/O watcher, filtered by its registered
 * interest; no-op when there is no watcher or no interesting bits. */
static inline void
stream_feed_user(struct mux_stream *restrict s, const int revents)
{
	if (!s->is_direct) {
		return;
	}
	struct mux_stream_io *const w = s->direct.w_io;
	if (w == NULL) {
		return;
	}
	const int filtered = revents & w->events;
	if (filtered == 0) {
		return;
	}
	ev_feed_event(w->loop, w, filtered);
}

static bool stream_on_recv(struct mux_stream *restrict s)
{
	if (s->rx_eof || !stream_can_send_data(s)) {
		return false;
	}

	const uint_fast32_t read_credit = stream_read_credit_avail(s);
	if (read_credit == 0) {
		STREAM_LOG(VERBOSE, s, "send credit exhausted, pausing read");
		return false;
	}

	struct mux_frame *const frame =
		mux_frame_get(&s->session->pool, s->session->max_payload);
	if (frame == NULL) {
		STREAM_LOG(WARNING, s, "out of memory for send frame");
		return false;
	}

	unsigned char *const buf = frame->data + MUX_FRAME_HEADER_SIZE;
	size_t nread;
	{
		const int fd = s->socket.w_io.fd;
		/* Clamp to send credit: a payload exceeding credit would never
		 * pass mux_stream_dequeue_send's payload <= credit gate and would
		 * deadlock the stream. */
		size_t nrecv = frame->cap;
		if ((size_t)read_credit < nrecv) {
			nrecv = read_credit;
		}
		const int err = socket_recv(fd, buf, &nrecv);
		if (err != 0) {
			if (sock_would_block(err)) {
				mux_frame_put(&s->session->pool, frame);
				return false; /* wait for EV_READ */
			}
			LOGE_F("recv [fd:%d]: (%d) %s", fd, err, strerror(err));
			mux_frame_put(&s->session->pool, frame);
			mux_stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
			return false;
		}
		nread = nrecv; /* 0 means EOF */
	}

	if (nread > 0) {
		STREAM_LOG_F(VERBOSE, s, "local recv: %zu bytes", nread);
		frame->len = MUX_FRAME_HEADER_SIZE + nread;

		mux_stream_queue_send(s, frame);
	} else {
		mux_frame_put(&s->session->pool, frame);
		s->rx_eof = true;
		STREAM_LOG(VERBOSE, s, "local recv: EOF");
	}

	mux_session_eager_flush(s->session, s);
	return nread > 0;
}

static void local_on_connected(struct mux_stream *restrict s)
{
	ev_timer_stop(s->session->loop, &s->socket.w_timeout);
	const int sockerr = socket_get_error(s->socket.w_io.fd);
	if (sockerr != 0) {
		STREAM_LOG_F(
			WARNING, s, "connect [fd:%d]: (%d) %s",
			s->socket.w_io.fd, sockerr, strerror(sockerr));
		mux_stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
		return;
	}
	STREAM_LOG_F(VERBOSE, s, "connected [fd:%d]", s->socket.w_io.fd);
	s->socket.connected = true;
}

static void stream_on_send(struct mux_stream *restrict s)
{
	if (!s->socket.connected) {
		/* local_on_connected() aborts the stream on a connect failure; on
		 * the last active stream of a draining session that frees s via the
		 * drain cascade. Capture the surviving session and stop touching s --
		 * both the state read below and stream_flush_local() -- once the free
		 * is detected. */
		struct mux_session *const restrict ss = s->session;
		local_on_connected(s);
		if (session_streams_freed(ss) || s->state == STREAM_CLOSED) {
			return;
		}
	}

	stream_flush_local(s);
}

static void local_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct mux_stream *const restrict s = w->data;
	ASSERT(!s->is_direct);
	ASSERT(loop == s->session->loop);
	(void)loop;
	/* STREAM_CLOSING is reachable: a peer FIN moves an EV_WRITE-armed
	 * (recv-backpressured) socket stream to CLOSE_WAIT, then a local EOF
	 * sends FIN and reaches CLOSING with recvbuf still draining; neither
	 * transition re-runs update_watcher, so the armed EV_WRITE persists. */
	ASSERT(s->state == STREAM_INIT || s->state == STREAM_ESTABLISHED ||
	       s->state == STREAM_FIN_WAIT || s->state == STREAM_CLOSE_WAIT ||
	       s->state == STREAM_CLOSING);
	STREAM_LOG_F(
		VERBOSE, s, "stream socket: state=%s revents=%d",
		stream_state_str[s->state], revents);
	/* stream_on_recv/stream_on_send can, on the last active stream of a
	 * draining session, cascade into mux_session_initiate_shutdown ->
	 * mux_sched_free_streams and free s; the session object survives, so capture
	 * it and stop touching s once session_streams_freed() reports the free. */
	struct mux_session *const restrict ss = s->session;
	if (revents & EV_READ) {
		while (stream_on_recv(s) && s->state != STREAM_CLOSED) {
		}
	}
	if (!session_streams_freed(ss) && (revents & EV_WRITE) &&
	    s->state != STREAM_CLOSED) {
		stream_on_send(s);
	}
	if (!session_streams_freed(ss)) {
		update_watcher(s);
	}
	mux_session_flush(ss);
}

static void timeout_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_stream *const restrict s = w->data;
	ASSERT(loop == s->session->loop);
	(void)loop;
	ASSERT(!s->is_direct);
	struct mux_session *const restrict ss = s->session;
	STREAM_LOG(WARNING, s, "local socket timeout");
	mux_stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
	mux_session_flush(ss);
}

static void tombstone_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct mux_stream *const restrict s = w->data;
	ASSERT(loop == s->session->loop);
	(void)loop;
	ASSERT(s->state == STREAM_CLOSED);
	STREAM_LOG(DEBUG, s, "tombstone expired; scheduling cleanup");
	ASSERT(s->session->sched.num_tombstones > 0);
	s->session->sched.num_tombstones--;
	/* Re-enter the normal cleanup path: mux_sched_wake routes CLOSED streams to the
	 * lp queue, which calls sched_remove_stream + mux_stream_free. */
	mux_sched_wake(s->session, s);
}

struct mux_stream *mux_stream_new(
	struct mux_session *restrict ss, const uint_fast16_t id,
	const bool active_open)
{
	struct mux_stream *const s = malloc(sizeof(struct mux_stream));
	if (s == NULL) {
		return NULL;
	}
	const struct mux_session_config *const restrict conf = &ss->conf;
	*s = (struct mux_stream){
		.id = id,
		.state = STREAM_INIT,
		.session = ss,
		.recv_window =
			(uint_fast32_t)ss->stream_window * MUX_WINDOW_UNIT,
		.send_window = MUX_DEFAULT_SEND_WINDOW,
		.grant_sent = MUX_DEFAULT_SEND_WINDOW,
		.unacked_bytes = 0,
		.deficit = 0,
	};
	ev_io_init(&s->socket.w_io, local_cb, -1, EV_NONE);
	s->socket.w_io.data = s;
	const double timeout = (double)conf->send_timeout;
	ev_timer_init(&s->socket.w_timeout, timeout_cb, 0.0, timeout);
	s->socket.w_timeout.data = s;
	s->recvbuf = bytebuf_new(ss->max_payload);
	if (s->recvbuf == NULL) {
		free(s);
		return NULL;
	}
	if (active_open) {
		COUNTER_ADD(ss->cnt.stream.num_stream_opened, 1);
	} else {
		COUNTER_ADD(ss->cnt.stream.num_stream_accepted, 1);
	}
	COUNTER_ADD(ss->cnt.stream.num_streams, 1);
	stream_set_state(s, active_open ? STREAM_INIT : STREAM_SYN_RECEIVED);
	ev_timer_init(&s->w_tombstone, tombstone_cb, 0.0, 0.0);
	s->w_tombstone.data = s;
	STREAM_LOG_F(DEBUG, s, "created, state=%s", stream_state_str[s->state]);
	return s;
}

void mux_stream_free(struct mux_stream *s)
{
	if (s == NULL) {
		return;
	}
	LOGV_F("[stream:%" PRIuLEAST16 "] freeing", s->id);
	if (s->halfopen_counted) {
		ASSERT(s->session->num_halfopen > 0);
		s->session->num_halfopen--;
		s->halfopen_counted = false;
		COUNTER_SUB(s->session->cnt.stream.num_stream_halfopen, 1);
	}
	COUNTER_SUB(s->session->cnt.stream.num_streams, 1);

	/* Safety net: detach/stop without invoking callbacks. */
	stream_detach_user(s);
	stream_stop(s);
	ASSERT(s->session->send_buffered_frames >= s->send_queue.count);
	s->session->send_buffered_frames -= s->send_queue.count;
	COUNTER_SUB(
		s->session->cnt.buffers.send_buffered_frames,
		s->send_queue.count);
	mux_frame_list_clear(&s->send_queue, &s->session->pool);
	ASSERT(s->session->recv_buffered_bytes >= s->recvbuf->len);
	s->session->recv_buffered_bytes -= s->recvbuf->len;
	COUNTER_SUB(
		s->session->cnt.buffers.recv_buffered_bytes, s->recvbuf->len);
	bytebuf_free(s->recvbuf);
	if (!s->is_direct && s->socket.w_io.fd != -1) {
		socket_close(s->socket.w_io.fd);
	}
	free(s);
}

void mux_stream_do_attach_fd(struct mux_stream *s, const int fd)
{
	if (s->state != STREAM_SYN_RECEIVED && s->state != STREAM_INIT &&
	    s->state != STREAM_SYN_SENT) {
		/* The application may defer attaching past the stream's own
		 * lifecycle (e.g. a peer RST arrived first while a local
		 * connect() was still in progress); there is nothing left to
		 * attach to. Take ownership of the fd we were handed and close
		 * it rather than leaking it, and reject gracefully instead of
		 * asserting on a condition the peer can trigger. */
		STREAM_LOG_F(
			DEBUG, s,
			"attach_fd: stream no longer attachable (state=%s), [fd:%d] closed",
			stream_state_str[s->state], fd);
		socket_close(fd);
		return;
	}
	ASSERT(!s->is_direct);

	struct ev_loop *const loop = s->session->loop;
	if (socket_user_timeout(fd, s->session->conf.send_timeout * 1000) ==
	    0) {
		s->socket.w_timeout.repeat = 0.0;
	}
	if (s->state == STREAM_SYN_RECEIVED) {
		STREAM_LOG_F(
			INFO, s, "stream accepted, local connect [fd:%d]", fd);
		/* Assign the fd before attempting the SYN|ACK send so a failure
		 * below still closes it via the normal mux_stream_abort() -> fd-close
		 * path instead of leaking it. */
		ev_io_set(&s->socket.w_io, fd, EV_WRITE);
		/* SYN|ACK now so the peer can send while local connect() is in
		 * progress; received data buffers until the connection completes. */
		const uint_fast32_t inc = mux_stream_grant_inc(s);
		if (!mux_session_send_ctrl(
			    s->session, s->id, MUX_FLAG_SYN | MUX_FLAG_ACK,
			    inc)) {
			STREAM_LOG(
				WARNING, s,
				"SYN|ACK failed (OOM), aborting stream");
			mux_stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
			return;
		}
		s->grant_sent += inc * MUX_WINDOW_UNIT;
		s->ack_pending = false;
		stream_set_state(s, STREAM_ESTABLISHED);
		s->socket.connected = false;
		if (s->socket.w_timeout.repeat > 0.0) {
			ev_timer_again(loop, &s->socket.w_timeout);
		}
	} else {
		STREAM_LOG_F(VERBOSE, s, "local accept [fd:%d]", fd);
		s->socket.connected = true;
		/* One frame may be read here for fast open (SYN|PUSH);
		 * update_watcher will set EV_READ when the queue is empty. */
		ev_io_set(&s->socket.w_io, fd, EV_NONE);
	}
	ev_io_start(loop, &s->socket.w_io);
	update_watcher(s);
}

bool mux_stream_do_io_start(struct ev_loop *loop, struct mux_stream_io *w)
{
	struct mux_stream *const s = w->stream;
	if (s == NULL) {
		/* mux_stream_io_stop() is terminal: it severs w->stream, so a
		 * later io_start has no stream to attach. Return rather than
		 * dereferencing NULL (the equivalent assert ships compiled out
		 * under NDEBUG in every release build). */
		return false;
	}
	if (s->state != STREAM_SYN_RECEIVED && s->state != STREAM_INIT &&
	    s->state != STREAM_SYN_SENT) {
		/* Same race as mux_stream_do_attach_fd -- the stream may have already
		 * left every attachable state (e.g. a peer RST) by the time the
		 * application starts direct I/O. Sever the binding and report
		 * failure so the caller does not wait forever for an event that
		 * will never come, and so w->stream cannot dangle once the stream
		 * is freed (stream_detach_user bails on !is_direct). */
		STREAM_LOG_F(
			DEBUG, s,
			"io_start: stream no longer attachable (state=%s)",
			stream_state_str[s->state]);
		w->stream = NULL;
		w->active = 0;
		return false;
	}
	ASSERT(!s->is_direct); /* neither mode activated yet */

	w->loop = loop;
	/* Activate direct mode before attempting the SYN|ACK send below so a
	 * failure can notify @p w through the normal mux_stream_abort() path
	 * instead of leaving it attached with no event ever delivered. */
	s->is_direct = true;
	s->direct.w_io = w;
	w->active = 1;

	if (s->state == STREAM_SYN_RECEIVED) {
		/* Passive opener: local side is ready, complete the handshake. */
		STREAM_LOG(INFO, s, "stream accepted (direct)");
		const uint_fast32_t inc = mux_stream_grant_inc(s);
		if (!mux_session_send_ctrl(
			    s->session, s->id, MUX_FLAG_SYN | MUX_FLAG_ACK,
			    inc)) {
			STREAM_LOG(
				WARNING, s,
				"SYN|ACK failed (OOM), aborting stream");
			mux_stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
			/* mux_stream_abort severed the binding for this direct stream
			 * (stream_detach_user cleared w->stream and dropped any
			 * pending event), so honor the "false => binding severed,
			 * no event will fire" contract like the not-attachable path
			 * above -- returning true would leave the caller waiting on
			 * a detached watcher for an event that never comes. */
			return false;
		}
		s->grant_sent += inc * MUX_WINDOW_UNIT;
		s->ack_pending = false;
		stream_set_state(s, STREAM_ESTABLISHED);
	} else {
		STREAM_LOG(VERBOSE, s, "direct attach (active)");
	}

	if (stream_direct_read_ready(s)) {
		stream_feed_user(s, EV_READ);
	}
	if (stream_direct_write_ready(s)) {
		stream_feed_user(s, EV_WRITE);
	}
	return true;
}

void mux_stream_mark_syn_sent(struct mux_stream *s)
{
	ASSERT(s->state == STREAM_INIT);
	stream_set_state(s, STREAM_SYN_SENT);
	/* Stamp the connect-latency start with the transition itself, so a future
	 * third caller cannot split the two and silently lose the measurement
	 * (syn_sent_ns is read only by stream.c/recv.c). */
	s->syn_sent_ns = (int_least64_t)clock_monotonic_ns();
	/* Fast-open path: fd is attached; stop watcher while SYN is in flight.
	 * If fd == -1, the watcher was never started. Guard on !is_direct
	 * first, matching every other touch point of this union: a direct-mode
	 * stream (mux_stream_io_start, common for 0-RTT opens before the SYN
	 * even leaves) has only written the union's direct.w_io arm, and
	 * reading .socket.w_io.fd there is type-punning through the wrong
	 * member. */
	if (!s->is_direct && s->socket.w_io.fd != -1) {
		update_watcher(s);
	}
}

static inline void stream_notify_writable(struct mux_stream *restrict s)
{
	if (!s->is_direct) {
		update_watcher(s);
	}
	/* Gate the direct-mode EV_WRITE feed on the same readiness predicate
	 * mux_stream_do_io_start() and mux_stream_io_modify() apply, so a WINDOW/ACK
	 * grant that arrives for a no-longer-sendable stream (e.g. after a local
	 * FIN, STREAM_CLOSING) does not feed a spurious EV_WRITE. */
	if (stream_can_send_data(s)) {
		stream_feed_user(s, EV_WRITE);
	}
}

void mux_stream_start(struct mux_stream *s)
{
	STREAM_LOG(VERBOSE, s, "starting");
	ASSERT(s->state == STREAM_SYN_SENT);
	stream_set_state(s, STREAM_ESTABLISHED);
	/* State is unconditionally ESTABLISHED here (asserted SYN_SENT on entry,
	 * just transitioned, no reentrant state change), so schedule the early FIN
	 * purely on a pending local EOF with an empty send queue. */
	if (s->rx_eof && s->send_queue.head == NULL) {
		STREAM_LOG(VERBOSE, s, "early local EOF, scheduling FIN");
		mux_sched_wake(s->session, s);
	}
	stream_notify_writable(s);
}

/* Queue @p frame (payload already filled in, frame->len set) on @p s's send
 * queue, paying into the same send_buffered_frames/queued_send_bytes
 * bookkeeping every dequeue/free path decrements out of. The sole place this
 * must happen so socket-mode and direct-mode can't drift apart. */
void mux_stream_queue_send(struct mux_stream *s, struct mux_frame *frame)
{
	frame->pos = 0;
	s->queued_send_bytes +=
		(uint_least32_t)(frame->len - MUX_FRAME_HEADER_SIZE);
	mux_frame_list_push(&s->send_queue, frame);
	s->session->send_buffered_frames++;
	COUNTER_ADD(s->session->cnt.buffers.send_buffered_frames, 1);
}

struct mux_frame *mux_stream_dequeue_send(struct mux_stream *restrict s)
{
	/* Allow first payload in pre-SYN stage, then regular established states. */
	if (!stream_can_send_data(s)) {
		return NULL;
	}

	struct mux_frame *frame = s->send_queue.head;
	if (frame == NULL) {
		/* Clear stale nagle_flush (delayed-ACK timer fired with no data
		 * queued) so the next small frame does not bypass Nagle. */
		s->nagle_flush = false;
		return NULL;
	}

	const uint_fast32_t credit = stream_credit_avail(s);
	if (credit == 0) {
		STREAM_LOG(VERBOSE, s, "send credit exhausted");
		return NULL;
	}
	STREAM_LOG_F(
		VERYVERBOSE, s, "dequeue_send credit=%" PRIuFAST32, credit);
	const size_t payload = frame->len - MUX_FRAME_HEADER_SIZE;
	STREAM_LOG_F(
		VERYVERBOSE, s,
		"dequeue_send payload=%zu frame_len=%zu frame_pos=%zu", payload,
		frame->len, frame->pos);

	if (payload == 0 || payload > credit) {
		STREAM_LOG_F(
			VERYVERBOSE, s,
			"dequeue blocked: payload=%zu credit=%" PRIuFAST32,
			payload, credit);
		return NULL;
	}

	/* Nagle: hold small frames while unacked data is in-flight.
	 * nagle_flush is a one-shot bypass set by the delay scheduler. */
	const bool nagle_bypass = s->nagle_flush;
	s->nagle_flush = false;
	if (!s->session->conf.nodelay && !nagle_bypass &&
	    s->unacked_bytes > 0 && payload < (size_t)s->session->max_payload) {
		STREAM_LOG_F(
			VERYVERBOSE, s,
			"nagle hold: payload=%zu unacked=%" PRIuLEAST32,
			payload, s->unacked_bytes);
		return NULL;
	}

	frame = mux_frame_list_pop(&s->send_queue);
	s->queued_send_bytes -=
		(uint_least32_t)(frame->len - MUX_FRAME_HEADER_SIZE);
	s->session->send_buffered_frames--;
	COUNTER_SUB(s->session->cnt.buffers.send_buffered_frames, 1);
	return frame;
}

void mux_stream_notify_recv(struct mux_stream *restrict s)
{
	/* A dequeued send_queue slot may restore read credit; re-evaluate the
	 * socket-mode watcher to re-enable EV_READ. */
	if (!s->is_direct) {
		update_watcher(s);
		return;
	}
	/* Notify the user that send credit is available; otherwise credit
	 * would only be visible after the peer sends a window update. */
	if (stream_read_credit_avail(s) > 0) {
		stream_feed_user(s, EV_WRITE);
	}
}

static inline void stream_notify_readable(struct mux_stream *restrict s)
{
	if (s->is_direct) {
		stream_feed_user(s, EV_READ);
		return;
	}
	/* Eager-deliver only while the local write watcher is idle.  Once EV_WRITE
	 * is armed the socket is backpressured, so payload accumulates in recvbuf
	 * and the coalesced EV_WRITE drain delivers it in one write. */
	if (s->socket.connected && !(s->socket.w_io.events & EV_WRITE)) {
		struct mux_session *const restrict ss = s->session;
		stream_flush_local(s);
		/* stream_flush_local can close the last active stream of a
		 * draining session and free s via the drain cascade. */
		if (session_streams_freed(ss)) {
			return;
		}
	}
	update_watcher(s);
	stream_feed_user(s, EV_READ);
}

void mux_stream_recv_copy(
	struct mux_stream *restrict s, const unsigned char *restrict payload,
	size_t payload_len)
{
	if (s->state == STREAM_CLOSED) {
		STREAM_LOG_F(
			VERBOSE, s,
			"discarding PUSH frame (%zu bytes) in CLOSED state",
			payload_len);
		return;
	}

	STREAM_LOG_F(
		VERYVERBOSE, s, "receiving PUSH frame with %zu bytes",
		payload_len);
	/* Flow control (spec §6.5/§6.6): the peer must not send more cumulative
	 * PUSH payload than the credit we have granted. recv_window alone does
	 * not enforce this -- it tracks undrained buffered_bytes, so a peer facing
	 * a promptly-draining app can push past grant_sent without ever tripping
	 * it, and stream_grantable_bytes' (grant_sent - bytes_received) then wraps
	 * in uint_least32_t, freezing the credit loop for the session's life.
	 * bytes_received and grant_sent both wrap, so compare via the module's
	 * wrap-safe idiom rather than magnitude: the outstanding credit
	 * (grant_sent - bytes_received) must cover this frame. payload_len is
	 * frame-bounded (<= 16 KiB) so the subtraction never wraps in the
	 * over-send direction; a plain-magnitude compare would instead abort a
	 * conforming bulk stream every ~4 GiB, when grant_sent wraps first. */
	if (payload_len > (uint_fast32_t)(s->grant_sent - s->bytes_received)) {
		STREAM_LOG_F(
			WARNING, s,
			"flow control: received=%" PRIuLEAST32
			" + payload=%zu exceeds granted credit=%" PRIuLEAST32,
			s->bytes_received, payload_len, s->grant_sent);
		mux_stream_abort(s, MUX_STATUS_FLOW_CONTROL_ERROR);
		return;
	}
	/* Window updates are quantized to MUX_WINDOW_UNIT; up to one full payload
	 * of over-window data is tolerated.  Hard cap: recv_window. */
	if (s->buffered_bytes + payload_len > s->recv_window) {
		STREAM_LOG_F(
			WARNING, s,
			"recv window overflow: payload_len=%zu buffered=%" PRIuLEAST32
			" window=%" PRIuLEAST32,
			payload_len, s->buffered_bytes, s->recv_window);
		mux_stream_abort(s, MUX_STATUS_FLOW_CONTROL_ERROR);
		return;
	}

	/* Fast path: with an empty recvbuf and a connected socket, write the
	 * payload straight to the fd, skipping the recvbuf memcpy and flush
	 * round-trip; only the unwritten remainder falls through to the bytebuf. */
	if (payload_len > 0 && bytebuf_readable(s->recvbuf) == 0 &&
	    !s->is_direct && s->socket.connected &&
	    (s->state == STREAM_ESTABLISHED || s->state == STREAM_CLOSE_WAIT)) {
		/* stream_local_write may mux_stream_abort on a hard error, which
		 * (last active stream + drain) can free s via the cascade;
		 * capture the session first, then check the free before touching
		 * s. The short-circuit keeps the s->state read on the alive path. */
		struct mux_session *const restrict ss = s->session;
		const size_t nwrite =
			stream_local_write(s, payload, payload_len);
		if (session_streams_freed(ss) || s->state == STREAM_CLOSED) {
			return;
		}
		if (nwrite > 0) {
			s->bytes_received += (uint_least32_t)nwrite;
			payload += nwrite;
			payload_len -= nwrite;
			mux_stream_check_ack(s);
			if (payload_len == 0) {
				STREAM_LOG_F(
					VERYVERBOSE, s,
					"direct write: %zu bytes, "
					"received=%" PRIuLEAST32,
					nwrite, s->bytes_received);
				return;
			}
		}
	}

	if (payload_len == 0) {
		return;
	}

	if (!mux_bytebuf_reserve(&s->recvbuf, payload_len, true)) {
		STREAM_LOG(WARNING, s, "out of memory for receive buffer");
		mux_stream_abort(s, MUX_STATUS_INTERNAL_ERROR);
		return;
	}

	memcpy(bytebuf_write_ptr(s->recvbuf), payload, payload_len);
	bytebuf_produce(s->recvbuf, payload_len);
	s->session->recv_buffered_bytes += payload_len;
	COUNTER_ADD(s->session->cnt.buffers.recv_buffered_bytes, payload_len);
	s->bytes_received += (uint_least32_t)payload_len;
	s->buffered_bytes += (uint_least32_t)payload_len;

	STREAM_LOG_F(
		VERYVERBOSE, s,
		"queued %zu bytes, received=%" PRIuLEAST32
		" buffered=%" PRIuLEAST32,
		payload_len, s->bytes_received, s->buffered_bytes);

	stream_notify_readable(s);
}

/* In auto-window mode, lazily shrink recv_window to the session stream_window
 * target once it is safe (buffered + outstanding peer credit fits the target).
 * Called atop mux_stream_check_ack so every grant sees the current window. */
static void stream_try_shrink_recv_window(struct mux_stream *restrict s)
{
	if (!s->session->auto_stream_window) {
		return;
	}
	const uint_fast32_t target =
		(uint_fast32_t)s->session->stream_window * MUX_WINDOW_UNIT;
	if (target >= s->recv_window) {
		return;
	}
	/* outstanding = credit peer may still spend (wrapping subtraction). */
	const uint_fast32_t outstanding =
		(uint_fast32_t)(s->grant_sent - s->bytes_received);
	if (s->buffered_bytes + outstanding > target) {
		return;
	}
	STREAM_LOG_F(
		DEBUG, s,
		"recv_window shrink: %" PRIuLEAST32 " -> %" PRIuFAST32
		" (buffered=%" PRIuLEAST32 " outstanding=%" PRIuFAST32 ")",
		s->recv_window, target, s->buffered_bytes, outstanding);
	s->recv_window = target;
}

void mux_stream_check_ack(struct mux_stream *restrict s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	stream_try_shrink_recv_window(s);
	if (s->ack_pending) {
		return;
	}

	const uint_fast32_t grantable = stream_grantable_bytes(s);
	/* Sub-unit grantable cannot be sent; see mux_stream_grant_inc(). */
	if (grantable < (uint_fast32_t)MUX_WINDOW_UNIT) {
		return;
	}
	/* Immediate ACK at 2-frame threshold (avoids half-window starvation);
	 * sub-threshold grants coalesce (spec §6.4, §7.1).  Tracks consumed
	 * payload bytes, not credit units. */
	const uint_fast32_t immediate =
		2u * (uint_fast32_t)s->session->max_payload;
	const bool immediate_ack = grantable >= immediate;
	if (!immediate_ack) {
		/* Sub-threshold: arm the coalescing timer so the grant is
		 * conveyed on the next flush (spec §6.4, §7.1). */
		STREAM_LOG_F(
			VERBOSE, s, "ACK delayed: grantable=%" PRIuFAST32,
			grantable);
		mux_sched_delay(s->session, s, MUX_DELAYED_ACK_TICKS);
		return;
	}
	STREAM_LOG_F(
		DEBUG, s, "ACK immediate: grantable=%" PRIuFAST32, grantable);
	s->ack_pending = true;
	if (s->sched_queue != SCHED_QUEUE_DRR &&
	    s != s->session->sched.drr_active) {
		mux_sched_wake(s->session, s);
	}
}

void mux_stream_recv_window(struct mux_stream *s, const uint_fast32_t window_inc)
{
	const uint_fast32_t inc_bytes = window_inc * MUX_WINDOW_UNIT;

	/* spec §6.6: 64-bit pre-check bounds credit at INT32_MAX, the range
	 * where the wrapping arithmetic stays correct. */
	const uint_fast32_t outstanding = stream_credit_avail(s);
	if ((uint_fast64_t)outstanding + inc_bytes > (uint_fast64_t)INT32_MAX) {
		STREAM_LOG_F(
			WARNING, s,
			"excessive send credit: outstanding=%" PRIuFAST32
			" inc=%" PRIuFAST32,
			outstanding, inc_bytes);
		mux_stream_abort(s, MUX_STATUS_FLOW_CONTROL_ERROR);
		return;
	}

	s->send_window += inc_bytes;

	STREAM_LOG_F(
		VERYVERBOSE, s,
		"recv_window: inc=%" PRIuFAST32 " send_window=%" PRIuLEAST32
		" sent=%" PRIuLEAST32,
		window_inc, s->send_window, s->bytes_sent);
	if (outstanding == 0 && inc_bytes > 0) {
		STREAM_LOG_F(
			DEBUG, s,
			"send credit restored: inc=%" PRIuFAST32
			" credit=%" PRIuFAST32 " queued=%" PRIuLEAST32,
			window_inc, stream_credit_avail(s),
			s->queued_send_bytes);
	}

	if (outstanding + inc_bytes == 0) {
		STREAM_LOG(VERYVERBOSE, s, "send credit still exhausted");
		return;
	}

	stream_notify_writable(s);

	if (s->send_queue.head != NULL) {
		mux_sched_wake(s->session, s);
	}
}

void mux_stream_mark_fin_sent(struct mux_stream *s)
{
	if (s->state == STREAM_FIN_WAIT || s->state == STREAM_CLOSING) {
		return;
	}
	STREAM_LOG(DEBUG, s, "sent FIN");

	switch (s->state) {
	case STREAM_ESTABLISHED:
		stream_set_state(s, STREAM_FIN_WAIT);
		break;
	case STREAM_CLOSE_WAIT:
		/* Both FINs exchanged; enter CLOSING until recv fully flushed */
		stream_set_state(s, STREAM_CLOSING);
		if (s->is_direct) {
			/* Direct mode normally defers the close to mux_stream_recv,
			 * which must not free a stream the application still holds.
			 * Once the application has closed it (user_closed) there is no
			 * such caller left, so finish it here via mux_stream_do_close -- which
			 * discards any data the peer sent after our FIN with an RST,
			 * matching mux_stream_close's close(fd) semantics for unread
			 * data, rather than stranding the stream in CLOSING for the
			 * session's life whenever that buffer is non-empty. */
			if (s->user_closed) {
				mux_stream_do_close(s);
			}
		} else if (bytebuf_readable(s->recvbuf) == 0) {
			/* Socket mode, recv drained: half-close the write side (as our
			 * two siblings do) and complete -- both FINs are now exchanged.
			 * s may be freed by the close; must not touch it again. */
			(void)stream_finish_drained_write(s);
		}
		break;
	default:
		STREAM_LOG_F(
			WARNING, s, "FIN sent in unexpected state=%s",
			stream_state_str[s->state]);
		break;
	}
}

void mux_stream_recv_fin(struct mux_stream *s)
{
	/* PUSH/ACK processing of this same frame may have aborted the stream
	 * without freeing it (recv-window overflow, §6.6 excessive credit,
	 * bytebuf OOM). The teardown is complete and the local fd already closed,
	 * so a piggybacked FIN has nothing left to do here. */
	if (s->state == STREAM_CLOSED) {
		STREAM_LOG(VERBOSE, s, "discarding FIN in CLOSED state");
		return;
	}
	if (s->state == STREAM_CLOSE_WAIT || s->state == STREAM_CLOSING) {
		return;
	}

	STREAM_LOG(DEBUG, s, "received FIN");

	switch (s->state) {
	case STREAM_ESTABLISHED:
		stream_set_state(s, STREAM_CLOSE_WAIT);
		break;
	case STREAM_FIN_WAIT:
		/* Both FINs exchanged; enter CLOSING until recv fully flushed */
		stream_set_state(s, STREAM_CLOSING);
		break;
	default:
		STREAM_LOG_F(
			WARNING, s, "FIN received in unexpected state=%s",
			stream_state_str[s->state]);
		break;
	}

	/* A direct-mode stream the application has closed has no mux_stream_recv
	 * caller left to complete it and no local socket to shut down, so finish
	 * it here once both FINs are exchanged; otherwise it would sit in CLOSING
	 * for the session's life, holding its scheduler slot and max_streams quota.
	 * Complete via mux_stream_do_close so any data the peer sent after our FIN is
	 * discarded with an RST -- close(fd) semantics, as mux_stream_close applies
	 * to unread data -- rather than stranding the stream whenever that buffer
	 * is non-empty. */
	if (s->is_direct && s->user_closed && s->state == STREAM_CLOSING) {
		/* s may be freed here (last active stream + a drain in progress
		 * cascades into mux_session_initiate_shutdown -> mux_sched_free_streams) --
		 * must not touch it again. */
		mux_stream_do_close(s);
		return;
	}

	/* Socket mode with no pending recv: half-close the local write side and,
	 * once both FINs are exchanged, complete. Direct mode defers to
	 * mux_stream_recv; an in-progress connect defers to stream_flush_local
	 * (handled inside the helper). */
	if (!s->is_direct && bytebuf_readable(s->recvbuf) == 0) {
		/* The close may free s (drain cascade); must not touch it again. */
		if (stream_finish_drained_write(s)) {
			return;
		}
	}
	stream_feed_user(s, EV_READ);
}

static void stream_rst_notify_socket(struct mux_stream *restrict s)
{
	if (s->socket.w_io.fd == -1) {
		/* Not yet attached (e.g. a peer RST before mux_stream_do_attach_fd);
		 * no socket to abortively close. */
		return;
	}
	/* Abortively close the local socket to propagate RST to the peer. */
	(void)socket_set_linger(s->socket.w_io.fd, true, 0);
}

void mux_stream_recv_rst(struct mux_stream *s, const uint_fast16_t status)
{
	/* status is otherwise write-only -- the sender selects it
	 * (PROTOCOL_ERROR/REFUSED_STREAM/CANCEL/...) but nothing on the receive
	 * side ever surfaced it, so a peer's REFUSED_STREAM was
	 * indistinguishable from FLOW_CONTROL_ERROR when debugging. */
	STREAM_LOG_F(
		DEBUG, s, "received RST: %s (%" PRIuFAST16 ")",
		mux_status_str(status), status);
	s->rst_received = true;
	if (!s->is_direct) {
		stream_rst_notify_socket(s);
	} else {
		/* Fire EV_READ before detach so the callback sees rst_received; it
		 * may call mux_stream_close(). On the last active stream of a
		 * draining session that cascades into mux_session_initiate_shutdown ->
		 * mux_sched_free_streams and frees s (the session object survives), so
		 * capture it and stop touching s -- both the STREAM_CLOSED read below
		 * and the recv-buffer bookkeeping after it, which the cascade already
		 * tore down -- once the free shows. */
		struct mux_session *const restrict ss = s->session;
		stream_rst_notify_direct(s);
		if (session_streams_freed(ss)) {
			return;
		}
	}
	if (s->state == STREAM_CLOSED) {
		return;
	}
	stream_detach_user(s);
	/* Discard outbound frames and the inbound receive buffer (spec §4.3.4:
	 * data buffered in the receive buffer MUST be discarded on RST). */
	mux_session_discard_stream_frames(s->session, s->id);
	ASSERT(s->session->recv_buffered_bytes >= s->recvbuf->len);
	s->session->recv_buffered_bytes -= s->recvbuf->len;
	COUNTER_SUB(
		s->session->cnt.buffers.recv_buffered_bytes, s->recvbuf->len);
	bytebuf_reset(s->recvbuf);
	s->buffered_bytes = 0;
	stream_mark_closed(s);
}

void mux_stream_do_close(struct mux_stream *s)
{
	if (s->state == STREAM_CLOSED) {
		return;
	}
	STREAM_LOG(VERBOSE, s, "closing");
	if (bytebuf_readable(s->recvbuf) > 0) {
		STREAM_LOG(DEBUG, s, "unread data at close, sending RST");
		ASSERT(s->session->recv_buffered_bytes >= s->recvbuf->len);
		s->session->recv_buffered_bytes -= s->recvbuf->len;
		COUNTER_SUB(
			s->session->cnt.buffers.recv_buffered_bytes,
			s->recvbuf->len);
		bytebuf_reset(s->recvbuf);
		s->buffered_bytes = 0;
		mux_session_discard_stream_frames(s->session, s->id);
		/* Never answer a peer RST with one: spec §4.3.4 has the receiver go
		 * straight to CLOSED and send no response frame. This is reachable
		 * because mux_stream_recv_rst fires the direct-mode EV_READ notify while
		 * the pre-RST payload is still buffered, and mux.c invites the app to
		 * call mux_stream_close() from that callback -- which arrives here
		 * with data unread and rst_received already set. */
		if (!s->rst_sent && !s->rst_received) {
			/* Latch rst_sent only on a successful enqueue; see
			 * mux_stream_abort -- an OOM here must leave the RST retryable. */
			s->rst_sent = mux_session_send_ctrl(
				s->session, s->id, MUX_FLAG_RST,
				MUX_STATUS_CANCEL);
			/* This is an abortive close (unread data discarded); mark it
			 * so stream_mark_closed counts it failed even when the RST
			 * could not be enqueued (rst_sent stays false on OOM),
			 * mirroring mux_stream_abort's aborted latch. */
			s->aborted = true;
		}
	}
	stream_detach_user(s);
	stream_mark_closed(s);
}

void mux_stream_do_shutdown(struct mux_stream *s)
{
	STREAM_LOG(VERBOSE, s, "local shutdown (write-EOF)");
	s->rx_eof = true;
	/* A direct-mode stream the application has fully closed (mux_stream_close
	 * set user_closed and detached the watcher) that is already in CLOSING --
	 * both FINs exchanged, completion previously deferred to mux_stream_recv --
	 * has no reader left to finish it; setting rx_eof + mux_sched_wake alone would
	 * strand it in CLOSING for the session's life (holding its scheduler slot
	 * and max_streams quota). Complete it here. stream_mark_closed may free s
	 * via the drain cascade, which is fine: mux_stream_close has relinquished
	 * it. A half-close (mux_stream_shutdown) never sets user_closed, so this
	 * cannot fire there. */
	if (s->is_direct && s->user_closed && s->state == STREAM_CLOSING &&
	    bytebuf_readable(s->recvbuf) == 0) {
		stream_mark_closed(s);
		return;
	}
	mux_sched_wake(s->session, s);
}

int mux_stream_format_tag(
	char *restrict buf, size_t buflen, const struct mux_stream *restrict s)
{
	const struct mux_session *const ss = s->session;
	/* Peer-initiated: a server session sees odd IDs (its own are even). */
	const bool peer_initiated = (bool)(s->id & 1u) == ss->accepted;
	const char *const arrow = peer_initiated ? " <- " : " -> ";

	/* Either endpoint may be an identity: this node's own is config-supplied
	 * and the peer's claim is only NUL-excluded per doc/spec.md 5.2.3.2, so a
	 * CR/LF or ESC in it would forge a log record or drive the terminal of
	 * whoever reads the log (CWE-117 / CWE-150). Escape both before they reach
	 * the tag, matching tunnel_set_tag(); the address and fd fallbacks are
	 * self-generated and need none. */
	char me[64];
	if (ss->handshake.identity != NULL) {
		escape_identity(
			me, sizeof(me), ss->handshake.identity, ESCAPE_PLAIN);
	} else {
		union sockaddr_max addr;
		if (socket_get_addr(ss->w_socket.fd, &addr)) {
			if (sa_format(me, sizeof(me), &addr.sa) < 0) {
				me[0] = '\0';
			}
		} else {
			const int ret = snprintf(
				me, sizeof(me), "[fd:%d]", ss->w_socket.fd);
			if (ret < 0) {
				me[0] = '\0';
			}
		}
	}

	char peer[64];
	if (ss->handshake.peer_identity != NULL) {
		escape_identity(
			peer, sizeof(peer), ss->handshake.peer_identity,
			ESCAPE_PLAIN);
	} else if (ss->handshake.peer_id != NULL) {
		escape_identity(
			peer, sizeof(peer), ss->handshake.peer_id,
			ESCAPE_PLAIN);
	} else if (ss->peer_addr.sa.sa_family != AF_UNSPEC) {
		if (sa_format(peer, sizeof(peer), &ss->peer_addr.sa) < 0) {
			peer[0] = '\0';
		}
	} else {
		const int ret = snprintf(
			peer, sizeof(peer), "[fd:%d]", ss->w_socket.fd);
		if (ret < 0) {
			peer[0] = '\0';
		}
	}

	return snprintf(
		buf, buflen, "[%" PRIuLEAST16 "] %s%s%s:", s->id, me, arrow,
		peer);
}
