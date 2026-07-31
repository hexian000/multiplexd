/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file stream_io.h
 * @brief Direct-mode stream I/O: the opt-in alternative to attaching a socket.
 *
 * A mux stream is driven in one of two mutually exclusive modes.  In socket
 * mode the application hands the stream a local fd (mux_stream_attach_fd(),
 * declared in mux.h) and the library pumps it.  In direct mode, declared here,
 * the application arms a ::mux_stream_io watcher for readiness and moves bytes
 * itself with mux_stream_send() / mux_stream_recv().  A stream never uses both.
 */

#ifndef MUX_STREAM_IO_H
#define MUX_STREAM_IO_H

#include "mux/mux.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>

/**
 * @addtogroup mux
 * @{
 */

/* --- Stream I/O watcher --- */

/**
 * @brief Per-stream I/O event watcher for direct (non-attach-fd) mode.
 * @note EV_READ fires on data available, peer FIN (recv returns 0), or a peer
 * RST or local abort (recv returns -1/ECONNRESET); EV_WRITE fires when the
 * send window opens.
 */
typedef struct mux_stream_io mux_stream_io;
struct mux_stream_io {
	EV_WATCHER(mux_stream_io)
	/* private */
	struct ev_loop *loop;
	struct mux_stream *stream;
	/* EV_READ | EV_WRITE */
	int events;
};

#define mux_stream_io_init(w, cb_, s_, events_)                                \
	do {                                                                   \
		ev_init((w), (cb_));                                           \
		mux_stream_io_set((w), (s_), (events_));                       \
	} while (0)

#define mux_stream_io_set(w, s_, events_)                                      \
	do {                                                                   \
		(w)->stream = (s_);                                            \
		(w)->events = (events_);                                       \
	} while (0)

/**
 * @brief Activate the watcher, entering direct I/O mode.
 * @param loop Event loop.
 * @param[in] w Stream I/O watcher.
 * @note For passive-open streams this sends SYN|ACK and transitions to
 * ESTABLISHED.
 * @return true if the watcher is now bound and will deliver events; false if the
 * stream had already left every attachable state (a peer-triggerable race, e.g.
 * a peer RST): the binding is severed (w->stream cleared) and no event will ever
 * fire, so the caller must not keep waiting on @p w.
 */
bool mux_stream_io_start(struct ev_loop *loop, mux_stream_io *restrict w);

/**
 * @brief Change the events a stream I/O watcher reports.
 * @param loop Event loop.
 * @param[in] w Stream I/O watcher.
 * @param events New event mask (EV_READ | EV_WRITE).
 */
void mux_stream_io_modify(
	struct ev_loop *loop, mux_stream_io *restrict w, int events);

/**
 * @brief Permanently detach a stream I/O watcher from its stream.
 * @note This is terminal, not a reversible pause: it severs the watcher from
 * the stream (and the stream from the watcher), so the watcher cannot be
 * re-armed with mux_stream_io_start afterwards. The application still owns the
 * stream and must still mux_stream_close() it. To merely pause/resume delivery,
 * use mux_stream_io_modify(loop, w, 0) instead.
 * @param loop Event loop.
 * @param[in] w Stream I/O watcher.
 */
void mux_stream_io_stop(struct ev_loop *loop, mux_stream_io *restrict w);

/* --- Direct-mode stream data transfer --- */

/**
 * @brief Queue up to *len bytes for sending.
 * @param s Target stream.
 * @param[in] buf Source bytes.
 * @param[inout] len In: bytes to queue. Out: bytes queued (may be less when the
 * window is partially full, or zero when exhausted — retry after EV_WRITE).
 * @return 0 on success; -1/EINVAL when not writable, -1/EAGAIN when the frame
 * pool is exhausted before any data is queued.
 */
int mux_stream_send(
	struct mux_stream *restrict s, const void *restrict buf,
	size_t *restrict len);

/**
 * @brief Copy up to *len bytes from the receive buffer.
 * @param s Target stream.
 * @param[out] buf Destination.
 * @param[inout] len In: buffer capacity. Out: bytes copied (zero means peer
 * FIN).
 * @return 0 on success; -1/ECONNRESET on a peer RST or local abort (e.g. a
 * local I/O failure), -1/EAGAIN when no data is available.
 * @note If the local side has also sent FIN (CLOSING) and the buffer drains,
 * the stream closes inside this call — do not use @p s again after a zero
 * return. In CLOSE_WAIT (local FIN not yet sent) @p s stays valid; follow up
 * with mux_stream_shutdown() or mux_stream_close().
 */
int mux_stream_recv(
	struct mux_stream *restrict s, void *restrict buf,
	size_t *restrict len);

/**
 * @brief Half-close the write side (shutdown(fd, SHUT_WR)).
 * @param s Target stream.
 */
void mux_stream_shutdown(struct mux_stream *s);

/**
 * @brief Close with close(fd) semantics.
 * @param s Target stream.
 * @note Sends RST (abortive close) if the receive buffer has unread data;
 * otherwise initiates a graceful FIN, as mux_stream_shutdown() does. No RST is
 * sent for a stream that already received one -- spec §4.3.4 requires the
 * receiver answer an RST with no frame at all -- so closing from an
 * ECONNRESET notification is silent even with data still buffered.
 * @note The caller relinquishes @p s: it must not be used again, and in direct
 * mode mux_stream_recv() will not be called for it, so the library stops
 * deferring the stream's final transition to that call.
 */
void mux_stream_close(struct mux_stream *s);

/** @} */

#endif /* MUX_STREAM_IO_H */
