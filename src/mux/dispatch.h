/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file dispatch.h
 * @brief Internal mux frame dispatch interface.
 */

#ifndef MUX_DISPATCH_H
#define MUX_DISPATCH_H

struct mux_session;

/* dispatch is a co-unit of session.  It handles frame parsing and
 * dispatching from the receive buffer and calls back into session.c
 * for state-machine side-effects: session_reset, session_send_ctrl,
 * session_emit_ack, session_ack_trim, session_log_frame_header. */

/* Process all complete frames in the session's receive buffer.
 * On error, session_reset has already been called and ss->state reflects
 * the new state; callers must check ss->state after this returns. */
void dispatch_frame(struct mux_session *ss);

#endif /* MUX_DISPATCH_H */
