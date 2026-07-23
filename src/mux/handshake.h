/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file handshake.h
 * @brief Internal mux hello and resume handshake interface.
 */

#ifndef MUX_HANDSHAKE_H
#define MUX_HANDSHAKE_H

/* handshake is a co-unit of session, not a standalone module: it owns the hello
 * codec and the protocol negotiation state machine, and calls back into
 * session.c and unacked.c for lifecycle side-effects. */

#include "mux/frame.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mux_session;

/* Session identity, resume, and peer capability state.  Embedded by value in
 * mux_session. */
struct handshake_ctx {
	/* Session identity and resume state (spec §5.8) */
	/* Server-assigned session identity, shared by both peers. */
	unsigned char session_id[MUX_SESSION_ID_LEN];
	/* true when session_id has been assigned (always true for server sessions) */
	bool has_session_id : 1;

	/* Peer capabilities and identity extension */
	bool peer_rejects_inbound_streams : 1;
	/* This node's identity announced in hello. */
	char *identity;
	/* Internal peer label for diagnostics; NOT sent in hello. */
	char *peer_id;
	/* Identity received from the peer's hello. */
	char *peer_identity;
};

enum proto_msgid {
	PROTO_MSG_CLIENT_HELLO = 0,
	PROTO_MSG_SERVER_HELLO = 1,
};

struct proto_hello {
	int version;
	int msgid;
	/* Server-assigned session identity.
	 * Present in ServerHello (always) and in ClientHello only on resume.
	 * Absent in an initial ClientHello; check has_session_id before use. */
	unsigned char session_id[MUX_SESSION_ID_LEN];
	/* recv_seq of the sender; 0 on an initial (non-resume) hello */
	uint_least32_t resume_seq;
	/* Identity string claimed by the sender (NUL-terminated, max 255 chars) */
	char identity[256];
	bool has_session_id : 1;
	bool has_resume_seq : 1;
	/* extensions.reject_inbound (spec §5.2.3.1); default false */
	bool reject_inbound : 1;
	/* extensions.identity (spec §5.2.3.2) */
	bool has_identity : 1;
};

/* Build and enqueue a hello frame; include resume_seq when resuming. */
bool mux_handshake_enqueue_hello(
	struct mux_session *ss, int msgid, bool include_resume_seq);

/* Parse and validate an incoming hello frame, advancing the handshake
 * state machine. */
bool mux_handshake_process_hello(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	size_t frame_size);

#endif /* MUX_HANDSHAKE_H */
