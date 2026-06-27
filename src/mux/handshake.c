/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file handshake.c
 * @brief Internal mux hello and resume handshake implementation.
 */

#include "mux/handshake.h"

#include "mux/frame.h"
#include "mux/mux.h"
#include "mux/proto_schema.gen.h"
#include "mux/sched.h"
#include "mux/session.h"
#include "mux/unacked.h"
#include "mux/wire.h"

#include "algo/hashtable.h"
#include "codec/base64.h"
#include "net/mime.h"
#include "utils/debug.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Hello wire format (spec §5.2.1): version=0, flags=0, length=json_len,
 * stream_id=0, extra=0, followed by the JSON body on stream 0. */
#define PROTO_MIME_TYPE "application/x-multiplexd-proto"
#define PROTO_VERSION "1"
#define PROTO_TYPE PROTO_MIME_TYPE "; version=" PROTO_VERSION

/* Base64 length of MUX_SESSION_ID_LEN bytes (with padding). */
enum { SESSION_ID_B64 = 24u };

static bool proto_hello_build(
	struct mux_frame *const frame, const size_t payload_cap,
	const struct proto_hello *const msg)
{
	char id_b64[SESSION_ID_B64 + 1];
	if (msg->has_session_id) {
		size_t len = SESSION_ID_B64;
		(void)base64_encode(
			(unsigned char *)id_b64, &len, msg->session_id,
			MUX_SESSION_ID_LEN);
		id_b64[SESSION_ID_B64] = '\0';
	}
	/* Strings in raw are borrowed; do not call json_free_proto(). */
	const struct json_proto raw = {
		.type = { .str = (char *)PROTO_TYPE, .len = sizeof(PROTO_TYPE) - 1 },
		.msgid = msg->msgid,
		.session_id = {
			.str = msg->has_session_id ? id_b64 : NULL,
			.len = msg->has_session_id ? SESSION_ID_B64 : 0,
		},
		.resume_seq = msg->has_resume_seq ? (unsigned)msg->resume_seq : 0,
		.extensions = {
			.reject_inbound = msg->reject_inbound,
			.identity = {
				.str = msg->has_identity
					? (char *)msg->identity
					: NULL,
				.len = msg->has_identity
					? strlen(msg->identity)
					: 0,
			},
		},
	};
	/* Marshal directly after the header; reserve one byte for the NUL that
	 * json_marshal_proto writes, hence the strict >= bound below. */
	const int json_sz = json_marshal_proto(
		(char *)frame->data + MUX_FRAME_HEADER_SIZE, payload_cap, &raw,
		NULL);
	if (json_sz <= 0 || (size_t)json_sz >= payload_cap) {
		return false;
	}
	const struct mux_header hdr = {
		.version = 0,
		.flags = 0,
		.length = (uint_least16_t)json_sz,
		.stream_id = 0,
		.extra = 0,
	};
	mux_write_header(frame->data, &hdr);
	frame->len = MUX_FRAME_HEADER_SIZE + (size_t)json_sz;
	return true;
}

static bool proto_parse_type(const char *type, int *const version_out)
{
	const size_t len = strlen(type);
	if (len > MUX_MAX_PAYLOAD_SIZE) {
		LOGE("protocol type too large");
		return false;
	}
	/* mime_parse tokenizes the buffer in place; copy onto the heap rather
	 * than a peer-sized stack VLA (the ASSERT bound compiles out under
	 * NDEBUG, leaving the stack at the mercy of the peer's type length). */
	char *const buf = malloc(len + 1);
	if (buf == NULL) {
		LOGOOM();
		return false;
	}
	memcpy(buf, type, len + 1);

	bool ok = false;
	char *media_type, *media_subtype;
	char *next = mime_parse(buf, &media_type, &media_subtype);
	if (next == NULL || strcmp(media_type, "application") != 0 ||
	    strcmp(media_subtype, "x-multiplexd-proto") != 0) {
		LOGE_F("unsupported protocol: \"%s\"", type);
		goto done;
	}

	const char *version = NULL;
	char *key, *value;
	next = mime_parseparam(next, &key, &value);
	while (next != NULL && key != NULL) {
		if (strcmp(key, "version") == 0) {
			version = value;
		}
		next = mime_parseparam(next, &key, &value);
	}
	if (version == NULL) {
		LOGE("protocol version not specified");
		goto done;
	}
	errno = 0;
	char *end = NULL;
	const uintmax_t parsed = strtoumax(version, &end, 10);
	if (errno != 0 || end == version || *end != '\0' || parsed == 0 ||
	    parsed > (uintmax_t)UINT8_MAX) {
		LOGE_F("invalid protocol version: %s", version);
		goto done;
	}
	*version_out = (int)parsed;
	ok = true;
done:
	free(buf);
	return ok;
}

/* Decode a Base64-encoded session_id string into a binary buffer.
 * Returns true on success; out receives MUX_SESSION_ID_LEN bytes. */
static bool proto_parse_session_id(const char *str, unsigned char *out)
{
	if (strlen(str) != SESSION_ID_B64) {
		return false;
	}
	size_t len = MUX_SESSION_ID_LEN;
	if (!base64_decode(
		    out, &len, (const unsigned char *)str, SESSION_ID_B64) ||
	    len != MUX_SESSION_ID_LEN) {
		return false;
	}
	return true;
}

static bool proto_hello_parse(
	const unsigned char *const json, const size_t json_len,
	struct proto_hello *const out)
{
	/* A hello may legally be up to MUX_MAX_PAYLOAD_SIZE (the JSON tolerates
	 * unknown keys and extensions).  Copy into a heap buffer rather than a
	 * stack VLA to keep the large hello off the handshake thread's stack. */
	if (json_len > MUX_MAX_PAYLOAD_SIZE) {
		LOGE("failed to parse protocol hello: too large");
		return false;
	}
	char *const json_buf = malloc(json_len + 1);
	if (json_buf == NULL) {
		LOGOOM();
		return false;
	}
	memcpy(json_buf, json, json_len);
	json_buf[json_len] = '\0';

	/* obj's string fields (type/session_id/identity) point into json_buf, so it
	 * must outlive every use below; freed together at the single cleanup exit. */
	struct json_proto obj = { 0 };
	bool ok = false;
	if (!json_unmarshal_proto(&obj, json_buf, json_len)) {
		LOGE("malformed protocol hello");
		goto done;
	}
	if (obj.type.str == NULL) {
		LOGE("protocol hello: missing type");
		goto done;
	}
	if (!proto_parse_type(obj.type.str, &out->version)) {
		goto done;
	}
	out->msgid = (int)obj.msgid;
	out->reject_inbound = obj.extensions.reject_inbound;

	if (obj.session_id.str != NULL &&
	    !proto_parse_session_id(obj.session_id.str, out->session_id)) {
		LOGE("protocol hello: invalid session_id");
		goto done;
	}
	out->has_session_id = obj.session_id.str != NULL;

	out->resume_seq = (uint_least32_t)obj.resume_seq;
	out->has_resume_seq = (obj.resume_seq != 0);

	out->has_identity = false;
	if (obj.extensions.identity.str != NULL) {
		const size_t id_len = obj.extensions.identity.len;
		if (id_len >= sizeof(out->identity)) {
			LOGE("protocol hello: identity too long");
			goto done;
		}
		out->has_identity = true;
		memcpy(out->identity, obj.extensions.identity.str, id_len + 1);
	}
	ok = true;
done:
	json_free_proto(&obj);
	free(json_buf);
	return ok;
}

bool handshake_enqueue_hello(
	struct mux_session *ss, const int msgid, const bool include_resume_seq)
{
	struct mux_frame *const frame =
		mux_frame_get(&ss->pool, ss->max_payload);
	if (frame == NULL) {
		LOGOOM();
		session_reset(ss);
		return false;
	}
	/* Include the server-assigned session_id when available.
	 * Initial ClientHello omits it; ServerHello and resume ClientHello include it. */
	struct proto_hello hello_msg = {
		.msgid = msgid,
		.reject_inbound = ss->conf.reject_inbound,
		.has_session_id = ss->handshake.has_session_id,
		.has_resume_seq = include_resume_seq,
		.resume_seq = include_resume_seq ? ss->unacked.recv_seq : 0,
	};
	if (ss->handshake.identity != NULL) {
		const size_t id_len = strlen(ss->handshake.identity);
		if (id_len < sizeof(hello_msg.identity)) {
			hello_msg.has_identity = true;
			memcpy(hello_msg.identity, ss->handshake.identity,
			       id_len + 1);
		}
	}
	if (ss->handshake.has_session_id) {
		memcpy(hello_msg.session_id, ss->handshake.session_id,
		       MUX_SESSION_ID_LEN);
	}
	MUX_LOG_F(
		VERBOSE, ss, "enqueue_hello: msgid=%d reject_inbound=%d",
		hello_msg.msgid, hello_msg.reject_inbound);
	if (hello_msg.has_session_id) {
		MUX_LOG_F(
			VERBOSE, ss,
			"enqueue_hello: session_id=%016" PRIxFAST64
			"%016" PRIxFAST64,
			read_uint64(hello_msg.session_id),
			read_uint64(hello_msg.session_id + sizeof(uint64_t)));
	}
	if (include_resume_seq) {
		MUX_LOG_F(
			VERBOSE, ss, "enqueue_hello: resume_seq=%" PRIuLEAST32,
			hello_msg.resume_seq);
	}
	if (!proto_hello_build(frame, frame->cap, &hello_msg)) {
		MUX_LOG(ERROR, ss, "failed to build hello message");
		mux_frame_put(&ss->pool, frame);
		session_reset(ss);
		return false;
	}
	LOG_BIN_F(
		VERYVERBOSE, frame->data, frame->len, 0,
		"[fd:%d] hello send:", ss->w_socket.fd);
	ASSERT(ss->wire.sendbuf.head == NULL);
	mux_frame_list_push(&ss->wire.sendbuf, frame);
	ss->wire.tx_pending = true;
	if (include_resume_seq) {
		ss->unacked.ack_seq = ss->unacked.recv_seq;
	}
	return true;
}

/* Server side: received ClientHello.  Returns true to continue to
 * session_handshake_done; false if the session was handed off or errored. */
static bool process_hello_server(
	struct mux_session *restrict ss,
	const struct proto_hello *restrict peer_hello)
{
	/* A ClientHello carrying a session_id is a resume attempt (presence is
	 * the discriminant, not has_resume_seq, since resume_seq=0 is valid). */
	if (peer_hello->has_session_id && ss->callbacks.on_resume != NULL) {
		/* The owner moves this transient session's transport onto the
		 * matching session.  When it reports the handoff done, our transport
		 * is gone, so reset to tear this transient session down. */
		if (ss->callbacks.on_resume(
			    ss->userdata, ss, peer_hello->session_id,
			    peer_hello->resume_seq)) {
			session_reset(ss);
			return false;
		}
		MUX_LOG(WARNING, ss,
			"resume requested but no matching session found;"
			" treating as fresh");
	}
	/* Fresh session: reply with our session_id. */
	return handshake_enqueue_hello(ss, PROTO_MSG_SERVER_HELLO, false);
}

/* Client fresh-session path (spec §5.8.3 step 4): discard preserved streams and
 * unacked frames, reset counters, adopt the server's session_id, and clear
 * peer_addr so session_handshake_done fires ESTABLISHED, not RESUMED. */
static bool handshake_client_fresh(
	struct mux_session *restrict ss,
	const struct proto_hello *restrict peer_hello)
{
	if (ss->handshake.has_session_id) {
		MUX_LOG_F(
			WARNING, ss,
			"server rejected resume, falling back to fresh"
			" session (unacked=%zu streams=%zu)",
			ss->unacked.frames,
			ss->sched.streams != NULL ?
				table_size(ss->sched.streams) :
				0);
	}
	sched_free_streams(ss);
	ss->sched.streams = table_new(&mux_stream_table_opts);
	if (ss->sched.streams == NULL) {
		LOGOOM();
		session_reset(ss);
		return false;
	}
	unacked_free_all(ss);
	ss->unacked.retransmit_copy = NULL;
	ss->unacked.send_seq = 0;
	ss->unacked.recv_seq = 0;
	ss->unacked.ack_seq = 0;
	ss->unacked.last_ack_recv = 0;
	ss->unacked.ack_ticks = 0;
	memset(&ss->peer_addr, 0, sizeof(ss->peer_addr));
	/* Adopt the server-assigned session id. */
	if (peer_hello->has_session_id) {
		memcpy(ss->handshake.session_id, peer_hello->session_id,
		       MUX_SESSION_ID_LEN);
		ss->handshake.has_session_id = true;
	}
	return true;
}

/* Client side: received ServerHello (spec §5.8.3).  A resume is confirmed when
 * the server echoes the same session_id; resume_seq=0 is valid and may not be
 * transmitted.  Returns true to continue, false on error. */
static bool process_hello_client(
	struct mux_session *restrict ss,
	const struct proto_hello *restrict peer_hello)
{
	const bool is_confirmed_resume =
		ss->handshake.has_session_id && peer_hello->has_session_id &&
		memcmp(peer_hello->session_id, ss->handshake.session_id,
		       MUX_SESSION_ID_LEN) == 0;
	if (is_confirmed_resume) {
		/* Trim our unacked list by the server's resume_seq. */
		if (!unacked_resume_ack_recv(ss, peer_hello->resume_seq)) {
			session_reset(ss);
			return false;
		}
		MUX_LOG_F(
			INFO, ss,
			"session resumed, resume_seq=%" PRIuLEAST32
			" unacked=%zu",
			peer_hello->resume_seq, ss->unacked.frames);
	} else {
		if (!handshake_client_fresh(ss, peer_hello)) {
			return false;
		}
	}
	return true;
}

bool handshake_process_hello(
	struct mux_session *restrict ss, const struct mux_header *restrict hdr,
	const size_t frame_size)
{
	if (ss->state != SESSION_HANDSHAKE) {
		MUX_LOG(ERROR, ss, "unexpected hello frame outside handshake");
		session_reset(ss);
		return false;
	}
	if (hdr->flags != 0 || hdr->stream_id != 0 || hdr->extra != 0) {
		MUX_LOG_F(
			ERROR, ss,
			"invalid hello frame: flags=0x%02" PRIxLEAST8
			" stream_id=%" PRIuLEAST16 " extra=%" PRIuLEAST16,
			hdr->flags, hdr->stream_id, hdr->extra);
		session_reset(ss);
		return false;
	}
	const unsigned char *const p = ringbuf_read_ptr(ss->wire.recvbuf);
	LOG_BIN_F(
		VERYVERBOSE, p, frame_size, 0,
		"[fd:%d] hello recv:", ss->w_socket.fd);
	const int expected_msgid =
		ss->accepted ? PROTO_MSG_CLIENT_HELLO : PROTO_MSG_SERVER_HELLO;
	struct proto_hello peer_hello = { 0 };
	if (!proto_hello_parse(
		    p + MUX_FRAME_HEADER_SIZE, (size_t)hdr->length,
		    &peer_hello)) {
		session_reset(ss);
		return false;
	}
	if (peer_hello.version != MUX_PROTOCOL_VERSION) {
		MUX_LOG_F(
			ERROR, ss, "incompatible protocol version: %d",
			peer_hello.version);
		session_reset(ss);
		return false;
	}
	if (peer_hello.msgid != expected_msgid) {
		MUX_LOG_F(
			ERROR, ss,
			"protocol hello: unexpected msgid %d (expected %d)",
			peer_hello.msgid, expected_msgid);
		session_reset(ss);
		return false;
	}
	MUX_LOG_F(
		VERBOSE, ss,
		"hello recv: version=%d msgid=%d reject_inbound=%d"
		" resume_seq=%" PRIuLEAST32,
		peer_hello.version, peer_hello.msgid, peer_hello.reject_inbound,
		peer_hello.resume_seq);
	if (peer_hello.has_session_id) {
		MUX_LOG_F(
			VERBOSE, ss,
			"hello recv: session_id=%016" PRIxFAST64
			"%016" PRIxFAST64,
			read_uint64(peer_hello.session_id),
			read_uint64(peer_hello.session_id + sizeof(uint64_t)));
	}
	ss->handshake.peer_rejects_inbound_streams = peer_hello.reject_inbound;
	if (peer_hello.has_identity) {
		char *const dup = strdup(peer_hello.identity);
		if (dup == NULL) {
			LOGOOM();
			session_reset(ss);
			return false;
		}
		free(ss->handshake.peer_identity);
		ss->handshake.peer_identity = dup;
	}
	ringbuf_consume(ss->wire.recvbuf, frame_size);

	const bool ok = ss->accepted ? process_hello_server(ss, &peer_hello) :
				       process_hello_client(ss, &peer_hello);
	if (!ok) {
		return false;
	}
	session_handshake_done(ss);
	/* If resuming, start retransmitting from the head after handshake. */
	if (ss->unacked.ring != NULL && ss->unacked.ring->count > 0) {
		ss->unacked.retransmit_off = 0;
		ss->wire.tx_pending = true;
		session_notify(ss);
	}
	return true;
}
