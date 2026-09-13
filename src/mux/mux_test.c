/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* mux_test.c - integration tests for the mux protocol stack (no mocks).
 * Uses the public mux API; local proto_hello_build crafts raw hello bytes
 * for the raw-peer driver. */

#include "mux.h"

#include "estimator.h"
#include "frame.h"
#include "handshake.h"
#include "proto_schema.gen.h"
#include "recv.h"
#include "sched.h"
#include "send.h"
#include "session.h"
#if WITH_TLS
#include "shim/tls.h"
#endif
#include "stream.h"
#include "stream_io.h"
#include "unacked.h"
#include "wire.h"

#include "algo/hashtable.h"
#include "algo/wndfilter.h"
#include "binary/serialize.h"
#include "codec/base64.h"
#include "io/file.h"
#include "math/rand.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Constants */

enum {
	ESTABLISH_TIMEOUT_MS = 1000,
	ECHO_TIMEOUT_MS = 3000,
	EOF_TIMEOUT_MS = 1000,
	CLOSE_TIMEOUT_MS = 1000,
	/* reconnect_delays[0]=0.2s + handshake; 3s gives ample headroom */
	RESUME_TIMEOUT_MS = 3000,
	MAX_ACCEPTED = 16,
	PAYLOAD_SMALL = 1024,
	PAYLOAD_LARGE = 262144,
	MULTI_CONCURRENCY = 4,
	/* Two window units (2 × MUX_WINDOW_UNIT = 32768) match the immediate-ACK
	 * threshold so each drain triggers an immediate ACK and avoids the
	 * 1-tick (40 ms) delayed-ACK timer on the fast path. */
	CHUNK_SIZE = 32768,
};

/* Forward declarations */

struct mux_test_fixture;
struct test_stream;
struct pending_accept;

static void stream_io_cb(struct ev_loop *loop, mux_stream_io *w, int revents);
static bool raw_drain_available(int fd);
static bool bench_loopback_pair(int out[2]);

/* Fixture types */

enum accept_mode {
	ACCEPT_ECHO = 0, /* echo all data, mirror FIN */
	ACCEPT_CLOSE_IMMEDIATE, /* close immediately (triggers RST) */
	/* send payload from fx->accept_send_data and FIN, do not echo */
	ACCEPT_SEND_PAYLOAD,
	/* drain and discard all received data, counting recv_total; used by
	 * the throughput benchmark to measure one-directional stream rate. */
	ACCEPT_DRAIN,
	/* socket mode: attach fx->accept_attach_fd to the accepted stream */
	ACCEPT_ATTACH_FD,
	/* accept without giving the stream a mode; keep it in fx->deferred */
	ACCEPT_DEFER,
};

/* Peer identities each fixture session claims in its hello. */
#define TEST_SRV_IDENTITY "srv.test"
#define TEST_CLI_IDENTITY "cli.test"

/* One ESTABLISHED/RESUMED payload.  Its strings are owned by the session and
 * may be replaced by a later hello or freed with it, so they are copied. */
struct connected_capture {
	int_least64_t ns;
	bool fired;
	bool has_peer_identity;
	char peer_identity[256];
};

struct test_stream {
	mux_stream_io w_io;
	struct mux_test_fixture *fx;
	struct mux_stream *s;

	/* Receive accumulation */
	unsigned char *recv_buf;
	size_t recv_cap;
	size_t recv_len;

	/* Send state */
	const unsigned char *send_data;
	size_t send_len;
	size_t send_off;
	bool send_shutdown_on_drain;
	/* Throughput bench: cyclic sender.  Repeatedly transmit the fixed
	 * send_data[0, send_len) buffer until send_remaining bytes have been
	 * queued, then (with send_shutdown_on_drain) half-close. */
	bool send_cyclic;
	uint_fast64_t send_remaining;

	/* Throughput bench: receiver discards every byte into recv_buf (without
	 * advancing recv_len) and only accumulates the running total. */
	bool is_drain;
	uint_fast64_t recv_total;

	/* echo: reflect all received bytes back to the sender */
	bool is_echo;
	/* Echo backpressure: bytes of recv_buf already echoed back.  The
	 * un-echoed region [echo_off, recv_len) is re-driven from both EV_READ
	 * and EV_WRITE so a full send window does not drop data. */
	size_t echo_off;
	bool echo_fin_seen;
	bool echo_shutdown_done;
	/* close_on_readable: close the stream as soon as EV_READ fires
	 * (without consuming data), triggering RST due to unread data */
	bool close_on_readable;

	bool got_eof;
	bool got_error;
	bool closed;
	/* The harness half-closed this stream (test_stream_shutdown()). */
	bool write_shut;
};

struct mux_test_fixture {
	struct ev_loop *loop;

	struct mux_session *srv;
	struct mux_session *cli;

	bool srv_established;
	/* EV_WRITE deliveries to a test_stream after the harness half-closed
	 * it: a shut-down stream must never report writable again. */
	unsigned int writes_after_shutdown;
	bool cli_established;
	bool srv_closed;
	bool cli_closed;
	bool srv_suspended;
	bool cli_suspended;
	bool srv_resumed;
	bool cli_resumed;
	bool cli_connect_failed;
	bool cli_lost;

	/* on_event() payloads captured for the event_data contract.  The
	 * ESTABLISHED/RESUMED and CLOSED payloads are kept per side, so a
	 * transient resume session, which matches neither, overwrites nothing;
	 * STREAM_ESTABLISHED populates ev_stream_established_ns.  The LOST and
	 * CONNECT_FAILED payloads are zero, so only the cli_lost and
	 * cli_connect_failed flags above record that they fired. */
	struct connected_capture srv_connected;
	struct connected_capture cli_connected;
	int_least64_t ev_stream_established_ns;
	union mux_event_data srv_closed_data;
	union mux_event_data cli_closed_data;

	enum accept_mode accept_mode;
	/* ACCEPT_ATTACH_FD: local socket the next accepted stream is attached to;
	 * -1 once consumed. */
	int accept_attach_fd;
	/* ACCEPT_DEFER: the last stream accepted without a mode. */
	struct mux_stream *deferred;

#if WITH_TLS
	/* TLS contexts of a TLS fixture (NULL for plain TCP); freed by
	 * fixture_teardown after the sessions that reference them. */
	struct tls_context *srv_tlsctx;
	struct tls_context *cli_tlsctx;
#endif

	/* Server-side accepted streams */
	struct test_stream *accepted[MAX_ACCEPTED];
	int n_accepted;

	/* Client-side streams opened by tests */
	struct test_stream *cli_streams[MAX_ACCEPTED];
	int n_cli_streams;

	/* Server-side streams opened actively by the server */
	struct test_stream *srv_active_streams[MAX_ACCEPTED];
	int n_srv_active_streams;

	/* Payload to send from ACCEPT_SEND_PAYLOAD mode */
	const unsigned char *accept_send_data;
	size_t accept_send_len;

	/* Mux-level Nagle bypass for this fixture. */
	bool nodelay;
#if WITH_TLS
	/* TLS fixture: the library owns the socket (else memory transport). */
	bool tls_socket_offload;
#endif

	/* TCP loopback listen fd and its pending-accept watcher (cleaned up in
	 * teardown if the accept fires before teardown, pending_accept is set
	 * to NULL by pending_accept_cb after use). */
	int listen_fd_cleanup;
	struct pending_accept *pending_accept;
	/* Loopback connect address; lifetime is the fixture (outlives pa). */
	char connect_str[64];

	/* Sentinel fd held open during a transport break to prevent the server
	 * fd slot from being reused by accept() before mux_session_suspend closes it.
	 * Set by fx_break_transport; freed by fixture_teardown. */
	int break_transport_sp;

	/* Declined-resume mode: on_resume_cb detaches the transient session's
	 * transport, restores it with mux_transport_reattach and declines, so
	 * the transient must go on as a fresh session.  declined is that
	 * transient (closed by fixture_teardown); declined_fd its socket before
	 * the detach; the two bools record whether the detach moved the fd and
	 * peer identity out and whether the reattach moved both back. */
	bool resume_decline;
	struct mux_session *declined;
	int declined_fd;
	bool declined_established;
	bool detach_moved_transport;
	bool reattach_restored_transport;

	/* The client session's live-stream gauge (cnt.stream.num_streams): a
	 * stream counts until it is freed. */
	mux_gauge cli_num_streams;
};

#if WITH_TLS
/* Self-signed RSA-4096 cert (CN=test.example) + key, in-memory for all
 * TLS backends.  Also the authorized peer cert (mutual auth).  Same as
 * tls_test so the benches share an apples-to-apples TLS setup; the TLS
 * fixture tests use it too. */
static char test_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFKjCCAxKgAwIBAgIUM70vOlOUSVk9dQ7tbW/ih/8sKCwwDQYJKoZIhvcNAQEL\n"
	"BQAwFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCAXDTI2MDYwOTAyNDQ0NVoYDzIx\n"
	"MjYwNTE2MDI0NDQ1WjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwggIiMA0GCSqG\n"
	"SIb3DQEBAQUAA4ICDwAwggIKAoICAQC+SzjGbGTgjqsKQCEGYS3hFnO1hBoy1VQ8\n"
	"zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uceOaVYLXIe3f96+TucfBJw\n"
	"Wh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXkaxOOVaayRJx79cPxqqLFr\n"
	"rDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW9tNYRrZWVoTe21m2apl6\n"
	"/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGmRNzcAnguhIIe3z8qbwDH\n"
	"1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVpmL6QLpMolNS0cznJgVo2\n"
	"eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV08tZNLeNoN3ezRXsEYE2\n"
	"/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baozaQwoGNzDO/QXffAADp/W\n"
	"F2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus2IBTNFZp+mW8mCliYWop\n"
	"zfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi0omuKHTR326KPLkG7IpW\n"
	"agolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6Rn0bwaeCR6t0or8ru7Dxs\n"
	"dq/TW93U5wIDAQABo2wwajAdBgNVHQ4EFgQU3hgHVZAn/Lh/xbRhabVaEGQbxc8w\n"
	"HwYDVR0jBBgwFoAU3hgHVZAn/Lh/xbRhabVaEGQbxc8wDwYDVR0TAQH/BAUwAwEB\n"
	"/zAXBgNVHREEEDAOggx0ZXN0LmV4YW1wbGUwDQYJKoZIhvcNAQELBQADggIBAIWF\n"
	"in4MUtRj4R6GYGtjjnWt1m9aN4I/w22kdD183G07uTJZ+i545DdFNglt8ZIO1f2F\n"
	"eQ67wQfxIeFeZrr4x6wA7B+RVwX/mRuj3aby5QXhNDVkjAp2su9GRPyIe3jXPDv/\n"
	"/quE4Oufa0kE8HuvqPIOSO6UYWkNAP81LDoyDhyoadB5+mIuxpM3+NyKh6AK2g8n\n"
	"Ran7GYKtMUrL7ryRoJyPcpFk/QyrWAMCbmO3p2Rxx5sj3RtL+6HNYTqNij5qsB+S\n"
	"zmdmX8XyAW5Bgog3hrnrTn1j1AaxNgEczsjdDmaGQiYKscyLwMe38DI8NP/rPP4X\n"
	"rMH8B/TLl+uRwY1THRtkyHI6y4ZnGzmdEBf001J/KUfBFnLxHZBrJwMYbgqLWjba\n"
	"nVXS5GXAtt7Mmz2tKQo7gCHUjgByWcnun3qMGcEoCkkTaqi0pxf2844BYyy73VRT\n"
	"XdPJnfOOHDhuwkkeOfVJbPnfYFAAd8qMpmzBQvz4Clz2q4plB7odyWPSGwvLbFYs\n"
	"sdwuTXnyLqCrB3K0uMBlKr7xeWiVHUfe5oGCwgp7TjV/2AmKUxNzdg41d3Fn7TPK\n"
	"CncDeSmMy1elKbutfBvWvl8d7C0A9viO49Vy0CVR41uQnF09bzdFTYoaOrX8c+w4\n"
	"VtiUoGP5D91X1vhTixpq4BqoHRkKVQpZ0Z/9386J\n"
	"-----END CERTIFICATE-----\n";

static char test_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQC+SzjGbGTgjqsK\n"
	"QCEGYS3hFnO1hBoy1VQ8zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uce\n"
	"OaVYLXIe3f96+TucfBJwWh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXka\n"
	"xOOVaayRJx79cPxqqLFrrDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW\n"
	"9tNYRrZWVoTe21m2apl6/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGm\n"
	"RNzcAnguhIIe3z8qbwDH1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVp\n"
	"mL6QLpMolNS0cznJgVo2eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV\n"
	"08tZNLeNoN3ezRXsEYE2/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baoz\n"
	"aQwoGNzDO/QXffAADp/WF2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus\n"
	"2IBTNFZp+mW8mCliYWopzfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi\n"
	"0omuKHTR326KPLkG7IpWagolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6R\n"
	"n0bwaeCR6t0or8ru7Dxsdq/TW93U5wIDAQABAoICAAorHteLh0BwnzcnAhzDKJ50\n"
	"gq5aZsP8nkm5kDqWre2s3IMqSJlVtKQg+GddTv/SyY5nzWt7tWjC0qLM1ccGdqir\n"
	"mDFMDCFqh9m1FwgPjEG+8lDWFpK8bc+fHluVbGDx21+UyOsI6c6WB+ikSLz9Lpl7\n"
	"C67jULmqVgC47NwoLpHpAoedu+/Pb89CDbzKqdfziAlT/NZmS3TaIA2KFvUKokeu\n"
	"y97UvdB/lb/617jVneXEMXr92ZfuCqqq0Wi0Dt8Egrdx29NoUhUwwcDuwRaIkz95\n"
	"GTLpHwj3cYU8G9BRheNkW6ddSzfvVy+E48mR0jJJItu7zOABucekSmaAIP63Xmmf\n"
	"ISujhU7P1LVLClj/T9c1AJ5EPCdZIbnooe3I1nEppGsKQZ6HP7YOPiWolDjJm2Z2\n"
	"nDQ/y/Ez3z44rywiY3slmypMDmbg96OBStHvfeBedDm18yRZu973QIJJ3kjrMBh9\n"
	"MitVVc/8q6WuTIgPnSfMLVYkSQv5AMrOntXcYMzxyiWHui3+lbT0JrL9knJVrNoi\n"
	"iT1NfSsbWaTxpOZgH0n07na9IDDvsENDy1uoE3wHVBGdHOKb+0bdauIHg4L2Vuaq\n"
	"9fEXHYnIfmXoPs2pAu+ijP2ZwAwBZpCQrs9wd5p5RAuCPnuQCnKhGZ2087/XZqGR\n"
	"e1sYrreurkSaZci1DbMxAoIBAQDjNLoiq/ckjuC4eBLr5ubgliKmQxGdXdwJJG/j\n"
	"udJfRWYY7yaRSSUWomin0jj35Ilmt5idzawSouDZVZz5LP7zPUvt78DtQSVFLazV\n"
	"vYyaKbPhRcVnt/y1nwbMIOCWPrNEE6smvQyjrANS9mAfPFUteDG7jH9qRxEOB6HT\n"
	"B3u0JinhbhP0sHyuju1bqzNLCS+Hqyv1re9eYATRMzsy+0vCnIZglojm9/Nfbu6F\n"
	"VNOaOmmpYn5+gfp3xepfa3CqRO/SdVWAwbgpYi000lWLQK1KarDad/UERwWjE96/\n"
	"cFStLkwK2IAGJ4K7hXFIcw5oWBanybyVg0SZp6d2X3ZHp6/lAoIBAQDWaPMZqLLY\n"
	"hDLTAi2FihBnva9zYd7BBkaGDiDas/HzTPfhSW2skCfFJbOf65NPq67YJTAbrVlN\n"
	"WLNsBFvaKgxAqJtmrgpcCrAW7L5x6hEPKNp4dBGaNOEVzDHZQjZMAobh5fCwl0uK\n"
	"2et6wda1BNat9ckYtSdYOZNoKSK2FCKzj2xGoboez8ndpq3sbQkYSsG62igMAXkd\n"
	"TRVlTdvIo5Tgjl6tFPPmppUi5hEJx0K6sD3v+vKK+kCoHU40blL+2t2sulXYSIfH\n"
	"YiyGBBAljA6AE2KKuz9YoRQ2+Erla2tPQMkC+LgJujEaCZaTP7jWzrvgB4mh+BrL\n"
	"yU73qOGfgyzbAoIBAESC98XQuRuLAfReMMZ1wBTk8NnVy4/6Z4lSNXMj623TDXBj\n"
	"XOvedJKYspo4Z/lILq6MmjareEG+X7LpgAYbLV3HlAfRjgl85XIwzbc+CxHJlXZO\n"
	"hbI65rcVlwUivNZRXdkfXTK3OwJ3siDoLh/9H2ownj6BpUI0382tO3zY+tJd168k\n"
	"dFwKg+5XJvfHbhYoVO7CDOVuZ4m7xngWzLkY0cWDUXn6qpmLFxYl60LFS3FsP8RV\n"
	"8PLQ2ugXBA915GlTlEWQIBJNV+0Sr7MH4ce13wtblKysE3QQvoBoU3jCtKXsGf4D\n"
	"PsecTm2hVYGVQDjypxI9YOJszNjQl0y4iIAe7okCggEBALhVkmtE9j3fqjJvdOOS\n"
	"R3hpRCZWxkP9OTSXgPeGLUWXrqUpk/kAFrEQMNYUmpmsaK27ixjAeD5fPCJpvO5b\n"
	"qB0O2Ev25UEsjyemcjVNn00BOpLEdz20qK8s1s6KdlPy+DPOlJe9+1xs7l6juAv5\n"
	"FPiKj1GGrUTUez7Z3tXbidoGPHidIn7K9ipx2qWhOGiCHPygAj4QJihi1To7LfHZ\n"
	"cW19+TelA+wQ27cdRRi7D0uhqh5gCZYigOQIDexVzVT+pgaSTKud794jMVQmuhsN\n"
	"xommINpVEakJE3APF5UWPTPt5uN/Ifp68SwJgkMmTaugITYCRPnTbHY3pISX1SJm\n"
	"jHECggEBAI7oDbmegf1H4KFbAn2ZCRJuMQg2SgtXb4gKbvrnvd/SAQoFkIth0VZ2\n"
	"9IccGPbgaEYxLXGDhY4oiibtRX5cCwB0uOYbb495SUuJRyA0bMJVHqtcRo3zX5df\n"
	"PNM+lny+hwzm3VziNfgGqNjAbOK5ukXrtaDMP1J2KyIbfC8A0eP+lUYnd/oJTRQN\n"
	"rJvfapSR/TGwsz0A4BtKCRJ5zlMvNm87soACzZBV9Es0ROf3683v/e1kMhffcvbS\n"
	"MKCbHGB5/oKk/I0aaRsNvyU0+TPSXEBu3HzAmmCns1p7MJYfghjg2H3f9nhE5smE\n"
	"NL+YLwobqSZhkl4iZWt2wGODitzp/aQ=\n"
	"-----END PRIVATE KEY-----\n";

/* Server and client contexts over the shared cert: mutual auth, AES-128-GCM
 * (the tls_test benches' cipher) and read-ahead on.  On failure neither is
 * returned. */
static bool test_tls_contexts_new(
	struct tls_context **restrict srv_out,
	struct tls_context **restrict cli_out)
{
	char *authcerts[] = { test_cert_pem };
	const struct tls_config tls_conf = {
		.cert = test_cert_pem,
		.key = test_key_pem,
		.authcerts = authcerts,
		.authcerts_count = 1,
#if WITH_OPENSSL
		.ciphersuites = "TLS_AES_128_GCM_SHA256",
#else
		.ciphersuites = "TLS1-3-AES-128-GCM-SHA256",
#endif
		/* Read-ahead on so the bench measures the high-throughput path. */
		.readahead = true,
	};
	struct tls_context *const srv = tls_ctx_server(&tls_conf);
	struct tls_context *const cli = tls_ctx_client(&tls_conf);
	if (srv == NULL || cli == NULL) {
		tls_ctx_free(srv);
		tls_ctx_free(cli);
		return false;
	}
	*srv_out = srv;
	*cli_out = cli;
	return true;
}
#endif /* WITH_TLS */

/* wait_until helpers */

typedef int (*wait_predicate_fn)(void *ctx);

struct condition_waiter {
	bool timed_out;
	ev_timer w_timer;
};

static void
condition_waiter_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)revents;
	struct condition_waiter *const restrict waiter = w->data;
	waiter->timed_out = true;
}

static int loop_wait_until(
	struct ev_loop *loop, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	struct condition_waiter waiter = {
		.timed_out = false,
	};
	ev_timer_init(
		&waiter.w_timer, condition_waiter_timer_cb, timeout_sec, 0.0);
	waiter.w_timer.data = &waiter;
	ev_timer_start(loop, &waiter.w_timer);

	/* The predicate inspects state that callbacks dispatched inside ev_run()
	 * mutate through their own pointers, so no caller may hand that state
	 * in through a restrict-qualified pointer: the compiler would then keep
	 * the polled value in a register across ev_run(). */
	while (!waiter.timed_out) {
		const int status = predicate(ctx);
		if (status != 0) {
			ev_timer_stop(loop, &waiter.w_timer);
			return status > 0 ? 0 : -1;
		}
		ev_run(loop, EVRUN_ONCE);
	}

	ev_timer_stop(loop, &waiter.w_timer);
	errno = ETIMEDOUT;
	return -1;
}

static int wait_until(
	struct mux_test_fixture *fx, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	return loop_wait_until(fx->loop, timeout_sec, predicate, ctx);
}

/* test_stream helpers */

static struct test_stream *test_stream_new(
	struct mux_test_fixture *restrict fx, struct mux_stream *restrict s)
{
	struct test_stream *const ts = malloc(sizeof(struct test_stream));
	if (ts == NULL) {
		return NULL;
	}
	*ts = (struct test_stream){
		.fx = fx,
		.s = s,
		.recv_buf = NULL,
		.recv_cap = 0,
		.recv_len = 0,
		.send_data = NULL,
		.send_len = 0,
		.send_off = 0,
		.send_shutdown_on_drain = false,
		.got_eof = false,
		.got_error = false,
		.closed = false,
	};
	{
		unsigned char *const buf = malloc(PAYLOAD_LARGE + CHUNK_SIZE);
		if (buf == NULL) {
			free(ts);
			return NULL;
		}
		ts->recv_buf = buf;
		ts->recv_cap = PAYLOAD_LARGE + CHUNK_SIZE;
	}
	mux_stream_io_init(&ts->w_io, stream_io_cb, s, EV_READ | EV_WRITE);
	return ts;
}

static void test_stream_free(struct test_stream *restrict ts)
{
	if (ts == NULL) {
		return;
	}
	free(ts->recv_buf);
	free(ts);
}

/* Half-close the stream the way the echo/drain/sender roles do, recording it
 * so stream_io_cb can count any EV_WRITE delivered afterwards. */
static void test_stream_shutdown(struct test_stream *restrict ts)
{
	ts->write_shut = true;
	mux_stream_shutdown(ts->s);
}

/* Flush pending send data for a test_stream in echo mode.
 * Returns true when all data has been sent. */
static bool test_stream_flush_send(struct test_stream *restrict ts)
{
	if (ts->send_cyclic) {
		/* Push as much as the send window allows, recycling the fixed
		 * send_data buffer; content is irrelevant for throughput. */
		while (ts->send_remaining > 0) {
			size_t chunk =
				ts->send_remaining < (uint_fast64_t)CHUNK_SIZE ?
					(size_t)ts->send_remaining :
					(size_t)CHUNK_SIZE;
			const int ret =
				mux_stream_send(ts->s, ts->send_data, &chunk);
			if (ret < 0) {
				return false; /* pool exhausted; resume on EV_WRITE */
			}
			if (chunk == 0) {
				return false; /* window full; resume on EV_WRITE */
			}
			ts->send_remaining -= chunk;
		}
		return true;
	}
	if (ts->send_off >= ts->send_len) {
		return true;
	}
	const size_t remaining = ts->send_len - ts->send_off;
	size_t chunk = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
	const int ret =
		mux_stream_send(ts->s, ts->send_data + ts->send_off, &chunk);
	if (ret < 0) {
		return false;
	}
	ts->send_off += chunk;
	return ts->send_off >= ts->send_len;
}

/* Echo backpressure pump: flush un-echoed recv_buf[echo_off, recv_len).
 * Stops on full send window; after peer FIN, mirrors the shutdown once
 * the backlog drains. */
static void test_stream_pump_echo(struct test_stream *restrict ts)
{
	while (ts->echo_off < ts->recv_len) {
		size_t chunk = ts->recv_len - ts->echo_off;
		const int r = mux_stream_send(
			ts->s, ts->recv_buf + ts->echo_off, &chunk);
		if (r < 0 || chunk == 0) {
			break;
		}
		ts->echo_off += chunk;
	}
	if (ts->echo_fin_seen && ts->echo_off >= ts->recv_len &&
	    !ts->echo_shutdown_done) {
		ts->echo_shutdown_done = true;
		test_stream_shutdown(ts);
	}
}

/* Echo I/O callback (used by both server-accepted and client-opened streams) */

static void
stream_io_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	struct test_stream *const restrict ts = (struct test_stream *)w;

	/* mux_stream_io is never registered with libev; the mux layer only ever
	 * feeds it EV_READ/EV_WRITE, so EV_ERROR cannot arrive here. */
	if ((revents & EV_WRITE) && ts->write_shut) {
		ts->fx->writes_after_shutdown++;
	}

	if (revents & EV_READ) {
		if (ts->is_drain) {
			/* Throughput sink: read and discard, counting bytes. */
			for (;;) {
				size_t cap = ts->recv_cap;
				const int ret = mux_stream_recv(
					ts->s, ts->recv_buf, &cap);
				if (ret < 0) {
					if (errno == EAGAIN) {
						break;
					}
					ts->got_error = true;
					if (!ts->closed) {
						ts->closed = true;
						mux_stream_close(ts->s);
					}
					return;
				}
				if (cap == 0) {
					/* Peer FIN: the count is final.  Mirror the
					 * shutdown to release the half-closed stream. */
					ts->got_eof = true;
					test_stream_shutdown(ts);
					return;
				}
				ts->recv_total += cap;
			}
			return;
		}
		if (ts->close_on_readable) {
			/* Close without reading to trigger RST. */
			if (!ts->closed) {
				ts->closed = true;
				mux_stream_close(ts->s);
			}
			return;
		}
		/* Drain available data */
		while (ts->recv_len < ts->recv_cap) {
			size_t cap = ts->recv_cap - ts->recv_len;
			const int ret = mux_stream_recv(
				ts->s, ts->recv_buf + ts->recv_len, &cap);
			if (ret < 0) {
				const int err = errno;
				if (err == EAGAIN) {
					break;
				}
				if (err == ECONNRESET) {
					ts->got_error = true;
					if (!ts->closed) {
						ts->closed = true;
						mux_stream_close(ts->s);
					}
					return;
				}
				break;
			}
			if (cap == 0) {
				/* EOF */
				ts->got_eof = true;
				if (ts->is_echo) {
					/* Echo server: drain the backlog, then
					 * mirror the FIN once it is empty. */
					ts->echo_fin_seen = true;
					test_stream_pump_echo(ts);
				}
				return;
			}
			ts->recv_len += cap;
		}

		/* Echo server: reflect everything received so far, honouring send
		 * backpressure (EV_WRITE resumes a window-blocked backlog). */
		if (ts->is_echo) {
			test_stream_pump_echo(ts);
		}
	}

	if (revents & EV_WRITE) {
		if (ts->is_echo) {
			test_stream_pump_echo(ts);
		} else if (ts->send_data != NULL) {
			const bool done = test_stream_flush_send(ts);
			if (done && ts->send_shutdown_on_drain) {
				test_stream_shutdown(ts);
			}
		}
	}
}

/* Session callbacks */

static bool
on_accept_cb(void *data, const struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	struct mux_test_fixture *const restrict fx = data;
	if (fx->accept_mode == ACCEPT_ATTACH_FD) {
		/* Socket mode: the local socket carries the stream from here on,
		 * so no direct-mode test_stream is created. */
		if (fx->accept_attach_fd < 0) {
			return false;
		}
		mux_stream_attach_fd(s, fx->accept_attach_fd);
		fx->accept_attach_fd = -1;
		return true;
	}
	if (fx->accept_mode == ACCEPT_DEFER) {
		fx->deferred = s;
		return true;
	}
	if (fx->n_accepted >= MAX_ACCEPTED) {
		return false;
	}

	struct test_stream *ts = test_stream_new(fx, s);
	if (ts == NULL) {
		return false;
	}
	fx->accepted[fx->n_accepted++] = ts;

	if (fx->accept_mode == ACCEPT_CLOSE_IMMEDIATE) {
		/* Start the watcher so the stream completes its SYN/ACK
		 * handshake. The first EV_READ (when client data arrives)
		 * will close without reading to trigger RST. */
		ts->close_on_readable = true;
		mux_stream_io_start(fx->loop, &ts->w_io);
		return true;
	}

	if (fx->accept_mode == ACCEPT_SEND_PAYLOAD) {
		/* Server sends its own payload then shuts down the write side.
		 * The accepted stream does not echo; the peer is expected to
		 * drain the data and observe EOF. */
		ts->send_data = fx->accept_send_data;
		ts->send_len = fx->accept_send_len;
		ts->send_shutdown_on_drain = true;
		mux_stream_io_start(fx->loop, &ts->w_io);
		return true;
	}

	if (fx->accept_mode == ACCEPT_DRAIN) {
		/* Throughput sink: drain and discard, no echo. */
		ts->is_drain = true;
		mux_stream_io_start(fx->loop, &ts->w_io);
		return true;
	}

	/* Echo mode: mark is_echo so stream_io_cb echoes data back. */
	ts->is_echo = true;
	mux_stream_io_start(fx->loop, &ts->w_io);
	return true;
}

static int fixture_dial(const char *restrict addr_str)
{
	/* addr_str is always "127.0.0.1:<port>" in the test fixture. */
	const char *colon = strchr(addr_str, ':');
	if (colon == NULL) {
		return -1;
	}
	char *end = NULL;
	const long lport = strtol(colon + 1, &end, 10);
	if (end == colon + 1 || *end != '\0' || lport <= 0 || lport > 65535) {
		return -1;
	}
	const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		return -1;
	}
	if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
		(void)close(fd);
		return -1;
	}
	const struct sockaddr_in saddr = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)lport),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	const int ret =
		connect(fd, (const struct sockaddr *)&saddr, sizeof(saddr));
	if (ret != 0 && errno != EINPROGRESS) {
		(void)close(fd);
		return -1;
	}
	return fd;
}

/* Copy an ESTABLISHED/RESUMED payload into the capture of the side it fired
 * on; a transient resume session matches neither side and is not recorded. */
static void fixture_capture_connected(
	struct mux_test_fixture *restrict fx, const struct mux_session *ss,
	const union mux_event_data *restrict edata)
{
	struct connected_capture *cap;
	if (ss == fx->srv) {
		cap = &fx->srv_connected;
	} else if (ss == fx->cli) {
		cap = &fx->cli_connected;
	} else {
		return;
	}
	*cap = (struct connected_capture){
		.fired = true,
		.ns = edata->connected.ns,
		.has_peer_identity = edata->connected.peer_identity != NULL,
	};
	if (cap->has_peer_identity) {
		(void)snprintf(
			cap->peer_identity, sizeof(cap->peer_identity), "%s",
			edata->connected.peer_identity);
	}
}

static void on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	struct mux_test_fixture *const restrict fx = data;
	switch (event) {
	case MUX_EVENT_ESTABLISHED:
		fixture_capture_connected(fx, ss, &edata);
		if (ss == fx->declined) {
			fx->declined_established = true;
		} else if (ss == fx->srv) {
			fx->srv_established = true;
		} else {
			fx->cli_established = true;
		}
		break;
	case MUX_EVENT_RESUMED:
		fixture_capture_connected(fx, ss, &edata);
		if (ss == fx->srv) {
			fx->srv_resumed = true;
		} else {
			fx->cli_resumed = true;
		}
		break;
	case MUX_EVENT_STREAM_ESTABLISHED:
		fx->ev_stream_established_ns = edata.stream_established.ns;
		break;
	case MUX_EVENT_LOST:
		if (ss == fx->cli) {
			fx->cli_lost = true;
		}
		break;
	case MUX_EVENT_CONNECT_FAILED:
		if (ss == fx->cli) {
			fx->cli_connect_failed = true;
		}
		break;
	case MUX_EVENT_SUSPENDED:
		if (ss == fx->srv) {
			fx->srv_suspended = true;
		} else {
			fx->cli_suspended = true;
		}
		if (ss == fx->cli && fx->connect_str[0] != '\0') {
			/* Reconnect the client session immediately. */
			const int fd = fixture_dial(fx->connect_str);
			if (fd >= 0) {
				mux_attach_fd(ss, fd);
			}
		}
		break;
	case MUX_EVENT_CLOSED:
		if (ss == fx->srv) {
			fx->srv_closed = true;
			fx->srv_closed_data = edata;
			fx->srv = NULL;
		} else if (ss == fx->cli) {
			fx->cli_closed = true;
			fx->cli_closed_data = edata;
			fx->cli = NULL;
		} else if (ss == fx->declined) {
			fx->declined = NULL;
		}
		/* Transient sessions (created during resume handshake) reach the
		 * closed event after the resume handoff resets them; they match
		 * neither fx->srv nor fx->cli.  mux_close is always required. */
		mux_close(ss);
		break;
	default:
		break;
	}
}

/* Stop from the public lifecycle callback, then leave the loop so the test
 * can inspect completion before another socket event drives the close. */
static void shutdown_and_break_on_connected(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	on_event_cb(data, ss, event, edata);
	if (event == MUX_EVENT_ESTABLISHED || event == MUX_EVENT_RESUMED) {
		mux_shutdown(ss);
		struct mux_test_fixture *const fx = data;
		ev_break(fx->loop, EVBREAK_ALL);
	}
}

/* TCP loopback listen helper: bind, listen, return fd and port */

static int tcp_listen_loopback(int *restrict port_out)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	int on = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		(void)close(fd);
		return -1;
	}
	if (listen(fd, 4) != 0) {
		(void)close(fd);
		return -1;
	}
	socklen_t len = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
		(void)close(fd);
		return -1;
	}
	*port_out = (int)ntohs(sa.sin_port);
	return fd;
}

/* Forward declaration needed by pending_accept_cb below */
static const struct mux_callbacks g_srv_callbacks;

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

static void proto_session_id_new(unsigned char *const id)
{
	write_uint64(id, rand64());
	write_uint64(id + sizeof(uint64_t), rand64());
}

/* Build a hello frame into buf, mirroring the on-wire format.  Local copy
 * for the raw-peer driver (no handshake.c link needed).
 * Returns total frame length, or -1 on failure. */
static int mux_test_proto_hello_build(
	unsigned char *const buf, const size_t buf_size,
	const struct proto_hello *const msg)
{
	enum { SESSION_ID_B64 = 24 };
	static const char proto_type[] =
		"application/x-multiplexd-proto; version=1";
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
		.type = { .str = (char *)proto_type,
			  .len = sizeof(proto_type) - 1 },
		.msgid = msg->msgid,
		.session_id = {
			.str = msg->has_session_id ? id_b64 : NULL,
			.len = msg->has_session_id ? SESSION_ID_B64 : 0,
		},
		.resume_seq = msg->has_resume_seq ? (unsigned)msg->resume_seq : 0,
		.extensions = {
			.reject_inbound = msg->reject_inbound,
			.lossymux = msg->lossymux,
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
	const int json_sz = json_marshal_proto(NULL, 0, &raw, NULL);
	if (json_sz <= 0 || (size_t)json_sz > MUX_MAX_PAYLOAD_SIZE) {
		return -1;
	}
	const size_t total = MUX_FRAME_HEADER_SIZE + (size_t)json_sz;
	if (total <= buf_size) {
		char json_buf[(size_t)json_sz + 1];
		(void)json_marshal_proto(
			json_buf, (size_t)json_sz + 1, &raw, NULL);
		const struct mux_header hdr = {
			.version = 0,
			.flags = 0,
			.length = (uint_least16_t)json_sz,
			.stream_id = 0,
			.extra = 0,
		};
		mux_write_header(buf, &hdr);
		memcpy(buf + MUX_FRAME_HEADER_SIZE, json_buf, (size_t)json_sz);
	}
	return (int)total;
}

/* Pending-accept helper: sits on the listen fd and calls mux_new + mux_start
 * for the first accepted connection. */
struct pending_accept {
	struct mux_test_fixture *fx;
	int listen_fd;
	ev_io w_accept;
};

static void pending_accept_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)revents;
	struct pending_accept *const restrict pa = w->data;

	const int srv_fd = accept(pa->listen_fd, NULL, NULL);
	if (srv_fd < 0) {
		return;
	}
	{
		const int flags = fcntl(srv_fd, F_GETFL, 0);
		if (flags >= 0) {
			(void)fcntl(srv_fd, F_SETFL, flags | O_NONBLOCK);
		}
	}

	struct mux_test_fixture *const restrict fx = pa->fx;
	const struct mux_session_config srv_conf = {
		.timeout = 30,
		.keepalive = 15,
		.send_timeout = 10,
		.connect_timeout = 10,
		.resume_timeout = 30,
		.idle_timeout = 0,
		.max_streams = 64,
		.stream_window = 4,
		.session_window = 256,
		.max_frame_payload =
			mux_session_config_default.max_frame_payload,
		.nodelay = fx->nodelay,
#if WITH_TLS
		.tls_socket_offload = fx->tls_socket_offload,
#endif
	};
	unsigned char srv_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(srv_sid);

#if WITH_TLS
	/* A TLS fixture wraps every accepted connection, a resume one included,
	 * as the server does: fd-backed with socket offload, memory-backed
	 * otherwise.  mux_new() takes ownership of it with the fd. */
	struct tls_connection *srv_conn = NULL;
	if (fx->srv_tlsctx != NULL) {
		srv_conn = tls_server(
			fx->srv_tlsctx, fx->tls_socket_offload ? srv_fd : -1);
		if (srv_conn == NULL) {
			(void)close(srv_fd);
			return;
		}
	}
#endif /* WITH_TLS */

	const struct mux_session_opts srv_opts = {
		.callbacks = &g_srv_callbacks,
		.userdata = fx,
		.conf = &srv_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = srv_fd,
		.id = srv_sid,
		.identity = TEST_SRV_IDENTITY,
#if WITH_TLS
		.conn = srv_conn,
#endif
	};
	/* mux_new() owns srv_fd (and srv_conn) even when it fails. */
	if (fx->srv == NULL) {
		/* First accept: create the primary server session. */
		fx->srv = mux_new(loop, &srv_opts);
		if (fx->srv == NULL) {
			return;
		}
		mux_start(fx->srv);
	} else {
		/* Subsequent accept (resume path): create a transient session.
		 * on_resume_cb detaches its transport onto fx->srv via
		 * mux_transport_detach + mux_resume_attach, then resets it. */
		struct mux_session *const transient = mux_new(loop, &srv_opts);
		if (transient == NULL) {
			return;
		}
		mux_start(transient);
	}
	/* The listen socket remains open so the client can reconnect. */
}

static struct mux_session_config make_cli_conf(const bool nodelay)
{
	return (struct mux_session_config){
		.nodelay = nodelay,
		.timeout = 30,
		.keepalive = 15,
		.send_timeout = 10,
		.connect_timeout = 10,
		.resume_timeout = 30,
		.idle_timeout = 0,
		.max_streams = 64,
		.stream_window = 4,
		.session_window = 256,
		.max_frame_payload =
			mux_session_config_default.max_frame_payload,
	};
}

/* Fixture setup / teardown */

static bool on_resume_cb(
	void *data, struct mux_session *new_ss, const unsigned char *session_id,
	const uint_least32_t resume_seq)
{
	struct mux_test_fixture *restrict fx = data;
	if (fx->resume_decline) {
		/* An owner whose handoff failed after the detach: put the
		 * transport back and decline, as tunnel_handoff_resume does when
		 * it cannot post the resume to the matched session's loop. */
		const int fd = mux_fd(new_ss);
		const char *const identity = mux_peer_identity(new_ss);
		struct mux_transport transport;
		mux_transport_detach(new_ss, &transport);
		fx->detach_moved_transport =
			transport.fd == fd &&
			transport.peer_identity == identity &&
			mux_fd(new_ss) == -1 &&
			mux_peer_identity(new_ss) == NULL;
		mux_transport_reattach(new_ss, &transport);
		fx->reattach_restored_transport =
			mux_fd(new_ss) == fd &&
			mux_peer_identity(new_ss) == identity &&
			transport.fd == -1 && transport.peer_identity == NULL;
		fx->declined = new_ss;
		fx->declined_fd = fd;
		return false;
	}
	if (fx->srv != NULL && memcmp(session_id, mux_session_id(fx->srv),
				      MUX_SESSION_ID_LEN) == 0) {
		/* Single test loop: move the transient transport onto fx->srv and
		 * resume inline (the tunnel layer would post this to srv's loop). */
		struct mux_transport transport;
		mux_transport_detach(new_ss, &transport);
		mux_resume_attach(fx->srv, &transport, resume_seq);
		return true;
	}
	return false;
}

static const struct mux_callbacks g_srv_callbacks = {
	.on_accept = on_accept_cb,
	.on_event = on_event_cb,
	.on_resume = on_resume_cb,
};

static const struct mux_callbacks g_cli_callbacks = {
	.on_accept = on_accept_cb,
	.on_event = on_event_cb,
};

/* What the fixture's session pair runs over. */
enum fixture_transport {
	FIXTURE_PLAIN,
	/* TLS with the library shuttling ciphertext through wire.c's buffers */
	FIXTURE_TLS_MEMORY,
	/* TLS with the library owning the socket (tls_socket_offload) */
	FIXTURE_TLS_OFFLOAD,
};

static void fixture_free_tls(struct mux_test_fixture *restrict fx)
{
#if WITH_TLS
	tls_ctx_free(fx->srv_tlsctx);
	fx->srv_tlsctx = NULL;
	tls_ctx_free(fx->cli_tlsctx);
	fx->cli_tlsctx = NULL;
#else
	(void)fx;
#endif
}

static int fixture_setup_transport(
	struct mux_test_fixture *restrict fx,
	const enum fixture_transport transport)
{
	*fx = (struct mux_test_fixture){ 0 };
	fx->listen_fd_cleanup = -1;
	fx->break_transport_sp = -1;
	fx->accept_attach_fd = -1;

	if (transport != FIXTURE_PLAIN) {
#if WITH_TLS
		if (!test_tls_contexts_new(&fx->srv_tlsctx, &fx->cli_tlsctx)) {
			return -1;
		}
		fx->tls_socket_offload = (transport == FIXTURE_TLS_OFFLOAD);
#else
		return -1;
#endif
	}

	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		fixture_free_tls(fx);
		return -1;
	}

	/* Create a TCP listen socket on loopback.  The client connects via
	 * session_connect (real TCP, EV_WRITE on completion), exercising
	 * the normal handshake path without socketpair tricks. */
	int port = 0;
	const int listen_fd = tcp_listen_loopback(&port);
	if (listen_fd < 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		fixture_free_tls(fx);
		return -1;
	}

	/* Register an accept watcher that creates the server-side mux session
	 * when the client connect() arrives. */
	struct pending_accept *pa = malloc(sizeof(struct pending_accept));
	if (pa == NULL) {
		(void)close(listen_fd);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		fixture_free_tls(fx);
		return -1;
	}
	pa->fx = fx;
	pa->listen_fd = listen_fd;
	ev_io_init(&pa->w_accept, pending_accept_cb, listen_fd, EV_READ);
	pa->w_accept.data = pa;

	(void)snprintf(
		fx->connect_str, sizeof(fx->connect_str), "127.0.0.1:%d", port);

	ev_io_start(fx->loop, &pa->w_accept);

	/* Client session: fd=-1, session_connect() will call connect() and
	 * arm EV_WRITE on the TCP connection. */
	struct mux_session_config cli_conf = make_cli_conf(fx->nodelay);
#if WITH_TLS
	cli_conf.tls_socket_offload = fx->tls_socket_offload;
#endif
	unsigned char cli_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(cli_sid);
	const struct mux_session_opts cli_opts = {
		.callbacks = &g_cli_callbacks,
		.userdata = fx,
		.conf = &cli_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = -1,
		.id = cli_sid,
		.identity = TEST_CLI_IDENTITY,
		.cnt.stream.num_streams = &fx->cli_num_streams,
#if WITH_TLS
		/* NULL for a plain fixture, which then runs over plain TCP. */
		.tlsctx = fx->cli_tlsctx,
#endif
	};
	fx->cli = mux_new(fx->loop, &cli_opts);
	if (fx->cli == NULL) {
		ev_io_stop(fx->loop, &pa->w_accept);
		(void)close(listen_fd);
		free(pa);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		fixture_free_tls(fx);
		return -1;
	}
	/* mux_start is a no-op for client sessions (fd=-1); attach a TCP
	 * connection immediately so the handshake can proceed. */
	mux_start(fx->cli);
	{
		const int cli_fd = fixture_dial(fx->connect_str);
		if (cli_fd >= 0) {
			mux_attach_fd(fx->cli, cli_fd);
		}
	}

	/* Store pa pointer so teardown can clean up if the accept never fires. */
	fx->listen_fd_cleanup = listen_fd;
	fx->pending_accept = pa;
	return 0;
}

static int fixture_setup(struct mux_test_fixture *restrict fx)
{
	return fixture_setup_transport(fx, FIXTURE_PLAIN);
}

static void fixture_teardown(struct mux_test_fixture *restrict fx)
{
	/* If the accept watcher never fired, clean it up here. */
	if (fx->pending_accept != NULL) {
		struct pending_accept *const restrict pa = fx->pending_accept;
		if (fx->loop != NULL) {
			ev_io_stop(fx->loop, &pa->w_accept);
		}
		(void)close(pa->listen_fd);
		free(pa);
		fx->pending_accept = NULL;
	}

	if (fx->break_transport_sp >= 0) {
		(void)close(fx->break_transport_sp);
		fx->break_transport_sp = -1;
	}
	if (fx->srv != NULL) {
		mux_close(fx->srv);
		fx->srv = NULL;
	}
	if (fx->cli != NULL) {
		mux_close(fx->cli);
		fx->cli = NULL;
	}
	if (fx->declined != NULL) {
		mux_close(fx->declined);
		fx->declined = NULL;
	}
	/* After the sessions: their TLS connections reference the contexts. */
	fixture_free_tls(fx);

	/* Free accepted server streams */
	for (int i = 0; i < fx->n_accepted; i++) {
		test_stream_free(fx->accepted[i]);
		fx->accepted[i] = NULL;
	}
	fx->n_accepted = 0;

	/* Free client-side test streams */
	for (int i = 0; i < fx->n_cli_streams; i++) {
		test_stream_free(fx->cli_streams[i]);
		fx->cli_streams[i] = NULL;
	}
	fx->n_cli_streams = 0;

	/* Free server-side actively opened streams */
	for (int i = 0; i < fx->n_srv_active_streams; i++) {
		test_stream_free(fx->srv_active_streams[i]);
		fx->srv_active_streams[i] = NULL;
	}
	fx->n_srv_active_streams = 0;

	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* Predicates */

static int pred_established(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->srv_established && fx->cli_established) {
		return 1;
	}
	return 0;
}

struct echo_ctx {
	struct test_stream *ts;
	const unsigned char *expected;
	size_t expected_len;
};

static int pred_echo_received(void *ptr)
{
	const struct echo_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	if (ctx->ts->recv_len >= ctx->expected_len) {
		return 1;
	}
	return 0;
}

static int pred_eof(void *ptr)
{
	const struct test_stream *restrict ts = ptr;
	if (ts->got_error) {
		return -1;
	}
	return ts->got_eof ? 1 : 0;
}

/* Satisfied when the stream has received at least expected_len bytes and also
 * obtained peer EOF.  Used to verify data-then-FIN sequences. */
static int pred_echo_and_eof(void *ptr)
{
	const struct echo_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	if (ctx->ts->recv_len >= ctx->expected_len && ctx->ts->got_eof) {
		return 1;
	}
	return 0;
}

static int pred_error(void *ptr)
{
	const struct test_stream *restrict ts = ptr;
	return ts->got_error ? 1 : 0;
}

static int pred_cli_closed(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	return fx->cli_closed ? 1 : 0;
}

/* Satisfied once the client has fired MUX_EVENT_SUSPENDED.
 * Returns -1 on a client close to short-circuit the wait. */
static int pred_cli_suspended(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->cli_closed) {
		return -1;
	}
	return fx->cli_suspended ? 1 : 0;
}

/* Satisfied when both sessions have fired MUX_EVENT_RESUMED.
 * Returns -1 on unexpected close to short-circuit the wait. */
static int pred_resumed(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->cli_closed || fx->srv_closed) {
		return -1;
	}
	return (fx->cli_resumed && fx->srv_resumed) ? 1 : 0;
}

/* Satisfied when both streams have received EOF and neither has an error.
 * Used to verify simultaneous-close (both sides send FIN independently). */
struct both_eof_ctx {
	const struct test_stream *a;
	const struct test_stream *b;
};

static int pred_both_eof_no_error(void *ptr)
{
	const struct both_eof_ctx *restrict ctx = ptr;
	if (ctx->a->got_error || ctx->b->got_error) {
		return -1;
	}
	if (ctx->a->got_eof && ctx->b->got_eof) {
		return 1;
	}
	return 0;
}

struct accepted_count_ctx {
	const struct mux_test_fixture *fx;
	int min_accepted;
};

static int pred_accepted_count(void *ptr)
{
	const struct accepted_count_ctx *restrict ctx = ptr;
	return ctx->fx->n_accepted >= ctx->min_accepted ? 1 : 0;
}

/* Satisfied once an active-open stream has received its SYN|ACK. */
struct stream_established_ctx {
	const struct mux_stream *s;
};

static int pred_stream_established(void *ptr)
{
	const struct stream_established_ctx *restrict ctx = ptr;
	return ctx->s->state == STREAM_ESTABLISHED ? 1 : 0;
}

/* Throughput bench: tracks the byte count the server-side drain stream must
 * reach.  See pred_drain_total near the benchmark itself. */
struct drain_done_ctx {
	const struct mux_test_fixture *fx;
	uint_fast64_t expected_total;
};

struct no_error_and_no_halfopen_ctx {
	const struct mux_test_fixture *fx;
	const struct test_stream *ts;
};

static int pred_no_error_and_no_halfopen(void *ptr)
{
	const struct no_error_and_no_halfopen_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	return ctx->fx->cli->num_halfopen == 0 ? 1 : 0;
}

/* Helper: fill buffer with deterministic pseudo-random content */

static void fill_payload(
	unsigned char *restrict buf, const size_t len, const uint_fast8_t seed)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (unsigned char)((seed + i * 31u + i * i * 7u) & 0xFFu);
	}
}

/* Test cases */

T_DECLARE_CASE(test_establish)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	const int ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established, &fx);
	const bool srv_established = fx.srv_established;
	const bool cli_established = fx.cli_established;
	/* ESTABLISHED payload, per side: setup latency is measured against a
	 * monotonic clock, so an established peer reports a strictly positive
	 * ns; peer_identity is what the other side claimed in its hello. */
	const struct connected_capture srv_cap = fx.srv_connected;
	const struct connected_capture cli_cap = fx.cli_connected;
	char srv_peer_identity[sizeof(srv_cap.peer_identity)] = "";
	char cli_peer_identity[sizeof(cli_cap.peer_identity)] = "";
	if (ret == 0) {
		/* mux_peer_identity() is owned by the session: copy it out. */
		const char *const srv_pi = mux_peer_identity(fx.srv);
		const char *const cli_pi = mux_peer_identity(fx.cli);
		(void)snprintf(
			srv_peer_identity, sizeof(srv_peer_identity), "%s",
			srv_pi != NULL ? srv_pi : "(null)");
		(void)snprintf(
			cli_peer_identity, sizeof(cli_peer_identity), "%s",
			cli_pi != NULL ? cli_pi : "(null)");
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(srv_established);
	T_EXPECT(cli_established);
	T_EXPECT(srv_cap.fired);
	T_EXPECT(cli_cap.fired);
	T_EXPECT(srv_cap.ns > 0);
	T_EXPECT(cli_cap.ns > 0);
	T_EXPECT(srv_cap.has_peer_identity);
	T_EXPECT_STREQ(srv_cap.peer_identity, TEST_CLI_IDENTITY);
	T_EXPECT(cli_cap.has_peer_identity);
	T_EXPECT_STREQ(cli_cap.peer_identity, TEST_SRV_IDENTITY);
	T_EXPECT_STREQ(srv_peer_identity, TEST_CLI_IDENTITY);
	T_EXPECT_STREQ(cli_peer_identity, TEST_SRV_IDENTITY);
}

T_DECLARE_CASE(test_send_recv_small)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x42);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == PAYLOAD_SMALL &&
		memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0;
	/* STREAM_ESTABLISHED payload: the active-open stream reports its
	 * SYN-to-SYN|ACK latency once, and it is strictly positive. */
	const int_least64_t stream_ns = fx.ev_stream_established_ns;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_SMALL);
	if (recv_len == PAYLOAD_SMALL) {
		T_EXPECT(payload_matches);
	}
	T_EXPECT(stream_ns > 0);
}

/* test_idle_scheduler_stops_while_sendbuf_blocked: INIT stream on a full
 * sendbuf must stay queued without marking lp_pending; mux_session_on_send
 * re-arms the drain once the sendbuf clears. */

T_DECLARE_CASE(test_idle_scheduler_stops_while_sendbuf_blocked)
{
	struct mux_test_fixture fx;
	struct mux_frame *frame = NULL;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		if (fx.cli != NULL) {
			if (fx.cli->wire.sendbuf.head == frame) {
				(void)mux_frame_list_pop(&fx.cli->wire.sendbuf);
				mux_frame_put(&fx.cli->pool, frame);
				frame = NULL;
			}
			fx.cli->wire.tx_pending = false;
			mux_session_notify(fx.cli);
		}
		if (fx.srv != NULL) {
			mux_session_notify(fx.srv);
		}
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Stop transport watchers so EVRUN_NOWAIT executes only the idle path. */
	ev_io_stop(fx.loop, &fx.cli->w_socket);
	ev_io_stop(fx.loop, &fx.srv->w_socket);

	frame = mux_frame_get(&fx.cli->pool, fx.cli->max_payload);
	if (frame == NULL) {
		if (fx.cli != NULL) {
			if (fx.cli->wire.sendbuf.head == frame) {
				(void)mux_frame_list_pop(&fx.cli->wire.sendbuf);
				mux_frame_put(&fx.cli->pool, frame);
				frame = NULL;
			}
			fx.cli->wire.tx_pending = false;
			mux_session_notify(fx.cli);
		}
		if (fx.srv != NULL) {
			mux_session_notify(fx.srv);
		}
		fixture_teardown(&fx);
		T_FATAL("mux_frame_get failed");
		return;
	}
	frame->pos = 0;
	frame->len = MUX_FRAME_HEADER_SIZE;
	mux_frame_list_push(&fx.cli->wire.sendbuf, frame);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		if (fx.cli != NULL) {
			if (fx.cli->wire.sendbuf.head == frame) {
				(void)mux_frame_list_pop(&fx.cli->wire.sendbuf);
				mux_frame_put(&fx.cli->pool, frame);
				frame = NULL;
			}
			fx.cli->wire.tx_pending = false;
			mux_session_notify(fx.cli);
		}
		if (fx.srv != NULL) {
			mux_session_notify(fx.srv);
		}
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	/* The INIT stream is parked on the low-priority queue while the sendbuf
	 * is occupied; the lifecycle drain is NOT scheduled (an active idle watcher
	 * would keep libev from sleeping and spin until the transport drains). */
	const bool lp_not_pending_pre = !fx.cli->sched.lp_pending;
	const bool lp_head_parked = fx.cli->sched.lp_head != NULL;
	const bool tx_pending_pre = fx.cli->wire.tx_pending;

	/* Stop the socket watcher so EVRUN_NOWAIT cannot flush the sendbuf:
	 * opening the stream re-armed EV_WRITE via mux_session_notify, so stop it here
	 * to confirm the lifecycle drain stays parked while the sendbuf is busy. */
	ev_io_stop(fx.loop, &fx.cli->w_socket);

	ev_run(fx.loop, EVRUN_NOWAIT);

	const bool lp_not_pending_post = !fx.cli->sched.lp_pending;
	const bool sendbuf_head_is_frame = fx.cli->wire.sendbuf.head == frame;
	const bool tx_pending_post = fx.cli->wire.tx_pending;

	/* Teardown first so a failing assert can't leak the fixture. */
	if (fx.cli != NULL) {
		if (fx.cli->wire.sendbuf.head == frame) {
			(void)mux_frame_list_pop(&fx.cli->wire.sendbuf);
			mux_frame_put(&fx.cli->pool, frame);
			frame = NULL;
		}
		fx.cli->wire.tx_pending = false;
		mux_session_notify(fx.cli);
	}
	if (fx.srv != NULL) {
		mux_session_notify(fx.srv);
	}
	fixture_teardown(&fx);

	T_EXPECT(lp_not_pending_pre);
	T_EXPECT(lp_head_parked);
	T_EXPECT(tx_pending_pre);
	T_EXPECT(lp_not_pending_post);
	T_EXPECT(sendbuf_head_is_frame);
	T_EXPECT(tx_pending_post);
}

/* test_retransmit_excludes_lifecycle_drain: while replay is in flight
 * (retransmit_off != SIZE_MAX), mux_session_on_send must NOT drain the
 * lifecycle queue; the drain stays pending until replay completes. */
T_DECLARE_CASE(test_retransmit_excludes_lifecycle_drain)
{
	struct mux_test_fixture fx;
	struct mux_frame *u = NULL;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Drive mux_session_on_send by hand; stop the watcher so the loop cannot
	 * drain in the background. */
	ev_io_stop(fx.loop, &fx.cli->w_socket);

	/* A fresh INIT stream parked on the lifecycle (lp) queue, drain armed. */
	struct mux_stream *b = mux_stream_open(fx.cli);
	if (b == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	const enum stream_state b_state_pre = b->state;
	const bool lp_head_is_b = fx.cli->sched.lp_head == b;
	fx.cli->sched.lp_pending = true;

	/* One unacked entry with the replay cursor at its head makes resume
	 * replay "in flight" for this send pass. */
	u = mux_frame_get(&fx.cli->pool, fx.cli->max_payload);
	if (u == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_frame_get failed");
		return;
	}
	u->pos = 0;
	u->len = MUX_FRAME_HEADER_SIZE;
	const struct mux_header uh = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 0,
		.stream_id = 2, /* any non-control id */
		.extra = 0,
	};
	mux_write_header(u->data, &uh);
	mux_unacked_track_sent(
		fx.cli, u); /* takes ownership; ring count -> 1 */
	u = NULL;
	if (fx.cli->unacked.ring == NULL || fx.cli->unacked.ring->count == 0) {
		fixture_teardown(&fx);
		T_FATAL("unacked ring not populated");
		return;
	}
	fx.cli->unacked.retransmit_off = 0;

	mux_session_on_send(fx.cli);

	/* Exclusivity: the lifecycle SYN must not have been staged ahead of the
	 * replay; the drain stays pending for after replay completes. */
	const enum stream_state b_state_post = b->state;
	const bool lp_pending_final = fx.cli->sched.lp_pending;

	/* Teardown first so a failing assert can't leak the fixture. */
	if (u != NULL) {
		mux_frame_put(&fx.cli->pool, u);
	}
	fixture_teardown(&fx);

	T_EXPECT_EQ(b_state_pre, STREAM_INIT);
	T_EXPECT(lp_head_is_b);
	T_EXPECT_EQ(b_state_post, STREAM_INIT);
	T_EXPECT(lp_pending_final);
}

struct nagle_ack_ctx {
	const struct mux_test_fixture *fx;
	const struct mux_stream *s;
	uint_least32_t unacked;
	uint_fast64_t drained;
};

/* Satisfied once the stream's queue is empty with exactly ctx->unacked bytes
 * in flight and the server-side drain has counted ctx->drained bytes. */
static int pred_nagle_flushed(void *ptr)
{
	const struct nagle_ack_ctx *restrict ctx = ptr;
	if (ctx->fx->n_accepted < 1) {
		return 0;
	}
	const struct test_stream *restrict srv = ctx->fx->accepted[0];
	if (srv->got_error) {
		return -1;
	}
	if (ctx->s->send_queue.head != NULL ||
	    ctx->s->unacked_bytes != ctx->unacked) {
		return 0;
	}
	return srv->recv_total >= ctx->drained ? 1 : 0;
}

/* Wait for both sessions, open a client stream with an attached I/O watcher,
 * and wait until the peer's SYN|ACK establishes it. Returns NULL on failure;
 * the fixture owns whatever was attached. */
static struct mux_stream *open_established_stream(struct mux_test_fixture *fx)
{
	if (wait_until(
		    fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established, fx) !=
	    0) {
		return NULL;
	}
	struct mux_stream *const s = mux_stream_open(fx->cli);
	if (s == NULL) {
		return NULL;
	}
	struct test_stream *const ts = test_stream_new(fx, s);
	if (ts == NULL) {
		return NULL;
	}
	fx->cli_streams[fx->n_cli_streams++] = ts;
	mux_stream_io_start(fx->loop, &ts->w_io);
	struct stream_established_ctx est = { .s = s };
	if (wait_until(
		    fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		    &est) != 0) {
		return NULL;
	}
	return s;
}

/* A small frame Nagle holds behind unacked data leaves on the peer's ACK. The
 * coalescing timer's flush, the other way out, is taken off the table: the
 * held stream is removed from the delay list before any tick can elapse, the
 * server drains without echoing (so no delayed ACK re-lists the client stream)
 * and its own grant never reaches a unit, so the ACK is injected by hand. */
T_DECLARE_CASE(test_nagle_releases_queued_small_frame_on_ack)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	fx.accept_mode = ACCEPT_DRAIN;

	/* The SYN|ACK clears unacked_bytes, so the first payload goes out after
	 * establishment to leave it in flight when the second is dequeued. */
	struct mux_stream *const s = open_established_stream(&fx);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("client stream did not establish");
		return;
	}

	unsigned char payload_a[37];
	unsigned char payload_b[53];
	fill_payload(payload_a, sizeof(payload_a), 0x21);
	fill_payload(payload_b, sizeof(payload_b), 0x4D);

	size_t len_a = sizeof(payload_a);
	const bool send_a_ok = mux_stream_send(s, payload_a, &len_a) == 0 &&
			       len_a == sizeof(payload_a);
	struct nagle_ack_ctx ctx = {
		.fx = &fx,
		.s = s,
		.unacked = sizeof(payload_a),
		.drained = sizeof(payload_a),
	};
	const int ret_a = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_nagle_flushed, &ctx);

	/* Dequeue the second payload synchronously, so no loop turn (and no
	 * coalescing tick) separates the hold from the check below. */
	size_t len_b = sizeof(payload_b);
	const bool send_b_ok = mux_stream_send(s, payload_b, &len_b) == 0 &&
			       len_b == sizeof(payload_b);
	mux_session_on_send(fx.cli);
	const bool held = s->send_queue.head != NULL;
	const uint_least32_t unacked_held = s->unacked_bytes;
	const bool flush_armed = s->delay_pending;
	if (s->delay_pending) {
		mux_sched_delay_remove(fx.cli, s);
	}

	/* The peer acknowledges without granting credit: only the ACK's
	 * unacked_bytes reset can release the frame now. */
	const bool ack_ok =
		mux_session_send_ctrl(fx.srv, s->id, MUX_FLAG_ACK, 0);
	ctx.unacked = sizeof(payload_b);
	ctx.drained = sizeof(payload_a) + sizeof(payload_b);
	const int ret_b = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_nagle_flushed, &ctx);
	const bool flush_rearmed = s->delay_pending;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(send_a_ok);
	T_EXPECT(ret_a == 0);
	T_EXPECT(send_b_ok);
	T_EXPECT(held && flush_armed);
	T_EXPECT_EQ(unacked_held, (uint_least32_t)sizeof(payload_a));
	T_EXPECT(ack_ok);
	T_EXPECT(ret_b == 0 && !flush_rearmed);
}

T_DECLARE_CASE(test_send_recv_large)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x7F);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_LARGE;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == PAYLOAD_LARGE &&
		memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_LARGE);
	if (recv_len == PAYLOAD_LARGE) {
		T_EXPECT(payload_matches);
	}
}

T_DECLARE_CASE(test_half_close)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0x11);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait for the echo to arrive and client to receive EOF from server. */
	const int ret = wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_eof, ts);
	const bool got_eof = ts->got_eof;
	const bool got_error = ts->got_error;
	const unsigned int writes_after_shutdown = fx.writes_after_shutdown;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(got_eof);
	T_EXPECT(!got_error);
	/* Neither half-closed end is reported writable again. */
	T_EXPECT_EQ(writes_after_shutdown, 0u);
}

T_DECLARE_CASE(test_rst_on_unread_data)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Server will close immediately when a stream arrives (RST). */
	fx.accept_mode = ACCEPT_CLOSE_IMMEDIATE;

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0xAB);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait for client to observe ECONNRESET (RST from server, delivered
	 * as EV_READ; mux_stream_recv returns -1 / ECONNRESET). */
	const int ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	const bool got_error = ts->got_error;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(got_error);
}

T_DECLARE_CASE(test_multi_stream)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payloads[MULTI_CONCURRENCY];
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		payloads[i] = NULL;
	}
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		payloads[i] = malloc(PAYLOAD_SMALL);
		if (payloads[i] == NULL) {
			for (int j = 0; j < MULTI_CONCURRENCY; j++) {
				free(payloads[j]);
			}
			fixture_teardown(&fx);
			T_FATAL("malloc failed");
			return;
		}
		fill_payload(
			payloads[i], PAYLOAD_SMALL, (uint_fast8_t)(i * 37));
	}

	struct test_stream *streams[MULTI_CONCURRENCY];
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		streams[i] = NULL;
	}
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		struct mux_stream *s = mux_stream_open(fx.cli);
		if (s == NULL) {
			for (int j = 0; j < MULTI_CONCURRENCY; j++) {
				free(payloads[j]);
			}
			fixture_teardown(&fx);
			T_FATAL("mux_stream_open returned NULL");
			return;
		}
		struct test_stream *ts = test_stream_new(&fx, s);
		if (ts == NULL) {
			for (int j = 0; j < MULTI_CONCURRENCY; j++) {
				free(payloads[j]);
			}
			fixture_teardown(&fx);
			T_FATAL("test_stream_new failed");
			return;
		}
		if (fx.n_cli_streams < MAX_ACCEPTED) {
			fx.cli_streams[fx.n_cli_streams++] = ts;
		}
		streams[i] = ts;
		ts->send_data = payloads[i];
		ts->send_len = PAYLOAD_SMALL;
		mux_stream_io_start(fx.loop, &ts->w_io);
	}

	/* Wait for all streams to receive their echoed payload. */
	int rets[MULTI_CONCURRENCY];
	size_t recv_lens[MULTI_CONCURRENCY];
	bool matches[MULTI_CONCURRENCY];
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		struct echo_ctx ctx = {
			.ts = streams[i],
			.expected = payloads[i],
			.expected_len = PAYLOAD_SMALL,
		};
		rets[i] = wait_until(
			&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
			&ctx);
		recv_lens[i] = streams[i]->recv_len;
		matches[i] = recv_lens[i] == PAYLOAD_SMALL &&
			     memcmp(streams[i]->recv_buf, payloads[i],
				    PAYLOAD_SMALL) == 0;
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		free(payloads[i]);
	}
	fixture_teardown(&fx);

	for (int i = 0; i < MULTI_CONCURRENCY; i++) {
		T_EXPECT(rets[i] == 0);
		if (rets[i] == 0) {
			T_EXPECT_EQ(recv_lens[i], (size_t)PAYLOAD_SMALL);
			if (recv_lens[i] == PAYLOAD_SMALL) {
				T_EXPECT(matches[i]);
			}
		}
	}
}

/* server actively opens a stream and sends a
 * payload first; the client-side (echo) sends it back.  Verifies that the
 * server-side initiator correctly receives the echoed data. */

T_DECLARE_CASE(test_server_open_send_recv)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x55);

	/* Server actively opens a stream toward the client. */
	struct mux_stream *s = mux_stream_open(fx.srv);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(srv) returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	if (fx.n_srv_active_streams < MAX_ACCEPTED) {
		fx.srv_active_streams[fx.n_srv_active_streams++] = ts;
	}
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Client-side on_accept_cb uses default ACCEPT_ECHO mode and will
	 * echo all data back to the server. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == PAYLOAD_SMALL &&
		memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_SMALL);
	if (recv_len == PAYLOAD_SMALL) {
		T_EXPECT(payload_matches);
	}
}

/* client opens a stream but sends no data; the server sends a payload
 * and immediately half-closes.  Verifies the client receives data and
 * peer EOF. */

T_DECLARE_CASE(test_client_open_server_sends_first)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0xC3);

	/* Server will send payload + FIN when a stream is accepted. */
	fx.accept_mode = ACCEPT_SEND_PAYLOAD;
	fx.accept_send_data = payload;
	fx.accept_send_len = PAYLOAD_SMALL;

	/* Client opens a stream; it does not send any data – it only receives. */
	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(cli) returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait until the client received all bytes AND got peer EOF. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	const size_t recv_len = ts->recv_len;
	const bool got_eof = ts->got_eof;
	const bool got_error = ts->got_error;
	const bool payload_matches =
		recv_len == PAYLOAD_SMALL &&
		memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_SMALL);
	T_EXPECT(got_eof);
	T_EXPECT(!got_error);
	if (recv_len == PAYLOAD_SMALL) {
		T_EXPECT(payload_matches);
	}
}

/* server actively opens a stream, sends a payload, then half-closes.
 * The client-side echo mirrors data and FIN back; verifies the server
 * observes clean EOF without errors. */

T_DECLARE_CASE(test_graceful_close_server_initiated)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0xD4);

	/* Server opens and will send payload then FIN. */
	struct mux_stream *s = mux_stream_open(fx.srv);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(srv) returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	if (fx.n_srv_active_streams < MAX_ACCEPTED) {
		fx.srv_active_streams[fx.n_srv_active_streams++] = ts;
	}
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Client-side (ACCEPT_ECHO) echoes the data and mirrors the FIN.
	 * Server then receives the echoed data and a peer EOF. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = sizeof(payload),
	};
	const int ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	const bool got_eof = ts->got_eof;
	const bool got_error = ts->got_error;
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == sizeof(payload) &&
		memcmp(ts->recv_buf, payload, sizeof(payload)) == 0;
	const unsigned int writes_after_shutdown = fx.writes_after_shutdown;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(got_eof);
	T_EXPECT(!got_error);
	T_EXPECT_EQ(recv_len, sizeof(payload));
	if (recv_len == sizeof(payload)) {
		T_EXPECT(payload_matches);
	}
	/* Neither half-closed end is reported writable again. */
	T_EXPECT_EQ(writes_after_shutdown, 0u);
}

/* test_simultaneous_close: both ends half-close independently, exercising
 * FIN_WAIT->CLOSING (active opener) and CLOSE_WAIT->CLOSING (passive opener)
 * with distinct payloads. */

T_DECLARE_CASE(test_simultaneous_close)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *cli_payload = malloc(PAYLOAD_SMALL);
	if (cli_payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(cli_payload, PAYLOAD_SMALL, 0x77);

	unsigned char *srv_payload = malloc(PAYLOAD_SMALL);
	if (srv_payload == NULL) {
		free(cli_payload);
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(srv_payload, PAYLOAD_SMALL, 0x88);

	/* Server sends srv_payload + FIN when the stream is accepted. */
	fx.accept_mode = ACCEPT_SEND_PAYLOAD;
	fx.accept_send_data = srv_payload;
	fx.accept_send_len = PAYLOAD_SMALL;

	/* Client opens a stream and sends cli_payload + FIN. */
	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(cli_payload);
		free(srv_payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(cli_payload);
		free(srv_payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = cli_payload;
	ts->send_len = PAYLOAD_SMALL;
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait until the server has accepted the stream. */
	struct accepted_count_ctx acc_ctx = { .fx = &fx, .min_accepted = 1 };
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_accepted_count,
		    &acc_ctx) != 0) {
		free(cli_payload);
		free(srv_payload);
		fixture_teardown(&fx);
		T_FATAL("server did not accept stream");
		return;
	}

	/* Both sides independently receive data and a peer FIN. */
	struct test_stream *srv_ts = fx.accepted[0];
	const struct both_eof_ctx ctx = { .a = ts, .b = srv_ts };
	const int ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_both_eof_no_error,
		(void *)&ctx);
	const bool ts_got_eof = ts->got_eof;
	const bool ts_got_error = ts->got_error;
	const bool srv_got_eof = srv_ts->got_eof;
	const bool srv_got_error = srv_ts->got_error;
	const size_t ts_recv_len = ts->recv_len;
	const bool ts_matches =
		ts_recv_len == PAYLOAD_SMALL &&
		memcmp(ts->recv_buf, srv_payload, PAYLOAD_SMALL) == 0;
	const size_t srv_recv_len = srv_ts->recv_len;
	const bool srv_matches =
		srv_recv_len == PAYLOAD_SMALL &&
		memcmp(srv_ts->recv_buf, cli_payload, PAYLOAD_SMALL) == 0;
	const size_t cli_halfopen = fx.cli->num_halfopen;

	free(cli_payload);
	free(srv_payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(ts_got_eof);
	T_EXPECT(!ts_got_error);
	T_EXPECT(srv_got_eof);
	T_EXPECT(!srv_got_error);
	T_EXPECT_EQ(ts_recv_len, (size_t)PAYLOAD_SMALL);
	if (ts_recv_len == PAYLOAD_SMALL) {
		T_EXPECT(ts_matches);
	}
	T_EXPECT_EQ(srv_recv_len, (size_t)PAYLOAD_SMALL);
	if (srv_recv_len == PAYLOAD_SMALL) {
		T_EXPECT(srv_matches);
	}
	T_EXPECT_EQ(cli_halfopen, (size_t)0);
}

/* server opens a stream and sends a payload; the client closes without
 * reading, triggering RST (non-empty recv buffer).  Verifies the server
 * observes ECONNRESET via got_error. */

T_DECLARE_CASE(test_rst_from_client)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Client-side accepted streams will close on first readable event,
	 * triggering RST because the receive buffer contains unread data. */
	fx.accept_mode = ACCEPT_CLOSE_IMMEDIATE;

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0xE5);

	/* Server opens a stream and sends data; this data will land in the
	 * client-side receive buffer, triggering RST on close. */
	struct mux_stream *s = mux_stream_open(fx.srv);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(srv) returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	if (fx.n_srv_active_streams < MAX_ACCEPTED) {
		fx.srv_active_streams[fx.n_srv_active_streams++] = ts;
	}
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Server should receive ECONNRESET (RST from client). */
	const int ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	const bool got_error = ts->got_error;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(got_error);
}

/* Satisfied once the server's accepted stream has observed ECONNRESET and the
 * client session holds no active stream (only tombstones). */
static int pred_srv_reset_cli_released(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->n_accepted == 0 || !fx->accepted[0]->got_error) {
		return 0;
	}
	return table_size(fx->cli->sched.streams) ==
			       fx->cli->sched.num_tombstones ?
		       1 :
		       0;
}

/* The client closes a direct stream before any data arrives (empty buffer:
 * graceful FIN, FIN_WAIT) while the server keeps sending more than the client's
 * window without a FIN. Nobody will read that data, so the client must reset
 * the stream on its arrival: the server observes ECONNRESET and the client's
 * stream stops being active, instead of both stranding for the session's life
 * with the client's buffered bytes never granted back. */
T_DECLARE_CASE(test_closed_stream_rsts_peer_sending_without_fin)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x5A);
	/* PAYLOAD_LARGE exceeds the client's stream window, so the server's FIN
	 * can only follow once the client grants credit back. */
	fx.accept_mode = ACCEPT_SEND_PAYLOAD;
	fx.accept_send_data = payload;
	fx.accept_send_len = PAYLOAD_LARGE;

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(cli) returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);
	ts->closed = true;
	mux_stream_close(s);

	const int ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_srv_reset_cli_released, &fx);
	const size_t cli_buffered = fx.cli->recv_buffered_bytes;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT_EQ(cli_buffered, (size_t)0);
}

/* Satisfied once the client's tombstone count is back to zero and its
 * lifecycle queue is empty: tombstone expiry has been processed. */
static int pred_cli_tombstones_swept(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	return fx->cli->sched.num_tombstones == 0 &&
			       fx->cli->sched.lp_head == NULL ?
		       1 :
		       0;
}

static int pred_cli_no_streams(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	return table_size(fx->cli->sched.streams) == 0 ? 1 : 0;
}

/* A direct stream reset under the application (peer RST, delivered as
 * ECONNRESET) belongs to the application until it calls mux_stream_close():
 * tombstone expiry must not free it, so a close deferred past the tombstone
 * period is still valid, and that close then frees the stream. */
T_DECLARE_CASE(test_rst_stream_kept_until_close)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* The server resets the stream when the client's data arrives. */
	fx.accept_mode = ACCEPT_CLOSE_IMMEDIATE;
	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0x3C);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	/* Record the ECONNRESET but defer the close, as an application handing
	 * the close to a worker queue would. */
	ts->closed = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	const int reset_ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	const bool tombstoned = reset_ret == 0 && s->state == STREAM_CLOSED &&
				ev_is_active(&s->w_tombstone);
	int swept_ret = -1;
	if (tombstoned) {
		/* Expire the tombstone now instead of waiting it out. */
		ev_timer_stop(fx.loop, &s->w_tombstone);
		ev_feed_event(fx.loop, &s->w_tombstone, EV_TIMER);
		swept_ret = wait_until(
			&fx, EOF_TIMEOUT_MS / 1000.0, pred_cli_tombstones_swept,
			&fx);
	}
	const bool held = table_size(fx.cli->sched.streams) == 1;
	int recv_ret = 0;
	int recv_err = 0;
	int freed_ret = -1;
	if (tombstoned && held) {
		unsigned char buf[16];
		size_t len = sizeof(buf);
		recv_ret = mux_stream_recv(s, buf, &len);
		recv_err = errno;
		mux_stream_close(s);
		freed_ret = wait_until(
			&fx, EOF_TIMEOUT_MS / 1000.0, pred_cli_no_streams, &fx);
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(reset_ret == 0);
	T_EXPECT(tombstoned);
	T_EXPECT(swept_ret == 0);
	T_EXPECT(held);
	T_EXPECT_EQ(recv_ret, -1);
	T_EXPECT_EQ(recv_err, ECONNRESET);
	T_EXPECT(freed_ret == 0);
}

T_DECLARE_CASE(test_active_open_shutdown_before_synack)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Half-close before SYN|ACK: must not emit FIN ahead of the SYN. */
	mux_stream_shutdown(s);

	/* Ensure server accepted the stream and local side reaches clean EOF. */
	struct accepted_count_ctx accepted_ctx = {
		.fx = &fx,
		.min_accepted = 1,
	};
	const int accepted_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_accepted_count,
		&accepted_ctx);

	/* Direct I/O may complete the FIN/FIN exchange and close the stream
	 * without delivering a final EOF callback.  The key regression signal
	 * is that the path stays graceful and does not raise ECONNRESET. */
	const struct no_error_and_no_halfopen_ctx stable_ctx = {
		.fx = &fx,
		.ts = ts,
	};
	const int stable_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_no_error_and_no_halfopen,
		(void *)&stable_ctx);
	const bool no_error = !ts->got_error;
	const size_t cli_halfopen = fx.cli->num_halfopen;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(accepted_ret == 0);
	T_EXPECT(stable_ret == 0);
	T_EXPECT(no_error);
	T_EXPECT_EQ(cli_halfopen, (size_t)0);
}

/* Socket mode (mux_stream_attach_fd): the test plays the local peer that the
 * tunnel layer would otherwise connect, one app_end on each side's local TCP
 * connection, driven non-blocking from its own watcher on the fixture loop so a
 * full socket buffer wakes the loop like any mux event. */

enum {
	/* Larger than the fixture's stream window (4 frames), so the relay is
	 * paced by flow control rather than fitting in one window. */
	SOCKET_PAYLOAD = 131072,
};

struct app_end {
	ev_io w_io;
	struct ev_loop *loop;
	int fd;
	const unsigned char *send_data;
	size_t send_len;
	size_t send_off;
	unsigned char *recv_buf;
	size_t recv_cap;
	size_t recv_len;
	bool eof;
	int err;
};

static void app_end_update(struct app_end *restrict e)
{
	int events = 0;
	if (e->fd >= 0 && e->err == 0) {
		if (!e->eof) {
			events |= EV_READ;
		}
		if (e->send_off < e->send_len) {
			events |= EV_WRITE;
		}
	}
	ev_io_stop(e->loop, &e->w_io);
	if (events != 0) {
		ev_io_set(&e->w_io, e->fd, events);
		ev_io_start(e->loop, &e->w_io);
	}
}

static void app_end_pump(struct app_end *restrict e)
{
	while (e->err == 0 && e->send_off < e->send_len) {
		const ssize_t n =
			send(e->fd, e->send_data + e->send_off,
			     e->send_len - e->send_off, 0);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				e->err = errno;
			}
			break;
		}
		e->send_off += (size_t)n;
	}
	while (e->err == 0 && !e->eof) {
		/* A full buffer still reads, so a later EOF or reset is seen;
		 * any byte past the expected ones is an overflow. */
		unsigned char spill;
		const bool full = e->recv_len >= e->recv_cap;
		const ssize_t n = full ? recv(e->fd, &spill, 1, 0) :
					 recv(e->fd, e->recv_buf + e->recv_len,
					      e->recv_cap - e->recv_len, 0);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				e->err = errno;
			}
			break;
		}
		if (n == 0) {
			e->eof = true;
			break;
		}
		if (full) {
			e->err = EOVERFLOW;
			break;
		}
		e->recv_len += (size_t)n;
	}
	app_end_update(e);
}

static void app_end_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)revents;
	app_end_pump(w->data);
}

/* Open one local connection: *mux_fd receives the end to attach to a stream,
 * and e the other, which the test drives. */
static bool app_end_open(
	struct app_end *restrict e, struct ev_loop *loop,
	unsigned char *restrict recv_buf, const size_t recv_cap,
	int *restrict mux_fd)
{
	int fds[2];
	if (!bench_loopback_pair(fds)) {
		return false;
	}
	if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		return false;
	}
	*e = (struct app_end){
		.loop = loop,
		.fd = fds[0],
		.recv_cap = recv_cap,
	};
	e->recv_buf = recv_buf;
	ev_io_init(&e->w_io, app_end_cb, e->fd, EV_READ);
	e->w_io.data = e;
	app_end_update(e);
	*mux_fd = fds[1];
	return true;
}

static void app_end_send(
	struct app_end *restrict e, const unsigned char *restrict data,
	const size_t len)
{
	e->send_data = data;
	e->send_len = len;
	e->send_off = 0;
	app_end_pump(e);
}

/* Close the test's end; with abort, abortively (SO_LINGER {1, 0}: RST). */
static void app_end_close(struct app_end *restrict e, const bool abort)
{
	if (e->fd < 0) {
		return;
	}
	ev_io_stop(e->loop, &e->w_io);
	if (abort) {
		const struct linger lg = { .l_onoff = 1, .l_linger = 0 };
		(void)setsockopt(e->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	}
	(void)close(e->fd);
	e->fd = -1;
}

static int pred_app_received(void *ptr)
{
	const struct app_end *restrict e = ptr;
	if (e->err != 0) {
		return -1;
	}
	if (e->recv_len >= e->recv_cap) {
		return 1;
	}
	return e->eof ? -1 : 0;
}

static int pred_app_eof(void *ptr)
{
	const struct app_end *restrict e = ptr;
	if (e->err != 0) {
		return -1;
	}
	return e->eof ? 1 : 0;
}

/* The local peer was reset: a FIN instead is the wrong outcome. */
static int pred_app_reset(void *ptr)
{
	const struct app_end *restrict e = ptr;
	if (e->err == ECONNRESET) {
		return 1;
	}
	return (e->err != 0 || e->eof) ? -1 : 0;
}

static int pred_both_streams_closed(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->cli == NULL || fx->srv == NULL) {
		return -1;
	}
	return (fx->cli->sched.num_tombstones > 0 &&
		fx->srv->sched.num_tombstones > 0) ?
		       1 :
		       0;
}

/* Socket mode end to end: a stream relays between two local sockets, one
 * attached on the dialing side and one on the accepted side.  Data written
 * before the SYN|ACK is delivered intact, both directions carry a payload
 * paced by flow control, and each local half-close (SHUT_WR) arrives as a FIN
 * the far side delivers as SHUT_WR on its own socket -- without ending the
 * other direction -- until both halves are closed and the stream completes. */
T_DECLARE_CASE(test_socket_mode_relay)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *const up = malloc(SOCKET_PAYLOAD);
	unsigned char *const down = malloc(SOCKET_PAYLOAD);
	unsigned char *const cli_recv = malloc(SOCKET_PAYLOAD);
	unsigned char *const srv_recv = malloc(SOCKET_PAYLOAD);
	struct app_end cli_app = { .fd = -1 };
	struct app_end srv_app = { .fd = -1 };
	int cli_mux_fd = -1;
	bool setup_ok = up != NULL && down != NULL && cli_recv != NULL &&
			srv_recv != NULL &&
			app_end_open(
				&cli_app, fx.loop, cli_recv, SOCKET_PAYLOAD,
				&cli_mux_fd) &&
			app_end_open(
				&srv_app, fx.loop, srv_recv, SOCKET_PAYLOAD,
				&fx.accept_attach_fd);
	struct mux_stream *s = NULL;
	if (setup_ok) {
		fill_payload(up, SOCKET_PAYLOAD, 0x3C);
		fill_payload(down, SOCKET_PAYLOAD, 0xC3);
		fx.accept_mode = ACCEPT_ATTACH_FD;
		/* Queue the whole upstream payload before the stream exists, so
		 * all but the fast-open frame must wait for the SYN|ACK. */
		app_end_send(&cli_app, up, SOCKET_PAYLOAD);
		s = mux_stream_open(fx.cli);
		setup_ok = s != NULL;
	}
	if (!setup_ok) {
		app_end_close(&cli_app, false);
		app_end_close(&srv_app, false);
		if (cli_mux_fd >= 0) {
			(void)close(cli_mux_fd);
		}
		if (fx.accept_attach_fd >= 0) {
			(void)close(fx.accept_attach_fd);
		}
		free(up);
		free(down);
		free(cli_recv);
		free(srv_recv);
		fixture_teardown(&fx);
		T_FATAL("socket-mode setup failed");
		return;
	}
	mux_stream_attach_fd(s, cli_mux_fd);

	/* Upstream: everything the client-side local peer wrote. */
	const int up_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_app_received, &srv_app);
	const bool attached = fx.accept_attach_fd == -1;
	const bool up_matches = srv_app.recv_len == SOCKET_PAYLOAD &&
				memcmp(srv_recv, up, SOCKET_PAYLOAD) == 0;

	/* Downstream on the same stream. */
	app_end_send(&srv_app, down, SOCKET_PAYLOAD);
	const int down_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_app_received, &cli_app);
	const bool down_matches = cli_app.recv_len == SOCKET_PAYLOAD &&
				  memcmp(cli_recv, down, SOCKET_PAYLOAD) == 0;

	/* Client-side half-close: the accepted side's local peer reads EOF. */
	(void)shutdown(cli_app.fd, SHUT_WR);
	const int srv_eof_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_app_eof, &srv_app);
	const bool cli_eof_early = cli_app.eof;

	/* The other direction survives the half-close. */
	cli_app.recv_len = 0;
	cli_app.recv_cap = PAYLOAD_SMALL;
	app_end_send(&srv_app, down, PAYLOAD_SMALL);
	const int late_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_app_received, &cli_app);
	const bool late_matches = cli_app.recv_len == PAYLOAD_SMALL &&
				  memcmp(cli_recv, down, PAYLOAD_SMALL) == 0;

	/* Close the second half: the client-side local peer reads EOF and the
	 * stream completes on both sessions. */
	(void)shutdown(srv_app.fd, SHUT_WR);
	const int cli_eof_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_app_eof, &cli_app);
	const int closed_ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_both_streams_closed, &fx);
	const int cli_err = cli_app.err;
	const int srv_err = srv_app.err;

	/* Teardown first so a failing assert can't leak the fixture. */
	app_end_close(&cli_app, false);
	app_end_close(&srv_app, false);
	free(up);
	free(down);
	free(cli_recv);
	free(srv_recv);
	fixture_teardown(&fx);

	T_EXPECT(attached);
	T_EXPECT(up_ret == 0);
	T_EXPECT(up_matches);
	T_EXPECT(down_ret == 0);
	T_EXPECT(down_matches);
	T_EXPECT(srv_eof_ret == 0);
	T_EXPECT(!cli_eof_early);
	T_EXPECT(late_ret == 0);
	T_EXPECT(late_matches);
	T_EXPECT(cli_eof_ret == 0);
	T_EXPECT(closed_ret == 0);
	T_EXPECT_EQ(cli_err, 0);
	T_EXPECT_EQ(srv_err, 0);
}

/* Socket mode abortive close: a local peer that resets its connection aborts
 * the stream, whose RST makes the far side reset its own local socket rather
 * than half-close it -- an abort must not reach the far peer as a clean EOF. */
T_DECLARE_CASE(test_socket_mode_abort)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char payload[64];
	unsigned char cli_recv[sizeof(payload)];
	unsigned char srv_recv[sizeof(payload)];
	struct app_end cli_app = { .fd = -1 };
	struct app_end srv_app = { .fd = -1 };
	int cli_mux_fd = -1;
	bool setup_ok = app_end_open(
				&cli_app, fx.loop, cli_recv, sizeof(cli_recv),
				&cli_mux_fd) &&
			app_end_open(
				&srv_app, fx.loop, srv_recv, sizeof(srv_recv),
				&fx.accept_attach_fd);
	struct mux_stream *s = NULL;
	if (setup_ok) {
		fx.accept_mode = ACCEPT_ATTACH_FD;
		s = mux_stream_open(fx.cli);
		setup_ok = s != NULL;
	}
	if (!setup_ok) {
		app_end_close(&cli_app, false);
		app_end_close(&srv_app, false);
		if (cli_mux_fd >= 0) {
			(void)close(cli_mux_fd);
		}
		if (fx.accept_attach_fd >= 0) {
			(void)close(fx.accept_attach_fd);
		}
		fixture_teardown(&fx);
		T_FATAL("socket-mode setup failed");
		return;
	}
	mux_stream_attach_fd(s, cli_mux_fd);

	/* Relay one payload first so the abort hits an established stream. */
	fill_payload(payload, sizeof(payload), 0x77);
	app_end_send(&cli_app, payload, sizeof(payload));
	const int relay_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_app_received, &srv_app);

	app_end_close(&cli_app, true);
	const int reset_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_app_reset, &srv_app);
	const int srv_err = srv_app.err;
	const bool srv_eof = srv_app.eof;
	/* The abort ends only the stream, never the session under it. */
	const bool sessions_up = fx.cli != NULL && fx.srv != NULL &&
				 mux_state(fx.cli) == MUX_STATE_ESTABLISHED &&
				 mux_state(fx.srv) == MUX_STATE_ESTABLISHED;

	/* Teardown first so a failing assert can't leak the fixture. */
	app_end_close(&srv_app, false);
	fixture_teardown(&fx);

	T_EXPECT(relay_ret == 0);
	T_EXPECT(reset_ret == 0);
	T_EXPECT_EQ(srv_err, ECONNRESET);
	T_EXPECT(!srv_eof);
	T_EXPECT(sessions_up);
}

/* Satisfied once the peer's FIN has reached the stream (CLOSE_WAIT). */
static int pred_stream_close_wait(void *ptr)
{
	const struct mux_stream *restrict s = ptr;
	return s->state == STREAM_CLOSE_WAIT ? 1 : 0;
}

/* Satisfied once every stream left in the client's table is a tombstone. */
static int pred_cli_no_active_streams(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->cli == NULL) {
		return -1;
	}
	return table_size(fx->cli->sched.streams) ==
			       fx->cli->sched.num_tombstones ?
		       1 :
		       0;
}

/* Socket mode, attached only after the peer's SYN|ACK, data and FIN have all
 * arrived: the stream is still the application's to attach, so the local
 * socket receives what the peer sent and then EOF, the other direction still
 * relays, and the stream completes on both sessions. */
T_DECLARE_CASE(test_socket_mode_attach_after_synack)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char up[PAYLOAD_SMALL];
	unsigned char down[PAYLOAD_SMALL];
	unsigned char cli_recv[sizeof(down)];
	unsigned char srv_recv[sizeof(up)];
	struct app_end cli_app = { .fd = -1 };
	struct app_end srv_app = { .fd = -1 };
	int cli_mux_fd = -1;
	bool setup_ok = app_end_open(
				&cli_app, fx.loop, cli_recv, sizeof(cli_recv),
				&cli_mux_fd) &&
			app_end_open(
				&srv_app, fx.loop, srv_recv, sizeof(srv_recv),
				&fx.accept_attach_fd);
	struct mux_stream *s = NULL;
	if (setup_ok) {
		fx.accept_mode = ACCEPT_ATTACH_FD;
		s = mux_stream_open(fx.cli);
		setup_ok = s != NULL;
	}
	if (!setup_ok) {
		app_end_close(&cli_app, false);
		app_end_close(&srv_app, false);
		if (cli_mux_fd >= 0) {
			(void)close(cli_mux_fd);
		}
		if (fx.accept_attach_fd >= 0) {
			(void)close(fx.accept_attach_fd);
		}
		fixture_teardown(&fx);
		T_FATAL("socket-mode setup failed");
		return;
	}
	fill_payload(up, sizeof(up), 0x52);
	fill_payload(down, sizeof(down), 0x25);

	struct stream_established_ctx est = { .s = s };
	const int est_ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		&est);
	/* The peer's data, then its FIN, arrive before the socket does. */
	app_end_send(&srv_app, down, sizeof(down));
	(void)shutdown(srv_app.fd, SHUT_WR);
	const int fin_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_stream_close_wait, s);
	const size_t buffered = bytebuf_readable(s->recvbuf);
	mux_stream_attach_fd(s, cli_mux_fd);

	const int down_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_app_eof, &cli_app);
	const bool down_matches = cli_app.recv_len == sizeof(down) &&
				  memcmp(cli_recv, down, sizeof(down)) == 0;
	app_end_send(&cli_app, up, sizeof(up));
	const int up_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_app_received, &srv_app);
	const bool up_matches = srv_app.recv_len == sizeof(up) &&
				memcmp(srv_recv, up, sizeof(up)) == 0;
	(void)shutdown(cli_app.fd, SHUT_WR);
	const int srv_eof_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_app_eof, &srv_app);
	const int closed_ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_both_streams_closed, &fx);
	const int cli_err = cli_app.err;
	const int srv_err = srv_app.err;

	/* Teardown first so a failing assert can't leak the fixture. */
	app_end_close(&cli_app, false);
	app_end_close(&srv_app, false);
	fixture_teardown(&fx);

	T_EXPECT(est_ret == 0);
	T_EXPECT(fin_ret == 0);
	T_EXPECT_EQ(buffered, sizeof(down));
	T_EXPECT(down_ret == 0);
	T_EXPECT(down_matches);
	T_EXPECT(up_ret == 0);
	T_EXPECT(up_matches);
	T_EXPECT(srv_eof_ret == 0);
	T_EXPECT(closed_ret == 0);
	T_EXPECT_EQ(cli_err, 0);
	T_EXPECT_EQ(srv_err, 0);
}

/* Socket mode, attached after a bare peer FIN: with nothing buffered ahead of
 * it, the attach itself passes the FIN on to the local socket, and the
 * stream completes once the local side half-closes too. */
T_DECLARE_CASE(test_socket_mode_attach_after_peer_fin)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char cli_recv[16];
	unsigned char srv_recv[16];
	struct app_end cli_app = { .fd = -1 };
	struct app_end srv_app = { .fd = -1 };
	int cli_mux_fd = -1;
	bool setup_ok = app_end_open(
				&cli_app, fx.loop, cli_recv, sizeof(cli_recv),
				&cli_mux_fd) &&
			app_end_open(
				&srv_app, fx.loop, srv_recv, sizeof(srv_recv),
				&fx.accept_attach_fd);
	struct mux_stream *s = NULL;
	if (setup_ok) {
		fx.accept_mode = ACCEPT_ATTACH_FD;
		s = mux_stream_open(fx.cli);
		setup_ok = s != NULL;
	}
	if (!setup_ok) {
		app_end_close(&cli_app, false);
		app_end_close(&srv_app, false);
		if (cli_mux_fd >= 0) {
			(void)close(cli_mux_fd);
		}
		if (fx.accept_attach_fd >= 0) {
			(void)close(fx.accept_attach_fd);
		}
		fixture_teardown(&fx);
		T_FATAL("socket-mode setup failed");
		return;
	}

	struct stream_established_ctx est = { .s = s };
	const int est_ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		&est);
	(void)shutdown(srv_app.fd, SHUT_WR);
	const int fin_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_stream_close_wait, s);
	mux_stream_attach_fd(s, cli_mux_fd);

	const int cli_eof_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_app_eof, &cli_app);
	const size_t cli_received = cli_app.recv_len;
	(void)shutdown(cli_app.fd, SHUT_WR);
	const int srv_eof_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_app_eof, &srv_app);
	const int closed_ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_both_streams_closed, &fx);
	const int cli_err = cli_app.err;
	const int srv_err = srv_app.err;

	/* Teardown first so a failing assert can't leak the fixture. */
	app_end_close(&cli_app, false);
	app_end_close(&srv_app, false);
	fixture_teardown(&fx);

	T_EXPECT(est_ret == 0);
	T_EXPECT(fin_ret == 0);
	T_EXPECT(cli_eof_ret == 0);
	T_EXPECT_EQ(cli_received, (size_t)0);
	T_EXPECT(srv_eof_ret == 0);
	T_EXPECT(closed_ret == 0);
	T_EXPECT_EQ(cli_err, 0);
	T_EXPECT_EQ(srv_err, 0);
}

/* Direct mode started only after the peer's SYN|ACK: the start binds the
 * watcher and the stream carries data both ways to a clean EOF. */
T_DECLARE_CASE(test_io_start_after_synack)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0x5A);
	struct mux_stream *const s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *const ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	ts->send_shutdown_on_drain = true;

	struct stream_established_ctx est = { .s = s };
	const int est_ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		&est);
	const bool started = mux_stream_io_start(fx.loop, &ts->w_io);
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = sizeof(payload),
	};
	const int echo_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	const bool matches =
		ts->recv_len == sizeof(payload) &&
		memcmp(ts->recv_buf, payload, sizeof(payload)) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(est_ret == 0);
	T_EXPECT(started);
	T_EXPECT(echo_ret == 0);
	T_EXPECT(matches);
}

/* An opened stream closed before it was given a mode -- one before its SYN
 * left, one after the peer's SYN|ACK -- still completes: the FINs are
 * exchanged, it stops counting as active, and a drain of its session finishes
 * rather than waiting on it. */
T_DECLARE_CASE(test_close_before_attach_completes)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	struct mux_stream *const early = mux_stream_open(fx.cli);
	if (early == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	mux_stream_close(early);
	struct mux_stream *const late = mux_stream_open(fx.cli);
	if (late == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct stream_established_ctx est = { .s = late };
	const int est_ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		&est);
	mux_stream_close(late);

	const int idle_ret = wait_until(
		&fx, EOF_TIMEOUT_MS / 1000.0, pred_cli_no_active_streams, &fx);
	const size_t tombstones =
		fx.cli != NULL ? fx.cli->sched.num_tombstones : 0;
	if (fx.cli != NULL) {
		mux_drain(fx.cli);
	}
	const int drained_ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_closed, &fx);

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(est_ret == 0);
	T_EXPECT(idle_ret == 0);
	T_EXPECT_EQ(tombstones, (size_t)2);
	T_EXPECT(drained_ret == 0);
}

static int pred_deferred(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	return fx->deferred != NULL ? 1 : 0;
}

/* An accepted stream the application closes before starting it has never been
 * answered with SYN|ACK, so the close refuses it: the opener sees a reset. */
T_DECLARE_CASE(test_close_before_start_refuses_accepted)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	fx.accept_mode = ACCEPT_DEFER;
	struct mux_stream *const s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *const ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	const int accepted_ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_deferred, &fx);
	if (accepted_ret == 0) {
		mux_stream_close(fx.deferred);
	}
	const int reset_ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	const bool srv_idle =
		fx.srv != NULL && table_size(fx.srv->sched.streams) ==
					  fx.srv->sched.num_tombstones;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(accepted_ret == 0);
	T_EXPECT(reset_ret == 0);
	T_EXPECT(srv_idle);
}

/* mux_shutdown() drives a graceful session shutdown: the session defers into
 * SESSION_CLOSING (not an immediate force-close), any open stream is torn down
 * (its direct user watcher detached), and the transport is half-closed with a
 * FIN -- the peer observes a clean EOF (and suspends for resume) rather than an
 * abortive RST.  Exercised on the real two-session fixture.
 *
 * Note on .closed.clean: the shutdown initiator reaches CLOSED via the
 * CLOSE_WAIT eof-wait (mux_wire_wait_eof).  The suspending peer closes its end
 * of the transport, so the initiator reads that FIN on the WIRE_EOF_CONFIRMED
 * arm, which sets wire.rx_eof: its CLOSED payload reports clean == true.  The
 * stream is opened and its SYN|ACK consumed before the shutdown, so no frame is
 * still in flight to land on the eof-wait as stray data (the WIRE_EOF_ERROR
 * arm, which reports clean == false). */
T_DECLARE_CASE(test_shutdown_graceful)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait for the SYN|ACK so the shutdown tears down a live, two-sided
	 * stream, and so the server's reply is consumed rather than left in
	 * flight for the eof-wait to read as unexpected data. */
	struct stream_established_ctx est_ctx = { .s = s };
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		    &est_ctx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("stream did not establish");
		return;
	}
	const int n_accepted = fx.n_accepted;

	/* Graceful shutdown: aborts the open stream and defers the transport
	 * close into SESSION_CLOSING. */
	mux_shutdown(fx.cli);
	/* The graceful path defers rather than force-closing: the session is now
	 * CLOSING (still live), not already CLOSED. */
	const bool post_shutdown_closing =
		(fx.cli != NULL && fx.cli->state == SESSION_CLOSING);

	const int ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_closed, &fx);
	const bool cli_closed = fx.cli_closed;
	/* The application still held the stream, so its watcher reported the
	 * abort (ECONNRESET) and the callback closed it. */
	const bool stream_reset = ts->got_error;
	/* Half-closed, not reset: the peer read a clean FIN and suspended for
	 * resume rather than seeing an abortive reset. */
	const bool srv_suspended = fx.srv_suspended;
	/* CLOSED payload fields (see the note above): the initiator saw the
	 * peer's FIN, so the close is clean, and it is not a resume-timeout
	 * expiry. */
	const bool closed_clean = fx.cli_closed_data.closed.clean;
	const bool closed_expired = fx.cli_closed_data.closed.expired;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT_EQ(n_accepted, 1);
	T_EXPECT(post_shutdown_closing);
	T_EXPECT(ret == 0);
	T_EXPECT(cli_closed);
	T_EXPECT(stream_reset);
	T_EXPECT(srv_suspended);
	T_EXPECT(closed_clean);
	T_EXPECT(!closed_expired);
}

/* Open a client direct stream whose application defers its close (ts->closed:
 * an ECONNRESET is recorded, not acted on, as when the close is handed to a
 * worker queue), and wait for its SYN|ACK. Returns NULL after tearing the
 * fixture down when the stream cannot be opened or does not establish. */
static struct test_stream *
open_held_direct_stream(struct mux_test_fixture *restrict fx)
{
	struct mux_stream *const s = mux_stream_open(fx->cli);
	if (s == NULL) {
		fixture_teardown(fx);
		return NULL;
	}
	struct test_stream *const ts = test_stream_new(fx, s);
	if (ts == NULL) {
		fixture_teardown(fx);
		return NULL;
	}
	fx->cli_streams[fx->n_cli_streams++] = ts;
	ts->closed = true;
	mux_stream_io_start(fx->loop, &ts->w_io);
	struct stream_established_ctx est_ctx = { .s = s };
	if (wait_until(
		    fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		    &est_ctx) != 0) {
		fixture_teardown(fx);
		return NULL;
	}
	return ts;
}

/* After a session-level teardown the application still holds s: mux_stream_recv()
 * must report ECONNRESET and mux_stream_close() must free it (the live-stream
 * gauge drops to zero). Only called once the gauge shows s still allocated.
 * fx is not restrict: mux_stream_close() updates fx->cli_num_streams through
 * the session's counter pointer. */
static void release_held_stream(
	struct mux_test_fixture *fx, struct mux_stream *restrict s,
	int *restrict recv_ret, int *restrict recv_err,
	size_t *restrict released)
{
	unsigned char buf[16];
	size_t len = sizeof(buf);
	*recv_ret = mux_stream_recv(s, buf, &len);
	*recv_err = errno;
	mux_stream_close(s);
	*released = fx->cli_num_streams;
}

/* mux_shutdown() tears down a session whose direct stream the application
 * still holds: the stream must not be freed under it. Its watcher stays bound
 * and gets EV_READ, and the stream lives until mux_stream_close(). */
T_DECLARE_CASE(test_shutdown_keeps_held_direct_stream)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}
	struct test_stream *const ts = open_held_direct_stream(&fx);
	if (ts == NULL) {
		T_FATAL("held direct stream setup failed");
		return;
	}
	struct mux_stream *const s = ts->s;

	mux_shutdown(fx.cli);
	const bool bound = ts->w_io.stream == s;
	const size_t held = fx.cli_num_streams;
	const int notified_ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	/* The fixture's CLOSED handler runs mux_close(), which frees s. */
	const bool session_alive = fx.cli != NULL;
	int recv_ret = 0;
	int recv_err = 0;
	size_t released = SIZE_MAX;
	if (bound && held == 1 && notified_ret == 0 && session_alive) {
		release_held_stream(&fx, s, &recv_ret, &recv_err, &released);
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(bound);
	T_EXPECT_EQ(held, (size_t)1);
	T_EXPECT(notified_ret == 0);
	T_EXPECT(session_alive);
	T_EXPECT_EQ(recv_ret, -1);
	T_EXPECT_EQ(recv_err, ECONNRESET);
	T_EXPECT_EQ(released, (size_t)0);
}

/* A peer RST on the last active stream of a draining session completes the
 * drain within the RST handling, tearing the session down. The application's
 * ECONNRESET callback has already returned without closing the stream, so the
 * teardown must keep it allocated until mux_stream_close(). */
T_DECLARE_CASE(test_drain_rst_keeps_held_direct_stream)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}
	/* The server resets the stream when the client's data arrives. */
	fx.accept_mode = ACCEPT_CLOSE_IMMEDIATE;
	struct test_stream *const ts = open_held_direct_stream(&fx);
	if (ts == NULL) {
		T_FATAL("held direct stream setup failed");
		return;
	}
	struct mux_stream *const s = ts->s;
	unsigned char payload[64];
	fill_payload(payload, sizeof(payload), 0x5D);
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	mux_drain(fx.cli);
	/* Send once the drain is armed; EV_WRITE resumes a partial send. */
	(void)test_stream_flush_send(ts);

	const int reset_ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts);
	/* The reset ended the last active stream, so the drain shut down. */
	const bool shut_down =
		fx.cli != NULL && mux_state(fx.cli) == MUX_STATE_CLOSING;
	const size_t held = fx.cli_num_streams;
	int recv_ret = 0;
	int recv_err = 0;
	size_t released = SIZE_MAX;
	if (reset_ret == 0 && shut_down && held == 1) {
		release_held_stream(&fx, s, &recv_ret, &recv_err, &released);
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(reset_ret == 0);
	T_EXPECT(shut_down);
	T_EXPECT_EQ(held, (size_t)1);
	T_EXPECT_EQ(recv_ret, -1);
	T_EXPECT_EQ(recv_err, ECONNRESET);
	T_EXPECT_EQ(released, (size_t)0);
}

/* Open a client stream the application defers attaching, then tear its session
 * down with mux_shutdown(). Returns NULL after tearing the fixture down when
 * the sessions do not establish or the stream cannot be opened. */
static struct mux_stream *
open_unattached_then_shutdown(struct mux_test_fixture *fx)
{
	if (wait_until(
		    fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established, fx) !=
	    0) {
		fixture_teardown(fx);
		return NULL;
	}
	struct mux_stream *const s = mux_stream_open(fx->cli);
	if (s == NULL) {
		fixture_teardown(fx);
		return NULL;
	}
	mux_shutdown(fx->cli);
	return s;
}

static bool fd_is_closed(const int fd)
{
	return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

/* A session teardown must not free a stream the application opened but has not
 * attached yet. The deferred mux_stream_attach_fd() then rejects it, closing the
 * fd it was handed, and mux_close() frees the stream. */
T_DECLARE_CASE(test_shutdown_keeps_unattached_stream)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		fixture_teardown(&fx);
		T_FATAL("socketpair failed");
		return;
	}
	struct mux_stream *const s = open_unattached_then_shutdown(&fx);
	if (s == NULL) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		T_FATAL("unattached stream setup failed");
		return;
	}
	const size_t held = fx.cli_num_streams;
	/* The graceful shutdown closes asynchronously: the session survives. */
	const bool session_alive = fx.cli != NULL;
	bool fd_closed = false;
	size_t after_attach = SIZE_MAX;
	if (held == 1 && session_alive) {
		mux_stream_attach_fd(s, fds[0]);
		fd_closed = fd_is_closed(fds[0]);
		after_attach = fx.cli_num_streams;
	} else {
		(void)close(fds[0]);
	}
	const int closed_ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_closed, &fx);
	/* The fixture's CLOSED handler runs mux_close(), which frees s. */
	const size_t after_close = fx.cli_num_streams;

	/* Teardown first so a failing assert can't leak the fixture. */
	(void)close(fds[1]);
	fixture_teardown(&fx);

	T_EXPECT_EQ(held, (size_t)1);
	T_EXPECT(session_alive);
	T_EXPECT(fd_closed);
	/* Rejected, not freed: the caller may still read it before returning. */
	T_EXPECT_EQ(after_attach, (size_t)1);
	T_EXPECT(closed_ret == 0);
	T_EXPECT_EQ(after_close, (size_t)0);
}

/* The same teardown ahead of a deferred mux_stream_io_start(): the start is
 * rejected (false, binding severed), and a mux_stream_close() after it is
 * harmless -- mux_close() still frees the stream exactly once. */
T_DECLARE_CASE(test_shutdown_rejects_deferred_io_start)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	struct mux_stream *const s = open_unattached_then_shutdown(&fx);
	if (s == NULL) {
		T_FATAL("unattached stream setup failed");
		return;
	}
	const size_t held = fx.cli_num_streams;
	const bool session_alive = fx.cli != NULL;
	struct mux_stream_io w = { 0 };
	bool started = true;
	bool severed = false;
	size_t after_close = SIZE_MAX;
	if (held == 1 && session_alive) {
		mux_stream_io_init(&w, stream_io_cb, s, EV_READ);
		started = mux_stream_io_start(fx.loop, &w);
		severed = w.stream == NULL && w.active == 0;
		mux_stream_close(s);
		after_close = fx.cli_num_streams;
	}
	const int closed_ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_closed, &fx);
	const size_t after_mux_close = fx.cli_num_streams;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT_EQ(held, (size_t)1);
	T_EXPECT(session_alive);
	T_EXPECT(!started);
	T_EXPECT(severed);
	T_EXPECT_EQ(after_close, (size_t)1);
	T_EXPECT(closed_ret == 0);
	T_EXPECT_EQ(after_mux_close, (size_t)0);
}

/* An application that gives up a stream it never attached after its session
 * was torn down releases it with mux_stream_close(), which frees it at once. */
T_DECLARE_CASE(test_shutdown_unattached_stream_close_frees)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	struct mux_stream *const s = open_unattached_then_shutdown(&fx);
	if (s == NULL) {
		T_FATAL("unattached stream setup failed");
		return;
	}
	const size_t held = fx.cli_num_streams;
	const bool session_alive = fx.cli != NULL;
	size_t released = SIZE_MAX;
	if (held == 1 && session_alive) {
		mux_stream_close(s);
		released = fx.cli_num_streams;
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT_EQ(held, (size_t)1);
	T_EXPECT(session_alive);
	T_EXPECT_EQ(released, (size_t)0);
}

static int pred_stream_closed(void *ptr)
{
	const struct mux_stream *restrict s = ptr;
	return s->state == STREAM_CLOSED ? 1 : 0;
}

/* Satisfied once the client has swept its low-priority lifecycle queue: no
 * tombstone left and no cleanup pending. */
static int pred_cli_lp_drained(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->cli == NULL) {
		return -1;
	}
	const struct sched_ctx *const sched = &fx->cli->sched;
	return (sched->num_tombstones == 0 && sched->lp_head == NULL &&
		!sched->lp_pending) ?
		       1 :
		       0;
}

/* A peer RST closes a stream the application opened but has not attached yet.
 * Once its tombstone expires, lifecycle cleanup must keep it allocated; the
 * deferred mux_stream_attach_fd() rejects it, closing the fd, and hands it
 * back to cleanup, which frees it. */
T_DECLARE_CASE(test_rst_keeps_unattached_stream_past_tombstone)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}
	/* No local socket to attach: the server refuses the stream (RST). */
	fx.accept_mode = ACCEPT_ATTACH_FD;
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		fixture_teardown(&fx);
		T_FATAL("socketpair failed");
		return;
	}
	struct mux_stream *const s = mux_stream_open(fx.cli);
	if (s == NULL) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open failed");
		return;
	}
	const int reset_ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_stream_closed, s);
	const bool reset = reset_ret == 0 && s->rst_received;
	int drained_ret = -1;
	if (reset) {
		/* Expire the tombstone now instead of MUX_TOMBSTONE_PERIOD_S. */
		ev_timer_stop(fx.loop, &s->w_tombstone);
		ev_feed_event(fx.loop, &s->w_tombstone, EV_TIMER);
		drained_ret = wait_until(
			&fx, EOF_TIMEOUT_MS / 1000.0, pred_cli_lp_drained, &fx);
	}
	const size_t held = fx.cli_num_streams;
	bool fd_closed = false;
	int freed_ret = -1;
	if (drained_ret == 0 && held == 1) {
		mux_stream_attach_fd(s, fds[0]);
		fd_closed = fd_is_closed(fds[0]);
		freed_ret = wait_until(
			&fx, EOF_TIMEOUT_MS / 1000.0, pred_cli_no_streams, &fx);
	} else {
		(void)close(fds[0]);
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	(void)close(fds[1]);
	fixture_teardown(&fx);

	T_EXPECT(reset);
	T_EXPECT(drained_ret == 0);
	T_EXPECT_EQ(held, (size_t)1);
	T_EXPECT(fd_closed);
	T_EXPECT(freed_ret == 0);
}

/* Exercise admission in either direction with a held RST handle, then drain
 * after the replacement closes. Timer expiry is driven directly; every wait
 * runs the real socketpair transport and has the fixture's bounded deadline. */
static struct mux_stream *rst_handle_for_accounting(
	struct testing_ctx *_t_, struct mux_test_fixture *fx, const bool direct)
{
	if (fixture_setup(fx) != 0) {
		T_FATAL("fixture_setup failed");
		return NULL;
	}
	if (wait_until(
		    fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established, fx) !=
	    0) {
		fixture_teardown(fx);
		T_FATAL("sessions did not establish");
		return NULL;
	}
	fx->cli->conf.max_streams = 1;
	fx->accept_mode =
		ACCEPT_ATTACH_FD; /* No fd: the server refuses the SYN. */
	struct mux_stream *const held = mux_stream_open(fx->cli);
	if (held == NULL) {
		fixture_teardown(fx);
		T_FATAL("mux_stream_open failed");
		return NULL;
	}
	if (direct) {
		struct test_stream *const ts = test_stream_new(fx, held);
		if (ts == NULL) {
			fixture_teardown(fx);
			T_FATAL("test_stream_new failed");
			return NULL;
		}
		fx->cli_streams[fx->n_cli_streams++] = ts;
		ts->closed =
			true; /* Observe the RST without relinquishing the handle. */
		mux_stream_io_start(fx->loop, &ts->w_io);
	}
	if (wait_until(fx, EOF_TIMEOUT_MS / 1000.0, pred_stream_closed, held) !=
	    0) {
		fixture_teardown(fx);
		T_FATAL("stream did not receive RST");
		return NULL;
	}
	ev_timer_stop(fx->loop, &held->w_tombstone);
	ev_feed_event(fx->loop, &held->w_tombstone, EV_TIMER);
	if (wait_until(fx, EOF_TIMEOUT_MS / 1000.0, pred_cli_lp_drained, fx) !=
	    0) {
		fixture_teardown(fx);
		T_FATAL("tombstone cleanup did not drain");
		return NULL;
	}
	return held;
}

static void check_rst_handle_accounting(
	struct testing_ctx *_t_, const bool direct, const bool inbound)
{
	struct mux_test_fixture fx;
	struct mux_stream *const held =
		rst_handle_for_accounting(_t_, &fx, direct);
	if (held == NULL) {
		return;
	}
	const uint_least16_t held_id = mux_stream_id(held);
	const bool retained = fx.cli_num_streams == 1 &&
			      held->state == STREAM_CLOSED &&
			      held->rst_received;
	bool admitted = false;
	bool quota_enforced = false;
	bool replacement_closed = false;
	if (inbound) {
		fx.accept_mode = ACCEPT_DEFER;
		struct mux_stream *const replacement = mux_stream_open(fx.srv);
		if (replacement != NULL) {
			admitted = wait_until(
					   &fx, EOF_TIMEOUT_MS / 1000.0,
					   pred_deferred, &fx) == 0;
		}
		if (admitted) {
			struct mux_stream *const refused =
				mux_stream_open(fx.srv);
			quota_enforced =
				refused != NULL &&
				wait_until(
					&fx, EOF_TIMEOUT_MS / 1000.0,
					pred_stream_closed, refused) == 0 &&
				refused->rst_received;
			mux_stream_close(fx.deferred);
			replacement_closed =
				fx.deferred->state == STREAM_CLOSED;
		}
	} else {
		struct mux_stream *const replacement = mux_stream_open(fx.cli);
		admitted = replacement != NULL;
		if (admitted) {
			quota_enforced = mux_stream_open(fx.cli) == NULL;
			mux_stream_close(replacement);
			replacement_closed =
				wait_until(
					&fx, EOF_TIMEOUT_MS / 1000.0,
					pred_stream_closed, replacement) == 0;
		}
	}
	/* No loop turn: drain must already leave ESTABLISHED, and the held
	 * handle must survive the bulk teardown until the caller releases it. */
	mux_drain(fx.cli);
	const bool drained = fx.cli->state != SESSION_ESTABLISHED;
	const bool orphaned = held->orphaned && mux_stream_id(held) == held_id;
	mux_stream_close(held);
	const size_t released = fx.cli_num_streams;
	fixture_teardown(&fx);

	T_EXPECT(retained);
	T_EXPECT(admitted);
	T_EXPECT(quota_enforced);
	T_EXPECT(replacement_closed);
	T_EXPECT(drained);
	T_EXPECT(orphaned);
	T_EXPECT_EQ(released, (size_t)0);
}

T_DECLARE_CASE(test_rst_direct_handle_excluded_from_outbound_quota_and_drain)
{
	check_rst_handle_accounting(_t_, true, false);
}

T_DECLARE_CASE(test_rst_unattached_handle_excluded_from_outbound_quota_and_drain)
{
	check_rst_handle_accounting(_t_, false, false);
}

T_DECLARE_CASE(test_rst_direct_handle_excluded_from_inbound_quota_and_drain)
{
	check_rst_handle_accounting(_t_, true, true);
}

T_DECLARE_CASE(test_rst_unattached_handle_excluded_from_inbound_quota_and_drain)
{
	check_rst_handle_accounting(_t_, false, true);
}

/* mux_shutdown() on a session not yet in HANDSHAKE or ESTABLISHED force-closes
 * it and emits MUX_EVENT_CLOSED re-entrantly, before the call returns -- unlike
 * the graceful path above.  The fixture's on_event handler calls mux_close() on
 * CLOSED, so the caller's handle is already gone once mux_shutdown() returns. */
T_DECLARE_CASE(test_shutdown_before_handshake_closes_synchronously)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	/* The loop has not run, so the dial is still in SESSION_CONNECT. */
	const bool pre_connect = (fx.cli->state == SESSION_CONNECT);

	mux_shutdown(fx.cli);
	/* Observed with no loop iteration in between. */
	const bool cli_closed = fx.cli_closed;
	const bool cli_released = (fx.cli == NULL);
	const bool connect_failed = fx.cli_connect_failed;
	const bool closed_expired = fx.cli_closed_data.closed.expired;

	fixture_teardown(&fx);

	T_EXPECT(pre_connect);
	T_EXPECT(cli_closed);
	T_EXPECT(cli_released);
	T_EXPECT(connect_failed);
	T_EXPECT(!closed_expired);
}

/* Raw interoperability test infrastructure: a minimal wire-level fixture where
 * a mux server session holds one end of a socketpair and raw_fd is driven
 * manually to inject or inspect frames. */

struct raw_fixture {
	struct ev_loop *loop;
	struct mux_session *srv;
	bool srv_established;
	bool srv_closed;
	int raw_fd;

	/* Last on_event() payload captured (event_data contract): ESTABLISHED
	 * populates ev_connected_ns; CLOSED populates ev_closed_*. */
	int_least64_t ev_connected_ns;
	bool ev_closed_clean;
	bool ev_closed_expired;
};

static void raw_on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	struct raw_fixture *const fx = data;
	switch (event) {
	case MUX_EVENT_ESTABLISHED:
		fx->ev_connected_ns = edata.connected.ns;
		fx->srv_established = true;
		break;
	case MUX_EVENT_CLOSED:
		fx->ev_closed_clean = edata.closed.clean;
		fx->ev_closed_expired = edata.closed.expired;
		fx->srv_closed = true;
		fx->srv = NULL;
		mux_close(ss);
		break;
	default:
		break;
	}
}

static const struct mux_callbacks g_raw_callbacks = {
	.on_accept = NULL,
	.on_event = raw_on_event_cb,
};

/* raw_fixture_setup with the server session's lossymux offer (spec §5.2.3.3)
 * chosen by @p lossymux. */
static int raw_fixture_setup_ex(
	struct raw_fixture *fx, const struct mux_callbacks *restrict cbs,
	void *userdata, const bool lossymux)
{
	*fx = (struct raw_fixture){ .raw_fd = -1 };

	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}

	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}

	/* fds[0] = server mux session socket (non-blocking for libev) */
	{
		const int flags = fcntl(fds[0], F_GETFL, 0);
		if (flags >= 0) {
			(void)fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
		}
	}
	/* fds[1] = raw test socket (blocking with a 2-second safety timeout on
	 * both directions, so raw_write_all cannot block forever if the server
	 * ever stops draining its receive buffer) */
	{
		const struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
		(void)setsockopt(
			fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		(void)setsockopt(
			fds[1], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}
	fx->raw_fd = fds[1];

	const struct mux_session_config srv_conf = {
		.timeout = 30,
		.keepalive = 15,
		.send_timeout = 10,
		.connect_timeout = 10,
		.resume_timeout = 30,
		.idle_timeout = 0,
		.max_streams = 64,
		.stream_window = 4,
		.session_window = 256,
		.max_frame_payload =
			mux_session_config_default.max_frame_payload,
		.lossymux = lossymux,
		.lossymux_idle_timeout =
			mux_session_config_default.lossymux_idle_timeout,
		.lossymux_queue = mux_session_config_default.lossymux_queue,
	};

	unsigned char raw_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(raw_sid);
	const struct mux_session_opts raw_opts = {
		.callbacks = cbs,
		.userdata = userdata,
		.conf = &srv_conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = fds[0],
		.id = raw_sid,
	};
	fx->srv = mux_new(fx->loop, &raw_opts);
	if (fx->srv == NULL) {
		(void)close(fds[0]);
		(void)close(fx->raw_fd);
		fx->raw_fd = -1;
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	mux_start(fx->srv);
	return 0;
}

static int raw_fixture_setup(
	struct raw_fixture *fx, const struct mux_callbacks *restrict cbs,
	void *userdata)
{
	return raw_fixture_setup_ex(fx, cbs, userdata, false);
}

static void raw_fixture_teardown(struct raw_fixture *restrict fx)
{
	if (fx->srv != NULL) {
		mux_close(fx->srv);
		fx->srv = NULL;
	}
	if (fx->raw_fd >= 0) {
		(void)close(fx->raw_fd);
		fx->raw_fd = -1;
	}
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

/* Write exactly n bytes, retrying on EINTR. */
static bool raw_write_all(const int fd, const void *const buf, const size_t n)
{
	const unsigned char *p = buf;
	size_t remaining = n;
	while (remaining > 0) {
		const ssize_t nw = write(fd, p, remaining);
		if (nw < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		p += (size_t)nw;
		remaining -= (size_t)nw;
	}
	return true;
}

/* Read exactly n bytes, retrying on EINTR.  Returns false on EOF or error. */
static bool raw_read_all(const int fd, void *const buf, const size_t n)
{
	unsigned char *p = buf;
	size_t remaining = n;
	while (remaining > 0) {
		const ssize_t nr = read(fd, p, remaining);
		if (nr <= 0) {
			if (nr == 0) {
				return false; /* EOF */
			}
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		p += (size_t)nr;
		remaining -= (size_t)nr;
	}
	return true;
}

static int raw_wait_until(
	struct raw_fixture *fx, const double timeout_sec,
	wait_predicate_fn predicate, void *ctx)
{
	return loop_wait_until(fx->loop, timeout_sec, predicate, ctx);
}

/* Predicate: server reached SESSION_ESTABLISHED. */
static int raw_pred_established(void *ctx)
{
	const struct raw_fixture *restrict fx = ctx;
	return fx->srv_established ? 1 : 0;
}

/* Predicate: server session closed. */
static int raw_pred_closed(void *ctx)
{
	const struct raw_fixture *restrict fx = ctx;
	return fx->srv_closed ? 1 : 0;
}

/* Write an 8-byte frame header (zero-payload) to fd. */
static bool raw_send_frame(const int fd, const struct mux_header *restrict hdr)
{
	unsigned char buf[MUX_FRAME_HEADER_SIZE];
	mux_write_header(buf, hdr);
	return raw_write_all(fd, buf, sizeof(buf));
}

/* Write a frame header followed by exactly hdr->length payload octets. */
static bool raw_send_frame_payload(
	const int fd, const struct mux_header *restrict hdr,
	const void *restrict payload)
{
	if (!raw_send_frame(fd, hdr)) {
		return false;
	}
	if (hdr->length == 0) {
		return true;
	}
	return raw_write_all(fd, payload, hdr->length);
}

/* Read an 8-byte frame header from fd (blocking, subject to SO_RCVTIMEO). */
static bool raw_read_frame_header(const int fd, struct mux_header *restrict hdr)
{
	unsigned char buf[MUX_FRAME_HEADER_SIZE];
	if (!raw_read_all(fd, buf, MUX_FRAME_HEADER_SIZE)) {
		return false;
	}
	mux_read_header(buf, hdr);
	return true;
}

static bool raw_discard_payload(const int fd, const uint_least16_t length)
{
	if (length == 0) {
		return true;
	}
	unsigned char *discard_buf = malloc(length);
	if (discard_buf == NULL) {
		return false;
	}
	const bool ok = raw_read_all(fd, discard_buf, length);
	free(discard_buf);
	return ok;
}

/* Returns 1 when raw_fd has incoming data, -1 on EOF/error, 0 otherwise. */
static int raw_pred_data_available(void *ctx)
{
	const int fd = *(const int *)ctx;
	unsigned char b;
	const ssize_t nr = recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT);
	if (nr > 0) {
		return 1;
	}
	if (nr == 0) {
		return -1; /* EOF */
	}
	return 0; /* EAGAIN / EINTR */
}

/* Perform the hello exchange from the raw (client) side:
 * send a ClientHello, drive the loop until SESSION_ESTABLISHED,
 * then drain the ServerHello reply from raw_fd. */
/* raw_do_hello with the raw client's lossymux offer chosen by @p lossymux. */
static bool raw_do_hello_ex(struct raw_fixture *fx, const bool lossymux)
{
	unsigned char buf[512];
	struct proto_hello hello = {
		.msgid = PROTO_MSG_CLIENT_HELLO,
		.reject_inbound = false,
		.lossymux = lossymux,
		.session_id = { 0 },
		.has_session_id = true,
		.has_resume_seq = true,
		.resume_seq = 0,
	};
	const int n = mux_test_proto_hello_build(buf, sizeof(buf), &hello);
	if (n <= 0) {
		return false;
	}
	if (!raw_write_all(fx->raw_fd, buf, (size_t)n)) {
		return false;
	}

	if (raw_wait_until(
		    fx, ESTABLISH_TIMEOUT_MS / 1000.0, raw_pred_established,
		    fx) != 0) {
		return false;
	}

	/* The server enqueues the ServerHello before signalling ESTABLISHED;
	 * drive the event loop until it is flushed to the socket. */
	if (raw_wait_until(fx, 2.0, raw_pred_data_available, &fx->raw_fd) !=
	    0) {
		return false;
	}

	/* Drain the 8-octet frame header + JSON body of the ServerHello. */
	struct mux_header srv_hdr;
	if (!raw_read_frame_header(fx->raw_fd, &srv_hdr)) {
		return false;
	}
	if (srv_hdr.length > 0) {
		unsigned char *body = malloc(srv_hdr.length);
		if (body == NULL) {
			return false;
		}
		const bool ok = raw_read_all(fx->raw_fd, body, srv_hdr.length);
		free(body);
		if (!ok) {
			return false;
		}
	}
	return true;
}

static bool raw_do_hello(struct raw_fixture *fx)
{
	return raw_do_hello_ex(fx, false);
}

/* Interoperability test cases */

/* I-1: non-SYN frame for an unknown stream.  A zero-length ACK is an ignorable
 * terminal control frame, so the server keeps the session open and sends no
 * stream-level response (session-level ACK on stream 0 may still occur). */
T_DECLARE_CASE(test_interop_i1_non_syn_unknown_stream)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	const struct mux_header ack_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_ACK,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool sent = raw_send_frame(fx.raw_fd, &ack_hdr);

	/* Deterministic drain: run the server loop until it makes no further
	 * progress, instead of passing by a fixed wall-clock timeout. */
	for (int i = 0; i < 16; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}

	/* A zero-length ACK for an unknown stream is an ignorable terminal
	 * control frame: the session stays open and emits no stream-level
	 * reply.  Any bytes present are session-level ACKs on stream 0. */
	int raw_fd = fx.raw_fd;
	bool responses_ok = true;
	while (raw_pred_data_available(&raw_fd) > 0) {
		struct mux_header resp;
		if (!raw_read_frame_header(fx.raw_fd, &resp) ||
		    resp.stream_id != 0 || (resp.flags & MUX_FLAG_ACK) == 0 ||
		    resp.length != 0 ||
		    !raw_discard_payload(fx.raw_fd, resp.length)) {
			responses_ok = false;
			break;
		}
	}
	const bool srv_closed = fx.srv_closed;
	/* ESTABLISHED payload from the hello exchange: positive setup latency. */
	const int_least64_t connected_ns = fx.ev_connected_ns;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(sent);
	T_EXPECT(responses_ok);
	/* Negative invariant asserted directly (no timeout): the session
	 * stayed open. */
	T_EXPECT(!srv_closed);
	T_EXPECT(connected_ns > 0);
}

/* Stream-aware raw fixture: extends raw_fixture with an on_accept callback
 * that tracks the accepted stream, enabling tests requiring an established
 * or half-closed stream. */

/* Accepts RAW stream events without acting on them. */
static void
raw_stream_io_noop_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

struct raw_stream_fixture {
	struct raw_fixture base;
	struct mux_stream *accepted_stream;
	mux_stream_io w_stream;
};

static bool raw_stream_on_accept_cb(
	void *data, const struct mux_session *ss, struct mux_stream *s)
{
	(void)ss;
	struct raw_stream_fixture *const sfx = data;
	sfx->accepted_stream = s;
	mux_stream_io_init(&sfx->w_stream, raw_stream_io_noop_cb, s, EV_READ);
	mux_stream_io_start(sfx->base.loop, &sfx->w_stream);
	return true;
}

static void raw_stream_on_event_cb(
	void *data, struct mux_session *ss, enum mux_event event,
	union mux_event_data edata)
{
	struct raw_stream_fixture *const sfx = data;
	switch (event) {
	case MUX_EVENT_ESTABLISHED:
		sfx->base.ev_connected_ns = edata.connected.ns;
		sfx->base.srv_established = true;
		break;
	case MUX_EVENT_CLOSED:
		sfx->base.ev_closed_clean = edata.closed.clean;
		sfx->base.ev_closed_expired = edata.closed.expired;
		sfx->base.srv_closed = true;
		sfx->base.srv = NULL;
		sfx->accepted_stream = NULL;
		mux_close(ss);
		break;
	default:
		break;
	}
}

static const struct mux_callbacks g_raw_stream_callbacks = {
	.on_accept = raw_stream_on_accept_cb,
	.on_event = raw_stream_on_event_cb,
};

static int raw_stream_fixture_setup(struct raw_stream_fixture *restrict sfx)
{
	*sfx = (struct raw_stream_fixture){ 0 };
	return raw_fixture_setup(&sfx->base, &g_raw_stream_callbacks, sfx);
}

static void raw_stream_fixture_teardown(struct raw_stream_fixture *restrict sfx)
{
	raw_fixture_teardown(&sfx->base);
}

/* Read and discard exactly one 8-byte frame header plus its payload from fd.
 * Returns false on read error. */
static bool raw_drain_frame(const int fd)
{
	struct mux_header hdr;
	if (!raw_read_frame_header(fd, &hdr)) {
		return false;
	}
	return raw_discard_payload(fd, hdr.length);
}

/* Drain all frames immediately available without blocking.  Used after
 * raw_drain_frame to consume piggybacked session ACKs so the socket
 * buffer is clean before the next raw_wait_until call. */
static bool raw_drain_available(const int fd)
{
	for (;;) {
		unsigned char peek[MUX_FRAME_HEADER_SIZE];
		const ssize_t nr =
			recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT);
		if (nr < (ssize_t)MUX_FRAME_HEADER_SIZE) {
			break;
		}
		if (!raw_drain_frame(fd)) {
			return false;
		}
	}
	return true;
}

/* I-2: undefined flags in CLOSE_WAIT.  After the client FIN the server stream
 * is CLOSE_WAIT, where only ACK is valid (spec §4.2.1); PUSH after FIN is
 * undefined and MAY draw RST with PROTOCOL_ERROR. */
T_DECLARE_CASE(test_interop_i2_close_wait_push)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		raw_stream_fixture_teardown(&sfx);
		T_FATAL("hello exchange failed");
		return;
	}

	/* Open stream 1 from the raw client side. */
	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool syn_sent = raw_send_frame(sfx.base.raw_fd, &syn_hdr);

	/* Wait for SYN|ACK from server, then drain it (including any
	 * piggybacked session-level headers packed in the same ctrl frame). */
	int raw_fd = sfx.base.raw_fd;
	const bool synack_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	const bool synack_drained = raw_drain_frame(sfx.base.raw_fd);
	const bool synack_extra_drained = raw_drain_available(sfx.base.raw_fd);

	/* Half-close: send FIN to push the server-side stream into
	 * STREAM_CLOSE_WAIT. */
	const struct mux_header fin_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_FIN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool fin_sent = raw_send_frame(sfx.base.raw_fd, &fin_hdr);

	/* Drive the event loop so the FIN is processed before sending PUSH. */
	ev_run(sfx.base.loop, EVRUN_NOWAIT);

	/* Send PUSH in STREAM_CLOSE_WAIT — invalid combination, MAY RST. */
	const struct mux_header push_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool push_sent = raw_send_frame(sfx.base.raw_fd, &push_hdr);

	/* Wait for and verify RST response. */
	const bool rst_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	struct mux_header resp = { 0 };
	const bool resp_read = raw_read_frame_header(sfx.base.raw_fd, &resp);
	const bool resp_is_rst = (resp.flags & MUX_FLAG_RST) != 0;
	const uint_least16_t resp_stream = resp.stream_id;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_stream_fixture_teardown(&sfx);

	T_EXPECT(syn_sent);
	T_EXPECT(synack_seen);
	T_EXPECT(synack_drained);
	T_EXPECT(synack_extra_drained);
	T_EXPECT(fin_sent);
	T_EXPECT(push_sent);
	T_EXPECT(rst_seen);
	T_EXPECT(resp_read);
	T_EXPECT(resp_is_rst);
	T_EXPECT_EQ(resp_stream, (uint_least16_t)1);
}

/* I-5: duplicate SYN for an existing stream.  After the SYN|ACK handshake the
 * client re-sends SYN for the same ID; the server MUST reply RST (spec §8). */
T_DECLARE_CASE(test_interop_i5_duplicate_syn)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		raw_stream_fixture_teardown(&sfx);
		T_FATAL("hello exchange failed");
		return;
	}

	/* Open stream 1 from the raw client side. */
	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool syn_sent = raw_send_frame(sfx.base.raw_fd, &syn_hdr);

	/* Wait for SYN|ACK, then drain it (including any piggybacked
	 * session-level headers packed in the same ctrl frame). */
	int raw_fd = sfx.base.raw_fd;
	const bool synack_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	const bool synack_drained = raw_drain_frame(sfx.base.raw_fd);
	const bool synack_extra_drained = raw_drain_available(sfx.base.raw_fd);

	/* Send a second SYN for the same stream ID — duplicate. */
	const bool dup_syn_sent = raw_send_frame(sfx.base.raw_fd, &syn_hdr);

	const bool rst_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	struct mux_header resp = { 0 };
	const bool resp_read = raw_read_frame_header(sfx.base.raw_fd, &resp);
	const bool resp_is_rst = (resp.flags & MUX_FLAG_RST) != 0;
	const uint_least16_t resp_stream = resp.stream_id;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_stream_fixture_teardown(&sfx);

	T_EXPECT(syn_sent);
	T_EXPECT(synack_seen);
	T_EXPECT(synack_drained);
	T_EXPECT(synack_extra_drained);
	T_EXPECT(dup_syn_sent);
	T_EXPECT(rst_seen);
	T_EXPECT(resp_read);
	T_EXPECT(resp_is_rst);
	T_EXPECT_EQ(resp_stream, (uint_least16_t)1);
}

/* I-3: ACK|FIN Extra carries a credit grant, not a status code.  A large
 * payload then half-close makes the echo server emit ACK|FIN with a credit
 * increment in Extra; treating it as a status code would stall the transfer. */
T_DECLARE_CASE(test_interop_i3_ack_fin_credit)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0xA1);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_LARGE;
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	const size_t recv_len = ts->recv_len;
	const bool got_eof = ts->got_eof;
	const bool got_error = ts->got_error;
	const bool payload_matches =
		recv_len == PAYLOAD_LARGE &&
		memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_LARGE);
	T_EXPECT(got_eof);
	T_EXPECT(!got_error);
	if (recv_len == PAYLOAD_LARGE) {
		T_EXPECT(payload_matches);
	}
}

/* I-4: stream ID parity violation.  A client SYN with an even ID (2) breaks
 * the odd-ID rule; the server MUST close the connection and MUST NOT resume
 * the session -- a per-stream RST is not enough. */
T_DECLARE_CASE(test_interop_i4_stream_id_parity)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 2, /* even — invalid for a client-side stream */
		.extra = 0,
	};
	const bool sent = raw_send_frame(fx.raw_fd, &syn_hdr);

	/* Server must close the connection on stream ID parity violation. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);

	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);
	/* CLOSED payload: a protocol-error close is neither a clean peer FIN
	 * nor a resume-timeout expiry. */
	const bool closed_clean = fx.ev_closed_clean;
	const bool closed_expired = fx.ev_closed_expired;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(sent);
	T_EXPECT(wait_ret == 0);
	T_EXPECT(nr == 0);
	T_EXPECT(!closed_clean);
	T_EXPECT(!closed_expired);
}

/* I-6, receiver direction: a raw peer opens stream 1 with a SYN|PUSH carrying
 * exactly MUX_DEFAULT_SEND_WINDOW (16384) octets -- the full implicit
 * fast-open credit, and 8 octets above the session's default max_payload
 * (16376), as a peer with a larger max_frame_size sends it.  The frame arrives
 * in two writes, so the receive ring must hold a partial oversized frame, grow
 * to complete it, and dispatch it.  The receiver must accept the stream with
 * every octet buffered, answer SYN|ACK, send no RST, and keep the session
 * open (spec App. A I-6). */
T_DECLARE_CASE(test_interop_i6_fast_open_16384_recv)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		raw_stream_fixture_teardown(&sfx);
		T_FATAL("hello exchange failed");
		return;
	}
	const bool payload_above_cap =
		sfx.base.srv->max_payload < MUX_DEFAULT_SEND_WINDOW;

	enum { I6_LEN = MUX_DEFAULT_SEND_WINDOW, I6_SPLIT = 8192 };
	unsigned char frame[MUX_FRAME_HEADER_SIZE + I6_LEN];
	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN | MUX_FLAG_PUSH,
		.length = I6_LEN,
		.stream_id = 1,
		.extra = 0,
	};
	mux_write_header(frame, &syn_hdr);
	fill_payload(frame + MUX_FRAME_HEADER_SIZE, I6_LEN, 0xC6);

	/* First half: the header plus part of the payload.  The server must
	 * buffer the partial frame without dispatching it. */
	const bool first_sent = raw_write_all(
		sfx.base.raw_fd, frame, MUX_FRAME_HEADER_SIZE + I6_SPLIT);
	for (int i = 0; i < 16; i++) {
		ev_run(sfx.base.loop, EVRUN_NOWAIT);
	}
	const bool accepted_early = sfx.accepted_stream != NULL;

	/* Second half completes the frame. */
	const bool second_sent = raw_write_all(
		sfx.base.raw_fd, frame + MUX_FRAME_HEADER_SIZE + I6_SPLIT,
		I6_LEN - I6_SPLIT);
	for (int i = 0; i < 16; i++) {
		ev_run(sfx.base.loop, EVRUN_NOWAIT);
	}

	/* The whole fast-open payload is buffered on the accepted stream. */
	struct mux_stream *const s = sfx.accepted_stream;
	const size_t buffered =
		s != NULL ? bytebuf_readable(s->recvbuf) : (size_t)0;
	unsigned char got[I6_LEN];
	size_t got_len = sizeof(got);
	const bool recv_ok =
		s != NULL && mux_stream_recv(s, got, &got_len) == 0;
	const bool payload_matches =
		recv_ok && got_len == I6_LEN &&
		memcmp(got, frame + MUX_FRAME_HEADER_SIZE, I6_LEN) == 0;

	/* Wire replies: a SYN|ACK for stream 1 and no RST on any stream
	 * (session-level ACKs on stream 0 may accompany it). */
	int raw_fd = sfx.base.raw_fd;
	const bool reply_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	bool synack_seen = false;
	bool rst_seen = false;
	bool frames_ok = true;
	for (int i = 0; i < 16 && raw_pred_data_available(&raw_fd) > 0; i++) {
		struct mux_header hdr;
		if (!raw_read_frame_header(sfx.base.raw_fd, &hdr) ||
		    !raw_discard_payload(sfx.base.raw_fd, hdr.length)) {
			frames_ok = false;
			break;
		}
		if ((hdr.flags & MUX_FLAG_RST) != 0) {
			rst_seen = true;
		}
		if (hdr.stream_id == 1 &&
		    (hdr.flags & (MUX_FLAG_SYN | MUX_FLAG_ACK)) ==
			    (MUX_FLAG_SYN | MUX_FLAG_ACK)) {
			synack_seen = true;
		}
	}
	const bool srv_closed = sfx.base.srv_closed;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_stream_fixture_teardown(&sfx);

	T_EXPECT(payload_above_cap);
	T_EXPECT(first_sent);
	T_EXPECT(!accepted_early);
	T_EXPECT(second_sent);
	T_EXPECT(s != NULL);
	T_EXPECT_EQ(buffered, (size_t)I6_LEN);
	T_EXPECT(recv_ok);
	T_EXPECT_EQ(got_len, (size_t)I6_LEN);
	T_EXPECT(payload_matches);
	T_EXPECT(reply_seen);
	T_EXPECT(frames_ok);
	T_EXPECT(synack_seen);
	T_EXPECT(!rst_seen);
	T_EXPECT(!srv_closed);
}

/* I-6, sender direction: with the frame payload cap raised to the full initial
 * window, an active opener that queues MUX_DEFAULT_SEND_WINDOW (16384) bytes
 * before the loop runs must emit exactly one SYN|PUSH of 16384 octets -- not a
 * max_frame_payload-split 16376+8.  Observed on the wire via the raw peer, not
 * merely inferred from an echo round-trip. */
T_DECLARE_CASE(test_interop_i6_fast_open_16384_send)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	/* Raise the frame payload cap to the full initial window so the queued
	 * 16384 octets fit a single frame; the default 16376 would split them. */
	fx.srv->max_payload = MUX_DEFAULT_SEND_WINDOW;

	struct mux_stream *s = mux_stream_open(fx.srv);
	if (s == NULL) {
		raw_fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}

	unsigned char payload[MUX_DEFAULT_SEND_WINDOW];
	fill_payload(payload, sizeof(payload), 0xB2);
	/* Queue the full credit window before the loop runs: the scheduler must
	 * fold SYN|PUSH and every octet into one frame. */
	size_t len = sizeof(payload);
	const bool queued = mux_stream_send(s, payload, &len) == 0 &&
			    len == sizeof(payload);

	/* Flush the queued SYN|PUSH onto the wire (16 KiB fits the socketpair
	 * send buffer in one write), then read it back from the raw side. */
	for (int i = 0; i < 16; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}

	int raw_fd = fx.raw_fd;
	struct mux_header syn = { 0 };
	bool syn_read = false;
	bool payload_drained = false;
	/* Skip any piggybacked session-level control frames (stream 0) and stop
	 * at the stream's opening SYN. */
	for (int i = 0; i < 8 && raw_pred_data_available(&raw_fd) > 0; i++) {
		struct mux_header hdr;
		if (!raw_read_frame_header(fx.raw_fd, &hdr)) {
			break;
		}
		if ((hdr.flags & MUX_FLAG_SYN) != 0) {
			syn = hdr;
			syn_read = true;
			payload_drained =
				raw_discard_payload(fx.raw_fd, hdr.length);
			break;
		}
		if (!raw_discard_payload(fx.raw_fd, hdr.length)) {
			break;
		}
	}
	const uint_least8_t syn_flags = syn.flags;
	const uint_least16_t syn_len = syn.length;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(queued);
	T_EXPECT(syn_read);
	T_EXPECT((syn_flags & MUX_FLAG_SYN) != 0);
	T_EXPECT((syn_flags & MUX_FLAG_PUSH) != 0);
	/* The whole 16384-octet payload rode one SYN|PUSH, not a split 16376. */
	T_EXPECT_EQ(syn_len, (uint_least16_t)MUX_DEFAULT_SEND_WINDOW);
	T_EXPECT(payload_drained);
}

/* I-7: out-of-order FIN then data.  After the client FIN the server stream is
 * CLOSE_WAIT; a later PUSH there is undefined and draws RST. */
T_DECLARE_CASE(test_interop_i7_fin_then_data)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		raw_stream_fixture_teardown(&sfx);
		T_FATAL("hello exchange failed");
		return;
	}

	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool syn_sent = raw_send_frame(sfx.base.raw_fd, &syn_hdr);

	int raw_fd = sfx.base.raw_fd;
	const bool synack_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	const bool synack_drained = raw_drain_frame(sfx.base.raw_fd);
	const bool synack_extra_drained = raw_drain_available(sfx.base.raw_fd);

	const struct mux_header fin_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_FIN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool fin_sent = raw_send_frame(sfx.base.raw_fd, &fin_hdr);

	ev_run(sfx.base.loop, EVRUN_NOWAIT);

	static const unsigned char payload[] = { 0x7A };
	const struct mux_header push_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = 1,
		.extra = 0,
	};
	const bool push_sent =
		raw_send_frame_payload(sfx.base.raw_fd, &push_hdr, payload);

	const bool rst_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	struct mux_header resp = { 0 };
	const bool resp_read = raw_read_frame_header(sfx.base.raw_fd, &resp);
	const bool resp_is_rst = (resp.flags & MUX_FLAG_RST) != 0;
	const uint_least16_t resp_stream = resp.stream_id;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_stream_fixture_teardown(&sfx);

	T_EXPECT(syn_sent);
	T_EXPECT(synack_seen);
	T_EXPECT(synack_drained);
	T_EXPECT(synack_extra_drained);
	T_EXPECT(fin_sent);
	T_EXPECT(push_sent);
	T_EXPECT(rst_seen);
	T_EXPECT(resp_read);
	T_EXPECT(resp_is_rst);
	T_EXPECT_EQ(resp_stream, (uint_least16_t)1);
}

/* I-8: out-of-order RST.  After the client RSTs an established stream the
 * server closes it; a later non-RST frame on that retired ID draws one RST
 * while the session stays open. */
T_DECLARE_CASE(test_interop_i8_rst_then_non_rst)
{
	struct raw_stream_fixture sfx;
	if (raw_stream_fixture_setup(&sfx) != 0) {
		T_FATAL("raw_stream_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&sfx.base)) {
		raw_stream_fixture_teardown(&sfx);
		T_FATAL("hello exchange failed");
		return;
	}

	const struct mux_header syn_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_SYN,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool syn_sent = raw_send_frame(sfx.base.raw_fd, &syn_hdr);

	int raw_fd = sfx.base.raw_fd;
	const bool synack_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	const bool synack_drained = raw_drain_frame(sfx.base.raw_fd);
	const bool synack_extra_drained = raw_drain_available(sfx.base.raw_fd);

	const struct mux_header rst_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_RST,
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool rst_sent = raw_send_frame(sfx.base.raw_fd, &rst_hdr);

	/* Deterministically process the RST instead of passing by a timeout:
	 * run the server loop until it makes no further progress. */
	for (int i = 0; i < 16; i++) {
		ev_run(sfx.base.loop, EVRUN_NOWAIT);
	}
	/* The server retires the stream but sends no proactive stream-level
	 * reply to the RST; only session-level ACKs may appear. */
	const bool acks_drained = raw_drain_available(sfx.base.raw_fd);
	const bool no_reply_after_rst = raw_pred_data_available(&raw_fd) == 0;
	const bool srv_open_after_rst = !sfx.base.srv_closed;

	static const unsigned char payload[] = { 0x52 };
	const struct mux_header push_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = 1,
		.extra = 0,
	};
	const bool push_sent =
		raw_send_frame_payload(sfx.base.raw_fd, &push_hdr, payload);

	const bool rst_reply_seen =
		raw_wait_until(
			&sfx.base, 1.0, raw_pred_data_available, &raw_fd) == 0;
	struct mux_header resp = { 0 };
	const bool rst_reply_read =
		raw_read_frame_header(sfx.base.raw_fd, &resp);
	const bool rst_reply_is_rst = (resp.flags & MUX_FLAG_RST) != 0;
	const uint_least16_t rst_reply_stream = resp.stream_id;
	const bool post_reply_drained = raw_drain_available(sfx.base.raw_fd);

	/* Again deterministic, not timeout-gated: the session must survive the
	 * non-RST frame on the retired id. */
	for (int i = 0; i < 16; i++) {
		ev_run(sfx.base.loop, EVRUN_NOWAIT);
	}
	const bool srv_open_after_reply = !sfx.base.srv_closed;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_stream_fixture_teardown(&sfx);

	T_EXPECT(syn_sent);
	T_EXPECT(synack_seen);
	T_EXPECT(synack_drained);
	T_EXPECT(synack_extra_drained);
	T_EXPECT(rst_sent);
	T_EXPECT(acks_drained);
	T_EXPECT(no_reply_after_rst);
	T_EXPECT(srv_open_after_rst);
	T_EXPECT(push_sent);
	T_EXPECT(rst_reply_seen);
	T_EXPECT(rst_reply_read);
	T_EXPECT(rst_reply_is_rst);
	T_EXPECT_EQ(rst_reply_stream, (uint_least16_t)1);
	T_EXPECT(post_reply_drained);
	T_EXPECT(srv_open_after_reply);
}

/* I-9: Reserved flag bit set — receiver MUST close the connection.
 * The raw side sends a frame with reserved bit 0x20 after handshake;
 * the server MUST close (not just RST). */
T_DECLARE_CASE(test_interop_i9_reserved_flag)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	const struct mux_header bad_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0x20, /* reserved bit */
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool bad_sent = raw_send_frame(fx.raw_fd, &bad_hdr);

	/* Drive the loop until the server closes its side of the connection. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);

	/* Connection must be closed; next blocking recv returns EOF. */
	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(bad_sent);
	T_EXPECT(wait_ret == 0);
	T_EXPECT(nr == 0);
}

/* I-10: Hello version parameter mismatch — server MUST close the connection.
 * The raw side sends a ClientHello with version=2; the server MUST close
 * upon detecting the mismatch. */
T_DECLARE_CASE(test_interop_i10_hello_version_mismatch)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}

	static const char bad_json[] =
		"{\"type\":\"application/x-multiplexd-proto; version=2\","
		"\"msgid\":0,\"connect\":false}";
	const size_t json_len = sizeof(bad_json) - 1;
	const struct mux_header bad_hdr = {
		.version = 0,
		.flags = 0,
		.length = (uint_least16_t)json_len,
		.stream_id = 0,
		.extra = 0,
	};
	unsigned char hdr_buf[MUX_FRAME_HEADER_SIZE];
	mux_write_header(hdr_buf, &bad_hdr);
	const bool hdr_written =
		raw_write_all(fx.raw_fd, hdr_buf, sizeof(hdr_buf));
	const bool json_written = raw_write_all(fx.raw_fd, bad_json, json_len);

	/* Server must close the connection on version mismatch. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);

	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(hdr_written);
	T_EXPECT(json_written);
	T_EXPECT(wait_ret == 0);
	T_EXPECT(nr == 0);
}

/* I-11: PING/PONG echo.  The raw side sends a stream-0 PING with an
 * opaque payload; the server MUST reply with a PONG whose payload is
 * byte-for-byte identical. */
T_DECLARE_CASE(test_interop_i11_ping_pong_echo)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	static const unsigned char ping_payload[] = {
		0x10, 0x22, 0x34, 0x46, 0x58,
	};
	const struct mux_header ping_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(ping_payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};
	const bool ping_sent =
		raw_send_frame_payload(fx.raw_fd, &ping_hdr, ping_payload);

	int raw_fd = fx.raw_fd;
	const bool pong_seen =
		raw_wait_until(&fx, 1.0, raw_pred_data_available, &raw_fd) == 0;

	struct mux_header resp = { 0 };
	const bool pong_read = raw_read_frame_header(fx.raw_fd, &resp);
	const uint_least8_t pong_version = resp.version;
	const uint_least8_t pong_flags = resp.flags;
	const uint_least16_t pong_stream = resp.stream_id;
	const uint_least16_t pong_extra = resp.extra;
	const uint_least16_t pong_len = resp.length;
	unsigned char pong_payload[sizeof(ping_payload)];
	const bool pong_body_read =
		raw_read_all(fx.raw_fd, pong_payload, sizeof(pong_payload));
	const bool pong_matches =
		pong_body_read &&
		memcmp(pong_payload, ping_payload, sizeof(ping_payload)) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(ping_sent);
	T_EXPECT(pong_seen);
	T_EXPECT(pong_read);
	T_EXPECT_EQ(pong_version, (uint_fast8_t)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(pong_flags, (uint_fast8_t)0);
	T_EXPECT_EQ(pong_stream, (uint_least16_t)STREAMID_CTRL);
	T_EXPECT_EQ(pong_extra, (uint_least16_t)MUX_CTRL_PONG);
	T_EXPECT_EQ(pong_len, (uint_least16_t)sizeof(ping_payload));
	T_EXPECT(pong_body_read);
	T_EXPECT(pong_matches);
}

/* I-12: unknown keepalive subtype.  A reserved stream-0 subtype is silently
 * discarded; sent before a valid PING, the first response is that PING's PONG. */
T_DECLARE_CASE(test_interop_i12_unknown_keepalive_subtype)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	const struct mux_header unknown_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = 0,
		.stream_id = STREAMID_CTRL,
		.extra = 0x0003u,
	};
	const bool unknown_sent = raw_send_frame(fx.raw_fd, &unknown_hdr);

	/* The reserved subtype must be silently discarded, so drive the loop to
	 * quiescence and assert the negative directly instead of timing out. */
	for (int i = 0; i < 16; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}
	int raw_fd = fx.raw_fd;
	const bool no_reply_to_unknown = raw_pred_data_available(&raw_fd) == 0;
	const bool srv_open_after_unknown = !fx.srv_closed;

	static const unsigned char ping_payload[] = {
		0x91, 0x82, 0x73, 0x64, 0x55,
	};
	const struct mux_header ping_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(ping_payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};
	const bool ping_sent =
		raw_send_frame_payload(fx.raw_fd, &ping_hdr, ping_payload);

	const bool pong_seen =
		raw_wait_until(&fx, 1.0, raw_pred_data_available, &raw_fd) == 0;
	struct mux_header resp = { 0 };
	const bool pong_read = raw_read_frame_header(fx.raw_fd, &resp);
	const uint_least8_t pong_version = resp.version;
	const uint_least8_t pong_flags = resp.flags;
	const uint_least16_t pong_stream = resp.stream_id;
	const uint_least16_t pong_extra = resp.extra;
	const uint_least16_t pong_len = resp.length;
	unsigned char pong_payload[sizeof(ping_payload)];
	const bool pong_body_read =
		raw_read_all(fx.raw_fd, pong_payload, sizeof(pong_payload));
	const bool pong_matches =
		pong_body_read &&
		memcmp(pong_payload, ping_payload, sizeof(ping_payload)) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(unknown_sent);
	T_EXPECT(no_reply_to_unknown);
	T_EXPECT(srv_open_after_unknown);
	T_EXPECT(ping_sent);
	T_EXPECT(pong_seen);
	T_EXPECT(pong_read);
	T_EXPECT_EQ(pong_version, (uint_fast8_t)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(pong_flags, (uint_fast8_t)0);
	T_EXPECT_EQ(pong_stream, (uint_least16_t)STREAMID_CTRL);
	T_EXPECT_EQ(pong_extra, (uint_least16_t)MUX_CTRL_PONG);
	T_EXPECT_EQ(pong_len, (uint_least16_t)sizeof(ping_payload));
	T_EXPECT(pong_body_read);
	T_EXPECT(pong_matches);
}

/* I-13: invalid opening SYN flags.  SYN|ACK as the first frame for an unknown
 * stream is a violation (only SYN/SYN|PUSH open); the server MUST close the
 * connection and MUST NOT resume. */
T_DECLARE_CASE(test_interop_i13_invalid_syn_flags)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	const struct mux_header bad_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags =
			MUX_FLAG_SYN | MUX_FLAG_ACK, /* invalid opening flags */
		.length = 0,
		.stream_id = 1,
		.extra = 0,
	};
	const bool bad_sent = raw_send_frame(fx.raw_fd, &bad_hdr);

	/* Server must close the connection, not reply with RST. */
	const int wait_ret = raw_wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, raw_pred_closed, &fx);

	unsigned char dummy;
	const ssize_t nr = recv(fx.raw_fd, &dummy, 1, 0);

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(bad_sent);
	T_EXPECT(wait_ret == 0);
	T_EXPECT(nr == 0);
}

/* I-14: reserved stream-0 frame type (spec §4.1).  A stream-0 frame
 * with non-zero non-ACK flags MUST be silently discarded; a subsequent
 * PING confirms the session survived and drew no reply. */
T_DECLARE_CASE(test_interop_i14_reserved_stream0_frame)
{
	struct raw_fixture fx;
	if (raw_fixture_setup(&fx, &g_raw_callbacks, &fx) != 0) {
		T_FATAL("raw_fixture_setup failed");
		return;
	}
	if (!raw_do_hello(&fx)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}

	/* PUSH on stream 0: non-zero, non-ACK flags -> reserved frame type. */
	static const unsigned char reserved_payload[] = {
		0xDE,
		0xAD,
		0xBE,
		0xEF,
	};
	const struct mux_header reserved_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = MUX_FLAG_PUSH,
		.length = (uint_least16_t)sizeof(reserved_payload),
		.stream_id = STREAMID_CTRL,
		.extra = 0,
	};
	const bool reserved_sent = raw_send_frame_payload(
		fx.raw_fd, &reserved_hdr, reserved_payload);

	/* The reserved stream-0 frame must be silently discarded, so drive the
	 * loop to quiescence and assert the negative directly, not by timeout. */
	for (int i = 0; i < 16; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}
	int raw_fd = fx.raw_fd;
	const bool no_reply_to_reserved = raw_pred_data_available(&raw_fd) == 0;
	const bool srv_open_after_reserved = !fx.srv_closed;

	/* The session must still answer a valid PING with a matching PONG. */
	static const unsigned char ping_payload[] = {
		0xA5, 0xB6, 0xC7, 0xD8, 0xE9,
	};
	const struct mux_header ping_hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(ping_payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PING,
	};
	const bool ping_sent =
		raw_send_frame_payload(fx.raw_fd, &ping_hdr, ping_payload);

	const bool pong_seen =
		raw_wait_until(&fx, 1.0, raw_pred_data_available, &raw_fd) == 0;
	struct mux_header resp = { 0 };
	const bool pong_read = raw_read_frame_header(fx.raw_fd, &resp);
	const uint_least8_t pong_version = resp.version;
	const uint_least8_t pong_flags = resp.flags;
	const uint_least16_t pong_stream = resp.stream_id;
	const uint_least16_t pong_extra = resp.extra;
	const uint_least16_t pong_len = resp.length;
	unsigned char pong_payload[sizeof(ping_payload)];
	const bool pong_body_read =
		raw_read_all(fx.raw_fd, pong_payload, sizeof(pong_payload));
	const bool pong_matches =
		pong_body_read &&
		memcmp(pong_payload, ping_payload, sizeof(ping_payload)) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	raw_fixture_teardown(&fx);

	T_EXPECT(reserved_sent);
	T_EXPECT(no_reply_to_reserved);
	T_EXPECT(srv_open_after_reserved);
	T_EXPECT(ping_sent);
	T_EXPECT(pong_seen);
	T_EXPECT(pong_read);
	T_EXPECT_EQ(pong_version, (uint_fast8_t)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(pong_flags, (uint_fast8_t)0);
	T_EXPECT_EQ(pong_stream, (uint_least16_t)STREAMID_CTRL);
	T_EXPECT_EQ(pong_extra, (uint_least16_t)MUX_CTRL_PONG);
	T_EXPECT_EQ(pong_len, (uint_least16_t)sizeof(ping_payload));
	T_EXPECT(pong_body_read);
	T_EXPECT(pong_matches);
}

/* lossymux (spec §5.2.3.3): what the server's datagram callbacks saw.  on_dgram
 * echoes each datagram back on its flow, which exercises the send path too. */
struct lossymux_spy {
	int dgram_calls;
	int close_calls;
	uint_least16_t last_flow;
	size_t last_len;
	bool echo_queued;
};
static struct lossymux_spy g_lossymux;

static void lossymux_echo_cb(
	void *data, struct mux_session *ss, const uint_least16_t flow,
	const unsigned char *payload, const size_t len)
{
	(void)data;
	g_lossymux.dgram_calls++;
	g_lossymux.last_flow = flow;
	g_lossymux.last_len = len;
	g_lossymux.echo_queued = mux_dgram_send(ss, flow, payload, len);
}

static void
lossymux_close_cb(void *data, struct mux_session *ss, const uint_least16_t flow)
{
	(void)data;
	(void)ss;
	g_lossymux.close_calls++;
	g_lossymux.last_flow = flow;
}

static const struct mux_callbacks g_lossymux_callbacks = {
	.on_accept = NULL,
	.on_event = raw_on_event_cb,
	.on_dgram = lossymux_echo_cb,
	.on_dgram_close = lossymux_close_cb,
};

/* Both hellos offer lossymux: a DATAGRAM reaches on_dgram, whose echo comes
 * back to the wire as a stream-0 PUSH frame on the same flow; a FLOW-CLOSE
 * reaches on_dgram_close; a DATAGRAM larger than the server's own frame
 * payload is still accepted (spec §2.3), though its echo cannot be framed and
 * is dropped. */
T_DECLARE_CASE(test_lossymux_datagram_roundtrip)
{
	struct raw_fixture fx;
	if (raw_fixture_setup_ex(&fx, &g_lossymux_callbacks, &fx, true) != 0) {
		T_FATAL("raw_fixture_setup_ex failed");
		return;
	}
	g_lossymux = (struct lossymux_spy){ 0 };
	if (!raw_do_hello_ex(&fx, true)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}
	const bool ready = mux_dgram_ready(fx.srv);

	static const unsigned char payload[] = { 'p', 'i', 'n', 'g', '!' };
	const bool sent = raw_send_frame_payload(
		fx.raw_fd,
		&(struct mux_header){
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_PUSH,
			.length = (uint_least16_t)sizeof(payload),
			.stream_id = STREAMID_CTRL,
			.extra = 7,
		},
		payload);
	int raw_fd = fx.raw_fd;
	const bool echo_seen =
		raw_wait_until(&fx, 1.0, raw_pred_data_available, &raw_fd) == 0;
	struct mux_header echo = { 0 };
	const bool echo_read = raw_read_frame_header(fx.raw_fd, &echo);
	unsigned char echo_payload[sizeof(payload)] = { 0 };
	const bool echo_body_read =
		echo_read && echo.length == sizeof(payload) &&
		raw_read_all(fx.raw_fd, echo_payload, sizeof(echo_payload));
	const int dgram_calls = g_lossymux.dgram_calls;
	const uint_least16_t dgram_flow = g_lossymux.last_flow;

	const bool close_sent = raw_send_frame_payload(
		fx.raw_fd,
		&(struct mux_header){
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_FIN,
			.stream_id = STREAMID_CTRL,
			.extra = 9,
		},
		NULL);
	/* Larger than the server's frame payload: received, echo dropped. */
	const size_t big_len = mux_session_config_default.max_frame_payload + 1;
	unsigned char *const big = calloc(1, big_len);
	T_CHECK(big != NULL);
	const bool big_sent = raw_send_frame_payload(
		fx.raw_fd,
		&(struct mux_header){
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_PUSH,
			.length = (uint_least16_t)big_len,
			.stream_id = STREAMID_CTRL,
			.extra = 11,
		},
		big);
	free(big);
	for (int i = 0; i < 16; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}
	const int close_calls = g_lossymux.close_calls;
	const int dgram_calls_after = g_lossymux.dgram_calls;
	const size_t big_seen_len = g_lossymux.last_len;
	const bool big_echo_queued = g_lossymux.echo_queued;
	const bool no_big_echo = raw_pred_data_available(&raw_fd) == 0;
	const bool open = !fx.srv_closed;

	raw_fixture_teardown(&fx);

	T_EXPECT(ready);
	T_EXPECT(sent);
	T_EXPECT(echo_seen);
	T_EXPECT(echo_read);
	T_EXPECT_EQ(echo.version, (uint_least8_t)MUX_PROTOCOL_VERSION);
	T_EXPECT_EQ(echo.flags, (uint_least8_t)MUX_FLAG_PUSH);
	T_EXPECT_EQ(echo.stream_id, (uint_least16_t)STREAMID_CTRL);
	T_EXPECT_EQ(echo.extra, (uint_least16_t)7);
	T_EXPECT(echo_body_read);
	T_EXPECT(memcmp(echo_payload, payload, sizeof(payload)) == 0);
	T_EXPECT_EQ(dgram_calls, 1);
	T_EXPECT_EQ(dgram_flow, (uint_least16_t)7);
	T_EXPECT(close_sent);
	T_EXPECT(big_sent);
	T_EXPECT_EQ(close_calls, 1);
	T_EXPECT_EQ(dgram_calls_after, 2);
	T_EXPECT_EQ(big_seen_len, big_len);
	T_EXPECT(!big_echo_queued);
	T_EXPECT(no_big_echo);
	T_EXPECT(open);
}

/* lossymux is bilateral (spec §5.2.2): the server offers it but the client
 * does not, so it stays inactive -- a DATAGRAM is a reserved stream-0 frame,
 * silently discarded (I-14), and the server cannot send one. */
T_DECLARE_CASE(test_lossymux_inactive_unless_both_offer)
{
	struct raw_fixture fx;
	if (raw_fixture_setup_ex(&fx, &g_lossymux_callbacks, &fx, true) != 0) {
		T_FATAL("raw_fixture_setup_ex failed");
		return;
	}
	g_lossymux = (struct lossymux_spy){ 0 };
	if (!raw_do_hello_ex(&fx, false)) {
		raw_fixture_teardown(&fx);
		T_FATAL("hello exchange failed");
		return;
	}
	const bool ready = mux_dgram_ready(fx.srv);
	const bool srv_sent = mux_dgram_send(fx.srv, 2, "x", 1);
	static const unsigned char payload[] = { 1, 2, 3 };
	const bool sent = raw_send_frame_payload(
		fx.raw_fd,
		&(struct mux_header){
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_PUSH,
			.length = (uint_least16_t)sizeof(payload),
			.stream_id = STREAMID_CTRL,
			.extra = 7,
		},
		payload);
	for (int i = 0; i < 16; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}
	int raw_fd = fx.raw_fd;
	const bool no_reply = raw_pred_data_available(&raw_fd) == 0;
	const int dgram_calls = g_lossymux.dgram_calls;
	const bool open = !fx.srv_closed;

	raw_fixture_teardown(&fx);

	T_EXPECT(!ready);
	T_EXPECT(!srv_sent);
	T_EXPECT(sent);
	T_EXPECT(no_reply);
	T_EXPECT_EQ(dgram_calls, 0);
	T_EXPECT(open);
}

/* An unexpected transport loss suspends a resumable client session whether or
 * not idle_timeout is configured: the mux layer only suspends, and whether (and
 * when) to redial is the owner's call.  The fixture's own SUSPENDED handler
 * redials, so this case disables it to observe the session as the mux layer
 * leaves it.  The idle timer runs at its configured period, so the CLOSED it
 * would produce cannot stand in for the suspend asserted here. */

T_DECLARE_CASE(test_transport_loss_suspends_with_idle_timeout)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	struct mux_session_config conf = make_cli_conf(fx.nodelay);
	conf.idle_timeout = 30;
	mux_set_config(fx.cli, &conf);
	/* Leave the redial to the owner, i.e. to nobody here. */
	fx.connect_str[0] = '\0';

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}
	/* The idle timer is live: an established client with no streams arms it
	 * at handshake completion. */
	const bool idle_armed = ev_is_active(&fx.cli->w_idle_timeout);

	/* Close the server session, closing the TCP connection under the client:
	 * the client reads EOF on an established, resumable session. */
	mux_close(fx.srv);
	fx.srv = NULL;

	const int ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_suspended, &fx);
	const bool cli_lost = fx.cli_lost;
	const bool cli_closed = fx.cli_closed;
	const enum mux_state cli_state =
		fx.cli != NULL ? mux_state(fx.cli) : MUX_STATE_CLOSED;
	/* Leaving ESTABLISHED stops the idle timer, so it cannot close the
	 * suspended session behind the owner's back. */
	const bool idle_stopped =
		fx.cli != NULL && !ev_is_active(&fx.cli->w_idle_timeout);

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(idle_armed);
	T_EXPECT(ret == 0);
	T_EXPECT(cli_lost);
	T_EXPECT(!cli_closed);
	T_EXPECT_EQ(cli_state, MUX_STATE_SUSPENDED);
	T_EXPECT(idle_stopped);
}

/* An idle timeout closes the session through the graceful shutdown exchange
 * (spec 5.6), not an abortive reset: the client waits in CLOSE_WAIT for the
 * peer's own close, so its MUX_EVENT_CLOSED reports a clean transport end. */
T_DECLARE_CASE(test_idle_close_is_graceful)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	/* The config is in whole seconds; shorten the armed repeat directly. */
	fx.cli->conf.idle_timeout = 1;
	fx.cli->w_idle_timeout.repeat = 0.01;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	const int ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_closed, &fx);
	/* Over plaintext the server suspends on the FIN and emits no CLOSED, so
	 * the captured payload is the client's own. */
	const bool cli_closed = fx.cli_closed;
	const bool cli_lost = fx.cli_lost;
	const bool closed_clean = fx.cli_closed_data.closed.clean;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(cli_closed);
	T_EXPECT(cli_lost);
	T_EXPECT(closed_clean);
}

T_DECLARE_CASE(test_live_reload_enables_idle_close)
{
	struct mux_test_fixture fx;
	T_CHECK(fixture_setup(&fx) == 0);
	T_CHECK(wait_until(
			&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
			&fx) == 0);
	T_CHECK(!ev_is_active(&fx.cli->w_idle_timeout));
	struct mux_session_config conf = *mux_conf(fx.cli);
	conf.idle_timeout = 5;
	mux_set_config(fx.cli, &conf);
	const bool enabled = ev_is_active(&fx.cli->w_idle_timeout);
	int closed = -1;
	if (enabled) {
		/* Deliver the real timer callback immediately; no elapsed-time wait
		 * is needed to test the close it now makes reachable. */
		ev_feed_event(fx.loop, &fx.cli->w_idle_timeout, EV_TIMER);
		closed = wait_until(
			&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_cli_closed, &fx);
	}
	const bool lost = fx.cli_lost;
	const bool clean = fx.cli_closed_data.closed.clean;
	fixture_teardown(&fx);
	T_EXPECT(enabled);
	T_EXPECT_EQ(closed, 0);
	T_EXPECT(lost && clean);
}

T_DECLARE_CASE(test_connected_callback_shutdown_keeps_timeout_stopped)
{
	struct mux_test_fixture fx;
	T_CHECK(fixture_setup(&fx) == 0);
	struct mux_callbacks callbacks = g_cli_callbacks;
	callbacks.on_event = shutdown_and_break_on_connected;
	mux_set_callbacks(fx.cli, &callbacks);
	const int established = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established, &fx);
	T_CHECK(fx.cli != NULL);
	const enum mux_state state = mux_state(fx.cli);
	const bool timeout_active = ev_is_active(&fx.cli->w_timeout);
	const bool keepalive_active = ev_is_active(&fx.cli->w_keepalive);
	fixture_teardown(&fx);
	T_EXPECT_EQ(established, 0);
	T_EXPECT_EQ(state, MUX_STATE_CLOSING);
	T_EXPECT(!timeout_active && !keepalive_active);
}

/* fx_break_transport: RST the TCP connection so both sessions suspend.
 * SO_LINGER{1,0} sends RST to the client; the server stays ESTABLISHED
 * until reconnect, when mux_resume_attach suspends it. */

static void fx_break_transport(struct mux_test_fixture *restrict fx)
{
	const int srv_fd = mux_fd(fx->srv);

	/* Sentinel socketpair: keeps srv_fd occupied so the next accept()
	 * does not reuse it and cause libev to dispatch new-connection
	 * events to fx->srv's socket watcher. */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
		return;
	}

	const struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	(void)setsockopt(srv_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

	/* dup2 atomically sends RST (SO_LINGER) and puts sp[0] in the slot.
	 * mux_resume_attach later calls mux_session_suspend which closes sp[0]
	 * cleanly — no EBADF. */
	(void)dup2(sp[0], srv_fd);
	(void)close(sp[0]);

	/* Retain sp[1] so sp[0] (= srv_fd) has a connected peer and does not
	 * immediately become readable as EOF in the event loop. */
	fx->break_transport_sp = sp[1];
}

static void test_session_set_write_only(struct mux_session *restrict ss)
{
	const int fd = ss->w_socket.fd;
	ev_io_stop(ss->loop, &ss->w_socket);
	ev_io_set(&ss->w_socket, fd, EV_WRITE);
	ev_io_start(ss->loop, &ss->w_socket);
}

static bool test_pump_unacked_no_wait(
	struct mux_test_fixture *restrict fx, const bool require_srv)
{
	test_session_set_write_only(fx->cli);
	test_session_set_write_only(fx->srv);

	/* Pump non-blocking until the client (and, when require_srv, the server)
	 * has buffered unacked frames. Each caller asserts only the side it
	 * genuinely populated: test_resume_retransmit opens a client and a server
	 * stream and needs both buffered, but test_resume_stream_unacked_retransmit
	 * opens only a client stream -- coupling it to srv->unacked.frames > 0 would
	 * spuriously fail whenever the echo server has already flushed and had its
	 * frames ACKed before both sides go write-only. The iteration bound only
	 * guards against a hang (a handful of EV_WRITE-only runs suffices). The
	 * postcondition is returned rather than asserted here: the caller captures
	 * it and asserts only after fixture_teardown, so a never-satisfied
	 * precondition fails the one case instead of aborting the binary and
	 * leaking the fixture. */
	bool ready = false;
	for (int i = 0; i < 32 && !ready; i++) {
		ev_run(fx->loop, EVRUN_NOWAIT);
		ready = fx->cli->unacked.frames > 0 &&
			(!require_srv || fx->srv->unacked.frames > 0);
	}

	mux_session_notify(fx->cli);
	mux_session_notify(fx->srv);
	return ready;
}

/* transport break with no active streams.
 * The session must suspend, reconnect, and fire MUX_EVENT_RESUMED on both
 * sides without any data loss. */

T_DECLARE_CASE(test_resume_idle)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Forget the ESTABLISHED payloads so only RESUMED can refill them. */
	fx.srv_connected = (struct connected_capture){ 0 };
	fx.cli_connected = (struct connected_capture){ 0 };
	fx_break_transport(&fx);

	const int ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	const bool cli_suspended = fx.cli_suspended;
	const bool srv_suspended = fx.srv_suspended;
	const bool cli_resumed = fx.cli_resumed;
	const bool srv_resumed = fx.srv_resumed;
	const enum mux_state cli_state = mux_state(fx.cli);
	const enum mux_state srv_state = mux_state(fx.srv);
	/* Leaving ESTABLISHED on the break emits LOST; the RESUMED payload
	 * carries the reconnect setup latency (strictly positive) and, on the
	 * server, the identity the resume hello claimed -- parsed by the
	 * transient session and carried across by the transport handoff. */
	const bool cli_lost = fx.cli_lost;
	const struct connected_capture srv_cap = fx.srv_connected;
	const struct connected_capture cli_cap = fx.cli_connected;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(cli_suspended);
	T_EXPECT(srv_suspended);
	T_EXPECT(cli_resumed);
	T_EXPECT(srv_resumed);
	T_EXPECT_EQ(cli_state, MUX_STATE_ESTABLISHED);
	T_EXPECT_EQ(srv_state, MUX_STATE_ESTABLISHED);
	T_EXPECT(cli_lost);
	T_EXPECT(srv_cap.fired);
	T_EXPECT(cli_cap.fired);
	T_EXPECT(srv_cap.ns > 0);
	T_EXPECT(cli_cap.ns > 0);
	T_EXPECT_STREQ(srv_cap.peer_identity, TEST_CLI_IDENTITY);
	T_EXPECT_STREQ(cli_cap.peer_identity, TEST_SRV_IDENTITY);
}

#if WITH_TLS
static int pred_both_closed(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	return (fx->cli_closed && fx->srv_closed) ? 1 : 0;
}

/* Open a client stream, echo @p len bytes of @p payload through the server's
 * echo stream, and report whether they came back intact.  The stream is left
 * open and owned by the fixture. */
static bool fixture_echo_roundtrip(
	struct mux_test_fixture *restrict fx,
	const unsigned char *restrict payload, const size_t len)
{
	if (fx->n_cli_streams >= MAX_ACCEPTED) {
		return false;
	}
	struct mux_stream *const s = mux_stream_open(fx->cli);
	if (s == NULL) {
		return false;
	}
	struct test_stream *const ts = test_stream_new(fx, s);
	if (ts == NULL) {
		mux_stream_close(s);
		return false;
	}
	fx->cli_streams[fx->n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = len;
	mux_stream_io_start(fx->loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = len,
	};
	if (wait_until(fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx) !=
	    0) {
		return false;
	}
	return ts->recv_len == len && memcmp(ts->recv_buf, payload, len) == 0;
}

/* A mux session pair over TLS, end to end: the handshake establishes both
 * sides on a TLS connection (mux_tls_conn), a payload larger than one record
 * round-trips, a transport break resumes onto the fresh TLS connection the
 * resume hello arrived on (mux_transport.tlsconn), which then carries traffic
 * too, and mux_shutdown() closes the transport with close_notify.  Run once
 * with the library owning the socket and once over wire.c's memory
 * transport. */
T_DECLARE_SUBCASE(tls_session_lifecycle, const enum fixture_transport transport)
{
	struct mux_test_fixture fx;
	if (fixture_setup_transport(&fx, transport) != 0) {
		T_FATAL("fixture_setup_transport failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}
	unsigned char *const payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x5E);

	const bool srv_tls = mux_tls_conn(fx.srv) != NULL;
	const bool cli_tls = mux_tls_conn(fx.cli) != NULL;
	const bool offload_srv = mux_conf(fx.srv)->tls_socket_offload;
	const bool offload_cli = mux_conf(fx.cli)->tls_socket_offload;
	const bool echo_ok =
		fixture_echo_roundtrip(&fx, payload, PAYLOAD_LARGE);

	fx_break_transport(&fx);
	const int resume_ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	const bool srv_tls_resumed =
		resume_ret == 0 && mux_tls_conn(fx.srv) != NULL;
	const bool cli_tls_resumed =
		resume_ret == 0 && mux_tls_conn(fx.cli) != NULL;
	const bool resumed_echo_ok =
		resume_ret == 0 &&
		fixture_echo_roundtrip(&fx, payload, PAYLOAD_SMALL);

	/* close_notify is a deliberate close, not a lost transport: the server
	 * answers with its own instead of suspending, and each side reports the
	 * other's close_notify as a clean CLOSED. */
	mux_shutdown(fx.cli);
	const int close_ret = wait_until(
		&fx, CLOSE_TIMEOUT_MS / 1000.0, pred_both_closed, &fx);
	const union mux_event_data srv_closed = fx.srv_closed_data;
	const union mux_event_data cli_closed = fx.cli_closed_data;

	/* Teardown first so a failing assert can't leak the fixture. */
	free(payload);
	fixture_teardown(&fx);

	T_EXPECT(srv_tls);
	T_EXPECT(cli_tls);
	T_EXPECT_EQ(offload_srv, transport == FIXTURE_TLS_OFFLOAD);
	T_EXPECT_EQ(offload_cli, transport == FIXTURE_TLS_OFFLOAD);
	T_EXPECT(echo_ok);
	T_EXPECT(resume_ret == 0);
	T_EXPECT(srv_tls_resumed);
	T_EXPECT(cli_tls_resumed);
	T_EXPECT(resumed_echo_ok);
	T_EXPECT(close_ret == 0);
	T_EXPECT(srv_closed.closed.clean);
	T_EXPECT(cli_closed.closed.clean);
	T_EXPECT(!srv_closed.closed.expired);
	T_EXPECT(!cli_closed.closed.expired);
	T_EXPECT_EQ(srv_closed.closed.err, 0);
	T_EXPECT_EQ(cli_closed.closed.err, 0);
}
#endif /* WITH_TLS */

T_DECLARE_CASE(test_tls_session_memory_transport)
{
#if WITH_TLS
	T_CALL_SUBCASE(tls_session_lifecycle, FIXTURE_TLS_MEMORY);
#else
	T_SKIPNOW();
#endif
}

T_DECLARE_CASE(test_tls_session_socket_offload)
{
#if WITH_TLS
	T_CALL_SUBCASE(tls_session_lifecycle, FIXTURE_TLS_OFFLOAD);
#else
	T_SKIPNOW();
#endif
}

/* Regression: a drain requested by a config reload must survive a transport
 * break + resume.  session_resume_attach() cleared ss->draining
 * unconditionally, so a resumed server session silently accepted new streams
 * again and kept running on stale pre-reload settings -- unlike the client
 * reconnect path (mux_session_attach_fd), which preserves draining across a
 * resume.  An open server stream keeps the session non-idle so mux_drain() does
 * not shut it down; drain it, then break the transport and let the client
 * reconnect and resume. */
T_DECLARE_CASE(test_resume_preserves_drain)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	struct mux_stream *const s = mux_stream_open(fx.srv);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(srv) returned NULL");
		return;
	}
	struct test_stream *const ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	if (fx.n_srv_active_streams < MAX_ACCEPTED) {
		fx.srv_active_streams[fx.n_srv_active_streams++] = ts;
	}
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Request a graceful drain on the server, then lose its transport and
	 * let the client reconnect + resume. */
	mux_drain(fx.srv);
	const bool draining_before = fx.srv->draining;

	fx_break_transport(&fx);
	const int ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	const bool srv_resumed = fx.srv_resumed;
	const bool draining_after = fx.srv->draining;
	const enum mux_state srv_state = mux_state(fx.srv);

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(draining_before); /* mux_drain took effect */
	T_EXPECT(srv_resumed); /* the server actually resumed */
	T_EXPECT_EQ(srv_state, MUX_STATE_ESTABLISHED);
	/* The drain must survive the resume, not be silently cancelled. */
	T_EXPECT(draining_after);
}

/* The client-side twin of the case above: a client that redials from
 * SESSION_SUSPENDED (mux_attach_fd on the SUSPENDED event) resumes, and its
 * pending drain survives that reattach -- it keeps rejecting new streams.  An
 * open client stream keeps the session non-idle so mux_drain() does not shut
 * it down. */
T_DECLARE_CASE(test_resume_preserves_client_drain)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	struct mux_stream *const s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(cli) returned NULL");
		return;
	}
	struct test_stream *const ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Request a graceful drain on the client, then lose its transport; the
	 * fixture's SUSPENDED handler redials and the session resumes. */
	mux_drain(fx.cli);
	const bool draining_before = fx.cli->draining;

	fx_break_transport(&fx);
	const int ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	const bool cli_suspended = fx.cli_suspended;
	const bool cli_resumed = fx.cli_resumed;
	if (fx.cli == NULL) {
		fixture_teardown(&fx);
		T_FATAL("client session closed instead of resuming");
		return;
	}
	const enum mux_state cli_state = mux_state(fx.cli);
	const bool draining_after = fx.cli->draining;
	/* Still draining after the resume: a new stream is refused. */
	const bool open_refused = mux_stream_open(fx.cli) == NULL;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(draining_before); /* mux_drain took effect */
	T_EXPECT(cli_suspended); /* the reattach was from SUSPENDED */
	T_EXPECT(cli_resumed);
	T_EXPECT_EQ(cli_state, MUX_STATE_ESTABLISHED);
	T_EXPECT(draining_after);
	T_EXPECT(open_refused);
}

/* transport break with a stream in flight.
 * Frames unacknowledged at suspension must be retransmitted after resume
 * and the echo must complete with exactly the original payload. */

T_DECLARE_CASE(test_resume_retransmit)
{
	struct mux_test_fixture fx;
	const size_t payload_len = PAYLOAD_SMALL;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	unsigned char *cli_payload = NULL;
	unsigned char *srv_payload = NULL;
	struct test_stream *cli_ts = NULL;
	struct test_stream *srv_ts = NULL;
	size_t cli_sent = 0;
	size_t srv_sent = 0;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		free(cli_payload);
		free(srv_payload);
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	cli_payload = malloc(payload_len);
	if (cli_payload == NULL) {
		free(cli_payload);
		free(srv_payload);
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(cli_payload, payload_len, 0x7B);

	srv_payload = malloc(payload_len);
	if (srv_payload == NULL) {
		free(cli_payload);
		free(srv_payload);
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(srv_payload, payload_len, 0x9C);

	{
		struct mux_stream *cli_s = mux_stream_open(fx.cli);
		if (cli_s == NULL) {
			free(cli_payload);
			free(srv_payload);
			fixture_teardown(&fx);
			T_FATAL("mux_stream_open returned NULL");
			return;
		}
		cli_ts = test_stream_new(&fx, cli_s);
		if (cli_ts == NULL) {
			free(cli_payload);
			free(srv_payload);
			fixture_teardown(&fx);
			T_FATAL("test_stream_new failed");
			return;
		}
		if (fx.n_cli_streams < MAX_ACCEPTED) {
			fx.cli_streams[fx.n_cli_streams++] = cli_ts;
		}

		struct mux_stream *srv_s = mux_stream_open(fx.srv);
		if (srv_s == NULL) {
			free(cli_payload);
			free(srv_payload);
			fixture_teardown(&fx);
			T_FATAL("mux_stream_open(srv) returned NULL");
			return;
		}
		srv_ts = test_stream_new(&fx, srv_s);
		if (srv_ts == NULL) {
			free(cli_payload);
			free(srv_payload);
			fixture_teardown(&fx);
			T_FATAL("test_stream_new failed");
			return;
		}
		if (fx.n_srv_active_streams < MAX_ACCEPTED) {
			fx.srv_active_streams[fx.n_srv_active_streams++] =
				srv_ts;
		}
	}

	/* Pre-break load injection (no waits): queue data from both endpoints.
	 * Stop naturally when flow control returns zero progress. */
	for (;;) {
		size_t chunk = payload_len - cli_sent;
		if (chunk == 0) {
			break;
		}
		if (mux_stream_send(cli_ts->s, cli_payload + cli_sent, &chunk) <
			    0 ||
		    chunk == 0) {
			break;
		}
		cli_sent += chunk;
	}
	for (;;) {
		size_t chunk = payload_len - srv_sent;
		if (chunk == 0) {
			break;
		}
		if (mux_stream_send(srv_ts->s, srv_payload + srv_sent, &chunk) <
			    0 ||
		    chunk == 0) {
			break;
		}
		srv_sent += chunk;
	}
	/* Invariants are captured here and asserted only after teardown, so a
	 * failing check cannot longjmp past fixture_teardown and leak the fixture
	 * (and the payload buffers). */
	const bool cli_sent_nonzero = cli_sent > 0;
	const bool srv_sent_nonzero = srv_sent > 0;

	mux_stream_io_start(fx.loop, &cli_ts->w_io);
	mux_stream_io_start(fx.loop, &srv_ts->w_io);
	/* Both a client and a server stream are open, so both sides must buffer. */
	const bool unacked_pre = test_pump_unacked_no_wait(&fx, true);
	T_LOGF("pre-suspend unacked: cli=%zu srv=%zu", fx.cli->unacked.frames,
	       fx.srv->unacked.frames);

	/* Freeze both endpoints directly into SUSPENDED with non-empty unacked
	 * lists. This avoids timing windows while still forcing resume to replay
	 * the preserved frames over a fresh transport. */
	mux_session_suspend(fx.cli);
	mux_session_suspend(fx.srv);
	const bool cli_retrans_armed =
		fx.cli->unacked.retransmit_off != SIZE_MAX;
	const bool srv_retrans_armed =
		fx.srv->unacked.retransmit_off != SIZE_MAX;
	T_LOGF("retransmit armed: cli=%d srv=%d",
	       fx.cli->unacked.retransmit_off != SIZE_MAX,
	       fx.srv->unacked.retransmit_off != SIZE_MAX);

	/* Wait for both sessions to resume. */
	const int resume_ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	if (resume_ret != 0) {
		T_LOGF("resume wait failed:"
		       " cli(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
		       " unreported=%" PRIuLEAST32 " tx_pending=%d retrans=%d)"
		       " srv(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
		       " unreported=%" PRIuLEAST32 " tx_pending=%d retrans=%d)",
		       fx.cli->state, fx.cli->unacked.frames,
		       fx.cli->unacked.recv_seq, fx.cli->unacked.unreported,
		       fx.cli->wire.tx_pending,
		       fx.cli->unacked.retransmit_off != SIZE_MAX,
		       fx.srv->state, fx.srv->unacked.frames,
		       fx.srv->unacked.recv_seq, fx.srv->unacked.unreported,
		       fx.srv->wire.tx_pending,
		       fx.srv->unacked.retransmit_off != SIZE_MAX);
	}
	const bool cli_suspended = fx.cli_suspended;
	const bool srv_suspended = fx.srv_suspended;
	const bool cli_resumed = fx.cli_resumed;
	const bool srv_resumed = fx.srv_resumed;

	/* Bidirectional echo must complete after retransmission. */
	bool cli_echo_ok;
	{
		struct echo_ctx cli_ctx = {
			.ts = cli_ts,
			.expected = cli_payload,
			.expected_len = cli_sent,
		};
		const int cli_echo_ret = wait_until(
			&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
			&cli_ctx);
		if (cli_echo_ret != 0) {
			T_LOGF("client echo after resume failed:"
			       " cli(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " unreported=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)"
			       " srv(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " unreported=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)",
			       fx.cli->state, fx.cli->unacked.frames,
			       fx.cli->unacked.recv_seq,
			       fx.cli->unacked.unreported,
			       fx.cli->wire.tx_pending,
			       fx.cli->unacked.retransmit_off != SIZE_MAX,
			       cli_ts->recv_len, cli_sent, cli_ts->got_error,
			       cli_ts->got_eof, fx.srv->state,
			       fx.srv->unacked.frames, fx.srv->unacked.recv_seq,
			       fx.srv->unacked.unreported,
			       fx.srv->wire.tx_pending,
			       fx.srv->unacked.retransmit_off != SIZE_MAX,
			       srv_ts->recv_len, srv_sent, srv_ts->got_error,
			       srv_ts->got_eof);
		}
		cli_echo_ok = cli_echo_ret == 0;
	}
	bool srv_echo_ok;
	{
		struct echo_ctx srv_ctx = {
			.ts = srv_ts,
			.expected = srv_payload,
			.expected_len = srv_sent,
		};
		const int srv_echo_ret = wait_until(
			&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
			&srv_ctx);
		if (srv_echo_ret != 0) {
			T_LOGF("server echo after resume failed:"
			       " cli(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " unreported=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)"
			       " srv(state=%d unacked=%zu recv_seq=%" PRIuLEAST32
			       " unreported=%" PRIuLEAST32
			       " tx_pending=%d retrans=%d"
			       " recv=%zu/%zu err=%d eof=%d)",
			       fx.cli->state, fx.cli->unacked.frames,
			       fx.cli->unacked.recv_seq,
			       fx.cli->unacked.unreported,
			       fx.cli->wire.tx_pending,
			       fx.cli->unacked.retransmit_off != SIZE_MAX,
			       cli_ts->recv_len, cli_sent, cli_ts->got_error,
			       cli_ts->got_eof, fx.srv->state,
			       fx.srv->unacked.frames, fx.srv->unacked.recv_seq,
			       fx.srv->unacked.unreported,
			       fx.srv->wire.tx_pending,
			       fx.srv->unacked.retransmit_off != SIZE_MAX,
			       srv_ts->recv_len, srv_sent, srv_ts->got_error,
			       srv_ts->got_eof);
		}
		srv_echo_ok = srv_echo_ret == 0;
	}
	const bool cli_no_error = !cli_ts->got_error;
	const bool srv_no_error = !srv_ts->got_error;
	const size_t cli_recv_len = cli_ts->recv_len;
	const size_t srv_recv_len = srv_ts->recv_len;
	const bool cli_matches =
		cli_recv_len >= cli_sent &&
		memcmp(cli_ts->recv_buf, cli_payload, cli_sent) == 0;
	const bool srv_matches =
		srv_recv_len >= srv_sent &&
		memcmp(srv_ts->recv_buf, srv_payload, srv_sent) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	free(cli_payload);
	free(srv_payload);
	fixture_teardown(&fx);

	T_EXPECT(cli_sent_nonzero);
	T_EXPECT(srv_sent_nonzero);
	T_EXPECT(unacked_pre);
	T_EXPECT(cli_retrans_armed);
	T_EXPECT(srv_retrans_armed);
	T_EXPECT(resume_ret == 0);
	T_EXPECT(cli_suspended);
	T_EXPECT(srv_suspended);
	T_EXPECT(cli_resumed);
	T_EXPECT(srv_resumed);
	T_EXPECT(cli_echo_ok);
	T_EXPECT(srv_echo_ok);
	T_EXPECT(cli_no_error);
	T_EXPECT(srv_no_error);
	if (cli_recv_len >= cli_sent) {
		T_EXPECT(cli_matches);
	}
	if (srv_recv_len >= srv_sent) {
		T_EXPECT(srv_matches);
	}
}

/* a stream mid-transfer across a real RST break must deliver its full
 * payload without error or premature EOF; the suspend→reconnect→resume
 * path is transparent to the stream. */

T_DECLARE_CASE(test_resume_stream_transparent)
{
	struct mux_test_fixture fx;
	unsigned char *payload = NULL;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x5A);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_LARGE;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Let the transfer get underway, then sever the transport mid-flight so
	 * the resume happens while data is still in transit on this stream. */
	struct echo_ctx partial_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE / 4,
	};
	if (wait_until(
		    &fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
		    &partial_ctx) != 0) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("echo transfer did not get underway");
		return;
	}
	/* Captured here, asserted only after teardown (see the tail): a failing
	 * check must not longjmp past fixture_teardown and leak the fixture. */
	const bool in_flight = ts->recv_len < (size_t)PAYLOAD_LARGE;
	const bool not_eof_pre = !ts->got_eof;
	const bool not_error_pre = !ts->got_error;

	fx_break_transport(&fx);

	/* The remaining payload must echo back without the stream ever observing
	 * an error (pred_echo_received returns -1 on got_error): the session
	 * resume is transparent to the stream. */
	struct echo_ctx full_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, (RESUME_TIMEOUT_MS + ECHO_TIMEOUT_MS) / 1000.0,
		pred_echo_received, &full_ctx);
	const bool got_error = ts->got_error;
	const bool got_eof = ts->got_eof;
	/* A real resume must have occurred on both sides. */
	const bool cli_suspended = fx.cli_suspended;
	const bool srv_suspended = fx.srv_suspended;
	const bool cli_resumed = fx.cli_resumed;
	const bool srv_resumed = fx.srv_resumed;
	const enum mux_state cli_state = mux_state(fx.cli);
	const enum mux_state srv_state = mux_state(fx.srv);
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == PAYLOAD_LARGE &&
		memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	free(payload);
	fixture_teardown(&fx);

	T_EXPECT(in_flight);
	T_EXPECT(not_eof_pre);
	T_EXPECT(not_error_pre);
	T_EXPECT(ret == 0);
	T_EXPECT(!got_error);
	T_EXPECT(!got_eof);
	T_EXPECT(cli_suspended);
	T_EXPECT(srv_suspended);
	T_EXPECT(cli_resumed);
	T_EXPECT(srv_resumed);
	T_EXPECT_EQ(cli_state, MUX_STATE_ESTABLISHED);
	T_EXPECT_EQ(srv_state, MUX_STATE_ESTABLISHED);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_LARGE);
	if (recv_len == PAYLOAD_LARGE) {
		T_EXPECT(payload_matches);
	}
}

/* like test_resume_stream_transparent, but deterministically forces
 * frames into the unacked ring (write-only sockets + mux_session_suspend)
 * so the resume path MUST retransmit; transparent to the stream. */

T_DECLARE_CASE(test_resume_stream_unacked_retransmit)
{
	struct mux_test_fixture fx;
	unsigned char *payload = NULL;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x3C);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_LARGE;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Let the transfer get underway so the stream straddles the break. */
	struct echo_ctx partial_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE / 4,
	};
	if (wait_until(
		    &fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received,
		    &partial_ctx) != 0) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("echo transfer did not get underway");
		return;
	}
	/* Captured here, asserted only after teardown (see the tail): a failing
	 * check must not longjmp past fixture_teardown and leak the fixture. */
	const bool not_error_underway = !ts->got_error;

	/* Force a non-empty unacked ring: stop processing ACKs and pump the send
	 * side so sent frames stay pending replay. Only a client stream is open, so
	 * require only the client side (the echo server may already be fully ACKed). */
	const bool cli_unacked_pre = test_pump_unacked_no_wait(&fx, false);

	/* Freeze straight into SUSPENDED with the ring populated; resume must
	 * replay the preserved frames over the fresh transport. */
	mux_session_suspend(fx.cli);
	mux_session_suspend(fx.srv);
	const bool cli_retrans_armed =
		fx.cli->unacked.retransmit_off != SIZE_MAX;

	const int resume_ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	const bool cli_suspended = fx.cli_suspended;
	const bool srv_suspended = fx.srv_suspended;
	const bool cli_resumed = fx.cli_resumed;
	const bool srv_resumed = fx.srv_resumed;

	/* The full payload must echo back intact, with the stream never observing
	 * an error or premature EOF: the retransmission is transparent. */
	struct echo_ctx full_ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, (RESUME_TIMEOUT_MS + ECHO_TIMEOUT_MS) / 1000.0,
		pred_echo_received, &full_ctx);
	const bool got_error = ts->got_error;
	const bool got_eof = ts->got_eof;
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == PAYLOAD_LARGE &&
		memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	free(payload);
	fixture_teardown(&fx);

	T_EXPECT(not_error_underway);
	T_EXPECT(cli_unacked_pre);
	T_EXPECT(cli_retrans_armed);
	T_EXPECT(resume_ret == 0);
	T_EXPECT(cli_suspended);
	T_EXPECT(srv_suspended);
	T_EXPECT(cli_resumed);
	T_EXPECT(srv_resumed);
	T_EXPECT(ret == 0);
	T_EXPECT(!got_error);
	T_EXPECT(!got_eof);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_LARGE);
	if (recv_len == PAYLOAD_LARGE) {
		T_EXPECT(payload_matches);
	}
}

/* test_resume_handshake_transport_lost: transport failure during a client
 * resume handshake must re-suspend (not reset/close) so the session can
 * resume on the next attempt. */

T_DECLARE_CASE(test_resume_handshake_transport_lost)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Disable auto-reconnect so that mux_session_suspend does not immediately
	 * re-dial; we will control the client's reconnect manually. */
	char saved_connect_str[sizeof(fx.connect_str)];
	memcpy(saved_connect_str, fx.connect_str, sizeof(saved_connect_str));
	fx.connect_str[0] = '\0';

	/* Suspend the client while the server remains ESTABLISHED.
	 * The server will handle the resume once the client reconnects. */
	mux_session_suspend(fx.cli);
	/* Captured, asserted after teardown (see the tail): a failing check must
	 * not longjmp past fixture_teardown and leak the fixture. */
	const bool cli_suspended_pre = fx.cli->state == SESSION_SUSPENDED;

	/* Give the client a dead-end socketpair: sp[1] is closed immediately
	 * so the client's resume ClientHello hits an error (EPIPE or EOF)
	 * during the handshake, exercising the re-suspension path. */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
		fixture_teardown(&fx);
		T_FATAL("socketpair failed");
		return;
	}
	{
		const int flags = fcntl(sp[0], F_GETFL, 0);
		if (flags >= 0) {
			(void)fcntl(sp[0], F_SETFL, flags | O_NONBLOCK);
		}
	}
	(void)close(
		sp[1]); /* close peer end; writes to sp[0] get EPIPE / reads get EOF */

	mux_attach_fd(fx.cli, sp[0]);

	/* Run the event loop until the client detects the error and re-suspends.
	 * With the fix, this reaches SESSION_SUSPENDED.
	 * Without the fix, it reaches SESSION_CLOSED (and the test fails). */
	for (int i = 0; i < 32 && fx.cli->state != SESSION_SUSPENDED; i++) {
		ev_run(fx.loop, EVRUN_NOWAIT);
	}

	/* On failure, tear down before asserting so the fixture cannot leak; the
	 * subsequent real-resume steps assume a re-suspended client, so bail here
	 * rather than driving them against a closed session. */
	const bool cli_resuspended = fx.cli->state == SESSION_SUSPENDED;
	if (!cli_resuspended) {
		T_LOGF("client state after dead-end handshake: %d"
		       " (expected SESSION_SUSPENDED=%d)",
		       fx.cli->state, (int)SESSION_SUSPENDED);
		fixture_teardown(&fx);
		T_EXPECT(cli_resuspended);
		return;
	}

	/* Restore the connect string and perform the real resume. */
	memcpy(fx.connect_str, saved_connect_str, sizeof(fx.connect_str));
	const int fd = fixture_dial(fx.connect_str);
	if (fd < 0) {
		fixture_teardown(&fx);
		T_FATAL("fixture_dial failed for real resume attempt");
		return;
	}
	mux_attach_fd(fx.cli, fd);

	const int ret =
		wait_until(&fx, RESUME_TIMEOUT_MS / 1000.0, pred_resumed, &fx);
	if (ret != 0) {
		T_LOGF("resume wait failed:"
		       " cli(state=%d unacked=%zu) srv(state=%d unacked=%zu)"
		       " cli_closed=%d srv_closed=%d",
		       fx.cli != NULL ? (int)fx.cli->state : -1,
		       fx.cli != NULL ? fx.cli->unacked.frames : 0,
		       fx.srv != NULL ? (int)fx.srv->state : -1,
		       fx.srv != NULL ? fx.srv->unacked.frames : 0,
		       fx.cli_closed, fx.srv_closed);
	}
	const bool cli_resumed = fx.cli_resumed;
	const bool srv_resumed = fx.srv_resumed;
	const bool cli_connect_failed = fx.cli_connect_failed;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(cli_suspended_pre);
	T_EXPECT(ret == 0);
	T_EXPECT(cli_resumed);
	T_EXPECT(srv_resumed);
	/* The dead-end attempt ended before ESTABLISHED. */
	T_EXPECT(cli_connect_failed);
}

/* Satisfied once the client and the declined transient have both completed
 * the fresh handshake; -1 if the client closed instead. */
static int pred_declined_fresh(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	if (fx->cli_closed) {
		return -1;
	}
	return (fx->cli_established && fx->declined_established) ? 1 : 0;
}

/* A client whose resume the server declines falls back to a fresh session,
 * discarding the streams it preserved while suspended. The session goes on,
 * so a direct stream the application still holds must be reported (EV_READ,
 * ECONNRESET) and kept allocated until mux_stream_close(). */
T_DECLARE_CASE(test_resume_declined_keeps_held_direct_stream)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}
	struct test_stream *const ts = open_held_direct_stream(&fx);
	if (ts == NULL) {
		T_FATAL("held direct stream setup failed");
		return;
	}
	struct mux_stream *const s = ts->s;

	fx.cli_established = false;
	fx.resume_decline = true;
	fx_break_transport(&fx);
	const int fresh_ret = wait_until(
		&fx, RESUME_TIMEOUT_MS / 1000.0, pred_declined_fresh, &fx);
	const bool bound = ts->w_io.stream == s;
	const bool notified = ts->got_error;
	const size_t held = fx.cli_num_streams;
	int recv_ret = 0;
	int recv_err = 0;
	size_t released = SIZE_MAX;
	if (fresh_ret == 0 && bound && held == 1) {
		release_held_stream(&fx, s, &recv_ret, &recv_err, &released);
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(fresh_ret == 0);
	T_EXPECT(bound);
	T_EXPECT(notified);
	T_EXPECT_EQ(held, (size_t)1);
	T_EXPECT_EQ(recv_ret, -1);
	T_EXPECT_EQ(recv_err, ECONNRESET);
	T_EXPECT_EQ(released, (size_t)0);
}

/* test_resume_declined_after_reattach: an owner that detaches the transient's
 * transport, then cannot complete the handoff, restores it with
 * mux_transport_reattach and declines the resume.  The transient must then be
 * served as a fresh session on its original socket: the handshake continues
 * on the re-armed watcher, the client falls back to a fresh session under the
 * transient's id, the claimed identity is back on the transient, and a stream
 * round-trips over the restored transport. */

T_DECLARE_CASE(test_resume_declined_after_reattach)
{
	static const char cli_identity[] = "reattach-client";
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Claim an identity in the resume ClientHello, so the reattach has a
	 * peer identity to move back onto the transient. */
	char *const identity = strdup(cli_identity);
	if (identity == NULL) {
		fixture_teardown(&fx);
		T_FATAL("strdup failed");
		return;
	}
	free(fx.cli->handshake.identity);
	fx.cli->handshake.identity = identity;

	unsigned char old_id[MUX_SESSION_ID_LEN];
	memcpy(old_id, mux_session_id(fx.srv), sizeof(old_id));
	fx.cli_established = false;
	fx.resume_decline = true;

	fx_break_transport(&fx);
	const int ret = wait_until(
		&fx, RESUME_TIMEOUT_MS / 1000.0, pred_declined_fresh, &fx);
	if (ret != 0 || fx.declined == NULL) {
		T_LOGF("declined resume wait failed: ret=%d declined=%d"
		       " cli_established=%d declined_established=%d",
		       ret, fx.declined != NULL, fx.cli_established,
		       fx.declined_established);
		fixture_teardown(&fx);
		T_FATAL("declined resume did not complete a fresh handshake");
		return;
	}

	const bool detach_moved = fx.detach_moved_transport;
	const bool reattach_restored = fx.reattach_restored_transport;
	const bool same_fd = mux_fd(fx.declined) == fx.declined_fd;
	const bool fd_open = fcntl(fx.declined_fd, F_GETFD) != -1;
	const char *const peer_identity = mux_peer_identity(fx.declined);
	const bool identity_restored = peer_identity != NULL &&
				       strcmp(peer_identity, cli_identity) == 0;
	const enum mux_state declined_state = mux_state(fx.declined);
	const enum mux_state cli_state = mux_state(fx.cli);
	const bool cli_adopted_fresh_id =
		memcmp(mux_session_id(fx.cli), mux_session_id(fx.declined),
		       MUX_SESSION_ID_LEN) == 0;
	const bool id_changed =
		memcmp(mux_session_id(fx.cli), old_id, MUX_SESSION_ID_LEN) != 0;
	const bool none_resumed = !fx.cli_resumed && !fx.srv_resumed;

	/* A stream over the fresh session proves the restored transport
	 * carries traffic, not merely a completed hello.  fx.srv's socket is
	 * the sentinel fx_break_transport left, so only the declined transient
	 * can echo it. */
	unsigned char payload[PAYLOAD_SMALL];
	fill_payload(payload, sizeof(payload), 0x49);
	struct mux_stream *const s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *const ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = sizeof(payload);
	mux_stream_io_start(fx.loop, &ts->w_io);
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = sizeof(payload),
	};
	const int echo_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_received, &ctx);
	const bool echo_matches =
		ts->recv_len == sizeof(payload) &&
		memcmp(ts->recv_buf, payload, sizeof(payload)) == 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(detach_moved);
	T_EXPECT(reattach_restored);
	T_EXPECT(same_fd);
	T_EXPECT(fd_open);
	T_EXPECT(identity_restored);
	T_EXPECT_EQ(declined_state, MUX_STATE_ESTABLISHED);
	T_EXPECT_EQ(cli_state, MUX_STATE_ESTABLISHED);
	T_EXPECT(cli_adopted_fresh_id);
	T_EXPECT(id_changed);
	T_EXPECT(none_resumed);
	T_EXPECT(echo_ret == 0);
	T_EXPECT(echo_matches);
}

/* nodelay=true, server sends PAYLOAD_LARGE to
 * client.  Reproduces reported infinite-loop / 100% CPU with nodelay and
 * reverse data direction. */

T_DECLARE_CASE(test_nodelay_reverse_large)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	/* Enable nodelay on the client session (already created by
	 * fixture_setup) and on the fixture so pending_accept_cb picks
	 * it up for the server config. */
	fx.nodelay = true;
	fx.cli->conf.nodelay = true;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0xE7);

	/* Server will send payload + FIN when a stream is accepted. */
	fx.accept_mode = ACCEPT_SEND_PAYLOAD;
	fx.accept_send_data = payload;
	fx.accept_send_len = PAYLOAD_LARGE;

	/* Client opens a stream; it does not send any data – it only receives. */
	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open(cli) returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait until the client received all bytes AND got peer EOF. */
	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	const size_t recv_len = ts->recv_len;
	const bool got_eof = ts->got_eof;
	const bool got_error = ts->got_error;
	const bool payload_matches =
		recv_len == PAYLOAD_LARGE &&
		memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_LARGE);
	T_EXPECT(got_eof);
	T_EXPECT(!got_error);
	if (recv_len == PAYLOAD_LARGE) {
		T_EXPECT(payload_matches);
	}
}

/* BDP estimator tests. */

struct bdp_ctx {
	struct test_stream *ts;
	const struct mux_session *ss;
	size_t expected_len;
};

static void bdp_enable_auto_windows(struct mux_session *restrict ss)
{
	struct mux_session_config conf = *mux_conf(ss);
	conf.stream_window = 0;
	conf.session_window = 0;
	mux_set_config(ss, &conf);
}

struct bdp_control_ctx {
	const struct mux_session *ss;
	uint_least64_t before_bytes_recv;
};

static int pred_control_only_no_bdp(void *ptr)
{
	const struct bdp_control_ctx *restrict ctx = ptr;
	if (ctx->ss->bytes_recv <= ctx->before_bytes_recv) {
		return 0;
	}
	if (wndfilter_get(&ctx->ss->estimator.rx.bw_wnd) > 0 ||
	    wndfilter_get(&ctx->ss->estimator.tx.bw_wnd) > 0 ||
	    ctx->ss->estimator.ping_in_flight) {
		return -1;
	}
	return 1;
}

static int pred_echo_and_bdp_cycle(void *ptr)
{
	const struct bdp_ctx *restrict ctx = ptr;
	if (ctx->ts->got_error) {
		return -1;
	}
	/* All echoed bytes received AND at least one full PING/PONG cycle. */
	if (ctx->ts->recv_len < ctx->expected_len) {
		return 0;
	}
	if (wndfilter_get(&ctx->ss->estimator.rtt_wnd) == 0 ||
	    ctx->ss->estimator.ping_in_flight) {
		return 0;
	}
	return 1;
}

/* when both windows are automatic, a PONG-driven BDP update from inbound
 * PUSH bytes must grow stream_window while session_window (tx estimate)
 * stays at its floor. */

T_DECLARE_CASE(test_bdp_auto_stream_window_updated_by_pong)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	bdp_enable_auto_windows(fx.cli);
	const bool auto_stream = fx.cli->auto_stream_window;
	const bool auto_session = fx.cli->auto_session_window;
	const uint_least32_t session_window_initial = fx.cli->session_window;
	const uint_least32_t stream_window_initial = fx.cli->stream_window;

	/* Drive the PONG -> estimator -> session_update_window path directly.
	 * Use 4 × MUX_INITIAL_SEND_WINDOW: a 1× sample lands at BDP_MIN
	 * where integer-division truncation makes the assertion fragile. */
	mux_estimator_add(fx.cli, (uint_least64_t)MUX_INITIAL_SEND_WINDOW * 4);
	const bool ping_in_flight_after_add = fx.cli->estimator.ping_in_flight;
	if (!fx.cli->estimator.ping_in_flight) {
		fixture_teardown(&fx);
		T_FATAL("estimator did not queue ping frame");
		return;
	}
	/* Back-date the timestamp by 1 ms so the measured RTT is positive. */
	if (fx.cli->estimator.last_probe_ns <= 1000000) {
		fixture_teardown(&fx);
		T_FATAL("invalid estimator timestamp");
		return;
	}
	fx.cli->estimator.last_probe_ns -= 1000000;
	const int_fast64_t sent_ns = fx.cli->estimator.last_probe_ns;

	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = MUX_PING_PAYLOAD_SIZE,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PONG,
	};
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + MUX_PING_PAYLOAD_SIZE;
	bytebuf_reset(fx.cli->wire.recvbuf);
	if (!mux_bytebuf_reserve(&fx.cli->wire.recvbuf, frame_size, false)) {
		fixture_teardown(&fx);
		T_FATAL("recvbuf has no space");
		return;
	}
	unsigned char *const pong = bytebuf_write_ptr(fx.cli->wire.recvbuf);
	mux_write_header(pong, &hdr);
	write_uint64(pong + MUX_FRAME_HEADER_SIZE, (uint_fast64_t)sent_ns);
	bytebuf_produce(fx.cli->wire.recvbuf, frame_size);
	mux_session_recv_pong(fx.cli, &hdr, frame_size);

	/* PONG grows stream_window from the rx estimate; the idle tx
	 * direction leaves session_window at its floor. */
	const uint_least32_t stream_window_final = fx.cli->stream_window;
	const uint_least32_t session_window_final = fx.cli->session_window;
	const bool ping_in_flight_final = fx.cli->estimator.ping_in_flight;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(auto_stream);
	T_EXPECT(auto_session);
	T_EXPECT_EQ(
		session_window_initial,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(stream_window_initial, session_window_initial);
	T_EXPECT(ping_in_flight_after_add);
	T_EXPECT(
		stream_window_final >
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(
		session_window_final,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT(!ping_in_flight_final);
}

/* test_bdp_session_window_grows_from_ack_sample_only: a pure sender (no inbound
 * PUSH, hence no rx sample) must still grow session_window from the tx ack-clock
 * (mux_estimator_add_acked) while stream_window stays at its rx-driven floor. */

T_DECLARE_CASE(test_bdp_session_window_grows_from_ack_sample_only)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	bdp_enable_auto_windows(fx.cli);
	const uint_least32_t session_window_initial = fx.cli->session_window;
	const uint_least32_t stream_window_initial = fx.cli->stream_window;

	/* Mirror test_bdp_auto_stream_window_updated_by_pong, but drive the
	 * cycle via mux_estimator_add_acked only: sample stays 0 throughout. */
	mux_estimator_add_acked(
		fx.cli, (uint_least64_t)MUX_INITIAL_SEND_WINDOW * 4);
	const bool ping_in_flight_after_add = fx.cli->estimator.ping_in_flight;
	const size_t rx_sample_after_add = fx.cli->estimator.rx.sample;
	const size_t tx_sample_after_add = fx.cli->estimator.tx.sample;
	if (!fx.cli->estimator.ping_in_flight) {
		fixture_teardown(&fx);
		T_FATAL("estimator did not queue ping frame");
		return;
	}
	/* Back-date the timestamp by 1 ms so the measured RTT is positive. */
	if (fx.cli->estimator.last_probe_ns <= 1000000) {
		fixture_teardown(&fx);
		T_FATAL("invalid estimator timestamp");
		return;
	}
	fx.cli->estimator.last_probe_ns -= 1000000;
	const int_fast64_t sent_ns = fx.cli->estimator.last_probe_ns;

	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = MUX_PING_PAYLOAD_SIZE,
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PONG,
	};
	const size_t frame_size = MUX_FRAME_HEADER_SIZE + MUX_PING_PAYLOAD_SIZE;
	bytebuf_reset(fx.cli->wire.recvbuf);
	if (!mux_bytebuf_reserve(&fx.cli->wire.recvbuf, frame_size, false)) {
		fixture_teardown(&fx);
		T_FATAL("recvbuf has no space");
		return;
	}
	unsigned char *const pong = bytebuf_write_ptr(fx.cli->wire.recvbuf);
	mux_write_header(pong, &hdr);
	write_uint64(pong + MUX_FRAME_HEADER_SIZE, (uint_fast64_t)sent_ns);
	bytebuf_produce(fx.cli->wire.recvbuf, frame_size);
	mux_session_recv_pong(fx.cli, &hdr, frame_size);

	/* PONG grows session_window from the tx ack-clock estimate; the idle
	 * rx direction leaves stream_window at its floor. */
	const uint_least32_t session_window_final = fx.cli->session_window;
	const uint_least32_t stream_window_final = fx.cli->stream_window;
	const bool ping_in_flight_final = fx.cli->estimator.ping_in_flight;
	const size_t rx_sample_final = fx.cli->estimator.rx.sample;
	const size_t tx_sample_final = fx.cli->estimator.tx.sample;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT_EQ(
		session_window_initial,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(stream_window_initial, session_window_initial);
	T_EXPECT(ping_in_flight_after_add);
	T_EXPECT_EQ(rx_sample_after_add, (size_t)0);
	T_EXPECT(tx_sample_after_add > 0);
	T_EXPECT(
		session_window_final >
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT_EQ(
		stream_window_final,
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT));
	T_EXPECT(!ping_in_flight_final);
	T_EXPECT_EQ(rx_sample_final, (size_t)0);
	T_EXPECT_EQ(tx_sample_final, (size_t)0);
}

/* Snapshot of a session's estimator: every field a probe cycle writes. */
struct estimator_snapshot {
	int_least64_t last_probe_ns;
	bool ping_in_flight;
	size_t rx_sample;
	size_t tx_sample;
	int_fast64_t rtt_min;
	int_fast64_t rx_bw;
	int_fast64_t tx_bw;
};

static struct estimator_snapshot
estimator_snapshot_take(const struct mux_session *restrict ss)
{
	const struct estimator_ctx *restrict est = &ss->estimator;
	return (struct estimator_snapshot){
		.last_probe_ns = est->last_probe_ns,
		.ping_in_flight = est->ping_in_flight,
		.rx_sample = est->rx.sample,
		.tx_sample = est->tx.sample,
		.rtt_min = wndfilter_get(&est->rtt_wnd),
		.rx_bw = wndfilter_get(&est->rx.bw_wnd),
		.tx_bw = wndfilter_get(&est->tx.bw_wnd),
	};
}

/* A session that never probed: no PING was ever sent and no sample, RTT or
 * bandwidth was ever recorded. */
static bool estimator_snapshot_untouched(const struct estimator_snapshot *snap)
{
	return snap->last_probe_ns == 0 && !snap->ping_in_flight &&
	       snap->rx_sample == 0 && snap->tx_sample == 0 &&
	       snap->rtt_min == 0 && snap->rx_bw == 0 && snap->tx_bw == 0;
}

/* Manual window mode (both stream_window and session_window > 0, the fixture
 * default on both ends): real traffic must never reach the estimator.  The echo
 * drives every receive-side feed on both sessions -- the fast-open SYN|PUSH
 * payload (server), ordinary PUSH payloads (both), and session ACKs trimming
 * sent PUSH bytes (both) -- so each auto-window gate in recv.c is exercised,
 * and neither session may start a probe cycle or move a window. */

T_DECLARE_CASE(test_bdp_manual_window_mode_no_estimator_effect)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	const bool cli_manual =
		!fx.cli->auto_stream_window && !fx.cli->auto_session_window;
	const bool srv_manual =
		!fx.srv->auto_stream_window && !fx.srv->auto_session_window;
	const uint_least32_t cli_stream_window = fx.cli->stream_window;
	const uint_least32_t cli_session_window = fx.cli->session_window;
	const uint_least32_t srv_stream_window = fx.srv->stream_window;
	const uint_least32_t srv_session_window = fx.srv->session_window;

	unsigned char *payload = malloc(PAYLOAD_LARGE);
	if (payload == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_LARGE, 0x5D);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	/* Queue the first chunk before the loop runs so it rides the SYN as a
	 * fast-open payload; the watcher sends the rest. */
	size_t fast_open_len = CHUNK_SIZE;
	const bool fast_open_queued =
		mux_stream_send(s, payload, &fast_open_len) == 0 &&
		fast_open_len > 0;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_LARGE;
	ts->send_off = fast_open_len;
	ts->send_shutdown_on_drain = true;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct echo_ctx ctx = {
		.ts = ts,
		.expected = payload,
		.expected_len = PAYLOAD_LARGE,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_eof, &ctx);
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == PAYLOAD_LARGE &&
		memcmp(ts->recv_buf, payload, PAYLOAD_LARGE) == 0;
	/* Traffic really crossed every gate: PUSH bytes both ways, and session
	 * ACKs acknowledged frames each side sent. */
	const bool cli_acked = fx.cli->unacked.last_ack_recv != 0;
	const bool srv_acked =
		fx.srv != NULL && fx.srv->unacked.last_ack_recv != 0;
	const struct estimator_snapshot cli_est =
		estimator_snapshot_take(fx.cli);
	const struct estimator_snapshot srv_est =
		fx.srv != NULL ?
			estimator_snapshot_take(fx.srv) :
			(struct estimator_snapshot){ .last_probe_ns = -1 };
	const bool cli_windows_kept =
		fx.cli->stream_window == cli_stream_window &&
		fx.cli->session_window == cli_session_window;
	const bool srv_windows_kept =
		fx.srv != NULL && fx.srv->stream_window == srv_stream_window &&
		fx.srv->session_window == srv_session_window;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(cli_manual);
	T_EXPECT(srv_manual);
	T_EXPECT(fast_open_queued);
	T_EXPECT(ret == 0);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_LARGE);
	if (recv_len == PAYLOAD_LARGE) {
		T_EXPECT(payload_matches);
	}
	T_EXPECT(cli_acked);
	T_EXPECT(srv_acked);
	T_EXPECT(estimator_snapshot_untouched(&cli_est));
	T_EXPECT(estimator_snapshot_untouched(&srv_est));
	T_EXPECT(cli_windows_kept);
	T_EXPECT(srv_windows_kept);
}

/* session_window auto (= 0), stream_window manual (> 0): session_window must
 * track peer_stream_window while stream_window stays at its configured value.
 * (The estimator is still fed in this mode -- recv.c gates it on either auto
 * flag -- but only the session window consumes its estimate.) */

T_DECLARE_CASE(test_bdp_auto_session_window_without_auto_stream_window)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* session_window = 0 (auto), stream_window = 4 (manual). */
	const uint_least32_t fixed_stream = 4;
	struct mux_session_config conf = *mux_conf(fx.cli);
	conf.session_window = 0;
	conf.stream_window = (int)fixed_stream;
	mux_set_config(fx.cli, &conf);
	const bool no_auto_stream = !fx.cli->auto_stream_window;
	const bool auto_session = fx.cli->auto_session_window;
	const uint_least32_t stream_window_after_config = fx.cli->stream_window;

	/* mux_session_update_session_window must still update session_window to
	 * track peer_stream_window even when stream_window is manual. */
	const uint_least32_t floor_frames =
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT);
	const uint_least32_t new_peer_window = floor_frames * 4;
	fx.cli->peer_stream_window = new_peer_window;
	mux_session_update_session_window(
		fx.cli, mux_estimator_tx_window_size(&fx.cli->estimator));
	const uint_least32_t session_window_after_update =
		fx.cli->session_window;
	const uint_least32_t stream_window_after_update = fx.cli->stream_window;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(no_auto_stream);
	T_EXPECT(auto_session);
	T_EXPECT_EQ(stream_window_after_config, fixed_stream);
	T_EXPECT_EQ(session_window_after_update, new_peer_window);
	/* stream_window must not have been modified. */
	T_EXPECT_EQ(stream_window_after_update, fixed_stream);
}

/* in automatic
 * window mode, mux_session_update_session_window must update session_window to
 * match peer_stream_window without touching stream_window. */

T_DECLARE_CASE(test_bdp_auto_session_window_tracks_peer_stream_window)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	bdp_enable_auto_windows(fx.cli);
	const bool auto_stream = fx.cli->auto_stream_window;
	const bool auto_session = fx.cli->auto_session_window;

	/* In auto mode, session_window tracks peer_stream_window via
	 * mux_session_update_session_window.  Set peer_stream_window to a value
	 * above the floor and call the function directly. */
	const uint_least32_t floor_frames =
		(uint_least32_t)(MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT);
	const uint_least32_t new_peer_window = floor_frames * 4;
	const uint_least32_t initial_stream_window = fx.cli->stream_window;

	fx.cli->peer_stream_window = new_peer_window;
	mux_session_update_session_window(
		fx.cli, mux_estimator_tx_window_size(&fx.cli->estimator));

	const uint_least32_t session_window_after = fx.cli->session_window;
	const uint_least32_t stream_window_after = fx.cli->stream_window;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(auto_stream);
	T_EXPECT(auto_session);
	T_EXPECT_EQ(session_window_after, new_peer_window);
	/* stream_window is driven by the BDP estimator, not peer_stream_window;
	 * mux_session_update_session_window must not change it. */
	T_EXPECT_EQ(stream_window_after, initial_stream_window);
}

/* test_bdp_control_only_no_cycle: control-only inbound traffic must not
 * start a measurement cycle when auto stream-window mode is enabled. */

T_DECLARE_CASE(test_bdp_control_only_no_cycle)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	bdp_enable_auto_windows(fx.cli);

	struct bdp_control_ctx ctx = {
		.ss = fx.cli,
		.before_bytes_recv = fx.cli->bytes_recv,
	};
	const bool ctrl_sent =
		mux_session_send_ctrl(fx.srv, STREAMID_CTRL, 0, MUX_CTRL_PROBE);
	mux_session_flush(fx.srv);
	const int ret = wait_until(
		&fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_control_only_no_bdp,
		&ctx);
	const bool rx_bw_zero =
		wndfilter_get(&fx.cli->estimator.rx.bw_wnd) == 0;
	const bool tx_bw_zero =
		wndfilter_get(&fx.cli->estimator.tx.bw_wnd) == 0;
	const bool no_ping_in_flight = !fx.cli->estimator.ping_in_flight;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ctrl_sent);
	T_EXPECT(ret == 0);
	T_EXPECT(rx_bw_zero);
	T_EXPECT(tx_bw_zero);
	T_EXPECT(no_ping_in_flight);
}

/* starting a cycle queues the
 * estimator PING immediately and stamps the timestamp into the frame payload
 * at queue time, transitioning directly to the in-flight state. */

T_DECLARE_CASE(test_bdp_ping_queued_before_send_progress)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	bdp_enable_auto_windows(fx.cli);
	mux_estimator_add(fx.cli, (uint_least64_t)MUX_MAX_PAYLOAD_SIZE);

	const size_t tx_window_size =
		mux_estimator_tx_window_size(&fx.cli->estimator);
	const size_t expected_tx_window =
		(size_t)fx.cli->session_window * (size_t)MUX_WINDOW_UNIT;
	const size_t rx_sample = fx.cli->estimator.rx.sample;
	const bool oob_queued = fx.cli->wire.oobbuf.head != NULL;
	const bool ping_in_flight = fx.cli->estimator.ping_in_flight;
	const bool probe_ns_positive = fx.cli->estimator.last_probe_ns > 0;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT_EQ(tx_window_size, expected_tx_window);
	T_EXPECT_EQ(rx_sample, (uint_least32_t)MUX_MAX_PAYLOAD_SIZE);
	T_EXPECT(oob_queued);
	T_EXPECT(ping_in_flight);
	T_EXPECT(probe_ns_positive);
}

/* test_bdp_ping_sent: inbound PUSH starts an estimator cycle; the queued PING
 * is delivered by EV_WRITE, the peer PONGs, and the cycle records a bandwidth
 * sample.  A stuck oobbuf would time out the wait. */

T_DECLARE_CASE(test_bdp_ping_sent)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	unsigned char *payload = NULL;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	bdp_enable_auto_windows(fx.cli);

	payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x4E);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	/* Wait for: (1) all echoed bytes received, (2) a complete PING/PONG
	 * cycle with no queued or in-flight estimator PING left behind. */
	struct bdp_ctx bdp = {
		.ts = ts,
		.ss = fx.cli,
		.expected_len = PAYLOAD_SMALL,
	};
	const int ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_bdp_cycle, &bdp);
	const bool rtt_positive = wndfilter_get(&fx.cli->estimator.rtt_wnd) > 0;
	const bool no_ping_in_flight = !fx.cli->estimator.ping_in_flight;
	const size_t recv_len = ts->recv_len;
	const bool payload_matches =
		recv_len == PAYLOAD_SMALL &&
		memcmp(ts->recv_buf, payload, PAYLOAD_SMALL) == 0;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(rtt_positive);
	T_EXPECT(no_ping_in_flight);
	T_EXPECT_EQ(recv_len, (size_t)PAYLOAD_SMALL);
	if (recv_len == PAYLOAD_SMALL) {
		T_EXPECT(payload_matches);
	}
}

/* on disconnect, stream_window is set to
 * the raw BDP in frames (half of the window target) and estimator learned
 * state is preserved. */

T_DECLARE_CASE(test_bdp_stop_halves_stream_window)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	unsigned char *payload = NULL;

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	bdp_enable_auto_windows(fx.cli);

	payload = malloc(PAYLOAD_SMALL);
	if (payload == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(payload, PAYLOAD_SMALL, 0x68);

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(payload);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = payload;
	ts->send_len = PAYLOAD_SMALL;
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct bdp_ctx bdp = {
		.ts = ts,
		.ss = fx.cli,
		.expected_len = PAYLOAD_SMALL,
	};
	const int cycle_ret = wait_until(
		&fx, ECHO_TIMEOUT_MS / 1000.0, pred_echo_and_bdp_cycle, &bdp);
	const bool rtt_positive_after_cycle =
		wndfilter_get(&fx.cli->estimator.rtt_wnd) > 0;

	/* Arm an in-flight probe (bypass the send-side rate limit) so the
	 * transition below can be shown to clear the transient probe. */
	fx.cli->estimator.last_probe_ns = 0;
	mux_estimator_add(fx.cli, (uint_fast64_t)MUX_MAX_PAYLOAD_SIZE);
	const bool ping_in_flight_after_add = fx.cli->estimator.ping_in_flight;

	/* Seed a known raw BDP window so the expected post-stop stream_window is
	 * a constant, not re-derived from the formula under test. */
	fx.cli->estimator.rx.effective_bdp =
		3u * (size_t)MUX_INITIAL_SEND_WINDOW;
	const size_t rx_window_size =
		mux_estimator_rx_window_size(&fx.cli->estimator);
	const uint_least32_t initial_frames =
		MUX_INITIAL_SEND_WINDOW / MUX_WINDOW_UNIT;

	/* Drive the real exit-from-ESTABLISHED transition rather than
	 * hand-computing the window and asserting it against itself:
	 * mux_session_set_state(SUSPENDED) runs session_reset_stream_window_floor
	 * (halve the raw BDP window, floored) and mux_estimator_suspend. */
	mux_session_set_state(fx.cli, SESSION_SUSPENDED);

	const uint_least32_t stream_window_after_stop = fx.cli->stream_window;
	const bool rtt_positive_after_stop =
		wndfilter_get(&fx.cli->estimator.rtt_wnd) > 0;
	const size_t effective_bdp_after_stop =
		fx.cli->estimator.rx.effective_bdp;
	const bool no_ping_after_stop = !fx.cli->estimator.ping_in_flight;

	free(payload);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(cycle_ret == 0);
	T_EXPECT(rtt_positive_after_cycle);
	T_EXPECT(ping_in_flight_after_add);
	T_EXPECT_EQ(rx_window_size, 3u * (size_t)MUX_INITIAL_SEND_WINDOW);
	/* stream_window halved to the raw BDP floor: 3*INITIAL / 2 / UNIT ==
	 * 3*initial_frames/2, above the initial-window floor. A regression in the
	 * divisor or floor would diverge from this constant. */
	T_EXPECT_EQ(stream_window_after_stop, 3u * initial_frames / 2u);
	/* Learned filter state survives the disconnect... */
	T_EXPECT(rtt_positive_after_stop);
	T_EXPECT_EQ(
		effective_bdp_after_stop, 3u * (size_t)MUX_INITIAL_SEND_WINDOW);
	/* ...while the transient in-flight probe is cleared (mux_estimator_suspend). */
	T_EXPECT(no_ping_after_stop);
}

/* test_send_queue_saturates_read_credit: mux_stream_send must gate on
 * stream_read_credit_avail; a call that fills it is accepted, the next
 * is rejected (== 0), and SYN|ACK credit growth re-enables sends. */

T_DECLARE_CASE(test_send_queue_saturates_read_credit)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}

	/* Stream in STREAM_INIT: send_window = MUX_DEFAULT_SEND_WINDOW,
	 * bytes_sent = 0, queued_send_bytes = 0.
	 * read_credit_avail = send_window - queued_send_bytes = 16384. */
	const size_t initial_credit = MUX_DEFAULT_SEND_WINDOW;

	/* Allocate a buffer that exactly fills the initial read credit. */
	unsigned char *buf = malloc(initial_credit + 1);
	if (buf == NULL) {
		fixture_teardown(&fx);
		T_FATAL("malloc failed");
		return;
	}
	fill_payload(buf, initial_credit + 1, 0xAA);

	/* --- Part 1: synchronous saturation (no event loop) --- */

	/* First call: exactly fills read_credit_avail. */
	size_t len1 = initial_credit;
	const bool send1_ok = mux_stream_send(s, buf, &len1) == 0;
	const size_t len1_after = len1;

	/* Second call: read_credit_avail = 0 → must be rejected. */
	size_t len2 = 1;
	const bool send2_ok = mux_stream_send(s, buf, &len2) == 0;
	const size_t len2_after = len2;

	/* --- Part 2: credit restored after SYN|ACK --- */

	/* Attach a direct I/O watcher and drive the event loop until the stream
	 * reaches ESTABLISHED (SYN|ACK received with new window grant). */
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		free(buf);
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	ts->send_data = buf;
	ts->send_len = 0; /* stream_io_cb won't send additional data */
	mux_stream_io_start(fx.loop, &ts->w_io);

	struct stream_established_ctx ec = { .s = s };
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_stream_established,
		    &ec) != 0) {
		free(buf);
		fixture_teardown(&fx);
		T_FATAL("stream did not reach ESTABLISHED");
		return;
	}

	/* SYN|ACK grants additional credit; read_credit_avail > 0 now. */
	size_t len3 = 1;
	const bool send3_ok =
		mux_stream_send(s, buf + initial_credit, &len3) == 0;
	const size_t len3_after = len3;

	free(buf);
	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(send1_ok);
	T_EXPECT_EQ(len1_after, initial_credit);
	T_EXPECT(send2_ok);
	T_EXPECT_EQ(len2_after, (size_t)0);
	T_EXPECT(send3_ok);
	T_EXPECT(len3_after > 0);
}

/* Direct-mode mux_stream_send must pay into the same
 * send_buffered_frames bookkeeping mux_stream_queue_send (the socket-mode
 * path) already does -- every dequeue/free path decrements it
 * unconditionally, so a direct-mode-only session that never pays in would
 * underflow this session-scoped size_t gauge to SIZE_MAX the moment a
 * frame it queued is dequeued or freed. */
T_DECLARE_CASE(test_stream_send_direct_mode_updates_send_buffered_frames)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}

	const size_t before = s->session->send_buffered_frames;

	unsigned char payload[10];
	fill_payload(payload, sizeof(payload), 0x77);
	size_t len = sizeof(payload);
	const bool send_ok = mux_stream_send(s, payload, &len) == 0;
	const size_t len_after = len;

	/* One small payload fits in a single frame. */
	const size_t after = s->session->send_buffered_frames;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(send_ok);
	T_EXPECT_EQ(len_after, sizeof(payload));
	T_EXPECT_EQ(after, before + 1);
}

/* mux_stream_open must return NULL after
 * mux_drain is called while a stream is open (so state stays ESTABLISHED
 * and the draining flag is what gates the rejection). */
T_DECLARE_CASE(test_drain_rejects_new_streams)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Open a stream to hold the session in ESTABLISHED during drain,
	 * ensuring the draining check in mux_session_open_stream is exercised. */
	struct mux_stream *s = mux_stream_open(fx.cli);
	if (s == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts = test_stream_new(&fx, s);
	if (ts == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts;
	mux_stream_io_start(fx.loop, &ts->w_io);

	mux_drain(fx.cli);

	const bool open_rejected = mux_stream_open(fx.cli) == NULL;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(open_rejected);
}

/* a draining session must refuse inbound
 * streams opened by the peer with RST (REFUSED_STREAM) so the drain can
 * converge; streams opened before the drain remain in the session table. */
T_DECLARE_CASE(test_drain_refuses_peer_syn)
{
	struct mux_test_fixture fx;
	if (fixture_setup(&fx) != 0) {
		T_FATAL("fixture_setup failed");
		return;
	}

	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_established,
		    &fx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("sessions did not establish");
		return;
	}

	/* Open a stream and wait until the server accepts it, holding the
	 * server session in ESTABLISHED during the drain. */
	struct mux_stream *s1 = mux_stream_open(fx.cli);
	if (s1 == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts1 = test_stream_new(&fx, s1);
	if (ts1 == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts1;
	mux_stream_io_start(fx.loop, &ts1->w_io);
	struct accepted_count_ctx acc_ctx = { .fx = &fx, .min_accepted = 1 };
	if (wait_until(
		    &fx, ESTABLISH_TIMEOUT_MS / 1000.0, pred_accepted_count,
		    &acc_ctx) != 0) {
		fixture_teardown(&fx);
		T_FATAL("server did not accept the first stream");
		return;
	}

	mux_drain(fx.srv);

	/* A stream opened by the peer after the drain must be refused:
	 * the client observes RST (delivered as a recv error) and the
	 * server never surfaces the stream to on_accept. */
	struct mux_stream *s2 = mux_stream_open(fx.cli);
	if (s2 == NULL) {
		fixture_teardown(&fx);
		T_FATAL("mux_stream_open returned NULL");
		return;
	}
	struct test_stream *ts2 = test_stream_new(&fx, s2);
	if (ts2 == NULL) {
		fixture_teardown(&fx);
		T_FATAL("test_stream_new failed");
		return;
	}
	fx.cli_streams[fx.n_cli_streams++] = ts2;
	mux_stream_io_start(fx.loop, &ts2->w_io);

	const int ret =
		wait_until(&fx, EOF_TIMEOUT_MS / 1000.0, pred_error, ts2);
	const bool ts2_got_error = ts2->got_error;
	const int n_accepted = fx.n_accepted;

	/* Teardown first so a failing assert can't leak the fixture. */
	fixture_teardown(&fx);

	T_EXPECT(ret == 0);
	T_EXPECT(ts2_got_error);
	T_EXPECT(n_accepted == 1);
}

/* Public API tests (mux_state / accessors / mux_stream_send / mux_stream_recv).
 * These drive the public mux API directly without the two-session harness. */

struct frame_pool_ctx {
	int alloc_calls;
	int free_calls;
};

static struct mux_frame *mux_api_test_alloc(void *data, const size_t size)
{
	struct frame_pool_ctx *const ctx = data;
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void mux_api_test_free(void *data, struct mux_frame *frame)
{
	struct frame_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator make_pool(struct frame_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = mux_api_test_alloc,
		.free = mux_api_test_free,
		.data = ctx,
	};
}

static void
mux_api_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void mux_api_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static struct mux_session make_session(struct frame_pool_ctx *restrict pool_ctx)
{
	return (struct mux_session){
		.pool = make_pool(pool_ctx),
		.max_payload = (uint_least32_t)mux_session_config_default
				       .max_frame_payload,
		.state = SESSION_ESTABLISHED,
		/* Seed the stats mirrors that mux_state()/mux_session_stats() read. */
		._pub_state = SESSION_ESTABLISHED,
		.stream_window = 3,
		._pub_stream_window = 3,
		.peer_stream_window = 5,
		._pub_peer_stream_window = 5,
	};
}

T_DECLARE_CASE(test_mux_state_maps_internal_states)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);

	/* mux_state() reads the published mirror, so drive it via PUB_STORE. */
	PUB_STORE(ss._pub_state, SESSION_ESTABLISHED);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_ESTABLISHED);
	PUB_STORE(ss._pub_state, SESSION_SUSPENDED);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_SUSPENDED);
	PUB_STORE(ss._pub_state, SESSION_HANDSHAKE);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_CONNECT);
	PUB_STORE(ss._pub_state, SESSION_CLOSED);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_CLOSED);
	PUB_STORE(ss._pub_state, SESSION_CLOSING);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_CLOSING);
	PUB_STORE(ss._pub_state, SESSION_CLOSE_WAIT);
	T_EXPECT_EQ(mux_state(&ss), (enum mux_state)MUX_STATE_CLOSING);
}

/* A shutting-down session must report as neither usable nor attachable.  Both
 * internal closing states still own their transport: mux_session_attach_fd
 * rejects them, and session_resume_attach drops a handoff to them.  Folding
 * them into ESTABLISHED lets server_on_resume_lookup pick a closing tunnel as a
 * resume target, whose dropped handoff then closes the peer's fresh transport
 * with no ServerHello sent; folding them into CLOSED instead lets
 * tunnel_open_fd's demand-reconnect attach to one and trip that CHECKMSGF.
 * Pin all three consumer predicates against both states. */
T_DECLARE_CASE(test_mux_state_closing_is_neither_usable_nor_attachable)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);

	PUB_STORE(ss._pub_state, SESSION_CLOSING);
	const enum mux_state closing = mux_state(&ss);
	PUB_STORE(ss._pub_state, SESSION_CLOSE_WAIT);
	const enum mux_state close_wait = mux_state(&ss);

	/* server_on_resume_lookup: never eligible as a resume target. */
	T_EXPECT(
		closing != MUX_STATE_SUSPENDED &&
		closing != MUX_STATE_ESTABLISHED);
	T_EXPECT(
		close_wait != MUX_STATE_SUSPENDED &&
		close_wait != MUX_STATE_ESTABLISHED);
	/* tunnel_open_fd: never demand-reconnected into. */
	T_EXPECT(closing != MUX_STATE_SUSPENDED && closing != MUX_STATE_CLOSED);
	T_EXPECT(
		close_wait != MUX_STATE_SUSPENDED &&
		close_wait != MUX_STATE_CLOSED);
	/* listener_has_live_tunnel / tunnel_stats: not counted as live. */
	T_EXPECT(closing != MUX_STATE_ESTABLISHED);
	T_EXPECT(close_wait != MUX_STATE_ESTABLISHED);
}

T_DECLARE_CASE(test_mux_peer_addr_and_window_accessors)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);

	memset(&ss.peer_addr, 0, sizeof(ss.peer_addr));
	T_EXPECT(mux_peer_addr(&ss) == NULL);
	ss.peer_addr.sa.sa_family = AF_UNIX;
	T_EXPECT(mux_peer_addr(&ss) != NULL);
	{
		struct mux_session_stats st = { 0 };
		mux_session_stats(&ss, &st);
		T_EXPECT_EQ(st.rx_window, (size_t)(3 * MUX_WINDOW_UNIT));
		T_EXPECT_EQ(st.tx_window, (size_t)(5 * MUX_WINDOW_UNIT));
	}
}

T_DECLARE_CASE(test_mux_stream_send_rejects_invalid_state)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct mux_stream s = {
		.state = STREAM_SYN_SENT,
		.session = &ss,
	};
	unsigned char payload[] = { 1, 2, 3 };
	size_t len = sizeof(payload);

	errno = 0;
	T_EXPECT(mux_stream_send(&s, payload, &len) < 0);
	T_EXPECT_EQ(errno, EINVAL);
}

T_DECLARE_CASE(test_mux_stream_send_queues_payload)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct ev_loop *loop = NULL;
	int fds[2] = { -1, -1 };
	struct mux_stream s = {
		.state = STREAM_INIT,
		.session = &ss,
		.send_window = 64,
	};
	unsigned char payload[20];
	size_t len = sizeof(payload);

	memset(payload, 0xA5, sizeof(payload));
	loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	ss.loop = loop;
	ss.wire.rx_open = true;
	ev_io_init(&ss.w_socket, mux_api_io_cb, fds[0], EV_READ);
	ss.w_socket.data = &ss;
	mux_sched_init(&ss);
	const bool send_ok = mux_stream_send(&s, payload, &len) == 0;
	const size_t len_after = len;
	const bool queue_nonempty = s.send_queue.head != NULL;

	/* Clean up before the asserts so a failing check can't leak. */
	mux_frame_list_clear(&s.send_queue, &ss.pool);
	(void)close(fds[0]);
	(void)close(fds[1]);
	ev_loop_destroy(loop);

	T_EXPECT(send_ok);
	T_EXPECT_EQ(len_after, sizeof(payload));
	T_EXPECT(queue_nonempty);
}

T_DECLARE_CASE(test_mux_stream_recv_reports_eagain_and_reset)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct mux_stream s = {
		.state = STREAM_ESTABLISHED,
		.session = &ss,
	};
	s.recvbuf = bytebuf_new(MUX_MAX_PAYLOAD_SIZE);
	T_CHECK(s.recvbuf != NULL);
	unsigned char buf[16];
	size_t len = sizeof(buf);

	errno = 0;
	const bool recv1_neg = mux_stream_recv(&s, buf, &len) < 0;
	const int errno1 = errno;

	s.rst_received = true;
	errno = 0;
	const bool recv2_neg = mux_stream_recv(&s, buf, &len) < 0;
	const int errno2 = errno;

	/* Free the recvbuf before the asserts so a failing check can't leak. */
	bytebuf_free(s.recvbuf);

	T_EXPECT(recv1_neg);
	T_EXPECT_EQ(errno1, EAGAIN);
	T_EXPECT(recv2_neg);
	T_EXPECT_EQ(errno2, ECONNRESET);
}

T_DECLARE_CASE(test_mux_stream_io_stop_clears_stream_binding)
{
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct mux_stream s = {
		.state = STREAM_ESTABLISHED,
		.session = &ss,
		/* Direct-mode stream: direct.w_io is the live union arm, so
		 * mux_stream_io_stop's is_direct-guarded clear applies. */
		.is_direct = true,
	};
	mux_stream_io watcher;

	T_CHECK(loop != NULL);
	mux_stream_io_init(&watcher, mux_api_cb, &s, EV_READ | EV_WRITE);
	watcher.loop = loop;
	watcher.active = 1;
	s.direct.w_io = &watcher;

	mux_stream_io_stop(loop, &watcher);
	const bool watcher_unbound = watcher.stream == NULL;
	const bool direct_cleared = s.direct.w_io == NULL;
	const int watcher_active = watcher.active;

	/* Destroy the loop before the asserts so a failing check can't leak. */
	ev_loop_destroy(loop);

	T_EXPECT(watcher_unbound);
	T_EXPECT(direct_cleared);
	T_EXPECT_EQ(watcher_active, 0);
}

/* main */

/* Cross-module cases against the real assembled stack; exercise behavior
 * the mock-isolated white-box tests cannot.  A self-contained xs_-prefixed
 * fixture keeps them independent of the integration harness. */

struct xs_pool_ctx {
	int alloc_calls;
	int free_calls;
	/* When set, every allocation fails as on frame-pool OOM. */
	bool fail;
};

struct xs_fixture {
	struct ev_loop *loop;
	struct mux_session ss;
	struct xs_pool_ctx pool_ctx;
	int fds[2];
};

static struct mux_frame *xs_alloc(void *data, const size_t size)
{
	struct xs_pool_ctx *const ctx = data;
	if (ctx->fail) {
		return NULL;
	}
	struct mux_frame *const frame = malloc(size);
	if (frame != NULL) {
		ctx->alloc_calls++;
	}
	return frame;
}

static void xs_free(void *data, struct mux_frame *frame)
{
	struct xs_pool_ctx *const ctx = data;
	ctx->free_calls++;
	free(frame);
}

static struct mux_frame_allocator xs_make_pool(struct xs_pool_ctx *ctx)
{
	return (struct mux_frame_allocator){
		.alloc = xs_alloc,
		.free = xs_free,
		.data = ctx,
	};
}

static void xs_timer_cb(struct ev_loop *loop, ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void xs_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static int xs_setup(struct xs_fixture *restrict fx)
{
	*fx = (struct xs_fixture){
		.fds = { -1, -1 },
	};
	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fx->fds) != 0) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	fx->ss = (struct mux_session){
		.loop = fx->loop,
		.state = SESSION_ESTABLISHED,
		.pool = xs_make_pool(&fx->pool_ctx),
		.max_payload = (uint_least32_t)mux_session_config_default.max_frame_payload,
		.session_window = 8,
		.stream_window = 4,
		.wire = {
			.rx_open = true,
		},
		/* Matches mux_session_new()'s real default: SIZE_MAX means "no resume
		 * replay in progress", not the zero-init compound literal would
		 * otherwise leave here. */
		.unacked = {
			.retransmit_off = SIZE_MAX,
		},
	};
	fx->ss.sched.streams = table_new(&mux_stream_table_opts);
	if (fx->ss.sched.streams == NULL) {
		(void)close(fx->fds[0]);
		(void)close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	ev_io_init(&fx->ss.w_socket, xs_io_cb, fx->fds[0], EV_READ);
	fx->ss.w_socket.data = &fx->ss;
	ev_timer_init(&fx->ss.w_idle_timeout, xs_timer_cb, 1.0, 0.0);
	fx->ss.w_idle_timeout.data = &fx->ss;
	mux_sched_init(&fx->ss);
	fx->ss.wire.recvbuf = bytebuf_new(4u * (size_t)MUX_MAX_FRAME_SIZE);
	if (fx->ss.wire.recvbuf == NULL) {
		table_free(fx->ss.sched.streams);
		(void)close(fx->fds[0]);
		(void)close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	fx->ss.unacked.ring = mux_frame_ring_new(MUX_FRAME_RING_MIN);
	if (fx->ss.unacked.ring == NULL) {
		bytebuf_free(fx->ss.wire.recvbuf);
		fx->ss.wire.recvbuf = NULL;
		table_free(fx->ss.sched.streams);
		(void)close(fx->fds[0]);
		(void)close(fx->fds[1]);
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
		return -1;
	}
	return 0;
}

static void xs_teardown(struct xs_fixture *restrict fx)
{
	if (fx->ss.sched.streams != NULL) {
		mux_sched_free_streams(&fx->ss);
	}
	if (fx->ss.wire.oobbuf.head != NULL ||
	    bytebuf_readable(fx->ss.wire.recvbuf) > 0 ||
	    fx->ss.wire.sendbuf.head != NULL) {
		mux_wire_discard_buffers(&fx->ss);
	}
	bytebuf_free(fx->ss.wire.recvbuf);
	fx->ss.wire.recvbuf = NULL;
	mux_frame_ring_free(&fx->ss.unacked.ring, &fx->ss.pool);
	fx->ss.unacked.frames = 0;
	fx->ss.unacked.retransmit_off = SIZE_MAX;
	if (fx->fds[0] >= 0) {
		(void)close(fx->fds[0]);
		fx->fds[0] = -1;
	}
	if (fx->fds[1] >= 0) {
		(void)close(fx->fds[1]);
		fx->fds[1] = -1;
	}
	if (fx->loop != NULL) {
		ev_loop_destroy(fx->loop);
		fx->loop = NULL;
	}
}

static struct mux_frame *xs_make_frame(
	const struct mux_frame_allocator *restrict pool,
	const uint_least16_t stream_id, const uint_least8_t flags,
	const uint_least16_t extra, const void *restrict payload,
	const size_t payload_len)
{
	struct mux_frame *const frame =
		mux_frame_get(pool, MUX_MAX_PAYLOAD_SIZE);
	if (frame == NULL) {
		return NULL;
	}
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = flags,
		.length = (uint_least16_t)payload_len,
		.stream_id = stream_id,
		.extra = extra,
	};
	mux_write_header(frame->data, &hdr);
	if (payload_len > 0 && payload != NULL) {
		memcpy(frame->data + MUX_FRAME_HEADER_SIZE, payload,
		       payload_len);
	}
	frame->len = MUX_FRAME_HEADER_SIZE + payload_len;
	frame->pos = 0;
	return frame;
}

/* mux_unacked_ack_trim reports the trimmed payload bytes so the caller can feed
 * mux_estimator_add_acked; the trim itself never touches the estimator (the
 * auto/manual gating lives in the receive dispatch caller, pinned by
 * test_bdp_manual_window_mode_no_estimator_effect). */
T_DECLARE_CASE(test_session_ack_trim_leaves_estimator_alone)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	static const unsigned char payload[100] = { 0 };

	struct mux_frame *const frame = xs_make_frame(
		&fx.ss.pool, 1, MUX_FLAG_PUSH, 0, payload, sizeof(payload));
	T_CHECK(frame != NULL);
	frame->unacked_count = 1;
	T_CHECK(mux_frame_ring_push(&fx.ss.unacked.ring, frame));
	fx.ss.unacked.frames = 1;
	fx.ss.unacked.bytes = sizeof(payload);
	fx.ss.unacked.last_ack_recv = 0;

	const struct unacked_ack_result r = mux_unacked_ack_trim(&fx.ss, 1);
	const bool r_ok = r.ok;
	const size_t unacked_bytes = fx.ss.unacked.bytes;
	const size_t trimmed_bytes = r.trimmed_bytes;
	const size_t tx_sample = fx.ss.estimator.tx.sample;
	const bool ping_in_flight = fx.ss.estimator.ping_in_flight;

	/* Teardown first so a failing assert can't leak the fixture. */
	xs_teardown(&fx);

	T_EXPECT(r_ok);
	T_EXPECT_EQ(unacked_bytes, (size_t)0);
	T_EXPECT_EQ(trimmed_bytes, sizeof(payload));
	/* unacked stays decoupled from the estimator: no probe is started here. */
	T_EXPECT_EQ(tx_sample, (size_t)0);
	T_EXPECT(!ping_in_flight);
}

T_DECLARE_CASE(test_session_open_stream_enforces_limits)
{
	struct xs_fixture fx;
	struct mux_stream *existing = NULL;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	fx.ss.conf.max_halfopen = 1;
	fx.ss.num_halfopen = 1;
	const bool halfopen_limit_rejects =
		mux_session_open_stream(&fx.ss) == NULL;

	fx.ss.num_halfopen = 0;
	fx.ss.conf.max_halfopen = 0;
	fx.ss.conf.max_streams = 1;
	existing = mux_stream_new(&fx.ss, 3, true);
	T_CHECK(existing != NULL);
	const bool add_existing_ok = mux_sched_add_stream(&fx.ss, existing);
	const bool max_streams_rejects =
		mux_session_open_stream(&fx.ss) == NULL;

	/* Teardown first so a failing assert can't leak the fixture. */
	xs_teardown(&fx);

	T_EXPECT(halfopen_limit_rejects);
	T_EXPECT(add_existing_ok);
	T_EXPECT(max_streams_rejects);
}

T_DECLARE_CASE(test_session_open_stream_success_sets_default_send_window)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	struct mux_stream *const s = mux_session_open_stream(&fx.ss);
	T_CHECK(s != NULL);
	const uint_least16_t s_id = s->id;
	const uint_least32_t s_send_window = s->send_window;
	const bool found_in_sched = mux_sched_find_stream(&fx.ss, s->id) == s;

	/* Teardown first so a failing assert can't leak the fixture. */
	xs_teardown(&fx);

	T_EXPECT_EQ(s_id, (uint_least16_t)1);
	T_EXPECT_EQ(s_send_window, (uint_least32_t)MUX_DEFAULT_SEND_WINDOW);
	T_EXPECT(found_in_sched);
}

/* Regression: a received PONG must clear the estimator's ping_in_flight token
 * (the data path drives BDP PINGs) and reset w_keepalive.repeat to the full
 * keepalive interval (jittered). */
T_DECLARE_CASE(test_session_recv_pong_clears_ping_in_flight)
{
	struct xs_fixture fx;
	static const unsigned char payload[MUX_PING_PAYLOAD_SIZE] = { 0 };
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	/* Simulate a probe in flight (sent by keepalive or data path):
	 * payload is all-zero so sent_ns == 0, which matches last_probe_ns. */
	fx.ss.conf.keepalive = 60;
	ev_timer_init(&fx.ss.w_keepalive, xs_timer_cb, 0.0, 15.0);
	fx.ss.w_keepalive.data = &fx.ss;
	fx.ss.estimator.ping_in_flight = true;
	fx.ss.estimator.last_probe_ns = 0;

	/* Build a minimal PONG frame in recvbuf. */
	struct mux_frame *const frame = xs_make_frame(
		&fx.ss.pool, STREAMID_CTRL, 0, MUX_CTRL_PONG, payload,
		sizeof(payload));
	T_CHECK(frame != NULL);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PONG,
	};
	bytebuf_reset(fx.ss.wire.recvbuf);
	memcpy(bytebuf_write_ptr(fx.ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(fx.ss.wire.recvbuf, frame->len);

	mux_session_recv_pong(&fx.ss, &hdr, frame->len);

	const bool no_ping_in_flight = !fx.ss.estimator.ping_in_flight;
	const ev_tstamp keepalive_repeat = fx.ss.w_keepalive.repeat;

	/* Teardown first so a failing assert can't leak the fixture. */
	mux_frame_put(&fx.ss.pool, frame);
	xs_teardown(&fx);

	T_EXPECT(no_ping_in_flight);
	/* Timer repeat must be restored to the keepalive interval, jittered
	 * down into (keepalive * (1 - jitter), keepalive]. */
	T_EXPECT(keepalive_repeat > 48.0 && keepalive_repeat <= 60.0);
}

/* Any received PONG resets w_keepalive.repeat to the keepalive interval,
 * jittered down, regardless of whether a probe was outstanding. */
T_DECLARE_CASE(test_session_recv_pong_resets_keepalive_interval)
{
	struct xs_fixture fx;
	static const unsigned char payload[MUX_PING_PAYLOAD_SIZE] = { 0 };
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	fx.ss.conf.keepalive = 60;
	ev_timer_init(&fx.ss.w_keepalive, xs_timer_cb, 0.0, 60.0);
	fx.ss.w_keepalive.data = &fx.ss;
	fx.ss.estimator.ping_in_flight = false;

	struct mux_frame *const frame = xs_make_frame(
		&fx.ss.pool, STREAMID_CTRL, 0, MUX_CTRL_PONG, payload,
		sizeof(payload));
	T_CHECK(frame != NULL);
	const struct mux_header hdr = {
		.version = MUX_PROTOCOL_VERSION,
		.flags = 0,
		.length = (uint_least16_t)sizeof(payload),
		.stream_id = STREAMID_CTRL,
		.extra = MUX_CTRL_PONG,
	};
	bytebuf_reset(fx.ss.wire.recvbuf);
	memcpy(bytebuf_write_ptr(fx.ss.wire.recvbuf), frame->data, frame->len);
	bytebuf_produce(fx.ss.wire.recvbuf, frame->len);

	mux_session_recv_pong(&fx.ss, &hdr, frame->len);

	const bool no_ping_in_flight = !fx.ss.estimator.ping_in_flight;
	const ev_tstamp keepalive_repeat = fx.ss.w_keepalive.repeat;

	/* Teardown first so a failing assert can't leak the fixture. */
	mux_frame_put(&fx.ss.pool, frame);
	xs_teardown(&fx);

	T_EXPECT(no_ping_in_flight);
	/* Timer repeat must be set to the keepalive interval, jittered down
	 * into (keepalive * (1 - jitter), keepalive]. */
	T_EXPECT(keepalive_repeat > 48.0 && keepalive_repeat <= 60.0);
}

/* The sendbuf head is in-flight while send_blocked (TLS WANT_WRITE);
 * discarding it caused SSL bad-length on retry (bench.py -P 10 --bidir):
 * SSL_write's own contract requires the next call to re-present the
 * identical bytes. The blocked head must survive a discard call when there
 * is a TLS connection to protect. This protection must not
 * extend to plain TCP, which has no such retry contract -- see the sibling
 * test_session_discard_drops_blocked_head_without_tls below. */
T_DECLARE_CASE(test_session_discard_keeps_blocked_inflight_head)
{
#if WITH_TLS
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	T_CHECK(mux_session_send_ctrl(&fx.ss, 5, MUX_FLAG_ACK, 0));
	T_CHECK(fx.ss.wire.sendbuf.head != NULL);

	/* Opaque non-NULL: mux_session_discard_stream_frames only tests tlsconn
	 * for NULL, never dereferences it. */
	fx.ss.wire.tlsconn = (struct tls_connection *)(uintptr_t)1;
	/* Mark the head as in flight; it must survive the discard. */
	fx.ss.wire.send_blocked = true;
	mux_session_discard_stream_frames(&fx.ss, 5);
	const bool head_survives = fx.ss.wire.sendbuf.head != NULL;

	/* Teardown first so a failing assert can't leak the fixture. */
	fx.ss.wire.send_blocked = false;
	fx.ss.wire.tlsconn = NULL;
	xs_teardown(&fx);

	T_EXPECT(head_survives);
#else /* WITH_TLS */
	T_SKIP();
#endif /* WITH_TLS */
}

/* Without a TLS connection (plain TCP, or WITH_TLS=OFF), the
 * send_blocked protection above must not apply -- send(2) has no
 * SSL_write-style "retry with identical bytes" requirement, so a head that
 * never had any bytes accepted (pos == 0) is always safe to drop and
 * replace. Before the fix this frame reached the peer as a stale PUSH
 * immediately ahead of the RST that should have superseded it. */
T_DECLARE_CASE(test_session_discard_drops_blocked_head_without_tls)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}

	T_CHECK(mux_session_send_ctrl(&fx.ss, 5, MUX_FLAG_ACK, 0));
	T_CHECK(fx.ss.wire.sendbuf.head != NULL);

	fx.ss.wire.send_blocked = true;
	mux_session_discard_stream_frames(&fx.ss, 5);
	const bool head_dropped = fx.ss.wire.sendbuf.head == NULL;

	/* Teardown first so a failing assert can't leak the fixture. */
	fx.ss.wire.send_blocked = false;
	xs_teardown(&fx);

	T_EXPECT(head_dropped);
}

/* A per-stream ACK/FIN the frame pool cannot allocate must be retried: the
 * scheduler has already dequeued the stream and nothing else re-arms it, so
 * without a retry the FIN (and any credit grant) is never sent.  The retry
 * rides the coalescing tick. */
T_DECLARE_CASE(test_sched_ctrl_oom_retries_fin_on_coalesce_tick)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}
	struct mux_stream *const s = mux_stream_new(&fx.ss, 1, true);
	T_CHECK(s != NULL);
	T_CHECK(mux_sched_add_stream(&fx.ss, s));
	s->state = STREAM_ESTABLISHED;
	s->rx_eof = true; /* local write-EOF: a FIN is pending */
	mux_sched_wake(&fx.ss, s);

	fx.pool_ctx.fail = true;
	(void)mux_sched_next_data(&fx.ss);
	fx.pool_ctx.fail = false;
	const bool nothing_sent = fx.ss.wire.sendbuf.head == NULL;
	const bool rearmed = s->delay_pending;
	const bool timer_armed = ev_is_active(&fx.ss.sched.w_coalesce);

	ev_invoke(fx.loop, &fx.ss.sched.w_coalesce, EV_TIMER);
	(void)mux_sched_next_data(&fx.ss);
	const enum stream_state state = s->state;
	const struct mux_frame *const head = fx.ss.wire.sendbuf.head;
	const bool frame_sent = head != NULL;
	uint_least8_t flags = 0;
	if (frame_sent) {
		struct mux_header hdr;
		mux_read_header(head->data, &hdr);
		flags = hdr.flags;
	}

	/* Teardown first so a failing assert can't leak the fixture. */
	ev_timer_stop(fx.loop, &fx.ss.sched.w_coalesce);
	xs_teardown(&fx);

	T_EXPECT(nothing_sent);
	T_EXPECT(rearmed);
	T_EXPECT(timer_armed);
	T_EXPECT(frame_sent);
	T_EXPECT_EQ(flags & MUX_FLAG_FIN, MUX_FLAG_FIN);
	T_EXPECT_EQ(state, (enum stream_state)STREAM_FIN_WAIT);
}

static int g_xs_io_events;
static bool g_xs_io_reset;

/* Reads on EV_READ; on ECONNRESET closes the stream as an application would. */
static void
xs_stream_io_cb(struct ev_loop *loop, mux_stream_io *w, const int revents)
{
	(void)loop;
	g_xs_io_events |= revents;
	struct mux_stream *const s = w->stream;
	unsigned char buf[16];
	size_t len = sizeof(buf);
	if (mux_stream_recv(s, buf, &len) != 0 && errno == ECONNRESET) {
		g_xs_io_reset = true;
		mux_stream_close(s);
	}
}

/* A SYN the frame pool cannot allocate is a failed open: a direct-mode
 * application must be told (EV_READ, then ECONNRESET) instead of being left on
 * a silently detached watcher, the stream is counted failed rather than
 * succeeded, and no RST goes out for an ID the peer never saw. */
T_DECLARE_CASE(test_syn_oom_resets_direct_stream_and_counts_failed)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}
	mux_counter failed = 0, succeeded = 0;
	fx.ss.cnt.stream.num_stream_failed = &failed;
	fx.ss.cnt.stream.num_stream_succeeded = &succeeded;
	g_xs_io_events = 0;
	g_xs_io_reset = false;

	struct mux_stream *const s = mux_session_open_stream(&fx.ss);
	T_CHECK(s != NULL);
	const uint_least16_t id = s->id;
	mux_stream_io w;
	mux_stream_io_init(&w, xs_stream_io_cb, s, EV_READ | EV_WRITE);
	T_CHECK(mux_stream_io_start(fx.loop, &w));
	ev_invoke_pending(fx.loop); /* deliver the initial EV_WRITE */
	g_xs_io_events = 0;

	fx.pool_ctx.fail = true;
	mux_sched_drain_lp(&fx.ss);
	fx.pool_ctx.fail = false;

	const bool freed = mux_sched_find_stream(&fx.ss, id) == NULL;
	const bool nothing_sent = fx.ss.wire.sendbuf.head == NULL &&
				  fx.ss.wire.oobbuf.head == NULL;
	const bool unbound = w.stream == NULL;
	const uint_least64_t n_failed = failed;
	const uint_least64_t n_succeeded = succeeded;

	/* Teardown first so a failing assert can't leak the fixture. */
	xs_teardown(&fx);

	T_EXPECT_EQ(g_xs_io_events & EV_READ, EV_READ);
	T_EXPECT(g_xs_io_reset);
	T_EXPECT(unbound);
	T_EXPECT(freed);
	T_EXPECT(nothing_sent);
	T_EXPECT_EQ(n_failed, (uint_least64_t)1);
	T_EXPECT_EQ(n_succeeded, (uint_least64_t)0);
}

/* The socket-mode side of the same failed open: the local client must see the
 * connection reset, not a clean EOF for a connection that never opened. */
T_DECLARE_CASE(test_syn_oom_resets_attached_socket)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}
	int port = 0;
	const int listen_fd = tcp_listen_loopback(&port);
	T_CHECK(listen_fd >= 0);
	const int cli_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(cli_fd >= 0);
	const struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	T_CHECK(connect(cli_fd, (const struct sockaddr *)&sa, sizeof(sa)) == 0);
	const int acc_fd = accept(listen_fd, NULL, NULL);
	T_CHECK(acc_fd >= 0);
	(void)close(listen_fd);

	struct mux_stream *const s = mux_session_open_stream(&fx.ss);
	T_CHECK(s != NULL);
	mux_stream_attach_fd(s, acc_fd); /* the stream owns acc_fd now */

	fx.pool_ctx.fail = true;
	mux_sched_drain_lp(&fx.ss);
	fx.pool_ctx.fail = false;

	struct pollfd pfd = { .fd = cli_fd, .events = POLLIN };
	const int ready = poll(&pfd, 1, 1000);
	unsigned char buf[16];
	const ssize_t n = recv(cli_fd, buf, sizeof(buf), MSG_DONTWAIT);
	const int err = (n < 0) ? errno : 0;
	(void)close(cli_fd);

	/* Teardown first so a failing assert can't leak the fixture. */
	xs_teardown(&fx);

	T_EXPECT_EQ(ready, 1);
	T_EXPECT_EQ(n, (ssize_t)-1);
	T_EXPECT_EQ(err, ECONNRESET);
}

/* Partial-write session ACK accounting: a coalesced sendbuf entry of
 * PW_SUBFRAMES data sub-frames of PW_PAYLOAD bytes each, exactly one
 * MUX_MAX_RECORD, written to a socketpair whose shrunken send buffer accepts
 * only part of it. The peer counts every sub-frame that fully reached it and
 * may acknowledge them before the rest of the entry is written. */
enum {
	PW_PAYLOAD = 8,
	PW_SUBFRAME_SIZE = MUX_FRAME_HEADER_SIZE + PW_PAYLOAD,
	PW_SUBFRAMES = MUX_MAX_RECORD / PW_SUBFRAME_SIZE,
	PW_DRAIN_ROUNDS = 256,
};

static struct mux_frame *
pw_make_coalesced(const struct mux_frame_allocator *restrict pool)
{
	struct mux_frame *const frame =
		mux_frame_get(pool, MUX_MAX_PAYLOAD_SIZE);
	if (frame == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < PW_SUBFRAMES; i++) {
		const struct mux_header hdr = {
			.version = MUX_PROTOCOL_VERSION,
			.flags = MUX_FLAG_PUSH,
			.length = PW_PAYLOAD,
			.stream_id = 1,
			.extra = 0,
		};
		unsigned char *const p = frame->data + i * PW_SUBFRAME_SIZE;
		mux_write_header(p, &hdr);
		memset(p + MUX_FRAME_HEADER_SIZE, (int)(i & 0xff), PW_PAYLOAD);
	}
	frame->len = (size_t)PW_SUBFRAMES * PW_SUBFRAME_SIZE;
	frame->pos = 0;
	return frame;
}

/* Make fds[0] non-blocking with a send buffer too small for one record, and
 * fds[1] non-blocking so the peer side can be drained without waiting. */
static bool pw_shrink_transport(struct xs_fixture *restrict fx)
{
	const int sndbuf = 4096;
	return fcntl(fx->fds[0], F_SETFL, O_NONBLOCK) == 0 &&
	       fcntl(fx->fds[1], F_SETFL, O_NONBLOCK) == 0 &&
	       setsockopt(
		       fx->fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
		       sizeof(sndbuf)) == 0;
}

/* Read everything currently buffered at the peer end; returns the byte count. */
static size_t pw_drain_peer(struct xs_fixture *restrict fx)
{
	unsigned char buf[4096];
	size_t total = 0;
	for (;;) {
		const ssize_t n = read(fx->fds[1], buf, sizeof(buf));
		if (n <= 0) {
			return total;
		}
		total += (size_t)n;
	}
}

/* Flush until the sendbuf is empty and no replay is pending, draining the
 * peer each round; returns the bytes the peer received. */
static size_t pw_flush_all(struct xs_fixture *restrict fx)
{
	size_t total = 0;
	for (int i = 0; i < PW_DRAIN_ROUNDS; i++) {
		total += pw_drain_peer(fx);
		if (fx->ss.wire.sendbuf.head == NULL &&
		    fx->ss.unacked.retransmit_off == SIZE_MAX) {
			break;
		}
		mux_session_on_send(&fx->ss);
	}
	return total + pw_drain_peer(fx);
}

/* Plain TCP: the peer ACKs the sub-frames of a partially written coalesced
 * entry that already reached it. The ACK must trim them instead of being
 * rejected as an overflow (which resets the session), and once the entry
 * completes its remainder is tracked exactly once. */
T_DECLARE_CASE(test_session_ack_covers_partially_written_entry)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}
	T_CHECK(pw_shrink_transport(&fx));
	struct mux_frame *const entry = pw_make_coalesced(&fx.ss.pool);
	T_CHECK(entry != NULL);
	mux_wire_sendbuf_push(&fx.ss, entry);

	mux_session_on_send(&fx.ss);
	const size_t first = pw_drain_peer(&fx);
	const bool partial = fx.ss.wire.sendbuf.head != NULL;
	const size_t acked = first / PW_SUBFRAME_SIZE;
	const bool early_ok = mux_unacked_ack_recv(&fx.ss, acked).ok;
	const size_t early_left = fx.ss.unacked.frames;

	const size_t total = first + pw_flush_all(&fx);
	const size_t tracked = fx.ss.unacked.frames;
	const bool late_ok =
		mux_unacked_ack_recv(&fx.ss, PW_SUBFRAMES - acked).ok;
	const size_t late_left = fx.ss.unacked.frames;
	const size_t late_bytes = fx.ss.unacked.bytes;

	/* Teardown first so a failing assert can't leak the fixture. */
	xs_teardown(&fx);
	const bool no_leak = fx.pool_ctx.alloc_calls == fx.pool_ctx.free_calls;

	T_EXPECT(partial); /* precondition: the socket took only part */
	T_EXPECT(acked > 0); /* ... but at least one whole sub-frame */
	T_EXPECT(early_ok);
	T_EXPECT_EQ(early_left, (size_t)0);
	T_EXPECT_EQ(total, (size_t)PW_SUBFRAMES * PW_SUBFRAME_SIZE);
	T_EXPECT_EQ(tracked, (size_t)PW_SUBFRAMES - acked);
	T_EXPECT(late_ok);
	T_EXPECT_EQ(late_left, (size_t)0);
	T_EXPECT_EQ(late_bytes, (size_t)0);
	T_EXPECT(no_leak);
}

/* Once a partial write commits complete frames, prefix-copy OOM is terminal:
 * reset before processing their ACK, and do not revive send state afterward. */
T_DECLARE_CASE(test_partial_write_prefix_oom_resets_session)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}
	T_CHECK(pw_shrink_transport(&fx));
	struct mux_frame *const entry = pw_make_coalesced(&fx.ss.pool);
	T_CHECK(entry != NULL);
	mux_wire_sendbuf_push(&fx.ss, entry);
	fx.ss.handshake.has_session_id = true;
	fx.pool_ctx.fail = true;
	mux_session_on_send(&fx.ss);
	fx.pool_ctx.fail = false;
	const size_t received = pw_drain_peer(&fx);
	const enum session_state state = fx.ss.state;
	const bool resumed = fx.ss.handshake.has_session_id;
	const bool sendbuf_empty = fx.ss.wire.sendbuf.head == NULL;
	const bool ring_freed = fx.ss.unacked.ring == NULL;
	const size_t tracked = fx.ss.unacked.frames;
	const size_t bytes = fx.ss.unacked.bytes;
	const bool pending = fx.ss.wire.tx_pending || fx.ss.sched.lp_pending;
	const bool socket_closed = fx.ss.w_socket.fd == -1;
	/* reset owns the transport close; the fixture must not close it again. */
	if (socket_closed) {
		fx.fds[0] = -1;
	}
	xs_teardown(&fx);
	const bool no_leak = fx.pool_ctx.alloc_calls == fx.pool_ctx.free_calls;

	T_LOGF("partial-write OOM: peer received %zu bytes (%zu complete frames),"
	       " closed=%d",
	       received, received / PW_SUBFRAME_SIZE, state == SESSION_CLOSED);
	T_EXPECT(received >= PW_SUBFRAME_SIZE);
	T_EXPECT(received < (size_t)PW_SUBFRAMES * PW_SUBFRAME_SIZE);
	T_EXPECT_EQ(state, SESSION_CLOSED);
	T_EXPECT(!resumed);
	T_EXPECT(sendbuf_empty);
	T_EXPECT(ring_freed);
	T_EXPECT_EQ(tracked, (size_t)0);
	T_EXPECT_EQ(bytes, (size_t)0);
	T_EXPECT(!pending);
	T_EXPECT(socket_closed);
	T_EXPECT(no_leak);
}

/* Resume replay: the peer ACKs the sub-frames of a partially written replay
 * copy that already reached it. The replay bound must admit them, and once
 * that copy retires the retransmitted-frame count must match the ring entry
 * the ACK trimmed into, so a later mid-replay ACK is bounded correctly. */
T_DECLARE_CASE(test_session_ack_covers_partially_written_replay_copy)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}
	T_CHECK(pw_shrink_transport(&fx));
	/* Two entries sent on the previous connection, now due for replay; each
	 * is larger than the shrunken send buffer, so neither copy can finish in
	 * the flush that finishes the one before it. */
	for (int i = 0; i < 2; i++) {
		struct mux_frame *const entry = pw_make_coalesced(&fx.ss.pool);
		T_CHECK(entry != NULL);
		mux_unacked_track_sent(&fx.ss, entry);
	}
	T_CHECK(fx.ss.unacked.frames == (size_t)2 * PW_SUBFRAMES);
	unacked_set_replay_off(&fx.ss.unacked, 0);

	mux_session_on_send(&fx.ss);
	size_t total = pw_drain_peer(&fx);
	const bool partial = fx.ss.unacked.retransmit_copy != NULL &&
			     fx.ss.unacked.retransmit_off == 0;
	const size_t acked = total / PW_SUBFRAME_SIZE;
	const bool early_ok = mux_unacked_ack_recv(&fx.ss, acked).ok;
	const size_t early_left = fx.ss.unacked.frames;

	/* Flush until the first copy retires and the second is in flight. */
	for (int i = 0;
	     i < PW_DRAIN_ROUNDS && fx.ss.unacked.retransmit_off == 0; i++) {
		mux_session_on_send(&fx.ss);
		total += pw_drain_peer(&fx);
	}
	const bool second_in_flight = fx.ss.unacked.retransmit_off == 1 &&
				      fx.ss.unacked.retransmit_copy != NULL;
	const size_t retransmitted = fx.ss.unacked.retransmitted_frames;
	/* The rest of the first entry: exactly what has been retransmitted. */
	const bool mid_ok =
		mux_unacked_ack_recv(&fx.ss, PW_SUBFRAMES - acked).ok;
	const size_t mid_left = fx.ss.unacked.frames;

	total += pw_flush_all(&fx);
	const bool replay_done = fx.ss.unacked.retransmit_off == SIZE_MAX;
	const bool late_ok = mux_unacked_ack_recv(&fx.ss, PW_SUBFRAMES).ok;
	const size_t late_left = fx.ss.unacked.frames;

	/* Teardown first so a failing assert can't leak the fixture. */
	xs_teardown(&fx);
	const bool no_leak = fx.pool_ctx.alloc_calls == fx.pool_ctx.free_calls;

	T_EXPECT(partial); /* precondition: the socket took only part */
	T_EXPECT(acked > 0); /* ... but at least one whole sub-frame */
	T_EXPECT(early_ok);
	T_EXPECT_EQ(early_left, (size_t)2 * PW_SUBFRAMES - acked);
	T_EXPECT(second_in_flight);
	T_EXPECT_EQ(retransmitted, (size_t)PW_SUBFRAMES - acked);
	T_EXPECT(mid_ok);
	T_EXPECT_EQ(mid_left, (size_t)PW_SUBFRAMES);
	T_EXPECT_EQ(total, (size_t)2 * PW_SUBFRAMES * PW_SUBFRAME_SIZE);
	T_EXPECT(replay_done);
	T_EXPECT(late_ok);
	T_EXPECT_EQ(late_left, (size_t)0);
	T_EXPECT(no_leak);
}

/* Throughput benchmark */

enum {
	/* Per-round drain timeout.  The bench runner caps each calibration round
	 * at roughly one second of transfer, so 60s is ample headroom. */
	BENCH_STREAM_TIMEOUT_MS = 60000,
};

/* Establish a TCP pair over loopback (matching the tls_test benches).
 * Returns two connected blocking fds (out[0]=accepted, out[1]=connected)
 * with TCP_NODELAY, or false on failure. */
static bool bench_loopback_pair(int out[2])
{
	out[0] = out[1] = -1;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		return false;
	}
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	socklen_t salen = sizeof(sa);
	if (bind(lfd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(lfd, 1) != 0 ||
	    getsockname(lfd, (struct sockaddr *)&sa, &salen) != 0) {
		(void)close(lfd);
		return false;
	}
	const int cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		(void)close(lfd);
		return false;
	}
	const int one = 1;
	(void)setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (connect(cfd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		(void)close(cfd);
		(void)close(lfd);
		return false;
	}
	const int afd = accept(lfd, NULL, NULL);
	(void)close(lfd);
	if (afd < 0) {
		(void)close(cfd);
		return false;
	}
	(void)setsockopt(afd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	out[0] = afd;
	out[1] = cfd;
	return true;
}

/* Connect two mux sessions over loopback TCP with TLS (AES-128-GCM) when
 * WITH_TLS.  Transport and cipher match the tls_test benches for comparable
 * GiB/s figures; fixture_teardown also frees the TLS contexts. */
static int bench_fixture_setup(struct mux_test_fixture *restrict fx)
{
	*fx = (struct mux_test_fixture){ 0 };
	fx->listen_fd_cleanup = -1;
	fx->break_transport_sp = -1;

	fx->loop = ev_loop_new(EVFLAG_AUTO);
	if (fx->loop == NULL) {
		return -1;
	}

	int fds[2] = { -1, -1 };
#if WITH_TLS
	struct tls_connection *srv_conn = NULL;
#endif
	if (!bench_loopback_pair(fds)) {
		goto fail;
	}
	if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
		goto fail;
	}

#if WITH_TLS
	{
		if (!test_tls_contexts_new(&fx->srv_tlsctx, &fx->cli_tlsctx)) {
			goto fail;
		}
		/* tls_server wraps the server fd; the server session takes
		 * ownership of both the fd and this connection below. */
		srv_conn = tls_server(fx->srv_tlsctx, fds[0]);
		if (srv_conn == NULL) {
			goto fail;
		}
	}
#endif /* WITH_TLS */

	/* Throughput config: nodelay (iperf-style) + large stream_window to
	 * keep grants above the 2-frame immediate-ACK threshold and avoid
	 * deferring window updates to the coalescing timer. */
	struct mux_session_config conf = make_cli_conf(true);
	conf.stream_window = 256;
#if WITH_TLS
	/* Socket-offloaded TLS on both ends: the pre-wrapped server connection owns
	 * fds[0] and the client's tlsctx is offloaded onto fds[1], so the mux wire
	 * must not also do buffered I/O on those fds (doing so steals handshake bytes
	 * from the TLS library).  readahead matches the tlsctx read-ahead above so
	 * the offloaded recv path measures the high-throughput config. */
	conf.tls_socket_offload = true;
	conf.readahead = 128 * 1024;
#endif
	unsigned char srv_sid[MUX_SESSION_ID_LEN];
	unsigned char cli_sid[MUX_SESSION_ID_LEN];
	proto_session_id_new(srv_sid);
	proto_session_id_new(cli_sid);

	/* Server: inbound session on fds[0]; mux_start begins the handshake. */
	const struct mux_session_opts srv_opts = {
		.callbacks = &g_srv_callbacks,
		.userdata = fx,
		.conf = &conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = fds[0],
		.id = srv_sid,
#if WITH_TLS
		.conn = srv_conn,
#endif
	};
	fx->srv = mux_new(fx->loop, &srv_opts);
	if (fx->srv == NULL) {
		goto fail;
	}
	fds[0] = -1; /* owned by fx->srv (which now also owns srv_conn) */
	mux_start(fx->srv);

	/* Client: outbound session (fd=-1) with the peer end attached, which
	 * sends the hello and drives the handshake to completion. */
	const struct mux_session_opts cli_opts = {
		.callbacks = &g_cli_callbacks,
		.userdata = fx,
		.conf = &conf,
		.pool = { test_frame_alloc, test_frame_free, NULL },
		.fd = -1,
		.id = cli_sid,
#if WITH_TLS
		.tlsctx = fx->cli_tlsctx,
#endif
	};
	fx->cli = mux_new(fx->loop, &cli_opts);
	if (fx->cli == NULL) {
		goto fail;
	}
	mux_start(fx->cli);
	mux_attach_fd(fx->cli, fds[1]);
	fds[1] = -1; /* owned by fx->cli */
	return 0;

fail:
	if (fds[0] >= 0) {
		(void)close(fds[0]);
	}
	if (fds[1] >= 0) {
		(void)close(fds[1]);
	}
#if WITH_TLS
	/* srv_conn is owned by fx->srv once it exists; otherwise free it here. */
	if (fx->srv == NULL && srv_conn != NULL) {
		tls_conn_free(srv_conn);
	}
#endif
	if (fx->srv != NULL) {
		mux_close(fx->srv);
		fx->srv = NULL;
	}
	fixture_free_tls(fx);
	ev_loop_destroy(fx->loop);
	fx->loop = NULL;
	return -1;
}

#if WITH_TLS
/* Satisfied once the server session has either closed or suspended, the two
 * ways it can leave ESTABLISHED when the client ends the transport. */
static int pred_srv_closed_or_suspended(void *ptr)
{
	const struct mux_test_fixture *restrict fx = ptr;
	return (fx->srv_closed || fx->srv_suspended) ? 1 : 0;
}

/* An idle-closed client leaves nothing suspended on a TLS server: the close
 * carries a close_notify, so the server closes its side instead of holding a
 * session for a resume the client can no longer request.  Runs over the
 * socket-offloaded TLS pair the throughput bench builds, where an abortive
 * close reached the server as an unexpected EOF and suspended it. */
T_DECLARE_CASE(test_idle_close_releases_tls_server)
{
	struct mux_test_fixture fx;
	if (bench_fixture_setup(&fx) != 0) {
		T_FATAL("bench_fixture_setup failed");
		return;
	}
	fx.cli->conf.idle_timeout = 1;
	fx.cli->w_idle_timeout.repeat = 0.01;

	const bool established =
		wait_until(&fx, 10.0, pred_established, &fx) == 0;
	const bool srv_done =
		established &&
		wait_until(&fx, 10.0, pred_srv_closed_or_suspended, &fx) == 0;
	const bool cli_done =
		srv_done && wait_until(&fx, 10.0, pred_cli_closed, &fx) == 0;
	const bool srv_closed = fx.srv_closed;
	const bool srv_suspended = fx.srv_suspended;

	/* Teardown first so a failing assert can't leak the fixture; it frees
	 * the TLS contexts after the connections that reference them. */
	fixture_teardown(&fx);

	T_EXPECT(established);
	T_EXPECT(srv_done);
	T_EXPECT(cli_done);
	T_EXPECT(srv_closed);
	T_EXPECT(!srv_suspended);
}
#endif /* WITH_TLS */

/* Cumulative-drain predicate for the throughput bench's persistent stream.
 * Unlike pred_drain_done it does not wait for a FIN: the stream is reused across
 * calibration rounds and stays open, so the sink only ever counts recv_total. */
static int pred_drain_total(void *ptr)
{
	const struct drain_done_ctx *restrict ctx = ptr;
	if (ctx->fx->n_accepted < 1) {
		return 0;
	}
	const struct test_stream *restrict ts = ctx->fx->accepted[0];
	if (ts->got_error) {
		return -1;
	}
	return ts->recv_total >= ctx->expected_total ? 1 : 0;
}

/* Persistent state for bench_mux_stream_throughput.  The fixture, the single
 * client stream and its send buffer are created once (bench_mux_setup) and
 * reused across calibration rounds, then reclaimed at process exit. */
static struct mux_test_fixture bench_mux_fx;
static struct test_stream *bench_mux_ts;
static unsigned char *bench_mux_send_buf;
static uint_fast64_t bench_mux_expected;

static void bench_mux_teardown(void)
{
	free(bench_mux_send_buf);
	bench_mux_send_buf = NULL;
	fixture_teardown(&bench_mux_fx);
	slog_setlevel(LOG_LEVEL_DEBUG);
}

static void bench_mux_setup(void)
{
	/* Silence setup and per-frame logging so it neither clutters the bench
	 * output nor dominates the measured transfer. */
	slog_setlevel(LOG_LEVEL_SILENCE);
	T_CHECK(bench_fixture_setup(&bench_mux_fx) == 0);
	T_CHECK(wait_until(
			&bench_mux_fx, ESTABLISH_TIMEOUT_MS / 1000.0,
			pred_established, &bench_mux_fx) == 0);

	/* Server accepts the stream as a discard sink. */
	bench_mux_fx.accept_mode = ACCEPT_DRAIN;

	bench_mux_send_buf = malloc(CHUNK_SIZE);
	T_CHECK(bench_mux_send_buf != NULL);
	fill_payload(bench_mux_send_buf, CHUNK_SIZE, 0x5A);

	struct mux_stream *const s = mux_stream_open(bench_mux_fx.cli);
	T_CHECK(s != NULL);
	bench_mux_ts = test_stream_new(&bench_mux_fx, s);
	T_CHECK(bench_mux_ts != NULL);
	bench_mux_fx.cli_streams[bench_mux_fx.n_cli_streams++] = bench_mux_ts;
	bench_mux_ts->send_data = bench_mux_send_buf;
	bench_mux_ts->send_len = CHUNK_SIZE;
	bench_mux_ts->send_cyclic = true;
	/* The stream is reused across rounds: never half-close, so the server's
	 * drain sink keeps counting into recv_total without a FIN. */
	bench_mux_ts->send_shutdown_on_drain = false;

	T_CHECK(atexit(bench_mux_teardown) == 0);
}

/* One-directional single-stream throughput over mux-over-TLS (loopback NIC),
 * matching the tls_test benches' transport and cipher so the figures are
 * directly comparable.  Each op streams one CHUNK_SIZE payload that the server
 * drains and discards (set via T_BENCH_SET_BYTES for the throughput column). */
T_DECLARE_BENCH(bench_mux_stream_throughput)
{
	static bool ready = false;
	if (!ready) {
		bench_mux_setup();
		ready = true;
	}
	T_BENCH_SET_BYTES(CHUNK_SIZE);

	/* Queue N more chunks onto the persistent stream and wait for the server
	 * to drain them all.  send_remaining and the expected total accumulate, so
	 * the cyclic sender simply resumes where the previous round left off. */
	const uint_fast64_t round_bytes = _b_->N * (uint_fast64_t)CHUNK_SIZE;
	bench_mux_expected += round_bytes;
	bench_mux_ts->send_remaining += round_bytes;
	struct drain_done_ctx ctx = {
		.fx = &bench_mux_fx,
		.expected_total = bench_mux_expected,
	};
	mux_stream_io_start(bench_mux_fx.loop, &bench_mux_ts->w_io);
	T_CHECK(wait_until(
			&bench_mux_fx, BENCH_STREAM_TIMEOUT_MS / 1000.0,
			pred_drain_total, &ctx) == 0);
}

/* mux_stream_io_modify(): newly-added events must immediately deliver any
 * already-satisfied condition (level-triggered semantics) and never re-deliver
 * events that were already registered. */
T_DECLARE_CASE(test_mux_stream_io_modify_delivers_ready_conditions)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	ss.loop = loop;

	struct mux_stream s = {
		.state = STREAM_ESTABLISHED,
		.session = &ss,
		.send_window = 64, /* stream_read_credit_avail() > 0 */
	};
	s.recvbuf = bytebuf_new(ss.max_payload);
	T_CHECK(s.recvbuf != NULL);

	mux_stream_io watcher;
	mux_stream_io_init(&watcher, mux_api_cb, &s, EV_NONE);
	watcher.loop = loop;
	s.direct.w_io = &watcher;
	s.is_direct = true;

	/* Adding EV_WRITE to an established stream with send credit delivers an
	 * immediate EV_WRITE; EV_READ is not ready (empty recvbuf, ESTABLISHED). */
	ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ | EV_WRITE);
	int fed = ev_clear_pending(loop, &watcher);
	const bool write_ready = (fed & EV_WRITE) != 0;
	const bool read_not_ready = (fed & EV_READ) == 0;

	/* Re-modifying with no newly-added bits delivers nothing. */
	ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ | EV_WRITE);
	const int cleared_no_newbits = ev_clear_pending(loop, &watcher);

	/* Buffered receive data makes EV_READ immediately ready on re-add, even
	 * on an otherwise-open (ESTABLISHED) stream. */
	watcher.events = EV_NONE;
	const unsigned char rxbyte = 0;
	memcpy(bytebuf_write_ptr(s.recvbuf), &rxbyte, 1);
	bytebuf_produce(s.recvbuf, 1);
	ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ);
	fed = ev_clear_pending(loop, &watcher);
	const bool read_ready_buffered = (fed & EV_READ) != 0;
	bytebuf_consume(s.recvbuf, 1);

	/* A half-closed (CLOSE_WAIT) stream signals readable EOF: EV_READ is
	 * immediately ready even with an empty recvbuf. */
	watcher.events = EV_NONE;
	s.state = STREAM_CLOSE_WAIT;
	ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ);
	fed = ev_clear_pending(loop, &watcher);
	const bool read_ready_closewait = (fed & EV_READ) != 0;
	s.state = STREAM_ESTABLISHED;

	/* EV_WRITE is suppressed when read credit is exhausted, even on a
	 * send-eligible state: feeding a spurious EV_WRITE with zero credit would
	 * busy-loop the caller. EV_READ is likewise not ready (empty recvbuf,
	 * ESTABLISHED), so nothing is delivered. */
	watcher.events = EV_NONE;
	const uint_least32_t saved_send_window = s.send_window;
	s.send_window = 0; /* stream_read_credit_avail() == 0 */
	ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ | EV_WRITE);
	const int cleared_no_credit = ev_clear_pending(loop, &watcher);
	s.send_window = saved_send_window;

	/* A detached watcher (w->stream == NULL) delivers nothing. */
	watcher.events = EV_NONE;
	watcher.stream = NULL;
	ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ | EV_WRITE);
	const int cleared_detached = ev_clear_pending(loop, &watcher);
	watcher.stream = &s;

	/* A received RST makes EV_READ immediately ready when it is re-added. */
	watcher.events = EV_NONE;
	s.rst_received = true;
	ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ);
	fed = ev_clear_pending(loop, &watcher);
	const bool read_ready_rst = (fed & EV_READ) != 0;

	/* Clean up before the asserts so a failing check can't leak. */
	bytebuf_free(s.recvbuf);
	ev_loop_destroy(loop);

	T_EXPECT(write_ready);
	T_EXPECT(read_not_ready);
	T_EXPECT_EQ(cleared_no_newbits, 0);
	T_EXPECT(read_ready_buffered);
	T_EXPECT(read_ready_closewait);
	T_EXPECT_EQ(cleared_no_credit, 0);
	T_EXPECT_EQ(cleared_detached, 0);
	T_EXPECT(read_ready_rst);
}

/* mux_stream_io_modify(): a pending fed event for a bit the caller removes must
 * not survive the modify (mirrors libev's ev_io_modify clearing pending). */
T_DECLARE_CASE(test_mux_stream_io_modify_removed_bit_clears_pending)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	ss.loop = loop;

	struct mux_stream s = {
		.state = STREAM_ESTABLISHED,
		.session = &ss,
		.send_window = 64,
	};
	s.recvbuf = bytebuf_new(ss.max_payload);
	T_CHECK(s.recvbuf != NULL);

	mux_stream_io watcher;
	mux_stream_io_init(&watcher, mux_api_cb, &s, EV_READ | EV_WRITE);
	watcher.loop = loop;
	s.direct.w_io = &watcher;
	s.is_direct = true;

	/* Stage a pending EV_WRITE (as the mux layer's ev_feed_event would), then
	 * drop EV_WRITE from the watched set: the stale pending must be dropped. */
	ev_feed_event(loop, &watcher, EV_WRITE);
	mux_stream_io_modify(loop, &watcher, EV_READ);
	const int after_remove = ev_clear_pending(loop, &watcher);

	/* A pending event for a still-watched bit must survive an unrelated modify
	 * (removing nothing). */
	ev_feed_event(loop, &watcher, EV_READ);
	mux_stream_io_modify(loop, &watcher, EV_READ);
	const int kept_read = ev_clear_pending(loop, &watcher);

	bytebuf_free(s.recvbuf);
	ev_loop_destroy(loop);

	T_EXPECT_EQ(after_remove & EV_WRITE, 0);
	T_EXPECT((kept_read & EV_READ) != 0);
}

/* mux_stream_shutdown() ends a direct stream's writability at once, in every
 * send-capable state, not only once its FIN has left: mux_stream_send() fails
 * with EINVAL, no path reports EV_WRITE any more, and an EV_WRITE fed before
 * the shutdown is dropped while a pending EV_READ survives. */
T_DECLARE_SUBCASE(
	direct_shutdown_ends_writability, const enum stream_state state)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	int fds[2] = { -1, -1 };
	struct ev_loop *const loop = ev_loop_new(EVFLAG_AUTO);
	T_CHECK(loop != NULL);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	ss.loop = loop;
	ss.wire.rx_open = true;
	ev_io_init(&ss.w_socket, mux_api_io_cb, fds[0], EV_READ);
	ss.w_socket.data = &ss;
	mux_sched_init(&ss);

	struct mux_stream s = {
		.state = state,
		.session = &ss,
		.send_window = 64, /* stream_read_credit_avail() > 0 */
	};
	s.recvbuf = bytebuf_new(ss.max_payload);
	T_CHECK(s.recvbuf != NULL);

	mux_stream_io watcher;
	mux_stream_io_init(&watcher, mux_api_cb, &s, EV_READ | EV_WRITE);
	watcher.loop = loop;
	watcher.active = 1;
	s.direct.w_io = &watcher;
	s.is_direct = true;

	/* An EV_WRITE and an EV_READ are both pending when the application
	 * half-closes; the FIN has not left, so the state is unchanged. */
	ev_feed_event(loop, &watcher, EV_READ | EV_WRITE);
	mux_stream_shutdown(&s);
	const enum stream_state state_after = s.state;
	const int pending = ev_clear_pending(loop, &watcher);

	unsigned char payload[] = { 1, 2, 3 };
	size_t len = sizeof(payload);
	errno = 0;
	const int send_ret = mux_stream_send(&s, payload, &len);
	const int send_errno = errno;
	const bool queue_empty = s.send_queue.head == NULL;

	/* Neither a credit notification nor re-adding EV_WRITE reports it. */
	mux_stream_notify_recv(&s);
	const int fed_notify = ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ);
	(void)ev_clear_pending(loop, &watcher);
	mux_stream_io_modify(loop, &watcher, EV_READ | EV_WRITE);
	const int fed_modify = ev_clear_pending(loop, &watcher);

	/* Clean up before the asserts so a failing check can't leak. */
	mux_frame_list_clear(&s.send_queue, &ss.pool);
	bytebuf_free(s.recvbuf);
	(void)close(fds[0]);
	(void)close(fds[1]);
	ev_loop_destroy(loop);

	T_EXPECT_EQ(state_after, state);
	T_EXPECT_EQ(pending & EV_WRITE, 0);
	T_EXPECT((pending & EV_READ) != 0);
	T_EXPECT_EQ(send_ret, -1);
	T_EXPECT_EQ(send_errno, EINVAL);
	T_EXPECT(queue_empty);
	T_EXPECT_EQ(fed_notify & EV_WRITE, 0);
	T_EXPECT_EQ(fed_modify & EV_WRITE, 0);
}

T_DECLARE_CASE(test_mux_stream_shutdown_ends_direct_writability)
{
	T_CALL_SUBCASE(direct_shutdown_ends_writability, STREAM_ESTABLISHED);
	T_CALL_SUBCASE(direct_shutdown_ends_writability, STREAM_CLOSE_WAIT);
}

/* mux_transport_discard(): closes the detached transport's fd and clears it. */
T_DECLARE_CASE(test_mux_transport_discard_closes_fd)
{
	int fds[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct mux_transport transport = {
		.fd = fds[0],
		.connect_started = 0,
#if WITH_TLS
		.tlsconn = NULL,
#endif
	};

	mux_transport_discard(&transport);

	const int transport_fd = transport.fd;
	const bool fd_closed = fcntl(fds[0], F_GETFD) == -1 && errno == EBADF;

	/* Close the surviving fd before the asserts so a failing check can't leak. */
	(void)close(fds[1]);

	T_EXPECT_EQ(transport_fd, -1);
	T_EXPECT(fd_closed);
}

/* mux_transport_reattach(): undoes mux_transport_detach() field for field --
 * the fd with its preserved event mask on a still-stopped watcher, the peer
 * identity and the TLS connection moved back, the transport left owning
 * nothing -- while the copied connect_started and reject_inbound stay put. */
T_DECLARE_CASE(test_mux_transport_reattach_undoes_detach)
{
	struct xs_fixture fx;
	if (xs_setup(&fx) != 0) {
		T_FATAL("xs_setup failed");
		return;
	}
	const int fd = fx.fds[0];
	char *const identity = strdup("reattach-peer");
	if (identity == NULL) {
		xs_teardown(&fx);
		T_FATAL("strdup failed");
		return;
	}
	fx.ss.handshake.peer_identity = identity;
	fx.ss.handshake.peer_rejects_inbound_streams = true;
	fx.ss.connect_started = 42;
#if WITH_TLS
	/* Opaque non-NULL: detach and reattach only move the pointer. */
	struct tls_connection *const tlsconn =
		(struct tls_connection *)(uintptr_t)1;
	fx.ss.wire.tlsconn = tlsconn;
#endif
	ev_io_stop(fx.loop, &fx.ss.w_socket);
	ev_io_set(&fx.ss.w_socket, fd, EV_READ | EV_WRITE);
	ev_io_start(fx.loop, &fx.ss.w_socket);

	struct mux_transport transport;
	mux_transport_detach(&fx.ss, &transport);
	const bool detached =
		transport.fd == fd && transport.peer_identity == identity &&
		transport.reject_inbound && transport.connect_started == 42 &&
		fx.ss.w_socket.fd == -1 &&
		fx.ss.handshake.peer_identity == NULL;
#if WITH_TLS
	const bool tls_detached =
		transport.tlsconn == tlsconn && fx.ss.wire.tlsconn == NULL;
#endif

	mux_transport_reattach(&fx.ss, &transport);
	const bool fd_restored = fx.ss.w_socket.fd == fd;
	const int events = fx.ss.w_socket.events & (EV_READ | EV_WRITE);
	const bool watcher_stopped = !ev_is_active(&fx.ss.w_socket);
	const bool identity_restored =
		fx.ss.handshake.peer_identity == identity;
	const bool copies_kept = fx.ss.handshake.peer_rejects_inbound_streams &&
				 fx.ss.connect_started == 42;
	const bool transport_emptied =
		transport.fd == -1 && transport.peer_identity == NULL;
#if WITH_TLS
	const bool tls_restored =
		fx.ss.wire.tlsconn == tlsconn && transport.tlsconn == NULL;
	fx.ss.wire.tlsconn = NULL;
#endif

	/* Teardown first so a failing assert can't leak the fixture. */
	free(fx.ss.handshake.peer_identity);
	fx.ss.handshake.peer_identity = NULL;
	xs_teardown(&fx);

	T_EXPECT(detached);
	T_EXPECT(fd_restored);
	T_EXPECT_EQ(events, EV_READ | EV_WRITE);
	T_EXPECT(watcher_stopped);
	T_EXPECT(identity_restored);
	T_EXPECT(copies_kept);
	T_EXPECT(transport_emptied);
#if WITH_TLS
	T_EXPECT(tls_detached);
	T_EXPECT(tls_restored);
#endif
}

static bool set_callbacks_probe_on_accept(
	void *data, const struct mux_session *ss, struct mux_stream *s)
{
	(void)data;
	(void)ss;
	(void)s;
	return false;
}

/* mux_set_callbacks(): replaces the whole callback table by value. */
T_DECLARE_CASE(test_mux_set_callbacks_replaces_callback_table)
{
	struct frame_pool_ctx pool_ctx = { 0 };
	struct mux_session ss = make_session(&pool_ctx);
	ss.callbacks = g_cli_callbacks;

	struct mux_callbacks probe = g_cli_callbacks;
	probe.on_accept = set_callbacks_probe_on_accept;
	mux_set_callbacks(&ss, &probe);

	T_EXPECT(ss.callbacks.on_accept == set_callbacks_probe_on_accept);
	T_EXPECT(ss.callbacks.on_event == g_cli_callbacks.on_event);
}

static const struct testing_suite suite[] = {
	T_CASE(test_establish),
	T_CASE(test_send_recv_small),
	T_CASE(test_idle_scheduler_stops_while_sendbuf_blocked),
	T_CASE(test_retransmit_excludes_lifecycle_drain),
	T_CASE(test_nagle_releases_queued_small_frame_on_ack),
	T_CASE(test_send_recv_large),
	T_CASE(test_half_close),
	T_CASE(test_rst_on_unread_data),
	T_CASE(test_multi_stream),
	T_CASE(test_server_open_send_recv),
	T_CASE(test_client_open_server_sends_first),
	T_CASE(test_graceful_close_server_initiated),
	T_CASE(test_simultaneous_close),
	T_CASE(test_rst_from_client),
	T_CASE(test_closed_stream_rsts_peer_sending_without_fin),
	T_CASE(test_rst_stream_kept_until_close),
	T_CASE(test_active_open_shutdown_before_synack),
	T_CASE(test_socket_mode_relay),
	T_CASE(test_socket_mode_abort),
	T_CASE(test_socket_mode_attach_after_synack),
	T_CASE(test_socket_mode_attach_after_peer_fin),
	T_CASE(test_io_start_after_synack),
	T_CASE(test_close_before_attach_completes),
	T_CASE(test_close_before_start_refuses_accepted),
	T_CASE(test_shutdown_graceful),
	T_CASE(test_shutdown_keeps_held_direct_stream),
	T_CASE(test_drain_rst_keeps_held_direct_stream),
	T_CASE(test_shutdown_keeps_unattached_stream),
	T_CASE(test_shutdown_rejects_deferred_io_start),
	T_CASE(test_shutdown_unattached_stream_close_frees),
	T_CASE(test_rst_keeps_unattached_stream_past_tombstone),
	T_CASE(test_rst_direct_handle_excluded_from_outbound_quota_and_drain),
	T_CASE(test_rst_unattached_handle_excluded_from_outbound_quota_and_drain),
	T_CASE(test_rst_direct_handle_excluded_from_inbound_quota_and_drain),
	T_CASE(test_rst_unattached_handle_excluded_from_inbound_quota_and_drain),
	T_CASE(test_shutdown_before_handshake_closes_synchronously),
	T_CASE(test_interop_i1_non_syn_unknown_stream),
	T_CASE(test_interop_i2_close_wait_push),
	T_CASE(test_interop_i3_ack_fin_credit),
	T_CASE(test_interop_i4_stream_id_parity),
	T_CASE(test_interop_i5_duplicate_syn),
	T_CASE(test_interop_i6_fast_open_16384_recv),
	T_CASE(test_interop_i6_fast_open_16384_send),
	T_CASE(test_interop_i7_fin_then_data),
	T_CASE(test_interop_i8_rst_then_non_rst),
	T_CASE(test_interop_i9_reserved_flag),
	T_CASE(test_interop_i10_hello_version_mismatch),
	T_CASE(test_interop_i11_ping_pong_echo),
	T_CASE(test_interop_i12_unknown_keepalive_subtype),
	T_CASE(test_interop_i13_invalid_syn_flags),
	T_CASE(test_interop_i14_reserved_stream0_frame),
	T_CASE(test_lossymux_datagram_roundtrip),
	T_CASE(test_lossymux_inactive_unless_both_offer),
	T_CASE(test_transport_loss_suspends_with_idle_timeout),
	T_CASE(test_idle_close_is_graceful),
	T_CASE(test_live_reload_enables_idle_close),
	T_CASE(test_connected_callback_shutdown_keeps_timeout_stopped),
#if WITH_TLS
	T_CASE(test_idle_close_releases_tls_server),
#endif
	T_CASE(test_resume_idle),
	T_CASE(test_resume_preserves_drain),
	T_CASE(test_resume_preserves_client_drain),
	T_CASE(test_resume_retransmit),
	T_CASE(test_resume_stream_transparent),
	T_CASE(test_resume_stream_unacked_retransmit),
	T_CASE(test_resume_handshake_transport_lost),
	T_CASE(test_resume_declined_after_reattach),
	T_CASE(test_resume_declined_keeps_held_direct_stream),
	T_CASE(test_tls_session_memory_transport),
	T_CASE(test_tls_session_socket_offload),
	T_CASE(test_nodelay_reverse_large),
	T_CASE(test_bdp_auto_stream_window_updated_by_pong),
	T_CASE(test_bdp_session_window_grows_from_ack_sample_only),
	T_CASE(test_bdp_manual_window_mode_no_estimator_effect),
	T_CASE(test_bdp_auto_session_window_without_auto_stream_window),
	T_CASE(test_bdp_auto_session_window_tracks_peer_stream_window),
	T_CASE(test_bdp_control_only_no_cycle),
	T_CASE(test_bdp_ping_queued_before_send_progress),
	T_CASE(test_bdp_ping_sent),
	T_CASE(test_bdp_stop_halves_stream_window),
	T_CASE(test_send_queue_saturates_read_credit),
	T_CASE(test_stream_send_direct_mode_updates_send_buffered_frames),
	T_CASE(test_drain_rejects_new_streams),
	T_CASE(test_drain_refuses_peer_syn),

	T_CASE(test_mux_state_maps_internal_states),
	T_CASE(test_mux_state_closing_is_neither_usable_nor_attachable),
	T_CASE(test_mux_peer_addr_and_window_accessors),
	T_CASE(test_mux_stream_send_rejects_invalid_state),
	T_CASE(test_mux_stream_send_queues_payload),
	T_CASE(test_mux_stream_recv_reports_eagain_and_reset),
	T_CASE(test_mux_stream_io_stop_clears_stream_binding),
	T_CASE(test_mux_stream_io_modify_delivers_ready_conditions),
	T_CASE(test_mux_stream_io_modify_removed_bit_clears_pending),
	T_CASE(test_mux_stream_shutdown_ends_direct_writability),
	T_CASE(test_mux_transport_discard_closes_fd),
	T_CASE(test_mux_transport_reattach_undoes_detach),
	T_CASE(test_mux_set_callbacks_replaces_callback_table),
	T_CASE(test_session_ack_trim_leaves_estimator_alone),
	T_CASE(test_session_open_stream_enforces_limits),
	T_CASE(test_session_open_stream_success_sets_default_send_window),
	T_CASE(test_session_recv_pong_clears_ping_in_flight),
	T_CASE(test_session_recv_pong_resets_keepalive_interval),
	T_CASE(test_session_discard_keeps_blocked_inflight_head),
	T_CASE(test_session_discard_drops_blocked_head_without_tls),
	T_CASE(test_sched_ctrl_oom_retries_fin_on_coalesce_tick),
	T_CASE(test_syn_oom_resets_direct_stream_and_counts_failed),
	T_CASE(test_syn_oom_resets_attached_socket),
	T_CASE(test_session_ack_covers_partially_written_entry),
	T_CASE(test_partial_write_prefix_oom_resets_session),
	T_CASE(test_session_ack_covers_partially_written_replay_copy),
	/* Opt-in throughput benchmark (mux-over-TLS, loopback NIC); skipped by the
	 * default run.  Select with `--bench <ere>` or TESTING_BENCH. */
	T_BENCH(bench_mux_stream_throughput),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	T_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	slog_setoutput(SLOG_OUTPUT_STREAM, io_filewriter(stderr));
	slog_setlevel(LOG_LEVEL_DEBUG);

	return testing_main(argc, argv, suite);
}
