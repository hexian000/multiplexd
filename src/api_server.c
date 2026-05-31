/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_server.h"

#include "conf.h"
#include "listener.h"
#include "server.h"
#include "tunnel.h"
#include "util.h"

#include "net/http.h"
#include "net/url.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"
#include "utils/formats.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <strings.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { HTTP_MAX_ENTITY = 8192 };

/* Inactivity timeout in seconds */
#define API_TIMEOUT 30.0

enum api_state {
	STATE_RECEIVE,
	STATE_RESPOND,
};

struct api_ctx {
	struct server *s;
	enum api_state state;
	int fd;
	ev_io w_recv, w_send;
	ev_timer w_timeout;
	struct http_message msg;
	/* current parse position in rbuf */
	char *next;
	bool hdr_done : 1;
	bool keepalive : 1;
	/* copy of Connection: request header value */
	char connection[32];
	/* bytes of wbuf already sent */
	size_t wpos;
	/* parsed Content-Length from the request; 0 when absent */
	size_t content_length;
	struct {
		BUFFER_HDR;
		unsigned char data[HTTP_MAX_ENTITY];
	} rbuf;
	struct {
		BUFFER_HDR;
		unsigned char data[HTTP_MAX_ENTITY];
	} wbuf;
	struct vbuffer *cbuf;
};

static void api_ctx_free(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);
	ev_timer_stop(loop, &ctx->w_timeout);
	if (ctx->fd != -1) {
		CLOSE_FD(ctx->fd);
	}
	VBUF_FREE(ctx->cbuf);
	free(ctx);
}

/* Resets the context to receive the next request on a kept-alive connection. */
static void api_ctx_reset(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	BUF_RESET(ctx->rbuf);
	ctx->rbuf.data[0] = '\0';
	ctx->next = (char *)ctx->rbuf.data;
	ctx->msg = (struct http_message){ 0 };
	ctx->hdr_done = false;
	ctx->keepalive = false;
	ctx->connection[0] = '\0';
	ctx->content_length = 0;
	BUF_RESET(ctx->wbuf);
	VBUF_RESET(ctx->cbuf);
	ctx->wpos = 0;
	ctx->state = STATE_RECEIVE;
	ev_io_stop(loop, &ctx->w_send);
	ev_timer_again(loop, &ctx->w_timeout);
	ev_io_start(loop, &ctx->w_recv);
}

#define FORMAT_DURATION(name, value)                                           \
	char name[16];                                                         \
	(void)format_duration(name, sizeof(name), (value))

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (double)(value))

static const char *server_modestr(const struct config *restrict conf)
{
	const bool server = conf->mux_listen != NULL;
	const bool client = conf->mux_connect != NULL ||
			    conf->identity.mux_connect_count > 0;
	if (server && client) {
		return "bidir";
	}
	if (server) {
		return "server";
	}
	if (client) {
		return "client";
	}
	return "none";
}

static bool parse_bool(const char *s)
{
	return s != NULL && (strcmp(s, "1") == 0 || strcmp(s, "y") == 0 ||
			     strcmp(s, "yes") == 0 || strcmp(s, "on") == 0 ||
			     strcmp(s, "t") == 0 || strcmp(s, "true") == 0);
}

/* Writes an HTTP response with the given status code and empty body. */
static void respond_status(struct api_ctx *restrict ctx, const int code)
{
	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	const char *status = http_status((uint_fast16_t)code);
	BUF_RESET(ctx->wbuf);
	BUF_APPENDF(
		ctx->wbuf,
		"HTTP/1.1 %d %s\r\n"
		"Date: %.*s\r\n"
		"Connection: %s\r\n"
		"Content-Length: 0\r\n"
		"\r\n",
		code, status ? status : "", (int)date_len, date_str,
		ctx->keepalive ? "keep-alive" : "close");
}

/* Writes a 200 OK response with headers only; body is expected in cbuf. */
static void respond_ok(
	struct api_ctx *restrict ctx, const char *content_type,
	const size_t body_len)
{
	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	BUF_RESET(ctx->wbuf);
	BUF_APPENDF(
		ctx->wbuf,
		"HTTP/1.1 200 OK\r\n"
		"Date: %.*s\r\n"
		"Connection: %s\r\n"
		"Content-Type: %s\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: %zu\r\n"
		"\r\n",
		(int)date_len, date_str,
		ctx->keepalive ? "keep-alive" : "close", content_type,
		body_len);
}

/* Handles GET /healthy */
static void handle_healthy(struct api_ctx *restrict ctx)
{
	respond_status(ctx, HTTP_OK);
}

/* Per-process CPU load since the previous call. */
static double process_load(void)
{
	static struct {
		struct timespec monotime, cputime;
		bool set;
	} last = { .set = false };
	double load = -1;
	struct timespec monotime, cputime;
	if (!clock_monotonic(&monotime)) {
		return load;
	}
	if (!clock_process(&cputime)) {
		return load;
	}
	if (last.set) {
		const intmax_t total = TIMESPEC_DIFF(monotime, last.monotime);
		const intmax_t busy = TIMESPEC_DIFF(cputime, last.cputime);
		if (busy > 0 && total > 0) {
			load = (double)busy / (double)total;
		}
	}
	last.monotime = monotime;
	last.cputime = cputime;
	last.set = true;
	return load;
}

/* Appends per-interval bandwidth and server load lines to body. */
static void append_stateful_stats(
	struct api_ctx *restrict ctx, const struct server_stats *restrict stats,
	const intmax_t now, const intmax_t started)
{
	struct server *restrict s = ctx->s;

	/* Rate tracking state stored per-server to avoid static shared state. */
	if (!s->rate_tracker.is_set) {
		s->rate_tracker.timestamp = started;
		s->rate_tracker.is_set = true;
	}

	const double dt = (double)(now - s->rate_tracker.timestamp) / 1e9;
	if (dt > 0.0) {
		const uintmax_t byt_mux_recv = stats->traffic_byt_mux_recv -
					       s->rate_tracker.byt_mux_recv;
		FORMAT_BYTES(rx_mux, (double)byt_mux_recv / dt);
		const uintmax_t byt_mux_sent = stats->traffic_byt_mux_sent -
					       s->rate_tracker.byt_mux_sent;
		FORMAT_BYTES(tx_mux, (double)byt_mux_sent / dt);
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: Rx %s/s, Tx %s/s\n",
			"Mux Throughput", rx_mux, tx_mux);
		const uintmax_t byt_push_recv = stats->traffic_byt_push_recv -
						s->rate_tracker.byt_push_recv;
		FORMAT_BYTES(rx_push, (double)byt_push_recv / dt);
		const uintmax_t byt_push_sent = stats->traffic_byt_push_sent -
						s->rate_tracker.byt_push_sent;
		FORMAT_BYTES(tx_push, (double)byt_push_sent / dt);
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: Rx %s/s, Tx %s/s\n",
			"Payload Throughput", rx_push, tx_push);
	}
	{
		char load_str[16] = "(unknown)";
		const double load = process_load();
		if (load >= 0.0) {
			(void)snprintf(
				load_str, sizeof(load_str), "%.3f%%",
				load * 100.0);
		}
		FORMAT_DURATION(dt_str, make_duration(dt));
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: %s (last %s)\n", "Server Load",
			load_str, dt_str);
	}

	s->rate_tracker.byt_mux_recv = stats->traffic_byt_mux_recv;
	s->rate_tracker.byt_mux_sent = stats->traffic_byt_mux_sent;
	s->rate_tracker.byt_push_recv = stats->traffic_byt_push_recv;
	s->rate_tracker.byt_push_sent = stats->traffic_byt_push_sent;
	s->rate_tracker.timestamp = now;
}

/* Appends the per-tunnel session status section to the response body. */
static void append_sessions(
	struct api_ctx *restrict ctx, const struct server_stats *restrict stats)
{
	VBUF_APPENDSTR(ctx->cbuf, "\n> Sessions\n");
	for (size_t i = 0; i < stats->num_tunnels; i++) {
		const struct tunnel_stats *restrict t = &stats->tunnels[i];
		if (t->peer_identity == NULL) {
			continue;
		}
		if (!t->established) {
			VBUF_APPENDF(
				ctx->cbuf, "%-20s: offline\n",
				t->peer_identity);
			continue;
		}
		if (t->rtt_ns > 0) {
			FORMAT_BYTES(rx_str, t->rx_window);
			FORMAT_BYTES(tx_str, t->tx_window);
			FORMAT_DURATION(
				rtt_str, make_duration_nanos(t->rtt_ns));
			VBUF_APPENDF(
				ctx->cbuf, "%-20s: W=Rx %s, Tx %s; RTT %s\n",
				t->peer_identity, rx_str, tx_str, rtt_str);
		} else {
			FORMAT_BYTES(rx_str, t->rx_window);
			FORMAT_BYTES(tx_str, t->tx_window);
			VBUF_APPENDF(
				ctx->cbuf, "%-20s: W=Rx %s, Tx %s\n",
				t->peer_identity, rx_str, tx_str);
		}
	}
}

/* Appends the recent event log section to the response body. */
static void append_eventlog(
	struct api_ctx *restrict ctx, const struct server_stats *restrict stats)
{
	VBUF_APPENDSTR(ctx->cbuf, "\n> Recent Events\n");
	const struct evlog *restrict evlog = stats->evlog;
	const size_t evlog_size = ARRAY_SIZE(evlog->entries);
	const size_t n = MIN(evlog->len, 10);
	for (size_t i = 0; i < n; i++) {
		const size_t idx =
			(evlog->pos + evlog_size - 1 - i) % evlog_size;
		const struct evlog_entry *restrict e = &evlog->entries[idx];
		char ts[32] = "(unknown)";
		if (e->timestamp != (time_t)-1) {
			(void)format_rfc3339(
				ts, sizeof(ts), e->timestamp, false);
		}
		if (e->count == 1) {
			VBUF_APPENDF(ctx->cbuf, "%s %s\n", ts, e->message);
		} else {
			VBUF_APPENDF(
				ctx->cbuf, "%s %s (x%zu)\n", ts, e->message,
				e->count);
		}
	}
}

/* Handles GET /stats (stateless) and POST /stats (stateful, includes rates). */
static void
handle_stats(struct api_ctx *restrict ctx, const bool stateless, char *query)
{
	struct {
		bool nobanner : 1;
	} opt = { false };
	while (query != NULL) {
		struct url_query_component comp;
		if (!url_query_component(&query, &comp)) {
			respond_status(ctx, HTTP_BAD_REQUEST);
			return;
		}
		if (strcmp(comp.key, "nobanner") == 0) {
			opt.nobanner = parse_bool(comp.value);
		}
	}

	struct server *restrict s = ctx->s;
	const struct config *restrict conf = s->conf;
	struct server_stats *restrict stats = server_stats(s);
	if (stats == NULL) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	const intmax_t now = clock_monotonic_ns();
	const time_t server_time = time(NULL);
	char timestamp[32] = "(unknown)";
	if (server_time != (time_t)-1) {
		(void)format_rfc3339(
			timestamp, sizeof(timestamp), server_time, false);
	}
	FORMAT_DURATION(str_uptime, make_duration_nanos(now - s->started));

	/*
	 * Build the response body in cbuf.
	 */
	VBUF_RESET(ctx->cbuf);

	if (!opt.nobanner) {
		VBUF_APPENDF(
			ctx->cbuf, "%s %s\n  %s\n\n", PROJECT_NAME, PROJECT_VER,
			PROJECT_HOMEPAGE);
	}
	VBUF_APPENDF(ctx->cbuf, "%-20s: %s\n", "Server Time", timestamp);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %s (mode: %s)\n", "Uptime", str_uptime,
		server_modestr(conf));
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %zu / %ju (+%zu)\n", "Sessions",
		stats->num_sessions,
		stats->num_session_created - stats->num_session_finalized,
		stats->num_session_halfopen);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %zu (+%zu)\n", "Streams", stats->num_streams,
		stats->num_stream_halfopen);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %ju active (%ju fastopen), %ju passive\n",
		"Stream Opens", stats->num_stream_opened,
		stats->num_stream_fastopen, stats->num_stream_accepted);
	if (stats->stream_establish_count > 0) {
		FORMAT_DURATION(
			p50_str,
			make_duration_nanos(stats->stream_establish_p50));
		FORMAT_DURATION(
			p90_str,
			make_duration_nanos(stats->stream_establish_p90));
		FORMAT_DURATION(
			p99_str,
			make_duration_nanos(stats->stream_establish_p99));
		FORMAT_DURATION(
			pmax_str,
			make_duration_nanos(stats->stream_establish_pmax));
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: P50=%s P90=%s P99=%s MAX=%s\n",
			"Stream Latency", p50_str, p90_str, p99_str, pmax_str);
	} else {
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: %s\n", "Stream Latency", "(never)");
	}
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %ju accepted, %ju served (%ju rejected)\n",
		"Mux Listener", stats->num_accepted, stats->num_served,
		stats->num_rejected);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %ju accepted, %ju served\n",
		"Stream Listener", stats->num_accepted_tcp,
		stats->num_served_tcp);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %ju accepted, %ju served\n", "API Listener",
		stats->num_accepted_api, stats->num_served_api);
#if WITH_TLS
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %ju\n", "TLS Failures",
		stats->num_tls_failures);
#endif
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %ju\n", "Reconnects", stats->num_reconnects);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: sent %ju, recv %ju\n", "RST Frames",
		stats->num_rst_sent, stats->num_rst_recv);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %ju\n", "Stream Errors",
		stats->num_stream_errors);
	{
		const size_t frame_size = 16384;
		FORMAT_BYTES(rx_buf, stats->recv_buffered_bytes);
		FORMAT_BYTES(
			tx_buf,
			(stats->send_buffered_frames + stats->unacked_frames) *
				frame_size);
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: Rx %s, Tx %s\n", "Buffered Data",
			rx_buf, tx_buf);
	}
	{
		FORMAT_BYTES(rx_mux, stats->traffic_byt_mux_recv);
		FORMAT_BYTES(tx_mux, stats->traffic_byt_mux_sent);
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: Rx %s, Tx %s\n", "Mux Traffic",
			rx_mux, tx_mux);
	}
	{
		FORMAT_BYTES(rx_push, stats->traffic_byt_push_recv);
		FORMAT_BYTES(tx_push, stats->traffic_byt_push_sent);
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: Rx %s, Tx %s\n", "Payload Traffic",
			rx_push, tx_push);
	}

	if (!stateless) {
		append_stateful_stats(ctx, stats, now, s->started);
	}

	append_sessions(ctx, stats);
	append_eventlog(ctx, stats);

	if (VBUF_HAS_OOM(ctx->cbuf)) {
		free(stats);
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	respond_ok(ctx, "text/plain; charset=utf-8", ctx->cbuf->len);
	/* body is in cbuf; send_cb will follow up with cbuf after wbuf */
	free(stats);
}

/* Appends all per-tunnel Prometheus metrics. */
static struct vbuffer *append_tunnel_metrics(
	struct vbuffer *restrict cbuf,
	const struct server_stats *restrict stats)
{
#define APPEND_TUNNEL_METRIC_DIR(name, help, fmt, rx_val, tx_val)                      \
	do {                                                                           \
		bool hdr = false;                                                      \
		for (size_t i = 0; i < stats->num_tunnels; i++) {                      \
			const struct tunnel_stats *restrict t =                        \
				&stats->tunnels[i];                                    \
			if (!t->established || t->peer_identity == NULL) {             \
				continue;                                              \
			}                                                              \
			if (!hdr) {                                                    \
				VBUF_APPENDF(                                          \
					cbuf,                                          \
					"# HELP multiplexd_%s %s\n"                    \
					"# TYPE multiplexd_%s counter\n",              \
					(name), (help), (name));                       \
				hdr = true;                                            \
			}                                                              \
			VBUF_APPENDF(                                                  \
				cbuf,                                                  \
				"multiplexd_%s{identity=\"%s\",direction=\"rx\"} " fmt \
				"\n"                                                   \
				"multiplexd_%s{identity=\"%s\",direction=\"tx\"} " fmt \
				"\n",                                                  \
				(name), t->peer_identity, (rx_val), (name),            \
				t->peer_identity, (tx_val));                           \
		}                                                                      \
	} while (0)

#define APPEND_TUNNEL_METRIC(name, help, extra_skip, fmt, val)                 \
	do {                                                                   \
		bool hdr = false;                                              \
		for (size_t i = 0; i < stats->num_tunnels; i++) {              \
			const struct tunnel_stats *restrict t =                \
				&stats->tunnels[i];                            \
			if (!t->established || t->peer_identity == NULL ||     \
			    (extra_skip)) {                                    \
				continue;                                      \
			}                                                      \
			if (!hdr) {                                            \
				VBUF_APPENDF(                                  \
					cbuf,                                  \
					"# HELP multiplexd_%s %s\n"            \
					"# TYPE multiplexd_%s gauge\n",        \
					(name), (help), (name));               \
				hdr = true;                                    \
			}                                                      \
			VBUF_APPENDF(                                          \
				cbuf,                                          \
				"multiplexd_%s{identity=\"%s\"} " fmt "\n",    \
				(name), t->peer_identity, (val));              \
		}                                                              \
	} while (0)

	APPEND_TUNNEL_METRIC_DIR(
		"session_bytes_total",
		"Wire bytes on the mux link per identity session", "%ju",
		t->byt_mux_recv, t->byt_mux_sent);
	APPEND_TUNNEL_METRIC_DIR(
		"session_payload_bytes_total",
		"PUSH-frame payload bytes on the mux link per identity session",
		"%ju", t->byt_push_recv, t->byt_push_sent);
	APPEND_TUNNEL_METRIC_DIR(
		"session_window_bytes",
		"Per-stream window size per identity session", "%zu",
		t->rx_window, t->tx_window);
	APPEND_TUNNEL_METRIC(
		"session_rtt_seconds", "Round-trip time per identity session",
		t->rtt_ns <= 0, "%g", (double)t->rtt_ns * 1e-9);
	APPEND_TUNNEL_METRIC(
		"session_bdp_bytes",
		"Instantaneous bandwidth-delay product (bw_wnd x rtt_wnd) per identity session",
		t->bdp == 0, "%zu", t->bdp);

#undef APPEND_TUNNEL_METRIC_DIR
#undef APPEND_TUNNEL_METRIC

	return cbuf;
}

/* Handles GET /metrics — Prometheus text format (version 0.0.4). */
static void handle_metrics(struct api_ctx *restrict ctx)
{
	struct server *restrict s = ctx->s;
	struct server_stats *restrict stats = server_stats(s);
	if (stats == NULL) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const intmax_t now = clock_monotonic_ns();
	const double uptime = (double)(now - s->started) / 1e9;

	VBUF_RESET(ctx->cbuf);

	/* Emits # HELP and # TYPE lines, then one unlabeled sample. */
#define APPEND_METRIC(cbuf, name, type, help, fmt, val)                        \
	do {                                                                   \
		VBUF_APPENDF(                                                  \
			(cbuf),                                                \
			"# HELP multiplexd_%s %s\n"                            \
			"# TYPE multiplexd_%s %s\n"                            \
			"multiplexd_%s " fmt "\n",                             \
			(name), (help), (name), (type), (name), (val));        \
	} while (0)

#define APPEND_METRIC_LISTENER(                                                \
	cbuf, name, type, help, mux_val, tcp_val, api_val)                     \
	do {                                                                   \
		VBUF_APPENDF(                                                  \
			(cbuf),                                                \
			"# HELP multiplexd_%s %s\n"                            \
			"# TYPE multiplexd_%s %s\n"                            \
			"multiplexd_%s{listener=\"mux\"}  %ju\n"               \
			"multiplexd_%s{listener=\"local\"} %ju\n"              \
			"multiplexd_%s{listener=\"api\"}  %ju\n",              \
			(name), (help), (name), (type), (name), (mux_val),     \
			(name), (tcp_val), (name), (api_val));                 \
	} while (0)

	/* --- Gauges --- */
	APPEND_METRIC(
		ctx->cbuf, "uptime_seconds", "gauge",
		"Seconds since server start", "%.3f", uptime);
	APPEND_METRIC(
		ctx->cbuf, "sessions", "gauge", "Total mux session objects",
		"%ju",
		stats->num_session_created - stats->num_session_finalized);
	APPEND_METRIC(
		ctx->cbuf, "sessions_established", "gauge",
		"Established mux sessions", "%zu", stats->num_sessions);
	APPEND_METRIC(
		ctx->cbuf, "sessions_halfopen", "gauge",
		"Half-open mux sessions (after accept, before established)",
		"%zu", stats->num_session_halfopen);
	APPEND_METRIC(
		ctx->cbuf, "streams", "gauge", "Active mux streams", "%zu",
		stats->num_streams);
	APPEND_METRIC(
		ctx->cbuf, "streams_halfopen", "gauge",
		"Half-open mux streams (SYN sent, before SYN-ACK)", "%zu",
		stats->num_stream_halfopen);

	APPEND_METRIC(
		ctx->cbuf, "stream_open_total", "counter",
		"Total successful active-open stream creations", "%ju",
		stats->num_stream_opened);
	APPEND_METRIC(
		ctx->cbuf, "stream_accept_total", "counter",
		"Total successful passive-open stream creations", "%ju",
		stats->num_stream_accepted);
	APPEND_METRIC(
		ctx->cbuf, "stream_fastopen_total", "counter",
		"Total active-open streams whose first flight used SYN|PUSH",
		"%ju", stats->num_stream_fastopen);
	if (stats->stream_establish_count > 0) {
		VBUF_APPENDF(
			ctx->cbuf,
			"# HELP multiplexd_%s %s\n"
			"# TYPE multiplexd_%s summary\n"
			"multiplexd_%s{quantile=\"0.5\"}  %g\n"
			"multiplexd_%s{quantile=\"0.9\"}  %g\n"
			"multiplexd_%s{quantile=\"0.99\"} %g\n"
			"multiplexd_%s_count %ju\n",
			"stream_establish_latency_seconds",
			"Active-open stream establishment latency from SYN to SYN|ACK",
			"stream_establish_latency_seconds",
			"stream_establish_latency_seconds",
			(double)stats->stream_establish_p50 * 1e-9,
			"stream_establish_latency_seconds",
			(double)stats->stream_establish_p90 * 1e-9,
			"stream_establish_latency_seconds",
			(double)stats->stream_establish_p99 * 1e-9,
			"stream_establish_latency_seconds",
			stats->num_stream_established);
	} else {
		VBUF_APPENDF(
			ctx->cbuf,
			"# HELP multiplexd_%s %s\n"
			"# TYPE multiplexd_%s summary\n"
			"multiplexd_%s_count %ju\n",
			"stream_establish_latency_seconds",
			"Active-open stream establishment latency from SYN to SYN|ACK",
			"stream_establish_latency_seconds",
			"stream_establish_latency_seconds",
			stats->num_stream_established);
	}

	/* --- Counters --- */
	APPEND_METRIC_LISTENER(
		ctx->cbuf, "connections_accepted_total", "counter",
		"Total accepted connections", stats->num_accepted,
		stats->num_accepted_tcp, stats->num_accepted_api);
	APPEND_METRIC_LISTENER(
		ctx->cbuf, "connections_served_total", "counter",
		"Connections that reached protocol setup", stats->num_served,
		stats->num_served_tcp, stats->num_served_api);
	APPEND_METRIC(
		ctx->cbuf, "connections_rejected_total", "counter",
		"Connections dropped by startup_limit", "%ju",
		stats->num_rejected);

#if WITH_TLS
	APPEND_METRIC(
		ctx->cbuf, "tls_failures_total", "counter",
		"TLS accept failures", "%ju", stats->num_tls_failures);
#endif
	APPEND_METRIC(
		ctx->cbuf, "reconnects_total", "counter",
		"Client-mode reconnect attempts", "%ju", stats->num_reconnects);
	APPEND_METRIC(
		ctx->cbuf, "rst_sent_total", "counter", "RST frames sent",
		"%ju", stats->num_rst_sent);
	APPEND_METRIC(
		ctx->cbuf, "rst_recv_total", "counter", "RST frames received",
		"%ju", stats->num_rst_recv);
	APPEND_METRIC(
		ctx->cbuf, "stream_errors_total", "counter",
		"Streams aborted due to local I/O errors", "%ju",
		stats->num_stream_errors);
	APPEND_METRIC(
		ctx->cbuf, "recv_buffered_bytes", "gauge",
		"Bytes buffered in per-stream receive rings", "%zu",
		stats->recv_buffered_bytes);
	APPEND_METRIC(
		ctx->cbuf, "send_buffered_frames", "gauge",
		"Frames queued in per-stream send buffers", "%zu",
		stats->send_buffered_frames);
	APPEND_METRIC(
		ctx->cbuf, "unacked_frames", "gauge",
		"Frames held in the session unacked list (spec §6.7.2)", "%zu",
		stats->unacked_frames);

	ctx->cbuf = append_tunnel_metrics(ctx->cbuf, stats);
	{
		struct timespec cpu_ts;
		if (clock_process(&cpu_ts)) {
			APPEND_METRIC(
				ctx->cbuf, "process_cpu_seconds_total",
				"counter", "Total process CPU time consumed",
				"%g", (double)TIMESPEC_NANO(cpu_ts) * 1e-9);
		}
	}

	respond_ok(
		ctx, "text/plain; version=0.0.4; charset=utf-8",
		ctx->cbuf->len);
	/* body is in cbuf; send_cb will follow up with cbuf after wbuf */
	free(stats);

#undef APPEND_METRIC
#undef APPEND_METRIC_LISTENER
}

/* Handles GET /config — serializes the active configuration as JSON. */
static void handle_config_get(struct api_ctx *restrict ctx)
{
	size_t len;
	char *restrict json = conf_dump(ctx->s->conf, &len);
	if (json == NULL) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	VBUF_RESET(ctx->cbuf);
	VBUF_APPEND(ctx->cbuf, (const unsigned char *)json, len);
	free(json);
	if (VBUF_HAS_OOM(ctx->cbuf)) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	respond_ok(ctx, "application/json; charset=utf-8", ctx->cbuf->len);
	/* body is in cbuf; send_cb will follow up with cbuf after wbuf */
}

/* Handles PUT /config — parse the request body as a new config and hot-reload. */
static void handle_config_put(struct api_ctx *restrict ctx)
{
	if (ctx->content_length == 0) {
		respond_status(ctx, HTTP_LENGTH_REQUIRED);
		return;
	}
	struct config *restrict new_conf =
		conf_parse(ctx->next, ctx->content_length);
	if (new_conf == NULL) {
		respond_status(ctx, HTTP_BAD_REQUEST);
		return;
	}
	/* new_conf ownership transfers; freed by server_apply_config on failure */
	if (!server_apply_config(ctx->s, new_conf)) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	respond_status(ctx, HTTP_NO_CONTENT);
}

/* Routes the parsed HTTP request to the appropriate handler. */
static void api_handle(struct api_ctx *restrict ctx)
{
	const char *const method = ctx->msg.req.method;
	struct url parsed_url;
	if (!url_parse(ctx->msg.req.url, &parsed_url)) {
		respond_status(ctx, HTTP_BAD_REQUEST);
		return;
	}
	const char *const path = parsed_url.path;

	if (strcmp(path, "config") == 0) {
		if (strcmp(method, "GET") == 0) {
			handle_config_get(ctx);
		} else if (strcmp(method, "PUT") == 0) {
			handle_config_put(ctx);
		} else {
			respond_status(ctx, HTTP_METHOD_NOT_ALLOWED);
		}
		return;
	}
	if (strcmp(path, "healthy") == 0) {
		handle_healthy(ctx);
		return;
	}
	if (strcmp(path, "stats") == 0) {
		bool stateless;
		if (strcmp(method, "GET") == 0) {
			stateless = true;
		} else if (strcmp(method, "POST") == 0) {
			stateless = false;
		} else {
			respond_status(ctx, HTTP_METHOD_NOT_ALLOWED);
			return;
		}
		handle_stats(ctx, stateless, parsed_url.query);
		return;
	}
	if (strcmp(path, "metrics") == 0) {
		if (strcmp(method, "GET") == 0) {
			handle_metrics(ctx);
		} else {
			respond_status(ctx, HTTP_METHOD_NOT_ALLOWED);
		}
		return;
	}
	respond_status(ctx, HTTP_NOT_FOUND);
}

/* Returns true if the connection should be kept alive after the response. */
static bool api_should_keepalive(const struct api_ctx *restrict ctx)
{
	const char *version = ctx->msg.req.version;
	if (version == NULL || strncmp(version, "HTTP/1.1", 8) != 0) {
		return false;
	}
	return ctx->connection[0] == '\0' ||
	       strcasecmp(ctx->connection, "close") != 0;
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct api_ctx *restrict ctx = watcher->data;

	/*
	 * Logical send buffer: wbuf (HTTP headers) followed by cbuf (body,
	 * non-empty only for /metrics).  wpos tracks position across both.
	 */
	const size_t wlen = ctx->wbuf.len;
	const size_t clen = ctx->cbuf->len;
	const size_t total = wlen + clen;
	const unsigned char *src;
	size_t remaining;
	if (ctx->wpos < wlen) {
		src = ctx->wbuf.data + ctx->wpos;
		remaining = wlen - ctx->wpos;
	} else {
		const size_t cpos = ctx->wpos - wlen;
		src = ctx->cbuf->data + cpos;
		remaining = clen - cpos;
	}
	size_t len = remaining;
	const int err = socket_send(ctx->fd, src, &len);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
		    err == ENOMEM) {
			return; /* wait for EV_WRITE */
		}
		LOGD_F("api [fd:%d]: send: (%d) %s", ctx->fd, err,
		       strerror(err));
		api_ctx_free(loop, ctx);
		return;
	}
	ctx->wpos += len;
	if (ctx->wpos >= total) {
		if (ctx->keepalive) {
			api_ctx_reset(loop, ctx);
		} else {
			api_ctx_free(loop, ctx);
		}
	}
}

static void
recv_error(struct ev_loop *loop, struct api_ctx *restrict ctx, const int code)
{
	respond_status(ctx, code);
	ctx->state = STATE_RESPOND;
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_start(loop, &ctx->w_send);
}

/* Read and parse the request incrementally; dispatch to api_handle() when headers are complete. */
static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct api_ctx *restrict ctx = watcher->data;

	const size_t cap = ctx->rbuf.cap - ctx->rbuf.len;
	if (cap == 0) {
		recv_error(loop, ctx, HTTP_ENTITY_TOO_LARGE);
		return;
	}

	size_t n = cap;
	const int err =
		socket_recv(ctx->fd, ctx->rbuf.data + ctx->rbuf.len, &n);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
		    err == ENOMEM) {
			return; /* wait for EV_READ */
		}
		LOGD_F("api [fd:%d]: recv: (%d) %s", ctx->fd, err,
		       strerror(err));
		api_ctx_free(loop, ctx);
		return;
	}
	if (n == 0) {
		api_ctx_free(loop, ctx);
		return;
	}
	ctx->rbuf.len += n;
	/* NUL-terminate so http_parse/http_parsehdr can use strstr.  When
	 * len == cap the next iteration responds HTTP_ENTITY_TOO_LARGE before
	 * parsing, so no NUL is needed. */
	if (ctx->rbuf.len < ctx->rbuf.cap) {
		ctx->rbuf.data[ctx->rbuf.len] = '\0';
	}

	/* Parse request line on first attempt or if previously incomplete */
	if (ctx->msg.req.method == NULL) {
		char *const parsed = http_parse(ctx->next, &ctx->msg);
		if (parsed == NULL) {
			recv_error(loop, ctx, HTTP_BAD_REQUEST);
			return;
		}
		if (parsed == ctx->next) {
			return; /* Partial line, wait for more data */
		}
		ctx->next = parsed;
	}

	/* Parse and discard remaining header lines */
	while (!ctx->hdr_done) {
		char *key, *value;
		char *const parsed = http_parsehdr(ctx->next, &key, &value);
		if (parsed == NULL) {
			recv_error(loop, ctx, HTTP_BAD_REQUEST);
			return;
		}
		if (parsed == ctx->next) {
			return; /* Partial header, wait for more data */
		}
		ctx->next = parsed;
		if (key == NULL) {
			ctx->hdr_done = true;
		} else if (strcasecmp(key, "Connection") == 0) {
			size_t vlen = strlen(value);
			if (vlen >= sizeof(ctx->connection)) {
				vlen = sizeof(ctx->connection) - 1;
			}
			(void)memcpy(ctx->connection, value, vlen);
			ctx->connection[vlen] = '\0';
		} else if (strcasecmp(key, "Content-Length") == 0) {
			char *endptr;
			const unsigned long cl = strtoul(value, &endptr, 10);
			if (endptr == value || *endptr != '\0') {
				recv_error(loop, ctx, HTTP_BAD_REQUEST);
				return;
			}
			ctx->content_length = (size_t)cl;
		}
	}

	/* Wait for the complete request body before dispatching */
	if (ctx->content_length > 0) {
		const size_t body_off =
			(size_t)((unsigned char *)ctx->next - ctx->rbuf.data);
		if (ctx->content_length > ctx->rbuf.cap - body_off) {
			recv_error(loop, ctx, HTTP_ENTITY_TOO_LARGE);
			return;
		}
		if (ctx->rbuf.len - body_off < ctx->content_length) {
			return; /* wait for more body data */
		}
	}

	/* All headers received; handle the request and start responding */
	ctx->keepalive = api_should_keepalive(ctx);
	ev_timer_stop(loop, &ctx->w_timeout);
	ev_io_stop(loop, &ctx->w_recv);
	api_handle(ctx);
	ctx->state = STATE_RESPOND;
	ctx->wpos = 0;
	ev_io_start(loop, &ctx->w_send);
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct api_ctx *restrict ctx = watcher->data;
	LOGD_F("api [fd:%d]: timeout", ctx->fd);
	api_ctx_free(loop, ctx);
}

static struct api_ctx *api_ctx_new(struct server *restrict s, const int fd)
{
	struct api_ctx *restrict ctx = malloc(sizeof(struct api_ctx));
	if (ctx == NULL) {
		LOGOOM();
		return NULL;
	}
	*ctx = (struct api_ctx){
		.s = s,
		.state = STATE_RECEIVE,
		.fd = fd,
		.hdr_done = false,
	};
	BUF_INIT(ctx->rbuf, 0);
	ctx->rbuf.data[0] = '\0';
	ctx->next = (char *)ctx->rbuf.data;
	BUF_INIT(ctx->wbuf, 0);
	ctx->cbuf = VBUF_NEW(4096);
	if (ctx->cbuf == NULL) {
		LOGOOM();
		free(ctx);
		return NULL;
	}

	ev_io_init(&ctx->w_recv, recv_cb, fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(&ctx->w_send, send_cb, fd, EV_WRITE);
	ctx->w_send.data = ctx;
	ev_timer_init(&ctx->w_timeout, timeout_cb, 0.0, API_TIMEOUT);
	ctx->w_timeout.data = ctx;
	return ctx;
}

void api_serve(
	struct listener *l, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	UNUSED(accepted_sa);
	struct server *restrict s = l->srv;
	struct api_ctx *restrict ctx = api_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		CLOSE_FD(accepted_fd);
		return;
	}
	s->counters.num_served_api++;
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_again(loop, &ctx->w_timeout);
}
