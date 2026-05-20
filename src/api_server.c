/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_server.h"

#include "conf.h"
#include "listener.h"
#include "server.h"
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
	const bool client =
		conf->mux_connect != NULL || conf->identity_connect_count > 0;
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
		const uintmax_t byt_local_recv = stats->traffic_byt_local_recv -
						 s->rate_tracker.byt_local_recv;
		FORMAT_BYTES(rx_local, (double)byt_local_recv / dt);
		const uintmax_t byt_local_sent = stats->traffic_byt_local_sent -
						 s->rate_tracker.byt_local_sent;
		FORMAT_BYTES(tx_local, (double)byt_local_sent / dt);
		BUF_APPENDF(
			ctx->rbuf, "Mux Throughput      : Rx %s/s, Tx %s/s\n",
			rx_mux, tx_mux);
		BUF_APPENDF(
			ctx->rbuf, "Stream Throughput   : Rx %s/s, Tx %s/s\n",
			rx_local, tx_local);
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
		BUF_APPENDF(
			ctx->rbuf, "Server Load         : %s (last %s)\n",
			load_str, dt_str);
	}

	s->rate_tracker.byt_mux_recv = stats->traffic_byt_mux_recv;
	s->rate_tracker.byt_mux_sent = stats->traffic_byt_mux_sent;
	s->rate_tracker.byt_local_recv = stats->traffic_byt_local_recv;
	s->rate_tracker.byt_local_sent = stats->traffic_byt_local_sent;
	s->rate_tracker.timestamp = now;
}

/* Appends the per-tunnel session status section to the response body. */
static void append_sessions(
	struct api_ctx *restrict ctx, const struct server_stats *restrict stats)
{
	BUF_APPENDSTR(ctx->rbuf, "\n> Sessions\n");
	for (size_t i = 0; i < stats->num_tunnels; i++) {
		const struct tunnel_stats *restrict t = &stats->tunnels[i];
		const char *id =
			t->peer_identity != NULL ? t->peer_identity : "(mux)";
		if (!t->established) {
			BUF_APPENDF(ctx->rbuf, "%-20s: offline\n", id);
			continue;
		}
		if (t->rtt_ns > 0) {
			FORMAT_BYTES(rx_str, t->rx_window);
			FORMAT_BYTES(tx_str, t->tx_window);
			FORMAT_DURATION(
				rtt_str, make_duration_nanos(t->rtt_ns));
			BUF_APPENDF(
				ctx->rbuf, "%-20s: W=Rx %s, Tx %s; RTT %s\n",
				id, rx_str, tx_str, rtt_str);
		} else {
			FORMAT_BYTES(rx_str, t->rx_window);
			FORMAT_BYTES(tx_str, t->tx_window);
			BUF_APPENDF(
				ctx->rbuf, "%-20s: W=Rx %s, Tx %s\n", id,
				rx_str, tx_str);
		}
	}
}

/* Appends the recent event log section to the response body. */
static void append_eventlog(
	struct api_ctx *restrict ctx, const struct server_stats *restrict stats)
{
	BUF_APPENDSTR(ctx->rbuf, "\n> Recent Events\n");
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
			BUF_APPENDF(ctx->rbuf, "%s %s\n", ts, e->message);
		} else {
			BUF_APPENDF(
				ctx->rbuf, "%s %s (x%zu)\n", ts, e->message,
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
	 * Build the response body in ctx->rbuf first so we know its
	 * exact size before writing the Content-Length header.
	 */
	BUF_RESET(ctx->rbuf);

	if (!opt.nobanner) {
		BUF_APPENDF(
			ctx->rbuf, "%s %s\n  %s\n\n", PROJECT_NAME, PROJECT_VER,
			PROJECT_HOMEPAGE);
	}
	BUF_APPENDF(ctx->rbuf, "Server Time         : %s\n", timestamp);
	BUF_APPENDF(
		ctx->rbuf, "Uptime              : %s (mode: %s)\n", str_uptime,
		server_modestr(conf));
	BUF_APPENDF(
		ctx->rbuf, "Sessions            : %zu / %ju (+%zu)\n",
		stats->num_sessions,
		stats->num_session_created - stats->num_session_finalized,
		stats->num_session_halfopen);
	BUF_APPENDF(
		ctx->rbuf, "Streams             : %zu (+%zu)\n",
		stats->num_streams, stats->num_stream_halfopen);
	BUF_APPENDF(
		ctx->rbuf,
		"Stream Opens        : %ju active (%ju fastopen), %ju passive\n",
		stats->num_stream_opened, stats->num_stream_fastopen,
		stats->num_stream_accepted);
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
		BUF_APPENDF(
			ctx->rbuf,
			"Stream Latency      : P50=%s P90=%s P99=%s MAX=%s\n",
			p50_str, p90_str, p99_str, pmax_str);
	} else {
		BUF_APPENDF(ctx->rbuf, "Stream Latency      : %s\n", "(never)");
	}
	BUF_APPENDF(
		ctx->rbuf,
		"Mux Listener        : %ju accepted, %ju served (%ju rejected)\n",
		stats->num_accepted, stats->num_served, stats->num_rejected);
	BUF_APPENDF(
		ctx->rbuf, "Stream Listener     : %ju accepted, %ju served\n",
		stats->num_accepted_tcp, stats->num_served_tcp);
	BUF_APPENDF(
		ctx->rbuf, "API Listener        : %ju accepted, %ju served\n",
		stats->num_accepted_api, stats->num_served_api);
#if WITH_TLS
	BUF_APPENDF(
		ctx->rbuf, "TLS Failures        : %ju\n",
		stats->num_tls_failures);
#endif
	BUF_APPENDF(
		ctx->rbuf, "Reconnects          : %ju\n",
		stats->num_reconnects);
	BUF_APPENDF(
		ctx->rbuf, "RST Frames          : sent %ju, recv %ju\n",
		stats->num_rst_sent, stats->num_rst_recv);
	BUF_APPENDF(
		ctx->rbuf, "Stream Errors       : %ju\n",
		stats->num_stream_errors);
	{
		const size_t frame_size = 16384;
		FORMAT_BYTES(rx_buf, stats->recv_buffered_bytes);
		FORMAT_BYTES(
			tx_buf,
			(stats->send_buffered_frames + stats->unacked_frames) *
				frame_size);
		BUF_APPENDF(
			ctx->rbuf, "Buffered Data       : Rx %s, Tx %s\n",
			rx_buf, tx_buf);
	}
	{
		FORMAT_BYTES(rx_mux, stats->traffic_byt_mux_recv);
		FORMAT_BYTES(tx_mux, stats->traffic_byt_mux_sent);
		FORMAT_BYTES(rx_local, stats->traffic_byt_local_recv);
		FORMAT_BYTES(tx_local, stats->traffic_byt_local_sent);
		BUF_APPENDF(
			ctx->rbuf, "Mux Traffic         : Rx %s, Tx %s\n",
			rx_mux, tx_mux);
		BUF_APPENDF(
			ctx->rbuf, "Stream Traffic      : Rx %s, Tx %s\n",
			rx_local, tx_local);
	}

	if (!stateless) {
		append_stateful_stats(ctx, stats, now, s->started);
	}

	append_sessions(ctx, stats);
	append_eventlog(ctx, stats);

	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	BUF_RESET(ctx->wbuf);
	BUF_APPENDF(
		ctx->wbuf,
		"HTTP/1.1 200 OK\r\n"
		"Date: %.*s\r\n"
		"Connection: %s\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: %zu\r\n"
		"\r\n",
		(int)date_len, date_str,
		ctx->keepalive ? "keep-alive" : "close", ctx->rbuf.len);
	BUF_APPEND(ctx->wbuf, ctx->rbuf.data, ctx->rbuf.len);
	free(stats);
}

/* Emits # HELP and # TYPE lines, then one unlabeled sample.
 * name, type, and help must be string literals. */
#define APPEND_METRIC(cbuf, name, type, help, fmt, val)                        \
	do {                                                                   \
		VBUF_APPENDSTR(                                                \
			(cbuf), "# HELP " name " " help "\n"                   \
				"# TYPE " name " " type "\n");                 \
		VBUF_APPENDF((cbuf), name " " fmt "\n", (val));                \
	} while (0)

/* Emits a metric family with {listener} label for mux, tcp, and api values. */
#define APPEND_METRIC_LISTENER(                                                \
	cbuf, name, type, help, mux_val, tcp_val, api_val)                     \
	do {                                                                   \
		VBUF_APPENDSTR(                                                \
			(cbuf), "# HELP " name " " help "\n"                   \
				"# TYPE " name " " type "\n");                 \
		VBUF_APPENDF(                                                  \
			(cbuf),                                                \
			name "{listener=\"mux\"} %ju\n" name                   \
			     "{listener=\"local\"} %ju\n" name                 \
			     "{listener=\"api\"} %ju\n",                       \
			(mux_val), (tcp_val), (api_val));                      \
	} while (0)

/* Emits the bytes counter family with {direction, link} labels. */
#define APPEND_METRIC_BYTES(                                                   \
	cbuf, name, help, mux_recv, mux_sent, local_recv, local_sent)          \
	do {                                                                   \
		VBUF_APPENDSTR(                                                \
			(cbuf), "# HELP " name " " help "\n"                   \
				"# TYPE " name " counter\n");                  \
		VBUF_APPENDF(                                                  \
			(cbuf),                                                \
			name "{direction=\"recv\",link=\"mux\"} %ju\n" name    \
			     "{direction=\"sent\",link=\"mux\"} %ju\n" name    \
			     "{direction=\"recv\",link=\"local\"} %ju\n" name  \
			     "{direction=\"sent\",link=\"local\"} %ju\n",      \
			(mux_recv), (mux_sent), (local_recv), (local_sent));   \
	} while (0)

/* Emits a latency summary family: quantiles (when has_samples) and _count. */
#define APPEND_METRIC_LATENCY_SUMMARY(                                         \
	cbuf, name, help, has_samples, p50, p90, p99, count)                   \
	do {                                                                   \
		VBUF_APPENDSTR(                                                \
			(cbuf), "# HELP " name " " help "\n"                   \
				"# TYPE " name " summary\n");                  \
		if (has_samples) {                                             \
			VBUF_APPENDF(                                          \
				(cbuf),                                        \
				name "{quantile=\"0.5\"} %g\n" name            \
				     "{quantile=\"0.9\"} %g\n" name            \
				     "{quantile=\"0.99\"} %g\n",               \
				(p50), (p90), (p99));                          \
		}                                                              \
		VBUF_APPENDF((cbuf), name "_count %ju\n", (count));            \
	} while (0)

/* Emits one complete Prometheus metric family for per-tunnel data.
 * name, type, and help must be string literals.  extra_skip is an additional
 * filter expression (referencing t) evaluated after the base checks.
 * Keeping each family in its own loop guarantees contiguous samples,
 * as required by the Prometheus text format exposition specification. */
#define APPEND_TUNNEL_METRIC(                                                  \
	cbuf, stats, name, type, help, extra_skip, fmt, val)                   \
	do {                                                                   \
		bool hdr = false;                                              \
		for (size_t i = 0; i < (stats)->num_tunnels; i++) {            \
			const struct tunnel_stats *restrict t =                \
				&(stats)->tunnels[i];                          \
			if (!t->established || t->session == NULL ||           \
			    (extra_skip)) {                                    \
				continue;                                      \
			}                                                      \
			if (!hdr) {                                            \
				VBUF_APPENDSTR(                                \
					(cbuf), "# HELP " name " " help "\n"   \
						"# TYPE " name " " type "\n"); \
				hdr = true;                                    \
			}                                                      \
			VBUF_APPENDF(                                          \
				(cbuf),                                        \
				name "{session=\"%s\",role=\"%s\"} " fmt "\n", \
				t->session, t->accepted ? "server" : "client", \
				(val));                                        \
		}                                                              \
	} while (0)

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

	/* --- Gauges --- */
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_uptime_seconds", "gauge",
		"Seconds since server start", "%.3f", uptime);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_sessions", "gauge",
		"Total mux session objects", "%ju",
		stats->num_session_created - stats->num_session_finalized);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_sessions_established", "gauge",
		"Established mux sessions", "%zu", stats->num_sessions);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_sessions_halfopen", "gauge",
		"Half-open mux sessions (after accept, before established)",
		"%zu", stats->num_session_halfopen);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_streams", "gauge", "Active mux streams",
		"%zu", stats->num_streams);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_streams_halfopen", "gauge",
		"Half-open mux streams (SYN sent, before SYN-ACK)", "%zu",
		stats->num_stream_halfopen);

	APPEND_METRIC(
		ctx->cbuf, "multiplexd_stream_open_total", "counter",
		"Total successful active-open stream creations", "%ju",
		stats->num_stream_opened);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_stream_accept_total", "counter",
		"Total successful passive-open stream creations", "%ju",
		stats->num_stream_accepted);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_stream_fastopen_total", "counter",
		"Total active-open streams whose first flight used SYN|PUSH",
		"%ju", stats->num_stream_fastopen);
	APPEND_METRIC_LATENCY_SUMMARY(
		ctx->cbuf, "multiplexd_stream_establish_latency_seconds",
		"Active-open stream establishment latency from SYN to SYN|ACK",
		stats->stream_establish_count > 0,
		(double)stats->stream_establish_p50 * 1e-9,
		(double)stats->stream_establish_p90 * 1e-9,
		(double)stats->stream_establish_p99 * 1e-9,
		stats->num_stream_established);

	/* --- Counters --- */
	APPEND_METRIC_LISTENER(
		ctx->cbuf, "multiplexd_connections_accepted_total", "counter",
		"Total accepted connections", stats->num_accepted,
		stats->num_accepted_tcp, stats->num_accepted_api);
	APPEND_METRIC_LISTENER(
		ctx->cbuf, "multiplexd_connections_served_total", "counter",
		"Connections that reached protocol setup", stats->num_served,
		stats->num_served_tcp, stats->num_served_api);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_connections_rejected_total", "counter",
		"Connections dropped by startup_limit", "%ju",
		stats->num_rejected);

#if WITH_TLS
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_tls_failures_total", "counter",
		"TLS accept failures", "%ju", stats->num_tls_failures);
#endif
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_reconnects_total", "counter",
		"Client-mode reconnect attempts", "%ju", stats->num_reconnects);
	APPEND_METRIC_BYTES(
		ctx->cbuf, "multiplexd_bytes_total", "Total bytes transferred",
		stats->traffic_byt_mux_recv, stats->traffic_byt_mux_sent,
		stats->traffic_byt_local_recv, stats->traffic_byt_local_sent);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_rst_sent_total", "counter",
		"RST frames sent", "%ju", stats->num_rst_sent);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_rst_recv_total", "counter",
		"RST frames received", "%ju", stats->num_rst_recv);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_stream_errors_total", "counter",
		"Streams aborted due to local I/O errors", "%ju",
		stats->num_stream_errors);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_recv_buffered_bytes", "gauge",
		"Bytes buffered in per-stream receive rings", "%zu",
		stats->recv_buffered_bytes);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_send_buffered_frames", "gauge",
		"Frames queued in per-stream send buffers", "%zu",
		stats->send_buffered_frames);
	APPEND_METRIC(
		ctx->cbuf, "multiplexd_unacked_frames", "gauge",
		"Frames held in the session unacked list (spec §6.7.2)", "%zu",
		stats->unacked_frames);

	/* Per-tunnel metrics: one loop per family keeps all samples contiguous. */
	APPEND_TUNNEL_METRIC(
		ctx->cbuf, stats, "multiplexd_session_rx_window_bytes", "gauge",
		"Per-stream receive window size per identity session", false,
		"%zu", t->rx_window);
	APPEND_TUNNEL_METRIC(
		ctx->cbuf, stats, "multiplexd_session_tx_window_bytes", "gauge",
		"Per-stream send window size per identity session", false,
		"%zu", t->tx_window);
	APPEND_TUNNEL_METRIC(
		ctx->cbuf, stats, "multiplexd_session_rtt_seconds", "gauge",
		"Windowed-minimum round-trip time per identity session",
		t->rtt_ns <= 0, "%g", (double)t->rtt_ns * 1e-9);
	APPEND_TUNNEL_METRIC(
		ctx->cbuf, stats, "multiplexd_session_bdp_bytes", "gauge",
		"Raw bandwidth-delay product estimate per identity session, no headroom",
		t->bdp == 0, "%zu", t->bdp);
	{
		struct timespec cpu_ts;
		if (clock_process(&cpu_ts)) {
			APPEND_METRIC(
				ctx->cbuf,
				"multiplexd_process_cpu_seconds_total",
				"counter", "Total process CPU time consumed",
				"%g", (double)TIMESPEC_NANO(cpu_ts) * 1e-9);
		}
	}

	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	BUF_RESET(ctx->wbuf);
	BUF_APPENDF(
		ctx->wbuf,
		"HTTP/1.1 200 OK\r\n"
		"Date: %.*s\r\n"
		"Connection: %s\r\n"
		"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: %zu\r\n"
		"\r\n",
		(int)date_len, date_str,
		ctx->keepalive ? "keep-alive" : "close", ctx->cbuf->len);
	/* body is in cbuf; send_cb will follow up with cbuf after wbuf */
	free(stats);
}

#undef APPEND_METRIC
#undef APPEND_METRIC_LISTENER
#undef APPEND_METRIC_BYTES
#undef APPEND_METRIC_LATENCY_SUMMARY
#undef APPEND_TUNNEL_METRIC

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

/*
 * Reads incoming HTTP request data and parses it incrementally.
 * When headers are complete, dispatches to api_handle() and begins sending.
 */
static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct api_ctx *restrict ctx = watcher->data;

	const size_t cap = ctx->rbuf.cap - ctx->rbuf.len;
	if (cap == 0) {
		respond_status(ctx, HTTP_ENTITY_TOO_LARGE);
		ctx->state = STATE_RESPOND;
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_start(loop, &ctx->w_send);
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
	/*
	 * Maintain NUL termination so http_parse/http_parsehdr can use strstr.
	 * When the buffer is full (len == cap) the next iteration detects
	 * cap == 0 and responds 413 before any parsing, so no NUL is needed.
	 */
	if (ctx->rbuf.len < ctx->rbuf.cap) {
		ctx->rbuf.data[ctx->rbuf.len] = '\0';
	}

	/* Parse request line on first attempt or if previously incomplete */
	if (ctx->msg.req.method == NULL) {
		char *const parsed = http_parse(ctx->next, &ctx->msg);
		if (parsed == NULL) {
			respond_status(ctx, HTTP_BAD_REQUEST);
			ctx->state = STATE_RESPOND;
			ev_io_stop(loop, &ctx->w_recv);
			ev_io_start(loop, &ctx->w_send);
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
			respond_status(ctx, HTTP_BAD_REQUEST);
			ctx->state = STATE_RESPOND;
			ev_io_stop(loop, &ctx->w_recv);
			ev_io_start(loop, &ctx->w_send);
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
