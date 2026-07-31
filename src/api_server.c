/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_server.h"

#include "conf.h"
#include "listener.h"
#include "mux/mux.h"
#include "server.h"
#include "shim/util.h"
#include "tunnel.h"

#include "meta/arraysize.h"
#include "meta/minmax.h"
#include "net/http.h"
#include "net/url.h"
#include "os/clock.h"
#include "os/socket.h"
#include "strings/format.h"
#include "strings/time.h"
#include "utils/buffer.h"
#include "utils/ctype_ascii.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>

enum {
	/* rbuf must admit a CONF_MAXSIZE config body plus HTTP framing
	 * headroom. */
	HTTP_MAX_ENTITY = CONF_MAXSIZE + 4096,
	/* wbuf only stages response headers; a body goes through cbuf. */
	HTTP_MAX_RESPONSE_HDR = 1024,
};

#define API_TIMEOUT 30.0

struct api_ctx {
	struct server *s;
	int fd;
	ev_io w_recv, w_send;
	ev_timer w_timeout;
	struct http_message msg;
	char *next;
	bool hdr_done : 1;
	bool keepalive : 1;
	bool content_length_seen : 1;
	/* Sticky OR of connection_has_close() over every Connection header, set
	 * at parse time.  Replaces a fixed value buffer so neither a token list
	 * longer than the buffer (dropping a trailing "close") nor a repeated
	 * list-valued Connection header (RFC 7230 3.2.2) can lose the token. */
	bool close_requested : 1;
	size_t wpos;
	/* parsed Content-Length from the request; 0 when absent */
	size_t content_length;
	struct {
		BUFFER_HDR;
		unsigned char data[HTTP_MAX_ENTITY];
	} rbuf;
	struct {
		BUFFER_HDR;
		unsigned char data[HTTP_MAX_RESPONSE_HDR];
	} wbuf;
	struct vbuffer *cbuf;
};

static void api_ctx_free(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);
	ev_timer_stop(loop, &ctx->w_timeout);
	if (ctx->fd != -1) {
		socket_close(ctx->fd);
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
	ctx->content_length_seen = false;
	ctx->close_requested = false;
	ctx->content_length = 0;
	BUF_RESET(ctx->wbuf);
	VBUF_RESET(ctx->cbuf);
	ctx->wpos = 0;
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

/* RFC 7231 section 7.1.1.1 IMF-fixdate, built from a static English name
 * table instead of contrib's http_date(), which formats via strftime's
 * locale-dependent %a/%b -- under init()'s own setlocale(LC_ALL, ""), a
 * non-English LC_TIME breaks the RFC-mandated English day/month names, and
 * an overflowing localized expansion can even make strftime return 0
 * (contrib is read-only, so the fix lives at the call site). Returns the
 * formatted length, or 0 on failure (undersized buf or gmtime_r failure),
 * matching http_date()'s own contract. */
static size_t http_date_safe(char *restrict buf, const size_t buf_size)
{
	static const char *const wday_name[7] = { "Sun", "Mon", "Tue", "Wed",
						  "Thu", "Fri", "Sat" };
	static const char *const mon_name[12] = { "Jan", "Feb", "Mar", "Apr",
						  "May", "Jun", "Jul", "Aug",
						  "Sep", "Oct", "Nov", "Dec" };
	const time_t now = time(NULL);
	struct tm gmt;
	if (gmtime_r(&now, &gmt) == NULL) {
		return 0;
	}
	const int n = snprintf(
		buf, buf_size, "%s, %02d %s %d %02d:%02d:%02d GMT",
		wday_name[gmt.tm_wday % 7], gmt.tm_mday,
		mon_name[gmt.tm_mon % 12], gmt.tm_year + 1900, gmt.tm_hour,
		gmt.tm_min, gmt.tm_sec);
	return (n > 0 && (size_t)n < buf_size) ? (size_t)n : 0;
}

/* Writes an HTTP response with the given status code and empty body. */
static void respond_status(struct api_ctx *restrict ctx, const int code)
{
	char date_str[32];
	const size_t date_len = http_date_safe(date_str, sizeof(date_str));
	const char *const status = http_status((uint_fast16_t)code);
	BUF_RESET(ctx->wbuf);
	/* Guarantee the documented "empty body" contract even when called
	 * after a partial cbuf append failed with OOM: send_cb() always
	 * transmits wbuf then cbuf, so a stale/partial cbuf here would
	 * otherwise desync the declared Content-Length: 0 from what's
	 * actually sent. */
	VBUF_RESET(ctx->cbuf);
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

/* Writes a response with the given status code and headers only; the body is
 * expected in cbuf. */
static void respond_body(
	struct api_ctx *restrict ctx, const int code, const char *content_type,
	const size_t body_len)
{
	char date_str[32];
	const size_t date_len = http_date_safe(date_str, sizeof(date_str));
	const char *const status = http_status((uint_fast16_t)code);
	BUF_RESET(ctx->wbuf);
	BUF_APPENDF(
		ctx->wbuf,
		"HTTP/1.1 %d %s\r\n"
		"Date: %.*s\r\n"
		"Connection: %s\r\n"
		"Content-Type: %s\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: %zu\r\n"
		"\r\n",
		code, status ? status : "", (int)date_len, date_str,
		ctx->keepalive ? "keep-alive" : "close", content_type,
		body_len);
}

/* Writes a 200 OK response with headers only; body is expected in cbuf. */
static void respond_ok(
	struct api_ctx *restrict ctx, const char *content_type,
	const size_t body_len)
{
	respond_body(ctx, HTTP_OK, content_type, body_len);
}

/* A peer identity is peer-controlled (config or PUT /config) and only
 * NUL-excluded per spec (doc/spec.md 5.2.3.2), so it may contain quotes,
 * backslashes, newlines, or other control bytes. Escape those before
 * interpolating into a Prometheus label value or a plaintext status line, or a
 * crafted identity could corrupt the /metrics exposition or inject spoofed
 * /stats /healthy lines. Max identity is 255 octets; a plaintext control byte
 * escapes to \xNN (4 bytes, the worst case -- the metric context never exceeds
 * 2x), plus a NUL. */
enum { IDENTITY_ESCAPED_MAX = 4 * 255 + 1 };

/* escape_identity target. The Prometheus 0.0.4 text format accepts only \\, \",
 * and \n as backslash escapes inside a label value; any other escape (e.g. \t
 * or \r) is an "invalid escape sequence" that makes the whole scrape
 * unparseable, so TAB and CR are emitted literally there -- both are valid
 * label-value bytes. A plaintext status line has no such grammar, so it escapes
 * every control byte: TAB and CR as \t and \r, and any other C0 byte (e.g. ESC)
 * as an inert \xNN -- denying a crafted identity the terminal cursor motion it
 * could otherwise use to spoof a status row. */
enum escape_ctx { ESCAPE_METRIC, ESCAPE_PLAIN };

static void escape_identity(
	char *restrict out, const size_t outsize, const char *restrict in,
	const enum escape_ctx ctx)
{
	size_t o = 0;
	for (size_t i = 0; in[i] != '\0'; i++) {
		const unsigned char c = (unsigned char)in[i];
		char esc = '\0';
		switch (c) {
		case '\\':
		case '"':
			esc = (char)c;
			break;
		case '\n':
			esc = 'n';
			break;
		case '\t':
			esc = ctx == ESCAPE_PLAIN ? 't' : '\0';
			break;
		case '\r':
			esc = ctx == ESCAPE_PLAIN ? 'r' : '\0';
			break;
		default:
			break;
		}
		if (esc != '\0') {
			if (o + 2 >= outsize) {
				break;
			}
			out[o++] = '\\';
			out[o++] = esc;
		} else if (ctx == ESCAPE_PLAIN && c < 0x20) {
			/* Any remaining C0 control byte (e.g. ESC) would let a
			 * crafted identity drive terminal cursor motion in the
			 * plaintext status output; emit an inert \xNN escape. */
			if (o + 4 >= outsize) {
				break;
			}
			out[o++] = '\\';
			out[o++] = 'x';
			tohexlower(&out[o], c);
			o += 2;
		} else {
			if (o + 1 >= outsize) {
				break;
			}
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

/* Active session count = created - finalized, clamped to 0. server_stats reads
 * the two counters from independent relaxed atomics with no ordering between
 * them, so under weak memory finalized can transiently exceed created and the
 * unsigned subtraction would wrap near UINT64_MAX for one scrape. */
static uint_least64_t sessions_active(const struct server_stats *restrict s)
{
	return s->num_session_created >= s->num_session_finalized ?
		       s->num_session_created - s->num_session_finalized :
		       0;
}

/* Appends one line per offline forwarding listener to the response body. */
static void healthy_offline_cb(void *data, const char *identifier)
{
	struct api_ctx *const restrict ctx = data;
	char esc[IDENTITY_ESCAPED_MAX];
	escape_identity(esc, sizeof(esc), identifier, ESCAPE_PLAIN);
	VBUF_APPENDF(ctx->cbuf, "offline: %s\n", esc);
}

/* Handles GET /healthy.  Returns 200 with an empty body when every forwarding
 * listener has a tunnel to forward over (or none are configured); 503 with the
 * offline listeners listed otherwise. */
static void handle_healthy(struct api_ctx *restrict ctx)
{
	VBUF_RESET(ctx->cbuf);
	const size_t offline =
		server_offline_listeners(ctx->s, healthy_offline_cb, ctx);
	if (offline == 0) {
		respond_status(ctx, HTTP_OK);
		return;
	}
	if (VBUF_HAS_OOM(ctx->cbuf)) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	respond_body(
		ctx, HTTP_SERVICE_UNAVAILABLE, "text/plain; charset=utf-8",
		ctx->cbuf->len);
}

/* Per-process CPU load since the previous call. */
static double process_load(void)
{
	static struct {
		struct timespec monotime, cputime;
		bool set;
	} last = { .set = false };
	double load = -1.0;
	struct timespec monotime, cputime;
	if (!clock_monotonic(&monotime)) {
		return load;
	}
	if (!clock_process(&cputime)) {
		return load;
	}
	if (last.set) {
		const int_fast64_t total =
			TIMESPEC_DIFF(monotime, last.monotime);
		const int_fast64_t busy = TIMESPEC_DIFF(cputime, last.cputime);
		/* total > 0 guards the division; busy == 0 is a legitimate 0.000%
		 * load, not "unknown", so admit it too. */
		if (busy >= 0 && total > 0) {
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
	const int_fast64_t now, const int_fast64_t started)
{
	struct server *const restrict s = ctx->s;

	if (!s->rate_tracker.is_set) {
		s->rate_tracker.timestamp = (int_least64_t)started;
		s->rate_tracker.is_set = true;
	}

	const double dt = (double)(now - s->rate_tracker.timestamp) / 1e9;
	if (dt > 0.0) {
		const uint_least64_t byt_mux_recv =
			stats->traffic_byt_mux_recv -
			s->rate_tracker.byt_mux_recv;
		FORMAT_BYTES(rx_mux, (double)byt_mux_recv / dt);
		const uint_least64_t byt_mux_sent =
			stats->traffic_byt_mux_sent -
			s->rate_tracker.byt_mux_sent;
		FORMAT_BYTES(tx_mux, (double)byt_mux_sent / dt);
		VBUF_APPENDF(
			ctx->cbuf, "%-20s: Rx %s/s, Tx %s/s\n",
			"Mux Throughput", rx_mux, tx_mux);
		const uint_least64_t byt_push_recv =
			stats->traffic_byt_push_recv -
			s->rate_tracker.byt_push_recv;
		FORMAT_BYTES(rx_push, (double)byt_push_recv / dt);
		const uint_least64_t byt_push_sent =
			stats->traffic_byt_push_sent -
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
	s->rate_tracker.timestamp = (int_least64_t)now;
}

/* Appends the per-tunnel session status section to the response body. */
static void append_sessions(
	struct api_ctx *restrict ctx, const struct server_stats *restrict stats)
{
	VBUF_APPENDSTR(ctx->cbuf, "\n> Sessions\n");
	for (size_t i = 0; i < stats->num_tunnels; i++) {
		const struct tunnel_stats *const restrict t =
			&stats->tunnels[i];
		if (t->peer_identity == NULL) {
			continue;
		}
		char id[IDENTITY_ESCAPED_MAX];
		escape_identity(id, sizeof(id), t->peer_identity, ESCAPE_PLAIN);
		if (!t->established) {
			VBUF_APPENDF(ctx->cbuf, "%-20s: offline\n", id);
			continue;
		}
		FORMAT_BYTES(rx_str, t->rx_window);
		FORMAT_BYTES(tx_str, t->tx_window);
		if (t->rtt_ns > 0) {
			FORMAT_DURATION(
				rtt_str, make_duration_nanos(t->rtt_ns));
			VBUF_APPENDF(
				ctx->cbuf, "%-20s: W=Rx %s, Tx %s; RTT %s\n",
				id, rx_str, tx_str, rtt_str);
		} else {
			VBUF_APPENDF(
				ctx->cbuf, "%-20s: W=Rx %s, Tx %s\n", id,
				rx_str, tx_str);
		}
	}
}

/* Appends the recent event log section to the response body. */
static void append_eventlog(
	struct api_ctx *restrict ctx, const struct server_stats *restrict stats)
{
	VBUF_APPENDSTR(ctx->cbuf, "\n> Recent Events\n");
	const struct server_evlog *const restrict evlog = stats->evlog;
	const size_t evlog_size = ARRAY_SIZE(evlog->entries);
	const size_t n = MIN(evlog->len, 10);
	for (size_t i = 0; i < n; i++) {
		const size_t idx =
			(evlog->pos + evlog_size - 1 - i) % evlog_size;
		const struct server_evlog_entry *const restrict e =
			&evlog->entries[idx];
		char ts[32] = "(unknown)";
		if (e->timestamp != (time_t)-1) {
			(void)format_rfc3339(
				ts, sizeof(ts), e->timestamp,
				local_tzoff(e->timestamp));
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

	struct server *const restrict s = ctx->s;
	const struct config *const restrict conf = s->conf;
	struct server_stats *const restrict stats = server_stats(s);
	if (stats == NULL) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	const int_fast64_t now = clock_monotonic_ns();
	const time_t server_time = time(NULL);
	char timestamp[32] = "(unknown)";
	if (server_time != (time_t)-1) {
		(void)format_rfc3339(
			timestamp, sizeof(timestamp), server_time,
			local_tzoff(server_time));
	}
	FORMAT_DURATION(str_uptime, make_duration_nanos(now - s->started));

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
		ctx->cbuf, "%-20s: %zu / %" PRIuLEAST64 " (+%zu)\n", "Sessions",
		stats->num_sessions, sessions_active(stats),
		stats->num_session_halfopen);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %zu (+%zu)\n", "Streams", stats->num_streams,
		stats->num_stream_halfopen);
	VBUF_APPENDF(
		ctx->cbuf,
		"%-20s: %" PRIuLEAST64 " active (%" PRIuLEAST64
		" fastopen), %" PRIuLEAST64 " passive\n",
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
		ctx->cbuf,
		"%-20s: %" PRIuLEAST64 " accepted, %" PRIuLEAST64
		" served (%" PRIuLEAST64 " rejected)\n",
		"Mux Listener", stats->num_accepted, stats->num_served,
		stats->num_rejected);
	VBUF_APPENDF(
		ctx->cbuf,
		"%-20s: %" PRIuLEAST64 " accepted, %" PRIuLEAST64 " served\n",
		"Stream Listener", stats->num_accepted_tcp,
		stats->num_served_tcp);
	VBUF_APPENDF(
		ctx->cbuf,
		"%-20s: %" PRIuLEAST64 " accepted, %" PRIuLEAST64 " served\n",
		"API Listener", stats->num_accepted_api, stats->num_served_api);
#if WITH_TLS
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %" PRIuLEAST64 "\n", "TLS Failures",
		stats->num_tls_failures);
#endif
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %" PRIuLEAST64 "\n", "Reconnects",
		stats->num_reconnects);
	VBUF_APPENDF(
		ctx->cbuf,
		"%-20s: sent %" PRIuLEAST64 ", recv %" PRIuLEAST64 "\n",
		"RST Frames", stats->num_rst_sent, stats->num_rst_recv);
	VBUF_APPENDF(
		ctx->cbuf, "%-20s: %" PRIuLEAST64 "\n", "Stream Errors",
		stats->num_stream_errors);
	{
		/* Wire size of one frame: header plus the configured payload
		 * cap. conf_load_mux() always clamps this to at least
		 * MUX_MIN_FRAME_PAYLOAD, so no fallback is needed here. */
		const size_t frame_size = MUX_FRAME_HEADER_SIZE +
					  (size_t)conf->mux.max_frame_payload;
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
	free(stats);
}

/* Emit HELP + TYPE header only (use once before multiple VAL/VAL_L lines) */
#define APPEND_METRIC_HDR(name, type, help)                                    \
	VBUF_APPENDF(                                                          \
		cbuf,                                                          \
		"# HELP multiplexd_%s %s\n"                                    \
		"# TYPE multiplexd_%s %s\n",                                   \
		name, help, name, type)

/* Emit one metric line without HELP/TYPE */
#define APPEND_METRIC_VAL(name, fmt, ...)                                      \
	VBUF_APPENDF(cbuf, "multiplexd_%s " fmt "\n", name, __VA_ARGS__)

/* Emit one labeled metric line without HELP/TYPE */
#define APPEND_METRIC_L(name, labels, fmt, ...)                                \
	VBUF_APPENDF(                                                          \
		cbuf, "multiplexd_%s{" labels "} " fmt "\n", name,             \
		__VA_ARGS__)

/* Emits # HELP and # TYPE lines, then one unlabeled sample. */
#define APPEND_METRIC(name, type, help, fmt, val)                              \
	do {                                                                   \
		APPEND_METRIC_HDR(name, type, help);                           \
		APPEND_METRIC_VAL(name, fmt, val);                             \
	} while (0)

#define APPEND_METRIC_LISTENER(name, type, help, mux_val, tcp_val, api_val)    \
	do {                                                                   \
		APPEND_METRIC_HDR(name, type, help);                           \
		APPEND_METRIC_L(                                               \
			name, "listener=\"%s\"", "%" PRIuLEAST64, "mux",       \
			mux_val);                                              \
		APPEND_METRIC_L(                                               \
			name, "listener=\"%s\"", "%" PRIuLEAST64, "local",     \
			tcp_val);                                              \
		APPEND_METRIC_L(                                               \
			name, "listener=\"%s\"", "%" PRIuLEAST64, "api",       \
			api_val);                                              \
	} while (0)

/* Appends the point-in-time gauge metrics (session/stream counts, uptime). */
static struct vbuffer *append_gauge_metrics(
	struct vbuffer *restrict cbuf,
	const struct server_stats *restrict stats, const double uptime)
{
	APPEND_METRIC(
		"uptime_seconds", "gauge", "Seconds since server start", "%.3f",
		uptime);
	APPEND_METRIC(
		"sessions", "gauge", "Total mux session objects",
		"%" PRIuLEAST64, sessions_active(stats));
	APPEND_METRIC(
		"sessions_established", "gauge", "Established mux sessions",
		"%zu", stats->num_sessions);
	APPEND_METRIC(
		"sessions_halfopen", "gauge",
		"Half-open mux sessions (after accept, before established)",
		"%zu", stats->num_session_halfopen);
	APPEND_METRIC(
		"streams", "gauge", "Active mux streams", "%zu",
		stats->num_streams);
	APPEND_METRIC(
		"streams_halfopen", "gauge",
		"Half-open mux streams (SYN sent, before SYN-ACK)", "%zu",
		stats->num_stream_halfopen);
	return cbuf;
}

/* Appends stream lifecycle counters and the establishment-latency summary. */
static struct vbuffer *append_stream_metrics(
	struct vbuffer *restrict cbuf,
	const struct server_stats *restrict stats)
{
	APPEND_METRIC(
		"stream_open_total", "counter",
		"Total successful active-open stream creations",
		"%" PRIuLEAST64, stats->num_stream_opened);
	APPEND_METRIC(
		"stream_accept_total", "counter",
		"Total successful passive-open stream creations",
		"%" PRIuLEAST64, stats->num_stream_accepted);
	APPEND_METRIC(
		"stream_fastopen_total", "counter",
		"Total active-open streams whose first flight used SYN|PUSH",
		"%" PRIuLEAST64, stats->num_stream_fastopen);
	APPEND_METRIC_HDR(
		"stream_establish_latency_seconds", "summary",
		"Active-open stream establishment latency from SYN to SYN|ACK");
	if (stats->stream_establish_count > 0) {
		APPEND_METRIC_L(
			"stream_establish_latency_seconds", "quantile=\"%s\"",
			"%g", "0.5",
			(double)stats->stream_establish_p50 * 1e-9);
		APPEND_METRIC_L(
			"stream_establish_latency_seconds", "quantile=\"%s\"",
			"%g", "0.9",
			(double)stats->stream_establish_p90 * 1e-9);
		APPEND_METRIC_L(
			"stream_establish_latency_seconds", "quantile=\"%s\"",
			"%g", "0.99",
			(double)stats->stream_establish_p99 * 1e-9);
	}
	APPEND_METRIC_VAL(
		"stream_establish_latency_seconds_count", "%" PRIuLEAST64,
		stats->num_stream_established);
	return cbuf;
}

/* Appends connection-lifecycle and error/backlog counters. */
static struct vbuffer *append_connection_metrics(
	struct vbuffer *restrict cbuf,
	const struct server_stats *restrict stats)
{
	APPEND_METRIC_LISTENER(
		"connections_accepted_total", "counter",
		"Total accepted connections", stats->num_accepted,
		stats->num_accepted_tcp, stats->num_accepted_api);
	APPEND_METRIC_LISTENER(
		"connections_served_total", "counter",
		"Connections that reached protocol setup", stats->num_served,
		stats->num_served_tcp, stats->num_served_api);
	APPEND_METRIC(
		"connections_rejected_total", "counter",
		"Connections dropped by startup_limit", "%" PRIuLEAST64,
		stats->num_rejected);

#if WITH_TLS
	APPEND_METRIC(
		"tls_failures_total", "counter", "TLS accept failures",
		"%" PRIuLEAST64, stats->num_tls_failures);
#endif
	APPEND_METRIC(
		"reconnects_total", "counter", "Client-mode reconnect attempts",
		"%" PRIuLEAST64, stats->num_reconnects);
	APPEND_METRIC(
		"rst_sent_total", "counter", "RST frames sent", "%" PRIuLEAST64,
		stats->num_rst_sent);
	APPEND_METRIC(
		"rst_recv_total", "counter", "RST frames received",
		"%" PRIuLEAST64, stats->num_rst_recv);
	APPEND_METRIC(
		"stream_errors_total", "counter",
		"Streams aborted due to local I/O errors", "%" PRIuLEAST64,
		stats->num_stream_errors);
	APPEND_METRIC(
		"recv_buffered_bytes", "gauge",
		"Bytes buffered in per-stream receive rings", "%zu",
		stats->recv_buffered_bytes);
	APPEND_METRIC(
		"send_buffered_frames", "gauge",
		"Frames queued in per-stream send buffers", "%zu",
		stats->send_buffered_frames);
	APPEND_METRIC(
		"unacked_frames", "gauge",
		"Frames held in the session unacked list (spec §5.7.2)", "%zu",
		stats->unacked_frames);
	return cbuf;
}

/* Appends all per-tunnel Prometheus metrics. */
static struct vbuffer *append_tunnel_metrics(
	struct vbuffer *restrict cbuf,
	const struct server_stats *restrict stats)
{
/* Emit a paired rx/tx sample (one series per direction) for every kept
 * tunnel. The metric name is spelled once (@p name): the header and both
 * sample lines all derive their "multiplexd_<name>" prefix from it via the
 * runtime %s, so # TYPE and the samples cannot silently diverge. @p valfmt is
 * the value's printf conversion (a string literal, e.g. "%zu"). */
#define APPEND_TUNNEL_METRIC_RXTX(                                                     \
	name, help, type, valfmt, keep_cond, rx_val, tx_val)                           \
	do {                                                                           \
		bool hdr = false;                                                      \
		for (size_t i = 0; i < stats->num_tunnels; i++) {                      \
			const struct tunnel_stats *restrict t =                        \
				&stats->tunnels[i];                                    \
			if (!(keep_cond) || t->peer_identity == NULL) {                \
				continue;                                              \
			}                                                              \
			if (!hdr) {                                                    \
				APPEND_METRIC_HDR(name, type, help);                   \
				hdr = true;                                            \
			}                                                              \
			char esc_id[IDENTITY_ESCAPED_MAX];                             \
			escape_identity(                                               \
				esc_id, sizeof(esc_id), t->peer_identity,              \
				ESCAPE_METRIC);                                        \
			VBUF_APPENDF(                                                  \
				cbuf,                                                  \
				"multiplexd_%s{identity=\"%s\",tunnel=\"%" PRIuLEAST64 \
				"\",direction=\"rx\"} " valfmt "\n"                    \
				"multiplexd_%s{identity=\"%s\",tunnel=\"%" PRIuLEAST64 \
				"\",direction=\"tx\"} " valfmt "\n",                   \
				name, esc_id, t->tunnel_index, (rx_val), name,         \
				esc_id, t->tunnel_index, (tx_val));                    \
		}                                                                      \
	} while (0)

#define APPEND_TUNNEL_METRIC(name, help, extra_skip, fmt, val, keep_cond)      \
	do {                                                                   \
		bool hdr = false;                                              \
		for (size_t i = 0; i < stats->num_tunnels; i++) {              \
			const struct tunnel_stats *restrict t =                \
				&stats->tunnels[i];                            \
			if (!(keep_cond) || t->peer_identity == NULL ||        \
			    (extra_skip)) {                                    \
				continue;                                      \
			}                                                      \
			if (!hdr) {                                            \
				APPEND_METRIC_HDR(name, "gauge", help);        \
				hdr = true;                                    \
			}                                                      \
			char esc_id[IDENTITY_ESCAPED_MAX];                     \
			escape_identity(                                       \
				esc_id, sizeof(esc_id), t->peer_identity,      \
				ESCAPE_METRIC);                                \
			APPEND_METRIC_L(                                       \
				name,                                          \
				"identity=\"%s\",tunnel=\"%" PRIuLEAST64 "\"", \
				fmt, esc_id, t->tunnel_index, (val));          \
		}                                                              \
	} while (0)

	APPEND_TUNNEL_METRIC_RXTX(
		"session_bytes_total",
		"Wire bytes on the mux link per identity session", "counter",
		"%" PRIuLEAST64, true, t->byt_mux_recv, t->byt_mux_sent);
	APPEND_TUNNEL_METRIC_RXTX(
		"session_payload_bytes_total",
		"PUSH-frame payload bytes on the mux link per identity session",
		"counter", "%" PRIuLEAST64, true, t->byt_push_recv,
		t->byt_push_sent);
	APPEND_TUNNEL_METRIC_RXTX(
		"session_window_bytes",
		"Per-stream window size per identity session", "gauge", "%zu",
		t->established, t->rx_window, t->tx_window);
	APPEND_TUNNEL_METRIC(
		"session_rtt_seconds", "Round-trip time per identity session",
		t->rtt_ns <= 0, "%g", (double)t->rtt_ns * 1e-9, t->established);
	APPEND_TUNNEL_METRIC_RXTX(
		"session_bdp_bytes",
		"Bandwidth-delay product per identity session", "gauge", "%zu",
		t->established && (t->bdp_rx != 0 || t->bdp_tx != 0), t->bdp_rx,
		t->bdp_tx);

#undef APPEND_TUNNEL_METRIC_RXTX
#undef APPEND_TUNNEL_METRIC

	return cbuf;
}

/* Handles GET /metrics — Prometheus text format (version 0.0.4). */
static void handle_metrics(struct api_ctx *restrict ctx)
{
	struct server *const restrict s = ctx->s;
	struct server_stats *const restrict stats = server_stats(s);
	if (stats == NULL) {
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const int_fast64_t now = clock_monotonic_ns();
	const double uptime = (double)(now - s->started) / 1e9;

	VBUF_RESET(ctx->cbuf);
	struct vbuffer *restrict cbuf = ctx->cbuf;

	/* Force LC_NUMERIC=C for the duration: init() runs setlocale(LC_ALL, ""),
	 * so a comma-decimal operator locale (de_DE, fr_FR, ...) would make the six
	 * stdio %f/%g samples below emit "1234,567", which Prometheus's value lexer
	 * rejects -- failing the entire scrape. Same class as the Date header's
	 * LC_TIME hazard. newlocale("C") is effectively infallible; on the off
	 * chance it fails, fall back to the environment locale rather than error. */
	const locale_t c_numeric = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
	const locale_t saved_locale =
		c_numeric != (locale_t)0 ? uselocale(c_numeric) : (locale_t)0;

	cbuf = append_gauge_metrics(cbuf, stats, uptime);
	cbuf = append_stream_metrics(cbuf, stats);
	cbuf = append_connection_metrics(cbuf, stats);
	cbuf = append_tunnel_metrics(cbuf, stats);
	{
		struct timespec cpu_ts;
		if (clock_process(&cpu_ts)) {
			APPEND_METRIC(
				"process_cpu_seconds_total", "counter",
				"Total process CPU time consumed", "%g",
				(double)TIMESPEC_NANO(cpu_ts) * 1e-9);
		}
	}

	if (c_numeric != (locale_t)0) {
		(void)uselocale(saved_locale);
		freelocale(c_numeric);
	}

	ctx->cbuf = cbuf;
	if (VBUF_HAS_OOM(ctx->cbuf)) {
		free(stats);
		respond_status(ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	respond_ok(
		ctx, "text/plain; version=0.0.4; charset=utf-8",
		ctx->cbuf->len);
	free(stats);
}

/* Handles GET /config — serializes the active configuration as JSON. */
static void handle_config_get(struct api_ctx *restrict ctx)
{
	size_t len;
	char *const restrict json = conf_dump(ctx->s->conf, &len, NULL);
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
}

/* Handles PUT /config — parse the request body as a new config and hot-reload. */
static void handle_config_put(struct api_ctx *restrict ctx)
{
	if (!ctx->content_length_seen) {
		respond_status(ctx, HTTP_LENGTH_REQUIRED);
		return;
	}
	if (ctx->content_length == 0) {
		/* Content-Length was supplied, just zero: a well-formed framing
		 * declaration, not a missing header -- a config body can never
		 * legitimately be empty, so this is a parse error, not 411. */
		respond_status(ctx, HTTP_BAD_REQUEST);
		return;
	}
	struct config *const restrict new_conf =
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
	if (path == NULL) {
		/* "//", "//host" or "x" (no leading slash) */
		respond_status(ctx, HTTP_BAD_REQUEST);
		return;
	}

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

/* True if the comma-separated Connection header value (RFC 7230 6.1) contains a
 * case-insensitive "close" token, so that a token-list form such as
 * "keep-alive, close" or "TE, close" is honored, not only a bare "close".
 * Optional whitespace around the commas is trimmed. */
static bool connection_has_close(const char *restrict value)
{
	const char *p = value;
	while (*p != '\0') {
		/* Skip leading OWS and empty (comma-only) list elements. */
		while (*p == ' ' || *p == '\t' || *p == ',') {
			p++;
		}
		const char *const start = p;
		while (*p != '\0' && *p != ',') {
			p++;
		}
		/* Trim trailing OWS from the [start, end) token. */
		const char *end = p;
		while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
			end--;
		}
		if ((size_t)(end - start) == 5 &&
		    strncasecmp(start, "close", 5) == 0) {
			return true;
		}
	}
	return false;
}

/* Returns true if the connection should be kept alive after the response. */
static bool api_should_keepalive(const struct api_ctx *restrict ctx)
{
	const char *const version = ctx->msg.req.version;
	if (version == NULL || strncmp(version, "HTTP/1.1", 8) != 0) {
		return false;
	}
	return !ctx->close_requested;
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct api_ctx *const restrict ctx = watcher->data;

	/* Logical send buffer: wbuf (headers) then cbuf (body, /metrics only);
	 * wpos tracks position across both. */
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
		if (sock_would_block(err)) {
			return; /* wait for EV_WRITE */
		}
		LOGD_F("api [fd:%d]: send: (%d) %s", ctx->fd, err,
		       strerror(err));
		api_ctx_free(loop, ctx);
		return;
	}
	ctx->wpos += len;
	/* Progress made: push the idle timeout forward. */
	ev_timer_again(loop, &ctx->w_timeout);
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
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_start(loop, &ctx->w_send);
}

/* Read and parse the request incrementally; dispatch to api_handle() when headers are complete. */
static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct api_ctx *const restrict ctx = watcher->data;

	/* Reserve one byte so received data can always be NUL-terminated for the
	 * strstr-based HTTP parser.  When only that byte remains, the request has
	 * filled the buffer without completing its headers: too large. */
	const size_t cap = ctx->rbuf.cap - ctx->rbuf.len;
	if (cap <= 1) {
		recv_error(loop, ctx, HTTP_ENTITY_TOO_LARGE);
		return;
	}

	size_t n = cap - 1;
	const int err =
		socket_recv(ctx->fd, ctx->rbuf.data + ctx->rbuf.len, &n);
	if (err != 0) {
		if (sock_would_block(err)) {
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
	/* NUL-terminate so http_parse/http_parsehdr can use strstr; the byte
	 * reserved above guarantees room. */
	ctx->rbuf.data[ctx->rbuf.len] = '\0';

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
			/* value points into the NUL-terminated rbuf, so parse it
			 * now and accumulate: no truncation, and a repeated
			 * Connection header combines instead of overwriting. */
			ctx->close_requested |= connection_has_close(value);
		} else if (strcasecmp(key, "Content-Length") == 0) {
			/* RFC 7230 3.3.3: a second Content-Length is an
			 * unrecoverable framing ambiguity, not "last one wins". */
			if (ctx->content_length_seen) {
				recv_error(loop, ctx, HTTP_BAD_REQUEST);
				return;
			}
			/* RFC 7230 3.3.2: Content-Length = 1*DIGIT. strtoul()
			 * alone accepts leading whitespace, '+', or '-'. */
			if (!isdigit((unsigned char)value[0])) {
				recv_error(loop, ctx, HTTP_BAD_REQUEST);
				return;
			}
			char *endptr;
			errno = 0;
			const unsigned long cl = strtoul(value, &endptr, 10);
			if (endptr == value || *endptr != '\0' ||
			    errno == ERANGE) {
				recv_error(loop, ctx, HTTP_BAD_REQUEST);
				return;
			}
			ctx->content_length = (size_t)cl;
			ctx->content_length_seen = true;
		} else if (strcasecmp(key, "Transfer-Encoding") == 0) {
			/* RFC 7230 3.3.3: reject a transfer-coding this server
			 * cannot decode instead of misparsing the body. */
			recv_error(loop, ctx, HTTP_NOT_IMPLEMENTED);
			return;
		}
	}

	/* Wait for the complete request body before dispatching */
	const size_t body_off =
		(size_t)((unsigned char *)ctx->next - ctx->rbuf.data);
	if (ctx->content_length > 0) {
		/* rbuf.len can reach at most cap - 1 (recv_cb reserves one byte
		 * for NUL-termination), so a Content-Length that would require
		 * exactly cap - body_off bytes can never actually be satisfied. */
		if (ctx->content_length > ctx->rbuf.cap - 1 - body_off) {
			recv_error(loop, ctx, HTTP_ENTITY_TOO_LARGE);
			return;
		}
		if (ctx->rbuf.len - body_off < ctx->content_length) {
			return; /* wait for more body data */
		}
	}
	/* This server does not support request pipelining; api_ctx_reset discards
	 * the rx buffer, so any bytes past this request's body would be silently
	 * lost.  Force the connection closed instead of keeping it alive. */
	const bool has_trailing =
		ctx->rbuf.len > body_off + ctx->content_length;

	/* All headers received; handle the request and respond.  Keep the idle
	 * timeout running while responding. */
	ctx->keepalive = api_should_keepalive(ctx) && !has_trailing;
	ev_timer_again(loop, &ctx->w_timeout);
	ev_io_stop(loop, &ctx->w_recv);
	api_handle(ctx);
	ctx->wpos = 0;
	ev_io_start(loop, &ctx->w_send);
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct api_ctx *const restrict ctx = watcher->data;
	LOGD_F("api [fd:%d]: timeout", ctx->fd);
	api_ctx_free(loop, ctx);
}

static struct api_ctx *api_ctx_new(struct server *restrict s, const int fd)
{
	struct api_ctx *const restrict ctx = malloc(sizeof(struct api_ctx));
	if (ctx == NULL) {
		LOGOOM();
		return NULL;
	}
	*ctx = (struct api_ctx){
		.s = s,
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
	(void)accepted_sa;
	struct server *const restrict s = l->srv;
	struct api_ctx *const restrict ctx = api_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		socket_close(accepted_fd);
		return;
	}
	s->counters.num_served_api++;
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_again(loop, &ctx->w_timeout);
}
