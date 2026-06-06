/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "utils/testing.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

T_DECLARE_CASE(test_http_parse_request)
{
	char buf[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
	struct http_message msg;
	char *next = http_parse(buf, &msg);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(msg.req.method, "GET");
	T_EXPECT_STREQ(msg.req.url, "/index.html");
	T_EXPECT_STREQ(msg.req.version, "HTTP/1.1");
	T_LOGF("http_parse request: method=%s url=%s version=%s",
	       msg.req.method, msg.req.url, msg.req.version);
}

T_DECLARE_CASE(test_http_parse_response)
{
	char buf[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
	struct http_message msg;
	char *next = http_parse(buf, &msg);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(msg.rsp.version, "HTTP/1.1");
	T_EXPECT_STREQ(msg.rsp.code, "200");
	T_EXPECT_STREQ(msg.rsp.status, "OK");
	T_LOGF("http_parse response: version=%s code=%s status=%s",
	       msg.rsp.version, msg.rsp.code, msg.rsp.status);
}

T_DECLARE_CASE(test_http_parse_incomplete)
{
	char buf[] = "GET /index.html HTTP/1.1";
	struct http_message msg;
	char *next = http_parse(buf, &msg);
	/* incomplete message, should return the same buffer */
	T_EXPECT_EQ(next, buf);
	T_LOGF("%s", "http_parse incomplete: wait for more data");
}

T_DECLARE_CASE(test_http_parse_invalid)
{
	char buf[] = "INVALID\r\n";
	struct http_message msg;
	char *next = http_parse(buf, &msg);
	/* missing fields, should return NULL */
	T_EXPECT(next == NULL);
	T_LOGF("%s", "http_parse invalid: parsing failed as expected");
}

T_DECLARE_CASE(test_http_parse_missing_field3)
{
	char buf[] = "GET /index.html\r\n";
	struct http_message msg;
	char *next = http_parse(buf, &msg);
	/* missing third field (version), should return NULL */
	T_EXPECT(next == NULL);
	T_LOGF("%s", "http_parse missing field3: parsing failed as expected");
}

T_DECLARE_CASE(test_http_parsehdr)
{
	char buf[] = "Host: example.com\r\nContent-Type: text/html\r\n\r\n";
	char *key, *value;

	char *next = http_parsehdr(buf, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(key, "Host");
	T_EXPECT_STREQ(value, "example.com");
	T_LOGF("http_parsehdr: key=%s value=%s", key, value);

	next = http_parsehdr(next, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(key, "Content-Type");
	T_EXPECT_STREQ(value, "text/html");
	T_LOGF("http_parsehdr: key=%s value=%s", key, value);

	/* end of headers */
	next = http_parsehdr(next, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT(key == NULL);
	T_EXPECT(value == NULL);
	T_LOGF("%s", "http_parsehdr: end of headers");
}

T_DECLARE_CASE(test_http_parsehdr_incomplete)
{
	char buf[] = "Host: example.com";
	char *key, *value;
	char *next = http_parsehdr(buf, &key, &value);
	/* incomplete header, should return the same buffer */
	T_EXPECT_EQ(next, buf);
	T_LOGF("%s", "http_parsehdr incomplete: wait for more data");
}

T_DECLARE_CASE(test_http_parsehdr_invalid)
{
	char buf[] = "InvalidHeader\r\n";
	char *key, *value;
	char *next = http_parsehdr(buf, &key, &value);
	/* missing colon, should return NULL */
	T_EXPECT(next == NULL);
	T_LOGF("%s", "http_parsehdr invalid: parsing failed as expected");
}

T_DECLARE_CASE(test_http_status)
{
	const char *status;

	status = http_status(HTTP_OK);
	T_EXPECT(status != NULL);
	T_EXPECT_STREQ(status, "OK");
	T_LOGF("http_status 200: %s", status);

	status = http_status(HTTP_NOT_FOUND);
	T_EXPECT(status != NULL);
	T_EXPECT_STREQ(status, "Not Found");
	T_LOGF("http_status 404: %s", status);

	status = http_status(HTTP_INTERNAL_SERVER_ERROR);
	T_EXPECT(status != NULL);
	T_EXPECT_STREQ(status, "Internal Server Error");
	T_LOGF("http_status 500: %s", status);

	/* unknown status code */
	status = http_status(999);
	T_EXPECT(status == NULL);
	T_LOGF("%s", "http_status 999: (null) as expected");
}

T_DECLARE_CASE(test_http_date)
{
	char buf[64];
	size_t len = http_date(buf, sizeof(buf));
	T_EXPECT(len > 0);
	T_LOGF("http_date: %s (len=%zu)", buf, len);
}

T_DECLARE_CASE(test_http_error)
{
	char buf[1024];
	int len;

	len = http_error(buf, sizeof(buf), HTTP_NOT_FOUND);
	T_EXPECT(len > 0);
	T_LOGF("http_error 404: len=%d", len);

	len = http_error(buf, sizeof(buf), HTTP_INTERNAL_SERVER_ERROR);
	T_EXPECT(len > 0);
	T_LOGF("http_error 500: len=%d", len);

	/* status code with NULL desc, should use name as desc */
	len = http_error(buf, sizeof(buf), HTTP_OK);
	T_EXPECT(len > 0);
	T_LOGF("http_error 200: len=%d (desc is NULL)", len);

	/* unknown status code */
	len = http_error(buf, sizeof(buf), 999);
	T_EXPECT_EQ(len, 0);
	T_LOGF("http_error 999: len=%d (unknown code)", len);
}

/* HTTP/1.1 Compliance Tests */

T_DECLARE_CASE(test_http_methods)
{
	/* Test various HTTP methods */
	const char *methods[] = { "GET",     "POST",  "PUT",   "DELETE", "HEAD",
				  "OPTIONS", "PATCH", "TRACE", "CONNECT" };

	for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s /path HTTP/1.1\r\n", methods[i]);
		struct http_message msg;
		char *next = http_parse(buf, &msg);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(msg.req.method, methods[i]);
		T_EXPECT_STREQ(msg.req.url, "/path");
		T_EXPECT_STREQ(msg.req.version, "HTTP/1.1");
		T_LOGF("http method %s: OK", methods[i]);
	}
}

T_DECLARE_CASE(test_http_urls)
{
	/* Test various URL formats */
	struct {
		const char *url;
		const char *desc;
	} urls[] = {
		{ "/", "root" },
		{ "/index.html", "simple path" },
		{ "/path/to/resource", "nested path" },
		{ "/file.txt?query=value", "with query string" },
		{ "/file?a=1&b=2", "multiple params" },
		{ "/path?q=hello%20world", "url encoded" },
		{ "/path#anchor", "with fragment" },
		{ "http://example.com/path", "absolute URI" },
		{ "/path?q=a&r=b#frag", "query and fragment" },
		{ "*", "asterisk (OPTIONS)" },
	};

	for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
		char buf[256];
		snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\n", urls[i].url);
		struct http_message msg;
		char *next = http_parse(buf, &msg);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(msg.req.url, urls[i].url);
		T_LOGF("http URL %s: %s", urls[i].desc, urls[i].url);
	}
}

T_DECLARE_CASE(test_http_versions)
{
	/* Test HTTP version strings */
	const char *versions[] = {
		"HTTP/1.0",
		"HTTP/1.1",
		"HTTP/2.0",
	};

	for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		char buf[256];
		snprintf(buf, sizeof(buf), "GET / %s\r\n", versions[i]);
		struct http_message msg;
		char *next = http_parse(buf, &msg);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(msg.req.version, versions[i]);
		T_LOGF("http version: %s", versions[i]);
	}
}

T_DECLARE_CASE(test_http_response_codes)
{
	/* Test various response codes */
	struct {
		uint_least16_t code;
		const char *name;
	} codes[] = {
		{ HTTP_CONTINUE, "Continue" },
		{ HTTP_OK, "OK" },
		{ HTTP_CREATED, "Created" },
		{ HTTP_NO_CONTENT, "No Content" },
		{ HTTP_MOVED_PERMANENTLY, "Moved Permanently" },
		{ HTTP_FOUND, "Found" },
		{ HTTP_BAD_REQUEST, "Bad Request" },
		{ HTTP_UNAUTHORIZED, "Unauthorized" },
		{ HTTP_FORBIDDEN, "Forbidden" },
		{ HTTP_NOT_FOUND, "Not Found" },
		{ HTTP_METHOD_NOT_ALLOWED, "Method Not Allowed" },
		{ HTTP_TOO_MANY_REQUESTS, "Too Many Requests" },
		{ HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error" },
		{ HTTP_NOT_IMPLEMENTED, "Not Implemented" },
		{ HTTP_SERVICE_UNAVAILABLE, "Service Unavailable" },
	};

	for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
		const char *name = http_status(codes[i].code);
		T_EXPECT(name != NULL);
		T_EXPECT_STREQ(name, codes[i].name);
		T_LOGF("http status %d: %s", codes[i].code, name);
	}
}

T_DECLARE_CASE(test_http_header_whitespace)
{
	/* Test header value with leading/trailing whitespace */
	char buf[] = "Content-Type:   text/html   \r\n\r\n";
	char *key, *value;
	char *next = http_parsehdr(buf, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(key, "Content-Type");
	/* RFC 7230: trailing OWS is stripped */
	T_EXPECT_STREQ(value, "text/html");
	T_LOGF("http header whitespace: key='%s' value='%s'", key, value);
}

T_DECLARE_CASE(test_http_header_tabs)
{
	/* Test header value with tabs */
	char buf[] = "X-Custom:\t\tvalue\t\t\r\n\r\n";
	char *key, *value;
	char *next = http_parsehdr(buf, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(key, "X-Custom");
	/* RFC 7230: trailing OWS (including tabs) is stripped */
	T_EXPECT_STREQ(value, "value");
	T_LOGF("http header tabs: key='%s' value='%s'", key, value);
}

T_DECLARE_CASE(test_http_multiple_headers)
{
	/* Test parsing multiple headers */
	char buf[] = "Host: example.com\r\n"
		     "User-Agent: TestAgent/1.0\r\n"
		     "Accept: */*\r\n"
		     "Connection: keep-alive\r\n"
		     "\r\n";

	struct {
		const char *key;
		const char *value;
	} expected[] = {
		{ "Host", "example.com" },
		{ "User-Agent", "TestAgent/1.0" },
		{ "Accept", "*/*" },
		{ "Connection", "keep-alive" },
	};

	char *next = buf;
	for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
		char *key, *value;
		next = http_parsehdr(next, &key, &value);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(key, expected[i].key);
		T_EXPECT_STREQ(value, expected[i].value);
		T_LOGF("http multiple headers [%zu]: %s: %s", i, key, value);
	}

	/* Verify end of headers */
	char *key, *value;
	next = http_parsehdr(next, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT(key == NULL);
	T_EXPECT(value == NULL);
	T_LOGF("%s", "http multiple headers: end reached");
}

T_DECLARE_CASE(test_http_empty_header_value)
{
	/* Test header with empty value */
	char buf[] = "X-Empty:\r\n\r\n";
	char *key, *value;
	char *next = http_parsehdr(buf, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(key, "X-Empty");
	T_EXPECT_STREQ(value, "");
	T_LOGF("http empty header value: '%s'", value);
}

T_DECLARE_CASE(test_http_request_line_spacing)
{
	/* Test request line with single spaces (RFC compliant) */
	char buf[] = "GET /test HTTP/1.1\r\n";
	struct http_message msg;
	char *next = http_parse(buf, &msg);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(msg.req.method, "GET");
	T_EXPECT_STREQ(msg.req.url, "/test");
	T_EXPECT_STREQ(msg.req.version, "HTTP/1.1");
	T_LOGF("%s", "http request single space: OK");
}

T_DECLARE_CASE(test_http_chunked_encoding_header)
{
	/* Test Transfer-Encoding header */
	char buf[] = "Transfer-Encoding: chunked\r\n\r\n";
	char *key, *value;
	char *next = http_parsehdr(buf, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(key, "Transfer-Encoding");
	T_EXPECT_STREQ(value, "chunked");
	T_LOGF("http Transfer-Encoding: %s", value);
}

T_DECLARE_CASE(test_http_content_length_header)
{
	/* Test Content-Length header */
	char buf[] = "Content-Length: 1234\r\n\r\n";
	char *key, *value;
	char *next = http_parsehdr(buf, &key, &value);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(key, "Content-Length");
	T_EXPECT_STREQ(value, "1234");
	T_LOGF("http Content-Length: %s", value);
}

T_DECLARE_CASE(test_http_connection_header)
{
	/* Test Connection header values */
	const char *values[] = { "close", "keep-alive", "upgrade" };

	for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		char buf[256];
		snprintf(buf, sizeof(buf), "Connection: %s\r\n\r\n", values[i]);
		char *key, *value;
		char *next = http_parsehdr(buf, &key, &value);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(key, "Connection");
		T_EXPECT_STREQ(value, values[i]);
		T_LOGF("http Connection: %s", value);
	}
}

T_DECLARE_CASE(test_http_complete_request)
{
	/* Test complete HTTP/1.1 request */
	char buf[] = "POST /api/users HTTP/1.1\r\n"
		     "Host: api.example.com\r\n"
		     "Content-Type: application/json\r\n"
		     "Content-Length: 27\r\n"
		     "Connection: keep-alive\r\n"
		     "\r\n";

	struct http_message msg;
	char *next = http_parse(buf, &msg);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(msg.req.method, "POST");
	T_EXPECT_STREQ(msg.req.url, "/api/users");
	T_EXPECT_STREQ(msg.req.version, "HTTP/1.1");

	char *key, *value;

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Host");
	T_EXPECT_STREQ(value, "api.example.com");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Content-Type");
	T_EXPECT_STREQ(value, "application/json");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Content-Length");
	T_EXPECT_STREQ(value, "27");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Connection");
	T_EXPECT_STREQ(value, "keep-alive");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT(key == NULL);
	T_EXPECT(value == NULL);

	T_LOGF("%s", "http complete request: parsed successfully");
}

T_DECLARE_CASE(test_http_complete_response)
{
	/* Test complete HTTP/1.1 response */
	char buf[] = "HTTP/1.1 200 OK\r\n"
		     "Date: Mon, 27 Jan 2026 12:00:00 GMT\r\n"
		     "Content-Type: text/html; charset=UTF-8\r\n"
		     "Content-Length: 138\r\n"
		     "Connection: keep-alive\r\n"
		     "\r\n";

	struct http_message msg;
	char *next = http_parse(buf, &msg);
	T_EXPECT(next != NULL);
	T_EXPECT_STREQ(msg.rsp.version, "HTTP/1.1");
	T_EXPECT_STREQ(msg.rsp.code, "200");
	T_EXPECT_STREQ(msg.rsp.status, "OK");

	char *key, *value;

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Date");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Content-Type");
	T_EXPECT_STREQ(value, "text/html; charset=UTF-8");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Content-Length");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT_STREQ(key, "Connection");

	next = http_parsehdr(next, &key, &value);
	T_EXPECT(key == NULL);

	T_LOGF("%s", "http complete response: parsed successfully");
}

T_DECLARE_CASE(test_http_parsehdr_trailing_ows)
{
	/* RFC 7230 Section 3.2: trailing OWS must be stripped from field values */

	/* Spaces only */
	{
		char buf[] = "X-A: value   \r\n\r\n";
		char *key, *value;
		char *next = http_parsehdr(buf, &key, &value);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(key, "X-A");
		T_EXPECT_STREQ(value, "value");
		T_LOG("http trailing OWS spaces: stripped OK");
	}

	/* Tabs only */
	{
		char buf[] = "X-B: value\t\t\r\n\r\n";
		char *key, *value;
		char *next = http_parsehdr(buf, &key, &value);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(value, "value");
		T_LOG("http trailing OWS tabs: stripped OK");
	}

	/* Mixed leading and trailing OWS */
	{
		char buf[] = "X-C:  \t value \t \r\n\r\n";
		char *key, *value;
		char *next = http_parsehdr(buf, &key, &value);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(value, "value");
		T_LOG("http mixed OWS: stripped OK");
	}

	/* Value with internal spaces preserved */
	{
		char buf[] = "X-D: foo bar baz \r\n\r\n";
		char *key, *value;
		char *next = http_parsehdr(buf, &key, &value);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(value, "foo bar baz");
		T_LOG("http internal spaces preserved: OK");
	}

	/* Value that is entirely OWS becomes empty string */
	{
		char buf[] = "X-E:    \r\n\r\n";
		char *key, *value;
		char *next = http_parsehdr(buf, &key, &value);
		T_EXPECT(next != NULL);
		T_EXPECT_STREQ(value, "");
		T_LOG("http all-OWS value becomes empty: OK");
	}
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_http_parse_request);
	T_RUN_CASE(t, test_http_parse_response);
	T_RUN_CASE(t, test_http_parse_incomplete);
	T_RUN_CASE(t, test_http_parse_invalid);
	T_RUN_CASE(t, test_http_parse_missing_field3);
	T_RUN_CASE(t, test_http_parsehdr);
	T_RUN_CASE(t, test_http_parsehdr_incomplete);
	T_RUN_CASE(t, test_http_parsehdr_invalid);
	T_RUN_CASE(t, test_http_status);
	T_RUN_CASE(t, test_http_date);
	T_RUN_CASE(t, test_http_error);
	T_RUN_CASE(t, test_http_methods);
	T_RUN_CASE(t, test_http_urls);
	T_RUN_CASE(t, test_http_versions);
	T_RUN_CASE(t, test_http_response_codes);
	T_RUN_CASE(t, test_http_header_whitespace);
	T_RUN_CASE(t, test_http_header_tabs);
	T_RUN_CASE(t, test_http_multiple_headers);
	T_RUN_CASE(t, test_http_empty_header_value);
	T_RUN_CASE(t, test_http_request_line_spacing);
	T_RUN_CASE(t, test_http_chunked_encoding_header);
	T_RUN_CASE(t, test_http_content_length_header);
	T_RUN_CASE(t, test_http_connection_header);
	T_RUN_CASE(t, test_http_complete_request);
	T_RUN_CASE(t, test_http_complete_response);
	T_RUN_CASE(t, test_http_parsehdr_trailing_ows);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
