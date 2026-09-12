/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* main_test.c - white-box tests for parse_args/print_usage in main.c;
 * main() renamed to avoid conflict; the daemon body is compiled but never
 * run; tests inspect only the static args state. */

#include "utils/slog.h"
#include "utils/testing.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Rename the daemon entry point so the test owns main().  main.c's body is
 * never executed here -- it is compiled only so parse_args/print_usage and the
 * static `args` state become reachable in this TU. */
#define main mux_daemon_main
#include "main.c"
#undef main

/* mock - argv builder and args reset helper */

static void reset_args(void)
{
	memset(&args, 0, sizeof(args));
	/* -1 is production's "not given" sentinel (see the args initializer in
	 * main.c); NOTICE would masquerade as an explicit --loglevel. */
	args.loglevel = -1;
}

/* parse_args() rejects a command line by exit()ing, so run it in a child and
 * expect that child to exit with EXIT_FAILURE; a parse_args() that returns
 * instead makes the child exit 0. Flushing first keeps buffered output from
 * being written twice, once by each process. */
T_DECLARE_SUBCASE(expect_parse_args_rejects, const int argc, char *const *argv)
{
	(void)fflush(stdout);
	(void)fflush(stderr);
	const pid_t pid = fork();
	T_CHECK(pid >= 0);
	if (pid == 0) {
		parse_args(argc, argv);
		_exit(EXIT_SUCCESS);
	}
	int status;
	T_CHECK(waitpid(pid, &status, 0) == pid);
	T_EXPECT(WIFEXITED(status));
	T_EXPECT_EQ(WEXITSTATUS(status), EXIT_FAILURE);
}

/* regression - one CLI-parsing decision per case (an error branch exit()s, so
 * a case expecting one runs parse_args through expect_parse_args_rejects) */

T_DECLARE_CASE(test_parse_args_config_short_and_long)
{
	reset_args();
	char *short_argv[] = { "multiplexd", "-c", "short.json", NULL };
	parse_args(3, short_argv);
	T_EXPECT(args.conf_path != NULL);
	T_EXPECT_STREQ(args.conf_path, "short.json");

	reset_args();
	char *long_argv[] = { "multiplexd", "--config", "long.json", NULL };
	parse_args(3, long_argv);
	T_EXPECT(args.conf_path != NULL);
	T_EXPECT_STREQ(args.conf_path, "long.json");
}

T_DECLARE_CASE(test_parse_args_loglevel_parses_number)
{
	reset_args();
	char *argv[] = { "multiplexd", "--loglevel", "6", NULL };
	parse_args(3, argv);
	T_EXPECT_EQ(args.loglevel, 6);

	/* Omitting --loglevel leaves the "not given" sentinel (-1) so main() and
	 * server_apply_config() fall back to the config's level instead of a CLI
	 * override. */
	reset_args();
	char *no_flag[] = { "multiplexd", "-c", "cfg.json", NULL };
	parse_args(3, no_flag);
	T_EXPECT_EQ(args.loglevel, -1);
}

/* Both ends of the range print_usage documents (0-8) must be accepted. Level 0
 * also pins that SILENCE stays distinct from the -1 "not given" sentinel. */
T_DECLARE_CASE(test_parse_args_loglevel_accepts_documented_bounds)
{
	reset_args();
	char *silence[] = { "multiplexd", "--loglevel", "0", NULL };
	parse_args(3, silence);
	T_EXPECT_EQ(args.loglevel, LOG_LEVEL_SILENCE);

	reset_args();
	char *veryverbose[] = { "multiplexd", "--loglevel", "8", NULL };
	parse_args(3, veryverbose);
	T_EXPECT_EQ(args.loglevel, LOG_LEVEL_VERYVERBOSE);
}

/* A level above LOG_LEVEL_VERYVERBOSE, or one parse_uint_arg refuses, is an
 * argument error. */
T_DECLARE_CASE(test_parse_args_loglevel_rejects_out_of_range)
{
	reset_args();
	char *above[] = { "multiplexd", "--loglevel", "9", NULL };
	T_CALL_SUBCASE(expect_parse_args_rejects, 3, above);
	char *negative[] = { "multiplexd", "--loglevel", "-1", NULL };
	T_CALL_SUBCASE(expect_parse_args_rejects, 3, negative);
}

T_DECLARE_CASE(test_parse_args_daemonize_and_dump_config_flags)
{
	reset_args();
	char *daemon[] = { "multiplexd", "-c", "cfg.json", "-d", NULL };
	parse_args(4, daemon);
	T_EXPECT(args.daemonize);
	T_EXPECT(!args.dump_config);

	reset_args();
	char *dump[] = { "multiplexd", "--dump-config", NULL };
	parse_args(2, dump);
	T_EXPECT(!args.daemonize);
	T_EXPECT(args.dump_config);
}

/* Regression: a one-shot option returns from main() before --daemonize and
 * --user are applied, and key/certificate generation never loads --config,
 * so each was dropped without a word under a zero exit status. */
T_DECLARE_CASE(test_parse_args_rejects_daemon_options_with_oneshot)
{
	reset_args();
	char *dump_daemonize[] = { "multiplexd", "--dump-config", "-d", NULL };
	T_CALL_SUBCASE(expect_parse_args_rejects, 3, dump_daemonize);
	char *dump_user[] = {
		"multiplexd", "--dump-config", "-u", "nobody", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 4, dump_user);
#if WITH_TLS
	char *psk_config[] = {
		"multiplexd", "--genpsk", "peer", "-c", "nonexist.json", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 5, psk_config);
	char *psk_daemon_user[] = {
		"multiplexd", "--genpsk", "peer", "--daemonize",
		"--user",     "nobody",	  NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 6, psk_daemon_user);
#endif /* WITH_TLS */
#if WITH_OPENSSL
	char *certs_config[] = {
		"multiplexd", "--config", "cfg.json",
		"--gencerts", "node",	  NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 5, certs_config);
	char *certs_user[] = {
		"multiplexd", "--gencerts", "node", "-u", "nobody", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 5, certs_user);
#endif /* WITH_OPENSSL */
}

/* --dump-config reads --config, and --loglevel applies to every run, so both
 * stay accepted beside a one-shot option; the daemon takes all of them. */
T_DECLARE_CASE(test_parse_args_accepts_options_the_run_reads)
{
	reset_args();
	char *dump[] = {
		"multiplexd", "-c", "cfg.json", "--dump-config",
		"--loglevel", "6",  NULL,
	};
	parse_args(6, dump);
	T_EXPECT(args.dump_config);
	T_EXPECT_STREQ(args.conf_path, "cfg.json");
	T_EXPECT_EQ(args.loglevel, 6);

	reset_args();
	char *daemon[] = {
		"multiplexd", "-c", "cfg.json", "-d", "-u", "nobody:", NULL,
	};
	parse_args(6, daemon);
	T_EXPECT(args.daemonize);
	T_EXPECT_STREQ(args.user_name, "nobody:");
#if WITH_TLS
	reset_args();
	char *psk[] = {
		"multiplexd", "--loglevel", "2", "--genpsk", "peer", NULL,
	};
	parse_args(5, psk);
	T_EXPECT_STREQ(args.genpsk, "peer");
	T_EXPECT_EQ(args.loglevel, 2);
#endif /* WITH_TLS */
}

T_DECLARE_CASE(test_parse_args_user_identity)
{
	reset_args();
	char *argv[] = { "multiplexd", "-u", "nobody:nogroup", NULL };
	parse_args(3, argv);
	T_EXPECT(args.user_name != NULL);
	T_EXPECT_STREQ(args.user_name, "nobody:nogroup");
}

/* drop_privileges_verified must only require the credential(s) the -u
 * argument's [user][:[group]] form actually asks drop_privileges() to
 * change, mirroring its colon-position parsing (contrib/csnippets/os/
 * daemon.c) without duplicating its uid/gid *value* resolution. One case
 * per form, matching this file's per-decision convention. */

/* Plain "-u user": drop_privileges() never touches gid. */
T_DECLARE_CASE(test_drop_privileges_requests_user_only)
{
	bool uid, gid;
	drop_privileges_requests("nobody", &uid, &gid);
	T_EXPECT(uid);
	T_EXPECT(!gid);
}

/* Trailing colon derives the user's primary group: both change. */
T_DECLARE_CASE(test_drop_privileges_requests_trailing_colon)
{
	bool uid, gid;
	drop_privileges_requests("nobody:", &uid, &gid);
	T_EXPECT(uid);
	T_EXPECT(gid);
}

/* Explicit user:group: both change. */
T_DECLARE_CASE(test_drop_privileges_requests_user_and_group)
{
	bool uid, gid;
	drop_privileges_requests("nobody:nogroup", &uid, &gid);
	T_EXPECT(uid);
	T_EXPECT(gid);
}

/* Leading colon, group only: drop_privileges() never touches uid. */
T_DECLARE_CASE(test_drop_privileges_requests_group_only)
{
	bool uid, gid;
	drop_privileges_requests(":nogroup", &uid, &gid);
	T_EXPECT(!uid);
	T_EXPECT(gid);
}

/* A bare ":" resolves neither a user nor a group, so drop_privileges(":") is a
 * no-op: neither uid nor gid changes. Regression -- gid was reported as
 * changing, making the daemon spuriously fail drop_privileges_verified as root. */
T_DECLARE_CASE(test_drop_privileges_requests_bare_colon)
{
	bool uid, gid;
	drop_privileges_requests(":", &uid, &gid);
	T_EXPECT(!uid);
	T_EXPECT(!gid);
}

/* Numeric forms classify the same way as names. */
T_DECLARE_CASE(test_drop_privileges_requests_numeric_forms)
{
	bool uid, gid;
	drop_privileges_requests("0", &uid, &gid);
	T_EXPECT(uid);
	T_EXPECT(!gid);
	drop_privileges_requests("0:0", &uid, &gid);
	T_EXPECT(uid);
	T_EXPECT(gid);
}

/* parse_uint_arg must accept only a plain decimal in [0, max]: strtoumax() alone
 * skips leading whitespace and honors a sign, and negating a `-` literal wraps
 * it to an in-range magnitude (`--keysize -18446744073709549568` became 2048).
 * A rejected argument must leave *out untouched. */
T_DECLARE_CASE(test_parse_uint_arg_rejects_non_plain_decimals)
{
	static const char *const rejected[] = {
		"-1", "+8", " 8", "8x", "", "9", "99999999999999999999999",
	};
	for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
		uintmax_t out = 42;
		if (parse_uint_arg(rejected[i], 8, &out)) {
			T_FATALF("accepted \"%s\"", rejected[i]);
		}
		T_EXPECT_EQ(out, (uintmax_t)42);
	}

	uintmax_t out = 42;
	T_EXPECT(!parse_uint_arg(
		"-18446744073709549568", (uintmax_t)INT_MAX, &out));
	T_EXPECT_EQ(out, (uintmax_t)42);
}

T_DECLARE_CASE(test_parse_uint_arg_accepts_bounds)
{
	uintmax_t out = 42;
	T_EXPECT(parse_uint_arg("0", 8, &out));
	T_EXPECT_EQ(out, (uintmax_t)0);
	T_EXPECT(parse_uint_arg("8", 8, &out));
	T_EXPECT_EQ(out, (uintmax_t)8);
}

T_DECLARE_CASE(test_parse_args_double_dash_stops_parsing)
{
	reset_args();
	/* "--" must end option parsing: the trailing -c is not consumed. */
	char *argv[] = { "multiplexd", "--", "-c", "ignored.json", NULL };
	parse_args(4, argv);
	T_EXPECT(args.conf_path == NULL);
}

#if WITH_OPENSSL
T_DECLARE_CASE(test_parse_args_gencerts_options)
{
	reset_args();
	char *argv[] = {
		"multiplexd",	"--gencerts", "node", "--sni",
		"example.test", "--keytype",  "rsa",  "--keysize",
		"2048",		"--sign",     "ca",   "--identity",
		"a,b",		NULL,
	};
	parse_args(13, argv);
	T_EXPECT_STREQ(args.gencerts, "node");
	T_EXPECT_STREQ(args.server_name, "example.test");
	T_EXPECT_STREQ(args.keytype, "rsa");
	T_EXPECT_EQ(args.keysize, 2048);
	T_EXPECT_STREQ(args.sign, "ca");
	T_EXPECT_STREQ(args.identities, "a,b");
}

/* Regression: only --gencerts reads the certificate options, so without it
 * each was stored and dropped -- an invalid --keytype included, since only
 * gencerts() validates one -- under a zero exit status. */
T_DECLARE_CASE(test_parse_args_rejects_gencerts_options_without_gencerts)
{
	reset_args();
	char *sni[] = { "multiplexd", "--sni", "x", "--dump-config", NULL };
	T_CALL_SUBCASE(expect_parse_args_rejects, 4, sni);
	char *identity[] = {
		"multiplexd", "-c", "cfg.json", "--identity", "a", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 5, identity);
	char *sign[] = { "multiplexd", "--sign", "ca", NULL };
	T_CALL_SUBCASE(expect_parse_args_rejects, 3, sign);
	char *keytype[] = {
		"multiplexd", "--keytype", "bogus", "--dump-config", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 4, keytype);
	/* 0 is also the field's unset value, so this pins that the option
	 * itself is tracked rather than the value it stored. */
	char *keysize[] = { "multiplexd", "--keysize", "0", NULL };
	T_CALL_SUBCASE(expect_parse_args_rejects, 3, keysize);
#if WITH_TLS
	char *psk_sni[] = {
		"multiplexd", "--genpsk", "peer", "--sni", "x", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 5, psk_sni);
#endif /* WITH_TLS */
}
#endif /* WITH_OPENSSL */

#if WITH_TLS
T_DECLARE_CASE(test_parse_args_genpsk)
{
	reset_args();
	char *argv[] = { "multiplexd", "--genpsk", "a~b,a~c", NULL };
	parse_args(3, argv);
	T_EXPECT(args.genpsk != NULL);
	T_EXPECT_STREQ(args.genpsk, "a~b,a~c");
}

/* Regression: each one-shot option runs its action in place of the daemon and
 * main() runs only the first it checks, so a command line naming two silently
 * skipped the other yet exited 0. It must be rejected instead. */
T_DECLARE_CASE(test_parse_args_rejects_combined_oneshot_options)
{
	reset_args();
	char *psk_dump[] = {
		"multiplexd", "--genpsk", "peer", "--dump-config", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 4, psk_dump);
#if WITH_OPENSSL
	char *certs_psk[] = {
		"multiplexd", "--gencerts", "node", "--genpsk", "peer", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 5, certs_psk);
	char *certs_dump[] = {
		"multiplexd", "--gencerts", "node", "--dump-config", NULL,
	};
	T_CALL_SUBCASE(expect_parse_args_rejects, 4, certs_dump);
#endif /* WITH_OPENSSL */
}
#endif /* WITH_TLS */

/* Regression: --dump-config's guard must reject a write that only reached the
 * stdio buffer.  A stream on /dev/full is fully buffered and fails every actual
 * write, so a payload smaller than the buffer leaves fwrite/fputc reporting
 * success and the error surfacing only at flush time -- exactly what exit()'s
 * implicit flush would swallow, handing the caller truncated JSON under a zero
 * exit status. */
T_DECLARE_CASE(test_write_dump_reports_flush_failure)
{
	static const char json[] = "{\"type\":\"x\"}";

	FILE *const f = fopen("/dev/full", "w");
	if (f == NULL) {
		/* No always-failing sink on this platform. */
		T_SKIPNOW();
	}
	const bool written = write_dump(f, json, sizeof(json) - 1);
	(void)fclose(f);
	T_EXPECT(!written);
}

/* The same helper reports success on a stream that accepts the whole payload. */
T_DECLARE_CASE(test_write_dump_accepts_a_complete_write)
{
	static const char json[] = "{\"type\":\"x\"}";

	FILE *const f = fopen("/dev/null", "w");
	if (f == NULL) {
		T_SKIPNOW();
	}
	const bool written = write_dump(f, json, sizeof(json) - 1);
	(void)fclose(f);
	T_EXPECT(written);
}

static const struct testing_suite suite[] = {
	T_CASE(test_parse_args_config_short_and_long),
	T_CASE(test_parse_args_loglevel_parses_number),
	T_CASE(test_parse_args_loglevel_accepts_documented_bounds),
	T_CASE(test_parse_args_loglevel_rejects_out_of_range),
	T_CASE(test_parse_args_daemonize_and_dump_config_flags),
	T_CASE(test_parse_args_rejects_daemon_options_with_oneshot),
	T_CASE(test_parse_args_accepts_options_the_run_reads),
	T_CASE(test_parse_args_user_identity),
	T_CASE(test_drop_privileges_requests_user_only),
	T_CASE(test_drop_privileges_requests_bare_colon),
	T_CASE(test_drop_privileges_requests_trailing_colon),
	T_CASE(test_drop_privileges_requests_user_and_group),
	T_CASE(test_drop_privileges_requests_group_only),
	T_CASE(test_drop_privileges_requests_numeric_forms),
	T_CASE(test_parse_uint_arg_rejects_non_plain_decimals),
	T_CASE(test_parse_uint_arg_accepts_bounds),
	T_CASE(test_parse_args_double_dash_stops_parsing),
	T_CASE(test_write_dump_reports_flush_failure),
	T_CASE(test_write_dump_accepts_a_complete_write),
#if WITH_OPENSSL
	T_CASE(test_parse_args_gencerts_options),
	T_CASE(test_parse_args_rejects_gencerts_options_without_gencerts),
#endif
#if WITH_TLS
	T_CASE(test_parse_args_genpsk),
	T_CASE(test_parse_args_rejects_combined_oneshot_options),
#endif
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
