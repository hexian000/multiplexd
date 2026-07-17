/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* main_test.c - white-box tests for parse_args/print_usage in main.c;
 * main() renamed to avoid conflict; the daemon body is compiled but never
 * run; tests inspect only the static args state. */

#include "utils/slog.h"
#include "utils/testing.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

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

/* regression - one CLI-parsing decision per case (happy paths only; the error
 * branches call exit(), so they cannot run in-process here and are exercised
 * nowhere -- only --help is covered end-to-end, by smoke_test.py grepping its
 * usage text) */

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

/* Both ends of the range print_usage documents (0-8) must be accepted; a level
 * above LOG_LEVEL_VERYVERBOSE is an argument error, and like every other
 * rejection here it exits (see this file's happy-paths-only note). Level 0 also
 * pins that SILENCE stays distinct from the -1 "not given" sentinel. */
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

T_DECLARE_CASE(test_parse_args_daemonize_and_dump_config_flags)
{
	reset_args();
	char *argv[] = { "multiplexd", "-d", "--dump-config", NULL };
	parse_args(3, argv);
	T_EXPECT(args.daemonize);
	T_EXPECT(args.dump_config);
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
		"2048",		"--sign",     "ca",   NULL,
	};
	parse_args(11, argv);
	T_EXPECT_STREQ(args.gencerts, "node");
	T_EXPECT_STREQ(args.server_name, "example.test");
	T_EXPECT_STREQ(args.keytype, "rsa");
	T_EXPECT_EQ(args.keysize, 2048);
	T_EXPECT_STREQ(args.sign, "ca");
}
#endif /* WITH_OPENSSL */

static const struct testing_suite suite[] = {
	T_CASE(test_parse_args_config_short_and_long),
	T_CASE(test_parse_args_loglevel_parses_number),
	T_CASE(test_parse_args_loglevel_accepts_documented_bounds),
	T_CASE(test_parse_args_daemonize_and_dump_config_flags),
	T_CASE(test_parse_args_user_identity),
	T_CASE(test_drop_privileges_requests_user_only),
	T_CASE(test_drop_privileges_requests_bare_colon),
	T_CASE(test_drop_privileges_requests_trailing_colon),
	T_CASE(test_drop_privileges_requests_user_and_group),
	T_CASE(test_drop_privileges_requests_group_only),
	T_CASE(test_drop_privileges_requests_numeric_forms),
	T_CASE(test_parse_args_double_dash_stops_parsing),
#if WITH_OPENSSL
	T_CASE(test_parse_args_gencerts_options),
#endif
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
