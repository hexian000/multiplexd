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
	args.loglevel = LOG_LEVEL_NOTICE;
}

/* regression - one CLI-parsing decision per case (happy paths only; the
 * error/--help branches call exit() and are exercised end-to-end elsewhere) */

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
		"2048",		NULL,
	};
	parse_args(9, argv);
	T_EXPECT_STREQ(args.gencerts, "node");
	T_EXPECT_STREQ(args.server_name, "example.test");
	T_EXPECT_STREQ(args.keytype, "rsa");
	T_EXPECT_EQ(args.keysize, 2048);
}
#endif /* WITH_OPENSSL */

static const struct testing_suite suite[] = {
	T_CASE(test_parse_args_config_short_and_long),
	T_CASE(test_parse_args_loglevel_parses_number),
	T_CASE(test_parse_args_daemonize_and_dump_config_flags),
	T_CASE(test_parse_args_user_identity),
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
