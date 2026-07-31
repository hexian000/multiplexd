/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file main.c
 * @brief Main entry point for the multiplexd daemon.
 */

#include "conf.h"
#if WITH_OPENSSL
#include "gencerts.h"
#endif
#include "server.h"
#if WITH_TLS
#include "shim/tls.h"
#endif

#include "io/file.h"
#include "math/rand.h"
#include "os/daemon.h"
#if WITH_CRASH_HANDLER
#include "os/signal.h"
#endif
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Per-level indent used when --dump-config pretty-prints the resolved config. */
#define DUMP_CONFIG_INDENT "    "

static struct {
	const char *conf_path;
	const char *user_name;
#if WITH_OPENSSL
	const char *gencerts;
	const char *server_name;
	const char *sign;
	const char *keytype;
	int keysize;
#endif
	int loglevel;
	bool daemonize : 1;
	bool dump_config : 1;
} args = { .loglevel = -1 }; /* -1: --loglevel not given on the CLI */
static void print_usage(const char *argv0)
{
	(void)fprintf(
		stderr, "%s %s\n  %s\n\n", PROJECT_NAME, PROJECT_VER,
		PROJECT_HOMEPAGE);
	(void)fprintf(stderr, "usage: %s <option>...\n", argv0);
	(void)fprintf(
		stderr, "%s",
		"  -h, --help                 show usage and exit\n"
		"  -c, --config <file>        specify json config (use - to read from stdin)\n"
		"  -d, --daemonize            run in background and write logs to syslog\n"
		"  -u, --user [user][:[group]]\n"
		"                             run as the specified identity, e.g. `nobody:nogroup'\n"
		"  --loglevel <level>         0-8 are Silence, Fatal, Error, Warning, Notice, Info,\n"
		"                             Debug, Verbose, VeryVerbose respectively (default: 4);\n"
		"                             overrides the config's loglevel when given\n"
		"  --dump-config              dump resolved config with inlined PEM to stdout\n"
		"\n"
#if WITH_OPENSSL
		"Certificate generation options:\n"
		"  --gencerts <name>[,<name>...]\n"
		"                             generate certificate and key pairs\n"
		"                             as <name>-cert.pem, <name>-key.pem\n"
		"  --sni <name>               server name for generated certs\n"
		"                             (default: example.com)\n"
		"  --sign <name>              sign certificates with <name>-cert.pem,\n"
		"                             <name>-key.pem\n"
		"  --keytype <type>           key type: rsa, ecdsa, or ed25519\n"
		"                             (default: rsa)\n"
		"  --keysize <bits>           key size (RSA: 2048-16384, default 4096;\n"
		"                             ECDSA: 224/256/384/521)\n"
		"\n"
#endif /* WITH_OPENSSL */
	);
	(void)fflush(stderr);
}

#define OPT_REQUIRE_ARG(argc, argv, i)                                         \
	do {                                                                   \
		if ((i) + 1 >= (argc)) {                                       \
			LOGF_F("option `%s' requires an argument",             \
			       (argv)[(i)]);                                   \
			exit(EXIT_FAILURE);                                    \
		}                                                              \
	} while (false)

#define OPT_ARG_ERROR(argv, i)                                                 \
	do {                                                                   \
		LOGF_F("argument error: %s `%s'", (argv)[(i) - 1],             \
		       (argv)[(i)]);                                           \
		exit(EXIT_FAILURE);                                            \
	} while (false)

/* Parse a plain non-negative decimal integer in [0, max] from a CLI argument
 * into *out, returning true on success. strtoumax() would skip leading
 * whitespace and honor a sign -- negating a `-` literal into a huge in-range
 * magnitude (e.g. `--keysize -...568` wrapping to 2048) -- so require the first
 * character to be a digit and reject any trailing junk. An overflowing literal
 * saturates to UINTMAX_MAX, which the `> max` bound rejects. */
static bool parse_uint_arg(const char *arg, uintmax_t max, uintmax_t *out)
{
	if (arg[0] < '0' || arg[0] > '9') {
		return false;
	}
	char *endptr = NULL;
	const uintmax_t val = strtoumax(arg, &endptr, 10);
	if (*endptr != '\0' || val > max) {
		return false;
	}
	*out = val;
	return true;
}

#if WITH_OPENSSL
/* Matches and consumes one --gencerts-family flag at argv[*i], advancing *i
 * past its argument; false if argv[*i] is not one of these flags. */
static bool parse_gencerts_arg(const int argc, char *const *argv, int *i)
{
	if (strcmp(argv[*i], "--gencerts") == 0) {
		OPT_REQUIRE_ARG(argc, argv, *i);
		args.gencerts = argv[++*i];
		return true;
	}
	if (strcmp(argv[*i], "--sni") == 0) {
		OPT_REQUIRE_ARG(argc, argv, *i);
		args.server_name = argv[++*i];
		return true;
	}
	if (strcmp(argv[*i], "--sign") == 0) {
		OPT_REQUIRE_ARG(argc, argv, *i);
		args.sign = argv[++*i];
		return true;
	}
	if (strcmp(argv[*i], "--keytype") == 0) {
		OPT_REQUIRE_ARG(argc, argv, *i);
		args.keytype = argv[++*i];
		return true;
	}
	if (strcmp(argv[*i], "--keysize") == 0) {
		OPT_REQUIRE_ARG(argc, argv, *i);
		uintmax_t val;
		if (!parse_uint_arg(argv[++*i], (uintmax_t)INT_MAX, &val)) {
			LOGF_F("invalid keysize: %s", argv[*i]);
			exit(EXIT_FAILURE);
		}
		args.keysize = (int)val;
		return true;
	}
	return false;
}
#endif /* WITH_OPENSSL */

static void parse_args(const int argc, char *const *argv)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			/* Keep non-zero exit to stop scripted invocations immediately. */
			exit(EXIT_FAILURE);
		}
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--config") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.conf_path = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-u") == 0 ||
		    strcmp(argv[i], "--user") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.user_name = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--loglevel") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			uintmax_t value;
			if (!parse_uint_arg(
				    argv[i], (uintmax_t)LOG_LEVEL_VERYVERBOSE,
				    &value)) {
				OPT_ARG_ERROR(argv, i);
			}
			args.loglevel = (int)value;
			continue;
		}
		if (strcmp(argv[i], "-d") == 0 ||
		    strcmp(argv[i], "--daemonize") == 0) {
			args.daemonize = true;
			continue;
		}
		if (strcmp(argv[i], "--dump-config") == 0) {
			args.dump_config = true;
			continue;
		}
#if WITH_OPENSSL
		if (parse_gencerts_arg(argc, argv, &i)) {
			continue;
		}
#endif /* WITH_OPENSSL */
		if (strcmp(argv[i], "--") == 0) {
			break;
		}
		LOGF_F("unknown argument: `%s'", argv[i]);
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

#undef OPT_REQUIRE_ARG
#undef OPT_ARG_ERROR
}

/* Release resources after a startup failure and report EXIT_FAILURE. */
static int
fail_startup(struct server *restrict server, struct config *restrict conf)
{
	server_stop(server);
	server_free(server);
	conf_free(conf);
	return EXIT_FAILURE;
}

/* Whether identity (the -u argument) requests changing uid/gid, mirroring
 * drop_privileges()'s own [user][:[group]] colon-position parsing
 * (contrib/csnippets/os/daemon.c): uid changes unless identity starts with
 * ':' (empty user part); gid changes whenever a colon is present at all (an
 * explicit group, or a trailing colon that derives the user's primary
 * group from the passwd database). */
static void drop_privileges_requests(
	const char *restrict identity, bool *restrict changes_uid,
	bool *restrict changes_gid)
{
	*changes_uid = identity[0] != ':';
	/* gid changes only for an explicit group (colon[1] != '\0') or a trailing
	 * colon with a non-empty user (colon != identity, deriving the user's
	 * primary group). A bare ":" resolves neither, so drop_privileges(":")
	 * leaves gid untouched -- reporting a gid change there made the daemon
	 * spuriously fail drop_privileges_verified when run as root. */
	const char *const colon = strchr(identity, ':');
	*changes_gid = colon != NULL && (colon[1] != '\0' || colon != identity);
}

/* drop_privileges() (contrib/csnippets/os/daemon.c) abort()s via FAILMSGF on
 * every real failure -- a bad user/group or a failed set[e]gid/set[e]uid -- so a
 * failed drop never returns here. What this re-check still catches is the
 * degenerate case where the drop "succeeds" but the requested credentials
 * themselves resolve to root (e.g. -u 0, -u 0:0, -u :0): the process would keep
 * running as root, defeating the purpose of -u, so returning false routes the
 * caller to a graceful startup failure. Only the credential(s) user_name
 * actually requests changing are checked: a valid single-credential -u (e.g.
 * plain "nobody", or ":group") leaves the other credential at its original value
 * by design. */
static bool drop_privileges_verified(const char *restrict user_name)
{
	bool changes_uid;
	bool changes_gid;
	drop_privileges_requests(user_name, &changes_uid, &changes_gid);
	drop_privileges(user_name);
	return (!changes_uid || geteuid() != 0) &&
	       (!changes_gid || getegid() != 0);
}

#if defined(WIN32)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

/* io_filewriter() heap-allocates a stream that slog only borrows for the
 * process lifetime; cache one per standard stream so the boot sequence's
 * repeated stdout/stderr sink switches neither leak the prior sink nor
 * dangle. */
static struct io_stream *log_filewriter(FILE *const f)
{
	static struct io_stream *stdout_writer = NULL;
	static struct io_stream *stderr_writer = NULL;
	struct io_stream **restrict slot =
		(f == stdout) ? &stdout_writer : &stderr_writer;
	if (*slot == NULL) {
		*slot = io_filewriter(f);
	}
	return *slot;
}

static void init(void)
{
	(void)setlocale(LC_ALL, "");
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stdout));
	{
		static char prefix[] = __FILE__;
		char *s = strrchr(prefix, PATH_SEPARATOR);
		if (s != NULL) {
			s[1] = '\0';
		}
		slog_setfileprefix(prefix);
	}
	slog_setlevel(LOG_LEVEL_VERBOSE);

	struct sigaction ignore = { .sa_handler = SIG_IGN };
	if (sigaction(SIGPIPE, &ignore, NULL) != 0) {
		const int err = errno;
		LOGF_F("sigaction: (%d) %s", err, strerror(err));
		exit(EXIT_FAILURE);
	}
#if WITH_CRASH_HANDLER
	crashhandler_install();
#endif
}

static void loadlibs(void)
{
	srand64((uint_fast64_t)time(NULL));

	LOGD_F("%s: %s", PROJECT_NAME, PROJECT_VER);
	LOGD_F("libev: %d.%d", ev_version_major(), ev_version_minor());
#if WITH_TLS
	LOGD_F("%s", tls_version());
#endif
}

static void unloadlibs(void)
{
	LOGD("library cleanup complete");
}

int main(int argc, char **argv)
{
	init();
	/* parse_args' fatal CLI diagnostics are errors and belong on stderr (as
	 * print_usage already writes there); every error path exit()s, so a failure
	 * simply keeps this stderr sink. Restore the stdout boot sink afterwards --
	 * stdout is deliberate for the daemon body (the config's `log` defaults
	 * there). */
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stderr));
	parse_args(argc, argv);
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stdout));
	/* --dump-config writes machine-readable JSON to stdout, so move the log
	 * off that stream for the rest of the run: config parsing legitimately
	 * warns (e.g. plaintext mode), and any such line would otherwise land on
	 * stdout ahead of the JSON and make it unparseable. This branch returns
	 * before the config's own `log` setting is applied, so nothing points the
	 * sink back at stdout. */
	if (args.dump_config) {
		slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stderr));
	}
	/* Boot/parse-phase log level: the CLI --loglevel if given, else NOTICE.
	 * Once a config is loaded, the effective runtime level is applied below. */
	slog_setlevel(args.loglevel >= 0 ? args.loglevel : LOG_LEVEL_NOTICE);
	loadlibs();

#if WITH_OPENSSL
	if (args.gencerts != NULL) {
		if (!gencerts(
			    args.gencerts, args.server_name, args.sign,
			    args.keytype, args.keysize)) {
			LOGF("failed to generate certificates");
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}
#endif /* WITH_OPENSSL */

	if (args.conf_path == NULL && !args.dump_config) {
		LOGF("config file must be specified");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	struct config *restrict conf;
	if (args.conf_path != NULL) {
		conf = conf_parsefile(args.conf_path);
		if (conf == NULL) {
			LOGF_F("failed to load config `%s'", args.conf_path);
			return EXIT_FAILURE;
		}
	} else {
		conf = conf_new_default();
		if (conf == NULL) {
			LOGF("failed to create default config");
			return EXIT_FAILURE;
		}
	}

#if WITH_TLS
	if (!conf_inline_pem(conf)) {
		LOGF("failed to load PEM references");
		conf_free(conf);
		return EXIT_FAILURE;
	}
#endif

	if (args.dump_config) {
		size_t dump_len;
		char *const dump_json =
			conf_dump(conf, &dump_len, DUMP_CONFIG_INDENT);
		if (dump_json == NULL) {
			LOGF("failed to dump config");
			conf_free(conf);
			return EXIT_FAILURE;
		}
		/* A short write would hand the caller truncated JSON, so report it
		 * rather than exiting 0 on output nothing can parse. */
		const bool written =
			fwrite(dump_json, 1, dump_len, stdout) == dump_len &&
			fputc('\n', stdout) != EOF;
		free(dump_json);
		conf_free(conf);
		if (!written) {
			LOGF_F("failed to write config: %s", strerror(errno));
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	/* An explicit --loglevel wins over the config's loglevel (which conf_check
	 * always resolves to a value, so it cannot be distinguished from an
	 * omitted one); otherwise the config's level applies for the daemon body. */
	slog_setlevel(args.loglevel >= 0 ? args.loglevel : conf->loglevel);
	if (conf->log != NULL) {
		if (strcmp(conf->log, "stdout") == 0) {
			slog_setoutput(
				SLOG_OUTPUT_STREAM, log_filewriter(stdout));
		} else if (strcmp(conf->log, "stderr") == 0) {
			slog_setoutput(
				SLOG_OUTPUT_STREAM, log_filewriter(stderr));
		} else if (strcmp(conf->log, "terminal") == 0) {
			slog_setoutput(
				SLOG_OUTPUT_TERMINAL, log_filewriter(stderr));
		} else if (strcmp(conf->log, "syslog") == 0) {
			slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME, NULL);
		} else if (strcmp(conf->log, "discard") == 0) {
			slog_setoutput(SLOG_OUTPUT_DISCARD);
		} else {
			LOGW_F("unknown log output: \"%s\"", conf->log);
		}
	}

	{
		char extensions[128];
		if (conf->identity.mux_connect_count > 0 ||
		    conf->identity.peers_count > 0) {
			(void)snprintf(
				extensions, sizeof(extensions),
				"identity (%zu connect, %zu listen)",
				conf->identity.mux_connect_count,
				conf->identity.peers_count);
		} else {
			(void)snprintf(
				extensions, sizeof(extensions), "%s", "none");
		}
		LOGI_F("%s %s starting (extensions: %s)", PROJECT_NAME,
		       PROJECT_VER, extensions);
	}

	struct ev_loop *const loop = EV_DEFAULT;

	struct server *const server = server_new(loop, conf);
	if (server == NULL) {
		LOGF("failed to create server");
		conf_free(conf);
		return EXIT_FAILURE;
	}
	/* Carry an explicit --loglevel into the server so SIGHUP reloads honor it
	 * too (server_apply_config), instead of reverting to the config's level. */
	server->loglevel_override = args.loglevel;
	/* Resolve to an absolute path before the possible daemonize() chdir("/")
	 * below, so a later reload can still find a relative -c path; fall
	 * back to the original string if realpath() fails. */
	static char conf_path_abs[PATH_MAX];
	server->conf_path = args.conf_path;
	if (args.conf_path != NULL && strcmp(args.conf_path, "-") != 0) {
		if (realpath(args.conf_path, conf_path_abs) != NULL) {
			server->conf_path = conf_path_abs;
		} else {
			const int err = errno;
			LOGW_F("realpath(\"%s\"): (%d) %s; a later SIGHUP reload"
			       " after daemonize()'s chdir(\"/\") may look in the"
			       " wrong directory",
			       args.conf_path, err, strerror(err));
		}
	}

	const char *const user_name = args.user_name;

	/* Daemonize before threads start (held mutexes would deadlock the child).
	 * Drop privileges after server_start so root can bind privileged ports. */
	if (args.daemonize) {
		daemonize(NULL, false, false);
		slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME, NULL);
	}

	if (!server_start(server)) {
		LOGF("failed to start server");
		return fail_startup(server, conf);
	}

	if (user_name != NULL && !drop_privileges_verified(user_name)) {
		LOGF_F("failed to drop privileges to '%s'", user_name);
		return fail_startup(server, conf);
	}

	LOGI("entering event loop");
	(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);
	ev_run(loop, 0);

	LOGI("shutting down");

	server_stop(server);
	/* A reload frees the startup config that `conf` still points at; free the
	 * server's current config instead to avoid a double free. */
	struct config *const final_conf = server->conf;
	server_free(server);

	unloadlibs();
	conf_free(final_conf);

	LOGD("program terminated normally");
	return EXIT_SUCCESS;
}
