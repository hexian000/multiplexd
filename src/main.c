/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file main.c
 * @brief Main entry point for the multiplexd daemon.
 */

#include "conf.h"
#include "gencerts.h"
#include "server.h"
#include "util.h"

#include "os/daemon.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
} args = { .loglevel = LOG_LEVEL_NOTICE };
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
		"                             Debug, Verbose, VeryVerbose respectively (default: 4)\n"
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
		"  --keysize <bits>           key size (RSA: 4096, ECDSA: 224/256/384/521)\n"
		"\n"
#endif /* WITH_OPENSSL */
	);
	(void)fflush(stderr);
}

static void parse_args(const int argc, char *const *argv)
{
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
			char *endptr = NULL;
			const uintmax_t value = strtoumax(argv[i], &endptr, 10);
			if (endptr == argv[i] || *endptr != '\0' ||
			    value > INT_MAX) {
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
		if (strcmp(argv[i], "--gencerts") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.gencerts = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--sni") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.server_name = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--sign") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.sign = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--keytype") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.keytype = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--keysize") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			char *endptr = NULL;
			const uintmax_t val = strtoumax(argv[++i], &endptr, 10);
			if (endptr == argv[i] || *endptr != '\0' ||
			    val > INT_MAX) {
				LOGF_F("invalid keysize: %s", argv[i]);
				exit(EXIT_FAILURE);
			}
			args.keysize = (int)val;
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

int main(int argc, char **argv)
{
	init(argc, argv);
	parse_args(argc, argv);
	slog_setlevel(args.loglevel);
	loadlibs();

#if WITH_OPENSSL
	if (args.gencerts != NULL) {
		const char *kt = (args.keytype != NULL) ? args.keytype : "rsa";
		if (!gencerts(
			    args.gencerts, args.server_name, args.sign, kt,
			    args.keysize)) {
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
		char *const dump_json = conf_dump(conf, &dump_len);
		if (dump_json == NULL) {
			LOGF("failed to dump config");
			conf_free(conf);
			return EXIT_FAILURE;
		}
		(void)fwrite(dump_json, 1, dump_len, stdout);
		(void)fputc('\n', stdout);
		free(dump_json);
		conf_free(conf);
		return EXIT_SUCCESS;
	}

	slog_setlevel(conf->loglevel);
	if (conf->log != NULL) {
		if (strcmp(conf->log, "stdout") == 0) {
			slog_setoutput(SLOG_OUTPUT_FILE, stdout);
		} else if (strcmp(conf->log, "stderr") == 0) {
			slog_setoutput(SLOG_OUTPUT_FILE, stderr);
		} else if (strcmp(conf->log, "terminal") == 0) {
			slog_setoutput(SLOG_OUTPUT_TERMINAL, stderr);
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
		int pos = 0;
		if (conf->identity.mux_connect_count > 0 ||
		    conf->identity.peers_count > 0) {
			pos += snprintf(
				extensions + pos, sizeof(extensions) - pos,
				"%sidentity (%zu connect, %zu listen)",
				pos > 0 ? ", " : "",
				conf->identity.mux_connect_count,
				conf->identity.peers_count);
		}
		if (pos == 0) {
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
	server->conf_path = args.conf_path;

	const char *const user_name = args.user_name;

	/* Daemonize before threads start (held mutexes would deadlock the child).
	 * Drop privileges after server_start so root can bind privileged ports. */
	if (args.daemonize) {
		daemonize(NULL, false, false);
		slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME, NULL);
	}

	if (!server_start(server)) {
		LOGF("failed to start server");
		server_stop(server);
		server_free(server);
		conf_free(conf);
		return EXIT_FAILURE;
	}

	if (user_name != NULL) {
		drop_privileges(user_name);
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
