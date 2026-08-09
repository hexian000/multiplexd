/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* genpsk_test.c - black-box tests for pre-shared key generation in genpsk.c
 * via its public API. Dependencies: links the real genpsk.c + TLS backend
 * (no-op when TLS disabled). */

#if WITH_TLS

#include "genpsk.h"

#include "shim/tls.h"

#include "utils/ctype_ascii.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* One key file: lowercase hex digits for the whole key, then a newline. */
enum { PSK_FILE_LEN = TLS_PSK_MIN_LEN * 2 + 1 };

/* Remove a file tree recursively using only POSIX APIs; used for
 * temp-directory cleanup. */
static void rm_tmpdir(const char *path)
{
	DIR *const dir = opendir(path);
	if (dir == NULL) {
		return;
	}
	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0) {
			continue;
		}
		char subpath[PATH_MAX];
		(void)snprintf(
			subpath, sizeof(subpath), "%s/%s", path, ent->d_name);
		struct stat st;
		if (lstat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
			rm_tmpdir(subpath);
		} else {
			(void)unlink(subpath);
		}
	}
	(void)closedir(dir);
	(void)rmdir(path);
}

/* Process-exit sweep for case failures that skip leave_tmpdir().
 * rm_tmpdir() no-ops for directories already removed by a passing case. */
enum { PENDING_TMPDIRS_MAX = 64 };
static char pending_tmpdirs[PENDING_TMPDIRS_MAX][64];
static int pending_tmpdirs_count = 0;

static void sweep_pending_tmpdirs(void)
{
	for (int i = 0; i < pending_tmpdirs_count; i++) {
		rm_tmpdir(pending_tmpdirs[i]);
	}
}

static void track_tmpdir(const char *tmpl)
{
	static bool registered = false;
	if (!registered) {
		T_CHECK(atexit(sweep_pending_tmpdirs) == 0);
		registered = true;
	}
	if (pending_tmpdirs_count < PENDING_TMPDIRS_MAX) {
		(void)snprintf(
			pending_tmpdirs[pending_tmpdirs_count],
			sizeof(pending_tmpdirs[0]), "%s", tmpl);
		pending_tmpdirs_count++;
	}
}

/* Enter a fresh temp dir, filling origdir with the original cwd and tmpl
 * with the created path. */
static bool
enter_tmpdir(char *restrict tmpl, char *restrict origdir, size_t origdir_size)
{
	if (getcwd(origdir, origdir_size) == NULL) {
		return false;
	}
	if (mkdtemp(tmpl) == NULL) {
		return false;
	}
	track_tmpdir(tmpl);
	if (chdir(tmpl) != 0) {
		rm_tmpdir(tmpl);
		return false;
	}
	return true;
}

static void
leave_tmpdir(const char *restrict origdir, const char *restrict tmpl)
{
	if (chdir(origdir) != 0) {
		const int err = errno;
		LOGW_F("chdir: (%d) %s", err, strerror(err));
	}
	rm_tmpdir(tmpl);
}

/* Entries in the cwd, excluding "." and ".."; -1 when it cannot be read.
 * Names the key files by count rather than by path, so a name the generator
 * mangled or truncated is still caught. */
static int count_entries(void)
{
	DIR *const dir = opendir(".");
	if (dir == NULL) {
		return -1;
	}
	int n = 0;
	const struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0) {
			continue;
		}
		n++;
	}
	(void)closedir(dir);
	return n;
}

/* Read a whole key file into buf; its byte count, 0 when unreadable. */
static size_t
read_key_file(const char *restrict path, char *restrict buf, const size_t len)
{
	FILE *const fp = fopen(path, "r");
	if (fp == NULL) {
		return 0;
	}
	const size_t n = fread(buf, 1, len, fp);
	(void)fclose(fp);
	return n;
}

T_DECLARE_CASE(test_genpsk_writes_lowercase_hex_key)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = genpsk("node-a");
	char buf[PSK_FILE_LEN * 2];
	const size_t n = read_key_file("node-a.psk", buf, sizeof(buf));

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT_EQ(n, (size_t)PSK_FILE_LEN);
	T_EXPECT_EQ(buf[PSK_FILE_LEN - 1], '\n');
	bool all_lower_hex = true;
	for (size_t i = 0; i + 1 < n; i++) {
		const char c = buf[i];
		if (!isxdigit(c) || isupper(c)) {
			all_lower_hex = false;
			break;
		}
	}
	T_EXPECT(all_lower_hex);
}

T_DECLARE_CASE(test_genpsk_multiple_names_get_distinct_keys)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = genpsk("alpha, beta");
	char alpha[PSK_FILE_LEN * 2];
	char beta[PSK_FILE_LEN * 2];
	const size_t n_alpha = read_key_file("alpha.psk", alpha, sizeof(alpha));
	const size_t n_beta = read_key_file("beta.psk", beta, sizeof(beta));
	const int entries = count_entries();

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	/* The space after the comma is trimmed, so "beta" is not " beta". */
	T_EXPECT_EQ(n_alpha, (size_t)PSK_FILE_LEN);
	T_EXPECT_EQ(n_beta, (size_t)PSK_FILE_LEN);
	T_EXPECT_EQ(entries, 2);
	/* Two keys from one CSPRNG must not be the same key. */
	T_EXPECT(memcmp(alpha, beta, (size_t)PSK_FILE_LEN) != 0);
}

/* A name token that is entirely spaces (e.g. between two commas) must be
 * skipped without writing a key for it, and must not disrupt the real tokens
 * on either side. */
T_DECLARE_CASE(test_genpsk_skips_all_space_name_token)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool ok = genpsk("alpha, ,beta");
	const bool wrote_alpha = access("alpha.psk", F_OK) == 0;
	const bool wrote_beta = access("beta.psk", F_OK) == 0;
	const int entries = count_entries();

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(wrote_alpha);
	T_EXPECT(wrote_beta);
	T_EXPECT_EQ(entries, 2);
}

/* A list yielding no usable token at all -- an empty string, or nothing but
 * separators and blanks, as `--genpsk "$NAMES"` produces when NAMES is unset --
 * writes no key, so it must be reported as a failure: success would tell a
 * provisioning script its keys exist. */
T_DECLARE_CASE(test_genpsk_empty_name_list_fails)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool empty_ok = genpsk("");
	const bool blank_ok = genpsk(" , , ");
	const bool null_ok = genpsk(NULL);
	const int entries = count_entries();

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(!empty_ok);
	T_EXPECT(!blank_ok);
	T_EXPECT(!null_ok);
	/* A blank token that slipped through would land under the empty name. */
	T_EXPECT_EQ(entries, 0);
}

/* O_EXCL: regenerating over an existing key would lock out the peer holding
 * the old one, so the call fails and the key on disk is left untouched. */
T_DECLARE_CASE(test_genpsk_refuses_overwrite_existing_key)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	const bool first_ok = genpsk("dup");
	char before[PSK_FILE_LEN * 2];
	const size_t n_before =
		read_key_file("dup.psk", before, sizeof(before));
	const bool second_ok = genpsk("dup");
	char after[PSK_FILE_LEN * 2];
	const size_t n_after = read_key_file("dup.psk", after, sizeof(after));

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(first_ok);
	T_EXPECT(!second_ok);
	T_EXPECT_EQ(n_before, (size_t)PSK_FILE_LEN);
	T_EXPECT_EQ(n_after, n_before);
	T_EXPECT(memcmp(before, after, n_before) == 0);
}

T_DECLARE_CASE(test_genpsk_file_permissions)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* genpsk requests 0600 but open(2) masks the mode by the ambient umask,
	 * so a laxer inherited umask cannot loosen it and a hardened one cannot
	 * be told apart from a correct request. Clear the umask around
	 * generation so the created mode is exactly what genpsk asked for. */
	const mode_t old_umask = umask(0);
	const bool ok = genpsk("perms");
	(void)umask(old_umask);
	struct stat st;
	const bool stated = stat("perms.psk", &st) == 0;

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(ok);
	T_EXPECT(stated);
	T_EXPECT_EQ((unsigned int)(st.st_mode & 0777U), 0600U);
}

/* The snprintf guard rejects a name whose "<name>.psk" path does not fit the
 * 256-byte buffer. A truncating guard would silently write the key under a
 * shortened name instead, so no file may appear either. */
T_DECLARE_CASE(test_genpsk_path_too_long_rejected)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	/* The shortest name the guard must reject: with ".psk" and the
	 * terminator it is one byte past genpsk_one()'s path buffer. */
	enum {
		PATH_BUF_LEN = 256,
		TOO_LONG = PATH_BUF_LEN - sizeof(".psk") + 1
	};
	char name[TOO_LONG + 1];
	memset(name, 'a', TOO_LONG);
	name[TOO_LONG] = '\0';

	const bool ok = genpsk(name);
	const int entries = count_entries();

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(!ok);
	T_EXPECT_EQ(entries, 0);
}

/* A key file that cannot be written through is discarded rather than left
 * behind half-written, which would then block the retry via O_EXCL. RLIMIT_FSIZE
 * makes the write fail deterministically; SIGXFSZ must be ignored first, or
 * exceeding the limit kills the process instead of failing the call. */
T_DECLARE_CASE(test_genpsk_write_failure_leaves_no_file)
{
	char tmpl[] = "/tmp/genpsk_test_XXXXXX";
	char origdir[PATH_MAX];
	T_CHECK(enter_tmpdir(tmpl, origdir, sizeof(origdir)));

	struct rlimit orig;
	T_CHECK(getrlimit(RLIMIT_FSIZE, &orig) == 0);
	struct rlimit nogrow = orig;
	nogrow.rlim_cur = 0;
	void (*const prev)(int) = signal(SIGXFSZ, SIG_IGN);
	T_CHECK(prev != SIG_ERR);
	T_CHECK(setrlimit(RLIMIT_FSIZE, &nogrow) == 0);

	const bool ok = genpsk("wfail");

	T_CHECK(setrlimit(RLIMIT_FSIZE, &orig) == 0);
	(void)signal(SIGXFSZ, prev);
	const int entries = count_entries();

	leave_tmpdir(origdir, tmpl);

	T_EXPECT(!ok);
	T_EXPECT_EQ(entries, 0);
}

static const struct testing_suite suite[] = {
	T_CASE(test_genpsk_writes_lowercase_hex_key),
	T_CASE(test_genpsk_multiple_names_get_distinct_keys),
	T_CASE(test_genpsk_skips_all_space_name_token),
	T_CASE(test_genpsk_empty_name_list_fails),
	T_CASE(test_genpsk_refuses_overwrite_existing_key),
	T_CASE(test_genpsk_file_permissions),
	T_CASE(test_genpsk_path_too_long_rejected),
	T_CASE(test_genpsk_write_failure_leaves_no_file),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}

#else /* !WITH_TLS */

#include <stdlib.h>

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
