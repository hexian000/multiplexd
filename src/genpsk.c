/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file genpsk.c
 * @brief Pre-shared key generation for tls.psk.
 */

#include "genpsk.h"

#if WITH_TLS

#include "shim/tls.h"
#include "shim/util.h"

#include "utils/slog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keys are generated at the minimum length rather than the maximum: the floor
 * already matches the hash output RFC 9257 asks for, and every extra octet is
 * a longer thing for an operator to copy between hosts. */
#define GENPSK_KEY_LEN TLS_PSK_MIN_LEN

/* "<name>.psk" into buf; false when it does not fit. */
static bool
format_psk_path(char *restrict buf, const size_t size, const char *name)
{
	const int n = snprintf(buf, size, "%s.psk", name);
	return n >= 0 && (size_t)n < size;
}

static bool genpsk_one(const char *restrict name)
{
	unsigned char key[GENPSK_KEY_LEN];
	if (!csprng_bytes(key, sizeof(key))) {
		LOGE_F("%s: failed to read the system entropy source", name);
		return false;
	}
	char label[TLS_PSK_LABEL_MAX + 1];
	size_t label_len = sizeof(label);
	if (!tls_psk_label(key, sizeof(key), label, &label_len)) {
		LOGE_F("%s: failed to derive the identity label", name);
		tls_secure_erase(key, sizeof(key));
		return false;
	}

	char path[256];
	if (!format_psk_path(path, sizeof(path), name)) {
		LOGE_F("path too long: %s.psk", name);
		tls_secure_erase(key, sizeof(key));
		return false;
	}
	/* Owner-only, and O_EXCL so an existing key is never clobbered: a
	 * silently regenerated key would lock out the peer holding the old one. */
	FILE *const fp = create_exclusive(path, 0600);
	if (fp == NULL) {
		tls_secure_erase(key, sizeof(key));
		return false;
	}
	char hex[GENPSK_KEY_LEN * 2 + 2];
	for (size_t i = 0; i < sizeof(key); i++) {
		static const char digits[] = "0123456789abcdef";
		hex[i * 2] = digits[key[i] >> 4u];
		hex[i * 2 + 1] = digits[key[i] & 0x0fu];
	}
	hex[sizeof(hex) - 2] = '\n';
	hex[sizeof(hex) - 1] = '\0';
	tls_secure_erase(key, sizeof(key));

	const size_t want = sizeof(hex) - 1;
	const bool written = fwrite(hex, 1, want, fp) == want;
	const bool closed = fclose(fp) == 0;
	tls_secure_erase(hex, sizeof(hex));
	if (!written || !closed) {
		LOGE_F("failed to write %s", path);
		discard_file(path);
		return false;
	}
	LOGN_F("write %s (identity label %s)", path, label);
	return true;
}

bool genpsk(const char *names)
{
	if (names == NULL) {
		LOGE("invalid options");
		return false;
	}
	char *const copy = strdup(names);
	if (copy == NULL) {
		LOGOOM();
		return false;
	}
	size_t capacity = 1;
	for (const char *p = names; *p != '\0'; p++) {
		if (*p == ',') {
			capacity++;
		}
	}
	const char **const generated_names =
		(const char **)calloc(capacity, sizeof(*generated_names));
	if (generated_names == NULL) {
		LOGOOM();
		free(copy);
		return false;
	}
	bool ok = true;
	size_t generated_count = 0;
	char *saveptr = NULL;
	for (char *name = strtok_r(copy, ",", &saveptr); name != NULL;
	     name = strtok_r(NULL, ",", &saveptr)) {
		while (*name == ' ') {
			name++;
		}
		char *end = name + strlen(name);
		while (end > name && end[-1] == ' ') {
			*--end = '\0';
		}
		if (*name == '\0') {
			continue;
		}
		if (!genpsk_one(name)) {
			ok = false;
			break;
		}
		generated_names[generated_count++] = name;
	}
	if (ok && generated_count == 0) {
		/* Every token was blank: nothing was written, so reporting
		 * success would tell a provisioning script its keys exist. */
		LOGE("no key names given");
		ok = false;
	}
	/* All or nothing: a failure part-way through the list takes back the
	 * keys this call already wrote, never a file that existed before it. */
	if (!ok) {
		while (generated_count > 0) {
			char path[256];
			const char *const name =
				generated_names[--generated_count];
			if (format_psk_path(path, sizeof(path), name)) {
				discard_file(path);
			}
		}
	}
	free((void *)generated_names);
	free(copy);
	return ok;
}

#endif /* WITH_TLS */
