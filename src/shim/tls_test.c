/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* tls_test.c - black-box tests for the TLS context helpers in shim/tls.h via
 * its public API. Dependencies: links the real TLS backend. */

#include "shim/tls.h"

#include "shim/util.h"

#if WITH_TLS

#include "utils/slog.h"
#include "utils/testing.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

/* Self-signed RSA-4096 certificate (CN/subjectAltName=DNS:test.example) and its
 * private key, in memory so they work with every TLS backend.  Doubles as the
 * authorized peer certificate for mutual authentication. */
static char test_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFKjCCAxKgAwIBAgIUM70vOlOUSVk9dQ7tbW/ih/8sKCwwDQYJKoZIhvcNAQEL\n"
	"BQAwFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCAXDTI2MDYwOTAyNDQ0NVoYDzIx\n"
	"MjYwNTE2MDI0NDQ1WjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwggIiMA0GCSqG\n"
	"SIb3DQEBAQUAA4ICDwAwggIKAoICAQC+SzjGbGTgjqsKQCEGYS3hFnO1hBoy1VQ8\n"
	"zypDdzFLyluGRZMym7Qb5W4dXZiSVTDFw8B+/GkB6uceOaVYLXIe3f96+TucfBJw\n"
	"Wh1TFc6toUP315rjauntWqTSOQQe3apuP3z9WyU+tXkaxOOVaayRJx79cPxqqLFr\n"
	"rDIUi2JBLOqN1dxwh6XYE6ny3wE27SOXB1J8gDVyl4gW9tNYRrZWVoTe21m2apl6\n"
	"/9T+Mn5GCZgjCiF21e/4Nq9oWXHS7K6P561XlfdWnPGmRNzcAnguhIIe3z8qbwDH\n"
	"1M0BtLiS84DIqJ0cZ3Jkl7UIKKCJrHS7oCLIMdbe9qVpmL6QLpMolNS0cznJgVo2\n"
	"eAGjQDt+b1nC9R/dT2kukvyltPEz4Ybd9CDzoP3MyDSV08tZNLeNoN3ezRXsEYE2\n"
	"/RVRGX0rJ35iqxKtj6hEip6HhQvBEQX1SiUHLAw0baozaQwoGNzDO/QXffAADp/W\n"
	"F2vG2VB6we1YXvFnwBKvPNplvTRHBPTXpVX2MQMXwKus2IBTNFZp+mW8mCliYWop\n"
	"zfVSamrV1aNXWn52Nx5iNVQ6JQzjziAWXEn58hWorkUi0omuKHTR326KPLkG7IpW\n"
	"agolWR89JHPaSM+ffRzgobbKHwNwhABRT3Ye9BqfxX6Rn0bwaeCR6t0or8ru7Dxs\n"
	"dq/TW93U5wIDAQABo2wwajAdBgNVHQ4EFgQU3hgHVZAn/Lh/xbRhabVaEGQbxc8w\n"
	"HwYDVR0jBBgwFoAU3hgHVZAn/Lh/xbRhabVaEGQbxc8wDwYDVR0TAQH/BAUwAwEB\n"
	"/zAXBgNVHREEEDAOggx0ZXN0LmV4YW1wbGUwDQYJKoZIhvcNAQELBQADggIBAIWF\n"
	"in4MUtRj4R6GYGtjjnWt1m9aN4I/w22kdD183G07uTJZ+i545DdFNglt8ZIO1f2F\n"
	"eQ67wQfxIeFeZrr4x6wA7B+RVwX/mRuj3aby5QXhNDVkjAp2su9GRPyIe3jXPDv/\n"
	"/quE4Oufa0kE8HuvqPIOSO6UYWkNAP81LDoyDhyoadB5+mIuxpM3+NyKh6AK2g8n\n"
	"Ran7GYKtMUrL7ryRoJyPcpFk/QyrWAMCbmO3p2Rxx5sj3RtL+6HNYTqNij5qsB+S\n"
	"zmdmX8XyAW5Bgog3hrnrTn1j1AaxNgEczsjdDmaGQiYKscyLwMe38DI8NP/rPP4X\n"
	"rMH8B/TLl+uRwY1THRtkyHI6y4ZnGzmdEBf001J/KUfBFnLxHZBrJwMYbgqLWjba\n"
	"nVXS5GXAtt7Mmz2tKQo7gCHUjgByWcnun3qMGcEoCkkTaqi0pxf2844BYyy73VRT\n"
	"XdPJnfOOHDhuwkkeOfVJbPnfYFAAd8qMpmzBQvz4Clz2q4plB7odyWPSGwvLbFYs\n"
	"sdwuTXnyLqCrB3K0uMBlKr7xeWiVHUfe5oGCwgp7TjV/2AmKUxNzdg41d3Fn7TPK\n"
	"CncDeSmMy1elKbutfBvWvl8d7C0A9viO49Vy0CVR41uQnF09bzdFTYoaOrX8c+w4\n"
	"VtiUoGP5D91X1vhTixpq4BqoHRkKVQpZ0Z/9386J\n"
	"-----END CERTIFICATE-----\n";

static char test_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"NL+YLwobqSZhkl4iZWt2wGODitzp/aQ=\n"
	"-----END PRIVATE KEY-----\n";

/* An unrelated RSA-2048 private key: syntactically valid but does not pair
 * with test_cert_pem's public key. Exercises the cert/key pairing check. */
static char mismatched_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCxiCI9PQsS8GB6\n"
	"YaA/56PQvPSaYBMeal4zs+lEMfrTYWsOaKHQXpRb/Bo6E8T6a0inGu5vKGmyQLTq\n"
	"NERlzgaFD8t//RCYOuZnPO4K8TXaXVOvjBPKdoD04cPAY2eLs2M0H4QrMuMeP0SZ\n"
	"w0sQiTThdlxSidxG0WNRnMKMpwoJeKd+MBzT84e0EmcaOFGJPFshE9XySJCU3wUn\n"
	"FSkarKDELXZkYO2bbTMkYePDbPeJOKFkOBj6LlXN+8Mmy3hrUPMVc7fDE5wp8srq\n"
	"nNjodkHjJg8zIlpFoFCryl1Sxek6dUcZWURK16Y1P5C6kx7NQ7t+t2zqyXgmHKgL\n"
	"I/LS/UcDAgMBAAECggEADjFV8L4Kk+8Hp4EFMKwHb/lLN3RAKF7/PPRAd8/kajW6\n"
	"5fdTcwxnS/CcStGoc7n+oEK068oNTnosfHTFQGZM0HfHdb9OLlK3IhXAP2ZdPyHV\n"
	"k46H89hZeDpRo0skd19V/6VtXuQTPX3NXDA9YLW3YTb3K9oS9CO/5EG7WUdECXxW\n"
	"EQJzkt84A6WkzWELYuUeh6G5lktZ3Nd5R3/uUl2QO2TlhYXASu4hfXuEJLMlxRBh\n"
	"WsFr/ssVobbSOzi/3hn+deoecedgu2eTIzVW355bfdUUASHbtmmP3B1jZ3pnvM7B\n"
	"87yU2UWWmxrMqFI9raxuqQc4V3Rl+f66XHux2l/NoQKBgQD2SsRFRotYhT6GPmh/\n"
	"5Gi079Ygi0OSCzvB9PetvxAJzXkYQv6LJt++le22ds+gxXd0akIj4OvoaZI+bptE\n"
	"EKH6pUCv4d+KqY3O4fP+cC/jYDbDM6XmUpRDCNZzrS8/9s669S1Go6jJr9HAF5Pu\n"
	"LYNCVJofrDBQdVImYOJKWRCoSQKBgQC4h4jvTKS6lyWNYud2gSIl+fufDj3kwxks\n"
	"xRAinImaNPa1gZx5KKJY64BgwX4cJ0s0ULNGKkaLID63/TKP0De4wqYQpBpeb5qT\n"
	"NGIhiEYWQLdgBVLY2c4VgLBgoVz6aYrrhtho3JVQIB60PhIl6Ux+PWd4ogLJwptz\n"
	"urQjxBRs6wKBgQCMaZW59Pzua5B40k2bVCnJtc464YqVUWgxLKqj2ICZRhZamZ8q\n"
	"z+/RZQKP+u5mNw3iRc4NTGbSKpXgmAhW5rCiB+J4I2rhT8b0AmerUGRM2gZ+hQx4\n"
	"4e16xigU7NA6REgZ2DuGwTkyOtV3EToaGMJzZ24yzmUBCdHa5XM9dceEWQKBgBet\n"
	"/NqIgVMYdk8wc/d3FsS80ZdVooeqqZ5fI3TtlZLeXRJpsYSyvDKg9fZ0nhRKzpHG\n"
	"EVtdrXPJDYNa0JQ36g6hm+HizSd1NubRAA7BiAzu/RkrVbhSKuoDe57K1j2kMZmL\n"
	"0lWSiO6hUI9cr8OBrrk8c/y8/ZKakIxHVzqHvP9FAoGBAMrVRQF1LLX1KkHmWlcq\n"
	"he6HF6Wtkjot7Rsn59EGxqJSj2g50sHg/Wb1tQnmqqZVA8WPuBTwxf+dwEHNQdzZ\n"
	"G7KkKQQObarh8zP0i4KJTRuBGwmC8lbP40Aq27FCJwsxUNkZqyHG9z+TmetHRqp8\n"
	"HWIgJfyco9XzhrSqu82XOc3O\n"
	"-----END PRIVATE KEY-----\n";

/* CA-signed chain fixtures: a self-signed CA cert (CN=test-ca.example,
 * basicConstraints=CA:TRUE) and a leaf cert/key (CN=test.example,
 * subjectAltName=DNS:test.example) it signs -- unlike every other
 * fixture in this file, the leaf is not also its own authorized peer
 * cert; the CA cert is presented as the trust anchor instead, exercising
 * actual chain validation rather than a single self-signed identity. */
static char test_ca_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFJzCCAw+gAwIBAgIUOAN/4WelYOPi/dDF68zbVK6TQw8wDQYJKoZIhvcNAQEL\n"
	"BQAwGjEYMBYGA1UEAwwPdGVzdC1jYS5leGFtcGxlMCAXDTI2MDcwMjEyNDM1MloY\n"
	"DzIxMjYwNjA4MTI0MzUyWjAaMRgwFgYDVQQDDA90ZXN0LWNhLmV4YW1wbGUwggIi\n"
	"MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCq3C03nf0MMFWYnqEjTJBiMtSM\n"
	"lOnOQYwPD15IaPUZ/1dS+iEItFWKOyR5jD08nv00qQm/Ez6a0j9lN8OKn4hglg7w\n"
	"sszjz8dGBi7KLO14Q1qj4fUgFDw43/iAPNf0kT1USDdHRc79peHDDM+oMWk46O+O\n"
	"vRMpRwPEhRax2GEtaJ5M/TqCPbYydMJQvVCnWyOw8SfQnm6hsh8MiHbTw4YaUqBD\n"
	"Flru4d+90OJ/IOLMQNntp1nY4F6w8Si07xYNP0TuFxv1m/e8i9LSGj9xT2zIiwDR\n"
	"v2MOAnbhYfTU7+zVicFbqvk2sBefn7hi2UTeVvjEcooTyOA6Lg0uvHt4nmcuUEg+\n"
	"OB8sqEwHGCmHGI9UYV+V2YuYwoaxjgAmYojtC2ZstLW8AHPndD1o8YQiM4jIfnSN\n"
	"qo/zMhnvduw9hduGJX1m9ew49mCHGbVab2PZuBUvSHsS6lMqgr/Ml+DWUK9by0CW\n"
	"h3CJ3YKsBDQqpQF6+s7DQwwhwvE9MjkacUZTnDqD7Wkk0w7PEBXIhwXDBEWbQNCn\n"
	"R9OT8Xbz4hMlBTrOqceEDcAN8ll/QRafX4WIw0vA2upEFv4o/4uonUU0UsM2Gnxf\n"
	"y6P0RbDZ2n3FckkUzTpaSUxwMTpy7ugHnhqr+f+SMAewwBRc9rOhHSEb/UGD6QsB\n"
	"IktiNL8IxkdmTtDskwIDAQABo2MwYTAdBgNVHQ4EFgQU9L8Auu7Dy7VAibLfjqvC\n"
	"+kbJ9dcwHwYDVR0jBBgwFoAU9L8Auu7Dy7VAibLfjqvC+kbJ9dcwDwYDVR0TAQH/\n"
	"BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAJST0f2k\n"
	"ZDDSpq0FSYvfcWL/oPcxEnuCohdylK/OLz9c9Pxi0Ba0v0bSm1YZpROE1lr+NkuR\n"
	"LSyOFAT/a6wpEdzuHpBxadBT/OUBXXGdd3bh2rhKnwEuzz0O7cj3ounIk8DVsTAP\n"
	"AXZ2EntKgyu7DzZ2v1d/kUhUOObx3nK7ZHBzHGCTRcbyE5u4w0QMcndzQMqqizEC\n"
	"+MWd4RnCz4LqJFSylGD6PrZxGrLpfsqvJsaPynvLglLNwy/3poQR57ZX3xSNF0r5\n"
	"PlD06kV+dnObCAFqDdbCXZyKX0w1NFQF0SK+e4qxs0sat9uIdKuWp5/0Cm4kboWb\n"
	"iMELo3+3zI8UcvypnifWcsJ2JtgnUKDNDDqs1XAUzg7QzqZF0q2WVC1LDIkY4Hfa\n"
	"x1AiHnxGVEjkgCjizxxOlLW/oUh3HvZvMQPad6huUEtnlHjIDbGZGGggjal27Oq5\n"
	"SamhNd2OSmdDDNKyJQ6f3ZaJKMZpq5wm1uP57ghdeP6XY8bcDQFB2UqylspJprhk\n"
	"sQA0cTC2cf1qioR3VObEPhPdWOyFD19D5yKdI2P7L9Y7uNOFktX4efJD+jtGSKYT\n"
	"VuJm1Gmx23n+lrVOlhwBqxBveqyb2C82UDJLEhNAuAdyD4VHhue8L6Vj/iNUqYqM\n"
	"jo26p4w1HNJG3DK3VuWO9hT64wpmfIpFU+mS\n"
	"-----END CERTIFICATE-----\n";

static char test_leaf_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFSDCCAzCgAwIBAgIUAoKpQL+NhRnyTyeyrAIeEN9u1+IwDQYJKoZIhvcNAQEL\n"
	"BQAwGjEYMBYGA1UEAwwPdGVzdC1jYS5leGFtcGxlMCAXDTI2MDcwMjEyNDM1M1oY\n"
	"DzIxMjYwNjA4MTI0MzUzWjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwggIiMA0G\n"
	"CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCrlKxCJvnvZu4QppbP0tP4YzmKkVXG\n"
	"DtQhhOM8BDb2yRBiYSdJbQzpA6Tn+M0B2gL/9vaGHazF31IMehPXrrhL4GADVdFa\n"
	"i+9Zqd2EDNo9w6Erjywbls05S5QQRDDJ6eYzqWsoVxfKpr8/Y6wsb0c/5TMUZZEt\n"
	"KNhWPFQ0plel8X64QvV90Uv7Iy4crlgIYyr9RX/KOl1wj6k47XwTXm7OlOKG39Sh\n"
	"+4mp1mrrq3jmLEZtAaN2Mo/ZUgLVweXtu3TaBuJC9wkB2m5dvpXOHUDOivUZsUYU\n"
	"EwsP2hQ3+6G+eAaLKFOtmzm/fub+NXjpG3VugKDHKSm9iLlnrfg3y++++QDuDVRS\n"
	"87n7KY1nR4RSYayCanqGraZcFRQ89Dv7Bid/LU3mkDdPMzORPp532V0HnpxjfQw1\n"
	"wMgALumsqf7iqiLiP7BydBW+gJ5UiCJTmMHLUbfHTYgXrbHOM2jIlve2w6iBUcbE\n"
	"+PrNuAreBJIWxyeIXzP6NcowCAa6Dtm7mM3uH0zvi1PwG2L8Revn7Y+RkBM45ChH\n"
	"nOX07TZJAX4DG2uqA8Y9MrA5crd3rt/WdzF/E0+CpGDctbugiarcVw+mYuvVoMgS\n"
	"adQTLTohHJn1tD/8m9HylfA2PoPeop1++WiAkvL/+pmuAQ7eg51AsSC99AoplVpp\n"
	"tiqdv8Vn4BoJXwIDAQABo4GGMIGDMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYB\n"
	"BQUHAwEGCCsGAQUFBwMCMBcGA1UdEQQQMA6CDHRlc3QuZXhhbXBsZTAdBgNVHQ4E\n"
	"FgQUEnEw+Sc2azHmfKL7ERuvBzyx3tcwHwYDVR0jBBgwFoAU9L8Auu7Dy7VAibLf\n"
	"jqvC+kbJ9dcwDQYJKoZIhvcNAQELBQADggIBAJRKwTcvaKamc33byXMFiQ7cAAll\n"
	"nXRAGNLm4M1PmpW7GhcoIr7SwMx4F56MyoyIMOnULWWPcxMOWujpzvVNzG4xfq1a\n"
	"CpCDg4hP11PRnJr/9zetoH/AGwpougIot1uJeBXx0ctkaj/qnNj9WmYJJOB1WgnM\n"
	"RrYQ0wI5qFr7T+qiBFb6yOJOZQYj7qOvj4eeITqnf1Fh77W7N8Eb+LHxRuufbb9N\n"
	"ZTs3uiMPRFqeQGnX0Nv7I2PILEFyqydIZjVIKt73hZOtfkytfyaTelg+5hjCiKwo\n"
	"c+F9zb3dsFUMrs8CIpbS3F8LSTZxDDurR7NLMZvcDyJOGf5ep+pz6Upw9qLpLyRY\n"
	"khzpq977Rf1Dk4mwuZMZRM/q5iIqcUrYpchiL9LS12R3zBa4yjp6NFmDGL8HSuFJ\n"
	"Jt1h7IH2/CgCQ0FyYMCgFYwLcVf06Io4p7mm0lX5gQ993xfRXbO/d84pOkOACDol\n"
	"XH+1HX5W7GdUPJP2Seh3v0ZyEcDayvKNwXjjtccGzwjN1UXOESM6bNeLby4eXH5j\n"
	"qheTjZ6CTHE2HoINmhB3JsXLNGuH9mG0xvQzkhpT+/TnnzbkwzXZjidi0UqkhqWZ\n"
	"xL85RM9dBgYcKoybayIL9A04dp6ZTUKYX7PF1mgnBH3lelsHH9Qh1+rSuJFKO+sY\n"
	"FayWFKOT8r3bbIGC\n"
	"-----END CERTIFICATE-----\n";

static char test_leaf_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"hENGB8EvQs6Qrz9ll8uIkNWOFiblPQ==\n"
	"-----END PRIVATE KEY-----\n";

/* Expired self-signed cert: notBefore/notAfter both fixed in the past
 * (2020-01-01 / 2021-01-01), well before this session's "today"
 * (2026-07-02) and any plausible future test run. Generated directly with
 * Python's cryptography library rather than via gencerts()/openssl-CLI,
 * neither of which expose an explicit backdated-validity option. */
static char test_expired_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIE1zCCAr+gAwIBAgIUBmi/HF8EWQ/8ydIxfK7rXQIo5lIwDQYJKoZIhvcNAQEL\n"
	"BQAwFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMB4XDTIwMDEwMTAwMDAwMFoXDTIx\n"
	"MDEwMTAwMDAwMFowFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMIICIjANBgkqhkiG\n"
	"9w0BAQEFAAOCAg8AMIICCgKCAgEAubpAmicP+YKb6BybP92jS16imv+9/jGUMapY\n"
	"oP+UyK4gkws8YmrBOYWQww0rIjmuJSs5RZH+ViB7KGjEVB1B0H7qcZbpmK/exkx+\n"
	"usVPYZryobFitQ+EziCaiM1RG8ZQvpUMoxRunLCaanu+5deEyDlTRY6E46dXaC2L\n"
	"DuHQzZohkB/v0GcMGYyiPU1ti3J25GuGN1ujbNFXkA8E1r33yzAS+xcrYUoewOZn\n"
	"bV35eqqGeuKkpuq+rLjlDG1vnY68eanMNjJ/ye2iDsM6OxrNKTNnVE1G6IblTTJJ\n"
	"i15D1V3+YfLpdMxOxQUNyVgJCHl7UJI9VYsUR1R7k5sTmgsGUf1Zpv6SUpbS7wzp\n"
	"1F9HGdKh6eAf651Q7L15eyFN1fgRBOCkqHOOrIqRgGAdJU4Ga9Vvu+54wo8oe2Ex\n"
	"j/740kKJGuFiGg8wgWDx9idps2lY92CGqSIjegPWpq7dfBgmpT7GGCwADtReHiDT\n"
	"zeGPo4xc0pB6lF3TtwpcQJIoSvr1SsnqzNmVmdV9tmQsD07SzD3vyCtYxeSvwwum\n"
	"Ou5vZ4Olm5WeTQMNl7iuTL/WYIpaGY4jiUxgO0KIqex7Vajfa0kW69b11wCPUKn4\n"
	"//XPrv2Z+DpM4sdA8aeZQrncy0oU4YZ4eoxm9fiLrYAr2TyQLVBgEN/cmWHRRV1o\n"
	"gaDyrw8CAwEAAaMbMBkwFwYDVR0RBBAwDoIMdGVzdC5leGFtcGxlMA0GCSqGSIb3\n"
	"DQEBCwUAA4ICAQAwxPD0SFQQgI8fw2M8fSvn1Q+dId+kVywdddTeX1zxTqNfchSI\n"
	"AUw32By7puPdSbD0yCk+XNKBtlz1hAJZ5HfOplFx+wLu2XHomOFhbVAka4E6+C75\n"
	"p9scMFFF0ZRvuI6lI3z+ZaILGI4p+olt0xkZ9OiWbK2dWx1OBYd4t0h2iMaYTniv\n"
	"6HiKTstPY0QHnJ1T7TciT5Kn8rtcdynrgltEzvmgcUGb1oEwpjmJHCmqlKYm9Uln\n"
	"ltsda3O159OxDfMf+2L9hUIKUztAThApfBB2Uj1JcNT+QdPllZZ/UTCOeaD5+bcM\n"
	"wqPSy4NQMCVPbWHpMg7nvT+5aBHdz83qrNRMzcteWGEMVJx5FnCyC/ohO2CmASpm\n"
	"6HrMRObPSFA29e1wVME9Pf8ls4qZHEPANFMGFgjTOfeWKmZY9IMjUSulOKZxv71Z\n"
	"+pqCMAkLG7neL15Tz63JH36iO+4aK+PHxGkOeuHRw+4W8sVoX+G5LCxzKQ9TKZu+\n"
	"5peJVG+VRbfdARQI5h9gzVmcHX+JHxs7cZo4rnE7gOWm1+QxR/TQCnEYRcfj9gyq\n"
	"z019ifN2Awziu9gIwhD6rdHlinIdre482GenTe5ZFZQkguN4Jkf4Pijrv4CddKgF\n"
	"T+lvSXeSCnPTCs9YAyeQlt9cgbSQRTM6OyUQtsQCyJSZl3b0foIYI8jNsQ==\n"
	"-----END CERTIFICATE-----\n";

static char test_expired_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"9vYtZX+/TZoECntmdfMAnrnpJSLSXg==\n"
	"-----END PRIVATE KEY-----\n";

/* Sub-floor certificates for certificate-strength rejection tests, all issued
 * by one strong CA (test_weak_floor_ca_cert_pem, RSA-2048 / SHA-256) so the
 * trust anchor itself is always loadable; each leaf is below one leg of the
 * floor both TLS backends must enforce. Generated with Python's cryptography
 * library (like test_expired_cert_pem):
 *  - test_weak_rsa_cert_pem: an RSA-1024 leaf (< TLS_RSA_MIN_BITS).
 *  - test_weak_digest_cert_pem: an RSA-2048 leaf CA-signed with SHA-1
 *    (< the SHA-256 digest floor); on a non-anchor leaf, since the floor
 *    exempts a trust anchor's own self-signature.
 * These two reach the wire on the mbedTLS backend (whose profile is enforced
 * only at verification), so the server's floor rejects them mid-handshake.
 * The EC-curve allowlist gets no handshake fixture: under the TLS-1.3-only
 * policy a sub-floor curve (e.g. P-224) has no TLS 1.3 signature scheme, so the
 * handshake aborts for a protocol reason upstream of the curve check and would
 * assert nothing.  The OpenSSL floor as a whole -- including the curve
 * allowlist -- is exercised directly in tls_openssl_test.c, since OpenSSL
 * refuses to load a sub-floor own certificate and it never reaches the wire. */
static char test_weak_floor_ca_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC4TCCAcmgAwIBAgIUGBYn8sMqRdA3UjyfuZ2W/yXI83IwDQYJKoZIhvcNAQEL\n"
	"BQAwHzEdMBsGA1UEAwwUd2Vha2Zsb29yLWNhLmV4YW1wbGUwIBcNMjAwMTAxMDAw\n"
	"MDAwWhgPMjA5OTAxMDEwMDAwMDBaMB8xHTAbBgNVBAMMFHdlYWtmbG9vci1jYS5l\n"
	"eGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzber445ccuVT\n"
	"iLGH8Q3Jo8XjLGMlPFLgWsbqFbQzp2/ZnEi0k8vljziAvIC4XggGkbsDYe3mtcK5\n"
	"43QWY+joVhLVCh7KqLZfBbAHRropalSaWXvLk24OOmPssfsenqoU7jZUZbgJdCUJ\n"
	"yepkduQhPAIcdjY5LcKMT15r3sTm3gNJ2LNVWtfxqzCmEDnlI5V0Dc5EqOkkUwWZ\n"
	"V2rN0Nl1bcim8Oq/XgoP0C/v6fguqaW4wF+PoaAqBSqPb3HkBQRI4dVjsQw6O50+\n"
	"v6nJy/lZTcnENQOBUANjZqu21fu7QCY4FGZVE79kM4ppVohqT3gghNNVGHZUPbOK\n"
	"6obncZe+LQIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n"
	"A4IBAQDFZJbYX48YOW3lfprA7Bhtqgzn+/0jFLHlAOW+bu9qdm9n2yC6oNKOj8O/\n"
	"Bg8W7FHaTyGJzrBKZJFLXc0Av1NKFAfTyEBYPnu6ErBqVNhPttWgnflOV4HW2lkm\n"
	"uXRz9MiMPURYlHSvGnIQ9RssGfyohATLhbDYxVChBXeBylkE1cCSqal+0A7vB2PE\n"
	"SXfm+un/FO0EAiZHNh9CDa/bP12zPIwZh9QJH5JcvKjT5X3p8jn3jJS8ahSOzzmD\n"
	"6nyRxT2kCcAS+p8DBMb0uBppvFGJ4Jya2LQsC6nFy8LNuMSgyIzFJa0SmtBsbnIn\n"
	"SfO9/ufhjD8dCX4cefuxSP8Hr4/l\n"
	"-----END CERTIFICATE-----\n";

static char test_weak_rsa_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICYzCCAUugAwIBAgIUBR0FjwQjzqpGR9qMXotgE/WeFPgwDQYJKoZIhvcNAQEL\n"
	"BQAwHzEdMBsGA1UEAwwUd2Vha2Zsb29yLWNhLmV4YW1wbGUwIBcNMjAwMTAxMDAw\n"
	"MDAwWhgPMjA5OTAxMDEwMDAwMDBaMBoxGDAWBgNVBAMMD3dlYWtyc2EuZXhhbXBs\n"
	"ZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAvzD00cjecLaWIxtIq5E/zNgb\n"
	"iaMvS0uEpMkXrQGOMH6TJdLP2uYybZHz9GIVCIzJK2O7VlFRjdSLGfXRAkXItScW\n"
	"IhayOW0OO7F6IbjbmJDQe8qJ6jqwCR0xNgRMYynnvgzY0nNz4+MU3V5bOE9odwR+\n"
	"Iyyt3xAeO9YZNffBy7kCAwEAAaMeMBwwGgYDVR0RBBMwEYIPd2Vha3JzYS5leGFt\n"
	"cGxlMA0GCSqGSIb3DQEBCwUAA4IBAQC5e0p+dfHC5rWFFZD+AIld8zD/93gpKTjL\n"
	"o43NhKAajERxheLNLcXl2J6Vi9G0P5ROzSCp1O/V/gKKlkGzSWdAUyjWNoRlMA4K\n"
	"qfgV1dVvWX5QEv7hIyzYADUnqdNuM7uMpK82eDYmCxHoHcCDY4bgZWgo5VWEHp3h\n"
	"ERHcJyOcr+4b3SrXGgHZAGDMnt22DdjbDkj3mFkY0QtUz4R5Kfy7o9227vsq29WB\n"
	"gnge8ZF9/GNWTmX5SfQ7e2cgx1Hg2vEvZ8VLSt3DUDSzdjDrlaHJzlG6i81U5c6Y\n"
	"xRyvCQZ3owKimsKRRDAU12aV5RyfgYJxq9861vzu/mFqWAuFvznt\n"
	"-----END CERTIFICATE-----\n";

static char test_weak_rsa_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAL8w9NHI3nC2liMb\n"
	"SKuRP8zYG4mjL0tLhKTJF60BjjB+kyXSz9rmMm2R8/RiFQiMyStju1ZRUY3Uixn1\n"
	"0QJFyLUnFiIWsjltDjuxeiG425iQ0HvKieo6sAkdMTYETGMp574M2NJzc+PjFN1e\n"
	"WzhPaHcEfiMsrd8QHjvWGTX3wcu5AgMBAAECgYAAy+JpMU4D6C7N7KIr3MoIP2o1\n"
	"85ER3jmqOhA4L0Z5Wz2frbYh8k2JeU8r2HC//V4lKSAxptsRHS6LKCP7v3Crlqcb\n"
	"hWpn2fQxYRT/kPxDsuCGL6iqY7SPK8ZdyOvyUdtIO9fWAmzCumw6Ke2o8oVDx0f8\n"
	"g9wAaeQG1TemYqjjgQJBAPyE8EHQ963+i0HCIa2dG0rRQNCNHeCzJ+rmjRywxd8C\n"
	"BNNZtcEdh1+xOY6OJOgNHOP3dmzpbqNvgC0kwmhbYfECQQDB05w9+WMq280/imGV\n"
	"P7knx9hX5j9YKRGlIN/17Phv15KpBVh3edn/NhQxfXxCliYKPbkVjct8NgZzDTRx\n"
	"Ir5JAkAVCa5KjXJVGKPZcqcDo9cmQJC5z0fx9Hsa4uJWxZN2pOBqC0tNL3ybyFQX\n"
	"QFhqzMzfYTqIkFobW6q+GBXqQ9LBAkB9/LV3Vy5NgngEUEejwrrwj6chY4lTHcbZ\n"
	"ZegNq43E7QPol4/sgSjhCd7QWHe3tG9fgsVWrEdTIq7IhBHNZD75AkAj7rCUPWJF\n"
	"O2tR7IbPsJ2MSGQ1QraVGSV9WUO4IBua7mk73FiLQD8N3MUQztYqvSzsH2Q3MuqT\n"
	"FupzctYBSP0Z\n"
	"-----END PRIVATE KEY-----\n";

static char test_weak_digest_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC7TCCAdWgAwIBAgIUAv6IlOFRnGzlm6C/JPllDSX5jEgwDQYJKoZIhvcNAQEF\n"
	"BQAwHzEdMBsGA1UEAwwUd2Vha2Zsb29yLWNhLmV4YW1wbGUwIBcNMjAwMTAxMDAw\n"
	"MDAwWhgPMjA5OTAxMDEwMDAwMDBaMB0xGzAZBgNVBAMMEndlYWtkaWdlc3QuZXhh\n"
	"bXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAGjnQDjN3wf84M\n"
	"RXuADPIpCUI5SaBJXheOHJGXH0JxQoYehxHUlCsTbEIPpaiO5fRbCqVkzI64l0L1\n"
	"1CbELJyQNVrNh58jcyGQLCoxfAC8cJg5f24E7EzZi0UMlUi8UEGukxYR57Cz/eqC\n"
	"4dlmG+RkASoOkDPqbAD/lYGso0xxWa1ZhCHjgDdxWl1ewMf42ULNjgTH+M87tp0V\n"
	"YM+r9ZWSjQWakfaQ/xZ501l3RK2YKDbPYXSh0ZCEXnYMFAF/EtHJkJ0wIA6Km3+2\n"
	"pDCKENX9op9U2JNTDTtd/hkBdXwkyTfcB1/7BfsETZotBmgKcuynp/0n4rZ1C9BV\n"
	"azTzBhcCAwEAAaMhMB8wHQYDVR0RBBYwFIISd2Vha2RpZ2VzdC5leGFtcGxlMA0G\n"
	"CSqGSIb3DQEBBQUAA4IBAQB55+24R2B4C6oYLMqCsHlJOIscF+C1Oe0GKWWtUaPp\n"
	"e50bDCyUebqaCg2G3BUWFFXJguukrzUsEs5Ht4MO+GSA6GAL4PMojZi2t/WtmNh2\n"
	"TjSt5IcCmSqdBLpK82IEtu3YjALOGhtbWvsXFfM48OsYgMaD7PwGcZtB6k+1VEX8\n"
	"KUh+ZuLrJWAX+aKSyMsd7U7C1QYSEt2Ui+eTEgn5FafDhmekse1jWY9fMvQcRfIV\n"
	"+jqzv56y4cp48OezIlK4Mex6lU7soaBkvBIVv9p33UCVODL0iqf6ICoytrF5v6Ao\n"
	"xKBOImm1GnSXwNWnonJcHCD9lzXhuexWqEw+TbQUlMyl\n"
	"-----END CERTIFICATE-----\n";

static char test_weak_digest_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDQBo50A4zd8H/O\n"
	"DEV7gAzyKQlCOUmgSV4XjhyRlx9CcUKGHocR1JQrE2xCD6WojuX0WwqlZMyOuJdC\n"
	"9dQmxCyckDVazYefI3MhkCwqMXwAvHCYOX9uBOxM2YtFDJVIvFBBrpMWEeews/3q\n"
	"guHZZhvkZAEqDpAz6mwA/5WBrKNMcVmtWYQh44A3cVpdXsDH+NlCzY4Ex/jPO7ad\n"
	"FWDPq/WVko0FmpH2kP8WedNZd0StmCg2z2F0odGQhF52DBQBfxLRyZCdMCAOipt/\n"
	"tqQwihDV/aKfVNiTUw07Xf4ZAXV8JMk33Adf+wX7BE2aLQZoCnLsp6f9J+K2dQvQ\n"
	"VWs08wYXAgMBAAECggEAR8y7hldjW4cS1a9um/3Kehqn02+qdeRc0Yx/V9DtPSWS\n"
	"bHBE9maE7Yk6qGJ2LwODYx+5QPTVlb0omDf5DZhQPYmYoMqnsMmvhzoXxEhoIGjq\n"
	"A+B0lyij1rKPWznInN5CZSk4Izny2g6F6VdbVInlvqK1tCpqo0CaHo4YsDVB97PX\n"
	"48zgoaYZhrKs2xzATm2t6v0oJlFESVpPTwgwj2KhZJOPmgghUOmtNh81e3oP6r9x\n"
	"mmRwSZ/F3DFCbN275rV9cAgCY5mwS7UrcZqGZSSWx2O5lkRdM6ErCTJq5V3IPPYq\n"
	"isaVa4eUrzaOg2ItGOOm2gebEXXN52n77GWhIl+qoQKBgQD84kx+pnuUrnI4Uc9s\n"
	"AARlvHW1DgyOfmISN/LMaiRxUzVNB4MnjC26e+9iyGFMRkjgk7ydXkFsG7hth+TP\n"
	"0prejBiQPoTt9Ac+Z47Do+0iCiNebIWVd2E93EfXEYcEy8LApUkrN66pdvIPwLtA\n"
	"5nHJuZnzQz0GV5JayCyL1U3gEwKBgQDSlsF2ITKloTavFdFi3oWgj3+DdJDVE8wZ\n"
	"W1E2SSeJP3TJxoDbK6fIQAq9CsaelFCiSpffrbZeh8ZMTkJUNCCAcaHDcPTw8dgp\n"
	"0VTrpOOZgiumdNYDajBjSTRv00ZRD0lGzsUEPg/Jw+j7PFnRg2YNaE7hweuXozLf\n"
	"In0xT8qqbQKBgArjm7Oga5XdZSGztCDMZ2QSF2dycWv5WTO7oQLYVzViBduJRUaA\n"
	"rL9o8sfoJPhp1l2FPwvvsRV8pBZjUaD5Sp3mnnAnoQW2ClHPl8Ao4N8kXJ2GQsJK\n"
	"368QOy+xm4TDWWF+PIZV4Xl+m7G99NI4mhG7ojttW8VYI/8wu2pSBwZtAoGAZxrG\n"
	"l6bDXFKlKm39OXIHbMg1P1BYBOsPd669AV4pzEnUTWIx/pzOJf4tA8d93XByVjM9\n"
	"TpeHfZruXLfIQ9/NtfVspPruAfX2xuqlsEXn5WXVJ0d27O8Vx9a0pLeFavSYBOIB\n"
	"lgUox7lynWc79pdl5NSYInJGfdS6eIMzVmxhprUCgYALWvIvyyTn8Q4R2NJXY/a6\n"
	"38FOOetUQYI8PApmqYYCSxql+J7+TDg2y41JQBWogDHerbXowQmbSb3q1oSuShPN\n"
	"A2vTM+TnHwTPuzdu4rCP6bDa11rEkHJcMJBgYC9cXOcQ/uV2K4WzW2OReSwrQEd0\n"
	"V+h+BXRXD3tseB2uANf+qw==\n"
	"-----END PRIVATE KEY-----\n";

/* Self-signed P-256/SHA-256 certificate (well above both backends' strength
 * floor) whose subjectAltName carries, in order: a DNS name that must be
 * ignored, "multiplexd:client-a", the percent-encoded UTF-8 identity
 * "multiplexd:caf%C3%A9", and a URI in an unrelated scheme that must not match.
 * Produced with the openssl CLI rather than gencerts(), which is unavailable in
 * a non-OpenSSL build. */
static char identity_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICADCCAaagAwIBAgIUFUKPae2ekFyJEKps8tigJhNCMvIwCgYIKoZIzj0EAwIw\n"
	"GzEZMBcGA1UEAwwQaWRlbnRpdHkuZXhhbXBsZTAgFw0yNjA4MDYwMzE5MzhaGA8y\n"
	"MTI2MDcxMzAzMTkzOFowGzEZMBcGA1UEAwwQaWRlbnRpdHkuZXhhbXBsZTBZMBMG\n"
	"ByqGSM49AgEGCCqGSM49AwEHA0IABIJ21b380L3JimzF8hLNQoHHpPBUYS+7jNPp\n"
	"haUpUaRDIdckntCrtPNb28l9CJ4TCZR+AqbLiIdERA3WBrfn3ICjgcUwgcIwDwYD\n"
	"VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUH\n"
	"AwEGCCsGAQUFBwMCMGEGA1UdEQRaMFiCEGlkZW50aXR5LmV4YW1wbGWGE211bHRp\n"
	"cGxleGQ6Y2xpZW50LWGGFG11bHRpcGxleGQ6Y2FmJUMzJUE5hhlodHRwczovL2V4\n"
	"YW1wbGUuY29tL290aGVyMB0GA1UdDgQWBBRXW/+gnbJLfqRposhQOgKNm48sXTAK\n"
	"BggqhkjOPQQDAgNIADBFAiBzhcKYVgMsfblg4CiLSD3L4imS82XAGWpehszk6unz\n"
	"pwIhANDc+HKlqdZypDy5gtGS3QnNIsfuLxcEycMJNJp0k7Wy\n"
	"-----END CERTIFICATE-----\n";

static char identity_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQge265Ux5i6NiqO6ks\n"
	"VjZw8uQ6yPJ9xaXKhPh7ireU54KhRANCAASCdtW9/NC9yYpsxfISzUKBx6TwVGEv\n"
	"u4zT6YWlKVGkQyHXJJ7Qq7TzW9vJfQieEwmUfgKmy4iHREQN1ga359yA\n"
	"-----END PRIVATE KEY-----\n";

static bool write_pem_file(const char *path, const char *data)
{
	FILE *const fp = fopen(path, "w");
	if (fp == NULL) {
		return false;
	}
	const size_t len = strlen(data);
	const size_t n = fwrite(data, 1, len, fp);
	const int closed = fclose(fp);
	return n == len && closed == 0;
}

static bool make_test_certs(void)
{
	if (!write_pem_file("t-cert.pem", test_cert_pem)) {
		return false;
	}
	if (!write_pem_file("t-key.pem", test_key_pem)) {
		return false;
	}
	if (!write_pem_file("id-cert.pem", identity_cert_pem)) {
		return false;
	}
	if (!write_pem_file("id-key.pem", identity_key_pem)) {
		return false;
	}
	return true;
}

/* Process-exit sweep for case failures that skip rm_tmpdir().
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

/* Write the shared self-signed RSA-4096 test cert/key into tmpdir; build
 * absolute @ paths.  Both backends load the same fixed cert material
 * (previously OpenSSL generated a fresh Ed25519 cert here while mbedTLS
 * fell back to this same hardcoded RSA-4096 pair, so no test ever
 * exercised the same algorithm against both backends). Returns origdir
 * (must be freed) or NULL on failure. */
static char *setup_cert_dir(
	char *restrict tmpl, char *restrict cert_out, const size_t cert_sz,
	char *restrict key_out, const size_t key_sz)
{
	char *const origdir = getcwd(NULL, 0);
	if (origdir == NULL) {
		return NULL;
	}
	if (mkdtemp(tmpl) == NULL) {
		free(origdir);
		return NULL;
	}
	track_tmpdir(tmpl);
	if (chdir(tmpl) != 0) {
		rm_tmpdir(tmpl);
		free(origdir);
		return NULL;
	}
	if (!make_test_certs()) {
		if (chdir(origdir) != 0) {
			const int err = errno;
			LOGW_F("chdir: (%d) %s", err, strerror(err));
		}
		rm_tmpdir(tmpl);
		free(origdir);
		return NULL;
	}
	/* Build absolute paths using the @ prefix recognised by tls_load_cert. */
	(void)snprintf(cert_out, cert_sz, "@%s/t-cert.pem", tmpl);
	(void)snprintf(key_out, key_sz, "@%s/t-key.pem", tmpl);
	if (chdir(origdir) != 0) {
		const int err = errno;
		LOGW_F("chdir: (%d) %s", err, strerror(err));
	}
	return origdir;
}

/* Read the entire contents of a file into a malloc-allocated string.
 * Returns NULL on failure. */
static char *slurp_file(const char *path)
{
	FILE *const fp = fopen(path, "r");
	if (fp == NULL) {
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		(void)fclose(fp);
		return NULL;
	}
	const long size = ftell(fp);
	if (size < 0) {
		(void)fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		(void)fclose(fp);
		return NULL;
	}
	char *const buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		(void)fclose(fp);
		return NULL;
	}
	const size_t n = fread(buf, 1, (size_t)size, fp);
	(void)fclose(fp);
	buf[n] = '\0';
	return buf;
}

/* Drive TLS handshake on both connections alternately until both complete.
 * Returns true on success, false on error. */
static bool drive_handshake(
	struct tls_connection *restrict srv,
	struct tls_connection *restrict cli, int max_rounds)
{
	bool srv_done = false, cli_done = false;
	for (int i = 0; i < max_rounds; i++) {
		if (!cli_done) {
			const enum tls_error err = tls_handshake(cli);
			if (err == TLS_ERROR_NONE) {
				cli_done = true;
			} else if (
				err != TLS_ERROR_WANT_READ &&
				err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
		}
		if (!srv_done) {
			const enum tls_error err = tls_handshake(srv);
			if (err == TLS_ERROR_NONE) {
				srv_done = true;
			} else if (
				err != TLS_ERROR_WANT_READ &&
				err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
		}
		if (cli_done && srv_done) {
			return true;
		}
	}
	return false;
}

/* Drive TLS shutdown on both connections alternately until both complete.
 * Returns true on clean completion, false on error. */
static bool drive_shutdown(
	struct tls_connection *restrict a, struct tls_connection *restrict b,
	int max_rounds)
{
	bool a_done = false, b_done = false;
	for (int i = 0; i < max_rounds; i++) {
		if (!a_done) {
			const enum tls_error err = tls_shutdown(a);
			if (err == TLS_ERROR_NONE) {
				a_done = true;
			} else if (
				err != TLS_ERROR_WANT_READ &&
				err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
		}
		if (!b_done) {
			const enum tls_error err = tls_shutdown(b);
			if (err == TLS_ERROR_NONE) {
				b_done = true;
			} else if (
				err != TLS_ERROR_WANT_READ &&
				err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
		}
		if (a_done && b_done) {
			return true;
		}
	}
	return false;
}

T_DECLARE_CASE(test_tls_ctx_server_null_cert_fails)
{
	char cert[] = "";
	char key[] = "";
	struct tls_context *const ctx = tls_ctx_server(
		&(struct tls_config){ .cert = cert, .key = key });
	T_EXPECT(ctx == NULL);
}

T_DECLARE_CASE(test_tls_ctx_bad_cert_fails)
{
	char cert[] = "this is not a PEM certificate at all";
	char key[] = "this is not a PEM key at all";
	struct tls_context *const ctx = tls_ctx_server(
		&(struct tls_config){ .cert = cert, .key = key });
	T_EXPECT(ctx == NULL);
}

/* A cryptographically mismatched cert/key pair must be rejected outright,
 * not silently accepted with an unusable identity, on both backends. */
T_DECLARE_CASE(test_tls_ctx_mismatched_key_fails)
{
	struct tls_context *const server = tls_ctx_server(&(struct tls_config){
		.cert = test_cert_pem, .key = mismatched_key_pem });
	T_EXPECT(server == NULL);

	struct tls_context *const client = tls_ctx_client(&(struct tls_config){
		.cert = test_cert_pem, .key = mismatched_key_pem });
	T_EXPECT(client == NULL);
}

T_DECLARE_CASE(test_tls_ctx_server_created)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_EXPECT(ctx != NULL);
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_ctx_client_created)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_EXPECT(ctx != NULL);
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_key_empty_fails)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char empty[] = "";
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);
	T_EXPECT(!tls_load_key(ctx, empty));
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

/* A password-protected key (AES-256-CBC encrypted EC key, passphrase
 * "testpass123", generated once via `openssl ec -aes256`) must fail to load
 * cleanly, not block waiting for a passphrase on the controlling terminal --
 * no callback here ever supplies one, so this exercises the reject path. */
static const char *const test_encrypted_key_pem =
	"-----BEGIN EC PRIVATE KEY-----\n"
	"Proc-Type: 4,ENCRYPTED\n"
	"DEK-Info: AES-256-CBC,F51B83B13BB82B882F7509BBD9A7FD6F\n"
	"\n"
	"NU4Dgk8he0/jvgJotN+mEQdvcCTxFf52UEsmmsM44G1LfUrtSwBO3FsTWkPhGOLF\n"
	"Y2E08TEL29XSDnUTa6DiXa24amyt2ieJnXTDkbpfOj+pjnzdoQtNJB0T30PUQ+nr\n"
	"QmBXa0Z+bdVrpnUTQS4rbYR1g6tVKC/h88F3TMiaJrw=\n"
	"-----END EC PRIVATE KEY-----\n";

T_DECLARE_CASE(test_tls_load_key_rejects_encrypted_key)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);
	T_EXPECT(!tls_load_key(ctx, test_encrypted_key_pem));
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_cert_missing_file_fails)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char missing[] = "@/tmp/tls_missing_cert.pem";
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);
	T_EXPECT(!tls_load_cert(ctx, missing));
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_authcerts_rejects_invalid_entries)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char empty[] = "";
	char garbage[] = "not a cert";
	char *authcerts_null[] = { NULL };
	char *authcerts_empty[] = { empty };
	char *authcerts_garbage[] = { garbage };
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);
	T_EXPECT(tls_load_authcerts(ctx, NULL, 0));
	T_EXPECT(!tls_load_authcerts(ctx, authcerts_null, 1));
	T_EXPECT(!tls_load_authcerts(ctx, authcerts_empty, 1));
	/* Non-empty but not a PEM certificate: zero certificates are actually
	 * parsed, so this must fail rather than silently succeed. */
	T_EXPECT(!tls_load_authcerts(ctx, authcerts_garbage, 1));
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_authcerts_rejects_corrupted_chain)
{
	/* A bundle with a valid first cert followed by a corrupted second
	 * entry (BEGIN marker present but an undecodable body -- unlike
	 * "not a cert" above, this exercises the real-parse-error path, not
	 * clean EOF) must be rejected outright instead of silently accepting
	 * just the first cert. */
	char bundle[4096];
	const int n = snprintf(
		bundle, sizeof(bundle),
		"%s"
		"-----BEGIN CERTIFICATE-----\n"
		"ThisIsNotValidBase64Content!!!!\n"
		"-----END CERTIFICATE-----\n",
		test_ca_cert_pem);
	T_CHECK(n > 0 && (size_t)n < sizeof(bundle));

	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);
	char *corrupted[] = { bundle };
	T_EXPECT(!tls_load_authcerts(ctx, corrupted, 1));
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

/* An unrecognized ciphersuite name must fail context creation outright
 * rather than silently falling back to the default suite set. */
T_DECLARE_CASE(test_tls_ctx_invalid_ciphersuites_fail)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char ciphersuites[] = "TLS_NO_SUCH_CIPHERSUITE";
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	const struct tls_config tls_conf = {
		.cert = cert_path,
		.key = key_path,
		.authcerts = authcerts,
		.authcerts_count = 1,
		.ciphersuites = ciphersuites,
	};
	T_EXPECT(tls_ctx_server(&tls_conf) == NULL);
	T_EXPECT(tls_ctx_client(&tls_conf) == NULL);

	rm_tmpdir(tmpl);
}

/* An empty ciphersuites string must fail context creation on both backends.
 * mbedTLS rejects it at context creation; OpenSSL's SSL_CTX_set_ciphersuites("")
 * would otherwise succeed but leave a TLS-1.3-pinned context with zero suites
 * that can never handshake. */
T_DECLARE_CASE(test_tls_ctx_empty_ciphersuites_fails)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char ciphersuites[] = "";
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	const struct tls_config tls_conf = {
		.cert = cert_path,
		.key = key_path,
		.authcerts = authcerts,
		.authcerts_count = 1,
		.ciphersuites = ciphersuites,
	};
	T_EXPECT(tls_ctx_server(&tls_conf) == NULL);
	T_EXPECT(tls_ctx_client(&tls_conf) == NULL);

	rm_tmpdir(tmpl);
}

#if !WITH_OPENSSL
/* mbedtls_ssl_get_ciphersuite_id() resolves from a unified TLS-1.2+1.3
 * registry with no applicability check against the pinned TLS-1.3-only
 * context, unlike OpenSSL's SSL_CTX_set_ciphersuites() (TLS-1.3 only by
 * construction, so this scenario cannot arise under WITH_OPENSSL -- any
 * TLS-1.2 name is already "unrecognized" to it, no differently than
 * test_tls_ctx_invalid_ciphersuites_fail above). A recognized-but-
 * TLS-1.2-only name must still fail context creation, not silently
 * construct a context that can never negotiate it. */
T_DECLARE_CASE(test_tls_ctx_tls12_only_ciphersuite_fails)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char ciphersuites[] = "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256";
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	const struct tls_config tls_conf = {
		.cert = cert_path,
		.key = key_path,
		.authcerts = authcerts,
		.authcerts_count = 1,
		.ciphersuites = ciphersuites,
	};
	T_EXPECT(tls_ctx_server(&tls_conf) == NULL);
	T_EXPECT(tls_ctx_client(&tls_conf) == NULL);

	rm_tmpdir(tmpl);
}
#endif /* !WITH_OPENSSL */

T_DECLARE_CASE(test_tls_server_and_client_validate_inputs)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	struct tls_connection *conn = NULL;
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);
	/* A NULL context is rejected; fd=-1 is valid and selects memory-backed mode. */
	T_EXPECT(tls_server(NULL, -1) == NULL);
	T_EXPECT(tls_client(NULL, -1) == NULL);
	conn = tls_server(ctx, -1);
	T_EXPECT(conn != NULL);
	if (conn != NULL) {
		tls_conn_free(conn);
	}
	if (ctx != NULL) {
		tls_ctx_free(ctx);
	}

	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_cert_from_memory_succeeds)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);

	/* Read the certificate PEM directly from the file (cert_path + 1 strips
	 * the '@' prefix to get the real path) and pass it without '@' to
	 * exercise the in-memory load path of tls_load_cert. */
	char *const pem = slurp_file(cert_path + 1);
	T_CHECK(pem != NULL);
	T_EXPECT(tls_load_cert(ctx, pem));
	free(pem);

	tls_ctx_free(ctx);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_load_key_from_memory_succeeds)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(ctx != NULL);

	/* Read the key PEM from the file (key_path + 1 strips '@') and pass it
	 * without '@' to exercise the in-memory load path of tls_load_key. */
	char *const pem = slurp_file(key_path + 1);
	T_CHECK(pem != NULL);
	T_EXPECT(tls_load_key(ctx, pem));
	free(pem);

	tls_ctx_free(ctx);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_full_handshake_and_io)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	/* Non-blocking so the handshake can be driven cooperatively. */
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* Round-trip: client sends, server receives. */
	unsigned char send_buf[] = "hello";
	unsigned char recv_buf[sizeof(send_buf)] = { 0 };
	size_t send_len = sizeof(send_buf) - 1;
	size_t recv_len = sizeof(recv_buf) - 1;
	T_EXPECT_EQ(tls_send(cli_conn, send_buf, &send_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(send_len, sizeof(send_buf) - 1);
	T_EXPECT_EQ(tls_recv(srv_conn, recv_buf, &recv_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(recv_len, sizeof(send_buf) - 1);
	T_EXPECT(memcmp(recv_buf, send_buf, recv_len) == 0);

	/* Exercise the TLS shutdown path: drive close_notify exchange. */
	T_EXPECT(drive_shutdown(cli_conn, srv_conn, 10));

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	rm_tmpdir(tmpl);
}

/* Backend-agnostic tls_ctx_ref lifetime: ref a client context, free the
 * *original*, then complete a handshake and round-trip through the ref. The
 * shared parsed credentials must survive the original's free -- exercising
 * mbedTLS's hand-rolled tls_ctx_impl_ref/unref (and per-connection
 * tls_conn_alloc/free) as well as OpenSSL's SSL_CTX up-ref, which the
 * WITH_OPENSSL-only ALPN case never covers under mbedTLS. */
T_DECLARE_CASE(test_tls_ctx_ref_shares_credentials_after_original_freed)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	struct tls_context *const cli_ref = tls_ctx_ref(cli_ctx);
	T_CHECK(cli_ref != NULL);
	/* Free the original: only the ref keeps the shared credentials alive. */
	tls_ctx_free(cli_ctx);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ref, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_EXPECT(drive_handshake(srv_conn, cli_conn, 20));

	unsigned char send_buf[] = "hello";
	unsigned char recv_buf[sizeof(send_buf)] = { 0 };
	size_t send_len = sizeof(send_buf) - 1;
	size_t recv_len = sizeof(recv_buf) - 1;
	T_EXPECT_EQ(tls_send(cli_conn, send_buf, &send_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(tls_recv(srv_conn, recv_buf, &recv_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(recv_len, sizeof(send_buf) - 1);
	T_EXPECT(memcmp(recv_buf, send_buf, recv_len) == 0);

	T_EXPECT(drive_shutdown(cli_conn, srv_conn, 10));

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ref);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_handshake_syscall_on_closed_peer)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	/* Peer gone before the handshake starts: SSL_do_handshake's first
	 * flush hits EPIPE, surfacing SSL_ERROR_SYSCALL with an empty error
	 * queue -- the exact case commit 4d2b096 added errno logging for. */
	(void)close(fds[1]);

	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[0]);
	T_CHECK(cli_conn != NULL);
	T_EXPECT_EQ(tls_handshake(cli_conn), TLS_ERROR_SYSCALL);

	tls_conn_free(cli_conn);
	tls_ctx_free(cli_ctx);
	(void)close(fds[0]);
	rm_tmpdir(tmpl);
}

/* "hostname never gates the mTLS trust decision" is an explicit,
 * security-relevant design choice per backend (OpenSSL's own comment
 * says "hostname check is omitted"; mbedTLS suppresses CN-mismatch via a
 * dedicated callback) -- a mismatching client SNI must not prevent the
 * handshake from succeeding, since trust here comes entirely from the
 * authcerts pin, not from hostname verification. */
T_DECLARE_CASE(test_tls_sni_mismatch_still_succeeds)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	/* SNI deliberately does not match the cert's CN/SAN (test.example). */
	struct tls_context *const cli_ctx = tls_ctx_client(
		&(struct tls_config){ .cert = cert_path,
				      .key = key_path,
				      .authcerts = authcerts,
				      .authcerts_count = 1,
				      .sni = "totally-different.invalid" });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_EXPECT(drive_handshake(srv_conn, cli_conn, 20));

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	rm_tmpdir(tmpl);
}

/* The documented CA-signed topology must actually work -- every other
 * fixture in this file is a single self-signed cert also presented as
 * its own authorized peer, which never exercises real chain validation
 * (leaf signed by a separate, distinct CA key). tls_config.cert/
 * key/authcerts accept raw PEM directly (not just "@file"), so this
 * needs no tmpdir. */
T_DECLARE_CASE(test_tls_ca_signed_chain_accepted)
{
	char *authcerts[] = { test_ca_cert_pem };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = test_leaf_cert_pem,
						     .key = test_leaf_key_pem,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = test_leaf_cert_pem,
						     .key = test_leaf_key_pem,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_EXPECT(drive_handshake(srv_conn, cli_conn, 20));

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* An expired peer certificate must be rejected during the handshake,
 * not silently accepted -- the client here presents
 * test_expired_cert_pem (notAfter 2021-01-01, long past) as its own
 * identity; the server trusts it via authcerts (self-signed, so it is
 * its own issuer) but must still reject it on expiry. */
T_DECLARE_CASE(test_tls_expired_cert_rejected)
{
	char *srv_authcerts[] = { test_cert_pem };
	char *cli_authcerts[] = { test_expired_cert_pem };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = test_cert_pem,
						     .key = test_key_pem,
						     .authcerts = cli_authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx = tls_ctx_client(
		&(struct tls_config){ .cert = test_expired_cert_pem,
				      .key = test_expired_key_pem,
				      .authcerts = srv_authcerts,
				      .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_EXPECT(!drive_handshake(srv_conn, cli_conn, 20));

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* The certificate-strength floor both backends must enforce identically has no
 * rejection coverage otherwise (every other fixture is above it). Each case
 * below has the client present a peer certificate below one leg of the floor
 * and the server trust it (or its CA) via authcerts; the sub-floor certificate
 * must not yield a completed handshake. The server presents the strong
 * test_cert_pem, which the client accepts, so only the client certificate's
 * strength is under test.
 *
 * A sub-floor certificate can be refused at two points: the TLS library may
 * decline to load it as an own certificate (OpenSSL's own security level
 * rejects a sub-2048 RSA key / SHA-1 signature, so cli_ctx creation fails), or
 * -- when it loads and reaches the wire, as it does on the mbedTLS backend
 * whose profile is applied only at verification -- the server's verify floor
 * rejects it during the handshake. Either outcome means the weak certificate
 * was not accepted.  On OpenSSL both cases take the load-refusal path, so they
 * do NOT exercise tls_verify_cert_strength_cb(); that verify floor is covered
 * directly in tls_openssl_test.c.  These handshake cases are what genuinely
 * exercises the mbedTLS profile floor. */
T_DECLARE_SUBCASE(
	assert_peer_cert_rejected, const char *restrict cli_cert,
	const char *restrict cli_key, char *cli_trust)
{
	char *srv_authcerts[] = { cli_trust };
	char *cli_authcerts[] = { test_cert_pem };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = test_cert_pem,
						     .key = test_key_pem,
						     .authcerts = srv_authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cli_cert,
						     .key = cli_key,
						     .authcerts = cli_authcerts,
						     .authcerts_count = 1 });
	if (cli_ctx == NULL) {
		/* Refused at load: the weak certificate never reaches the wire. */
		tls_ctx_free(srv_ctx);
		return;
	}

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_EXPECT(!drive_handshake(srv_conn, cli_conn, 20));

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* An RSA key below TLS_RSA_MIN_BITS (RSA-1024) must be rejected. */
T_DECLARE_CASE(test_tls_weak_rsa_cert_rejected)
{
	T_CALL_SUBCASE(
		assert_peer_cert_rejected, test_weak_rsa_cert_pem,
		test_weak_rsa_key_pem, test_weak_floor_ca_cert_pem);
}

/* A leaf whose signature digest is below the floor (SHA-1) must be rejected. */
T_DECLARE_CASE(test_tls_weak_digest_cert_rejected)
{
	T_CALL_SUBCASE(
		assert_peer_cert_rejected, test_weak_digest_cert_pem,
		test_weak_digest_key_pem, test_weak_floor_ca_cert_pem);
}

/* Verify tls_shutdown is one-way: sending close_notify returns NONE without
 * waiting for the peer, and the peer observes the close via tls_recv returning
 * ZERO_RETURN.  This is the unified contract both backends must honour. */
T_DECLARE_CASE(test_tls_shutdown_oneway)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* Client sends close_notify only; it must complete without waiting for
	 * the server's close_notify (one-way). */
	enum tls_error sd = TLS_ERROR_WANT_WRITE;
	for (int i = 0; i < 10 && (sd == TLS_ERROR_WANT_READ ||
				   sd == TLS_ERROR_WANT_WRITE);
	     i++) {
		sd = tls_shutdown(cli_conn);
	}
	T_EXPECT_EQ(sd, TLS_ERROR_NONE);

	/* The server observes the close via tls_recv, not via its own shutdown. */
	enum tls_error rd = TLS_ERROR_WANT_READ;
	for (int i = 0; i < 10 && rd == TLS_ERROR_WANT_READ; i++) {
		unsigned char buf[64];
		size_t n = sizeof(buf);
		rd = tls_recv(srv_conn, buf, &n);
	}
	T_EXPECT_EQ(rd, TLS_ERROR_ZERO_RETURN);

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	rm_tmpdir(tmpl);
}

/* A transport failure while sending close_notify must classify as
 * TLS_ERROR_SYSCALL on both backends, not TLS_ERROR_SSL: the shim's
 * cross-backend contract routes a syscall-level failure to SYSCALL (mbedTLS's
 * MBEDTLS_ERR_NET_CONN_RESET / NET_SEND_FAILED / NET_RECV_FAILED and OpenSSL's
 * SSL_ERROR_SYSCALL all land there).  Complete a handshake, drop the peer's
 * transport, then drive tls_shutdown: the close_notify send hits a broken pipe
 * (EPIPE -> NET_CONN_RESET on mbedTLS; SIGPIPE is ignored in main), so both
 * backends must report SYSCALL.  Guards the parity contract against a
 * regression that let the NET_* cases fall back to the default TLS_ERROR_SSL
 * branch -- the whole suite would otherwise pass while the two backends
 * re-diverged (cf. test_tls_shutdown_oneway, which only covers the NONE happy
 * path). */
T_DECLARE_CASE(test_tls_shutdown_syscall_on_broken_transport)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* Drop the server's transport with no close_notify; the client's
	 * close_notify send below then hits a broken pipe.  NOCLOSE semantics
	 * (SSL_set_fd / mbedTLS net BIO) mean freeing srv_conn never touches this
	 * fd, so closing it here is safe. */
	(void)close(fds[0]);

	enum tls_error sd = TLS_ERROR_WANT_WRITE;
	for (int i = 0; i < 10 && (sd == TLS_ERROR_WANT_READ ||
				   sd == TLS_ERROR_WANT_WRITE);
	     i++) {
		sd = tls_shutdown(cli_conn);
	}
	T_EXPECT_EQ(sd, TLS_ERROR_SYSCALL);

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[1]);
	rm_tmpdir(tmpl);
}

/* A post-handshake abrupt close (peer transport gone with no close_notify)
 * must surface a terminal error from tls_recv, never TLS_ERROR_NONE with zero
 * bytes read -- the buggy path there left the caller busy-looping on an
 * always-readable EOF fd.  The exact terminal code is backend-specific
 * (mbedTLS: TLS_ERROR_SYSCALL, since mbedtls_ssl_read() returns 0 for an EOF
 * without CloseNotify; OpenSSL 3.x: TLS_ERROR_SSL for the unexpected-EOF
 * protocol error), but both differ from the orderly TLS_ERROR_ZERO_RETURN a
 * close_notify produces -- contrast test_tls_shutdown_oneway above. */
T_DECLARE_CASE(test_tls_recv_syscall_on_abrupt_peer_close)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* Drop the client's transport with no close_notify (SSL_set_fd/mbedTLS
	 * net BIO both use NOCLOSE, so freeing cli_conn below never touches this
	 * fd -- closing it here is safe). */
	(void)close(fds[1]);

	enum tls_error rd = TLS_ERROR_WANT_READ;
	for (int i = 0; i < 10 && rd == TLS_ERROR_WANT_READ; i++) {
		unsigned char buf[64];
		size_t n = sizeof(buf);
		rd = tls_recv(srv_conn, buf, &n);
	}
	/* The bug reported TLS_ERROR_NONE with n==0 here; require a terminal
	 * error indicating the connection is gone instead. */
	T_EXPECT(rd == TLS_ERROR_SYSCALL || rd == TLS_ERROR_SSL);

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	rm_tmpdir(tmpl);
}

/* Run a full handshake with the given server/client ALPN lists (NULL = omit
 * the extension) and report whether it completed.  Used to verify ALPN
 * negotiation policy. */
static bool alpn_handshake(
	const char *restrict cert_path, const char *restrict key_path,
	char *const *restrict authcerts, const char *restrict srv_alpn,
	const char *restrict cli_alpn)
{
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1,
						     .alpn = srv_alpn });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1,
						     .alpn = cli_alpn });
	bool ok = false;
	int fds[2] = { -1, -1 };
	struct tls_connection *srv_conn = NULL, *cli_conn = NULL;
	if (srv_ctx == NULL || cli_ctx == NULL) {
		goto cleanup;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0 ||
	    fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
		goto cleanup;
	}
	srv_conn = tls_server(srv_ctx, fds[0]);
	cli_conn = tls_client(cli_ctx, fds[1]);
	if (srv_conn == NULL || cli_conn == NULL) {
		goto cleanup;
	}
	ok = drive_handshake(srv_conn, cli_conn, 20);
cleanup:
	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	if (fds[0] >= 0) {
		(void)close(fds[0]);
	}
	if (fds[1] >= 0) {
		(void)close(fds[1]);
	}
	return ok;
}

T_DECLARE_CASE(test_tls_alpn_negotiation)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	/* Overlapping lists negotiate successfully. */
	T_EXPECT(alpn_handshake(
		cert_path, key_path, authcerts, "h2,http/1.1", "http/1.1"));
	/* Both advertise ALPN but share no protocol: handshake must fail. */
	T_EXPECT(!alpn_handshake(
		cert_path, key_path, authcerts, "h2", "http/1.1"));
	/* One side omits ALPN (NULL): handshake proceeds without negotiation. */
	T_EXPECT(alpn_handshake(cert_path, key_path, authcerts, NULL, "h2"));
	T_EXPECT(alpn_handshake(cert_path, key_path, authcerts, "h2", NULL));
	/* An empty string is equivalent to NULL: no ALPN extension is sent, so
	 * the otherwise-disjoint lists do not cause a failure. */
	T_EXPECT(alpn_handshake(cert_path, key_path, authcerts, "", "h2"));
	T_EXPECT(alpn_handshake(cert_path, key_path, authcerts, "h2", ""));
	T_EXPECT(alpn_handshake(cert_path, key_path, authcerts, "", ""));

	rm_tmpdir(tmpl);
}

/* csv_scanfield's "need more data" check could not distinguish a
 * genuinely incomplete quoted field (ran off the end of the buffer
 * without ever finding a closing quote) from a complete one whose
 * closing quote simply happened to be the last byte -- both left the
 * scan cursor sitting on the same NUL. A quoted protocol name as the
 * *last* ALPN list entry hit exactly this: the client's sole entry here
 * is quoted with nothing following its closing quote, and the server's
 * list ends the same way. The only entry the two sides have in common
 * is that quoted name, so this can only succeed if both ends parse it,
 * not just tolerate a malformed list falling back to no-ALPN. */
T_DECLARE_CASE(test_tls_alpn_quoted_entry_at_list_end)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	T_EXPECT(alpn_handshake(
		cert_path, key_path, authcerts, "h2,\"x,y\"", "\"x,y\""));

	rm_tmpdir(tmpl);
}

/* A malformed ALPN list must fail context creation (fail closed), not silently
 * drop the operator's configured ALPN.  An unterminated quote and stray bytes
 * after a closing quote both make tls_ctx_server/tls_ctx_client return NULL --
 * the gap that let the silent-drop (mbedTLS parse_alpn) and CSV-truncation (both
 * backends) ALPN P0s through. */
T_DECLARE_CASE(test_tls_alpn_malformed_list_fails_ctx)
{
	static const char *const bad[] = {
		"\"unterminated", /* quote never closed */
		"h2,\"x\"y", /* stray bytes after a closing quote */
		"h2,\"\"x", /* stray bytes after an empty closing quote */
		"\"\"x", /* stray bytes after a leading empty quoted field */
		NULL,
	};
	for (const char *const *list = bad; *list != NULL; list++) {
		T_EXPECT(
			tls_ctx_server(
				&(struct tls_config){ .cert = test_cert_pem,
						      .key = test_key_pem,
						      .alpn = *list }) == NULL);
		T_EXPECT(
			tls_ctx_client(
				&(struct tls_config){ .cert = test_cert_pem,
						      .key = test_key_pem,
						      .alpn = *list }) == NULL);
	}
}

#if WITH_OPENSSL
/* OpenSSL-only: tls_ctx_ref() refuses to share a server-role context whose
 * ssl_ctx has an ALPN select callback registered.  The callback argument is an
 * SSL_CTX-lifetime struct alpn_wire (via ex_data), so sharing would no longer
 * dangle; the refusal is conservative, keeping one owner per ALPN-enabled
 * server context (see alpn_cb_registered in tls_openssl.c).  mbedTLS has no
 * analogous case. */
T_DECLARE_CASE(test_tls_ctx_ref_refuses_alpn_server)
{
	struct tls_context *const alpn_server =
		tls_ctx_server(&(struct tls_config){ .cert = test_cert_pem,
						     .key = test_key_pem,
						     .alpn = "h2" });
	T_CHECK(alpn_server != NULL);
	T_EXPECT(tls_ctx_ref(alpn_server) == NULL);
	tls_ctx_free(alpn_server);

	struct tls_context *const plain_server =
		tls_ctx_server(&(struct tls_config){ .cert = test_cert_pem,
						     .key = test_key_pem });
	T_CHECK(plain_server != NULL);
	struct tls_context *const plain_ref = tls_ctx_ref(plain_server);
	T_EXPECT(plain_ref != NULL);
	tls_ctx_free(plain_ref);
	tls_ctx_free(plain_server);
}

/* OpenSSL-only regression: SSL_new up-refs only the SSL_CTX, not the
 * tls_ctx_impl wrapper, so a reload that tls_ctx_free()s the server context
 * while an accepted connection is still mid-handshake must not leave
 * alpn_select_cb dereferencing a freed buffer.  Freeing both contexts before
 * driving the handshake reproduces the window; the fix hangs the ALPN buffer
 * off the SSL_CTX ex_data, so the pre-fix wrapper-as-callback-arg tripped ASan
 * heap-use-after-free here. */
T_DECLARE_CASE(test_tls_alpn_survives_ctx_free_mid_handshake)
{
	char *authcerts[] = { test_cert_pem };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = test_cert_pem,
						     .key = test_key_pem,
						     .authcerts = authcerts,
						     .authcerts_count = 1,
						     .alpn = "h2,http/1.1" });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = test_cert_pem,
						     .key = test_key_pem,
						     .authcerts = authcerts,
						     .authcerts_count = 1,
						     .alpn = "h2" });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);

	/* Free both contexts before the handshake runs: the SSL objects keep the
	 * SSL_CTX alive via SSL_new's ref, but the wrappers are gone. */
	tls_ctx_free(srv_ctx);
	tls_ctx_free(cli_ctx);

	const bool ok = drive_handshake(srv_conn, cli_conn, 20);

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	(void)close(fds[0]);
	(void)close(fds[1]);
	T_EXPECT(ok);
}
#endif /* WITH_OPENSSL */

T_DECLARE_CASE(test_tls_peer_cert_der_after_handshake)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* Both sides should be able to retrieve the peer's certificate. */
	unsigned char *srv_der = NULL;
	size_t srv_der_len = 0;
	T_EXPECT(tls_peer_cert_der(srv_conn, &srv_der, &srv_der_len));
	T_EXPECT(srv_der != NULL);
	T_EXPECT(srv_der_len > 0);

	unsigned char *cli_der = NULL;
	size_t cli_der_len = 0;
	T_EXPECT(tls_peer_cert_der(cli_conn, &cli_der, &cli_der_len));
	T_EXPECT(cli_der != NULL);
	T_EXPECT(cli_der_len > 0);

	/* Same certificate on both sides (self-signed test cert). */
	T_EXPECT(srv_der_len == cli_der_len);
	T_EXPECT(memcmp(srv_der, cli_der, srv_der_len) == 0);

	free(srv_der);
	free(cli_der);

	T_EXPECT(drive_shutdown(cli_conn, srv_conn, 10));
	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	rm_tmpdir(tmpl);
}

/* Handshake both ends using the identity fixture certificate, so each side sees
 * it as the peer certificate.  On success the caller owns everything and must
 * run identity_fixture_teardown(); on failure nothing is left open. */
struct identity_fixture {
	struct tls_context *srv_ctx, *cli_ctx;
	struct tls_connection *srv_conn, *cli_conn;
	int fds[2];
};

static bool identity_fixture_setup(
	struct identity_fixture *restrict f, const char *restrict tmpl)
{
	char cert[PATH_MAX + 2];
	char key[PATH_MAX + 2];
	(void)snprintf(cert, sizeof(cert), "@%s/id-cert.pem", tmpl);
	(void)snprintf(key, sizeof(key), "@%s/id-key.pem", tmpl);
	char *authcerts[] = { cert };
	const struct tls_config conf = {
		.cert = cert,
		.key = key,
		.authcerts = authcerts,
		.authcerts_count = 1,
	};
	*f = (struct identity_fixture){ .fds = { -1, -1 } };
	f->srv_ctx = tls_ctx_server(&conf);
	f->cli_ctx = tls_ctx_client(&conf);
	if (f->srv_ctx == NULL || f->cli_ctx == NULL ||
	    socketpair(AF_UNIX, SOCK_STREAM, 0, f->fds) != 0) {
		tls_ctx_free(f->srv_ctx);
		tls_ctx_free(f->cli_ctx);
		return false;
	}
	if (fcntl(f->fds[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(f->fds[1], F_SETFL, O_NONBLOCK) != 0) {
		goto fail;
	}
	f->srv_conn = tls_server(f->srv_ctx, f->fds[0]);
	f->cli_conn = tls_client(f->cli_ctx, f->fds[1]);
	if (f->srv_conn == NULL || f->cli_conn == NULL ||
	    !drive_handshake(f->srv_conn, f->cli_conn, 20)) {
		tls_conn_free(f->srv_conn);
		tls_conn_free(f->cli_conn);
		goto fail;
	}
	return true;
fail:
	(void)close(f->fds[0]);
	(void)close(f->fds[1]);
	tls_ctx_free(f->srv_ctx);
	tls_ctx_free(f->cli_ctx);
	return false;
}

static void identity_fixture_teardown(struct identity_fixture *restrict f)
{
	tls_conn_free(f->cli_conn);
	tls_conn_free(f->srv_conn);
	tls_ctx_free(f->cli_ctx);
	tls_ctx_free(f->srv_ctx);
	(void)close(f->fds[0]);
	(void)close(f->fds[1]);
}

/* PSK fixtures.  The expected labels are golden values cross-checked against
 * an independent HKDF-SHA256 implementation and the openssl kdf CLI, so they
 * pin the derivation itself rather than merely agreeing with whatever this
 * build computes -- and both backends must reproduce them. */
static const unsigned char psk_ones[TLS_PSK_MIN_LEN] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};
static const unsigned char psk_twos[TLS_PSK_MIN_LEN] = {
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};
#define PSK_ONES_LABEL "940645b8f8542cfecce8598684ea96de"
#define PSK_TWOS_LABEL "955df2a45f835db1569e151156e4b8dc"

T_DECLARE_CASE(test_tls_psk_label)
{
	char buf[TLS_PSK_LABEL_MAX + 1];
	size_t len = sizeof(buf);
	T_EXPECT(tls_psk_label(psk_ones, sizeof(psk_ones), buf, &len));
	T_EXPECT_STREQ(buf, PSK_ONES_LABEL);
	T_EXPECT_EQ((int)len, (int)TLS_PSK_LABEL_MAX);

	/* Deterministic, and distinct for a different key. */
	len = sizeof(buf);
	T_EXPECT(tls_psk_label(psk_ones, sizeof(psk_ones), buf, &len));
	T_EXPECT_STREQ(buf, PSK_ONES_LABEL);
	len = sizeof(buf);
	T_EXPECT(tls_psk_label(psk_twos, sizeof(psk_twos), buf, &len));
	T_EXPECT_STREQ(buf, PSK_TWOS_LABEL);

	/* Rejects a key outside the accepted range and a short buffer. */
	len = sizeof(buf);
	T_EXPECT(!tls_psk_label(psk_ones, TLS_PSK_MIN_LEN - 1, buf, &len));
	T_EXPECT(!tls_psk_label(psk_ones, TLS_PSK_MAX_LEN + 1, buf, &len));
	len = TLS_PSK_LABEL_MAX;
	T_EXPECT(!tls_psk_label(psk_ones, sizeof(psk_ones), buf, &len));
	len = sizeof(buf);
	T_EXPECT(!tls_psk_label(NULL, sizeof(psk_ones), buf, &len));
}

/* tls_psk_lookup_fn knowing only psk_ones. */
static bool psk_test_lookup(
	void *ctx, const char *identity, unsigned char *key, size_t *key_len)
{
	(void)ctx;
	if (strcmp(identity, PSK_ONES_LABEL) != 0) {
		return false;
	}
	if (*key_len < sizeof(psk_ones)) {
		return false;
	}
	memcpy(key, psk_ones, sizeof(psk_ones));
	*key_len = sizeof(psk_ones);
	return true;
}

/* Handshake a PSK pair over a socketpair; *ok reports completion. */
T_DECLARE_SUBCASE(
	run_psk_handshake, const unsigned char *client_key, bool *restrict ok,
	char *restrict srv_label, char *restrict cli_label)
{
	*ok = false;
	srv_label[0] = cli_label[0] = '\0';
	struct tls_context *const srv_ctx = tls_ctx_server(
		&(struct tls_config){ .psk_lookup = psk_test_lookup });
	struct tls_context *const cli_ctx = tls_ctx_client(&(struct tls_config){
		.psk = client_key, .psk_len = TLS_PSK_MIN_LEN });
	/* A context with only PSK credentials must be creatable: no
	 * certificate, no key, no trust store. */
	T_EXPECT(srv_ctx != NULL);
	T_EXPECT(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_EXPECT(srv_conn != NULL);
	T_EXPECT(cli_conn != NULL);

	*ok = drive_handshake(srv_conn, cli_conn, 20);
	size_t len = TLS_PSK_LABEL_MAX + 1;
	if (!tls_peer_psk_label(srv_conn, srv_label, &len)) {
		srv_label[0] = '\0';
	}
	len = TLS_PSK_LABEL_MAX + 1;
	if (!tls_peer_psk_label(cli_conn, cli_label, &len)) {
		cli_label[0] = '\0';
	}
	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
}

/* No certificate is involved on either side, which is the point. */
T_DECLARE_CASE(test_tls_psk_handshake)
{
	bool ok = false;
	char srv_label[TLS_PSK_LABEL_MAX + 1];
	char cli_label[TLS_PSK_LABEL_MAX + 1];
	T_CALL_SUBCASE(run_psk_handshake, psk_ones, &ok, srv_label, cli_label);
	T_EXPECT(ok);
	T_EXPECT_STREQ(srv_label, PSK_ONES_LABEL);
	T_EXPECT_STREQ(cli_label, PSK_ONES_LABEL);
}

/* A key the server does not know must not complete a handshake. */
T_DECLARE_CASE(test_tls_psk_unknown_rejected)
{
	bool ok = true;
	char srv_label[TLS_PSK_LABEL_MAX + 1];
	char cli_label[TLS_PSK_LABEL_MAX + 1];
	T_CALL_SUBCASE(run_psk_handshake, psk_twos, &ok, srv_label, cli_label);
	T_EXPECT(!ok);
	/* The server authenticated nobody, so it reports no label. */
	T_EXPECT_STREQ(srv_label, "");
}

T_DECLARE_CASE(test_tls_peer_cert_uri_sans)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	struct identity_fixture f;
	T_CHECK(identity_fixture_setup(&f, tmpl));

	/* Only the three URI entries are reported, in certificate order: the DNS
	 * name is a different GeneralName CHOICE, and the foreign-scheme URI is
	 * still a URI name and so is returned (the scheme filter belongs to
	 * identity_matches_cert, not to extraction). */
	char **names = NULL;
	size_t count = 0;
	T_EXPECT(tls_peer_cert_uri_sans(f.cli_conn, &names, &count));
	T_EXPECT(count == 3);
	if (count == 3) {
		T_EXPECT(strcmp(names[0], "multiplexd:client-a") == 0);
		T_EXPECT(strcmp(names[1], "multiplexd:caf%C3%A9") == 0);
		T_EXPECT(strcmp(names[2], "https://example.com/other") == 0);
	}
	/* One allocation backs both the pointer array and the names. */
	free((void *)names);

	/* Defensive NULL handling, per the tls.h contract. */
	T_EXPECT(!tls_peer_cert_uri_sans(NULL, &names, &count));
	T_EXPECT(!tls_peer_cert_uri_sans(f.cli_conn, NULL, &count));
	T_EXPECT(!tls_peer_cert_uri_sans(f.cli_conn, &names, NULL));

	T_EXPECT(drive_shutdown(f.cli_conn, f.srv_conn, 10));
	identity_fixture_teardown(&f);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_tls_peer_cert_uri_sans_absent)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	const struct tls_config conf = { .cert = cert_path,
					 .key = key_path,
					 .authcerts = authcerts,
					 .authcerts_count = 1 };
	struct tls_context *const srv_ctx = tls_ctx_server(&conf);
	struct tls_context *const cli_ctx = tls_ctx_client(&conf);
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	int fds[2];
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	T_CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	T_CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
	struct tls_connection *const srv_conn = tls_server(srv_ctx, fds[0]);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, fds[1]);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake(srv_conn, cli_conn, 20));

	/* A certificate with no URI subjectAltName is not an error: it reports
	 * zero names and leaves nothing to free. */
	char **names = (char **)(uintptr_t)1;
	size_t count = 1;
	T_EXPECT(tls_peer_cert_uri_sans(cli_conn, &names, &count));
	T_EXPECT(names == NULL);
	T_EXPECT(count == 0);
	/* Nothing to match against, so no identity can be claimed. */
	T_EXPECT(!identity_matches_cert(cli_conn, "client-a"));

	T_EXPECT(drive_shutdown(cli_conn, srv_conn, 10));
	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	(void)close(fds[0]);
	(void)close(fds[1]);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_identity_matches_cert)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	struct identity_fixture f;
	T_CHECK(identity_fixture_setup(&f, tmpl));

	/* Plain identity, and one whose UTF-8 octets are percent-encoded in the
	 * certificate: both compare equal after decoding.  Both roles check the
	 * same certificate here. */
	T_EXPECT(identity_matches_cert(f.cli_conn, "client-a"));
	T_EXPECT(identity_matches_cert(f.cli_conn, "caf\xC3\xA9"));
	T_EXPECT(identity_matches_cert(f.srv_conn, "client-a"));

	T_EXPECT(drive_shutdown(f.cli_conn, f.srv_conn, 10));
	identity_fixture_teardown(&f);
	rm_tmpdir(tmpl);
}

T_DECLARE_CASE(test_identity_matches_cert_rejects)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	struct identity_fixture f;
	T_CHECK(identity_fixture_setup(&f, tmpl));

	/* A different identity, the still-encoded spelling, a bare prefix, the
	 * empty identity, and a name carried under another URI scheme must all
	 * fail. */
	T_EXPECT(!identity_matches_cert(f.cli_conn, "client-b"));
	T_EXPECT(!identity_matches_cert(f.cli_conn, "caf%C3%A9"));
	T_EXPECT(!identity_matches_cert(f.cli_conn, "client"));
	T_EXPECT(!identity_matches_cert(f.cli_conn, ""));
	T_EXPECT(!identity_matches_cert(
		f.cli_conn, "https://example.com/other"));
	/* The scheme is matched exactly: RFC 3986 spells it lower case in
	 * canonical form, and only that spelling is accepted.  Passing a whole
	 * URI as the identity must not match either. */
	T_EXPECT(!identity_matches_cert(f.cli_conn, "MULTIPLEXD:client-a"));
	T_EXPECT(!identity_matches_cert(f.cli_conn, "multiplexd:client-a"));

	T_EXPECT(drive_shutdown(f.cli_conn, f.srv_conn, 10));
	identity_fixture_teardown(&f);
	rm_tmpdir(tmpl);
}

/* Move all pending outgoing ciphertext from @p src into @p dst's inbound buffer
 * (the "wire" between two buffered connections). Returns false on OOM. */
static bool tls_pipe(struct tls_connection *src, struct tls_connection *dst)
{
	unsigned char buf[16384];
	for (;;) {
		const size_t n = tls_output(src, buf, sizeof(buf));
		if (n == 0) {
			return true;
		}
		if (!tls_input(dst, buf, n)) {
			return false;
		}
	}
}

/* tls_callback handler that counts invocations through an int *ctx. */
static void count_io_event(void *ctx)
{
	(*(int *)ctx)++;
}

/* Scan a single plaintext TLS ClientHello record for a server_name (SNI,
 * extension type 0) extension.  Returns 1 if present, 0 if absent, -1 on a
 * malformed or short buffer.  Only the one-record ClientHello a fresh handshake
 * emits is handled -- enough to assert the SNI extension's presence/absence. */
static int client_hello_has_sni(const unsigned char *restrict buf, size_t n)
{
	if (n < 5 || buf[0] != 0x16) { /* handshake record */
		return -1;
	}
	size_t off = 5;
	if (n - off < 4 || buf[off] != 0x01) { /* ClientHello */
		return -1;
	}
	off += 4; /* msg_type(1) + length(3) */
	if (n - off < 2 + 32 + 1) {
		return -1;
	}
	off += 2 + 32; /* legacy_version + random */
	const size_t sid_len = buf[off];
	off += 1;
	if (n - off < sid_len + 2) {
		return -1;
	}
	off += sid_len;
	const size_t cs_len = ((size_t)buf[off] << 8) | buf[off + 1];
	off += 2;
	if (n - off < cs_len + 1) {
		return -1;
	}
	off += cs_len;
	const size_t comp_len = buf[off];
	off += 1;
	if (n - off < comp_len + 2) {
		return -1;
	}
	off += comp_len;
	const size_t ext_total = ((size_t)buf[off] << 8) | buf[off + 1];
	off += 2;
	if (ext_total > n - off) {
		return -1;
	}
	const size_t ext_end = off + ext_total;
	while (off + 4 <= ext_end) {
		const size_t ext_type = ((size_t)buf[off] << 8) | buf[off + 1];
		const size_t ext_len =
			((size_t)buf[off + 2] << 8) | buf[off + 3];
		off += 4;
		if (ext_len > ext_end - off) {
			return -1;
		}
		if (ext_type == 0x0000) {
			return 1;
		}
		off += ext_len;
	}
	return 0;
}

/* Capture the ClientHello a fresh buffered client emits and report whether it
 * carries an SNI extension: 1 present, 0 absent, -1 on failure. */
static int client_hello_sni_state(const struct tls_config *restrict conf)
{
	struct tls_context *const ctx = tls_ctx_client(conf);
	if (ctx == NULL) {
		return -1;
	}
	struct tls_connection *const conn = tls_client(ctx, -1);
	int result = -1;
	if (conn != NULL) {
		(void)tls_handshake(conn);
		unsigned char buf[16384];
		const size_t n = tls_output(conn, buf, sizeof(buf));
		result = client_hello_has_sni(buf, n);
	}
	tls_conn_free(conn);
	tls_ctx_free(ctx);
	return result;
}

/* A client with no SNI configured must omit the server_name extension entirely,
 * not send a zero-length one (RFC 6066).  mbedtls_ssl_set_hostname("") emitted
 * an empty extension where NULL omits it; OpenSSL already omitted it, so this
 * backend-agnostic case also guards against a regression there. */
T_DECLARE_CASE(test_tls_client_hello_omits_empty_sni)
{
	char *authcerts[] = { test_cert_pem };
	const int without_sni = client_hello_sni_state(
		&(struct tls_config){ .cert = test_cert_pem,
				      .key = test_key_pem,
				      .authcerts = authcerts,
				      .authcerts_count = 1 });
	const int with_sni = client_hello_sni_state(
		&(struct tls_config){ .cert = test_cert_pem,
				      .key = test_key_pem,
				      .authcerts = authcerts,
				      .authcerts_count = 1,
				      .sni = "example.com" });
	T_EXPECT_EQ(without_sni, 0);
	T_EXPECT_EQ(with_sni, 1);
}

/* Drive the TLS handshake on two buffered connections by shuttling ciphertext
 * between them until both report success or a fatal error occurs. */
static bool drive_handshake_buf(
	struct tls_connection *srv, struct tls_connection *cli, int max_rounds)
{
	bool srv_done = false, cli_done = false;
	for (int i = 0; i < max_rounds; i++) {
		if (!cli_done) {
			const enum tls_error err = tls_handshake(cli);
			if (err == TLS_ERROR_NONE) {
				cli_done = true;
			} else if (
				err != TLS_ERROR_WANT_READ &&
				err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
		}
		if (!tls_pipe(cli, srv)) { /* client output -> server input */
			return false;
		}
		if (!srv_done) {
			const enum tls_error err = tls_handshake(srv);
			if (err == TLS_ERROR_NONE) {
				srv_done = true;
			} else if (
				err != TLS_ERROR_WANT_READ &&
				err != TLS_ERROR_WANT_WRITE) {
				return false;
			}
		}
		if (!tls_pipe(srv, cli)) { /* server output -> client input */
			return false;
		}
		if (cli_done && srv_done) {
			return true;
		}
	}
	return false;
}

T_DECLARE_CASE(test_tls_buf_handshake_and_io)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	/* fd=-1 selects memory-backed mode.  The client carries an on_send notifier
	 * so we can assert the library reported staged ciphertext. */
	int cli_send_events = 0;
	struct tls_connection *const srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, -1);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	tls_set_callback(
		cli_conn, &(struct tls_callback){ .ctx = &cli_send_events,
						  .on_send = count_io_event });
	T_CHECK(drive_handshake_buf(srv_conn, cli_conn, 20));

	/* Round-trip: client sends, server receives. */
	unsigned char send_buf[] = "hello";
	unsigned char recv_buf[sizeof(send_buf)] = { 0 };
	size_t send_len = sizeof(send_buf) - 1;
	cli_send_events = 0;
	T_EXPECT_EQ(tls_send(cli_conn, send_buf, &send_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(send_len, sizeof(send_buf) - 1);
	T_EXPECT(cli_send_events > 0);
	T_CHECK(tls_pipe(cli_conn, srv_conn));
	size_t recv_len = sizeof(recv_buf) - 1;
	T_EXPECT_EQ(tls_recv(srv_conn, recv_buf, &recv_len), TLS_ERROR_NONE);
	T_EXPECT_EQ(recv_len, sizeof(send_buf) - 1);
	T_EXPECT(memcmp(recv_buf, send_buf, recv_len) == 0);

	/* One-way shutdown: client sends close_notify; server observes it. */
	T_EXPECT_EQ(tls_shutdown(cli_conn), TLS_ERROR_NONE);
	T_CHECK(tls_pipe(cli_conn, srv_conn));
	recv_len = sizeof(recv_buf);
	T_EXPECT_EQ(
		tls_recv(srv_conn, recv_buf, &recv_len), TLS_ERROR_ZERO_RETURN);

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	rm_tmpdir(tmpl);
}

/* Regression: on_recv must stay set until all staged records are drained;
 * mbedTLS buffered path missed this because check_pending cannot see
 * conn->in. */
T_DECLARE_CASE(test_tls_buf_recv_drains_stacked_records)
{
	char tmpl[] = "/tmp/tls_test_XXXXXX";
	char cert_path[PATH_MAX + 2];
	char key_path[PATH_MAX + 2];
	char *const origdir = setup_cert_dir(
		tmpl, cert_path, sizeof(cert_path), key_path, sizeof(key_path));
	T_CHECK(origdir != NULL);
	free(origdir);

	char *authcerts[] = { cert_path };
	struct tls_context *const srv_ctx =
		tls_ctx_server(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	struct tls_context *const cli_ctx =
		tls_ctx_client(&(struct tls_config){ .cert = cert_path,
						     .key = key_path,
						     .authcerts = authcerts,
						     .authcerts_count = 1 });
	T_CHECK(srv_ctx != NULL);
	T_CHECK(cli_ctx != NULL);

	struct tls_connection *const srv_conn = tls_server(srv_ctx, -1);
	struct tls_connection *const cli_conn = tls_client(cli_ctx, -1);
	T_CHECK(srv_conn != NULL);
	T_CHECK(cli_conn != NULL);
	T_CHECK(drive_handshake_buf(srv_conn, cli_conn, 20));

	/* Spans several TLS records (max ~16 KiB plaintext each), with a position-
	 * dependent pattern so a dropped or reordered record is caught. */
	static unsigned char payload[40000];
	for (size_t i = 0; i < sizeof(payload); i++) {
		payload[i] = (unsigned char)(i ^ (i >> 8));
	}

	/* Encrypt the whole payload into the client's staging buffer before moving
	 * any ciphertext, so it lands in the server as one burst.  tls_send writes at
	 * most one record per call, so loop until all plaintext is accepted. */
	for (size_t off = 0; off < sizeof(payload);) {
		size_t n = sizeof(payload) - off;
		T_CHECK(tls_send(cli_conn, payload + off, &n) ==
			TLS_ERROR_NONE);
		T_CHECK(n > 0);
		off += n;
	}

	/* The single shuttle is the "one socket_recv": every record's ciphertext is
	 * now staged in the server's conn->in at once. */
	int srv_recv_events = 0;
	tls_set_callback(
		srv_conn, &(struct tls_callback){ .ctx = &srv_recv_events,
						  .on_recv = count_io_event });
	T_CHECK(tls_pipe(cli_conn, srv_conn));

	/* Drain exactly as session_on_recv does: one recv, then keep going while the
	 * notifier reports more is readable without feeding further ciphertext. */
	static unsigned char out[sizeof(payload)];
	size_t got = 0;
	int recv_calls = 0;
	for (;;) {
		const int before = srv_recv_events;
		size_t n = sizeof(out) -
			   got; /* >= one record while data remains */
		T_CHECK(tls_recv(srv_conn, out + got, &n) == TLS_ERROR_NONE);
		got += n;
		recv_calls++;
		const bool readable = (srv_recv_events > before);
		if (recv_calls == 1) {
			/* The decisive assertion: with records still staged behind the
			 * first, on_recv must fire.  Pre-fix mbedTLS left this false. */
			T_EXPECT(readable);
		}
		if (!readable) {
			break;
		}
	}

	/* Everything decrypted from the one burst (no second socket read), in order,
	 * and it genuinely took multiple records (otherwise the test is vacuous). */
	T_EXPECT_EQ(got, sizeof(payload));
	T_EXPECT(recv_calls >= 2);
	T_EXPECT(memcmp(out, payload, sizeof(payload)) == 0);

	tls_conn_free(cli_conn);
	tls_conn_free(srv_conn);
	tls_ctx_free(cli_ctx);
	tls_ctx_free(srv_ctx);
	rm_tmpdir(tmpl);
}

/* ---- throughput benchmark: plain TCP baseline ---- */

/* Loopback TCP socket pair for throughput benches (real kernel TCP, not AF_UNIX).
 * Returns two blocking fds with TCP_NODELAY (out[0]=accepted, out[1]=connected),
 * or false on failure. */
static bool bench_loopback_pair(int out[2])
{
	out[0] = out[1] = -1;
	const int lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		return false;
	}
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	socklen_t salen = sizeof(sa);
	if (bind(lfd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(lfd, 1) != 0 ||
	    getsockname(lfd, (struct sockaddr *)&sa, &salen) != 0) {
		(void)close(lfd);
		return false;
	}
	const int cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		(void)close(lfd);
		return false;
	}
	const int one = 1;
	(void)setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (connect(cfd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		(void)close(cfd);
		(void)close(lfd);
		return false;
	}
	const int afd = accept(lfd, NULL, NULL);
	(void)close(lfd);
	if (afd < 0) {
		(void)close(cfd);
		return false;
	}
	(void)setsockopt(afd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	out[0] = afd;
	out[1] = cfd;
	return true;
}

static int tcp_bench_fds[2] = { -1, -1 };

static void tcp_bench_teardown(void)
{
	if (tcp_bench_fds[0] >= 0) {
		(void)close(tcp_bench_fds[0]);
		(void)close(tcp_bench_fds[1]);
		tcp_bench_fds[0] = -1;
		tcp_bench_fds[1] = -1;
	}
}

static bool tcp_bench_setup(void)
{
	return bench_loopback_pair(tcp_bench_fds);
}

/* Per-op payload for the throughput benches: 16 KiB, the TLS 1.3 maximum
 * record plaintext size. */
enum { BENCH_BUFSIZE = 16384 };

T_DECLARE_BENCH(bench_tcp_throughput)
{
	/* One-time setup: the loopback pair persists across calibration rounds and
	 * is reclaimed at process exit. */
	static bool ready = false;
	if (!ready) {
		T_CHECK(tcp_bench_setup());
		T_CHECK(atexit(tcp_bench_teardown) == 0);
		ready = true;
	}
	T_BENCH_SET_BYTES(BENCH_BUFSIZE);

	unsigned char send_buf[BENCH_BUFSIZE];
	unsigned char recv_buf[BENCH_BUFSIZE];
	memset(send_buf, 0xA5, sizeof(send_buf));

	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		/* TCP is a byte stream: a blocking send queues all bytes, but a
		 * single recv may return fewer than requested, so drain in a loop. */
		for (size_t off = 0; off < sizeof(send_buf);) {
			const ssize_t w =
				send(tcp_bench_fds[1], send_buf + off,
				     sizeof(send_buf) - off, 0);
			T_CHECK(w > 0);
			off += (size_t)w;
		}
		for (size_t off = 0; off < sizeof(recv_buf);) {
			const ssize_t r =
				recv(tcp_bench_fds[0], recv_buf + off,
				     sizeof(recv_buf) - off, 0);
			T_CHECK(r > 0);
			off += (size_t)r;
		}
	}
}

/* Throughput benchmark: RSA 4096, production-matching TLS config.  Reuses the
 * shared in-memory test_cert_pem/test_key_pem (no gencerts dependency, works on
 * every backend), with the same self-signed cert as the authorized peer. */
static struct tls_connection *bench_srv_conn;
static struct tls_connection *bench_cli_conn;
static struct tls_context *bench_srv_ctx;
static struct tls_context *bench_cli_ctx;
static int bench_fds[2] = { -1, -1 };

static void bench_teardown(void)
{
	if (bench_cli_conn != NULL && bench_srv_conn != NULL) {
		(void)drive_shutdown(bench_cli_conn, bench_srv_conn, 20);
	}
	tls_conn_free(bench_cli_conn);
	bench_cli_conn = NULL;
	tls_conn_free(bench_srv_conn);
	bench_srv_conn = NULL;
	tls_ctx_free(bench_cli_ctx);
	bench_cli_ctx = NULL;
	tls_ctx_free(bench_srv_ctx);
	bench_srv_ctx = NULL;
	if (bench_fds[0] >= 0) {
		(void)close(bench_fds[0]);
		(void)close(bench_fds[1]);
		bench_fds[0] = -1;
		bench_fds[1] = -1;
	}
}

static bool bench_setup(void)
{
	char *authcerts[] = { test_cert_pem };
	const struct tls_config tls_conf = {
		.cert = test_cert_pem,
		.key = test_key_pem,
		.authcerts = authcerts,
		.authcerts_count = 1,
	/* Pin AES-128-GCM so the bench measures a single, fixed cipher.  The
	 * two backends spell the TLS 1.3 suite differently. */
#if WITH_OPENSSL
		.ciphersuites = "TLS_AES_128_GCM_SHA256",
#else
		.ciphersuites = "TLS1-3-AES-128-GCM-SHA256",
#endif
		/* Enable library read-ahead so the bench measures the high-throughput
		 * path (one socket read can buffer several records). */
		.readahead = true,
	};

	bench_srv_ctx = tls_ctx_server(&tls_conf);
	bench_cli_ctx = tls_ctx_client(&tls_conf);
	if (bench_srv_ctx == NULL || bench_cli_ctx == NULL) {
		goto fail;
	}

	if (!bench_loopback_pair(bench_fds)) {
		goto fail;
	}
	if (fcntl(bench_fds[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(bench_fds[1], F_SETFL, O_NONBLOCK) != 0) {
		goto fail;
	}

	bench_srv_conn = tls_server(bench_srv_ctx, bench_fds[0]);
	bench_cli_conn = tls_client(bench_cli_ctx, bench_fds[1]);
	if (bench_srv_conn == NULL || bench_cli_conn == NULL) {
		goto fail;
	}
	if (!drive_handshake(bench_srv_conn, bench_cli_conn, 50)) {
		goto fail;
	}

	return true;

fail:
	bench_teardown();
	return false;
}

T_DECLARE_BENCH(bench_tls_throughput)
{
	/* One-time setup: the TLS session (handshake done once) persists across
	 * calibration rounds and is torn down at process exit. */
	static bool ready = false;
	if (!ready) {
		(void)fprintf(stderr, "--- TLS library: %s\n", tls_version());
		(void)fflush(stderr);
		T_CHECK(bench_setup());
		T_CHECK(atexit(bench_teardown) == 0);
		ready = true;
	}
	T_BENCH_SET_BYTES(BENCH_BUFSIZE);

	unsigned char send_buf[BENCH_BUFSIZE];
	unsigned char recv_buf[BENCH_BUFSIZE];
	memset(send_buf, 0xA5, sizeof(send_buf));

	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		/* tls_send does partial writes and tls_recv returns at most one
		 * record per call (and a backend may split the payload across
		 * several records), so drain the whole payload each way. */
		for (size_t off = 0; off < sizeof(send_buf);) {
			size_t n = sizeof(send_buf) - off;
			T_CHECK(tls_send(bench_cli_conn, send_buf + off, &n) ==
				TLS_ERROR_NONE);
			off += n;
		}
		for (size_t off = 0; off < sizeof(recv_buf);) {
			size_t n = sizeof(recv_buf) - off;
			T_CHECK(tls_recv(bench_srv_conn, recv_buf + off, &n) ==
				TLS_ERROR_NONE);
			off += n;
		}
	}
}

static const struct testing_suite suite[] = {
	T_CASE(test_tls_ctx_server_null_cert_fails),
	T_CASE(test_tls_ctx_bad_cert_fails),
	T_CASE(test_tls_ctx_mismatched_key_fails),
	T_CASE(test_tls_ctx_server_created),
	T_CASE(test_tls_ctx_client_created),
	T_CASE(test_tls_load_key_empty_fails),
	T_CASE(test_tls_load_key_rejects_encrypted_key),
	T_CASE(test_tls_load_cert_missing_file_fails),
	T_CASE(test_tls_load_authcerts_rejects_invalid_entries),
	T_CASE(test_tls_load_authcerts_rejects_corrupted_chain),
	T_CASE(test_tls_ctx_invalid_ciphersuites_fail),
	T_CASE(test_tls_ctx_empty_ciphersuites_fails),
#if !WITH_OPENSSL
	T_CASE(test_tls_ctx_tls12_only_ciphersuite_fails),
#endif
	T_CASE(test_tls_server_and_client_validate_inputs),
	T_CASE(test_tls_load_cert_from_memory_succeeds),
	T_CASE(test_tls_load_key_from_memory_succeeds),
	T_CASE(test_tls_full_handshake_and_io),
	T_CASE(test_tls_ctx_ref_shares_credentials_after_original_freed),
	T_CASE(test_tls_handshake_syscall_on_closed_peer),
	T_CASE(test_tls_sni_mismatch_still_succeeds),
	T_CASE(test_tls_client_hello_omits_empty_sni),
	T_CASE(test_tls_ca_signed_chain_accepted),
	T_CASE(test_tls_expired_cert_rejected),
	T_CASE(test_tls_weak_rsa_cert_rejected),
	T_CASE(test_tls_weak_digest_cert_rejected),
	T_CASE(test_tls_shutdown_oneway),
	T_CASE(test_tls_shutdown_syscall_on_broken_transport),
	T_CASE(test_tls_recv_syscall_on_abrupt_peer_close),
	T_CASE(test_tls_alpn_negotiation),
	T_CASE(test_tls_alpn_quoted_entry_at_list_end),
	T_CASE(test_tls_alpn_malformed_list_fails_ctx),
#if WITH_OPENSSL
	T_CASE(test_tls_ctx_ref_refuses_alpn_server),
	T_CASE(test_tls_alpn_survives_ctx_free_mid_handshake),
#endif
	T_CASE(test_tls_peer_cert_der_after_handshake),
	T_CASE(test_tls_psk_label),
	T_CASE(test_tls_psk_handshake),
	T_CASE(test_tls_psk_unknown_rejected),
	T_CASE(test_tls_peer_cert_uri_sans),
	T_CASE(test_tls_peer_cert_uri_sans_absent),
	T_CASE(test_identity_matches_cert),
	T_CASE(test_identity_matches_cert_rejects),
	T_CASE(test_tls_buf_handshake_and_io),
	T_CASE(test_tls_buf_recv_drains_stacked_records),
	/* Opt-in throughput benchmarks (16 KiB/op, AES-128-GCM); skipped by the
	 * default run.  Select with `--bench <ere>` or TESTING_BENCH. */
	T_BENCH(bench_tcp_throughput),
	T_BENCH(bench_tls_throughput),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* A peer closed before the handshake starts (used to force a genuine
	 * SSL_ERROR_SYSCALL) raises SIGPIPE by default; the test process must
	 * survive it. */
	T_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	return testing_main(argc, argv, suite);
}

#else /* !WITH_TLS */

#include <stdlib.h>

int main(void)
{
	return EXIT_SUCCESS;
}

#endif /* WITH_TLS */
