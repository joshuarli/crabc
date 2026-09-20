#!/usr/bin/env python3
"""Prepare the one lifetime-safe os-test AIO fixture from frozen bytes.

The byte literal below is `basic/aio/aio_suspend.c` from os-test revision
`5e9456d510612f83b6ec8b1a0c06d6b1303a2512` (tree
`68fd4eef88d0e52b55c7cc2a73659b1e439d33fe`).  It is reproduced under the
upstream ISC license:

Copyright 2017 Jonas 'Sortie' Termansen and contributors.

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Keeping the exact source beside the preparation rule makes the one admitted
upstream input and its small derivative reviewable without trusting a mutable
checkout.

The upstream test returns after one `aio_suspend` wake and reaps only controls
already terminal at that instant.  POSIX permits another listed request to
remain live.  The prepared derivative preserves that original one-completion
assertion, then drains every submitted request before `fclose` or stack
storage can expire.  Its cleanup path has the same lifetime boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_PATH = "basic/aio/aio_suspend.c"
SCHEMA = "crabc.x86_64-owned-os-test-aio-suspend-source/v1"
ORIGINAL_SHA256 = "3ff7bf5dc07a92d3c8fe0394d581ccc9c34dbbad10737953be6d7e595904f51d"

FROZEN_SOURCE = b'''/* Test whether a basic aio_suspend invocation works. */

#include <aio.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "../basic.h"

int main(void)
{
	FILE* fp = tmpfile();
	if ( !fp )
		err(1, "tmpfile");
	int fd = fileno(fp);
	char buffer[6] = {'F', 'O', 'O', 'B', 'A', 'R'};
	struct aiocb aio1 =
	{
		.aio_fildes = fd,
		.aio_offset = 0,
		.aio_buf = buffer,
		.aio_nbytes = sizeof(buffer),
		.aio_sigevent = { .sigev_notify = SIGEV_NONE },
	};
	if ( aio_write(&aio1) < 0 )
		err(1, "first aio_write");
	struct aiocb aio2 =
	{
		.aio_fildes = fd,
		.aio_offset = 6,
		.aio_buf = buffer,
		.aio_nbytes = sizeof(buffer),
		.aio_sigevent = { .sigev_notify = SIGEV_NONE },
	};
	if ( aio_write(&aio2) < 0 )
		err(1, "second aio_write");
	const struct aiocb* const aiop[2] = { &aio1, &aio2 };
	if ( aio_suspend(aiop, 2, NULL) < 0 )
		err(1, "aio_suspend");
	int done = 0;
	for ( int i = 0; i < 2; i++ )
	{
		if ( (errno = aio_error((struct aiocb*) aiop[i])) )
		{
			if ( errno == EINPROGRESS )
				continue;
			err(1, "aio_error");
		}
		ssize_t ret = aio_return((struct aiocb*) aiop[i]);
		if ( ret < 0 )
			errx(1, "aio_return() != < 0");
		if ( ret != sizeof(buffer) )
			errx(1, "aio_return() != sizeof(buffer)");
		done++;
	}
	if ( !done )
		errx(1, "no async io had completed");
	return 0;
}
'''

# The focused native replay compiles the prepared C source with the unchanged
# upstream local headers it includes.  These literals are source inputs, not
# replacements: their fixed hashes make that small standalone fixture runnable
# without accepting a mutable os-test checkout.
FROZEN_LICENSE = b'''Copyright 2017 Jonas 'Sortie' Termansen and contributors.

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

FROZEN_BASIC_HEADER = b'''#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Fix math_errhandling missing on Minix. Use INFINITY to detect math.h.
#if defined(__minix__) && defined(INFINITY)
#ifndef MATH_ERRNO
#define MATH_ERRNO (1 << 0)
#define MATH_ERREXCEPT (1 << 1)
#define math_errhandling MATH_ERREXCEPT
#endif
#endif

// Fix CMPLX macros missing on some systems. Use complex to detect complex.h.
#ifdef complex

// Minix is shipping clang 3.6 which doesn't support __builtin_complex,
// introduced in clang 19.1.0
#if (defined(__GNUC__) && !defined(__clang__)) || (defined(__clang_major__) && 19 < __clang_major__) || defined(__open_xl__) || __has_builtin(__builtin_complex)

#ifndef CMPLXF
#define CMPLXF(x, y) (__builtin_complex((float)(x), (float)(y)))
#endif
#ifndef CMPLX
#define CMPLX(x, y) (__builtin_complex((double)(x), (double)(y)))
#endif
#ifndef CMPLXL
#define CMPLXL(x, y) (__builtin_complex((long double)(x), (long double)(y)))
#endif

#else

#ifndef CMPLXF
union float_complex { float complex c; float parts[2]; };
float complex CMPLXF(float real, float imag)
{
	union float_complex u = { .parts = { real, imag } };
	return u.c;
}
#endif
#ifndef CMPLX
union double_complex { double complex c; double parts[2]; };
double complex CMPLX(double real, double imag)
{
	union double_complex u = { .parts = { real, imag } };
	return u.c;
}
#endif
#ifndef CMPLXL
union long_double_complex { long double complex c; long double parts[2]; };
long double complex CMPLXL(long double real, long double imag)
{
	union long_double_complex u = { .parts = { real, imag } };
	return u.c;
}
#endif

#endif

#endif

#include "../misc/errors.h"
'''

FROZEN_ERRORS_HEADER = b'''const char* strerrno(int errnum)
{
	switch ( errnum )
	{
	case 0: return "errno == 0";
	case E2BIG: return "E2BIG";
	case EACCES: return "EACCES";
	case EADDRINUSE: return "EADDRINUSE";
	case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
	case EAFNOSUPPORT: return "EAFNOSUPPORT";
#if EWOULDBLOCK != EAGAIN
	case EAGAIN: return "EAGAIN";
#endif
	case EALREADY: return "EALREADY";
	case EBADF: return "EBADF";
	case EBADMSG: return "EBADMSG";
	case EBUSY: return "EBUSY";
	case ECANCELED: return "ECANCELED";
	case ECHILD: return "ECHILD";
	case ECONNABORTED: return "ECONNABORTED";
	case ECONNREFUSED: return "ECONNREFUSED";
	case ECONNRESET: return "ECONNRESET";
	case EDEADLK: return "EDEADLK";
	case EDESTADDRREQ: return "EDESTADDRREQ";
	case EDOM: return "EDOM";
	case EDQUOT: return "EDQUOT";
	case EEXIST: return "EEXIST";
	case EFAULT: return "EFAULT";
	case EFBIG: return "EFBIG";
	case EHOSTUNREACH: return "EHOSTUNREACH";
	case EIDRM: return "EIDRM";
	case EILSEQ: return "EILSEQ";
	case EINPROGRESS: return "EINPROGRESS";
	case EINTR: return "EINTR";
	case EINVAL: return "EINVAL";
	case EIO: return "EIO";
	case EISCONN: return "EISCONN";
	case EISDIR: return "EISDIR";
	case ELOOP: return "ELOOP";
	case EMFILE: return "EMFILE";
	case EMLINK: return "EMLINK";
	case EMSGSIZE: return "EMSGSIZE";
#ifdef EMULTIHOP
	case EMULTIHOP: return "EMULTIHOP";
#endif
	case ENAMETOOLONG: return "ENAMETOOLONG";
	case ENETDOWN: return "ENETDOWN";
	case ENETRESET: return "ENETRESET";
	case ENETUNREACH: return "ENETUNREACH";
	case ENFILE: return "ENFILE";
	case ENOBUFS: return "ENOBUFS";
	case ENODEV: return "ENODEV";
	case ENOENT: return "ENOENT";
	case ENOEXEC: return "ENOEXEC";
	case ENOLCK: return "ENOLCK";
#ifdef ENOLINK
	case ENOLINK: return "ENOLINK";
#endif
	case ENOMEM: return "ENOMEM";
	case ENOMSG: return "ENOMSG";
	case ENOPROTOOPT: return "ENOPROTOOPT";
	case ENOSPC: return "ENOSPC";
	case ENOSYS: return "ENOSYS";
	case ENOTCONN: return "ENOTCONN";
	case ENOTDIR: return "ENOTDIR";
#if ENOTEMPTY != EEXIST
	case ENOTEMPTY: return "ENOTEMPTY";
#endif
#ifdef ENOTRECOVERABLE
	case ENOTRECOVERABLE: return "ENOTRECOVERABLE";
#endif
	case ENOTSOCK: return "ENOTSOCK";
	case ENOTSUP: return "ENOTSUP";
	case ENOTTY: return "ENOTTY";
	case ENXIO: return "ENXIO";
#if EOPNOTSUPP != ENOTSUP
	case EOPNOTSUPP: return "ENOTSUP";
#endif
	case EOVERFLOW: return "EOVERFLOW";
#ifdef EOWNERDEAD
	case EOWNERDEAD: return "EOWNERDEAD";
#endif
	case EPERM: return "EPERM";
#ifdef EPFNOSUPPORT
	case EPFNOSUPPORT: return "EPFNOSUPPORT";
#endif
	case EPIPE: return "EPIPE";
	case EPROTO: return "EPROTO";
	case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
	case EPROTOTYPE: return "EPROTOTYPE";
	case ERANGE: return "ERANGE";
	case EROFS: return "EROFS";
#ifdef ESOCKTNOSUPPORT
	case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
#endif
	case ESPIPE: return "ESPIPE";
	case ESRCH: return "ESRCH";
	case ESTALE: return "ESTALE";
	case ETIMEDOUT: return "ETIMEDOUT";
	case ETXTBSY: return "ETXTBSY";
	case EWOULDBLOCK: return "EWOULDBLOCK";
	case EXDEV: return "EXDEV";

	default: return strerror(errnum);
	}
}

__attribute__((unused))
static void test_vwarnc(int errnum, const char* fmt, va_list ap)
{
	if ( fmt )
	{
		vfprintf(stderr, fmt, ap);
		fputs(": ", stderr);
	}
	fprintf(stderr, "%s\\n", strerrno(errnum));
}

__attribute__((unused))
static void test_vwarn(const char* fmt, va_list ap)
{
	test_vwarnc(errno, fmt, ap);
}

__attribute__((unused))
static void test_warn(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	test_vwarn(fmt, ap);
	va_end(ap);
}

__attribute__((unused))
static void test_vwarnx(const char* fmt, va_list ap)
{
	if ( fmt )
		vfprintf(stderr, fmt, ap);
	fputc('\\n', stderr);
}

__attribute__((unused))
static void test_warnx(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	test_vwarnx(fmt, ap);
	va_end(ap);
}

__attribute__((unused))
static void test_verr(int exitcode, const char* fmt, va_list ap)
{
	test_vwarn(fmt, ap);
	exit(exitcode);
}

__attribute__((unused))
static void test_err(int exitcode, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	test_verr(exitcode, fmt, ap);
	va_end(ap);
}

__attribute__((unused))
static void test_verrx(int exitcode, const char* fmt, va_list ap)
{
	test_vwarnx(fmt, ap);
	exit(exitcode);
}

__attribute__((unused))
static void test_errx(int exitcode, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	test_verrx(exitcode, fmt, ap);
	va_end(ap);
}

#define err test_err
#define errc test_errc
#define errx test_errx
#define verr test_err
#define verrc test_errc
#define verrx test_errx
#define warn test_warn
#define warnc test_warnc
#define warnx test_warnx
#define vwarn test_warn
#define vwarnc test_warnc
#define vwarnx test_warnx
'''

FROZEN_BASIC_COMPILE_SCRIPT = rb'''#!/usr/bin/env sh
set -e

COMPILE=$1
FILE=$2
LDFLAGS=$3
EXTRA_LDFLAGS=$4
OS=$5
OUT_PATH=$6

COMPILE="$COMPILE -Wall -Wextra -Werror=implicit-function-declaration"

mkdir -p -- "$(dirname "$OUT_PATH/$FILE")"
rm -f "$FILE" "$OUT_PATH/$FILE.o" "$OUT_PATH/$FILE.err" "$OUT_PATH/$FILE.out"
echo "$COMPILE $FILE.c -o $FILE -D_GNU_SOURCE -D_BSD_SOURCE -D_ALL_SOURCE -D_DEFAULT_SOURCE $LDFLAGS $EXTRA_LDFLAGS" > "$OUT_PATH/$FILE.err"
if ! $COMPILE -c "$FILE.c" -o "$OUT_PATH/$FILE.o" -D_GNU_SOURCE -D_BSD_SOURCE -D_ALL_SOURCE -D_DEFAULT_SOURCE 2>> "$OUT_PATH/$FILE.err" 1>&2; then
  rm -f "$OUT_PATH/$FILE.o"
  if grep -Eq '^/\*optional\*/$' "$FILE.c"; then
    outcome=missing_optional
  elif grep -E 'error:' "$OUT_PATH/$FILE.err" | grep -Ev 'type specifier missing,' | head -n 1 | grep -E 'fatal error' > /dev/null; then
    outcome=missing_header
  elif grep -E 'error:' "$OUT_PATH/$FILE.err" | grep -Ev 'type specifier missing,' | head -n 1 | grep -E 'incompatible|pointer-sign' > /dev/null; then
    outcome=incompatible
  elif grep -E 'error:' "$OUT_PATH/$FILE.err" | grep -Ev 'type specifier missing,' | head -n 1 | grep -E 'undeclared|no member named|is not defined' > /dev/null; then
    outcome=undeclared
  elif grep -E 'error:' "$OUT_PATH/$FILE.err" | grep -Ev 'type specifier missing,' | head -n 1 | grep -E 'unknown type name|Wvisibility|expected declaration specifiers|function cannot return function type|storage size of|declared inside parameter list|tentative definition has type|expected identifier|a parameter list without types|parameter names \(without types\) in function declaration' > /dev/null; then
    outcome=unknown_type
   else
    outcome=compile_error
  fi
  echo "echo $outcome" > "$FILE"
  chmod +x "$FILE"
  echo "$outcome" > "$OUT_PATH/$FILE.out"
  exit 0
fi
if ! $COMPILE "$OUT_PATH/$FILE.o" -o "$FILE" $LDFLAGS $EXTRA_LDFLAGS 2>> "$OUT_PATH/$FILE.err" 1>&2; then
  rm -f "$OUT_PATH/$FILE.o" "$FILE"
  outcome=undefined
  echo "echo $outcome" > "$FILE"
  chmod +x "$FILE"
  echo "$outcome" > "$OUT_PATH/$FILE.out"
  exit 0
fi
rm -f "$OUT_PATH/$FILE.o" "$OUT_PATH/$FILE.err" "$OUT_PATH/$FILE.out"
'''

SUPPORT_FILES = {
    "LICENSE": FROZEN_LICENSE,
    "basic/basic.h": FROZEN_BASIC_HEADER,
    "misc/errors.h": FROZEN_ERRORS_HEADER,
    "misc/compile.sh": FROZEN_BASIC_COMPILE_SCRIPT,
}
SUPPORT_SHA256 = {
    "LICENSE": "8e9e382f154fcd590f51b007df9fae08a39879452083a91f198ef93c86206658",
    "basic/basic.h": "dcb827c06edc8800175904d5bd73b2e3cd09173ea0e6074a3798bb8df52c3b33",
    "misc/errors.h": "e6bd4c01d3d899f0bb13ecf2dc35090a093ccbe3ba57b30ba983125683487d01",
    "misc/compile.sh": "b1a00d20865612b0b5b0a88b4cea52ccd51ee785333c4a9aa5223e539608d85b",
}

# `basic` invokes this frozen script for ordinary C cases. Its warning and
# feature profile are part of the source contract for the focused replay,
# rather than ambient compiler defaults.
BASIC_COMPILE_FLAGS = (
    "-Wall", "-Wextra", "-Werror=implicit-function-declaration",
    "-D_GNU_SOURCE", "-D_BSD_SOURCE", "-D_ALL_SOURCE", "-D_DEFAULT_SOURCE",
)


MAIN_START = b"int main(void)\n"

PREPARED_MAIN = b'''static int wait_for_terminal(struct aiocb* control)
{
	const struct aiocb* const one[1] = { control };
	while ( aio_error(control) == EINPROGRESS )
	{
		if ( aio_suspend(one, 1, NULL) < 0 && errno != EINTR )
			return -1;
	}
	return 0;
}

/* Every submitted control, buffer, and descriptor remains valid until this
 * cleanup has observed a terminal status and consumed aio_return(). */
static void reap_pending(FILE* fp, const struct aiocb* const aiop[2],
	const int submitted[2], int returned[2])
{
	for ( int i = 0; i < 2; i++ )
	{
		struct aiocb* control = (struct aiocb*) aiop[i];
		if ( !submitted[i] || returned[i] )
			continue;
		while ( aio_error(control) == EINPROGRESS )
		{
			const struct aiocb* const one[1] = { control };
			(void) aio_cancel(fileno(fp), control);
			(void) aio_suspend(one, 1, NULL);
		}
		(void) aio_return(control);
		returned[i] = 1;
	}
}

int main(void)
{
	FILE* fp = tmpfile();
	if ( !fp )
		err(1, "tmpfile");
	int fd = fileno(fp);
	char buffer[6] = {'F', 'O', 'O', 'B', 'A', 'R'};
	struct aiocb aio1 =
	{
		.aio_fildes = fd,
		.aio_offset = 0,
		.aio_buf = buffer,
		.aio_nbytes = sizeof(buffer),
		.aio_sigevent = { .sigev_notify = SIGEV_NONE },
	};
	struct aiocb aio2 =
	{
		.aio_fildes = fd,
		.aio_offset = 6,
		.aio_buf = buffer,
		.aio_nbytes = sizeof(buffer),
		.aio_sigevent = { .sigev_notify = SIGEV_NONE },
	};
	const struct aiocb* const aiop[2] = { &aio1, &aio2 };
	int submitted[2] = { 0, 0 };
	int returned[2] = { 0, 0 };
	int failure = 0;
	int saved_errno = 0;
	const char* failure_text = NULL;

	if ( aio_write(&aio1) < 0 )
	{
		failure = 1;
		saved_errno = errno;
		failure_text = "first aio_write";
		goto cleanup;
	}
	submitted[0] = 1;
	if ( aio_write(&aio2) < 0 )
	{
		failure = 1;
		saved_errno = errno;
		failure_text = "second aio_write";
		goto cleanup;
	}
	submitted[1] = 1;
	/* Preserve the upstream assertion: one successful return must make at
	 * least one listed request observable as terminal. */
	if ( aio_suspend(aiop, 2, NULL) < 0 )
	{
		failure = 1;
		saved_errno = errno;
		failure_text = "aio_suspend";
		goto cleanup;
	}
	int done = 0;
	for ( int i = 0; i < 2; i++ )
	{
		int error = aio_error((struct aiocb*) aiop[i]);
		if ( error )
		{
			if ( error == EINPROGRESS )
				continue;
			failure = 1;
			saved_errno = error;
			failure_text = "aio_error";
			goto cleanup;
		}
		ssize_t ret = aio_return((struct aiocb*) aiop[i]);
		returned[i] = 1;
		if ( ret < 0 )
		{
			failure = 1;
			saved_errno = errno;
			failure_text = "aio_return";
			goto cleanup;
		}
		if ( ret != sizeof(buffer) )
		{
			failure = 2;
			failure_text = "aio_return() != sizeof(buffer)";
			goto cleanup;
		}
		done++;
	}
	if ( !done )
	{
		failure = 2;
		failure_text = "no async io had completed";
		goto cleanup;
	}
	for ( int i = 0; i < 2; i++ )
	{
		struct aiocb* control = (struct aiocb*) aiop[i];
		if ( returned[i] )
			continue;
		if ( wait_for_terminal(control) < 0 )
		{
			failure = 1;
			saved_errno = errno;
			failure_text = "aio_suspend";
			goto cleanup;
		}
		int error = aio_error(control);
		if ( error )
		{
			failure = 1;
			saved_errno = error;
			failure_text = "aio_error";
			goto cleanup;
		}
		ssize_t ret = aio_return(control);
		returned[i] = 1;
		if ( ret < 0 )
		{
			failure = 1;
			saved_errno = errno;
			failure_text = "aio_return";
			goto cleanup;
		}
		if ( ret != sizeof(buffer) )
		{
			failure = 2;
			failure_text = "aio_return() != sizeof(buffer)";
			goto cleanup;
		}
	}

cleanup:
	reap_pending(fp, aiop, submitted, returned);
	if ( fclose(fp) < 0 && !failure )
	{
		failure = 1;
		saved_errno = errno;
		failure_text = "fclose";
	}
	if ( failure == 1 )
	{
		errno = saved_errno;
		err(1, "%s", failure_text);
	}
	if ( failure == 2 )
		errx(1, "%s", failure_text);
	return 0;
}
'''

PREPARED_SHA256 = "80908d67d2cc9da4913aa093a5297cdee5cff8709a170c44c1be0786d421628d"


class SourcePreparationError(ValueError):
    """The frozen source or its sole lifetime repair differs from the contract."""


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def prepare(original: bytes) -> tuple[bytes, list[dict[str, object]]]:
    """Return the exact lifetime-safe derivative, refusing all source drift."""
    if sha256(original) != ORIGINAL_SHA256:
        raise SourcePreparationError("frozen os-test aio_suspend SHA-256 differs")
    if original != FROZEN_SOURCE:
        raise SourcePreparationError("frozen os-test aio_suspend bytes differ")
    if original.count(MAIN_START) != 1:
        raise SourcePreparationError("frozen os-test aio_suspend main occurrence differs")
    prefix, _ = original.split(MAIN_START, 1)
    prepared = prefix + PREPARED_MAIN
    if sha256(prepared) != PREPARED_SHA256:
        raise SourcePreparationError("prepared os-test aio_suspend SHA-256 differs")
    replacement = {
        "source_function": "main",
        "original_line": original[:len(prefix)].count(b"\n") + 1,
        "original_sha256": sha256(original[len(prefix):]),
        "prepared_sha256": sha256(PREPARED_MAIN),
    }
    return prepared, [replacement]


def preparation_record(original: bytes) -> dict[str, object]:
    """Describe one verified C-source preparation without a checkout path."""
    prepared, replacements = prepare(original)
    return {
        "schema": SCHEMA,
        "fixture": SOURCE_PATH,
        "source_sha256": ORIGINAL_SHA256,
        "prepared_sha256": sha256(prepared),
        "replacements": replacements,
    }


def prepared_fixture_files() -> dict[str, bytes]:
    """Return the exact standalone source tree used by the focused replay."""
    prepared, _ = prepare(FROZEN_SOURCE)
    for relative, expected in SUPPORT_SHA256.items():
        if sha256(SUPPORT_FILES[relative]) != expected:
            raise SourcePreparationError(f"frozen os-test support file differs: {relative}")
    warning_flags = b" ".join(flag.encode("ascii") for flag in BASIC_COMPILE_FLAGS[:3])
    feature_flags = b" ".join(flag.encode("ascii") for flag in BASIC_COMPILE_FLAGS[3:])
    if warning_flags not in FROZEN_BASIC_COMPILE_SCRIPT or feature_flags not in FROZEN_BASIC_COMPILE_SCRIPT:
        raise SourcePreparationError("frozen os-test basic compile flags differ")
    return {SOURCE_PATH: prepared, **SUPPORT_FILES}


def prepared_fixture_receipt() -> dict[str, object]:
    """Return the source, support, and frozen-basic compile attribution."""
    return {
        **preparation_record(FROZEN_SOURCE),
        "support_files": {relative: sha256(content) for relative, content in SUPPORT_FILES.items()},
        "compile_flags": list(BASIC_COMPILE_FLAGS),
    }


def materialize_prepared_fixture(destination: Path) -> dict[str, object]:
    """Write the sealed derivative and its unchanged local source support."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise SourcePreparationError("refusing to replace an os-test AIO fixture directory")
    files = prepared_fixture_files()
    try:
        destination.mkdir(parents=True)
        for relative, content in files.items():
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(content)
        return prepared_fixture_receipt()
    except OSError as error:
        raise SourcePreparationError("cannot materialize os-test AIO fixture") from error


def write_prepared_fixture_receipt(destination: Path, receipt: Path) -> dict[str, object]:
    """Materialize once and retain the exact source-preparation attribution."""
    record = materialize_prepared_fixture(destination)
    receipt = Path(receipt)
    try:
        with receipt.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except OSError as error:
        raise SourcePreparationError("cannot retain os-test AIO fixture receipt") from error
    return record


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materialize", type=Path, required=True,
                        help="new directory for the sealed focused source tree")
    parser.add_argument("--receipt", type=Path, required=True,
                        help="new JSON receipt for the sealed source tree")
    values = parser.parse_args(arguments)
    try:
        record = write_prepared_fixture_receipt(values.materialize, values.receipt)
    except SourcePreparationError as error:
        parser.error(str(error))
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
