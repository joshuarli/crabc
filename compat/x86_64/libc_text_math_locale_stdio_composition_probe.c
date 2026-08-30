/* Native x86-64 static text/math/locale/stdio composition fixture.
 *
 * This is deliberately a composition test, not another implementation leaf.
 * It crosses the four already selected static seams: C-locale floating parsing,
 * binary64 classification, named C.UTF-8 multibyte state, and the permanent
 * stdout stream.  The exact source first executes through pinned musl 1.2.6
 * (commit 9fa28ece75d8a2191de7c5bb53bed224c5947417), then through one true
 * `-nostdlib -static` crabc-libc archive.  It selects no formatter, path
 * stream, locale object, scalar libm, wide stream, allocation, CRT, loader,
 * sysroot, or general text/math/locale/stdio completion.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53,
    "x86 binary64 parsing ABI");
_Static_assert(sizeof(wchar_t) == 4 && sizeof(mbstate_t) == 8,
    "x86 multibyte ABI");
_Static_assert(FP_NORMAL == 4 && MB_LEN_MAX >= 4,
    "selected math and UTF-8 header constants");

typedef double (*strtod_fn)(const char *, char **);
typedef int (*fpclassify_fn)(double);
typedef char *(*setlocale_fn)(int, const char *);
typedef struct lconv *(*localeconv_fn)(void);
typedef size_t (*mbrtowc_fn)(wchar_t *, const char *, size_t, mbstate_t *);
typedef int (*pipe_fn)(int *);
typedef int (*dup_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*close_fn)(int);
typedef int (*fputc_fn)(int, FILE *);
typedef int (*fflush_fn)(FILE *);
typedef ssize_t (*read_fn)(int, void *, size_t);

static strtod_fn volatile strtod_entry = strtod;
static fpclassify_fn volatile fpclassify_entry = __fpclassify;
static setlocale_fn volatile setlocale_entry = setlocale;
static localeconv_fn volatile localeconv_entry = localeconv;
static mbrtowc_fn volatile mbrtowc_entry = mbrtowc;
static pipe_fn volatile pipe_entry = pipe;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static close_fn volatile close_entry = close;
static fputc_fn volatile fputc_entry = fputc;
static fflush_fn volatile fflush_entry = fflush;
static read_fn volatile read_entry = read;

static int text_equal(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

static int check_composed_c_utf8_parse_and_stream(void)
{
    static const char euro[] = "\xe2\x82\xac";
    int fds[2] = { -1, -1 };
    char *end = NULL;
    wchar_t wide = 0;
    mbstate_t state = { 0, 0 };
    struct lconv *conventions;
    double parsed;
    char observed = '\0';
    int saved_stdout = -1;
    int status = 0;

    if (setlocale_entry(LC_ALL, "C") == NULL || MB_CUR_MAX != 1)
        return 1;
    if (setlocale_entry(LC_CTYPE, "C.UTF-8") == NULL || MB_CUR_MAX != 4)
        return 2;
    conventions = localeconv_entry();
    if (conventions == NULL || !text_equal(conventions->decimal_point, "."))
        return 3;

    errno = EINTR;
    if (mbrtowc_entry(&wide, euro, sizeof(euro) - 1U, &state) != 3 ||
        wide != 0x20ac || errno != EINTR)
        return 4;
    parsed = strtod_entry("12.5tail", &end);
    if (parsed != 12.5 || end == NULL || *end != 't' ||
        fpclassify_entry(parsed) != FP_NORMAL || errno != EINTR)
        return 5;

    /* This UTF-8 failure establishes errno through the locale seam.  The
     * following parser and permanent-stream success paths must leave the
     * same initial-exec errno datum stale, as musl does. */
    errno = 0;
    if (mbrtowc_entry(&wide, "\xc0", 1, &state) != (size_t)-1 || errno != EILSEQ)
        return 6;
    parsed = strtod_entry("2.0", &end);
    if (parsed != 2.0 || end == NULL || *end != '\0' || errno != EILSEQ)
        return 7;

    if (pipe_entry(fds) != 0)
        return 8;
    saved_stdout = dup_entry(STDOUT_FILENO);
    if (saved_stdout < 0 || dup2_entry(fds[1], STDOUT_FILENO) != STDOUT_FILENO) {
        status = 9;
        goto cleanup;
    }
    if (close_entry(fds[1]) != 0) {
        fds[1] = -1;
        status = 10;
        goto cleanup;
    }
    fds[1] = -1;
    if (fputc_entry('P', stdout) != 'P' || errno != EILSEQ) {
        status = 11;
        goto cleanup;
    }
    if (fflush_entry(stdout) != 0 || errno != EILSEQ) {
        status = 12;
        goto cleanup;
    }
    if (read_entry(fds[0], &observed, 1) != 1 || observed != 'P') {
        status = 13;
        goto cleanup;
    }

cleanup:
    if (saved_stdout >= 0 && dup2_entry(saved_stdout, STDOUT_FILENO) != STDOUT_FILENO &&
        status == 0)
        status = 14;
    if (saved_stdout >= 0 && close_entry(saved_stdout) != 0 && status == 0)
        status = 15;
    if (fds[0] >= 0 && close_entry(fds[0]) != 0 && status == 0)
        status = 16;
    if (fds[1] >= 0 && close_entry(fds[1]) != 0 && status == 0)
        status = 17;
    return status;
}

int crabc_x86_64_text_math_locale_stdio_composition_probe(void)
{
    return check_composed_c_utf8_parse_and_stream();
}

#ifndef CRABC_TEXT_MATH_LOCALE_STDIO_COMPOSITION_FREESTANDING
int main(void)
{
    return crabc_x86_64_text_math_locale_stdio_composition_probe();
}
#endif
