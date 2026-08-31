/* Static x86-64 sealed format-whitespace scanf fixture.
 *
 * This fixture owns only musl vfscanf's top-level format-whitespace parser
 * state through the existing no-FILE, NUL-terminated `sscanf`/`vsscanf`
 * boundary. It uses fixed narrow C-locale byte strings, consumes no conversion
 * destination, and makes no assignment. It is not evidence for literal-percent
 * matching, count-store `%n`, character, string, scanset, pointer, integer,
 * floating, wide, stream, locale, or general stdio behavior.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(size_t) == 8 && sizeof(uintptr_t) == 8,
    "x86 pointer-sized scalar widths");

typedef int (*crabc_sscanf_signature)(const char *, const char *, ...);
typedef int (*crabc_vsscanf_signature)(const char *, const char *, va_list);

#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)
_Static_assert(CRABC_TYPE_IS(__typeof__(&sscanf), crabc_sscanf_signature),
    "sscanf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&vsscanf), crabc_vsscanf_signature),
    "vsscanf declaration");

static int call_vsscanf(const char *input, const char *format, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = vsscanf(input, format, arguments);
    va_end(arguments);
    return result;
}

static int check_selected_format_whitespace_scan(void)
{
    int result;

    /* musl coalesces the format run, consumes every selected C-locale input
     * whitespace byte, then leaves the first nonspace for the next literal.
     * No conversion means zero assignments and no errno write. */
    errno = EINTR;
    result = sscanf(" \t\n\r\v\f!", " \t\n\r\v\f!");
    if (result != 0 || errno != EINTR)
        return 1;

    /* Direct vsscanf forwarding supplies no variadic destination because the
     * format-whitespace state leaves its va_list untouched. */
    errno = EDOM;
    result = call_vsscanf("\v\f?", "\t\r?");
    if (result != 0 || errno != EDOM)
        return 2;

    /* The selected state admits zero input whitespace before a following
     * literal; it must not require an input-space byte. */
    errno = EILSEQ;
    result = sscanf("!", " \t!");
    if (result != 0 || errno != EILSEQ)
        return 3;

    /* An all-whitespace format succeeds with zero assignments even at source
     * EOF, because vfscanf has no following literal or conversion to match. */
    errno = EINTR;
    result = call_vsscanf("", "\v\f");
    if (result != 0 || errno != EINTR)
        return 4;

    errno = EDOM;
    result = sscanf(" \t\n", " \r\v\f");
    if (result != 0 || errno != EDOM)
        return 5;

    /* A later literal sees EOF after the zero-or-more whitespace state and
     * returns EOF before any assignment; a nonmatching byte returns zero. */
    errno = EILSEQ;
    result = sscanf("", " !");
    if (result != EOF || errno != EILSEQ)
        return 6;

    errno = EINTR;
    result = call_vsscanf(" \t?", " !");
    if (result != 0 || errno != EINTR)
        return 7;

    return 0;
}

int crabc_x86_64_stdio_fixed_format_whitespace_scan_probe(void)
{
    return check_selected_format_whitespace_scan();
}

#ifndef CRABC_STDIO_FIXED_FORMAT_WHITESPACE_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_fixed_format_whitespace_scan_probe();
}
#endif
