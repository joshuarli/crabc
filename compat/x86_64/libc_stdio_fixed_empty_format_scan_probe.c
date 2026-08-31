/* Static x86-64 sealed empty-format scanf fixture.
 *
 * This fixture owns only musl vfscanf's zero-length format termination through
 * the existing no-external-FILE, NUL-terminated `sscanf`/`vsscanf` boundary.
 * It uses
 * fixed narrow byte strings, reaches the format-end return after vsscanf's
 * private NUL-string setup, consumes no conversion destination, and makes no
 * assignment. Its trailing vsscanf sentinel is fixture-local ABI evidence
 * that this state leaves va_list untouched. It is
 * not evidence for literal, literal-percent, format-whitespace, conversion,
 * count-store `%n`, character, string, scanset, pointer, integer, floating,
 * wide, stream, locale, or general stdio behavior.
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

static int call_vsscanf_empty_format(
    const char *input, int expected_trailing, ...)
{
    va_list arguments;
    int result;
    int trailing;

    va_start(arguments, expected_trailing);
    result = vsscanf(input, "", arguments);
    /* The fixed empty format has no destination or conversion. This extra
     * fixture argument checks that the scanner did not advance va_list. */
    trailing = va_arg(arguments, int);
    va_end(arguments);
    return result == 0 && trailing == expected_trailing ? 0 : 1;
}

static int check_selected_empty_format_scan(void)
{
    int result;

    /* After vsscanf's private NUL-string setup admits this empty input, a
     * zero-assignment empty format reaches vfscanf's format-end return and
     * therefore preserves stale errno. */
    errno = EINTR;
    result = sscanf("", "");
    if (result != 0 || errno != EINTR)
        return 1;

    /* No format-directed parser state handles this nonempty input. */
    errno = EDOM;
    result = sscanf("unread bytes", "");
    if (result != 0 || errno != EDOM)
        return 2;

    /* Direct vsscanf forwarding retains the trailing variadic value because
     * this parser state does not acquire a destination or call va_arg. */
    errno = EILSEQ;
    result = call_vsscanf_empty_format("", 0x3141, 0x3141);
    if (result != 0 || errno != EILSEQ)
        return 3;

    errno = EINTR;
    result = call_vsscanf_empty_format("unread bytes", 0x2718, 0x2718);
    if (result != 0 || errno != EINTR)
        return 4;

    return 0;
}

int crabc_x86_64_stdio_fixed_empty_format_scan_probe(void)
{
    return check_selected_empty_format_scan();
}

#ifndef CRABC_STDIO_FIXED_EMPTY_FORMAT_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_fixed_empty_format_scan_probe();
}
#endif
