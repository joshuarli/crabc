/* Static x86-64 bounded octal/uppercase-hex source-overflow scanf fixture.
 *
 * This fixture deliberately owns only the musl `__intscan(..., ULLONG_MAX)`
 * source-overflow result for the existing no-FILE, NUL-terminated
 * `sscanf`/`vsscanf` boundary. Every input is a fixed narrow byte-string
 * literal, and every conversion is `%o` or `%X` (with `%llo`/`%llX` only for
 * the exact ULLONG_MAX boundaries). It is not a portable ISO C
 * target-overflow claim or a claim about decimal, floating, wide, scanset,
 * positional, FILE, byte-formatting, or general stdio behavior.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(unsigned int) == 4 && sizeof(unsigned long long) == 8,
    "x86 selected unsigned widths");

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

static int check_selected_octal_upper_hex_source_overflow(void)
{
    unsigned long long exact_octal_limit = 0;
    unsigned long long exact_upper_hex_limit = 0;
    unsigned int octal = 17;
    unsigned int uppercase_hex = 19;
    int result;

    /* Exact ULLONG_MAX octal leaves errno untouched. */
    errno = EINTR;
    result = sscanf("1777777777777777777777!", "%llo!", &exact_octal_limit);
    if (result != 1 || exact_octal_limit != ULLONG_MAX || errno != EINTR)
        return 1;

    /* `%X` accepts uppercase digits and direct vsscanf preserves errno at the
     * exact ULLONG_MAX boundary. */
    errno = EILSEQ;
    result = call_vsscanf("FFFFFFFFFFFFFFFF?", "%llX?", &exact_upper_hex_limit);
    if (result != 1 || exact_upper_hex_limit != ULLONG_MAX || errno != EILSEQ)
        return 2;

    /* The overflow run is fully consumed before the literal; musl's odd
     * ULLONG_MAX limit clears the leading negative sign before target store. */
    errno = EDOM;
    result = sscanf("-2000000000000000000000;", "%o;", &octal);
    if (result != 1 || octal != UINT_MAX || errno != ERANGE)
        return 3;

    /* This 17-digit overflow contains an uppercase alpha digit and verifies
     * complete `%X` consumption through a direct vsscanf literal witness. */
    errno = EINTR;
    result = call_vsscanf("1000000000000000A.", "%X.", &uppercase_hex);
    if (result != 1 || uppercase_hex != UINT_MAX || errno != ERANGE)
        return 4;

    /* Width counts all source digits; matching the following literal seals
     * exact consumption at the two power-of-two overflow boundaries. */
    errno = EILSEQ;
    result = sscanf("2000000000000000000000#", "%22o#", &octal);
    if (result != 1 || octal != UINT_MAX || errno != ERANGE)
        return 5;

    errno = EDOM;
    result = call_vsscanf("1000000000000000A#", "%17X#", &uppercase_hex);
    if (result != 1 || uppercase_hex != UINT_MAX || errno != ERANGE)
        return 6;

    return 0;
}

int crabc_x86_64_stdio_octal_hex_scan_probe(void)
{
    return check_selected_octal_upper_hex_source_overflow();
}

#ifndef CRABC_STDIO_OCTAL_HEX_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_octal_hex_scan_probe();
}
#endif
