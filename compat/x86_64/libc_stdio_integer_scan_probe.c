/* Static x86-64 bounded integer-source-overflow sscanf behavior fixture.
 *
 * The fixture deliberately owns only the previously unproved musl
 * unsigned-long-long source-overflow result of the existing no-FILE,
 * NUL-terminated `sscanf`/`vsscanf` boundary.  Every input is a narrow
 * byte-string literal and every conversion is one of %d, %i, %u, or %x.
 * It is not a claim about floating, wide, scanset, positional, FILE, or
 * general stdio behavior.
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

static int check_selected_source_overflow(void)
{
    unsigned long long exact_limit = 0;
    int decimal = 17;
    int automatic = 19;
    unsigned int decimal_unsigned = 23;
    unsigned int hexadecimal = 29;
    int width_limited = 31;
    int result;

    /* The ULLONG_MAX boundary itself leaves the caller's errno untouched. */
    errno = EINTR;
    result = sscanf("18446744073709551615!", "%llu!", &exact_limit);
    if (result != 1 || exact_limit != ULLONG_MAX || errno != EINTR)
        return 1;

    /* musl intscan saturates source overflow before the ordinary target store. */
    errno = EDOM;
    result = sscanf("18446744073709551616!", "%d!", &decimal);
    if (result != 1 || decimal != -1 || errno != ERANGE)
        return 2;

    /* The source-overflow path clears a negative sign before storing %i. */
    errno = EILSEQ;
    result = sscanf("-0x10000000000000000?", "%i?", &automatic);
    if (result != 1 || automatic != -1 || errno != ERANGE)
        return 3;

    errno = EINTR;
    result = sscanf("-18446744073709551616;", "%u;", &decimal_unsigned);
    if (result != 1 || decimal_unsigned != UINT_MAX || errno != ERANGE)
        return 4;

    errno = EDOM;
    result = call_vsscanf("10000000000000000.", "%x.", &hexadecimal);
    if (result != 1 || hexadecimal != UINT_MAX || errno != ERANGE)
        return 5;

    /* Width includes all twenty decimal digits; the trailing literal proves
     * that the scanner consumed the complete bounded source run. */
    errno = EILSEQ;
    result = sscanf("18446744073709551616#", "%20u#", &decimal_unsigned);
    if (result != 1 || decimal_unsigned != UINT_MAX || errno != ERANGE)
        return 6;

    errno = EDOM;
    result = sscanf("18446744073709551616#", "%20d#", &width_limited);
    if (result != 1 || width_limited != -1 || errno != ERANGE)
        return 7;

    return 0;
}

static int check_integer_failure_and_consumption(void)
{
    int signed_value = 37;
    unsigned int unsigned_value = 41;
    int consumed = -1;
    char trailing = '?';
    int result;

    /* A sign without a digit is a matching failure. The scanner has seen
     * input, so it preserves the destination and count while setting EINVAL. */
    errno = EINTR;
    result = sscanf("+", "%d%n", &signed_value, &consumed);
    if (result != 0 || signed_value != 37 || consumed != -1 || errno != EINVAL)
        return 1;

    errno = EDOM;
    result = call_vsscanf("-x", "%u%n", &unsigned_value, &consumed);
    if (result != 0 || unsigned_value != 41 || consumed != -1 || errno != EINVAL)
        return 2;

    /* A field width ending immediately after the sign has the same failure,
     * even though an otherwise valid digit follows outside the field. */
    errno = EILSEQ;
    result = sscanf("-7", "%1i%n", &signed_value, &consumed);
    if (result != 0 || signed_value != 37 || consumed != -1 || errno != EINVAL)
        return 3;

    /* A prefix without a following hex digit also fails, but does not set
     * EINVAL: the leading zero was a valid digit before prefix admission. */
    errno = EDOM;
    result = sscanf("0x", "%i%n", &signed_value, &consumed);
    if (result != 0 || signed_value != 37 || consumed != -1 || errno != EDOM)
        return 4;

    errno = EINTR;
    result = sscanf("0x1", "%1x%n%c", &unsigned_value, &consumed,
        &trailing);
    if (result != 2 || unsigned_value != 0U || consumed != 1 ||
        trailing != 'x' || errno != EINTR)
        return 5;

    /* Suppression still parses the entire overflowing source field and
     * records ERANGE; only the later character contributes an assignment. */
    consumed = -1;
    trailing = '?';
    errno = EILSEQ;
    result = sscanf("18446744073709551616!", "%*20u%n%c",
        &consumed, &trailing);
    if (result != 1 || consumed != 20 || trailing != '!' || errno != ERANGE)
        return 6;

    /* Successful integer assignment at exact input exhaustion is retained
     * when a later character directive encounters EOF. */
    consumed = -1;
    trailing = '?';
    errno = EDOM;
    result = call_vsscanf("18446744073709551616", "%20u%n%c",
        &unsigned_value, &consumed, &trailing);
    if (result != 1 || unsigned_value != UINT_MAX || consumed != 20 ||
        trailing != '?' || errno != ERANGE)
        return 7;

    /* Input exhaustion before any conversion is an input failure, with no
     * destination or count store and with the caller's errno intact. */
    signed_value = 37;
    consumed = -1;
    errno = EINTR;
    result = sscanf(" \t", "%d%n", &signed_value, &consumed);
    if (result != EOF || signed_value != 37 || consumed != -1 || errno != EINTR)
        return 8;

    return 0;
}

int crabc_x86_64_stdio_integer_scan_probe(void)
{
    int status = check_selected_source_overflow();
    if (status != 0)
        return status;
    status = check_integer_failure_and_consumption();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_STDIO_INTEGER_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_integer_scan_probe();
}
#endif
