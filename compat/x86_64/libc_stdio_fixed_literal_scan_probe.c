/* Static x86-64 sealed raw-literal scanf fixture.
 *
 * This fixture owns only musl vfscanf's top-level non-percent,
 * non-format-whitespace raw-literal parser state through the existing no-FILE,
 * NUL-terminated `sscanf`/`vsscanf` boundary. It uses fixed narrow byte
 * strings, consumes no conversion destination, and makes no assignment. It is
 * not evidence for literal-percent matching, format whitespace, count-store
 * `%n`, character, string, scanset, pointer, integer, floating, wide, stream,
 * locale, or general stdio behavior.
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

static int check_selected_raw_literal_scan(void)
{
    int result;

    /* A complete fixed raw byte sequence matches with zero assignments and no
     * errno write: this is a zero-assignment raw literal parser state, not a
     * conversion or destination-bearing scan. */
    errno = EINTR;
    result = sscanf("crate/42", "crate/42");
    if (result != 0 || errno != EINTR)
        return 1;

    /* Direct vsscanf forwarding supplies no variadic destination because raw
     * literal matching leaves its va_list untouched. */
    errno = EDOM;
    result = call_vsscanf("A-B", "A-B");
    if (result != 0 || errno != EDOM)
        return 2;

    /* A mismatch after already matched raw bytes is matching failure, not
     * input failure, and still has no assignment. */
    errno = EILSEQ;
    result = sscanf("stop!", "stop?");
    if (result != 0 || errno != EILSEQ)
        return 3;

    /* Input EOF after a matched literal prefix reaches vfscanf's input-failure
     * path before any assignment. */
    errno = EINTR;
    result = call_vsscanf("AB", "ABC");
    if (result != EOF || errno != EINTR)
        return 4;

    errno = EDOM;
    result = sscanf("", "x");
    if (result != EOF || errno != EDOM)
        return 5;

    /* A first-byte nonmatch remains zero rather than EOF. */
    errno = EILSEQ;
    result = call_vsscanf("y", "x");
    if (result != 0 || errno != EILSEQ)
        return 6;

    return 0;
}

int crabc_x86_64_stdio_fixed_literal_scan_probe(void)
{
    return check_selected_raw_literal_scan();
}

#ifndef CRABC_STDIO_FIXED_LITERAL_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_fixed_literal_scan_probe();
}
#endif
