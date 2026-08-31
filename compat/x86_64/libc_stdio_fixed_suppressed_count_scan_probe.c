/* Static x86-64 sealed assignment-suppressed count scanf fixture.
 *
 * This fixture owns only pinned musl 1.2.6's literal non-wide %*n parser
 * state through the existing no-external-FILE, NUL-terminated sscanf/vsscanf
 * boundary. It uses fixed C-locale narrow byte strings, gives the scanner no
 * destination, reads no source byte at the count state, and makes no
 * assignment. Its trailing vsscanf sentinel is fixture-local ABI evidence
 * that suppression leaves va_list untouched. Following raw literals only
 * prove that the selected count state does not consume input; they do not
 * establish literal matching. This is a musl-specific parser-state witness,
 * not a portable general scanf-suppression or count-conversion claim.
 *
 * It does not evidence unsuppressed %n storage, other count length or width
 * forms, character/string/scanset/pointer/integer/floating/wide conversions,
 * streams, locale, or general stdio behavior.
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

static int call_vsscanf_suppressed_count(
    const char *input, int *result_out, int expected_trailing, ...)
{
    va_list arguments;
    int trailing;

    va_start(arguments, expected_trailing);
    *result_out = vsscanf(input, "%*n", arguments);
    /* The fixed star field supplies no scanner destination. This extra
     * fixture argument checks that the count state did not advance va_list. */
    trailing = va_arg(arguments, int);
    va_end(arguments);
    return trailing == expected_trailing ? 0 : 1;
}

static int check_selected_suppressed_count_scan(void)
{
    int result;

    /* musl's n state needs no source byte and stores nothing when its star
     * field made dest null, so zero-assignment suppressed count succeeds at
     * input EOF and preserves stale errno. */
    errno = EINTR;
    result = sscanf("", "%*n");
    if (result != 0 || errno != EINTR)
        return 1;

    /* Direct vsscanf forwarding has no destination for the selected state:
     * the fixture-only trailing vararg remains available after the call. */
    errno = EDOM;
    if (call_vsscanf_suppressed_count("abc", &result, 0x3141, 0x3141) ||
        result != 0 || errno != EDOM)
        return 2;

    /* The selected count state reads no source byte. The sibling raw-literal
     * state therefore still matches b after literal a and %*n. */
    errno = EILSEQ;
    result = sscanf("ab", "a%*nb");
    if (result != 0 || errno != EILSEQ)
        return 3;

    /* A later literal mismatch remains a zero-assignment matching failure,
     * rather than an input failure or a hidden count assignment. */
    errno = EINTR;
    result = sscanf("a?", "a%*nb");
    if (result != 0 || errno != EINTR)
        return 4;

    /* Empty input through the vsscanf path has the same successful
     * zero-assignment result and leaves the sentinel unadvanced. */
    errno = EDOM;
    if (call_vsscanf_suppressed_count("", &result, 0x2718, 0x2718) ||
        result != 0 || errno != EDOM)
        return 5;

    return 0;
}

int crabc_x86_64_stdio_fixed_suppressed_count_scan_probe(void)
{
    return check_selected_suppressed_count_scan();
}

#ifndef CRABC_STDIO_FIXED_SUPPRESSED_COUNT_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_fixed_suppressed_count_scan_probe();
}
#endif
