/* Static x86-64 sealed assignment-suppressed scanset scanf fixture.
 *
 * This fixture owns only musl vfscanf's non-wide literal `%*3[abc]`
 * conversion state through the existing no-external-FILE, NUL-terminated
 * `sscanf`/`vsscanf` boundary. It uses fixed C-locale narrow byte strings,
 * gives the scanner no destination, and makes no assignment. Its trailing
 * vsscanf sentinel is fixture-local ABI evidence that suppression leaves
 * va_list untouched. Following literals only prove the preexisting raw
 * member-run consumption boundary; they do not establish literal matching.
 * This is not evidence for unsuppressed scansets, other scanset grammar,
 * `%c`/`%s`, pointer, integer, floating, wide, stream, locale, or general
 * stdio behavior.
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

static int call_vsscanf_suppressed_scanset(
    const char *input, int *result_out, int expected_trailing, ...)
{
    va_list arguments;
    int trailing;

    va_start(arguments, expected_trailing);
    *result_out = vsscanf(input, "%*3[abc]!", arguments);
    /* The fixed star field supplies no scanner destination. This extra
     * fixture argument checks that the scanner did not advance va_list. */
    trailing = va_arg(arguments, int);
    va_end(arguments);
    return trailing == expected_trailing ? 0 : 1;
}

static int check_selected_suppressed_scanset_scan(void)
{
    static const char high_input[] = { 'a', (char)0x80, '!', '\0' };
    static const char high_format[] = {
        '%', '*', '3', '[', 'a', 'b', 'c', ']', (char)0x80, '!', '\0'
    };
    int result;

    /* A nonempty member run shorter than width three succeeds without a
     * destination or assignment, leaving its first non-member for `!`. */
    errno = EINTR;
    result = sscanf("ab!", "%*3[abc]!");
    if (result != 0 || errno != EINTR)
        return 1;

    /* Direct vsscanf forwarding keeps the fixture-only sentinel available
     * after the exact-width raw member run. */
    errno = EDOM;
    if (call_vsscanf_suppressed_scanset("abc!", &result, 0x3141, 0x3141) ||
        result != 0 || errno != EDOM)
        return 2;

    /* Unlike `%s`, musl's bracket state does not skip leading C-locale input
     * whitespace: it is an immediate matching failure with no assignment. */
    errno = EILSEQ;
    result = sscanf(" abc", "%*3[abc]");
    if (result != 0 || errno != EILSEQ)
        return 3;

    /* A first non-member is matching failure, distinct from input EOF. */
    errno = EINTR;
    result = sscanf("z", "%*3[abc]");
    if (result != 0 || errno != EINTR)
        return 4;

    /* Initial EOF through vsscanf preserves both its zero-assignment EOF
     * result and its fixture-only trailing argument. */
    errno = EDOM;
    if (call_vsscanf_suppressed_scanset("", &result, 0x2718, 0x2718) ||
        result != EOF || errno != EDOM)
        return 5;

    /* Membership is raw narrow bytes: the high byte is not an `a`/`b`/`c`
     * member and remains available for a following raw literal. */
    errno = EILSEQ;
    result = sscanf(high_input, high_format);
    if (result != 0 || errno != EILSEQ)
        return 6;

    return 0;
}

static int check_candidate_limitations(void)
{
#ifdef CRABC_STDIO_FIXED_SUPPRESSED_SCANSET_SCAN_FREESTANDING
    int result;

    /* Keep the selected grammar to exactly the literal non-wide `%*3[abc]`
     * spelling. These musl-accepted forms remain candidate-only and fail
     * closed rather than becoming a general scanset parser. */
    errno = 0;
    result = sscanf("abc", "%3[abc]");
    if (result != 0 || errno != EINVAL)
        return 30;

    errno = 0;
    result = sscanf("abc", "%*[abc]");
    if (result != 0 || errno != EINVAL)
        return 31;

    errno = 0;
    result = sscanf("abc", "%*03[abc]");
    if (result != 0 || errno != EINVAL)
        return 32;

    errno = 0;
    result = sscanf("abc", "%*3[a-z]");
    if (result != 0 || errno != EINVAL)
        return 33;

    errno = 0;
    result = sscanf("z", "%*3[^abc]");
    if (result != 0 || errno != EINVAL)
        return 34;

    errno = 0;
    result = sscanf("abc", "%*3l[abc]");
    if (result != 0 || errno != EINVAL)
        return 35;
#endif
    return 0;
}

int crabc_x86_64_stdio_fixed_suppressed_scanset_scan_probe(void)
{
    int status = check_selected_suppressed_scanset_scan();

    if (status != 0)
        return status;
    return check_candidate_limitations();
}

#ifndef CRABC_STDIO_FIXED_SUPPRESSED_SCANSET_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_fixed_suppressed_scanset_scan_probe();
}
#endif
