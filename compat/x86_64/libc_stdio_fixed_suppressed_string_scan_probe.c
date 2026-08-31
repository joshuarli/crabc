/* Static x86-64 sealed assignment-suppressed token-string scanf fixture.
 *
 * This fixture owns only musl vfscanf's non-wide `%*3s` conversion state
 * through the existing no-external-FILE, NUL-terminated `sscanf`/`vsscanf`
 * boundary. It uses fixed narrow byte strings, gives the scanner no
 * destination, and makes no assignment. Its trailing vsscanf sentinel is
 * fixture-local ABI evidence that suppression leaves va_list untouched. A
 * following literal only proves the preexisting token consumption boundary;
 * it does not establish literal matching. This is not evidence for `%3s`
 * destination storage, `%c`, scansets, pointer, integer, floating, wide,
 * stream, locale, or general stdio behavior.
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

static int call_vsscanf_suppressed_string(
    const char *input, int *result_out, int expected_trailing, ...)
{
    va_list arguments;
    int trailing;

    va_start(arguments, expected_trailing);
    *result_out = vsscanf(input, "%*3s!", arguments);
    /* The fixed star field supplies no scanner destination. This extra
     * fixture argument checks that the scanner did not advance va_list. */
    trailing = va_arg(arguments, int);
    va_end(arguments);
    return trailing == expected_trailing ? 0 : 1;
}

static int check_selected_suppressed_string_scan(void)
{
    static const char high_input[] = { (char)0x80, 'A', 'B', '!', '\0' };
    int result;

    /* A zero-assignment suppressed token path skips C-locale input whitespace
     * before it consumes a short token. It leaves no destination behind. */
    errno = EINTR;
    result = sscanf(" \txy", "%*3s");
    if (result != 0 || errno != EINTR)
        return 1;

    /* Direct vsscanf forwarding has no destination: the trailing fixture
     * argument stays available after an exact-width suppressed token. */
    errno = EDOM;
    if (call_vsscanf_suppressed_string("abc!", &result, 0x3141, 0x3141) ||
        result != 0 || errno != EDOM)
        return 2;

    /* Unlike `%*3c`, a nonempty token shorter than its width succeeds; no
     * caller buffer receives a terminator or partial data. */
    errno = EILSEQ;
    result = sscanf("ab", "%*3s");
    if (result != 0 || errno != EILSEQ)
        return 3;

    /* After its C-locale whitespace skip, whitespace-only input reaches the
     * selected initial input-failure route with no ordinary assignment. */
    errno = EINTR;
    result = sscanf(" \t", "%*3s");
    if (result != EOF || errno != EINTR)
        return 4;

    /* Initial EOF through vsscanf still leaves its sentinel alone. */
    errno = EDOM;
    if (call_vsscanf_suppressed_string("", &result, 0x2718, 0x2718) ||
        result != EOF || errno != EDOM)
        return 5;

    /* The selected C-locale source path accepts a non-NUL high byte as token
     * data rather than applying text or UTF-8 interpretation. */
    errno = EILSEQ;
    result = sscanf(high_input, "%*3s!");
    if (result != 0 || errno != EILSEQ)
        return 6;

    return 0;
}

static int check_candidate_limitations(void)
{
#ifdef CRABC_STDIO_FIXED_SUPPRESSED_STRING_SCAN_FREESTANDING
    int result;

    /* This sealed profile does not select musl's multibyte/wide `ls` route;
     * the candidate rejects it before any destination or allocation state. */
    errno = 0;
    result = sscanf("abc", "%*3ls");
    if (result != 0 || errno != EINVAL)
        return 30;
#endif
    return 0;
}

int crabc_x86_64_stdio_fixed_suppressed_string_scan_probe(void)
{
    int status = check_selected_suppressed_string_scan();

    if (status != 0)
        return status;
    return check_candidate_limitations();
}

#ifndef CRABC_STDIO_FIXED_SUPPRESSED_STRING_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_fixed_suppressed_string_scan_probe();
}
#endif
