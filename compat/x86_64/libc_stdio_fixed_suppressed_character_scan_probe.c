/* Static x86-64 sealed assignment-suppressed raw-character scanf fixture.
 *
 * This fixture owns only musl vfscanf's non-wide `%*3c` conversion state
 * through the existing no-external-FILE, NUL-terminated `sscanf`/`vsscanf`
 * boundary. It uses fixed narrow byte strings, gives the scanner no
 * destination, and makes no assignment. Its trailing vsscanf sentinel is
 * fixture-local ABI evidence that suppression leaves va_list untouched. A
 * following literal only proves the preexisting raw-character consumption
 * boundary; it does not establish literal matching. This is not evidence for
 * unsuppressed `%c`, other widths or suppression forms, `%s`, scansets,
 * pointer, integer, floating, wide, stream, locale, or general stdio behavior.
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

static int call_vsscanf_suppressed_character(
    const char *input, int *result_out, int expected_trailing, ...)
{
    va_list arguments;
    int trailing;

    va_start(arguments, expected_trailing);
    *result_out = vsscanf(input, "%*3c!", arguments);
    /* The fixed star field supplies no scanner destination. This extra
     * fixture argument checks that the scanner did not advance va_list. */
    trailing = va_arg(arguments, int);
    va_end(arguments);
    return trailing == expected_trailing ? 0 : 1;
}

static int check_selected_suppressed_character_scan(void)
{
    static const char high_input[] = { (char)0x80, 'x', 'y', '!', '\0' };
    int result;

    /* A zero-assignment suppressed character consumes exactly three raw
     * bytes, including interior whitespace, before the fixed literal. */
    errno = EINTR;
    result = sscanf("A B!", "%*3c!");
    if (result != 0 || errno != EINTR)
        return 1;

    /* Direct vsscanf forwarding has no destination: the trailing fixture
     * argument stays available after a successful suppressed conversion. */
    errno = EDOM;
    if (call_vsscanf_suppressed_character("xy?!", &result, 0x3141, 0x3141) ||
        result != 0 || errno != EDOM)
        return 2;

    /* Unlike `%s`, raw `%*3c` treats leading C-locale whitespace as data. */
    errno = EILSEQ;
    result = sscanf("\txy!", "%*3c!");
    if (result != 0 || errno != EILSEQ)
        return 3;

    /* Once it has read a raw byte, a short fixed-width run is matching
     * failure, not input failure, and has no caller buffer to modify. */
    errno = EINTR;
    result = sscanf("ab", "%*3c");
    if (result != 0 || errno != EINTR)
        return 4;

    /* Initial EOF is input failure; vsscanf still leaves its sentinel alone. */
    errno = EDOM;
    if (call_vsscanf_suppressed_character("", &result, 0x2718, 0x2718) ||
        result != EOF || errno != EDOM)
        return 5;

    /* The selected C-locale source path accepts a non-NUL high byte as raw
     * character data rather than applying text or UTF-8 interpretation. */
    errno = EILSEQ;
    result = sscanf(high_input, "%*3c!");
    if (result != 0 || errno != EILSEQ)
        return 6;

    return 0;
}

int crabc_x86_64_stdio_fixed_suppressed_character_scan_probe(void)
{
    return check_selected_suppressed_character_scan();
}

#ifndef CRABC_STDIO_FIXED_SUPPRESSED_CHARACTER_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_fixed_suppressed_character_scan_probe();
}
#endif
