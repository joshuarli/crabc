/* Static x86-64 wcswcs C ABI and pinned-musl behavioral fixture.
 *
 * The same project-header body executes through pinned musl and the selected
 * true static archive. It proves the legacy wide-substring alias's first
 * suffix, empty-needle, no-match, signed-unit, and no-mutation behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <wchar.h>

typedef wchar_t *(*wcswcs_signature)(const wchar_t *, const wchar_t *);

_Static_assert(sizeof(wchar_t) == 4 && _Alignof(wchar_t) == 4,
    "x86 wchar_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wcswcs),
    wcswcs_signature), "wcswcs declaration");

static int units_match(const wchar_t *left, const wchar_t *right, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int check_empty_and_first_suffix(void)
{
    wchar_t haystack[] = { L'p', L'r', L'e', L'f', L'i', L'x', 0 };
    wchar_t empty[] = { 0 };
    wchar_t needle[] = { L'e', L'f', L'i', L'x', 0 };
    const wcswcs_signature find = wcswcs;

    if (find(haystack, empty) != haystack)
        return 1;
    return wcswcs(haystack, needle) == haystack + 2 ? 0 : 2;
}

static int check_first_match_and_miss(void)
{
    wchar_t haystack[] = { L'a', L'b', L'a', L'b', L'a', L'b', L'a', 0 };
    wchar_t first[] = { L'a', L'b', L'a', 0 };
    wchar_t later[] = { L'b', L'a', L'b', L'a', 0 };
    wchar_t absent[] = { L'b', L'b', 0 };
    wchar_t too_long[] = { L'a', L'b', L'a', L'b', L'a', L'b', L'a', L'b', 0 };

    if (wcswcs(haystack, first) != haystack)
        return 1;
    if (wcswcs(haystack, later) != haystack + 1)
        return 2;
    if (wcswcs(haystack, absent) != 0)
        return 3;
    return wcswcs(haystack, too_long) == 0 ? 0 : 4;
}

static int check_empty_haystack_and_no_mutation(void)
{
    wchar_t empty[] = { 0 };
    wchar_t nonempty[] = { L'x', 0 };
    wchar_t haystack[] = { L'm', L'u', L't', L'a', L'b', L'l', L'e', 0 };
    const wchar_t baseline[] = { L'm', L'u', L't', L'a', L'b', L'l', L'e', 0 };
    wchar_t needle[] = { L'a', L'b', L'l', 0 };

    if (wcswcs(empty, nonempty) != 0)
        return 1;
    if (wcswcs(haystack, needle) != haystack + 3)
        return 2;
    return units_match(haystack, baseline, sizeof(haystack) / sizeof(haystack[0]))
        ? 0 : 3;
}

static int check_full_wchar_domain_units(void)
{
    wchar_t haystack[] = {
        INT32_MIN, (wchar_t)0x10ffff, (wchar_t)0x00010437,
        INT32_MIN, (wchar_t)0x10ffff, 0,
    };
    wchar_t first[] = { INT32_MIN, (wchar_t)0x10ffff, 0 };
    wchar_t middle[] = { (wchar_t)0x10ffff, (wchar_t)0x00010437,
        INT32_MIN, 0 };
    wchar_t absent[] = { (wchar_t)0x00010437, (wchar_t)0x10ffff, 0 };

    if (wcswcs(haystack, first) != haystack)
        return 1;
    if (wcswcs(haystack, middle) != haystack + 1)
        return 2;
    return wcswcs(haystack, absent) == 0 ? 0 : 3;
}

int crabc_x86_64_wcswcs_probe(void)
{
    int result = check_empty_and_first_suffix();

    if (result != 0)
        return result;
    result = check_first_match_and_miss();
    if (result != 0)
        return 10 + result;
    result = check_empty_haystack_and_no_mutation();
    if (result != 0)
        return 20 + result;
    result = check_full_wchar_domain_units();
    return result == 0 ? 0 : 30 + result;
}

#ifndef CRABC_WCSWCS_FREESTANDING
int main(void)
{
    return crabc_x86_64_wcswcs_probe();
}
#endif
