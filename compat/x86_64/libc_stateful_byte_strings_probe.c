/* Static Linux/x86-64 caller-owned stateful byte-string ABI fixture.
 *
 * One project-header C body runs through pinned musl and then through a
 * one-member -nostdlib static candidate. It covers dirname's caller buffer,
 * strcasestr's fixed ASCII observations, and independent strtok_r save slots.
 */

#define _GNU_SOURCE

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <libgen.h>
#include <string.h>

#ifndef CRABC_STATEFUL_BYTE_STRINGS_FREESTANDING
#include <errno.h>
#endif

typedef char *(*dirname_signature)(char *);
typedef char *(*strcasestr_signature)(const char *, const char *);
typedef char *(*strtok_r_signature)(char *, const char *, char **);

_Static_assert(__builtin_types_compatible_p(__typeof__(&dirname), dirname_signature),
    "dirname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strcasestr), strcasestr_signature),
    "strcasestr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strtok_r), strtok_r_signature),
    "strtok_r declaration");

static int same_text(const char *left, const char *right)
{
    for (;;) {
        if (*left != *right)
            return 0;
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
}

static int check_dirname(dirname_signature function)
{
    static const struct {
        const char *input;
        const char *result;
        const char *after;
        int aliases;
    } cases[] = {
        {"", ".", "", 0},
        {"name", ".", "name", 0},
        {"dir/file", "dir", "dir", 1},
        {"dir//file", "dir", "dir", 1},
        {"dir/file///", "dir", "dir", 1},
        {"/file", "/", "/file", 0},
        {"/dir///file///", "/dir", "/dir", 1},
        {"/", "/", "/", 0},
        {"///", "/", "///", 0},
        {"//dir", "/", "//dir", 0},
    };
    unsigned long index;

    if (!same_text(function((char *)0), "."))
        return 1;
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char storage[64];
        char *result;
        unsigned long offset;

        for (offset = 0; ; ++offset) {
            storage[offset] = cases[index].input[offset];
            if (!storage[offset])
                break;
        }
        result = function(storage);
        if (!same_text(result, cases[index].result) ||
            !same_text(storage, cases[index].after))
            return 2 + (int)index * 3;
        if ((result == storage) != cases[index].aliases)
            return 3 + (int)index * 3;
    }
    return 0;
}

static int check_strcasestr(strcasestr_signature function)
{
    const char haystack[] = "AbC--alphabet--END";
    const char high_haystack[] = { 'x', (char)0xc0, 'y', '\0' };
    const char high_needle[] = { (char)0xe0, '\0' };

    if (function(haystack, "") != haystack)
        return 1;
    if (function(haystack, "aBc") != haystack)
        return 2;
    if (function(haystack, "ALPHA") != haystack + 5)
        return 3;
    if (function(haystack, "end") != haystack + 15)
        return 4;
    if (function(haystack, "alphabet--end!") != 0 ||
        function(haystack, "missing") != 0)
        return 5;
    return function(high_haystack, high_needle) == 0 ? 0 : 6;
}

static int check_strtok_r(strtok_r_signature function)
{
    char left[] = ",,alpha::beta,";
    char right[] = "red:blue";
    char whole[] = "whole";
    char high[] = { 'a', (char)0xff, 'b', '\0' };
    char separator[] = { (char)0xff, '\0' };
    char *left_state = (char *)1;
    char *right_state = (char *)1;
    char *state = 0;
    char *token;

    token = function(left, ",:", &left_state);
    if (token != left + 2 || !same_text(token, "alpha") || left_state != left + 8)
        return 1;
    token = function(right, ":", &right_state);
    if (token != right || !same_text(token, "red") || right_state != right + 4)
        return 2;
    token = function(0, ",:", &left_state);
    if (token != left + 9 || !same_text(token, "beta") || left_state != left + 14)
        return 3;
    if (function(0, ",:", &left_state) != 0 || left_state != 0)
        return 8;
    token = function(0, ":", &right_state);
    if (token != right + 4 || !same_text(token, "blue") || right_state != 0)
        return 4;
    if (function(whole, "", &state) != whole || state != 0 ||
        function(0, "", &state) != 0)
        return 5;
    token = function(high, separator, &state);
    if (token != high || high[1] != 0 || state != high + 2)
        return 6;
    return function(0, separator, &state) == high + 2 && state == 0 ? 0 : 7;
}

int crabc_x86_64_stateful_byte_strings_probe(void)
{
    int result;

#ifndef CRABC_STATEFUL_BYTE_STRINGS_FREESTANDING
    errno = E2BIG;
#endif
    result = check_dirname(dirname);
    if (result)
        return result;
    result = check_strcasestr(strcasestr);
    if (result)
        return 40 + result;
    result = check_strtok_r(strtok_r);
    if (result)
        return 80 + result;
#ifndef CRABC_STATEFUL_BYTE_STRINGS_FREESTANDING
    if (errno != E2BIG)
        return 120;
#endif
    return 0;
}

#ifndef CRABC_STATEFUL_BYTE_STRINGS_FREESTANDING
int main(void)
{
    return crabc_x86_64_stateful_byte_strings_probe();
}
#endif
