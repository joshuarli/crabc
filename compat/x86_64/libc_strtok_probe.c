/* Static Linux/x86-64 strtok C ABI and mutation-behavior fixture.
 *
 * The same project-header C body runs first through pinned musl 1.2.6 and
 * then through one extracted `-nostdlib -static` crabc archive member. It
 * proves musl's one shared historical continuation cursor, not a reentrant or
 * thread-safe tokenizer contract.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

#ifndef CRABC_STRTOK_FREESTANDING
#include <errno.h>
#endif

typedef char *(*strtok_signature)(char *, const char *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&strtok), strtok_signature),
    "strtok declaration");

static int bytes_equal(const unsigned char *actual, const unsigned char *expected,
    size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if (actual[index] != expected[index])
            return 0;
    }
    return 1;
}

static int c_string_equal(const char *actual, const char *expected)
{
    for (;;) {
        if (*actual != *expected)
            return 0;
        if (*actual == '\0')
            return 1;
        ++actual;
        ++expected;
    }
}

static int check_primary_sequence(strtok_signature function)
{
    char input[] = ",,alpha::beta,gamma,,";
    static const unsigned char expected[] = {
        ',', ',', 'a', 'l', 'p', 'h', 'a', 0, ':', 'b', 'e', 't', 'a', 0,
        'g', 'a', 'm', 'm', 'a', 0, ',', 0,
    };
    char *token;

    token = function(input, ",:");
    if (token != input + 2 || !c_string_equal(token, "alpha"))
        return 1;
    token = function(0, ",:");
    if (token != input + 9 || !c_string_equal(token, "beta"))
        return 2;
    token = function(0, ",:");
    if (token != input + 14 || !c_string_equal(token, "gamma"))
        return 3;
    if (function(0, ",:") != 0)
        return 4;
    if (function(0, ",:") != 0)
        return 5;
    return bytes_equal((const unsigned char *)input, expected, sizeof(expected)) ? 0 : 6;
}

static int check_empty_and_empty_separator(strtok_signature function)
{
    char empty[] = "";
    char delimiters[] = ";;;";
    char whole[] = "whole token";
    char *token;

    if (function(empty, ",") != 0 || function(0, ",") != 0)
        return 1;
    if (function(delimiters, ";") != 0 || function(0, ";") != 0)
        return 2;
    token = function(whole, "");
    if (token != whole || !c_string_equal(token, "whole token") || function(0, "") != 0)
        return 3;
    return whole[11] == '\0' ? 0 : 4;
}

static int check_replacement_and_shared_cursor(strtok_signature function)
{
    char first[] = "one,two";
    char replacement[] = "replacement";
    char left[] = "left,right";
    char right[] = "red:blue";
    char *token;

    token = function(first, ",");
    if (token != first || !c_string_equal(token, "one") || first[3] != '\0')
        return 1;
    token = function(replacement, ",");
    if (token != replacement || !c_string_equal(token, "replacement") ||
        function(0, ",") != 0)
        return 2;

    token = function(left, ",");
    if (token != left || !c_string_equal(token, "left") || left[4] != '\0')
        return 3;
    token = function(right, ":");
    if (token != right || !c_string_equal(token, "red") || right[3] != '\0')
        return 4;
    token = function(0, ":");
    if (token != right + 4 || !c_string_equal(token, "blue"))
        return 5;
    if (function(0, ":") != 0)
        return 6;
    return left[5] == 'r' && right[8] == '\0' ? 0 : 7;
}

static int check_high_byte_separator(strtok_signature function)
{
    char input[] = { 'a', (char)0xff, 'b', '\0' };
    char separators[] = { (char)0xff, '\0' };
    char *token;

    token = function(input, separators);
    if (token != input || !c_string_equal(token, "a") || input[1] != '\0')
        return 1;
    token = function(0, separators);
    if (token != input + 2 || !c_string_equal(token, "b"))
        return 2;
    if (function(0, separators) != 0)
        return 3;
    return (unsigned char)separators[0] == 0xffU ? 0 : 4;
}

int crabc_x86_64_strtok_probe(void)
{
    const strtok_signature function = strtok;
    int result;

#ifndef CRABC_STRTOK_FREESTANDING
    errno = E2BIG;
#endif

    result = check_primary_sequence(function);
    if (result != 0)
        return result;
    result = check_empty_and_empty_separator(function);
    if (result != 0)
        return 16 + result;
    result = check_replacement_and_shared_cursor(function);
    if (result != 0)
        return 32 + result;
    result = check_high_byte_separator(function);
    if (result != 0)
        return 48 + result;

#ifndef CRABC_STRTOK_FREESTANDING
    if (errno != E2BIG)
        return 64;
#endif
    return 0;
}

#ifndef CRABC_STRTOK_FREESTANDING
int main(void)
{
    return crabc_x86_64_strtok_probe();
}
#endif
