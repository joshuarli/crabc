/* Static Linux/x86-64 strsep C ABI and mutation-behavior fixture. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef char *(*strsep_signature)(char **, const char *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&strsep), strsep_signature),
    "strsep declaration");

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

static int check_basic_sequence(void)
{
    char values[] = "alpha,beta,,gamma,";
    char delimiter[] = ",";
    static const unsigned char expected[] = {
        'a', 'l', 'p', 'h', 'a', 0,
        'b', 'e', 't', 'a', 0, 0,
        'g', 'a', 'm', 'm', 'a', 0, 0,
    };
    char *state = values;
    char *token;

    token = strsep(&state, delimiter);
    if (token != values || !c_string_equal(token, "alpha") || state != values + 6)
        return 1;
    token = strsep(&state, delimiter);
    if (token != values + 6 || !c_string_equal(token, "beta") || state != values + 11)
        return 2;
    token = strsep(&state, delimiter);
    if (token != values + 11 || !c_string_equal(token, "") || state != values + 12)
        return 3;
    token = strsep(&state, delimiter);
    if (token != values + 12 || !c_string_equal(token, "gamma") || state != values + 18)
        return 4;
    token = strsep(&state, delimiter);
    if (token != values + 18 || !c_string_equal(token, "") || state != 0)
        return 5;
    if (strsep(&state, delimiter) != 0 || state != 0)
        return 6;
    if (!bytes_equal((const unsigned char *)values, expected, sizeof(expected)))
        return 7;
    if (delimiter[0] != ',' || delimiter[1] != '\0')
        return 8;
    return 0;
}

static int check_delimiter_set_sequence(void)
{
    char values[] = "|one,two||";
    char delimiter[] = "|,";
    static const unsigned char expected[] = {
        0, 'o', 'n', 'e', 0, 't', 'w', 'o', 0, 0, 0,
    };
    char *state = values;
    char *token;

    token = strsep(&state, delimiter);
    if (token != values || !c_string_equal(token, "") || state != values + 1)
        return 1;
    token = strsep(&state, delimiter);
    if (token != values + 1 || !c_string_equal(token, "one") || state != values + 5)
        return 2;
    token = strsep(&state, delimiter);
    if (token != values + 5 || !c_string_equal(token, "two") || state != values + 9)
        return 3;
    token = strsep(&state, delimiter);
    if (token != values + 9 || !c_string_equal(token, "") || state != values + 10)
        return 4;
    token = strsep(&state, delimiter);
    if (token != values + 10 || !c_string_equal(token, "") || state != 0)
        return 5;
    if (strsep(&state, delimiter) != 0 || state != 0)
        return 6;
    if (!bytes_equal((const unsigned char *)values, expected, sizeof(expected)))
        return 7;
    if (delimiter[0] != '|' || delimiter[1] != ',' || delimiter[2] != '\0')
        return 8;
    return 0;
}

static int check_no_separator_cases(void)
{
    char empty_delimiter_values[] = "plain";
    char empty_delimiter[] = "";
    char no_match_values[] = "plain";
    char no_match_delimiter[] = ";";
    char empty_values[] = "";
    char *state;
    char *token;

    state = empty_delimiter_values;
    token = strsep(&state, empty_delimiter);
    if (token != empty_delimiter_values || !c_string_equal(token, "plain") || state != 0)
        return 1;
    if (empty_delimiter_values[5] != '\0' || empty_delimiter[0] != '\0')
        return 2;

    state = no_match_values;
    token = strsep(&state, no_match_delimiter);
    if (token != no_match_values || !c_string_equal(token, "plain") || state != 0)
        return 3;
    if (no_match_values[5] != '\0' || no_match_delimiter[0] != ';' ||
        no_match_delimiter[1] != '\0')
        return 4;

    state = empty_values;
    token = strsep(&state, no_match_delimiter);
    if (token != empty_values || *token != '\0' || state != 0)
        return 5;
    if (strsep(&state, no_match_delimiter) != 0 || state != 0)
        return 6;
    return 0;
}

static int check_unsigned_delimiter_byte(void)
{
    char values[] = { (char)0x81, (char)0xff, 'x', '\0' };
    char delimiter[] = { (char)0xff, '\0' };
    char *state = values;
    char *token;

    token = strsep(&state, delimiter);
    if (token != values || (unsigned char)token[0] != 0x81U || token[1] != '\0' ||
        state != values + 2)
        return 1;
    if ((unsigned char)values[0] != 0x81U || values[1] != '\0' || values[2] != 'x' ||
        values[3] != '\0' || (unsigned char)delimiter[0] != 0xffU ||
        delimiter[1] != '\0')
        return 2;
    token = strsep(&state, delimiter);
    if (token != values + 2 || !c_string_equal(token, "x") || state != 0)
        return 3;
    return 0;
}

static int check_null_state_value(void)
{
    char *state = 0;

    return strsep(&state, ",") != 0 || state != 0;
}

int crabc_x86_64_strsep_probe(void)
{
    int result;

    result = check_basic_sequence();
    if (result != 0)
        return result;
    result = check_delimiter_set_sequence();
    if (result != 0)
        return 16 + result;
    result = check_no_separator_cases();
    if (result != 0)
        return 32 + result;
    result = check_unsigned_delimiter_byte();
    if (result != 0)
        return 48 + result;
    return check_null_state_value() ? 64 : 0;
}

#ifndef CRABC_STRSEP_FREESTANDING
int main(void)
{
    return crabc_x86_64_strsep_probe();
}
#endif
