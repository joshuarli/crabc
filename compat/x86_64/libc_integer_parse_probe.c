/* Static x86-64 integer parsing behavior fixture.
 *
 * This is a complete narrow strto* family: its cases ratchet end-pointer
 * movement, stale errno on successful conversion, musl's EINVAL paths, and
 * signed/unsigned range boundaries. atoi/atol/atoll are separately exercised
 * only on inputs whose result is representable in their result type.
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "integer widths");
_Static_assert(sizeof(intmax_t) == sizeof(long), "x86 LP64 intmax_t width");
_Static_assert(sizeof(uintmax_t) == sizeof(unsigned long), "x86 LP64 uintmax_t width");

typedef long (*strtol_fn)(const char *, char **, int);
typedef unsigned long (*strtoul_fn)(const char *, char **, int);
typedef long long (*strtoll_fn)(const char *, char **, int);
typedef unsigned long long (*strtoull_fn)(const char *, char **, int);
typedef intmax_t (*strtoimax_fn)(const char *, char **, int);
typedef uintmax_t (*strtoumax_fn)(const char *, char **, int);

static int expect_long(strtol_fn parse, const char *input, int base,
    long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_long_long(strtoll_fn parse, const char *input, int base,
    long long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_intmax(strtoimax_fn parse, const char *input, int base,
    intmax_t expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_ulong(strtoul_fn parse, const char *input, int base,
    unsigned long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_ulong_long(strtoull_fn parse, const char *input, int base,
    unsigned long long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_uintmax(strtoumax_fn parse, const char *input, int base,
    uintmax_t expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int check_signed_parsers(void)
{
    const strtol_fn parse_long = strtol;
    const strtoll_fn parse_long_long = strtoll;
    const strtoimax_fn parse_intmax = strtoimax;
    int status;

    status = expect_long(parse_long, " \t-42tail", 10, -42L, 5, EINTR, EINTR);
    if (status != 0) return 10 + status;
    status = expect_long(parse_long, "0x2a!", 0, 42L, 4, EDOM, EDOM);
    if (status != 0) return 20 + status;
    status = expect_long(parse_long, "077z", 0, 63L, 3, EILSEQ, EILSEQ);
    if (status != 0) return 30 + status;
    status = expect_long(parse_long, "0Xf?", 16, 15L, 3, EINTR, EINTR);
    if (status != 0) return 40 + status;
    status = expect_long(parse_long, "1012", 2, 5L, 3, EDOM, EDOM);
    if (status != 0) return 50 + status;
    status = expect_long(parse_long, "0x", 0, 0L, 1, EINTR, EINTR);
    if (status != 0) return 60 + status;
    status = expect_long(parse_long, "0xg", 0, 0L, 1, EDOM, EDOM);
    if (status != 0) return 65 + status;
    status = expect_long(parse_long, "+", 10, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 70 + status;
    status = expect_long(parse_long, "\xa0", 10, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 80 + status;
    status = expect_long(parse_long, "42", 1, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 90 + status;
    status = expect_long(parse_long, "42", -1, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 95 + status;
    status = expect_long(parse_long, "z!", 36, 35L, 1, EDOM, EDOM);
    if (status != 0) return 98 + status;
    status = expect_long(parse_long, "9223372036854775807", 10, LONG_MAX, 19,
        EINTR, EINTR);
    if (status != 0) return 100 + status;
    status = expect_long(parse_long, "9223372036854775808", 10, LONG_MAX, 19,
        EDOM, ERANGE);
    if (status != 0) return 110 + status;
    status = expect_long(parse_long, "-9223372036854775808", 10, LONG_MIN, 20,
        EINTR, EINTR);
    if (status != 0) return 120 + status;
    status = expect_long(parse_long, "-9223372036854775809", 10, LONG_MIN, 20,
        EDOM, ERANGE);
    if (status != 0) return 130 + status;

    status = expect_long_long(parse_long_long, "-9223372036854775808", 10,
        LLONG_MIN, 20, EINTR, EINTR);
    if (status != 0) return 140 + status;
    status = expect_long_long(parse_long_long, "9223372036854775808", 10,
        LLONG_MAX, 19, EDOM, ERANGE);
    if (status != 0) return 150 + status;
    status = expect_intmax(parse_intmax, "-9223372036854775808", 10,
        INTMAX_MIN, 20, EINTR, EINTR);
    if (status != 0) return 160 + status;
    status = expect_intmax(parse_intmax, "9223372036854775808", 10,
        INTMAX_MAX, 19, EDOM, ERANGE);
    return status == 0 ? 0 : 170 + status;
}

static int check_unsigned_parsers(void)
{
    const strtoul_fn parse_ulong = strtoul;
    const strtoull_fn parse_ulong_long = strtoull;
    const strtoumax_fn parse_uintmax = strtoumax;
    int status;

    status = expect_ulong(parse_ulong, "-1", 10, ULONG_MAX, 2, EINTR, EINTR);
    if (status != 0) return 10 + status;
    status = expect_ulong(parse_ulong, "0xFf!", 0, 255UL, 4, EDOM, EDOM);
    if (status != 0) return 20 + status;
    status = expect_ulong(parse_ulong, "0x", 16, 0UL, 1, EINTR, EINTR);
    if (status != 0) return 30 + status;
    status = expect_ulong(parse_ulong, "-0xF!", 0, ULONG_MAX - 14UL, 4,
        EDOM, EDOM);
    if (status != 0) return 35 + status;
    status = expect_ulong(parse_ulong, "18446744073709551615", 10, ULONG_MAX, 20,
        EINTR, EINTR);
    if (status != 0) return 40 + status;
    status = expect_ulong(parse_ulong, "18446744073709551616", 10, ULONG_MAX, 20,
        EDOM, ERANGE);
    if (status != 0) return 50 + status;
    status = expect_ulong(parse_ulong, "-18446744073709551616", 10, ULONG_MAX, 21,
        EDOM, ERANGE);
    if (status != 0) return 60 + status;
    status = expect_ulong(parse_ulong, "$", 10, 0UL, 0, EDOM, EINVAL);
    if (status != 0) return 70 + status;

    status = expect_ulong_long(parse_ulong_long, "18446744073709551615", 10,
        ULLONG_MAX, 20, EINTR, EINTR);
    if (status != 0) return 80 + status;
    status = expect_ulong_long(parse_ulong_long, "18446744073709551616", 10,
        ULLONG_MAX, 20, EDOM, ERANGE);
    if (status != 0) return 90 + status;
    status = expect_uintmax(parse_uintmax, "18446744073709551615", 10,
        UINTMAX_MAX, 20, EINTR, EINTR);
    if (status != 0) return 100 + status;
    status = expect_uintmax(parse_uintmax, "18446744073709551616", 10,
        UINTMAX_MAX, 20, EDOM, ERANGE);
    return status == 0 ? 0 : 110 + status;
}

static int check_convenience_parsers(void)
{
    errno = EDOM;
    if (atoi(" \t-42tail") != -42 || errno != EDOM)
        return 1;
    errno = EINTR;
    if (atoi("-2147483648") != INT_MIN || errno != EINTR)
        return 2;
    errno = EDOM;
    if (atol("-9223372036854775808") != LONG_MIN || errno != EDOM)
        return 3;
    errno = EINTR;
    if (atoll("-9223372036854775808") != LLONG_MIN || errno != EINTR)
        return 4;
    errno = EDOM;
    if (atoi("0x10") != 0 || errno != EDOM)
        return 5;
    return 0;
}

int crabc_x86_64_integer_parse_probe(void)
{
    int status = check_signed_parsers();
    if (status != 0)
        return status;
    status = check_unsigned_parsers();
    if (status != 0)
        return 200 + status;
    status = check_convenience_parsers();
    return status == 0 ? 0 : 400 + status;
}

#ifndef CRABC_INTEGER_PARSE_FREESTANDING
int main(void)
{
    return crabc_x86_64_integer_parse_probe();
}
#endif
