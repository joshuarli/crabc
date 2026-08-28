/* Static x86-64 integer arithmetic ABI and behavior fixture.
 *
 * C leaves abs/labs/llabs at their signed-minimum input, zero divisors, and
 * signed-minimum divided by -1 undefined. Every case below remains in the
 * defined domain, including the nearest signed-minimum values.
 */

#include <stddef.h>
#include <stdlib.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "integer widths");
_Static_assert(sizeof(div_t) == 8 && offsetof(div_t, quot) == 0 &&
    offsetof(div_t, rem) == 4, "div_t layout");
_Static_assert(sizeof(ldiv_t) == 16 && offsetof(ldiv_t, quot) == 0 &&
    offsetof(ldiv_t, rem) == 8, "ldiv_t layout");
_Static_assert(sizeof(lldiv_t) == 16 && offsetof(lldiv_t, quot) == 0 &&
    offsetof(lldiv_t, rem) == 8, "lldiv_t layout");

typedef int (*abs_fn)(int);
typedef long (*labs_fn)(long);
typedef long long (*llabs_fn)(long long);
typedef div_t (*div_fn)(int, int);
typedef ldiv_t (*ldiv_fn)(long, long);
typedef lldiv_t (*lldiv_fn)(long long, long long);

static int check_absolute_values(void)
{
    static const int ints[] = { 0, 1, -1, 37, -37, 2147483647 };
    static const long longs[] = { 0, 1, -1, 37, -37, 9223372036854775807L };
    static const long long ll_values[] = {
        0, 1, -1, 37, -37, 9223372036854775807LL
    };
    const abs_fn absolute = abs;
    const labs_fn long_absolute = labs;
    const llabs_fn long_long_absolute = llabs;
    size_t index;

    for (index = 0; index < sizeof(ints) / sizeof(ints[0]); ++index)
        if (absolute(ints[index]) != (ints[index] < 0 ? -ints[index] : ints[index]))
            return 1;
    for (index = 0; index < sizeof(longs) / sizeof(longs[0]); ++index)
        if (long_absolute(longs[index]) != (longs[index] < 0 ? -longs[index] : longs[index]))
            return 2;
    for (index = 0; index < sizeof(ll_values) / sizeof(ll_values[0]); ++index)
        if (long_long_absolute(ll_values[index]) !=
                (ll_values[index] < 0 ? -ll_values[index] : ll_values[index]))
            return 3;
    return 0;
}

static int check_division(void)
{
    static const int int_cases[][2] = {
        { 0, 3 }, { 7, 3 }, { -7, 3 }, { 7, -3 }, { -7, -3 },
        { 1, 2 }, { -1, 2 }, { 2147483647, 2 }, { -2147483647, 2 }
    };
    static const long long_cases[][2] = {
        { 0, 3 }, { 7, 3 }, { -7, 3 }, { 7, -3 }, { -7, -3 },
        { 1, 2 }, { -1, 2 }, { 9223372036854775807L, 2 },
        { -9223372036854775807L, 2 }
    };
    static const long long ll_cases[][2] = {
        { 0, 3 }, { 7, 3 }, { -7, 3 }, { 7, -3 }, { -7, -3 },
        { 1, 2 }, { -1, 2 }, { 9223372036854775807LL, 2 },
        { -9223372036854775807LL, 2 }
    };
    const div_fn divide = div;
    const ldiv_fn long_divide = ldiv;
    const lldiv_fn long_long_divide = lldiv;
    size_t index;

    for (index = 0; index < sizeof(int_cases) / sizeof(int_cases[0]); ++index) {
        int numerator = int_cases[index][0], denominator = int_cases[index][1];
        div_t result = divide(numerator, denominator);
        if (result.quot != numerator / denominator ||
            result.rem != numerator % denominator ||
            numerator != result.quot * denominator + result.rem ||
            (result.rem != 0 && ((result.rem < 0) != (numerator < 0))))
            return 1;
    }
    for (index = 0; index < sizeof(long_cases) / sizeof(long_cases[0]); ++index) {
        long numerator = long_cases[index][0], denominator = long_cases[index][1];
        ldiv_t result = long_divide(numerator, denominator);
        if (result.quot != numerator / denominator ||
            result.rem != numerator % denominator ||
            numerator != result.quot * denominator + result.rem ||
            (result.rem != 0 && ((result.rem < 0) != (numerator < 0))))
            return 2;
    }
    for (index = 0; index < sizeof(ll_cases) / sizeof(ll_cases[0]); ++index) {
        long long numerator = ll_cases[index][0], denominator = ll_cases[index][1];
        lldiv_t result = long_long_divide(numerator, denominator);
        if (result.quot != numerator / denominator ||
            result.rem != numerator % denominator ||
            numerator != result.quot * denominator + result.rem ||
            (result.rem != 0 && ((result.rem < 0) != (numerator < 0))))
            return 3;
    }
    return 0;
}

int crabc_x86_64_integer_arithmetic_probe(void)
{
    int status = check_absolute_values();
    if (status != 0)
        return 10 + status;
    status = check_division();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_INTEGER_ARITHMETIC_FREESTANDING
int main(void)
{
    return crabc_x86_64_integer_arithmetic_probe();
}
#endif
