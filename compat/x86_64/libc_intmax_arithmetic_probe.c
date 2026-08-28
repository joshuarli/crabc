/* Static x86-64 intmax arithmetic C ABI and behavior fixture.
 *
 * `imaxabs` at INTMAX_MIN, a zero divisor, and INTMAX_MIN divided by -1 are
 * undefined C inputs. Every case below remains in the defined domain.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <inttypes.h>

_Static_assert(sizeof(intmax_t) == 8, "intmax_t width");
_Static_assert(sizeof(imaxdiv_t) == 16 && offsetof(imaxdiv_t, quot) == 0 &&
    offsetof(imaxdiv_t, rem) == 8, "imaxdiv_t layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&imaxabs),
    intmax_t (*)(intmax_t)), "imaxabs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&imaxdiv),
    imaxdiv_t (*)(intmax_t, intmax_t)), "imaxdiv declaration");

typedef intmax_t (*imaxabs_fn)(intmax_t);
typedef imaxdiv_t (*imaxdiv_fn)(intmax_t, intmax_t);

static int check_absolute_values(void)
{
    static const intmax_t values[] = {
        INTMAX_C(0), INTMAX_C(1), INTMAX_C(-1), INTMAX_C(37), INTMAX_C(-37),
        INTMAX_MIN + INTMAX_C(1), INTMAX_MAX,
    };
    const imaxabs_fn absolute = imaxabs;
    size_t index;

    for (index = 0; index < sizeof(values) / sizeof(values[0]); ++index) {
        intmax_t value = values[index];
        intmax_t expected = value < 0 ? -value : value;

        if (absolute(value) != expected)
            return 1;
    }
    return 0;
}

static int check_division(void)
{
    static const intmax_t cases[][2] = {
        { INTMAX_C(0), INTMAX_C(3) },
        { INTMAX_C(7), INTMAX_C(3) },
        { INTMAX_C(-7), INTMAX_C(3) },
        { INTMAX_C(7), INTMAX_C(-3) },
        { INTMAX_C(-7), INTMAX_C(-3) },
        { INTMAX_C(1), INTMAX_C(2) },
        { INTMAX_C(-1), INTMAX_C(2) },
        { INTMAX_MAX, INTMAX_C(2) },
        { INTMAX_MIN + INTMAX_C(1), INTMAX_C(2) },
    };
    const imaxdiv_fn divide = imaxdiv;
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        intmax_t numerator = cases[index][0];
        intmax_t denominator = cases[index][1];
        imaxdiv_t result = divide(numerator, denominator);

        if (result.quot != numerator / denominator ||
            result.rem != numerator % denominator ||
            numerator != result.quot * denominator + result.rem ||
            (result.rem != 0 && ((result.rem < 0) != (numerator < 0))))
            return 1;
    }
    return 0;
}

int crabc_x86_64_intmax_arithmetic_probe(void)
{
    int status = check_absolute_values();

    if (status != 0)
        return 10 + status;
    status = check_division();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_INTMAX_ARITHMETIC_FREESTANDING
int main(void)
{
    return crabc_x86_64_intmax_arithmetic_probe();
}
#endif
