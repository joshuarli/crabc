/* Static Linux/x86-64 rand_r C ABI and caller-state behavior fixture. */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

typedef int (*rand_r_signature)(unsigned *);

_Static_assert(sizeof(unsigned) == 4, "rand_r unsigned width");
_Static_assert(sizeof(int) == 4, "rand_r int width");
_Static_assert(RAND_MAX == 0x7fffffff, "rand_r result bound");
_Static_assert(__builtin_types_compatible_p(__typeof__(&rand_r), rand_r_signature),
    "rand_r declaration");

static int check_vector(unsigned initial_seed, unsigned expected_seed,
    int expected_value)
{
    unsigned seed = initial_seed;
    int value = rand_r(&seed);

    if (value != expected_value)
        return 1;
    if (seed != expected_seed)
        return 2;
    if (value < 0 || value > RAND_MAX)
        return 3;
    return 0;
}

static int check_function_pointer(void)
{
    rand_r_signature function = rand_r;
    unsigned seed = 1U;
    int value = function(&seed);

    if (value != 1993684161)
        return 1;
    if (seed != 0x41c67ea6U)
        return 2;
    return 0;
}

int crabc_x86_64_rand_r_probe(void)
{
    int result;

    result = check_vector(0U, 0x00003039U, 27726646);
    if (result != 0)
        return result;
    result = check_vector(1U, 0x41c67ea6U, 1993684161);
    if (result != 0)
        return 8 + result;
    result = check_vector(0x12345678U, 0x0b719151U, 2051959138);
    if (result != 0)
        return 16 + result;
    result = check_vector(0xffffffffU, 0xbe39e1ccU, 1077357429);
    if (result != 0)
        return 24 + result;
    result = check_function_pointer();
    return result == 0 ? 0 : 32 + result;
}

#ifndef CRABC_RAND_R_FREESTANDING
int main(void)
{
    return crabc_x86_64_rand_r_probe();
}
#endif
