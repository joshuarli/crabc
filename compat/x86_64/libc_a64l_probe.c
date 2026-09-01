/* Static Linux/x86-64 a64l C ABI and behavior fixture.
 *
 * One X/Open 700 project-header C body runs first through pinned musl 1.2.6
 * and then through an opt-in `-nostdlib -static` crabc archive. It proves
 * only musl's state-free radix-64 decoder: all digit values, low-to-high
 * packing, invalid-byte stopping, the six-byte bound, signed int32_t result,
 * and caller-input immutability. It leaves l64a's shared result storage,
 * general numeric conversion, errno/TLS, locale, allocation, and C runtime
 * state outside this artifact.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#ifndef CRABC_A64L_FREESTANDING
#include <errno.h>
#endif

typedef long (*a64l_signature)(const char *);

_Static_assert(sizeof(long) == 8, "x86 LP64 long");
_Static_assert(__builtin_types_compatible_p(__typeof__(&a64l), a64l_signature),
    "a64l declaration");

static int check_alphabet(a64l_signature function)
{
    static const char digits[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char input[2] = { 0, 0 };
    size_t index;

    for (index = 0; index < sizeof(digits) - 1; ++index) {
        input[0] = digits[index];
        if (function(input) != (long)index)
            return (int)index + 1;
    }
    return 0;
}

static int check_bit_packing(a64l_signature function)
{
    const long expected = (1L << 6) | (2L << 12) | (12L << 18) | (63L << 24);

    return function("./0Az") == expected ? 0 : 1;
}

static int check_invalid_and_bound(a64l_signature function)
{
    static const char high_bit[] = { '2', (char)0x80, 'z', 0 };
    static const char nul_with_suffix[] = { '2', 0, 'z', 0 };

    if (function("/0Z?z") != function("/0Z"))
        return 1;
    if (function("?z") != 0)
        return 2;
    if (function(high_bit) != function("2"))
        return 3;
    if (function(nul_with_suffix) != function("2"))
        return 4;
    if (function("zzzzzz/") != function("zzzzzz"))
        return 5;
    return function("zzzzzz") == -1L ? 0 : 6;
}

static int check_signed_result(a64l_signature function)
{
    return function(".....0") == -2147483648L ? 0 : 1;
}

static int check_input_is_unchanged(a64l_signature function)
{
    char input[] = "/0Z?z";
    char before[sizeof(input)];
    size_t index;

    for (index = 0; index < sizeof(input); ++index)
        before[index] = input[index];
    (void)function(input);
    for (index = 0; index < sizeof(input); ++index) {
        if (input[index] != before[index])
            return 1;
    }
    return 0;
}

int crabc_x86_64_a64l_probe(void)
{
    const a64l_signature function = a64l;
    int result;

#ifndef CRABC_A64L_FREESTANDING
    errno = E2BIG;
#endif

    result = check_alphabet(function);
    if (result != 0) return result;
    result = check_bit_packing(function);
    if (result != 0) return 70 + result;
    result = check_invalid_and_bound(function);
    if (result != 0) return 80 + result;
    result = check_signed_result(function);
    if (result != 0) return 90 + result;
    result = check_input_is_unchanged(function);
    if (result != 0) return 100 + result;

#ifndef CRABC_A64L_FREESTANDING
    if (errno != E2BIG) return 120;
#endif
    return 0;
}

#ifndef CRABC_A64L_FREESTANDING
int main(void)
{
    return crabc_x86_64_a64l_probe();
}
#endif
