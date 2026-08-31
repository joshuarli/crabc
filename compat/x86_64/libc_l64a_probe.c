/* Static Linux/x86-64 l64a C ABI and behavior fixture.
 *
 * One X/Open 700 project-header C body runs through pinned musl 1.2.6 and
 * then through a selected one-member `-nostdlib -static` crabc archive. It
 * proves only l64a's low-32-bit, low-to-high radix-64 encoder and the one
 * shared seven-byte static result buffer. It leaves sibling a64l decoding,
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

#ifndef CRABC_L64A_FREESTANDING
#include <errno.h>
#endif

typedef char *(*l64a_signature)(long);

_Static_assert(sizeof(long) == 8, "x86 LP64 long");
_Static_assert(__builtin_types_compatible_p(__typeof__(&l64a), l64a_signature),
    "l64a declaration");

static int text_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int check_alphabet_and_order(l64a_signature function)
{
    if (!text_equal(function(0), "")) return 1;
    if (!text_equal(function(1), "/")) return 2;
    if (!text_equal(function(2), "0") || !text_equal(function(11), "9")) return 3;
    if (!text_equal(function(12), "A") || !text_equal(function(37), "Z")) return 4;
    if (!text_equal(function(38), "a") || !text_equal(function(63), "z")) return 5;
    if (!text_equal(function(64), "./")) return 6;
    if (!text_equal(function((1L << 6) | (2L << 12) | (12L << 18) |
                             (63L << 24)), "./0Az")) return 7;
    return 0;
}

static int check_low_32_bits(l64a_signature function)
{
    if (!text_equal(function(-1L), "zzzzz1")) return 1;
    if (!text_equal(function(1L << 32), "")) return 2;
    if (!text_equal(function((1L << 32) | 64L), "./")) return 3;
    return 0;
}

static int check_shared_buffer(l64a_signature function)
{
    char *first = function(1);
    char *second;

    if (!first || !text_equal(first, "/")) return 1;
    second = function(64);
    if (!second || second != first || !text_equal(second, "./")) return 2;
    if (!text_equal(first, "./")) return 3;
    if (function(0) != first || !text_equal(first, "")) return 4;
    return 0;
}

int crabc_x86_64_l64a_probe(void)
{
    const l64a_signature function = l64a;
    int result;

#ifndef CRABC_L64A_FREESTANDING
    errno = E2BIG;
#endif

    result = check_alphabet_and_order(function);
    if (result != 0) return result;
    result = check_low_32_bits(function);
    if (result != 0) return 10 + result;
    result = check_shared_buffer(function);
    if (result != 0) return 20 + result;

#ifndef CRABC_L64A_FREESTANDING
    if (errno != E2BIG) return 40;
#endif
    return 0;
}

#ifndef CRABC_L64A_FREESTANDING
int main(void)
{
    return crabc_x86_64_l64a_probe();
}
#endif
