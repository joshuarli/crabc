/* Static x86-64 find-first-set C ABI and behavior fixture.
 *
 * `ffs`, `ffsl`, and `ffsll` return one plus the least-significant set-bit
 * index, or zero for zero. Negative values are valid two's-complement input
 * bit patterns on this Linux/x86-64 LP64 target.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <strings.h>

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "find-first-set scalar widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ffs), int (*)(int)),
    "ffs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ffsl), int (*)(long)),
    "ffsl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ffsll), int (*)(long long)),
    "ffsll declaration");

typedef int (*ffs_fn)(int);
typedef int (*ffsl_fn)(long);
typedef int (*ffsll_fn)(long long);

static int first_set_u32(uint32_t value)
{
    int position = 0;

    while (value != 0) {
        ++position;
        if ((value & 1U) != 0)
            return position;
        value >>= 1;
    }
    return 0;
}

static int first_set_u64(uint64_t value)
{
    int position = 0;

    while (value != 0) {
        ++position;
        if ((value & UINT64_C(1)) != 0)
            return position;
        value >>= 1;
    }
    return 0;
}

static int check_int_values(void)
{
    static const struct {
        int value;
        int expected;
    } cases[] = {
        { 0, 0 }, { 1, 1 }, { 2, 2 }, { 3, 1 }, { 4, 3 }, { 1 << 30, 31 },
        { -1, 1 }, { -2, 2 }, { -2147483647 - 1, 32 },
    };
    const ffs_fn function = ffs;
    unsigned index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (first_set_u32((uint32_t)cases[index].value) != cases[index].expected ||
            function(cases[index].value) != cases[index].expected)
            return 1;
    }
    return 0;
}

static int check_long_values(void)
{
    static const struct {
        long value;
        int expected;
    } cases[] = {
        { 0L, 0 }, { 1L, 1 }, { 2L, 2 }, { 3L, 1 }, { 4L, 3 },
        { 1L << 32, 33 }, { 1L << 62, 63 }, { -1L, 1 }, { -2L, 2 },
        { -9223372036854775807L - 1L, 64 },
    };
    const ffsl_fn function = ffsl;
    unsigned index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (first_set_u64((uint64_t)cases[index].value) != cases[index].expected ||
            function(cases[index].value) != cases[index].expected)
            return 1;
    }
    return 0;
}

static int check_long_long_values(void)
{
    static const struct {
        long long value;
        int expected;
    } cases[] = {
        { 0LL, 0 }, { 1LL, 1 }, { 2LL, 2 }, { 3LL, 1 }, { 4LL, 3 },
        { 1LL << 32, 33 }, { 1LL << 62, 63 }, { -1LL, 1 }, { -2LL, 2 },
        { -9223372036854775807LL - 1LL, 64 },
    };
    const ffsll_fn function = ffsll;
    unsigned index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (first_set_u64((uint64_t)cases[index].value) != cases[index].expected ||
            function(cases[index].value) != cases[index].expected)
            return 1;
    }
    return 0;
}

int crabc_x86_64_ffs_probe(void)
{
    int status = check_int_values();

    if (status != 0)
        return 10 + status;
    status = check_long_values();
    if (status != 0)
        return 20 + status;
    status = check_long_long_values();
    return status == 0 ? 0 : 30 + status;
}

#ifndef CRABC_FFS_FREESTANDING
int main(void)
{
    return crabc_x86_64_ffs_probe();
}
#endif
