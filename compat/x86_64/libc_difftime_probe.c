/* Static crabc-libc x86-64 binary64 difftime fixture.
 *
 * The same project-header C body executes first through pinned musl 1.2.6
 * and then through a freestanding candidate linked solely with the selected
 * crabc archive. It admits only the scalar time_t-to-double calculation.
 * Function-pointer calls suppress compiler builtins. The endpoint cases stay
 * inside musl's signed-subtraction C domain: no cross-endpoint overflow pair
 * is a selected contract. This is not clock observation, timezone state,
 * calendar conversion, formatting, a floating-environment policy, timer
 * behavior, CRT, loader, sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <time.h>

_Static_assert(sizeof(time_t) == 8, "x86 time_t width");
_Static_assert(sizeof(double) == 8, "x86 binary64 double");
_Static_assert(__builtin_types_compatible_p(__typeof__(&difftime),
    double (*)(time_t, time_t)), "difftime declaration");

typedef double (*difftime_function)(time_t, time_t);

/* Parentheses retain the callable C ABI boundary rather than a builtin. */
static difftime_function volatile direct_difftime = (difftime);

static uint64_t double_bits(double value)
{
    union {
        double value;
        uint64_t bits;
    } view = { .value = value };
    return view.bits;
}

static int check_ordinary_values(void)
{
    if (double_bits(direct_difftime((time_t)7, (time_t)3)) !=
        UINT64_C(0x4010000000000000))
        return 1;
    if (double_bits(direct_difftime((time_t)-3, (time_t)7)) !=
        UINT64_C(0xc024000000000000))
        return 2;
    if (double_bits(direct_difftime((time_t)0, (time_t)0)) != 0)
        return 3;
    return 0;
}

static int check_endpoint_values(void)
{
    if (double_bits(direct_difftime((time_t)INT64_MAX, (time_t)0)) !=
        UINT64_C(0x43e0000000000000))
        return 1;
    if (double_bits(direct_difftime((time_t)INT64_MIN, (time_t)0)) !=
        UINT64_C(0xc3e0000000000000))
        return 2;
    if (double_bits(direct_difftime((time_t)INT64_MAX,
        (time_t)(INT64_MAX - INT64_C(1)))) != UINT64_C(0x3ff0000000000000))
        return 3;
    if (double_bits(direct_difftime((time_t)(INT64_MIN + INT64_C(1)),
        (time_t)INT64_MIN)) != UINT64_C(0x3ff0000000000000))
        return 4;
    return 0;
}

static int check_subtract_before_convert(void)
{
    /* 2047 distinguishes musl's integer subtraction before binary64 rounding. */
    if (double_bits(direct_difftime((time_t)INT64_MAX,
        (time_t)(INT64_MAX - INT64_C(2047)))) !=
        UINT64_C(0x409ffc0000000000))
        return 1;
    if (double_bits(direct_difftime((time_t)(INT64_MIN + INT64_C(2047)),
        (time_t)INT64_MIN)) != UINT64_C(0x409ffc0000000000))
        return 2;
    if (double_bits(direct_difftime((time_t)(INT64_MAX - INT64_C(2047)),
        (time_t)INT64_MAX)) != UINT64_C(0xc09ffc0000000000))
        return 3;
    return 0;
}

int crabc_x86_64_difftime_probe(void)
{
    int status = check_ordinary_values();

    if (status != 0)
        return 10 + status;
    status = check_endpoint_values();
    if (status != 0)
        return 20 + status;
    status = check_subtract_before_convert();
    return status == 0 ? 0 : 30 + status;
}

#ifndef CRABC_DIFFTIME_FREESTANDING
int main(void)
{
    return crabc_x86_64_difftime_probe();
}
#endif
