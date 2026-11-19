#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <unistd.h>

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16, "binary128 storage");
_Static_assert(LDBL_MANT_DIG == 113 && LDBL_MAX_EXP == 16384 && LDBL_MIN_EXP == -16381,
    "AArch64 binary128 format");

typedef long double (*unary_fn)(long double);
typedef long double (*binary_fn)(long double, long double);
static unary_fn volatile exp10_call = (exp10l);
static unary_fn volatile pow10_call = (pow10l);
static binary_fn volatile fdim_call = (fdiml);

union binary128 {
    long double value;
    struct { uint64_t low, high; } words;
    unsigned char bytes[16];
};

struct record {
    uint16_t function, index;
    uint32_t rounding, fpsr, exceptions;
    uint64_t fpcr_before, fpcr_after;
    unsigned char value[16];
};
_Static_assert(sizeof(struct record) == 48, "binary128 record layout");

static uint64_t fpcr(void)
{
    uint64_t value;
    __asm__ volatile ("mrs %0, fpcr" : "=r" (value));
    return value;
}

static uint64_t fpsr(void)
{
    uint64_t value;
    __asm__ volatile ("mrs %0, fpsr" : "=r" (value));
    return value;
}

static long double nan_payload(uint64_t low, uint64_t high)
{
    union binary128 value = { .words = { low, high } };
    return value.value;
}

static int emit(unsigned int function, unsigned int index, int rounding,
                long double value, uint64_t before)
{
    union binary128 bits = { .value = value };
    struct record record = { .function = function, .index = index, .rounding = rounding,
        .fpsr = (uint32_t)fpsr(), .exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT),
        .fpcr_before = before, .fpcr_after = fpcr() };
    if (record.fpcr_before != record.fpcr_after)
        return -1;
    for (unsigned int i = 0; i < 16; ++i)
        record.value[i] = bits.bytes[i];
    const unsigned char *p = (const unsigned char *)&record;
    size_t remaining = sizeof(record);
    while (remaining) {
        ssize_t n = write(1, p, remaining);
        if (n <= 0) return -1;
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

int main(void)
{
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    const long double left[] = { 3, 1, -0.0L, 0.0L, HUGE_VALL, HUGE_VALL, -HUGE_VALL,
        nan_payload(0x41, UINT64_C(0x7fff800000000000)), 1,
        nan_payload(0x43, UINT64_C(0x7fff000000000000)), 1, 0x1p100L, LDBL_MAX };
    const long double right[] = { 1, 3, 0.0L, -0.0L, HUGE_VALL, 1, 1, 1,
        nan_payload(0x42, UINT64_C(0x7fff800000000000)), 1,
        nan_payload(0x44, UINT64_C(0x7fff000000000000)), 0x1p-100L, -LDBL_MAX };
    const long double inputs[] = { 0.0L, -0.0L, LDBL_TRUE_MIN, -LDBL_TRUE_MIN,
        -15, -1, 1, 15, 0.5L, -0.5L, 15.5L, -15.5L, 16, -16, 16.5L, -16.5L,
        4932, 4933, -4950, -4951, HUGE_VALL, -HUGE_VALL,
        nan_payload(0x45, UINT64_C(0x7fff800000000000)),
        nan_payload(0x46, UINT64_C(0x7fff000000000000)) };
    fenv_t saved;
    if (exp10_call != pow10_call || fegetenv(&saved) || fesetenv(FE_DFL_ENV)) return 1;
    for (unsigned int m = 0; m < 4; ++m) {
        for (unsigned int i = 0; i < 13; ++i) {
            if (fesetround(modes[m]) || feclearexcept(FE_ALL_EXCEPT)) return 2;
            uint64_t before = fpcr();
            long double value = fdim_call(left[i], right[i]);
            if (emit(1, i, modes[m], value, before)) return 3;
        }
        for (unsigned int f = 2; f <= 3; ++f) {
            unary_fn call = f == 2 ? exp10_call : pow10_call;
            for (unsigned int i = 0; i < 24; ++i) {
                if (fesetround(modes[m]) || feclearexcept(FE_ALL_EXCEPT)) return 4;
                uint64_t before = fpcr();
                long double value = call(inputs[i]);
                if (emit(f, i, modes[m], value, before)) return 5;
            }
        }
    }
    return fesetenv(&saved) != 0;
}
