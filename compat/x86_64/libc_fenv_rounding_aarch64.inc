#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(long double) == 16 && LDBL_MANT_DIG == 113, "binary128 ABI");

struct rounding_record {
    uint16_t precision, operation, mode, seed, index, reserved;
    uint32_t rounding, exceptions, fpcr, fpsr;
    unsigned char value[16];
};

static double (*volatile round_d[2])(double) = { rint, nearbyint };
static float (*volatile round_f[2])(float) = { rintf, nearbyintf };
static long double (*volatile round_l[2])(long double) = { rintl, nearbyintl };

static int write_record(const struct rounding_record *record)
{
    const unsigned char *bytes = (const unsigned char *)record;
    size_t left = sizeof(*record);
    while (left) {
        ssize_t count = write(1, bytes, left);
        if (count <= 0) return 1;
        bytes += count;
        left -= (size_t)count;
    }
    return 0;
}

int crabc_x86_64_fenv_rounding_probe(void)
{
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    static const int seeds[] = { 0, FE_INEXACT, FE_DIVBYZERO, FE_INEXACT | FE_DIVBYZERO };
    static const uint64_t ds[] = { 0, UINT64_C(0x8000000000000000), UINT64_C(0x3fe0000000000000), UINT64_C(0xbfe0000000000000), UINT64_C(0x3ff8000000000000), UINT64_C(0xbff8000000000000), 1, UINT64_C(0x8000000000000001), UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000), UINT64_C(0x432fffffffffffff), UINT64_C(0xc32fffffffffffff) };
    static const uint32_t fs[] = { 0, UINT32_C(0x80000000), UINT32_C(0x3f000000), UINT32_C(0xbf000000), UINT32_C(0x3fc00000), UINT32_C(0xbfc00000), 1, UINT32_C(0x80000001), UINT32_C(0x3f800000), UINT32_C(0xbf800000), UINT32_C(0x4affffff), UINT32_C(0xcaffffff) };
    static const long double ls[] = { 0.0L, -0.0L, 0.5L, -0.5L, 1.5L, -1.5L, 0x1p-16494L, -0x1p-16494L, 1.0L, -1.0L, 0x1.ffffffffffffffffffffffffffffp111L, -0x1.ffffffffffffffffffffffffffffp111L };
    fenv_t original;
    if (fegetenv(&original)) return 1;
    for (unsigned mode = 0; mode < 4; ++mode)
    for (unsigned seed = 0; seed < 4; ++seed)
    for (unsigned operation = 0; operation < 2; ++operation)
    for (unsigned index = 0; index < 12; ++index)
    for (unsigned precision = 0; precision < 3; ++precision) {
        struct rounding_record record = { .precision = precision, .operation = operation,
            .mode = mode, .seed = seed, .index = index };
        union { double value; uint64_t bits; } d = { .bits = ds[index] };
        union { float value; uint32_t bits; } f = { .bits = fs[index] };
        if (fesetenv(FE_DFL_ENV) || fesetround(modes[mode]) || feraiseexcept(seeds[seed])) return 2;
        if (precision == 0) { double value = round_d[operation](d.value); memcpy(record.value, &value, sizeof(value)); }
        else if (precision == 1) { float value = round_f[operation](f.value); memcpy(record.value, &value, sizeof(value)); }
        else { long double value = round_l[operation](ls[index]); memcpy(record.value, &value, sizeof(value)); }
        uint64_t fpcr, fpsr;
        __asm__ volatile ("mrs %0, fpcr" : "=r"(fpcr));
        __asm__ volatile ("mrs %0, fpsr" : "=r"(fpsr));
        record.fpcr = (uint32_t)fpcr;
        record.fpsr = (uint32_t)fpsr;
        record.rounding = fegetround();
        record.exceptions = fetestexcept(FE_ALL_EXCEPT);
        int expected = seeds[seed];
        if (!operation && index != 0 && index != 1 && index != 8 && index != 9)
            expected |= FE_INEXACT;
        if ((record.fpcr & 0xc00000) != (unsigned)modes[mode] ||
            record.rounding != (unsigned)modes[mode] ||
            (record.fpsr & FE_ALL_EXCEPT) != record.exceptions ||
            record.exceptions != (unsigned)expected) return 3;
        if (write_record(&record)) return 4;
    }
    return fesetenv(&original) != 0;
}
#ifndef CRABC_FENV_ROUNDING_FREESTANDING
int main(void) { return crabc_x86_64_fenv_rounding_probe(); }
#endif
