/* Exact finite power identities through ordinary compiler-generated C calls. */
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

static double (*volatile call_pow)(double, double) = pow;
static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
static const double bases[] = {
    0.0, -0.0, DBL_TRUE_MIN, -DBL_TRUE_MIN, DBL_MIN, -DBL_MIN,
    0.1, -0.1, 0.5, -0.5, 1.0, -1.0, 1.5, -1.5, 2.0, -2.0,
    DBL_MAX, -DBL_MAX,
};
static const struct { double base, exponent; } controls[] = {
    {4.0, 0.5}, {1.5, 2.0}, {-2.0, 3.0}, {2.0, -1.0},
    {-0.0, 2.0}, {-0.0, 3.0}, {INFINITY, 1.0}, {-INFINITY, 1.0},
    {__builtin_nan("0x1234"), 1.0}, {1.0, __builtin_nan("0x5678")},
};

static uint64_t bits(double value)
{
    union { double value; uint64_t bits; } representation = { value };
    return representation.bits;
}

static int emit(const uint64_t record[5])
{
    const unsigned char *cursor = (const unsigned char *)record;
    unsigned long left = 5 * sizeof(uint64_t);
    while (left) {
        register long number __asm__("rax") = 1;
        register long descriptor __asm__("rdi") = 1;
        register const void *address __asm__("rsi") = cursor;
        register unsigned long length __asm__("rdx") = left;
        __asm__ volatile ("syscall" : "+a"(number)
            : "D"(descriptor), "S"(address), "d"(length)
            : "rcx", "r11", "memory");
        if (number == -4) continue;
        if (number <= 0 || (unsigned long)number > left) return -1;
        cursor += number;
        left -= number;
    }
    return 0;
}

int crabc_math_pow_identity110_probe(void)
{
    int failures = 0;
    for (unsigned m = 0; m < sizeof(modes) / sizeof(*modes); ++m) {
        for (unsigned i = 0; i < sizeof(bases) / sizeof(*bases); ++i) {
            int seed = i % 2 ? FE_DIVBYZERO : 0;
            if (fesetround(modes[m]) || feclearexcept(FE_ALL_EXCEPT) ||
                feraiseexcept(seed)) return 125;
            double result = call_pow(bases[i], 1.0);
            int flags = fetestexcept(FE_ALL_EXCEPT);
            int rounding = fegetround();
            uint64_t record[5] = { bits(bases[i]), bits(1.0), bits(result),
                ((uint64_t)(unsigned)modes[m] << 32) | (unsigned)rounding, (unsigned)flags };
            if (emit(record)) return 126;
            failures += bits(result) != bits(bases[i]) || flags != seed || rounding != modes[m];
        }
        for (unsigned i = 0; i < sizeof(controls) / sizeof(*controls); ++i) {
            if (fesetround(modes[m]) || feclearexcept(FE_ALL_EXCEPT)) return 125;
            double result = call_pow(controls[i].base, controls[i].exponent);
            int flags = fetestexcept(FE_ALL_EXCEPT);
            uint64_t record[5] = { bits(controls[i].base), bits(controls[i].exponent), bits(result),
                ((uint64_t)(unsigned)modes[m] << 32) | (unsigned)fegetround(), (unsigned)flags };
            if (emit(record)) return 126;
        }
    }
    if (fesetenv(FE_DFL_ENV)) return 125;
    return failures ? 1 : 0;
}
