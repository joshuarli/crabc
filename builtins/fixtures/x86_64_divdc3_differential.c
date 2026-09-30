#include <fenv.h>
#include <stdint.h>
#include <stdio.h>

typedef double _Complex complex_double;
extern complex_double __divdc3(double, double, double, double);
extern complex_double crabc_reference_divdc3(double, double, double, double);

static double floating(uint64_t bits)
{
    union { uint64_t bits; double value; } word = { .bits = bits };
    return word.value;
}

static uint64_t representation(double value)
{
    union { uint64_t bits; double value; } word = { .value = value };
    return word.bits;
}

static int nan_bits(uint64_t bits)
{
    return (bits & UINT64_C(0x7fffffffffffffff)) > UINT64_C(0x7ff0000000000000);
}

static int component_equal(uint64_t a, uint64_t b)
{
    return a == b || (nan_bits(a) && nan_bits(b));
}

static int check(uint64_t a, uint64_t b, uint64_t c, uint64_t d, int mode)
{
    feclearexcept(FE_ALL_EXCEPT);
    complex_double candidate = __divdc3(floating(a), floating(b), floating(c), floating(d));
    int candidate_flags = fetestexcept(FE_ALL_EXCEPT);
    feclearexcept(FE_ALL_EXCEPT);
    complex_double reference = crabc_reference_divdc3(floating(a), floating(b), floating(c), floating(d));
    int reference_flags = fetestexcept(FE_ALL_EXCEPT);
    uint64_t real = representation(__real__ candidate);
    uint64_t imaginary = representation(__imag__ candidate);
    uint64_t reference_real = representation(__real__ reference);
    uint64_t reference_imaginary = representation(__imag__ reference);
    if (!component_equal(real, reference_real) || !component_equal(imaginary, reference_imaginary) ||
        candidate_flags != reference_flags) {
        fprintf(stderr, "mode %d inputs %016llx %016llx %016llx %016llx: "
                "%016llx %016llx flags %x / %016llx %016llx flags %x\n", mode,
                (unsigned long long)a, (unsigned long long)b, (unsigned long long)c, (unsigned long long)d,
                (unsigned long long)real, (unsigned long long)imaginary, candidate_flags,
                (unsigned long long)reference_real, (unsigned long long)reference_imaginary, reference_flags);
        return 1;
    }
    return 0;
}

static uint64_t random_word(uint64_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

int main(void)
{
    static const uint64_t values[] = {
        0, UINT64_C(0x8000000000000000), UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000),
        UINT64_C(0x4000000000000000), UINT64_C(0xc000000000000000),
        1, UINT64_C(0x8000000000000001), UINT64_C(0x000fffffffffffff), UINT64_C(0x800fffffffffffff),
        UINT64_C(0x0010000000000000), UINT64_C(0x8010000000000000),
        UINT64_C(0x7fefffffffffffff), UINT64_C(0xffefffffffffffff),
        UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
        UINT64_C(0x7ff8000000000001), UINT64_C(0xfff8000000000001),
        UINT64_C(0x7ff0000000000001), UINT64_C(0xfff0000000000001),
        UINT64_C(0x3fb999999999999a), UINT64_C(0xbfb999999999999a),
        UINT64_C(0x7fd0000000000000), UINT64_C(0x0020000000000000)
    };
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    unsigned long cases = 0;
    for (unsigned m = 0; m < sizeof modes / sizeof *modes; ++m) {
        if (fesetround(modes[m])) return 2;
        for (unsigned a = 0; a < sizeof values / sizeof *values; ++a)
        for (unsigned b = 0; b < sizeof values / sizeof *values; ++b)
        for (unsigned c = 0; c < sizeof values / sizeof *values; ++c)
        for (unsigned d = 0; d < sizeof values / sizeof *values; ++d) {
            if (check(values[a], values[b], values[c], values[d], modes[m])) return 3;
            ++cases;
        }
        uint64_t state = UINT64_C(0xe17a1465d921c03b);
        for (unsigned n = 0; n < 20000; ++n) {
            uint64_t a = random_word(&state), b = random_word(&state);
            uint64_t c = random_word(&state), d = random_word(&state);
            if (check(a, b, c, d, modes[m])) return 4;
            ++cases;
        }
    }
    printf("double complex division differential: PASS (%lu cases; four rounding modes)\n", cases);
    return 0;
}
