#include <fenv.h>
#include <stdint.h>
#include <stdio.h>

typedef float _Complex complex_float;
extern complex_float __mulsc3(float, float, float, float);
extern complex_float crabc_reference_mulsc3(float, float, float, float);
extern complex_float __divsc3(float, float, float, float);
extern complex_float crabc_reference_divsc3(float, float, float, float);

static float floating(uint32_t bits)
{
    union { uint32_t bits; float value; } word = { .bits = bits };
    return word.value;
}

static uint32_t representation(float value)
{
    union { uint32_t bits; float value; } word = { .value = value };
    return word.bits;
}

static int nan_bits(uint32_t bits)
{
    return (bits & UINT32_C(0x7fffffff)) > UINT32_C(0x7f800000);
}

static int component_equal(uint32_t a, uint32_t b)
{
    return a == b || (nan_bits(a) && nan_bits(b));
}

static int check(uint32_t a, uint32_t b, uint32_t c, uint32_t d, int mode, int multiply)
{
    feclearexcept(FE_ALL_EXCEPT);
    complex_float candidate = (multiply ? __mulsc3 : __divsc3)(floating(a), floating(b), floating(c), floating(d));
    int candidate_flags = fetestexcept(FE_ALL_EXCEPT);
    feclearexcept(FE_ALL_EXCEPT);
    complex_float reference = (multiply ? crabc_reference_mulsc3 : crabc_reference_divsc3)(floating(a), floating(b), floating(c), floating(d));
    int reference_flags = fetestexcept(FE_ALL_EXCEPT);
    uint32_t real = representation(__real__ candidate);
    uint32_t imaginary = representation(__imag__ candidate);
    uint32_t reference_real = representation(__real__ reference);
    uint32_t reference_imaginary = representation(__imag__ reference);
    if (!component_equal(real, reference_real) || !component_equal(imaginary, reference_imaginary) ||
        candidate_flags != reference_flags) {
        fprintf(stderr, "mode %d inputs %08x %08x %08x %08x: "
                "%08x %08x flags %x / %08x %08x flags %x\n", mode,
                (unsigned)a, (unsigned)b, (unsigned)c, (unsigned)d,
                (unsigned)real, (unsigned)imaginary, candidate_flags,
                (unsigned)reference_real, (unsigned)reference_imaginary, reference_flags);
        return 1;
    }
    return 0;
}

static uint32_t random_word(uint32_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

int main(void)
{
    static const uint32_t values[] = {
        0, UINT32_C(0x80000000), UINT32_C(0x3f800000), UINT32_C(0xbf800000),
        UINT32_C(0x40000000), UINT32_C(0xc0000000),
        1, UINT32_C(0x80000001), UINT32_C(0x007fffff), UINT32_C(0x807fffff),
        UINT32_C(0x00800000), UINT32_C(0x80800000),
        UINT32_C(0x7f7fffff), UINT32_C(0xff7fffff),
        UINT32_C(0x7f800000), UINT32_C(0xff800000),
        UINT32_C(0x7fc00001), UINT32_C(0xffc00001),
        UINT32_C(0x7f800001), UINT32_C(0xff800001),
        UINT32_C(0x3dcccccd), UINT32_C(0xbdcccccd),
        UINT32_C(0x7e800000), UINT32_C(0x01000000)
    };
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    unsigned long cases = 0;
    for (unsigned m = 0; m < sizeof modes / sizeof *modes; ++m) {
        if (fesetround(modes[m])) return 2;
        for (unsigned a = 0; a < sizeof values / sizeof *values; ++a)
        for (unsigned b = 0; b < sizeof values / sizeof *values; ++b)
        for (unsigned c = 0; c < sizeof values / sizeof *values; ++c)
        for (unsigned d = 0; d < sizeof values / sizeof *values; ++d) {
            if (check(values[a], values[b], values[c], values[d], modes[m], 0) || check(values[a], values[b], values[c], values[d], modes[m], 1)) return 3;
            cases += 2;
        }
        uint32_t state = UINT32_C(0xd921c03b);
        for (unsigned n = 0; n < 20000; ++n) {
            uint32_t a = random_word(&state), b = random_word(&state);
            uint32_t c = random_word(&state), d = random_word(&state);
            if (check(a, b, c, d, modes[m], 0) || check(a, b, c, d, modes[m], 1)) return 4;
            cases += 2;
        }
    }
    printf("float complex differential: PASS (%lu cases; four rounding modes)\n", cases);
    return 0;
}
