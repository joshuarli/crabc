#include <fenv.h>
#include <math.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

extern int __fpclassify(double);
extern int __fpclassifyf(float);
static int (*volatile classify_double)(double) = __fpclassify;
static int (*volatile classify_float)(float) = __fpclassifyf;

static int crabc_fpclassify_signal_probe(void)
{
    union { uint64_t bits; double value; } d = { .bits = UINT64_C(0x7ff4000000000123) };
    union { uint32_t bits; float value; } f = { .bits = UINT32_C(0x7fa00123) };
    if (feclearexcept(FE_ALL_EXCEPT) || feraiseexcept(FE_DIVBYZERO)) return 1;
    if (classify_double(d.value) != FP_NAN || fetestexcept(FE_ALL_EXCEPT) != FE_DIVBYZERO) return 2;
    if (classify_float(f.value) != FP_NAN || fetestexcept(FE_ALL_EXCEPT) != FE_DIVBYZERO) return 3;
    return 0;
}

#ifndef CRABC_FPCLASSIFY_COMPOSED
int main(void)
{
    return crabc_fpclassify_signal_probe();
}
#endif
