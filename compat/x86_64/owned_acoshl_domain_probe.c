#include <fenv.h>
#include <math.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

static long double (*volatile call_acoshl)(long double) = acoshl;

static int crabc_acoshl_domain_probe(void)
{
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    static const uint64_t words[][2] = {
        { UINT64_C(0x8672bef2ec5aa425), UINT64_C(0xc01029c329c06ecd) },
        { 0, UINT64_C(0xc002000000000000) },
        { 0, UINT64_C(0x8000000000000000) },
        { 0, 0 },
        { 0, UINT64_C(0x3ffe000000000000) },
    };
    for (unsigned m = 0; m < 4; ++m) {
        if (fesetround(modes[m])) return 1;
        for (unsigned i = 0; i < sizeof(words) / sizeof(words[0]); ++i) {
            union { uint64_t words[2]; long double value; } input, result;
            input.words[0] = words[i][0]; input.words[1] = words[i][1];
            if (feclearexcept(FE_ALL_EXCEPT)) return 2;
            result.value = call_acoshl(input.value);
            if ((result.words[1] & UINT64_C(0x7fff000000000000)) != UINT64_C(0x7fff000000000000) ||
                !((result.words[1] & UINT64_C(0x0000ffffffffffff)) | result.words[0]) ||
                !(fetestexcept(FE_INVALID) & FE_INVALID)) return 3;
        }
        union { uint64_t words[2]; long double value; } nan, result;
        nan.words[0] = 1; nan.words[1] = UINT64_C(0xffff800000000000);
        if (feclearexcept(FE_ALL_EXCEPT)) return 4;
        result.value = call_acoshl(nan.value);
        if ((result.words[1] & UINT64_C(0x7fff000000000000)) != UINT64_C(0x7fff000000000000) ||
            !((result.words[1] & UINT64_C(0x0000ffffffffffff)) | result.words[0]) ||
            fetestexcept(FE_INVALID)) return 5;
    }
    return 0;
}

#ifndef CRABC_ACOSHL_DOMAIN_COMPOSED
int main(void)
{
    return crabc_acoshl_domain_probe();
}
#endif
