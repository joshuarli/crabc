#include <fenv.h>
#include <math.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

static long double (*volatile call_sqrtl)(long double) = sqrtl;

static int crabc_sqrtl_snan_probe(void)
{
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    for (unsigned m = 0; m < 4; ++m) {
        if (fesetround(modes[m])) return 1;
        for (unsigned sign = 0; sign < 2; ++sign) {
            for (unsigned quiet = 0; quiet < 2; ++quiet) {
                union { uint64_t words[2]; long double value; } input, result;
                input.words[0] = UINT64_C(0x123);
                input.words[1] = UINT64_C(0x7fff000000000000) | ((uint64_t)sign << 63) | ((uint64_t)quiet << 47);
                if (feclearexcept(FE_ALL_EXCEPT) || feraiseexcept(FE_DIVBYZERO)) return 2;
                result.value = call_sqrtl(input.value);
                if (result.words[0] != input.words[0] || result.words[1] != (input.words[1] | (UINT64_C(1) << 47)) ||
                    fetestexcept(FE_ALL_EXCEPT) != (FE_DIVBYZERO | (quiet ? 0 : FE_INVALID))) return 3;
            }
        }
    }
    return 0;
}
#ifndef CRABC_SQRTL_SNAN_COMPOSED
int main(void) { return crabc_sqrtl_snan_probe(); }
#endif
