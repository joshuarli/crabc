/* Native x86 regression: musl-1.2.6's retained scalar-math defects.
 * These checks state exact IEEE results, independent of the pinned oracle.
 * The runner retains the oracle's failing exit status separately.
 */
#include <fenv.h>
#include <math.h>

#pragma STDC FENV_ACCESS ON

static float (*volatile call_fmaf)(float, float, float) = fmaf;
static long double (*volatile call_fmal)(long double, long double, long double) = fmal;
static long double (*volatile call_nextafterl)(long double, long double) = nextafterl;
static float (*volatile call_powf)(float, float) = powf;

int math_scalar_corrections_probe(void)
{
    int failures = 0;
    fesetround(FE_TONEAREST);
    feclearexcept(FE_ALL_EXCEPT);
    volatile float f = call_fmaf(-0x1.001p-81f, 0x1.ffe002p-70f, 0x1.0002p-133f);
    int flags = fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
    if (f != 0x1.0001p-133f || flags != (FE_INEXACT | FE_UNDERFLOW)) failures |= 1;
    feclearexcept(FE_ALL_EXCEPT);
    volatile long double l = call_fmal(-0x1p-10000L, 0x1.0000000000001p-6445L, 0x1p-16382L);
    flags = fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
    if (l != 0x1.fffffffffffffffcp-16383L || flags != (FE_INEXACT | FE_UNDERFLOW)) failures |= 2;
    fesetround(FE_UPWARD);
    feclearexcept(FE_ALL_EXCEPT);
    f = call_powf(0x1.fffffep+127f, 1.0f);
    flags = fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
    if (f != 0x1.fffffep+127f || flags != 0) failures |= 4;
    fesetround(FE_TONEAREST);
    feclearexcept(FE_ALL_EXCEPT);
    l = call_fmal(0x1p-10000L, 0x1p-6448L, -0x1.fffffffffffffffcp-16383L);
    flags = fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
    if (l != -0x1.fffffffffffffffcp-16383L || flags != (FE_INEXACT | FE_UNDERFLOW)) failures |= 8;
    feclearexcept(FE_ALL_EXCEPT);
    l = call_nextafterl(-0x1p-16382L, 0.0L);
    flags = fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
    if (l != -0x1.fffffffffffffffcp-16383L || flags != (FE_INEXACT | FE_UNDERFLOW)) failures |= 16;
    feclearexcept(FE_ALL_EXCEPT);
    l = call_fmal(-0x1p-10000L, 0x1.0000000000000002p-6447L, 0x1p-16382L);
    flags = fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
    if (l != 0x1p-16382L || flags != (FE_INEXACT | FE_UNDERFLOW)) failures |= 32;
    return failures;
}

#ifdef CRABC_MATH_CORRECTIONS_INSTALLED
#include <errno.h>
int main(void)
{
    errno = 0x3456;
    int status = math_scalar_corrections_probe();
    return status ? status : (errno == 0x3456 ? 0 : 64);
}
#endif
