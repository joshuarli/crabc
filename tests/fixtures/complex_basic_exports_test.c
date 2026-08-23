#include <complex.h>
#include <float.h>
#include <fenv.h>
#include <math.h>
#include <stdio.h>

static int close_double(double got, double want) {
    return got > want - 1e-12 && got < want + 1e-12;
}

static int close_float(float got, float want) {
    return got > want - 1e-5f && got < want + 1e-5f;
}

static int close_long_double(long double got, long double want) {
    return got > want - 1e-12L && got < want + 1e-12L;
}

int main(void) {
    double complex zd;
    __real__ zd = 3.0;
    __imag__ zd = -4.0;
    if (creal(zd) != 3.0 || cimag(zd) != -4.0) return 1;
    if (!close_double(cabs(zd), 5.0)) return 2;
    if (!close_double(carg(zd), -0.9272952180016122)) return 3;
    double complex cd = conj(zd);
    if (creal(cd) != 3.0 || cimag(cd) != 4.0) return 4;
    double complex pd = cproj(zd);
    if (creal(pd) != 3.0 || cimag(pd) != -4.0) return 5;

    float complex zf;
    __real__ zf = -3.0f;
    __imag__ zf = 4.0f;
    if (crealf(zf) != -3.0f || cimagf(zf) != 4.0f) return 6;
    if (!close_float(cabsf(zf), 5.0f)) return 7;
    if (!close_float(cargf(zf), 2.2142975f)) return 8;
    float complex cf = conjf(zf);
    if (crealf(cf) != -3.0f || cimagf(cf) != -4.0f) return 9;

    long double complex zl;
    __real__ zl = 3.0L;
    __imag__ zl = -4.0L;
    if (creall(zl) != 3.0L || cimagl(zl) != -4.0L) return 10;
    if (!close_long_double(cabsl(zl), 5.0L)) return 11;
    if (!close_long_double(cargl(zl), -0.9272952180016122L)) return 12;
    long double complex cl = conjl(zl);
    if (creall(cl) != 3.0L || cimagl(cl) != 4.0L) return 13;

#if LDBL_MANT_DIG == 113
    // Keep one native binary128 probe here: the generated os-test cases use
    // these same double-origin inputs and reject an f64-backed *l result by
    // checking the narrow native-precision interval.
    // The ordinary double/float complex entry points must preserve the same
    // native precision internally on AArch64.  GCC lowers carg/cargf to
    // atan2/atan2f, so these assertions also guard that real-function path.
    double complex precision_double = CMPLX(90.01, 13.37);
    if (!(0x1.6bfd81ea6a64bp+6 < cabs(precision_double) &&
          cabs(precision_double) < 0x1.6bfd81ea6a64dp+6)) return 23;
    if (!(0x1.2dfff31e7d1c9p-3 < carg(precision_double) &&
          carg(precision_double) < 0x1.2dfff31e7d1cbp-3)) return 24;
    float complex precision_float = CMPLXF(90.01, 13.37);
    if (!(0x1.2dfffp-3 < cargf(precision_float) &&
          cargf(precision_float) < 0x1.2dfff4p-3)) return 25;

    long double complex precision_z = CMPLXL(90.01, 13.37);
    long double precision_abs = cabsl(precision_z);
    if (!(0xb.5fec0f535325c22p+3L < precision_abs &&
          precision_abs < 0xb.5fec0f535325c24p+3L)) return 21;
    long double precision_arg = cargl(precision_z);
    if (!(0x9.6fff98f3e8e5142p-6L < precision_arg &&
          precision_arg < 0x9.6fff98f3e8e5144p-6L)) return 22;

    // Narrowing the native binary128 atan2 path must retain musl's required
    // underflow/inexact side effects for tiny finite results.
    feclearexcept(FE_ALL_EXCEPT);
    (void)atan2(0x1.0p-1022, 0x1.fffffffffffffp+1023);
    if ((fetestexcept(FE_INEXACT | FE_UNDERFLOW) &
         (FE_INEXACT | FE_UNDERFLOW)) != (FE_INEXACT | FE_UNDERFLOW)) return 26;
    feclearexcept(FE_ALL_EXCEPT);
    (void)atan2f(0x1.0p-126f, 0x1.fffffep+127f);
    if ((fetestexcept(FE_INEXACT | FE_UNDERFLOW) &
         (FE_INEXACT | FE_UNDERFLOW)) != (FE_INEXACT | FE_UNDERFLOW)) return 27;
#endif

    // cproj preserves finite values but maps an infinite component to
    // (+infinity, signed zero), including the sign of an infinite imaginary
    // component.
    double complex zi;
    __real__ zi = INFINITY;
    __imag__ zi = -INFINITY;
    double complex pi = cproj(zi);
    if (!isinf(creal(pi)) || signbit(creal(pi))) return 14;
    if (cimag(pi) != 0.0 || !signbit(cimag(pi))) return 15;

    float complex zif;
    __real__ zif = -INFINITY;
    __imag__ zif = INFINITY;
    float complex pif = cprojf(zif);
    if (!isinf(crealf(pif)) || signbit(crealf(pif))) return 16;
    if (cimagf(pif) != 0.0f || signbit(cimagf(pif))) return 17;

    long double complex zil;
    __real__ zil = -INFINITY;
    __imag__ zil = -INFINITY;
    long double complex pil = cprojl(zil);
    if (!isinf(creall(pil)) || signbit(creall(pil))) return 18;
    if (cimagl(pil) != 0.0L || !signbit(cimagl(pil))) return 19;

    // Conjugation must flip the sign bit even for zero.
    __imag__ zd = 0.0;
    cd = conj(zd);
    if (cimag(cd) != 0.0 || !signbit(cimag(cd))) return 20;

    puts("c-abi complex basic exports ok");
    return 0;
}
