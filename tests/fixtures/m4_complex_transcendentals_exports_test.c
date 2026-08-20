#include <complex.h>
#include <math.h>
#include <stdio.h>

static int close_double(double got, double want, double tol) {
    return fabs(got - want) <= tol;
}

static int close_float(float got, float want, float tol) {
    return fabsf(got - want) <= tol;
}

static int close_long_double(long double got, long double want, long double tol) {
    return fabsl(got - want) <= tol;
}

static int close_complex(double complex got, double re, double im, double tol) {
    return close_double(creal(got), re, tol) && close_double(cimag(got), im, tol);
}

static int close_complexf(float complex got, float re, float im, float tol) {
    return close_float(crealf(got), re, tol) && close_float(cimagf(got), im, tol);
}

static int close_complexl(long double complex got, long double re, long double im,
                          long double tol) {
    return close_long_double(creall(got), re, tol) &&
           close_long_double(cimagl(got), im, tol);
}

int main(void) {
    const double pi_2 = 1.57079632679489661923;
    double complex z = 1.0 + 2.0 * I;

    // Primary circular/hyperbolic values, compared with independently
    // evaluated musl reference constants.
    if (!close_complex(cexp(1.0 + pi_2 * I), 0.0, 2.718281828459045, 1e-12)) return 1;
    if (!close_complex(clog(3.0 + 4.0 * I), 1.6094379124341003,
                       0.9272952180016122, 1e-12)) return 2;
    if (!close_complex(csin(z), 3.165778513216168,
                       1.959601041421606, 1e-12)) return 3;
    if (!close_complex(ccos(z), 2.0327230070196656,
                       -3.0518977991518, 1e-12)) return 4;
    if (!close_complex(csinh(z), -0.4890562590412937,
                       1.4031192506220405, 1e-12)) return 5;
    if (!close_complex(ccosh(z), -0.64214812471552,
                       1.0686074213827783, 1e-12)) return 6;

    // ctan is checked through the musl identity sin(z)/cos(z), without
    // relying on the compiler's complex division lowering.
    double complex t = ctan(0.5 - 0.25 * I);
    double complex sn = csin(0.5 - 0.25 * I);
    double complex cs = ccos(0.5 - 0.25 * I);
    double den = creal(cs) * creal(cs) + cimag(cs) * cimag(cs);
    double tr = (creal(sn) * creal(cs) + cimag(sn) * cimag(cs)) / den;
    double ti = (cimag(sn) * creal(cs) - creal(sn) * cimag(cs)) / den;
    if (!close_complex(t, tr, ti, 1e-12)) return 7;

    if (!close_complex(csqrt(-3.0 + 4.0 * I), 1.0, 2.0, 1e-12)) return 8;
    if (!close_complex(casin(1.0 + 0.0 * I), pi_2, 0.0, 1e-12)) return 9;
    if (!close_complex(cacos(1.0 + 0.0 * I), 0.0, 0.0, 1e-12)) return 10;
    if (!close_complex(catan(0.0 + 0.0 * I), 0.0, 0.0, 1e-12)) return 11;
    if (!close_complex(casinh(0.0 + 0.0 * I), 0.0, 0.0, 1e-12)) return 12;
    if (!close_complex(cacosh(1.0 + 0.0 * I), 0.0, 0.0, 1e-12)) return 13;
    if (!close_complex(catanh(0.0 + 0.0 * I), 0.0, 0.0, 1e-12)) return 14;

    // Stable large-real-part path in cexp, plus principal-branch boundaries.
    double complex large = cexp(709.5 + 0.25 * I);
    double large_scale = exp(709.5);
    if (!close_complex(large, large_scale * cos(0.25),
                       large_scale * sin(0.25), 1e294)) return 15;
    double complex neg_inf = cexp(-INFINITY + pi_2 * I);
    if (creal(neg_inf) != 0.0 || cimag(neg_inf) != 0.0) return 16;
    double complex zero_log = clog(0.0 + 0.0 * I);
    if (!isinf(creal(zero_log)) || !signbit(creal(zero_log)) || cimag(zero_log) != 0.0) return 17;
    double complex neg_sqrt = csqrt(-4.0 - 0.0 * I);
    if (creal(neg_sqrt) != 0.0 || cimag(neg_sqrt) != -2.0) return 18;

    // Exercise the float and long-double ABI variants as exported symbols.
    float complex zf = 0.75f + 0.5f * I;
    if (!close_complexf(cexpf(zf), 1.8578423f, 1.0149438f, 2e-5f)) return 19;
    if (!close_complexf(clogf(3.0f + 4.0f * I), 1.609438f,
                        0.9272952f, 2e-5f)) return 20;
    if (!close_complexf(csqrtf(-3.0f + 4.0f * I), 1.0f, 2.0f, 2e-5f)) return 21;
    if (!close_complexf(csinf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 22;
    if (!close_complexf(ccosf(0.0f + 0.0f * I), 1.0f, 0.0f, 2e-5f)) return 23;
    if (!close_complexf(ctanf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 24;
    if (!close_complexf(csinhf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 25;
    if (!close_complexf(ccoshf(0.0f + 0.0f * I), 1.0f, 0.0f, 2e-5f)) return 26;
    if (!close_complexf(ctanhf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 27;
    if (!close_complexf(casinf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 28;
    if (!close_complexf(cacosf(1.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 29;
    if (!close_complexf(catanf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 30;
    if (!close_complexf(casinhf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 31;
    if (!close_complexf(cacoshf(1.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 32;
    if (!close_complexf(catanhf(0.0f + 0.0f * I), 0.0f, 0.0f, 2e-5f)) return 33;

    long double complex zl = 3.0L + 4.0L * I;
    if (!close_complexl(cexpl(0.0L + pi_2 * I), 0.0L, 1.0L, 1e-12L)) return 34;
    if (!close_complexl(clogl(zl), 1.6094379124341003L,
                        0.9272952180016122L, 1e-12L)) return 35;
    if (!close_complexl(csqrtl(-3.0L + 4.0L * I), 1.0L, 2.0L, 1e-12L)) return 36;
    if (!close_complexl(csinhl(0.0L + 0.0L * I), 0.0L, 0.0L, 1e-12L)) return 37;
    if (!close_complexl(ccoshl(0.0L + 0.0L * I), 1.0L, 0.0L, 1e-12L)) return 38;
    if (!close_complexl(ctanhl(0.0L + 0.0L * I), 0.0L, 0.0L, 1e-12L)) return 39;
    if (!close_complexl(casinhl(0.0L + 0.0L * I), 0.0L, 0.0L, 1e-12L)) return 40;
    if (!close_complexl(cacoshl(1.0L + 0.0L * I), 0.0L, 0.0L, 1e-12L)) return 41;
    if (!close_complexl(catanhl(0.0L + 0.0L * I), 0.0L, 0.0L, 1e-12L)) return 42;

    puts("m4 complex transcendental exports ok");
    return 0;
}
