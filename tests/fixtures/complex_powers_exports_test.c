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
    // Principal-branch finite value: this exercises c * clog(z) before cexp.
    double complex zd = cpow(1.0 + 2.0 * I, 2.0 - 1.0 * I);
    if (!close_complex(zd, 2.428447747683073, 14.93241486964456, 1e-12)) return 1;

    // The sign of the zero imaginary component selects the side of the
    // negative-real branch cut, as it does for musl's clog/cexp composition.
    double complex upper = cpow(-1.0 + 0.0 * I, 0.5 + 0.0 * I);
    double complex lower = cpow(-1.0 - 0.0 * I, 0.5 + 0.0 * I);
    if (!close_complex(upper, 0.0, 1.0, 1e-12)) return 2;
    if (!close_complex(lower, 0.0, -1.0, 1e-12) || !signbit(cimag(lower))) return 3;

    // Non-real exponents use both components of the product, not just a
    // real pow() approximation.
    double complex nonreal = cpow(3.0 + 4.0 * I, 0.5 - 0.25 * I);
    if (!close_complex(nonreal, 2.814159016814292, 0.172690822775958, 1e-12)) return 4;

    // Zero and unity exponents follow cexp(c * clog(z)); these are useful
    // boundaries for preserving signed zero through the reduction.
    double complex unity = cpow(2.0 + 0.0 * I, 0.0 + 0.0 * I);
    if (creal(unity) != 1.0 || cimag(unity) != 0.0) return 5;
    double complex zero = cpow(0.0 + 0.0 * I, 2.0 + 3.0 * I);
    if (creal(zero) != 0.0 || cimag(zero) != 0.0) return 6;

    float complex zf = cpowf(1.0f + 2.0f * I, 2.0f - 1.0f * I);
    if (!close_complexf(zf, 2.42844653f, 14.9324141f, 3e-5f)) return 7;
    float complex zfi = cpowf(3.0f + 4.0f * I, 0.5f - 0.25f * I);
    if (!close_complexf(zfi, 2.81415915f, 0.172690794f, 3e-5f)) return 8;

    long double complex zl = cpowl(1.0L + 2.0L * I, 2.0L - 1.0L * I);
    if (!close_complexl(zl, 2.428447747683073L, 14.93241486964456L, 1e-12L)) return 9;
    long double complex zli = cpowl(3.0L + 4.0L * I, 0.5L - 0.25L * I);
    if (!close_complexl(zli, 2.814159016814292L, 0.172690822775958L, 1e-12L)) return 10;

    puts("c-abi complex powers exports ok");
    return 0;
}
