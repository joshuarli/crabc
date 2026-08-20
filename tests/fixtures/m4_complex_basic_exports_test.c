#include <complex.h>
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

    puts("m4 complex basic exports ok");
    return 0;
}
