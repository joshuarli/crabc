#include <stdio.h>

extern int __signbit(double);
extern int __signbitf(float);
extern int __signbitl(long double);
extern double lgamma_r(double, int *);
extern float lgammaf_r(float, int *);
extern long double lgammal_r(long double, int *);
extern long double __lgammal_r(long double, int *);

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
    int sign;

    if (__signbit(0.0) != 0 || __signbit(-0.0) != 1) return 1;
    if (__signbitf(0.0f) != 0 || __signbitf(-0.0f) != 1) return 2;
    if (__signbitl(0.0L) != 0 || __signbitl(-0.0L) != 1) return 3;

    if (!close_double(lgamma_r(5.0, &sign), 3.1780538303479458) || sign != 1) return 4;
    if (!close_double(lgamma_r(-0.5, &sign), 1.2655121234846454) || sign != -1) return 5;
    if (!close_float(lgammaf_r(-0.5f, &sign), 1.2655121f) || sign != -1) return 6;

    if (!close_long_double(lgammal_r(5.0L, &sign), 3.1780538303479458L) || sign != 1) return 7;
    if (!close_long_double(__lgammal_r(-0.5L, &sign), 1.2655121234846454L) || sign != -1) return 8;

    puts("c-abi existing exports ok");
    return 0;
}
