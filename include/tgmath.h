#ifndef _TGMATH_H
#define _TGMATH_H

#include <math.h>
#include <complex.h>

/* The generic forms are part of the public C contract, not aliases for
 * runtime symbols.  Function-like macros also keep their availability
 * visible to strict API conformance checks. */
#define acos(x) acos(x)
#define acosh(x) acosh(x)
#define asin(x) asin(x)
#define asinh(x) asinh(x)
#define atan(x) atan(x)
#define atan2(x,y) atan2((x),(y))
#define atanh(x) atanh(x)
#define carg(x) carg(x)
#define cbrt(x) cbrt(x)
#define ceil(x) ceil(x)
#define cimag(x) cimag(x)
#define conj(x) conj(x)
#define copysign(x,y) copysign((x),(y))
#define cos(x) cos(x)
#define cosh(x) cosh(x)
#define cproj(x) cproj(x)
#define creal(x) creal(x)
#define erf(x) erf(x)
#define erfc(x) erfc(x)
#define exp(x) exp(x)
#define exp2(x) exp2(x)
#define expm1(x) expm1(x)
#define fabs(x) fabs(x)
#define fdim(x,y) fdim((x),(y))
#define floor(x) floor(x)
#define fma(x,y,z) fma((x),(y),(z))
#define fmax(x,y) fmax((x),(y))
#define fmin(x,y) fmin((x),(y))
#define fmod(x,y) fmod((x),(y))
#define frexp(x,y) frexp((x),(y))
#define hypot(x,y) hypot((x),(y))
#define ilogb(x) ilogb(x)
#define ldexp(x,y) ldexp((x),(y))
#define lgamma(x) lgamma(x)
#define llround(x) llround(x)
#define log(x) log(x)
#define log10(x) log10(x)
#define log1p(x) log1p(x)
#define log2(x) log2(x)
#define logb(x) logb(x)
#define lround(x) lround(x)
#define nearbyint(x) nearbyint(x)
#define nextafter(x,y) nextafter((x),(y))
#define nexttoward(x,y) nexttoward((x),(y))
#define pow(x,y) pow((x),(y))
#define remainder(x,y) remainder((x),(y))
#define remquo(x,y,z) remquo((x),(y),(z))
#define rint(x) rint(x)
#define round(x) round(x)
#define scalbln(x,y) scalbln((x),(y))
#define scalbn(x,y) scalbn((x),(y))
#define sin(x) sin(x)
#define sinh(x) sinh(x)
#define sqrt(x) sqrt(x)
#define tan(x) tan(x)
#define tanh(x) tanh(x)
#define tgamma(x) tgamma(x)
#define trunc(x) trunc(x)

#define lrint(x) _Generic((x), \
    float: lrintf, \
    long double: lrintl, \
    default: lrint \
)(x)

#define llrint(x) _Generic((x), \
    float: llrintf, \
    long double: llrintl, \
    default: llrint \
)(x)

#endif
