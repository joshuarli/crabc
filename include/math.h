#ifndef _MATH_H
#define _MATH_H

#include <features.h>

/* `float_t` and `double_t` are compiler-evaluation-mode types, not fixed
 * aliases. In particular, the x86 -mfpmath=387 contract promotes both to
 * long double; the pinned musl alltypes source owns that selection. */
#define __NEED_float_t
#define __NEED_double_t
#include <bits/alltypes.h>

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define M_E        2.71828182845904523536
#define M_LOG2E    1.44269504088896340736
#define M_LOG10E   0.434294481903251827651
#define M_LN2      0.693147180559945309417
#define M_LN10     2.30258509299404568402
#define M_PI       3.14159265358979323846
#define M_PI_2     1.57079632679489661923
#define M_PI_4     0.785398163397448309616
#define M_1_PI     0.318309886183790671538
#define M_2_PI     0.636619772367581343076
#define M_2_SQRTPI 1.12837916709551257390
#define M_SQRT2    1.41421356237309504880
#define M_SQRT1_2  0.707106781186547524401
#endif
/* POSIX.1-2024 removes this legacy XSI macro. Keep the historic X/Open
 * namespace and the BSD extension namespace without copying musl's current
 * XSI-800 overexposure. */
#if defined(_BSD_SOURCE) || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 800)
#define MAXFLOAT 3.40282346638528859812e+38F
#endif

#define NAN       __builtin_nanf("")
#define INFINITY  __builtin_inff()
#define HUGE_VALF INFINITY
#define HUGE_VAL  ((double)INFINITY)
#define HUGE_VALL ((long double)INFINITY)

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define HUGE 3.40282346638528859812e+38F
#endif

#define FP_ILOGBNAN (-1-0x7fffffff)
#define FP_ILOGB0 FP_ILOGBNAN

#define FP_NAN       0
#define FP_INFINITE  1
#define FP_ZERO      2
#define FP_SUBNORMAL 3
#define FP_NORMAL    4
#define MATH_ERRNO 1
#define MATH_ERREXCEPT 2
#if defined(__x86_64__)
/* Pinned musl's x86 math contract reports floating-point exceptions rather
 * than advertising errno-only handling. The selected x87 classifiers below
 * are a prerequisite, not a claim that all x86 scalar math is implemented. */
#define math_errhandling MATH_ERREXCEPT
#else
#define math_errhandling MATH_ERRNO
#endif

/* AArch64 provides fused multiply-add for binary32 and binary64. On x86,
 * match the pinned compiler's advertised fast-math indicators rather than
 * promising FMA where the selected target has not enabled it. */
#if defined(__x86_64__)
#ifdef __FP_FAST_FMA
#define FP_FAST_FMA 1
#endif
#ifdef __FP_FAST_FMAF
#define FP_FAST_FMAF 1
#endif
#ifdef __FP_FAST_FMAL
#define FP_FAST_FMAL 1
#endif
#else
#define FP_FAST_FMA 1
#define FP_FAST_FMAF 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
extern int signgam;
#endif

/* Match musl's public ABI declarations. The selected x86 archive supplies all
 * six entries; AArch64 retains its existing exported implementations. */
int __fpclassify(double);
int __fpclassifyf(float);
int __fpclassifyl(long double);

static __inline unsigned __FLOAT_BITS(float __f)
{
    union {float __f; unsigned __i;} __u;
    __u.__f = __f;
    return __u.__i;
}

static __inline unsigned long long __DOUBLE_BITS(double __f)
{
    union {double __f; unsigned long long __i;} __u;
    __u.__f = __f;
    return __u.__i;
}

/* Preserve musl's external __signbit* ABI on each target. Long-double storage
 * is target-specific: x86 uses x87 extended precision and AArch64 binary128. */
int __signbit(double);
int __signbitf(float);
int __signbitl(long double);

#define fpclassify(x) ( \
    sizeof(x) == sizeof(float) ? __fpclassifyf(x) : \
    sizeof(x) == sizeof(double) ? __fpclassify(x) : \
    __fpclassifyl(x) )

#define isinf(x) ( \
    sizeof(x) == sizeof(float) ? (__FLOAT_BITS(x) & 0x7fffffff) == 0x7f800000 : \
    sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & (-1ULL>>1)) == (0x7ffULL<<52) : \
    __fpclassifyl(x) == FP_INFINITE)

#define isnan(x) ( \
    sizeof(x) == sizeof(float) ? (__FLOAT_BITS(x) & 0x7fffffff) > 0x7f800000 : \
    sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & (-1ULL>>1)) > (0x7ffULL<<52) : \
    __fpclassifyl(x) == FP_NAN)

#define isnormal(x) ( \
    sizeof(x) == sizeof(float) ? ((__FLOAT_BITS(x)+0x00800000) & 0x7fffffff) >= 0x01000000 : \
    sizeof(x) == sizeof(double) ? ((__DOUBLE_BITS(x)+(1ULL<<52)) & (-1ULL>>1)) >= (1ULL<<53) : \
    __fpclassifyl(x) == FP_NORMAL)

#define isfinite(x) ( \
    sizeof(x) == sizeof(float) ? (__FLOAT_BITS(x) & 0x7fffffff) < 0x7f800000 : \
    sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & (-1ULL>>1)) < (0x7ffULL<<52) : \
    __fpclassifyl(x) > FP_INFINITE)

#define signbit(x) ( \
    sizeof(x) == sizeof(float) ? (int)(__FLOAT_BITS(x)>>31) : \
    sizeof(x) == sizeof(double) ? (int)(__DOUBLE_BITS(x)>>63) : \
    __signbitl(x) )

#define isunordered(x,y) (isnan((x)) ? ((void)(y),1) : isnan((y)))

/* Keep musl's typed helpers instead of spelling each comparison from the
 * macro arguments: C relational predicates must evaluate each operand once.
 * `float_t`/`double_t` intentionally preserve the target evaluation mode. */
#define __ISREL_DEF(rel, op, type) \
static __inline int __is##rel(type __x, type __y) \
{ return !isunordered(__x,__y) && __x op __y; }

__ISREL_DEF(lessf, <, float_t)
__ISREL_DEF(less, <, double_t)
__ISREL_DEF(lessl, <, long double)
__ISREL_DEF(lessequalf, <=, float_t)
__ISREL_DEF(lessequal, <=, double_t)
__ISREL_DEF(lessequall, <=, long double)
__ISREL_DEF(lessgreaterf, !=, float_t)
__ISREL_DEF(lessgreater, !=, double_t)
__ISREL_DEF(lessgreaterl, !=, long double)
__ISREL_DEF(greaterf, >, float_t)
__ISREL_DEF(greater, >, double_t)
__ISREL_DEF(greaterl, >, long double)
__ISREL_DEF(greaterequalf, >=, float_t)
__ISREL_DEF(greaterequal, >=, double_t)
__ISREL_DEF(greaterequall, >=, long double)

#define __tg_pred_2(x, y, p) ( \
	sizeof((x)+(y)) == sizeof(float) ? p##f(x, y) : \
	sizeof((x)+(y)) == sizeof(double) ? p(x, y) : \
	p##l(x, y) )

#define isless(x, y)            __tg_pred_2(x, y, __isless)
#define islessequal(x, y)       __tg_pred_2(x, y, __islessequal)
#define islessgreater(x, y)     __tg_pred_2(x, y, __islessgreater)
#define isgreater(x, y)         __tg_pred_2(x, y, __isgreater)
#define isgreaterequal(x, y)    __tg_pred_2(x, y, __isgreaterequal)

double      acos(double);
float       acosf(float);
long double acosl(long double);
double      acosh(double);
float       acoshf(float);
long double acoshl(long double);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
double drem(double, double);
float dremf(float, float);
double exp10(double);
float exp10f(float);
long double exp10l(long double);
double pow10(double);
float pow10f(float);
long double pow10l(long double);
double scalb(double, double);
float scalbf(float, float);
void sincos(double, double *, double *);
void sincosf(float, float *, float *);
void sincosl(long double, long double *, long double *);
double nan(const char *);
float nanf(const char *);
long double nanl(const char *);
int finite(double);
int finitef(float);
double significand(double);
float significandf(float);
#endif
double      asin(double);
float       asinf(float);
long double asinl(long double);
double      asinh(double);
float       asinhf(float);
long double asinhl(long double);
double      atan(double);
float       atanf(float);
long double atanl(long double);
double      atan2(double, double);
float       atan2f(float, float);
long double atan2l(long double, long double);
double      atanh(double);
float       atanhf(float);
long double atanhl(long double);
double      cbrt(double);
float       cbrtf(float);
long double cbrtl(long double);
double      ceil(double);
float       ceilf(float);
long double ceill(long double);
double      copysign(double, double);
float       copysignf(float, float);
long double copysignl(long double, long double);
double      cos(double);
float       cosf(float);
long double cosl(long double);
double      cosh(double);
float       coshf(float);
long double coshl(long double);
double      erf(double);
float       erff(float);
long double erfl(long double);
double      erfc(double);
float       erfcf(float);
long double erfcl(long double);
double      exp(double);
float       expf(float);
long double expl(long double);
double      exp2(double);
float       exp2f(float);
long double exp2l(long double);
double      expm1(double);
float       expm1f(float);
long double expm1l(long double);
double      fabs(double);
float       fabsf(float);
long double fabsl(long double);
double      fdim(double, double);
float       fdimf(float, float);
long double fdiml(long double, long double);
double      floor(double);
float       floorf(float);
long double floorl(long double);
double      fma(double, double, double);
float       fmaf(float, float, float);
long double fmal(long double, long double, long double);
double      fmax(double, double);
float       fmaxf(float, float);
long double fmaxl(long double, long double);
double      fmin(double, double);
float       fminf(float, float);
long double fminl(long double, long double);
double      fmod(double, double);
float       fmodf(float, float);
long double fmodl(long double, long double);
double      frexp(double, int *);
float       frexpf(float, int *);
long double frexpl(long double, int *);
double      hypot(double, double);
float       hypotf(float, float);
long double hypotl(long double, long double);
int         ilogb(double);
int         ilogbf(float);
int         ilogbl(long double);
double      ldexp(double, int);
float       ldexpf(float, int);
long double ldexpl(long double, int);
double      lgamma(double);
float       lgammaf(float);
long double lgammal(long double);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
double      lgamma_r(double, int *);
float       lgammaf_r(float, int *);
long double lgammal_r(long double, int *);
#endif
long long   llrint(double);
long long   llrintf(float);
long long   llrintl(long double);
long long   llround(double);
long long   llroundf(float);
long long   llroundl(long double);
double      log(double);
float       logf(float);
long double logl(long double);
double      log10(double);
float       log10f(float);
long double log10l(long double);
double      log1p(double);
float       log1pf(float);
long double log1pl(long double);
double      log2(double);
float       log2f(float);
long double log2l(long double);
double      logb(double);
float       logbf(float);
long double logbl(long double);
long        lrint(double);
long        lrintf(float);
long        lrintl(long double);
long        lround(double);
long        lroundf(float);
long        lroundl(long double);
double      modf(double, double *);
float       modff(float, float *);
long double modfl(long double, long double *);
double      nan(const char *);
float       nanf(const char *);
long double nanl(const char *);
double      nearbyint(double);
float       nearbyintf(float);
long double nearbyintl(long double);
double      nextafter(double, double);
float       nextafterf(float, float);
long double nextafterl(long double, long double);
double      nexttoward(double, long double);
float       nexttowardf(float, long double);
long double nexttowardl(long double, long double);
double      pow(double, double);
float       powf(float, float);
long double powl(long double, long double);
double      remainder(double, double);
float       remainderf(float, float);
long double remainderl(long double, long double);
double      remquo(double, double, int *);
float       remquof(float, float, int *);
long double remquol(long double, long double, int *);
double      rint(double);
float       rintf(float);
long double rintl(long double);
double      round(double);
float       roundf(float);
long double roundl(long double);
double      scalbln(double, long);
float       scalblnf(float, long);
long double scalblnl(long double, long);
double      scalbn(double, int);
float       scalbnf(float, int);
long double scalbnl(long double, int);
double      sin(double);
float       sinf(float);
long double sinl(long double);
double      sinh(double);
float       sinhf(float);
long double sinhl(long double);
double      sqrt(double);
float       sqrtf(float);
long double sqrtl(long double);
double      tan(double);
float       tanf(float);
long double tanl(long double);
double      tanh(double);
float       tanhf(float);
long double tanhl(long double);
double      tgamma(double);
float       tgammaf(float);
long double tgammal(long double);
double      trunc(double);
float       truncf(float);
long double truncl(long double);

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
double      j0(double);
double      j1(double);
double      jn(int, double);
double      y0(double);
double      y1(double);
double      yn(int, double);
#endif
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
float       j0f(float);
float       j1f(float);
float       jnf(int, float);
float       y0f(float);
float       y1f(float);
float       ynf(int, float);
#endif

#ifdef __cplusplus
}
#endif

#endif
