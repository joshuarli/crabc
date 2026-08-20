#ifndef _COMPLEX_H
#define _COMPLEX_H

#define complex _Complex
#define _Complex_I (1.0fi)
#define I _Complex_I

#if __STDC_VERSION__ >= 201112L
#if defined(_Imaginary_I)
#define __CRABC_CMPLX(x, y, t) ((t)(x) + _Imaginary_I*(t)(y))
#elif defined(__clang__)
#define __CRABC_CMPLX(x, y, t) (+(_Complex t){ (t)(x), (t)(y) })
#else
#define __CRABC_CMPLX(x, y, t) (__builtin_complex((t)(x), (t)(y)))
#endif
#define CMPLX(x, y) __CRABC_CMPLX(x, y, double)
#define CMPLXF(x, y) __CRABC_CMPLX(x, y, float)
#define CMPLXL(x, y) __CRABC_CMPLX(x, y, long double)
#endif

#define __CRABC_COMPLEX_DECL(name) \
double complex name(double complex); \
float complex name##f(float complex); \
long double complex name##l(long double complex)
#define __CRABC_REAL_DECL(name) \
double name(double complex); \
float name##f(float complex); \
long double name##l(long double complex)

__CRABC_REAL_DECL(cabs);
__CRABC_COMPLEX_DECL(cacos);
__CRABC_COMPLEX_DECL(cacosh);
__CRABC_REAL_DECL(carg);
__CRABC_COMPLEX_DECL(casin);
__CRABC_COMPLEX_DECL(casinh);
__CRABC_COMPLEX_DECL(catan);
__CRABC_COMPLEX_DECL(catanh);
__CRABC_COMPLEX_DECL(ccos);
__CRABC_COMPLEX_DECL(ccosh);
__CRABC_COMPLEX_DECL(cexp);
__CRABC_REAL_DECL(cimag);
__CRABC_COMPLEX_DECL(clog);
__CRABC_COMPLEX_DECL(conj);
double complex cpow(double complex, double complex);
float complex cpowf(float complex, float complex);
long double complex cpowl(long double complex, long double complex);
__CRABC_COMPLEX_DECL(cproj);
__CRABC_REAL_DECL(creal);
__CRABC_COMPLEX_DECL(csin);
__CRABC_COMPLEX_DECL(csinh);
__CRABC_COMPLEX_DECL(csqrt);
__CRABC_COMPLEX_DECL(ctan);
__CRABC_COMPLEX_DECL(ctanh);

#undef __CRABC_COMPLEX_DECL
#undef __CRABC_REAL_DECL

#endif
