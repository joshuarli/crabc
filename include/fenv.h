#ifndef _FENV_H
#define _FENV_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__)
/*
 * Linux/x86-64 uses the x87 control/status representation together with
 * MXCSR. Keep this declaration local to the explicit staged target: this
 * header is not a cross-architecture fenv abstraction. The record and its
 * constants live in the target-owned bits header, matching pinned musl's
 * physical source boundary.
 */
#if !defined(__LP64__) || !defined(__BYTE_ORDER__) || \
	!defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "crabc x86-64 fenv requires little-endian LP64"
#endif

#include <bits/fenv.h>

#else
#define FE_INVALID    1
#define FE_DIVBYZERO  2
#define FE_OVERFLOW   4
#define FE_UNDERFLOW  8
#define FE_INEXACT    16
#define FE_ALL_EXCEPT 31

#define FE_TONEAREST  0
#define FE_DOWNWARD   0x800000
#define FE_UPWARD     0x400000
#define FE_TOWARDZERO 0xc00000

typedef unsigned int fexcept_t;

typedef struct {
	unsigned int __fpcr;
	unsigned int __fpsr;
} fenv_t;

#define FE_DFL_ENV      ((const fenv_t *) -1)
#endif

int feclearexcept(int);
int fegetexceptflag(fexcept_t *, int);
int feraiseexcept(int);
int fesetexceptflag(const fexcept_t *, int);
int fetestexcept(int);

int fegetround(void);
int fesetround(int);

int fegetenv(fenv_t *);
int feholdexcept(fenv_t *);
int fesetenv(const fenv_t *);
int feupdateenv(const fenv_t *);

#ifdef __cplusplus
}
#endif
#endif
