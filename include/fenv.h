#ifndef _FENV_H
#define _FENV_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__) && (!defined(__LP64__) || !defined(__BYTE_ORDER__) || \
	!defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "crabc x86-64 fenv require little-endian LP64"
#endif

#include <bits/fenv.h>
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
