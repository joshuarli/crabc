//===-- complex_mul_support.c - private compiler ABI multiplication -------===//
//
// Direct source translation of LLVM compiler-rt 22.1.3
// compiler-rt/lib/builtins/{mulsc3,muldc3,mulxc3}.c.
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "libm.h"
#include <complex.h>

#define DEFINE_COMPLEX_MULTIPLY(name, type, complex_type, copy_sign, infinity) \
complex_type name(type a, type b, type c, type d) \
{ \
	type ac = a * c; \
	type bd = b * d; \
	type ad = a * d; \
	type bc = b * c; \
	complex_type result; \
	int recalculate = 0; \
	__real__ result = ac - bd; \
	__imag__ result = ad + bc; \
	if (isnan(__real__ result) && isnan(__imag__ result)) { \
		if (isinf(a) || isinf(b)) { \
			a = copy_sign(isinf(a) ? 1 : 0, a); \
			b = copy_sign(isinf(b) ? 1 : 0, b); \
			if (isnan(c)) c = copy_sign(0, c); \
			if (isnan(d)) d = copy_sign(0, d); \
			recalculate = 1; \
		} \
		if (isinf(c) || isinf(d)) { \
			c = copy_sign(isinf(c) ? 1 : 0, c); \
			d = copy_sign(isinf(d) ? 1 : 0, d); \
			if (isnan(a)) a = copy_sign(0, a); \
			if (isnan(b)) b = copy_sign(0, b); \
			recalculate = 1; \
		} \
		if (!recalculate && (isinf(ac) || isinf(bd) || isinf(ad) || isinf(bc))) { \
			if (isnan(a)) a = copy_sign(0, a); \
			if (isnan(b)) b = copy_sign(0, b); \
			if (isnan(c)) c = copy_sign(0, c); \
			if (isnan(d)) d = copy_sign(0, d); \
			recalculate = 1; \
		} \
		if (recalculate) { \
			__real__ result = (infinity) * (a * c - b * d); \
			__imag__ result = (infinity) * (a * d + b * c); \
		} \
	} \
	return result; \
}

DEFINE_COMPLEX_MULTIPLY(__mulsc3, float, float complex, copysignf, __builtin_inff())
DEFINE_COMPLEX_MULTIPLY(__muldc3, double, double complex, copysign, __builtin_inf())
DEFINE_COMPLEX_MULTIPLY(__mulxc3, long double, long double complex, copysignl, __builtin_infl())
