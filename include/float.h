#ifndef _FLOAT_H
#define _FLOAT_H

#if defined(__x86_64__)
/*
 * SysV x86-64 stores an 80-bit x87 value in a 16-byte long double. The
 * evaluation-method branch is part of the target ABI: GCC's x87 evaluation
 * mode changes the public float_t and double_t declarations in alltypes.h.
 */
#if !defined(__LP64__) || !defined(__BYTE_ORDER__) || \
	!defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "crabc x86-64 float definitions require little-endian LP64"
#endif

#define FLT_RADIX        2
#ifdef __FLT_EVAL_METHOD__
#define FLT_EVAL_METHOD  __FLT_EVAL_METHOD__
#else
#define FLT_EVAL_METHOD  0
#endif
/* The source-only x86 header slice declares musl's runtime query but does
 * not provide its implementation until crabc-libc's fenv leaf is selected. */
#ifdef __cplusplus
extern "C" {
#endif
int __flt_rounds(void);
#ifdef __cplusplus
}
#endif
#define FLT_ROUNDS       (__flt_rounds())
#define DECIMAL_DIG      21

#define FLT_MIN          1.17549435082228750797e-38F
#define FLT_MAX          3.40282346638528859812e+38F
#define FLT_EPSILON      1.1920928955078125e-07F
#define FLT_TRUE_MIN     1.40129846432481707092e-45F

#define FLT_MANT_DIG     24
#define FLT_MIN_EXP      (-125)
#define FLT_MAX_EXP      128
#define FLT_DIG          6
#define FLT_DECIMAL_DIG  9
#define FLT_MIN_10_EXP   (-37)
#define FLT_MAX_10_EXP   38

#define DBL_MIN          2.22507385850720138309e-308
#define DBL_MAX          1.79769313486231570815e+308
#define DBL_EPSILON      2.22044604925031308085e-16
#define DBL_TRUE_MIN     4.94065645841246544177e-324

#define DBL_MANT_DIG     53
#define DBL_MIN_EXP      (-1021)
#define DBL_MAX_EXP      1024
#define DBL_DIG          15
#define DBL_DECIMAL_DIG  17
#define DBL_MIN_10_EXP   (-307)
#define DBL_MAX_10_EXP   308

#define LDBL_MIN         3.3621031431120935063e-4932L
#define LDBL_TRUE_MIN    3.6451995318824746025e-4951L
#define LDBL_MAX         1.1897314953572317650e+4932L
#define LDBL_EPSILON     1.0842021724855044340e-19L

#define LDBL_MANT_DIG    64
#define LDBL_MIN_EXP     (-16381)
#define LDBL_MAX_EXP     16384
#define LDBL_DIG         18
#define LDBL_MIN_10_EXP  (-4931)
#define LDBL_MAX_10_EXP  4932

#define FLT_HAS_SUBNORM  1
#define DBL_HAS_SUBNORM  1
#define LDBL_HAS_SUBNORM 1
#define LDBL_DECIMAL_DIG DECIMAL_DIG

#else
#define FLT_RADIX        2
#define FLT_ROUNDS       1
#define FLT_EVAL_METHOD  0
/* The supported AArch64 ABI passes long double as IEEE-754 binary128. */
#define DECIMAL_DIG      36

#define FLT_MIN          1.17549435082228750797e-38F
#define FLT_MAX          3.40282346638528859812e+38F
#define FLT_EPSILON      1.1920928955078125e-07F
#define FLT_TRUE_MIN     1.40129846432481707092e-45F

#define FLT_MANT_DIG     24
#define FLT_MIN_EXP      (-125)
#define FLT_MAX_EXP      128
#define FLT_DIG          6
#define FLT_DECIMAL_DIG  9
#define FLT_MIN_10_EXP   (-37)
#define FLT_MAX_10_EXP   38

#define DBL_MIN          2.22507385850720138309e-308
#define DBL_MAX          1.79769313486231570815e+308
#define DBL_EPSILON      2.22044604925031308085e-16
#define DBL_TRUE_MIN     4.94065645841246544177e-324

#define DBL_MANT_DIG     53
#define DBL_MIN_EXP      (-1021)
#define DBL_MAX_EXP      1024
#define DBL_DIG          15
#define DBL_DECIMAL_DIG  17
#define DBL_MIN_10_EXP   (-307)
#define DBL_MAX_10_EXP   308

#define LDBL_MIN         3.36210314311209350626267781732175260e-4932L
#define LDBL_TRUE_MIN    6.47517511943802511092443895822764655e-4966L
#define LDBL_MAX         1.18973149535723176508575932662800702e+4932L
#define LDBL_EPSILON     1.92592994438723585305597794258492732e-34L

#define LDBL_MANT_DIG    113
#define LDBL_MIN_EXP     (-16381)
#define LDBL_MAX_EXP     16384
#define LDBL_DIG         33
#define LDBL_MIN_10_EXP  (-4931)
#define LDBL_MAX_10_EXP  4932

#define FLT_HAS_SUBNORM  1
#define DBL_HAS_SUBNORM  1
#define LDBL_HAS_SUBNORM 1
#define LDBL_DECIMAL_DIG DECIMAL_DIG
#endif

#endif
