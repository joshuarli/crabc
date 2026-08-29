/*
 * Native Linux/x86-64 <math.h>/<complex.h>/<tgmath.h> header contract.
 *
 * This C11 consumer exercises only public header semantics against the pinned
 * musl 1.2.6 x86 compiler/runtime.  The paired static-archive fixture owns
 * the selected x87 runtime symbols; this file deliberately does not select
 * general scalar or complex math from crabc-libc.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <complex.h>

/* musl's ordinary C accessors are function-like macros before tgmath
 * deliberately replaces them with type-generic macros. */
#ifndef creal
#error "musl C <complex.h> exposes creal as a macro"
#endif
#ifndef cimag
#error "musl C <complex.h> exposes cimag as a macro"
#endif

#include <float.h>
#include <math.h>
#include <tgmath.h>

#ifndef HUGE
#error "pinned musl exposes HUGE under _GNU_SOURCE"
#endif

#define CRABC_TYPE_IS(expression, type) \
	_Generic((expression), type: 1, default: 0)

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
	"SysV x86-64 long double storage");
_Static_assert(sizeof(long double complex) == 32 &&
	_Alignof(long double complex) == 16,
	"SysV x86-64 long double complex storage");
_Static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384 &&
	LDBL_DIG == 18 && DECIMAL_DIG == 21,
	"musl x87 long-double constants");

#if defined(__FLT_EVAL_METHOD__) && __FLT_EVAL_METHOD__ == 2
_Static_assert(CRABC_TYPE_IS((float_t)0, long double),
	"x87 float_t must be long double");
_Static_assert(CRABC_TYPE_IS((double_t)0, long double),
	"x87 double_t must be long double");
#else
_Static_assert(CRABC_TYPE_IS((float_t)0, float),
	"SSE float_t must be float");
_Static_assert(CRABC_TYPE_IS((double_t)0, double),
	"SSE double_t must be double");
#endif

_Static_assert(CRABC_TYPE_IS(sin(0.0f), float), "tgmath sin(float)");
_Static_assert(CRABC_TYPE_IS(sin(0.0), double), "tgmath sin(double)");
_Static_assert(CRABC_TYPE_IS(sin(0.0L), long double), "tgmath sin(long double)");
_Static_assert(CRABC_TYPE_IS(sin(CMPLXF(0.0f, 0.0f)), float complex),
	"tgmath sin(float complex)");
_Static_assert(CRABC_TYPE_IS(sin(CMPLX(0.0, 0.0)), double complex),
	"tgmath sin(double complex)");
_Static_assert(CRABC_TYPE_IS(sin(CMPLXL(0.0L, 0.0L)), long double complex),
	"tgmath sin(long double complex)");
_Static_assert(CRABC_TYPE_IS(carg(CMPLXF(0.0f, 0.0f)), float),
	"tgmath carg(float complex)");
_Static_assert(CRABC_TYPE_IS(carg(CMPLX(0.0, 0.0)), double),
	"tgmath carg(double complex)");
_Static_assert(CRABC_TYPE_IS(carg(CMPLXL(0.0L, 0.0L)), long double),
	"tgmath carg(long double complex)");
_Static_assert(CRABC_TYPE_IS(fabs(CMPLXF(0.0f, 0.0f)), float),
	"tgmath fabs(float complex)");
_Static_assert(CRABC_TYPE_IS(fabs(CMPLX(0.0, 0.0)), double),
	"tgmath fabs(double complex)");
_Static_assert(CRABC_TYPE_IS(fabs(CMPLXL(0.0L, 0.0L)), long double),
	"tgmath fabs(long double complex)");
_Static_assert(CRABC_TYPE_IS(pow(CMPLXF(0.0f, 0.0f), CMPLXF(0.0f, 0.0f)),
	float complex), "tgmath pow(float complex)");
_Static_assert(CRABC_TYPE_IS(pow(CMPLX(0.0, 0.0), CMPLX(0.0, 0.0)),
	double complex), "tgmath pow(double complex)");
_Static_assert(CRABC_TYPE_IS(pow(CMPLXL(0.0L, 0.0L), CMPLXL(0.0L, 0.0L)),
	long double complex), "tgmath pow(long double complex)");

static int calls;

static float complex next_float_complex(void)
{
	++calls;
	return CMPLXF(0.25f, -0.5f);
}

static float next_float(void)
{
	++calls;
	return 0.5f;
}

static long double next_long_double(long double value)
{
	++calls;
	return value;
}

static int check_tgmath_single_evaluation(void)
{
	volatile float complex complex_result;
	volatile float real_result;

	calls = 0;
	complex_result = sin(next_float_complex());
	if (calls != 1)
		return 10;
	calls = 0;
	real_result = carg(next_float_complex());
	if (calls != 1)
		return 11;
	calls = 0;
	real_result = pow(next_float(), next_float());
	if (calls != 2)
		return 12;
	(void)complex_result;
	(void)real_result;
	return 0;
}

static int check_relational_single_evaluation(void)
{
	calls = 0;
	if (!isgreater(next_long_double(2.0L), next_long_double(1.0L)) || calls != 2)
		return 30;
	calls = 0;
	if (!isgreaterequal(next_long_double(2.0L), next_long_double(2.0L)) ||
		calls != 2)
		return 31;
	calls = 0;
	if (!isless(next_long_double(1.0L), next_long_double(2.0L)) || calls != 2)
		return 32;
	calls = 0;
	if (!islessequal(next_long_double(1.0L), next_long_double(1.0L)) ||
		calls != 2)
		return 33;
	calls = 0;
	if (!islessgreater(next_long_double(1.0L), next_long_double(2.0L)) ||
		calls != 2)
		return 34;
	return 0;
}

static int check_x87_public_semantics(void)
{
	if (math_errhandling != MATH_ERREXCEPT)
		return 20;
	if (HUGE != FLT_MAX)
		return 24;
#if defined(FP_FAST_FMA) || defined(FP_FAST_FMAF) || defined(FP_FAST_FMAL)
	return 21;
#endif
	if (!signbit(-0.0L) || signbit(0.0L))
		return 22;
	if (fpclassify(0.0L) != FP_ZERO ||
		fpclassify(LDBL_TRUE_MIN) != FP_SUBNORMAL ||
		fpclassify(1.0L) != FP_NORMAL ||
		fpclassify(HUGE_VALL) != FP_INFINITE ||
		fpclassify(__builtin_nanl("")) != FP_NAN)
		return 23;
	return 0;
}

int main(void)
{
	int status = check_tgmath_single_evaluation();

	if (status != 0)
		return status;
	status = check_relational_single_evaluation();
	if (status != 0)
		return status;
	return check_x87_public_semantics();
}
