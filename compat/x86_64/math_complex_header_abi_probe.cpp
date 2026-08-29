/* Native Linux/x86-64 C++ linkage contract for <math.h> and <complex.h>. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <complex.h>
#include <float.h>
#include <math.h>

using double_real_signature = double (*)(double _Complex);
using float_real_signature = float (*)(float _Complex);
using long_real_signature = long double (*)(long double _Complex);
using double_complex_signature = double _Complex (*)(double _Complex);
using float_complex_signature = float _Complex (*)(float _Complex);
using long_complex_signature = long double _Complex (*)(long double _Complex);
using double_classify_signature = int (*)(double);
using float_classify_signature = int (*)(float);
using long_classify_signature = int (*)(long double);

static double_real_signature direct_creal = &creal;
static float_real_signature direct_crealf = &crealf;
static long_real_signature direct_creall = &creall;
static double_real_signature direct_cimag = &cimag;
static float_real_signature direct_cimagf = &cimagf;
static long_real_signature direct_cimagl = &cimagl;
static double_complex_signature direct_conj = &conj;
static float_complex_signature direct_conjf = &conjf;
static long_complex_signature direct_conjl = &conjl;
static double_classify_signature direct_fpclassify = &__fpclassify;
static float_classify_signature direct_fpclassifyf = &__fpclassifyf;
static long_classify_signature direct_fpclassifyl = &__fpclassifyl;
static double_classify_signature direct_signbit = &__signbit;
static float_classify_signature direct_signbitf = &__signbitf;
static long_classify_signature direct_signbitl = &__signbitl;

static_assert(sizeof(long double) == 16 && alignof(long double) == 16,
	"SysV x86-64 long double storage");
static_assert(sizeof(long double _Complex) == 32 && alignof(long double _Complex) == 16,
	"SysV x86-64 long double complex storage");
static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384 &&
	LDBL_DIG == 18 && DECIMAL_DIG == 21,
	"musl x87 long-double constants");

#if defined(__FLT_EVAL_METHOD__) && __FLT_EVAL_METHOD__ == 2
static_assert(sizeof(float_t) == sizeof(long double), "x87 float_t width");
static_assert(sizeof(double_t) == sizeof(long double), "x87 double_t width");
#else
static_assert(sizeof(float_t) == sizeof(float), "SSE float_t width");
static_assert(sizeof(double_t) == sizeof(double), "SSE double_t width");
#endif

extern "C" int crabc_x86_64_math_complex_header_cxx_probe(void)
{
	__complex__ double value;

	__real__ value = 1.0;
	__imag__ value = -2.0;
	return direct_creal(value) == 1.0 && direct_cimag(value) == -2.0 &&
		direct_fpclassify(1.0) == FP_NORMAL &&
		direct_fpclassifyf(1.0f) == FP_NORMAL &&
		direct_fpclassifyl(1.0L) == FP_NORMAL && direct_signbit(-0.0) == 1 &&
		direct_signbitf(-0.0f) == 1 && direct_signbitl(-0.0L) == 1
		? 0 : 1;
}
