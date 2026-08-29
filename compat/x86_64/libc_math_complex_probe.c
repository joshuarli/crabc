/*
 * Static Linux/x86-64 long-double classification and basic complex ABI probe.
 *
 * The selected surface is intentionally tiny: binary32/binary64/x87
 * `__fpclassify*` and `__signbit*`, plus the C99 real/imaginary accessors and
 * conjugation for float, double, and long double complex. It excludes scalar
 * math, cabs/carg, projection, powers, transcendentals, errno/fenv behavior
 * beyond named classification, libm, libc.so, and all lifecycle/runtime
 * claims.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <complex.h>
#include <float.h>
#include <math.h>

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
	"x86 long-double storage");
_Static_assert(sizeof(long double complex) == 32 &&
	_Alignof(long double complex) == 16,
	"x86 long-double complex storage");
_Static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384 &&
	LDBL_DIG == 18 && DECIMAL_DIG == 21,
	"x86 x87 long-double constants");

typedef float (*float_real_function)(float complex);
typedef double (*double_real_function)(double complex);
typedef long double (*long_real_function)(long double complex);
typedef float complex (*float_complex_function)(float complex);
typedef double complex (*double_complex_function)(double complex);
typedef long double complex (*long_complex_function)(long double complex);
typedef int (*float_classify_function)(float);
typedef int (*double_classify_function)(double);
typedef int (*long_classify_function)(long double);

/* GNU asm names make the four binary32/binary64 scalar archive entries
 * explicit in this freestanding fixture while retaining local identifiers. */
extern int archive_fpclassify(double) __asm__("__fpclassify");
extern int archive_fpclassifyf(float) __asm__("__fpclassifyf");
extern int archive_signbit(double) __asm__("__signbit");
extern int archive_signbitf(float) __asm__("__signbitf");

/* Parentheses suppress musl's function-like C macros, forcing each named ABI
 * entry point through a function pointer rather than a compiler builtin. */
static float_real_function direct_crealf = (crealf);
static double_real_function direct_creal = (creal);
static long_real_function direct_creall = (creall);
static float_real_function direct_cimagf = (cimagf);
static double_real_function direct_cimag = (cimag);
static long_real_function direct_cimagl = (cimagl);
static float_complex_function direct_conjf = conjf;
static double_complex_function direct_conj = conj;
static long_complex_function direct_conjl = conjl;
static double_classify_function direct_fpclassify = archive_fpclassify;
static float_classify_function direct_fpclassifyf = archive_fpclassifyf;
static double_classify_function direct_signbit = archive_signbit;
static float_classify_function direct_signbitf = archive_signbitf;
static long_classify_function direct_fpclassifyl = __fpclassifyl;
static long_classify_function direct_signbitl = __signbitl;

static int check_scalar_classification(void)
{
	if (direct_fpclassify(0.0) != FP_ZERO)
		return 1;
	if (direct_fpclassify(DBL_TRUE_MIN) != FP_SUBNORMAL)
		return 2;
	if (direct_fpclassify(1.0) != FP_NORMAL)
		return 3;
	if (direct_fpclassify(HUGE_VAL) != FP_INFINITE)
		return 4;
	if (direct_fpclassify(__builtin_nan("")) != FP_NAN)
		return 5;
	if (direct_fpclassifyf(0.0f) != FP_ZERO)
		return 10;
	if (direct_fpclassifyf(FLT_TRUE_MIN) != FP_SUBNORMAL)
		return 11;
	if (direct_fpclassifyf(1.0f) != FP_NORMAL)
		return 12;
	if (direct_fpclassifyf(HUGE_VALF) != FP_INFINITE)
		return 13;
	if (direct_fpclassifyf(__builtin_nanf("")) != FP_NAN)
		return 14;
	if (direct_signbit(0.0) != 0 || direct_signbit(-0.0) != 1 ||
		direct_signbitf(0.0f) != 0 || direct_signbitf(-0.0f) != 1)
		return 20;
	return 0;
}

static int check_long_classification(void)
{
	if (direct_fpclassifyl(0.0L) != FP_ZERO ||
		direct_fpclassifyl(-0.0L) != FP_ZERO ||
		direct_fpclassifyl(LDBL_TRUE_MIN) != FP_SUBNORMAL ||
		direct_fpclassifyl(1.0L) != FP_NORMAL ||
		direct_fpclassifyl(HUGE_VALL) != FP_INFINITE ||
		direct_fpclassifyl(__builtin_nanl("")) != FP_NAN)
		return 1;
	if (direct_signbitl(0.0L) != 0 || direct_signbitl(-0.0L) != 1 ||
		direct_signbitl(-1.0L) != 1 || direct_signbitl(1.0L) != 0)
		return 2;
	return 0;
}

static int check_float_accessors_and_conjugation(void)
{
	float complex input = CMPLXF(-0.0f, __builtin_nanf(""));
	float complex conjugate = direct_conjf(CMPLXF(-1.25f, -0.0f));

	if (!signbit(direct_crealf(input)) || !isnan(direct_cimagf(input)))
		return 1;
	if (crealf(conjugate) != -1.25f || cimagf(conjugate) != 0.0f ||
		signbit(cimagf(conjugate)))
		return 2;
	return 0;
}

static int check_double_accessors_and_conjugation(void)
{
	double complex input = CMPLX(-0.0, __builtin_nan(""));
	double complex conjugate = direct_conj(CMPLX(-1.25, -0.0));

	if (!signbit(direct_creal(input)) || !isnan(direct_cimag(input)))
		return 1;
	if (creal(conjugate) != -1.25 || cimag(conjugate) != 0.0 ||
		signbit(cimag(conjugate)))
		return 2;
	return 0;
}

static int check_long_accessors_and_conjugation(void)
{
	long double complex input = CMPLXL(-0.0L, __builtin_nanl(""));
	long double complex conjugate = direct_conjl(CMPLXL(-1.25L, -0.0L));

	if (direct_signbitl(direct_creall(input)) != 1 ||
		direct_fpclassifyl(direct_cimagl(input)) != FP_NAN)
		return 1;
	if (creall(conjugate) != -1.25L || cimagl(conjugate) != 0.0L ||
		direct_signbitl(cimagl(conjugate)) != 0)
		return 2;
	return 0;
}

int crabc_x86_64_math_complex_probe(void)
{
	int status = check_scalar_classification();

	if (status != 0)
		return status;
	status = check_long_classification();

	if (status != 0)
		return 10 + status;
	status = check_float_accessors_and_conjugation();
	if (status != 0)
		return 20 + status;
	status = check_double_accessors_and_conjugation();
	if (status != 0)
		return 30 + status;
	status = check_long_accessors_and_conjugation();
	return status == 0 ? 0 : 40 + status;
}

#ifndef CRABC_MATH_COMPLEX_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_complex_probe();
}
#endif
