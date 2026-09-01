/*
 * Freestanding Linux/x86-64 aggregate extraction fixture for the selected
 * math.elementary-fenv-sensitive surface.
 *
 * This is deliberately a composition/linkage proof, not a replacement for
 * the five focused behavior differentials. It calls every public spelling
 * from one feature-gated archive, so --gc-sections cannot hide a provider in
 * a disjoint candidate. The values are exact and merely prove that each
 * typed address is callable; the leaf runners own rounding, exceptions, NaN,
 * underflow, and overflow behavior.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <float.h>
#include <math.h>

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);
typedef long double (*binary80_unary_function)(long double);
typedef double (*double_binary_function)(double, double);
typedef float (*float_binary_function)(float, float);
typedef long double (*binary80_binary_function)(long double, long double);

/* Parentheses and -fno-builtin preserve every named public C ABI edge. */
static double_unary_function volatile direct_exp10 = (exp10);
static float_unary_function volatile direct_exp10f = (exp10f);
static binary80_unary_function volatile direct_exp10l = (exp10l);
static double_binary_function volatile direct_fdim = (fdim);
static float_binary_function volatile direct_fdimf = (fdimf);
static binary80_binary_function volatile direct_fdiml = (fdiml);
static double_unary_function volatile direct_nearbyint = (nearbyint);
static float_unary_function volatile direct_nearbyintf = (nearbyintf);
static binary80_unary_function volatile direct_nearbyintl = (nearbyintl);
static double_unary_function volatile direct_pow10 = (pow10);
static float_unary_function volatile direct_pow10f = (pow10f);
static binary80_unary_function volatile direct_pow10l = (pow10l);
static double_unary_function volatile direct_rint = (rint);
static float_unary_function volatile direct_rintf = (rintf);
static binary80_unary_function volatile direct_rintl = (rintl);

_Static_assert(sizeof(float) == 4 && _Alignof(float) == 4,
	"SysV x86-64 binary32 storage");
_Static_assert(sizeof(double) == 8 && _Alignof(double) == 8,
	"SysV x86-64 binary64 storage");
_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
	"SysV x86-64 binary80 storage");
_Static_assert(FLT_RADIX == 2 && DBL_MANT_DIG == 53 && LDBL_MANT_DIG == 64,
	"selected IEEE scalar formats");

static int verify_double_surface(void)
{
	if (direct_exp10 != direct_pow10)
		return 1;
	if (direct_exp10(1.0) != 10.0 || direct_pow10(1.0) != 10.0)
		return 2;
	if (direct_fdim(3.0, 1.0) != 2.0)
		return 3;
	if (direct_nearbyint(2.0) != 2.0 || direct_rint(2.0) != 2.0)
		return 4;
	return 0;
}

static int verify_float_surface(void)
{
	if (direct_exp10f != direct_pow10f)
		return 1;
	if (direct_exp10f(1.0f) != 10.0f || direct_pow10f(1.0f) != 10.0f)
		return 2;
	if (direct_fdimf(3.0f, 1.0f) != 2.0f)
		return 3;
	if (direct_nearbyintf(2.0f) != 2.0f || direct_rintf(2.0f) != 2.0f)
		return 4;
	return 0;
}

static int verify_binary80_surface(void)
{
	if (direct_exp10l != direct_pow10l)
		return 1;
	if (direct_exp10l(1.0L) != 10.0L || direct_pow10l(1.0L) != 10.0L)
		return 2;
	if (direct_fdiml(3.0L, 1.0L) != 2.0L)
		return 3;
	if (direct_nearbyintl(2.0L) != 2.0L || direct_rintl(2.0L) != 2.0L)
		return 4;
	return 0;
}

int crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe(void)
{
	int status;

	status = verify_double_surface();
	if (status != 0)
		return status;
	status = verify_float_surface();
	if (status != 0)
		return 16 + status;
	status = verify_binary80_surface();
	return status == 0 ? 0 : 32 + status;
}
