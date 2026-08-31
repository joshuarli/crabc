/*
 * Static Linux/x86-64 elementary square-root and fenv probe.
 *
 * This fixture is intentionally a narrow selected scalar-math boundary.  It
 * calls `sqrt`, `sqrtf`, and `sqrtl` through C function pointers after the
 * same checks pass against pinned musl.  The three entry points must retain
 * x86's split IEEE environment: binary64 and binary32 consume MXCSR through
 * `sqrtsd`/`sqrtss`, while binary80 consumes the x87 control word through
 * `fsqrt`.  It is not a claim for fmod, rounding helpers, libm, or general
 * scalar math.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <math.h>
#include <stdint.h>

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
	"x86 long-double storage");

typedef double (*sqrt_function)(double);
typedef float (*sqrtf_function)(float);
typedef long double (*sqrtl_function)(long double);

/* Parentheses force addresses of the ABI symbols rather than any
 * implementation-defined compiler builtin expansion. */
static sqrt_function const direct_sqrt = (sqrt);
static sqrtf_function const direct_sqrtf = (sqrtf);
static sqrtl_function const direct_sqrtl = (sqrtl);

static uint64_t double_bits(double value)
{
	union {
		double value;
		uint64_t bits;
	} view = { .value = value };
	return view.bits;
}

static uint32_t float_bits(float value)
{
	union {
		float value;
		uint32_t bits;
	} view = { .value = value };
	return view.bits;
}

/* Only the low ten bytes of an x86 long double carry the binary80 value.
 * Read those bytes explicitly, leaving the ABI's six padding bytes outside
 * the assertion. */
static uint64_t long_double_mantissa(long double value)
{
	union {
		long double value;
		unsigned char raw[16];
	} view = { .value = value };
	uint64_t bits = 0;
	int index;

	for (index = 7; index >= 0; index--)
		bits = (bits << 8) | view.raw[index];
	return bits;
}

static uint16_t long_double_sign_exponent(long double value)
{
	union {
		long double value;
		unsigned char raw[16];
	} view = { .value = value };
	return (uint16_t)view.raw[8] | ((uint16_t)view.raw[9] << 8);
}

static int check_special_values(void)
{
	volatile double four = 4.0;
	volatile double negative = -4.0;
	volatile double zero = 0.0;
	volatile double negative_zero = -0.0;
	volatile float fourf = 4.0f;
	volatile float negativef = -4.0f;
	volatile float zerof = 0.0f;
	volatile float negative_zerof = -0.0f;
	volatile long double fourl = 4.0L;
	volatile long double negativel = -4.0L;
	volatile long double zerol = 0.0L;
	volatile long double negative_zerol = -0.0L;
	double result;
	float resultf;
	long double resultl;

	if (double_bits(direct_sqrt(four)) != UINT64_C(0x4000000000000000))
		return 10;
	if (double_bits(direct_sqrt(zero)) != 0 ||
		double_bits(direct_sqrt(negative_zero)) != UINT64_C(0x8000000000000000))
		return 11;
	if (!isinf(direct_sqrt(HUGE_VAL)) || signbit(direct_sqrt(HUGE_VAL)))
		return 12;
	if (!isnan(direct_sqrt(NAN)))
		return 13;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 14;
	result = direct_sqrt(negative);
	if (!isnan(result) || !(fetestexcept(FE_INVALID) & FE_INVALID))
		return 15;

	if (float_bits(direct_sqrtf(fourf)) != UINT32_C(0x40000000))
		return 20;
	if (float_bits(direct_sqrtf(zerof)) != 0 ||
		float_bits(direct_sqrtf(negative_zerof)) != UINT32_C(0x80000000))
		return 21;
	if (!isinf(direct_sqrtf(HUGE_VALF)) || signbit(direct_sqrtf(HUGE_VALF)))
		return 22;
	if (!isnan(direct_sqrtf(NAN)))
		return 23;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 24;
	resultf = direct_sqrtf(negativef);
	if (!isnan(resultf) || !(fetestexcept(FE_INVALID) & FE_INVALID))
		return 25;

	if (long_double_mantissa(direct_sqrtl(fourl)) != UINT64_C(0x8000000000000000) ||
		long_double_sign_exponent(direct_sqrtl(fourl)) != UINT16_C(0x4000))
		return 30;
	if (long_double_mantissa(direct_sqrtl(zerol)) != 0 ||
		long_double_sign_exponent(direct_sqrtl(zerol)) != 0 ||
		long_double_mantissa(direct_sqrtl(negative_zerol)) != 0 ||
		long_double_sign_exponent(direct_sqrtl(negative_zerol)) != UINT16_C(0x8000))
		return 31;
	if (!isinf(direct_sqrtl(HUGE_VALL)) || signbit(direct_sqrtl(HUGE_VALL)))
		return 32;
	if (!isnan(direct_sqrtl((long double)NAN)))
		return 33;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 34;
	resultl = direct_sqrtl(negativel);
	if (!isnan(resultl) || !(fetestexcept(FE_INVALID) & FE_INVALID))
		return 35;

	return 0;
}

static int check_binary64_rounding(void)
{
	volatile double input = 2.0;
	double result;

	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 40;
	result = direct_sqrt(input);
	if (double_bits(result) != UINT64_C(0x3ff6a09e667f3bcd) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 41;
	if (fesetround(FE_DOWNWARD) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 42;
	result = direct_sqrt(input);
	if (double_bits(result) != UINT64_C(0x3ff6a09e667f3bcc) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 43;
	if (fesetround(FE_UPWARD) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 44;
	result = direct_sqrt(input);
	if (double_bits(result) != UINT64_C(0x3ff6a09e667f3bcd) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 45;
	if (fesetround(FE_TOWARDZERO) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 46;
	result = direct_sqrt(input);
	if (double_bits(result) != UINT64_C(0x3ff6a09e667f3bcc) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 47;
	return 0;
}

static int check_binary32_rounding(void)
{
	volatile float input = 2.0f;
	float result;

	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 50;
	result = direct_sqrtf(input);
	if (float_bits(result) != UINT32_C(0x3fb504f3) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 51;
	if (fesetround(FE_DOWNWARD) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 52;
	result = direct_sqrtf(input);
	if (float_bits(result) != UINT32_C(0x3fb504f3) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 53;
	if (fesetround(FE_UPWARD) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 54;
	result = direct_sqrtf(input);
	if (float_bits(result) != UINT32_C(0x3fb504f4) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 55;
	if (fesetround(FE_TOWARDZERO) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 56;
	result = direct_sqrtf(input);
	if (float_bits(result) != UINT32_C(0x3fb504f3) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 57;
	return 0;
}

static int check_binary80_rounding(void)
{
	volatile long double input = 2.0L;
	long double result;

	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 60;
	result = direct_sqrtl(input);
	if (long_double_mantissa(result) != UINT64_C(0xb504f333f9de6484) ||
		long_double_sign_exponent(result) != UINT16_C(0x3fff) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 61;
	if (fesetround(FE_DOWNWARD) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 62;
	result = direct_sqrtl(input);
	if (long_double_mantissa(result) != UINT64_C(0xb504f333f9de6484) ||
		long_double_sign_exponent(result) != UINT16_C(0x3fff) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 63;
	if (fesetround(FE_UPWARD) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 64;
	result = direct_sqrtl(input);
	if (long_double_mantissa(result) != UINT64_C(0xb504f333f9de6485) ||
		long_double_sign_exponent(result) != UINT16_C(0x3fff) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 65;
	if (fesetround(FE_TOWARDZERO) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 66;
	result = direct_sqrtl(input);
	if (long_double_mantissa(result) != UINT64_C(0xb504f333f9de6484) ||
		long_double_sign_exponent(result) != UINT16_C(0x3fff) ||
		!(fetestexcept(FE_INEXACT) & FE_INEXACT))
		return 67;
	return 0;
}

int crabc_x86_64_elementary_sqrt_fenv_probe(void)
{
	fenv_t original;
	int status;

	if (fegetenv(&original) != 0)
		return 1;
	if (fesetenv(FE_DFL_ENV) != 0)
		return 2;
	status = check_special_values();
	if (status == 0)
		status = check_binary64_rounding();
	if (status == 0)
		status = check_binary32_rounding();
	if (status == 0)
		status = check_binary80_rounding();
	if (fesetenv(&original) != 0 && status == 0)
		status = 3;
	return status;
}

#ifndef CRABC_ELEMENTARY_SQRT_FENV_FREESTANDING
int main(void)
{
	return crabc_x86_64_elementary_sqrt_fenv_probe();
}
#endif
